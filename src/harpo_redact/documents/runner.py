"""The gateway side of the process boundary: spawn a worker, talk to it, never trust it.

The worker gets an empty environment (no provider keys), its own session, and limits it applies
to itself before reading the document. A document is parsed by exactly one worker and the worker
exits afterwards, so nothing carries over from one document to the next.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import signal
import struct
import sys
from pathlib import Path
from types import TracebackType
from typing import Any

from .common import MAX_FRAME

_BOOT = "import sys; sys.path.insert(0, {root!r}); from harpo_redact.documents.worker import main; sys.exit(main())"


class DocumentError(Exception):
    """A document that was refused or could not be processed. ``code`` is stable and safe to show."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.message = message or code


class OpenResult:
    def __init__(self, segments: list[list[Any]], info: dict[str, Any]) -> None:
        self.segments = segments  # [text, ctx, group, row]
        self.info = info


class Session:
    def __init__(self, runner: WorkerRunner, fmt: str, name: str, data: bytes) -> None:
        self.runner, self.fmt, self.name, self.data = runner, fmt, name, data
        self.proc: asyncio.subprocess.Process | None = None

    async def __aenter__(self) -> Session:
        runner = self.runner
        if runner.semaphore.locked() and runner.waiting >= runner.max_waiting:
            # Every queued upload holds its bytes in memory, so the queue is bounded.
            raise DocumentError("busy", "too many documents are being processed: retry shortly")
        runner.waiting += 1
        try:
            await runner.semaphore.acquire()
        finally:
            runner.waiting -= 1
        try:
            self.proc = await self.runner.spawn()
        except BaseException:
            self.runner.semaphore.release()
            raise
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        try:
            await self.runner.stop(self.proc)
        finally:
            self.runner.semaphore.release()

    def _streams(self) -> tuple[asyncio.StreamWriter, asyncio.StreamReader]:
        proc = self.proc
        if proc is None or proc.stdin is None or proc.stdout is None:
            raise DocumentError("worker_crashed", "the document worker is not running")
        return proc.stdin, proc.stdout

    async def _send(self, payload: bytes) -> None:
        stdin, _ = self._streams()
        stdin.write(struct.pack(">I", len(payload)) + payload)
        await stdin.drain()

    async def _recv(self) -> bytes:
        _, stdout = self._streams()
        try:
            (size,) = struct.unpack(">I", await stdout.readexactly(4))
            if size > MAX_FRAME:
                raise DocumentError("worker_failed", "the document worker sent an oversized reply")
            return await stdout.readexactly(size)
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            raise await self.runner.crash(self.proc) from None

    async def _json(self) -> dict[str, Any]:
        reply: dict[str, Any] = json.loads(await self._recv())
        if not reply.get("ok"):
            raise DocumentError(str(reply.get("code", "worker_failed")), str(reply.get("message", "")))
        return reply

    def _head(self, op: str, **extra: Any) -> bytes:
        cfg = self.runner.settings
        head = {"op": op, "limits": {"memory_mb": cfg.worker_memory_mb, "cpu_s": cfg.worker_cpu_s}, **extra}
        return json.dumps(head).encode()

    async def open(self, options: dict[str, Any]) -> OpenResult:
        try:
            await self._send(self._head("open", format=self.fmt, name=self.name, options=options))
            await self._send(self.data)
        except (ConnectionResetError, BrokenPipeError):
            raise await self.runner.crash(self.proc) from None
        reply = await self._json()
        return OpenResult(reply["segments"], reply["info"])

    async def apply(self, edits: dict[int, dict[str, Any]]) -> tuple[bytes, list[str], str | None, str]:
        try:
            await self._send(json.dumps({"op": "apply", "edits": {str(k): v for k, v in edits.items()}}).encode())
        except (ConnectionResetError, BrokenPipeError):
            raise await self.runner.crash(self.proc) from None
        reply = await self._json()
        data = await self._recv()
        return data, list(reply["verify"]), reply.get("content_type"), str(reply.get("extension", ""))

    async def call(self, op: str, **extra: Any) -> dict[str, Any]:
        await self._send(self._head(op, **extra))
        return await self._json()


class WorkerRunner:
    def __init__(self, settings: Any) -> None:
        self.settings = settings
        self.semaphore = asyncio.Semaphore(settings.max_concurrent)
        self.waiting = 0
        self.max_waiting = settings.max_concurrent * 4
        self.root = str(Path(__file__).resolve().parents[2])

    def session(self, fmt: str, name: str, data: bytes) -> Session:
        return Session(self, fmt, name, data)

    async def spawn(self) -> asyncio.subprocess.Process:
        return await asyncio.create_subprocess_exec(
            sys.executable,
            "-I",
            "-B",
            "-X",
            "utf8",
            "-c",
            _BOOT.format(root=self.root),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env={},
            cwd="/",
            start_new_session=True,
            close_fds=True,
            limit=1 << 26,
        )

    async def crash(self, proc: asyncio.subprocess.Process | None) -> DocumentError:
        code = None
        if proc is not None:
            try:
                code = await asyncio.wait_for(proc.wait(), 5)
            except TimeoutError:
                code = None
        if code in (-signal.SIGXCPU, -signal.SIGKILL):
            return DocumentError("worker_limit", "the document needed more time or memory than the worker may use")
        return DocumentError("worker_crashed", "the document worker stopped unexpectedly")

    async def stop(self, proc: asyncio.subprocess.Process | None) -> None:
        if proc is None:
            return
        if proc.returncode is None:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(proc.pid, signal.SIGKILL)
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(proc.wait(), 5)

    async def selftest(self) -> dict[str, Any]:
        async with self.session("text", "", b"") as session:
            return await session.call("selftest")
