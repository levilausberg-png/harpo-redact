"""The process that parses untrusted documents.

Started by ``runner`` with an empty environment. It reads length-prefixed frames on stdin and
answers on stdout. Before it touches a document it caps its memory and CPU time, forbids writing
files, and tries to leave the network namespace. It never imports the gateway's pipeline,
configuration or HTTP code, so a bug in a parser can reach the document and nothing else.

Conversation: ``{"op": "open", ...}`` + document bytes -> segments; then ``{"op": "apply", edits}``
-> verification strings + the redacted file.
"""

from __future__ import annotations

import contextlib
import json
import os
import signal
import struct
import sys
import tempfile
import time
from typing import Any

from .common import MAX_FRAME, DocError, Limits


def _read_exact(stream: Any, size: int) -> bytes:
    buffer = bytearray()
    while len(buffer) < size:
        chunk = stream.read(size - len(buffer))
        if not chunk:
            raise EOFError
        buffer += chunk
    return bytes(buffer)


def _vm_bytes() -> int:
    try:
        with open("/proc/self/statm") as handle:
            return int(handle.read().split()[0]) * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError):
        return 0


def _isolate_network() -> bool:
    """Leave the network namespace if the system allows it: a compromised parser cannot phone home."""
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        return bool(libc.unshare(0x10000000 | 0x40000000) == 0)  # CLONE_NEWUSER | CLONE_NEWNET
    except (OSError, AttributeError):
        return False


def apply_limits(cfg: dict[str, Any]) -> dict[str, Any]:
    import resource

    vm = _vm_bytes()
    memory = int(cfg.get("memory_mb", 768)) * 1024 * 1024
    if vm:  # the cap is on the address space, so it is the size the process already has plus the budget
        resource.setrlimit(resource.RLIMIT_AS, (vm + memory, vm + memory))
    cpu = int(cfg.get("cpu_s", 60))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))  # no file can be written
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    os.chdir("/")
    return {"network_isolated": _isolate_network()}


def open_document(fmt: str, data: bytes, name: str, limits: Limits) -> Any:
    if fmt == "pdf":
        from .pdf import PdfDocument

        return PdfDocument(data, name, limits)
    if fmt == "ooxml":
        from .ooxml import OoxmlDocument

        return OoxmlDocument(data, name, limits)
    if fmt == "text":
        from .textfile import TextDocument

        return TextDocument(data, name, limits)
    raise DocError("unsupported_format", "unknown document format")


def selftest(status: dict[str, Any]) -> dict[str, Any]:
    import resource

    try:
        with open(os.path.join(tempfile.gettempdir(), "harpo-selftest"), "w") as handle:  # this must fail
            handle.write("x")
        wrote = True
    except OSError:
        wrote = False
    return {
        **status,
        "environment_empty": len(os.environ) == 0,
        "can_write_files": wrote,
        "address_space_limited": resource.getrlimit(resource.RLIMIT_AS)[0] != resource.RLIM_INFINITY,
        "cpu_limit_s": resource.getrlimit(resource.RLIMIT_CPU)[0],
        "cwd": os.getcwd(),
    }


def main() -> int:
    out = sys.stdout.buffer
    sys.stdout = sys.stderr  # a stray print must never corrupt the protocol
    os.environ.clear()
    stdin = sys.stdin.buffer

    def recv() -> bytes:
        (size,) = struct.unpack(">I", _read_exact(stdin, 4))
        if size > MAX_FRAME:
            raise EOFError
        return _read_exact(stdin, size)

    def send(payload: bytes) -> None:
        out.write(struct.pack(">I", len(payload)))
        out.write(payload)
        out.flush()

    def reply(obj: dict[str, Any]) -> None:
        send(json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    try:
        head = json.loads(recv())
        status = apply_limits(head.get("limits") or {})
        if head["op"] == "selftest":
            reply({"ok": True, **selftest(status)})
            return 0
        if head["op"] == "sleep":
            time.sleep(float(head["seconds"]))
            reply({"ok": True})
            return 0
        data = recv()
        try:
            doc = open_document(head["format"], data, head.get("name", ""), Limits.from_dict(head.get("options") or {}))
        except DocError as exc:
            reply({"ok": False, "code": exc.code, "message": exc.message})
            return 0
        except MemoryError:
            reply(
                {
                    "ok": False,
                    "code": "worker_limit",
                    "message": "the document needs more memory than the worker may use",
                }
            )
            return 0
        except RecursionError:
            reply({"ok": False, "code": "corrupt", "message": "the document is nested too deeply"})
            return 0
        reply({"ok": True, "segments": [s.to_json() for s in doc.segments()], "info": doc.info})
        message = json.loads(recv())
        if message.get("op") != "apply":
            return 0
        try:
            edits = {int(k): v for k, v in message["edits"].items()}
            if any(not 0 <= k < len(doc.segments()) for k in edits):
                raise DocError("bad_edit", "an edit refers to a text piece that does not exist")
            result = doc.apply(edits)
            verify = doc.verify_strings(result)
        except DocError as exc:
            reply({"ok": False, "code": exc.code, "message": exc.message})
            return 0
        except MemoryError:
            reply(
                {
                    "ok": False,
                    "code": "worker_limit",
                    "message": "the document needs more memory than the worker may use",
                }
            )
            return 0
        reply(
            {
                "ok": True,
                "verify": verify,
                "content_type": getattr(doc, "content_type", None) or _office_type(doc),
                "extension": getattr(doc, "extension", None) or getattr(doc, "kind", ""),
            }
        )
        send(result)
        return 0
    except (EOFError, struct.error, KeyError, ValueError):
        return 2
    except Exception as exc:  # last line of defence: report the class only, never content
        with contextlib.suppress(Exception):
            reply({"ok": False, "code": "internal_error", "message": type(exc).__name__})
        return 3


def _office_type(doc: Any) -> str | None:
    from .ooxml import CONTENT_TYPES

    return CONTENT_TYPES.get(getattr(doc, "kind", ""))


if __name__ == "__main__":
    sys.exit(main())
