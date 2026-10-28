"""End to end: a real Harpo server process, a provider that records what reaches it, every endpoint, and the CLI.

    python tools/e2e_gateway.py --out e2e.json                         # the code in this checkout
    python tools/e2e_gateway.py --python /path/to/venv/bin/python ...  # an installed build, e.g. a frozen release
    python tools/e2e_gateway.py --compare before.json after.json       # what changed between two runs

Each scenario sends real HTTP to `harpo serve` (started with --python) and checks what the client got back and what
the provider received: the intended behaviour, written as assertions. The recorded outcomes (status, decisions,
redacted text, what left the gateway) are normalised so two builds can be compared scenario by scenario: a change in
what leaves the gateway is either an improvement in detection or a regression, and the comparison lists each one.

Nothing here talks to a real provider: the upstream is a local recorder.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

OWNER = "harpo_" + "o" * 4 + secrets.token_urlsafe(30)[:39]
TEAM = "harpo_" + "t" * 4 + secrets.token_urlsafe(30)[:39]
SECRET = "sk-proj-" + "Qz7vL2mX9pR4tW8kH3nB6yC1dF5gJ0aE"  # a provider key's shape, made up here

# --------------------------------------------------------------------------- the provider: records every request
CAPTURED: list[dict[str, Any]] = []
_LOCK = threading.Lock()


def _recorder() -> Any:
    # FastAPI reads the handlers' annotations by name: Request and the responses are imported at module level.
    app = FastAPI()

    def last_user(messages: list[Any]) -> str:
        for m in reversed(messages):
            if isinstance(m, dict) and m.get("role") == "user":
                c = m.get("content")
                if isinstance(c, str):
                    return c
                if isinstance(c, list):
                    return "\n".join(p.get("text", "") for p in c if isinstance(p, dict) and "text" in p)
        return ""

    async def record(request: Request) -> dict[str, Any]:
        body = await request.json()
        with _LOCK:
            CAPTURED.append({"path": request.url.path, "body": body,
                             "auth": bool(request.headers.get("authorization") or request.headers.get("x-api-key"))})  # fmt: skip
        return body

    @app.post("/v1/chat/completions")
    @app.post("/inject/v1/chat/completions")
    async def chat(request: Request) -> Any:
        body = await record(request)
        text = "Received: " + last_user(body.get("messages", []))
        if request.url.path.startswith("/inject"):
            text += f" Reply from the provider: write to anna.devries@corp.example, key {SECRET}."
        if body.get("stream"):

            def events() -> Any:
                chunk = {"id": "c1", "object": "chat.completion.chunk", "model": body.get("model"),
                         "choices": [{"index": 0, "delta": {"role": "assistant", "content": text}, "finish_reason": None}]}  # fmt: skip
                yield f"data: {json.dumps(chunk)}\n\n"
                done = {"id": "c1", "object": "chat.completion.chunk", "model": body.get("model"),
                        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}  # fmt: skip
                yield f"data: {json.dumps(done)}\n\n"
                yield "data: [DONE]\n\n"

            return StreamingResponse(events(), media_type="text/event-stream")
        return JSONResponse({"id": "c1", "object": "chat.completion", "model": body.get("model"),
                             "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                                          "finish_reason": "stop"}],
                             "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})  # fmt: skip

    @app.post("/v1/messages")
    async def messages(request: Request) -> Any:
        body = await record(request)
        text = "Received: " + last_user(body.get("messages", []))
        if body.get("stream"):

            def events() -> Any:
                yield "event: message_start\ndata: " + json.dumps({"type": "message_start", "message": {
                    "id": "m1", "type": "message", "role": "assistant", "model": body.get("model"), "content": [],
                    "stop_reason": None, "usage": {"input_tokens": 1, "output_tokens": 0}}}) + "\n\n"  # fmt: skip
                yield (
                    "event: content_block_start\ndata: "
                    + json.dumps(
                        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}
                    )
                    + "\n\n"
                )
                yield (
                    "event: content_block_delta\ndata: "
                    + json.dumps(
                        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}}
                    )
                    + "\n\n"
                )
                yield (
                    "event: content_block_stop\ndata: "
                    + json.dumps({"type": "content_block_stop", "index": 0})
                    + "\n\n"
                )
                yield (
                    "event: message_delta\ndata: "
                    + json.dumps(
                        {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 1}}
                    )
                    + "\n\n"
                )
                yield "event: message_stop\ndata: " + json.dumps({"type": "message_stop"}) + "\n\n"

            return StreamingResponse(events(), media_type="text/event-stream")
        return JSONResponse({"id": "m1", "type": "message", "role": "assistant", "model": body.get("model"),
                             "content": [{"type": "text", "text": text}], "stop_reason": "end_turn",
                             "usage": {"input_tokens": 1, "output_tokens": 1}})  # fmt: skip

    @app.post("/v1/messages/count_tokens")
    async def count(request: Request) -> Any:
        body = await record(request)
        return JSONResponse({"input_tokens": len(json.dumps(body)) // 4})

    @app.get("/v1/models")
    async def models() -> Any:
        return JSONResponse({"object": "list", "data": [{"id": "mock-gpt", "object": "model"}]})

    return app


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _start_recorder() -> int:
    import uvicorn

    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(_recorder(), host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        try:
            httpx.post(f"http://127.0.0.1:{port}/v1/messages/count_tokens", json={}, timeout=0.5)
            break
        except httpx.HTTPError:
            time.sleep(0.05)
    with _LOCK:
        CAPTURED.clear()
    return port


# --------------------------------------------------------------------------- the gateway under test
def _sha(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _config(folder: Path, port: int, upstream: int, extra_policy: dict[str, Any]) -> Path:
    import yaml

    policy = {"live_file": str(folder / "policy.live.yaml"), "response_scan": "redact", **extra_policy}
    config = {
        "environment": "development",
        "server": {"host": "127.0.0.1", "port": port},
        "auth": {"enabled": True, "keys": [
            {"id": "owner", "sha256": _sha(OWNER), "admin": True, "can_override": True},
            {"id": "team", "sha256": _sha(TEAM)},
        ]},
        "upstreams": [
            {"name": "up-openai", "style": "openai", "base_url": f"http://127.0.0.1:{upstream}/v1", "models": ["mock-gpt"]},
            {"name": "up-anthropic", "style": "anthropic", "base_url": f"http://127.0.0.1:{upstream}",
             "models": ["mock-claude"]},
            {"name": "up-inject", "style": "openai", "base_url": f"http://127.0.0.1:{upstream}/inject/v1",
             "models": ["inject-gpt"]},
        ],
        "policy": policy,
    }  # fmt: skip
    path = folder / "harpo.yaml"
    path.write_text(yaml.safe_dump(config, sort_keys=False))
    return path


class Gateway:
    def __init__(self, python: str, config: Path, port: int, workdir: Path) -> None:
        env = {**os.environ, "HARPO_NO_BANNER": "1", "NO_COLOR": "1"}
        self.log = (workdir / f"gateway-{port}.log").open("w")
        self.proc = subprocess.Popen(  # noqa: S603  # nosec B603: our own interpreter and module
            [python, "-m", "harpo_redact", "serve", "--config", str(config)], cwd=workdir, env=env,
            stdout=self.log, stderr=subprocess.STDOUT,
        )  # fmt: skip
        self.url = f"http://127.0.0.1:{port}"
        deadline = time.time() + 180
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"the gateway exited with {self.proc.returncode}; see {self.log.name}")
            try:
                if httpx.get(f"{self.url}/readyz", timeout=1).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.25)
        raise RuntimeError("the gateway did not become ready in 180 s")

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(20)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()


# --------------------------------------------------------------------------- scenarios
PROMPT = (
    "Refund Anna de Vries (anna.devries@acme.example, +31 20 794 6095), IBAN NL91 ABNA 0417 1643 00, BSN 111222333, "
    "card 4111 1111 1111 1111, living at Keizersgracht 123, 1015 CJ Amsterdam. SSN 536-90-4407. "
    f"Deploy with OPENAI_API_KEY={SECRET}."
)
LEAKS = ["Anna de Vries", "anna.devries@acme.example", "794 6095", "NL91 ABNA", "111222333", "4111 1111 1111 1111",
         "Keizersgracht 123", "536-90-4407", SECRET]  # fmt: skip


def _norm(value: Any) -> Any:
    """Drop what changes between runs: ids, timings, timestamps."""
    if isinstance(value, dict):
        return {k: _norm(v) for k, v in sorted(value.items())
                if k not in ("request_id", "id", "created", "timings_ms", "latency_ms", "uptime_s", "ran_at",
                             "updated_at", "timestamp", "ts", "started", "seconds", "python")}  # fmt: skip
    if isinstance(value, list):
        return [_norm(v) for v in value]
    if isinstance(value, str):
        return re.sub(r"harpo_[A-Za-z0-9_\-]{20,}", "harpo_<key>", value)
    return value


class Run:
    def __init__(self, gateway: Gateway) -> None:
        self.g = gateway
        self.client = httpx.Client(base_url=gateway.url, timeout=120)
        self.rows: list[dict[str, Any]] = []

    def call(self, method: str, path: str, key: str | None = OWNER, **kw: Any) -> httpx.Response:
        headers = dict(kw.pop("headers", {}) or {})
        if key:
            headers["Authorization"] = f"Bearer {key}"
        return self.client.request(method, path, headers=headers, **kw)

    def scenario(
        self, name: str, fn: Callable[[], tuple[dict[str, Any], list[str]]], allowed: tuple[str, ...] = ()
    ) -> None:
        """Run one scenario. ``allowed`` are values the scenario sends on purpose (a type set to allow)."""
        with _LOCK:
            start = len(CAPTURED)
        try:
            outcome, failures = fn()
        except Exception as exc:  # a crash is a failed scenario, recorded with its message
            outcome, failures = {"exception": f"{type(exc).__name__}: {exc}"}, [f"raised {type(exc).__name__}: {exc}"]
        with _LOCK:
            sent = [c["body"] for c in CAPTURED[start:]]
        upstream_text = json.dumps(sent, ensure_ascii=False)
        leaked = [v for v in LEAKS if v in upstream_text and v not in allowed]
        row = {"scenario": name, "outcome": _norm(outcome), "upstream": _norm(sent), "leaked_upstream": leaked,
               "failures": failures, "ok": not failures}  # fmt: skip
        self.rows.append(row)
        mark = "ok  " if not failures else "FAIL"
        print(f"  {mark} {name}" + ("" if not failures else f": {'; '.join(failures)}"), flush=True)


def _expect(failures: list[str], condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def chat_body(text: str, model: str = "mock-gpt", **extra: Any) -> dict[str, Any]:
    return {"model": model, "messages": [{"role": "user", "content": text}], **extra}


def main_scenarios(r: Run) -> None:
    def health() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        a, b = r.call("GET", "/healthz", key=None), r.call("GET", "/readyz", key=None)
        _expect(f, a.status_code == 200 and b.status_code == 200, f"healthz {a.status_code}, readyz {b.status_code}")
        return {"healthz": a.status_code, "readyz": b.status_code, "ready": b.json()}, f

    def auth() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        none = r.call("POST", "/v1/chat/completions", key=None, json=chat_body("hi"))
        wrong = r.call("POST", "/v1/chat/completions", key="harpo_wrong", json=chat_body("hi"))
        team_admin = r.call("GET", "/v1/system", key=TEAM)
        team_chat = r.call("POST", "/v1/chat/completions", key=TEAM, json=chat_body("hi"))
        _expect(f, none.status_code == 401 and wrong.status_code == 401, "missing or wrong key not refused")
        _expect(f, team_admin.status_code == 403, f"a team key reached /v1/system ({team_admin.status_code})")
        _expect(f, team_chat.status_code == 200, f"a team key cannot chat ({team_chat.status_code})")
        return {"none": none.status_code, "wrong": wrong.status_code, "team_admin": team_admin.status_code,
                "team_chat": team_chat.status_code}, f  # fmt: skip

    def openai_chat() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        resp = r.call("POST", "/v1/chat/completions", json=chat_body(PROMPT))
        reply = resp.json()["choices"][0]["message"]["content"] if resp.status_code == 200 else resp.text
        _expect(f, resp.status_code == 200, f"status {resp.status_code}")
        _expect(f, resp.headers.get("x-harpo-request-id") is not None, "no x-harpo-request-id header")
        _expect(f, int(resp.headers.get("x-harpo-redactions") or 0) >= len(LEAKS), "fewer redactions than values")
        _expect(f, not any(v in reply for v in LEAKS), "a value came back in the reply")
        return {"status": resp.status_code, "risk": resp.headers.get("x-harpo-risk"),
                "redactions": resp.headers.get("x-harpo-redactions"), "reply": reply}, f  # fmt: skip

    def openai_stream() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        resp = r.call("POST", "/v1/chat/completions", json=chat_body(PROMPT, stream=True))
        text = "".join(json.loads(line[6:])["choices"][0]["delta"].get("content") or ""
                       for line in resp.text.splitlines() if line.startswith("data: {"))  # fmt: skip
        _expect(f, resp.status_code == 200 and "text/event-stream" in resp.headers.get("content-type", ""), "no stream")
        _expect(f, resp.headers.get("x-harpo-response-scan") == "not_scanned_stream", "stream not marked unscanned")
        return {"status": resp.status_code, "text": text, "response_scan": resp.headers.get("x-harpo-response-scan")}, f

    def anthropic() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        body = {"model": "mock-claude", "max_tokens": 64, "system": "Customer: Anna de Vries, BSN 111222333.",
                "messages": [{"role": "user", "content": [{"type": "text", "text": PROMPT}]}]}  # fmt: skip
        resp = r.call("POST", "/v1/messages", json=body, headers={"anthropic-version": "2023-06-01"})
        streamed = r.call(
            "POST", "/v1/messages", json={**body, "stream": True}, headers={"anthropic-version": "2023-06-01"}
        )
        tokens = r.call("POST", "/v1/messages/count_tokens", json={k: v for k, v in body.items() if k != "max_tokens"})
        reply = resp.json()["content"][0]["text"] if resp.status_code == 200 else resp.text
        _expect(
            f, resp.status_code == 200 and streamed.status_code == 200, f"{resp.status_code}/{streamed.status_code}"
        )
        _expect(f, tokens.status_code == 200, f"count_tokens {tokens.status_code}")
        _expect(f, "message_stop" in streamed.text, "the stream did not finish")
        return {
            "status": resp.status_code,
            "reply": reply,
            "stream": streamed.status_code,
            "count": tokens.status_code,
        }, f

    def tools() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        body = {"model": "mock-gpt", "messages": [
            {"role": "user", "content": "Look up the customer."},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "call_1", "type": "function", "function": {
                "name": "lookup", "arguments": json.dumps({"email": "anna.devries@acme.example", "token": SECRET})}}]},
            {"role": "tool", "tool_call_id": "call_1", "content": json.dumps(
                {"name": "Anna de Vries", "iban": "NL91 ABNA 0417 1643 00", "bsn": "111222333"})},
        ], "tools": [{"type": "function", "function": {"name": "lookup", "description": "Find a customer by e-mail",
                     "parameters": {"type": "object", "properties": {"email": {"type": "string"}}}}}]}  # fmt: skip
        resp = r.call("POST", "/v1/chat/completions", json=body)
        _expect(f, resp.status_code == 200, f"status {resp.status_code}")
        return {"status": resp.status_code}, f

    def openrouter_alias() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        resp = r.call("POST", "/api/v1/chat/completions", json=chat_body("Mail anna.devries@acme.example"))
        _expect(f, resp.status_code == 200, f"status {resp.status_code}")
        return {"status": resp.status_code}, f

    def models() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        resp = r.call("GET", "/v1/models")
        claude = r.call("GET", "/v1/models", headers={"anthropic-version": "2023-06-01"})
        ids = sorted(m["id"] for m in resp.json().get("data", [])) if resp.status_code == 200 else []
        claude_ids = sorted(m["id"] for m in claude.json().get("data", [])) if claude.status_code == 200 else []
        _expect(f, ids == ["inject-gpt", "mock-gpt"], f"OpenAI-style models {ids}")
        _expect(f, claude_ids == ["mock-claude"], f"Anthropic-style models {claude_ids}")
        return {"status": resp.status_code, "models": ids, "anthropic_models": claude_ids}, f

    def model_not_allowed() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        resp = r.call("POST", "/v1/chat/completions", json=chat_body("hi", model="gpt-unknown"))
        _expect(f, resp.status_code in (400, 403, 404), f"status {resp.status_code}")
        return {"status": resp.status_code, "type": resp.json().get("error", {}).get("type")}, f

    def image_blocked() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        content = [{"type": "text", "text": "What is this?"},
                   {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}}]  # fmt: skip
        resp = r.call(
            "POST",
            "/v1/chat/completions",
            json={"model": "mock-gpt", "messages": [{"role": "user", "content": content}]},
        )
        _expect(f, resp.status_code == 403, f"an image went through ({resp.status_code})")
        return {"status": resp.status_code, "reasons": resp.json().get("error", {}).get("harpo", {}).get("reasons")}, f

    def unknown_field() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        resp = r.call("POST", "/v1/chat/completions", json=chat_body("hi", undeclared_field={"x": "Anna de Vries"}))
        _expect(f, resp.status_code == 400, f"an undeclared field went through ({resp.status_code})")
        return {"status": resp.status_code}, f

    def too_large() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        resp = r.call("POST", "/v1/chat/completions", json=chat_body("a " * 1_100_000))
        _expect(f, resp.status_code == 413, f"status {resp.status_code}")
        return {"status": resp.status_code}, f

    def response_scan() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        resp = r.call("POST", "/v1/chat/completions", json=chat_body("Say hello", model="inject-gpt"))
        reply = resp.json()["choices"][0]["message"]["content"] if resp.status_code == 200 else resp.text
        _expect(f, SECRET not in reply and "anna.devries@corp.example" not in reply, "the provider's values came back")
        return {
            "status": resp.status_code,
            "reply": reply,
            "findings": resp.headers.get("x-harpo-response-findings"),
        }, f

    def modes() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        text = "Anna told Ben that Anna's card 4111 1111 1111 1111 was declined."
        out = {}
        for mode in ("relational", "generic"):
            resp = r.call("POST", "/v1/scan", json={"text": text, "mode": mode})
            out[mode] = resp.json()["results"][0]["redacted"] if resp.status_code == 200 else resp.status_code
        repaired = r.call("POST", "/v1/scan", json={"text": text, "context_repair": True})
        out["context_repair"] = (
            repaired.json()["results"][0]["redacted"] if repaired.status_code == 200 else repaired.status_code
        )
        bad = r.call("POST", "/v1/chat/completions", json=chat_body(text), headers={"X-Harpo-Mode": "loose"})
        _expect(f, bad.status_code == 400, "an unknown mode was accepted")
        return out | {"bad_mode": bad.status_code}, f

    def scan_api() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        resp = r.call("POST", "/v1/scan", json={"texts": [PROMPT, "nothing here"]})
        body = resp.json()
        redacted = [x["redacted"] for x in body.get("results", [])]
        _expect(f, resp.status_code == 200 and not any(v in redacted[0] for v in LEAKS), "a value was not redacted")
        return {
            "status": resp.status_code,
            "redacted": redacted,
            "counts": body.get("counts"),
            "risk": body.get("risk"),
        }, f

    def egress_preview() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        resp = r.call("POST", "/v1/egress/preview", json={"style": "openai", "body": chat_body(PROMPT)})
        _expect(f, resp.status_code == 200 and SECRET not in resp.text, f"status {resp.status_code}")
        return {"status": resp.status_code}, f

    def documents() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        data = (PROMPT + "\n").encode()
        resp = r.call("POST", "/v1/documents/redact", content=data,
                      headers={"x-harpo-filename": "letter.txt", "content-type": "text/plain"})  # fmt: skip
        text = resp.content.decode("utf-8", "replace")
        _expect(f, resp.status_code == 200 and not any(v in text for v in LEAKS), f"status {resp.status_code}")
        return {"status": resp.status_code, "text": text}, f

    def policy_live() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        view = r.call("GET", "/v1/policy/live")
        put = r.call("PUT", "/v1/policy/live", json={"entities": {"EMAIL": "allow"}, "custom_types": [
            {"name": "EMPLOYEE_ID", "patterns": [r"\bEMP-\d{6}\b"]}]})  # fmt: skip
        after = r.call(
            "POST", "/v1/chat/completions", json=chat_body("Mail anna.devries@acme.example about EMP-123456")
        )
        reply = after.json()["choices"][0]["message"]["content"] if after.status_code == 200 else after.text
        key_change = r.call("PUT", "/v1/policy/live", json={"entities": {"SECRET": "allow"}})
        reset = r.call("DELETE", "/v1/policy/live")
        back = r.call("POST", "/v1/chat/completions", json=chat_body("Mail anna.devries@acme.example"))
        back_reply = back.json()["choices"][0]["message"]["content"] if back.status_code == 200 else back.text
        _expect(f, put.status_code == 200 and "anna.devries@acme.example" in reply and "[EMPLOYEE_ID_1]" in reply,
                "the live policy did not apply")  # fmt: skip
        _expect(f, key_change.status_code in (400, 422), "keys could be allowed")
        _expect(f, reset.status_code == 200 and "anna.devries@acme.example" not in back_reply, "reset did not apply")
        return {"view": view.status_code, "put": put.status_code, "reply": reply, "key_change": key_change.status_code,
                "reset": reset.status_code, "back": back_reply}, f  # fmt: skip

    def library_switch() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        text = "router MAC 00:1A:2B:3C:4D:5E, wallet bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
        before = r.call("POST", "/v1/scan", json={"text": text}).json()["results"][0]["redacted"]
        put = r.call("PUT", "/v1/policy/live", json={"detectors": {"identifiers.devices": False}})
        during = r.call("POST", "/v1/scan", json={"text": text}).json()["results"][0]["redacted"]
        locked = r.call("PUT", "/v1/policy/live", json={"detectors": {"secrets.library": False}})
        system = r.call("GET", "/v1/system").json().get("detection", {})
        r.call("DELETE", "/v1/policy/live")
        after = r.call("POST", "/v1/scan", json={"text": text}).json()["results"][0]["redacted"]
        _expect(f, put.status_code == 200 and "00:1A:2B:3C:4D:5E" in during and "00:1A" not in after, "switch failed")
        _expect(f, locked.status_code in (400, 422), "the credential library could be switched off")
        _expect(f, "library" in system, "/v1/system has no library")
        return {"before": before, "put": put.status_code, "during": during, "after": after,
                "locked": locked.status_code, "families": sum(len(g["families"]) for g in system.get("library", {}).get("groups", []))}, f  # fmt: skip

    def preview() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        resp = r.call("POST", "/v1/policy/preview", json={"text": "Mail anna.devries@acme.example",
                                                          "policy": {"entities": {"EMAIL": "block"}}})  # fmt: skip
        _expect(f, resp.status_code == 200 and resp.json().get("blocked") is True, "preview did not block")
        return {"status": resp.status_code, "blocked": resp.json().get("blocked")}, f

    def control_plane() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        out: dict[str, Any] = {}
        for path in (
            "/v1/policy",
            "/v1/system",
            "/v1/providers",
            "/v1/keys",
            "/v1/config/effective",
            "/v1/config/analysis",
            "/v1/diagnostics",
            "/v1/attention",
            "/v1/stats",
            "/v1/setup/presets",
            "/metrics",
        ):
            resp = r.call("GET", path)
            out[path] = resp.status_code
            _expect(f, resp.status_code == 200, f"{path} {resp.status_code}")
            if path in ("/v1/diagnostics", "/v1/config/effective", "/metrics", "/v1/stats"):
                _expect(f, OWNER not in resp.text and "anna.devries" not in resp.text, f"{path} holds a key or content")
        check = r.call("POST", "/v1/providers/up-openai/check")
        out["provider_check"] = check.status_code
        validate = r.call("POST", "/v1/config/validate", json={"yaml": "environment: development\n"})
        out["validate"] = validate.status_code
        lab = r.call("POST", "/v1/lab/detect", json={"text": PROMPT})
        out["lab"] = lab.status_code
        _expect(f, lab.status_code == 200, f"lab {lab.status_code}")
        selftest = r.call("POST", "/v1/selftest")
        out["selftest"] = selftest.status_code
        _expect(f, selftest.status_code == 200 and selftest.json().get("passed") is True, "the live self-test failed")
        out["console"] = r.call("GET", "/", key=None).status_code
        _expect(f, out["console"] == 200, "the console page is not served")
        return out, f

    def placeholders() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        body = {"model": "mock-gpt", "messages": [
            {"role": "user", "content": "Mail anna.devries@acme.example and ben.smit@acme.example."},
            {"role": "assistant", "content": "Which address first?"},
            {"role": "user", "content": "anna.devries@acme.example first, then ben.smit@acme.example."},
        ]}  # fmt: skip
        resp = r.call("POST", "/v1/chat/completions", json=body)
        with _LOCK:
            sent = CAPTURED[-1]["body"]["messages"] if CAPTURED else []
        first, last = (sent[0]["content"], sent[2]["content"]) if len(sent) == 3 else ("", "")
        tags = re.findall(r"\[EMAIL_\d+\]", first), re.findall(r"\[EMAIL_\d+\]", last)
        _expect(f, resp.status_code == 200, f"status {resp.status_code}")
        _expect(f, len(set(tags[0])) == 2 and tags[0] == tags[1], f"placeholders across messages {tags}")
        return {"status": resp.status_code, "sent": [first, last]}, f

    def events() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        first = ""
        with r.client.stream("GET", "/v1/events", headers={"Authorization": f"Bearer {OWNER}"}, timeout=10) as resp:
            status = resp.status_code
            for line in resp.iter_lines():
                first = line
                break
        _expect(f, status == 200 and first.startswith("retry:"), f"events {status} {first!r}")
        return {"status": status, "first": first}, f

    def key_generation() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        new = r.call("POST", "/v1/keys/generate", json={"id": "e2e-new"})
        clash = r.call("POST", "/v1/keys/generate", json={"id": "team"})
        team = r.call("POST", "/v1/keys/generate", key=TEAM, json={"id": "x"})
        body = new.json() if new.status_code == 200 else {}
        _expect(f, new.status_code == 200 and str(body.get("key", "")).startswith("harpo_"), "no key generated")
        _expect(f, body.get("persisted") is False, "a generated key was stored")
        _expect(f, clash.status_code == 409 and team.status_code == 403, f"{clash.status_code}/{team.status_code}")
        return {"status": new.status_code, "persisted": body.get("persisted"), "clash": clash.status_code,
                "team": team.status_code}, f  # fmt: skip

    def suites() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        resp = r.call("POST", "/v1/selftest/suites", json={})
        body = resp.json() if resp.status_code == 200 else {}
        results = {s["id"] if "id" in s else s.get("name"): s.get("status") for s in body.get("suites", [])}
        _expect(f, resp.status_code == 200 and body.get("passed") is True, f"suites {results}")
        return {"status": resp.status_code, "suites": results}, f

    def console_assets() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        page = r.call("GET", "/", key=None)
        script = r.call("GET", "/console/app/main.js", key=None)
        csp = page.headers.get("content-security-policy", "")
        _expect(f, script.status_code == 200 and "javascript" in script.headers.get("content-type", ""), "no script")
        _expect(f, "script-src 'self'" in csp and "unsafe" not in csp, f"console CSP {csp[:60]!r}")
        return {"page": page.status_code, "script": script.status_code, "csp": bool(csp)}, f

    def override() -> tuple[dict[str, Any], list[str]]:
        return {"skipped": "see the second configuration"}, []

    for name, fn in [("health", health), ("auth", auth), ("openai chat", openai_chat), ("openai stream", openai_stream),
                     ("anthropic messages", anthropic), ("tool calls and results", tools),
                     ("openrouter alias", openrouter_alias), ("models", models), ("model not allowed", model_not_allowed),
                     ("image blocked", image_blocked), ("undeclared field", unknown_field), ("body too large", too_large),
                     ("response scan", response_scan), ("placeholder modes", modes), ("scan api", scan_api),
                     ("egress preview", egress_preview), ("documents", documents), ("live policy", policy_live),
                     ("detection library switch", library_switch), ("policy preview", preview),
                     ("control plane and console", control_plane), ("placeholders across messages", placeholders),
                     ("event stream", events), ("key generation", key_generation), ("self-test suites", suites),
                     ("console assets", console_assets), ("override", override)]:  # fmt: skip
        r.scenario(name, fn, allowed=("anna.devries@acme.example",) if name == "live policy" else ())


def block_scenarios(r: Run) -> None:
    def block_and_override() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        blocked = r.call("POST", "/v1/chat/completions", key=TEAM, json=chat_body("Mail anna.devries@acme.example"))
        error = blocked.json().get("error", {})
        overridden = r.call("POST", "/v1/chat/completions", json=chat_body("Mail anna.devries@acme.example"),
                            headers={"X-Harpo-Override": "true"})  # fmt: skip
        team_override = r.call("POST", "/v1/chat/completions", key=TEAM, json=chat_body("Mail anna.devries@acme.example"),
                               headers={"X-Harpo-Override": "true"})  # fmt: skip
        _expect(
            f,
            blocked.status_code == 403 and error.get("type") == "privacy_block",
            f"not blocked ({blocked.status_code})",
        )
        _expect(f, overridden.status_code == 200, f"an allowed override was refused ({overridden.status_code})")
        _expect(f, team_override.status_code == 403, "a key without override rights overrode")
        _expect(f, "anna.devries" not in blocked.text, "the blocked value is in the error")
        return {"blocked": blocked.status_code, "blocked_types": error.get("harpo", {}).get("blocked_types"),
                "overridden": overridden.status_code, "team_override": team_override.status_code}, f  # fmt: skip

    def keys_never_block() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        resp = r.call("POST", "/v1/chat/completions", key=TEAM, json=chat_body(f"deploy with {SECRET}"))
        _expect(f, resp.status_code == 200, f"a key blocked the request ({resp.status_code})")
        return {"status": resp.status_code, "risk": resp.headers.get("x-harpo-risk")}, f

    def image_dropped() -> tuple[dict[str, Any], list[str]]:
        f: list[str] = []
        content = [{"type": "text", "text": "What is this?"},
                   {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}}]  # fmt: skip
        resp = r.call(
            "POST",
            "/v1/chat/completions",
            json={"model": "mock-gpt", "messages": [{"role": "user", "content": content}]},
        )
        _expect(f, resp.status_code == 200, f"status {resp.status_code}")
        return {"status": resp.status_code}, f

    for name, fn in [("block and override", block_and_override), ("keys never block", keys_never_block),
                     ("image dropped by policy", image_dropped)]:  # fmt: skip
        r.scenario(name, fn)


def cli_scenarios(python: str, workdir: Path, config: Path) -> list[dict[str, Any]]:
    rows = []

    def run(
        name: str,
        args: list[str],
        stdin: str | None = None,
        expect: Callable[[subprocess.CompletedProcess[str]], list[str]] | None = None,
    ) -> None:
        proc = subprocess.run([python, "-m", "harpo_redact", *args], input=stdin, capture_output=True, text=True,  # noqa: S603  # nosec B603
                              cwd=workdir, timeout=600, env={**os.environ, "HARPO_NO_BANNER": "1"})  # fmt: skip
        failures = expect(proc) if expect else []
        out = proc.stdout
        try:
            parsed: Any = _norm(json.loads(out))
        except ValueError:
            parsed = re.sub(
                r"harpo_[A-Za-z0-9_\-]{20,}", "harpo_<key>", re.sub(r"[0-9a-f]{64}", "<sha256>", out)
            ).strip()
        rows.append({"scenario": f"cli {name}", "outcome": {"exit": proc.returncode, "stdout": parsed},
                     "upstream": [], "leaked_upstream": [], "failures": failures, "ok": not failures})  # fmt: skip
        print(
            f"  {'ok  ' if not failures else 'FAIL'} cli {name}" + ("" if not failures else f": {failures}"), flush=True
        )

    run(
        "check-config",
        ["check-config", "--config", str(config)],
        expect=lambda p: (
            [] if p.returncode == 0 and p.stdout.startswith("ok:") else [f"exit {p.returncode}: {p.stdout[-200:]}"]
        ),
    )
    run(
        "hash-key",
        ["hash-key", "--id", "ci"],
        expect=lambda p: [] if p.returncode == 0 and "sha256:" in p.stdout else [f"exit {p.returncode}"],
    )
    run(
        "scan",
        ["scan", "--config", str(config)],
        stdin=PROMPT,
        expect=lambda p: (
            [] if p.returncode == 0 and not any(v in p.stdout for v in LEAKS) else [f"exit {p.returncode}"]
        ),
    )
    letter = workdir / "letter.txt"
    letter.write_text(PROMPT + "\n")
    out = workdir / "letter.redacted.txt"
    run("redact-file", ["redact-file", str(letter), "--output", str(out), "--config", str(config)],
        expect=lambda p: [] if p.returncode == 0 and out.exists() and not any(v in out.read_text() for v in LEAKS)
        else [f"exit {p.returncode}: {p.stderr[-300:]}"])  # fmt: skip
    return rows


def _log_check(kind: str, folder: Path) -> dict[str, Any]:
    """What the gateway wrote while it ran (its log and audit lines) holds no value and no key: INV-04."""
    text = "\n".join(p.read_text(errors="replace") for p in folder.glob("gateway-*.log"))
    found = [v for v in [*LEAKS, OWNER, TEAM, "ben.smit@acme.example"] if v in text]
    failures = [f"the log holds {len(found)} value(s) or key(s)"] if found else []
    print(f"  {'ok  ' if not failures else 'FAIL'} logs hold no content ({kind})", flush=True)
    return {"scenario": f"logs hold no content ({kind})", "outcome": {"lines": text.count("\n") > 0},
            "upstream": [], "leaked_upstream": [], "failures": failures, "ok": not failures}  # fmt: skip


def run_all(python: str, label: str) -> dict[str, Any]:
    workdir = Path(tempfile.mkdtemp(prefix="harpo-e2e-"))
    upstream = _start_recorder()
    rows: list[dict[str, Any]] = []
    version = subprocess.run([python, "-c", "import harpo_redact; print(harpo_redact.__version__)"],  # noqa: S603  # nosec B603
                             capture_output=True, text=True).stdout.strip()  # fmt: skip
    print(f"{label}: harpo-redact {version} ({python})")
    for kind, extra in (("main", {}), ("block", {"entities": {"EMAIL": {"action": "block", "overridable": True}},
                                                  "unsupported_content": "drop"})):  # fmt: skip
        folder = workdir / kind
        folder.mkdir()
        port = _free_port()
        config = _config(folder, port, upstream, extra)
        gateway = Gateway(python, config, port, folder)
        try:
            run = Run(gateway)
            (main_scenarios if kind == "main" else block_scenarios)(run)
            rows.extend(run.rows)
        finally:
            gateway.stop()
        rows.append(_log_check(kind, folder))
        if kind == "main":
            rows.extend(cli_scenarios(python, folder, config))
    shutil.rmtree(workdir, ignore_errors=True)
    failed = [r["scenario"] for r in rows if not r["ok"]]
    leaked = sorted({v for r in rows for v in r["leaked_upstream"]})
    print(f"{label}: {len(rows) - len(failed)} of {len(rows)} scenarios as intended; values that reached the provider: "
          f"{leaked or 'none'}")  # fmt: skip
    return {"label": label, "version": version, "scenarios": rows, "failed": failed, "leaked_upstream": leaked}


def compare(before: dict[str, Any], after: dict[str, Any]) -> int:
    """Scenario by scenario: what the client saw and what the provider received, before and after."""
    a = {r["scenario"]: r for r in before["scenarios"]}
    b = {r["scenario"]: r for r in after["scenarios"]}
    print(f"{before['label']} -> {after['label']}")
    same = 0
    for name in list(a) + [n for n in b if n not in a]:
        ra, rb = a.get(name), b.get(name)
        if ra is None or rb is None:
            print(f"  {'new' if ra is None else 'gone'}: {name}")
            continue
        changes = [part for part in ("outcome", "upstream", "ok") if ra[part] != rb[part]]
        if not changes:
            same += 1
            continue
        print(f"  changed: {name} ({', '.join(changes)}); ok {ra['ok']} -> {rb['ok']}; leaked to the provider "
              f"{ra['leaked_upstream'] or 'nothing'} -> {rb['leaked_upstream'] or 'nothing'}")  # fmt: skip
    print(f"  unchanged: {same}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--python", default=sys.executable, help="the interpreter of the build under test")
    parser.add_argument("--label", default="checkout")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--compare", nargs=2, type=Path, metavar=("BEFORE", "AFTER"))
    args = parser.parse_args(argv)
    if args.compare:
        return compare(*(json.loads(p.read_text()) for p in args.compare))
    result = run_all(args.python, args.label)
    if args.out:
        args.out.write_text(json.dumps(result, indent=1, ensure_ascii=False) + "\n")
    return 1 if result["failed"] or result["leaked_upstream"] else 0


if __name__ == "__main__":
    sys.exit(main())
