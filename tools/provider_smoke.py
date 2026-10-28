"""Smoke-test Harpo against your real providers, before you put it in front of people.

    python tools/provider_smoke.py --start --openai-model gpt-5-mini --anthropic-model claude-haiku-5-5
    python tools/provider_smoke.py --key harpo_... --openai-model gpt-5-mini     # against a gateway already running

--start runs its own gateway (production mode, a gateway key made up for the run) for whichever of OPENAI_API_KEY and
ANTHROPIC_API_KEY is set, and stops it afterwards; it needs harpo-redact installed in the same Python. Without a
terminal: add the keys as repository secrets and run the provider-smoke workflow from the Actions tab.

For each API style given a model: a plain request with personal data, the same request streamed, a tool call and its
result, a provider error (a parameter out of range), and a stream cancelled halfway, after which the gateway must still
answer. Every value sent is invented, and every answer is checked for those values: the provider only ever saw
placeholders, so no answer can contain them. Costs a few cents of tokens. Exit status 0 when every check passed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

VALUES = ["Priya Raman", "priya.raman@northwind.example", "+31 20 794 6095", "NL91ABNA0417164300"]
PROMPT = (
    "Repeat the text between the markers exactly, then say in one sentence what it asks for.\n<<<\nHi team, customer "
    "Priya Raman (priya.raman@northwind.example, +31 20 794 6095) asked us to refund invoice INV-2026-000123 to IBAN "
    "NL91ABNA0417164300.\n>>>"
)
TOOL_ASK = "Look up the customer priya.raman@northwind.example with the tool, then summarise the result."
TOOL_RESULT = "Customer Priya Raman, IBAN NL91ABNA0417164300, phone +31 20 794 6095, status: gold, since 2019."
SCHEMA = {"type": "object", "properties": {"email": {"type": "string"}}, "required": ["email"]}
PLACEHOLDER = re.compile(r"\[[A-Z_]+_\d+\]")


class Check(Exception):
    pass


class Gateway:
    def __init__(self, base: str, key: str) -> None:
        self.base, self.key = base.rstrip("/"), key
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def open(self, path: str, body: dict[str, Any], style: str, timeout: float = 120) -> Any:
        headers = {"content-type": "application/json"}
        if style == "openai":
            headers["authorization"] = f"Bearer {self.key}"
        else:
            headers.update({"x-api-key": self.key, "anthropic-version": "2023-06-01"})
        request = urllib.request.Request(self.base + path, json.dumps(body).encode(), headers, method="POST")  # noqa: S310
        return self.opener.open(request, timeout=timeout)

    def post(self, path: str, body: dict[str, Any], style: str) -> tuple[int, dict[str, str], Any]:
        try:
            with self.open(path, body, style) as response:
                return response.status, dict(response.headers), json.loads(response.read())
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, dict(exc.headers), json.loads(raw)
            except ValueError:
                return exc.code, dict(exc.headers), raw.decode(errors="replace")


def clean(text: str, where: str) -> None:
    leaked = [value for value in VALUES if value in text]
    if leaked:
        raise Check(f"{where} contains {leaked}: the provider must never have seen them")


class Style:
    """One provider API style: how to ask, stream, call a tool and read the answer."""

    def __init__(self, gateway: Gateway, style: str, model: str) -> None:
        self.gw, self.style, self.model = gateway, style, model
        self.path = "/v1/chat/completions" if style == "openai" else "/v1/messages"

    def body(self, messages: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
        body: dict[str, Any] = {"model": self.model, "messages": messages, **extra}
        if self.style == "anthropic":
            body.setdefault("max_tokens", 400)
        return body

    def text(self, answer: Any) -> str:
        if self.style == "openai":
            return answer["choices"][0]["message"].get("content") or ""
        return "".join(block.get("text", "") for block in answer["content"])

    def plain(self) -> str:
        status, headers, answer = self.gw.post(self.path, self.body([{"role": "user", "content": PROMPT}]), self.style)
        if status != 200:
            raise Check(f"status {status}: {str(answer)[:300]}")
        reply = self.text(answer)
        clean(reply, "the answer")
        redactions = {k.lower(): v for k, v in headers.items()}.get("x-harpo-redactions", "0")
        if int(redactions) < len(VALUES):
            raise Check(f"x-harpo-redactions is {redactions}, expected at least {len(VALUES)}")
        echoed = sorted(set(PLACEHOLDER.findall(reply)))
        return f"{redactions} values redacted; the model repeated {', '.join(echoed) or 'no placeholders'}"

    def streamed(self) -> str:
        body = self.body([{"role": "user", "content": PROMPT}], stream=True)
        parts, done = [], False
        with self.gw.open(self.path, body, self.style) as response:
            for raw in response:
                line = raw.decode().strip()
                if not line.startswith("data: "):
                    continue
                if line == "data: [DONE]":
                    done = True
                    continue
                event = json.loads(line[6:])
                if self.style == "openai":
                    parts += [c.get("delta", {}).get("content") or "" for c in event.get("choices", [])]
                elif event.get("type") == "content_block_delta":
                    parts.append(event["delta"].get("text", ""))
                elif event.get("type") == "message_stop":
                    done = True
        reply = "".join(parts)
        clean(reply, "the streamed answer")
        if not reply or not done:
            raise Check(f"the stream ended early ({len(reply)} characters, end marker {'seen' if done else 'missing'})")
        return f"{len(reply)} characters, ended properly"

    def tool(self) -> str:
        ask = [{"role": "user", "content": TOOL_ASK}]
        if self.style == "openai":
            tools = [{"type": "function", "function": {"name": "lookup_customer", "parameters": SCHEMA}}]
            choice: dict[str, Any] = {"type": "function", "function": {"name": "lookup_customer"}}
        else:
            tools = [{"name": "lookup_customer", "description": "Find a customer by email", "input_schema": SCHEMA}]
            choice = {"type": "tool", "name": "lookup_customer"}
        status, _, answer = self.gw.post(self.path, self.body(ask, tools=tools, tool_choice=choice), self.style)
        if status != 200:
            raise Check(f"tool call: status {status}: {str(answer)[:300]}")
        if self.style == "openai":
            message = answer["choices"][0]["message"]
            if not message.get("tool_calls"):
                raise Check("the model answered without calling the tool, although tool_choice named it")
            call = message["tool_calls"][0]
            arguments = call["function"]["arguments"]
            follow = [*ask, message, {"role": "tool", "tool_call_id": call["id"], "content": TOOL_RESULT}]
        else:
            use = next((block for block in answer["content"] if block["type"] == "tool_use"), None)
            if use is None:
                raise Check("the model answered without calling the tool, although tool_choice named it")
            arguments = json.dumps(use["input"])
            result = {"type": "tool_result", "tool_use_id": use["id"], "content": TOOL_RESULT}
            follow = [*ask, {"role": "assistant", "content": answer["content"]}, {"role": "user", "content": [result]}]
        clean(arguments, "the tool call's arguments")
        status, _, final = self.gw.post(self.path, self.body(follow, tools=tools), self.style)
        if status != 200:
            raise Check(f"tool result: status {status}: {str(final)[:300]}")
        clean(self.text(final), "the answer after the tool result")
        return f"the model called the tool with {arguments}; the result went back redacted"

    def provider_error(self) -> str:
        body = self.body([{"role": "user", "content": PROMPT}], temperature=5)
        status, _, answer = self.gw.post(self.path, body, self.style)
        if status != 400 or not isinstance(answer, dict) or "error" not in answer:  # 400: the provider refused it
            raise Check(f"expected the provider's 400 in the {self.style} format, got {status}: {str(answer)[:300]}")
        clean(json.dumps(answer), "the error")
        error = answer["error"]
        return f"{status} {error.get('type', '')}: {str(error.get('message', ''))[:90]}"

    def cancelled(self) -> str:
        body = self.body([{"role": "user", "content": "Count from 1 to 400, one number per line."}], stream=True)
        response = self.gw.open(self.path, body, self.style)
        first = response.readline()
        response.close()  # hang up mid-answer
        if not first:
            raise Check("the stream sent nothing before the hang-up")
        started = time.monotonic()
        self.plain()
        return f"hung up after the first event; the next request answered in {time.monotonic() - started:.1f} s"


def start_gateway(models: dict[str, str | None]) -> tuple[subprocess.Popen[bytes], str, str]:
    """Run `harpo serve` in production mode for the providers asked for, with a gateway key made up for this run.

    The provider keys stay in the environment; the configuration holds only the gateway key's hash."""
    import yaml

    from harpo_redact.presets import PROVIDERS

    upstreams = []
    for name, model in models.items():
        if not model:
            continue
        style, base_url, key_env, patterns = PROVIDERS[name]
        if not key_env or not os.environ.get(key_env):
            raise SystemExit(f"--{name}-model needs {key_env} in the environment")
        upstreams.append(
            {"name": name, "style": style, "base_url": base_url, "api_key_env": key_env, "models": patterns}
        )
    key = "harpo_" + secrets.token_urlsafe(32)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    folder = tempfile.mkdtemp(prefix="harpo-provider-smoke-")
    config = {
        "environment": "production",
        "server": {"host": "127.0.0.1", "port": port, "workers": 1},
        "auth": {
            "enabled": True,
            "keys": [{"id": "provider-smoke", "sha256": hashlib.sha256(key.encode()).hexdigest()}],
        },
        "upstreams": upstreams,
    }
    path = os.path.join(folder, "harpo.yaml")
    with open(path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(config, fh, sort_keys=False)
    log_path = os.path.join(folder, "gateway.log")
    command = [sys.executable, "-m", "harpo_redact", "serve", "--config", path]
    env = {**os.environ, "HARPO_NO_BANNER": "1"}
    with open(log_path, "wb") as log:
        proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=env)  # noqa: S603
    base = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        try:
            with opener.open(base + "/readyz", timeout=5) as response:
                if response.status == 200:
                    print(f"gateway up on {base} for {', '.join(u['name'] for u in upstreams)}")
                    return proc, base, key
        except OSError:
            pass
        time.sleep(1)
    proc.kill()
    with open(log_path, encoding="utf-8", errors="replace") as fh:
        tail = fh.read().splitlines()[-30:]
    raise SystemExit("the gateway did not start:\n" + "\n".join(tail))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", default="http://127.0.0.1:8080", help="the gateway (default %(default)s)")
    parser.add_argument("--key", default=os.environ.get("HARPO_KEY"), help="a gateway key (or HARPO_KEY)")
    parser.add_argument("--openai-model", help="a model your OpenAI-style upstream allows")
    parser.add_argument("--anthropic-model", help="a model your Anthropic-style upstream allows")
    parser.add_argument(
        "--start", action="store_true", help="run a gateway for this test, with keys from the environment"
    )
    args = parser.parse_args(argv)
    if not (args.openai_model or args.anthropic_model):
        parser.error("needs at least one of --openai-model, --anthropic-model")
    started = None
    if args.start:
        started, args.base, args.key = start_gateway({"openai": args.openai_model, "anthropic": args.anthropic_model})
    elif not args.key:
        parser.error("needs --key (or HARPO_KEY), or --start")
    try:
        return run_checks(Gateway(args.base, args.key), args.openai_model, args.anthropic_model)
    finally:
        if started is not None:
            started.send_signal(signal.SIGTERM)
            started.wait(timeout=30)


def run_checks(gateway: Gateway, openai_model: str | None, anthropic_model: str | None) -> int:
    failed = 0
    for style, model in (("openai", openai_model), ("anthropic", anthropic_model)):
        if not model:
            continue
        api = Style(gateway, style, model)
        print(f"\n{style} style, {model}")
        checks: list[tuple[str, Callable[[], str]]] = [
            ("request", api.plain),
            ("streaming", api.streamed),
            ("tools", api.tool),
            ("provider error", api.provider_error),
            ("cancellation", api.cancelled),
        ]
        for name, check in checks:
            try:
                print(f"  pass  {name:15} {check()}")
            except (Check, OSError, KeyError, IndexError, ValueError) as exc:
                failed += 1
                hint = "  (is the provider key right?)" if "401" in str(exc) else ""
                print(f"  FAIL  {name:15} {type(exc).__name__}: {exc}{hint}")
    print("\nall checks passed" if not failed else f"\n{failed} check(s) failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
