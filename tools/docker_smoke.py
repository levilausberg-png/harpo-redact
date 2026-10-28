"""Smoke-test Harpo the way the README deploys it, end to end.

    python tools/docker_smoke.py              # build the image, then test the containers (CI runs this)
    python tools/docker_smoke.py --no-build   # test the image that is already built (harpo-redact:<version>)
    python tools/docker_smoke.py --local      # the same cycle with local processes, for machines without Docker

The production compose file (docker-compose.yml: read-only root filesystem, no capabilities, the policy volume) runs
with a small override: the built-in fake provider as a second service and a test configuration with an app key and
an admin key, so no provider key and no internet access are needed. The demo compose file gets a shorter check.

In order: build; the shipped production example passes check-config; the demo answers with placeholders; the
gateway comes up healthy and ready; it runs as uid 10001 on a read-only root filesystem without capabilities; a
request in each API style, streamed and not, reaches the provider with placeholders only and is verified; an admin
key blocks EMAIL in the live policy and every worker enforces it; the block survives a restart and a recreated
container, then is reset; the logs hold none of the values sent; the gateway stops cleanly. Exit status 0 when
every step passed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
VERSION = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M).group(1)  # type: ignore[union-attr]
IMAGE = f"harpo-redact:{VERSION}"
PROJECT = "harpo-smoke"
PORT = 8080
BASE = f"http://127.0.0.1:{PORT}"
MOCK_PORT = 9100

# Invented values, one of each kind, and the kind of placeholder each must become. The key is made up per run.
FAKE_KEY = "AKIA" + "".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16))
VALUES = {
    "Priya Raman": "PERSON",
    "priya.raman@northwind.example": "EMAIL",
    "+31 20 794 6095": "PHONE",
    "NL91ABNA0417164300": "IBAN",
    "4111 1111 1111 1111": "CREDIT_CARD",
    FAKE_KEY: "SECRET",
}
PROMPT = (
    "Hi team, customer Priya Raman (priya.raman@northwind.example, +31 20 794 6095) asked for a refund to IBAN "
    f"NL91ABNA0417164300; card 4111 1111 1111 1111 was charged twice. The deploy key is {FAKE_KEY}. Draft a reply."
)
EMAIL_ONLY = "Please write to jane.doe@acme.example about the invoice."
NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # localhost, never through a proxy


class Failure(Exception):
    pass


def step(title: str) -> None:
    print(f"\n== {title}", flush=True)


def ok(message: str) -> None:
    print(f"   ok  {message}", flush=True)


def run(cmd: list[str], *, check: bool = True, capture: bool = False, env: dict[str, str] | None = None) -> str:
    print("   $ " + " ".join(cmd), flush=True)
    done = subprocess.run(cmd, check=False, text=True, capture_output=capture, env=env)  # noqa: S603
    if check and done.returncode != 0:
        detail = (done.stderr or done.stdout or "").strip()[-2000:] if capture else ""
        raise Failure(f"command failed with exit status {done.returncode}: {' '.join(cmd)}\n{detail}")
    return done.stdout if capture else ""


def call(method: str, path: str, key: str | None = None, body: Any = None, headers: dict[str, str] | None = None,
         timeout: float = 60) -> tuple[int, dict[str, str], bytes]:  # fmt: skip
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(BASE + path, data=data, method=method)  # noqa: S310  (a fixed localhost URL)
    request.add_header("content-type", "application/json")
    if key:
        request.add_header("authorization", f"Bearer {key}")
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    try:
        with NO_PROXY.open(request, timeout=timeout) as response:
            return response.status, {k.lower(): v for k, v in response.headers.items()}, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()


def wait_ready(timeout: float = 240) -> None:
    deadline = time.monotonic() + timeout
    last = "no answer"
    while time.monotonic() < deadline:
        try:
            status, _, body = call("GET", "/readyz", timeout=5)
            if status == 200:
                return
            last = f"{status} {body[:200]!r}"
        except OSError as exc:
            last = str(exc)
        time.sleep(2)
    raise Failure(f"the gateway was not ready within {timeout:.0f} s (last: {last})")


def check_sanitized(text: str, where: str) -> None:
    leaked = [value for value in VALUES if value in text]
    if leaked:
        raise Failure(f"{where}: values reached the provider: {leaked}")
    kinds = set(re.findall(r"\[([A-Z_]+?)_\d+\]", text))
    missing = sorted({kind for kind in VALUES.values() if kind not in kinds})
    if missing:
        raise Failure(f"{where}: no placeholder for {missing} (found {sorted(kinds)})")
    ok(f"{where}: the provider received {len(kinds)} kinds of placeholder and none of the values")


def openai_text(key: str, prompt: str = PROMPT, stream: bool = False) -> tuple[int, dict[str, str], str]:
    body = {"model": "demo-gpt", "messages": [{"role": "user", "content": prompt}], "stream": stream}
    status, headers, raw = call("POST", "/v1/chat/completions", key=key, body=body)
    if status != 200:
        return status, headers, raw.decode(errors="replace")
    if not stream:
        return status, headers, json.loads(raw)["choices"][0]["message"]["content"]
    events = [json.loads(line[6:]) for line in raw.decode().splitlines() if line.startswith("data: {")]
    parts = [choice.get("delta", {}).get("content") or "" for event in events for choice in event.get("choices", [])]
    return status, headers, "".join(parts)


def anthropic_text(key: str) -> str:
    body = {"model": "demo-claude", "max_tokens": 400, "messages": [{"role": "user", "content": PROMPT}]}
    status, _, raw = call(
        "POST", "/v1/messages", body=body, headers={"x-api-key": key, "anthropic-version": "2023-06-01"}
    )
    if status != 200:
        raise Failure(f"/v1/messages answered {status}: {raw[:300]!r}")
    return "".join(block.get("text", "") for block in json.loads(raw)["content"])


def check_requests(app_key: str) -> None:
    status, headers, text = openai_text(app_key)
    if status != 200:
        raise Failure(f"/v1/chat/completions answered {status}: {text[:300]}")
    check_sanitized(text, "OpenAI style")
    if int(headers.get("x-harpo-redactions", "0")) < len(VALUES):
        raise Failure(f"x-harpo-redactions is {headers.get('x-harpo-redactions')!r}, expected at least {len(VALUES)}")
    ok(f"x-harpo-redactions: {headers['x-harpo-redactions']}, risk {headers.get('x-harpo-risk')}")
    status, _, text = openai_text(app_key, stream=True)
    if status != 200:
        raise Failure(f"streamed /v1/chat/completions answered {status}: {text[:300]}")
    check_sanitized(text, "OpenAI style, streamed")
    check_sanitized(anthropic_text(app_key), "Anthropic style")
    status, _, _ = call("POST", "/v1/chat/completions", key="harpo_" + "x" * 43, body={"model": "demo-gpt"})
    if status != 401:
        raise Failure(f"an unknown gateway key got {status}, expected 401")
    ok("an unknown gateway key is refused (401)")


def email_outcomes(app_key: str, tries: int = 8) -> set[int]:
    return {openai_text(app_key, EMAIL_ONLY)[0] for _ in range(tries)}  # several tries reach every worker


def expect_email(app_key: str, status: int, why: str) -> None:
    seen = email_outcomes(app_key)
    if seen != {status}:
        raise Failure(f"{why}: a request with an email address got {sorted(seen)}, expected only {status}")
    ok(f"{why}: every request with an email address got {status}")


def smoke_config(upstream_host: str, app_hash: str, admin_hash: str) -> str:
    return f"""# Written by tools/docker_smoke.py. Development mode only because the fake provider speaks plain http.
environment: development
server: {{host: 0.0.0.0, port: {PORT}, workers: 2}}
auth:
  enabled: true
  keys:
    - {{id: smoke-app, sha256: {app_hash}}}
    - {{id: smoke-admin, sha256: {admin_hash}, admin: true}}
detection:
  ner:
    enabled: true
    language_models: {{de: de_core_news_sm, other: xx_ent_wiki_sm}}
upstreams:
  - {{name: mock-openai, style: openai, base_url: "http://{upstream_host}:{MOCK_PORT}/v1", models: [demo-gpt]}}
  - {{name: mock-anthropic, style: anthropic, base_url: "http://{upstream_host}:{MOCK_PORT}", models: [demo-claude]}}
"""


class Docker:
    """The containers, as docker compose runs them from the repository's compose files."""

    def __init__(self, tmp: Path, config: Path) -> None:
        self.override = tmp / "compose.smoke.yml"
        self.override.write_text(
            f"""services:
  gateway:
    volumes:
      - {{type: bind, source: "{config}", target: /etc/harpo/harpo.yaml, read_only: true}}
    depends_on: [mock]
  mock:
    image: {IMAGE}
    command: ["mock-upstream", "--host", "0.0.0.0", "--port", "{MOCK_PORT}"]
    read_only: true
    cap_drop: [ALL]
    healthcheck: {{disable: true}}
    networks: [internal]
"""
        )
        self.base = [
            "docker",
            "compose",
            "-p",
            PROJECT,
            "-f",
            str(ROOT / "docker-compose.yml"),
            "-f",
            str(self.override),
        ]
        self.earlier_logs = ""  # a recreated container starts a new log; keep the old one for the checks

    def compose(self, *args: str, capture: bool = False, check: bool = True) -> str:
        return run([*self.base, *args], capture=capture, check=check)

    def container(self) -> str:
        cid = self.compose("ps", "-q", "gateway", capture=True).strip()
        if not cid:
            raise Failure("the gateway container is not running")
        return cid

    def inspect(self) -> dict[str, Any]:
        return json.loads(run(["docker", "inspect", self.container()], capture=True))[0]  # type: ignore[no-any-return]

    def start(self) -> None:
        self.compose("up", "-d", "--no-build")

    def restart(self) -> None:
        self.compose("restart", "gateway")

    def recreate(self) -> None:
        self.earlier_logs = self.logs()  # logs() already holds the earlier ones
        self.compose("up", "-d", "--no-build", "--no-deps", "--force-recreate", "gateway")

    def logs(self) -> str:
        return self.earlier_logs + self.compose("logs", "--no-color", "gateway", capture=True)

    def wait_healthy(self, timeout: float = 150) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state = self.inspect()["State"]
            if state.get("Health", {}).get("Status") == "healthy":
                ok("Docker reports the container healthy (the image's own HEALTHCHECK)")
                return
            if state["Status"] in ("exited", "dead"):
                raise Failure(f"the gateway container stopped: exit status {state.get('ExitCode')}")
            time.sleep(3)
        raise Failure("Docker did not report the container healthy in time")

    def check_hardening(self) -> None:
        info = self.inspect()
        config, host = info["Config"], info["HostConfig"]
        if config.get("User") != "10001:10001":
            raise Failure(f"the container runs as {config.get('User')!r}, expected 10001:10001")
        if not host.get("ReadonlyRootfs"):
            raise Failure("the root filesystem is writable")
        if host.get("CapDrop") != ["ALL"]:
            raise Failure(f"capabilities dropped: {host.get('CapDrop')!r}, expected ALL")
        if not any("no-new-privileges" in opt for opt in host.get("SecurityOpt") or []):
            raise Failure("no-new-privileges is not set")
        uid = self.compose("exec", "-T", "gateway", "python", "-c", "import os; print(os.getuid())", capture=True)
        if uid.strip() != "10001":
            raise Failure(f"the gateway process runs as uid {uid.strip()}")
        probe = ["python", "-c", "open('/opt/venv/harpo-smoke-write-test', 'w')"]
        if subprocess.run([*self.base, "exec", "-T", "gateway", *probe], capture_output=True).returncode == 0:  # noqa: S603
            raise Failure("the gateway could write to its root filesystem")
        ok("uid 10001, read-only root filesystem, no capabilities, no-new-privileges")

    def stop(self) -> None:
        self.compose("stop", "gateway")
        code = self.inspect_stopped()
        if code != 0:
            raise Failure(f"the gateway exited with status {code} on docker compose stop")
        ok("the gateway stopped on SIGTERM with exit status 0")

    def inspect_stopped(self) -> int:
        cid = self.compose("ps", "-a", "-q", "gateway", capture=True).strip()
        return int(json.loads(run(["docker", "inspect", cid], capture=True))[0]["State"]["ExitCode"])

    def down(self) -> None:
        self.compose("down", "-v", "--remove-orphans", check=False)

    def check_example_config(self) -> None:
        env = ["-e", "OPENAI_API_KEY=smoke", "-e", "ANTHROPIC_API_KEY=smoke", "-e", "GEMINI_API_KEY=smoke"]
        mount = ["-v", f"{ROOT / 'config' / 'harpo.example.yaml'}:/etc/harpo/harpo.yaml:ro"]
        out = run(["docker", "run", "--rm", *env, *mount, IMAGE, "check-config"], capture=True)
        if "ok: production configuration" not in out:
            raise Failure(f"check-config on the example said: {out.strip()}")
        ok(out.strip().splitlines()[-1])

    def demo(self, check: Callable[[], None]) -> None:
        base = ["docker", "compose", "-p", PROJECT + "-demo", "-f", str(ROOT / "docker-compose.demo.yml")]
        try:
            run([*base, "up", "-d", "--no-build", "gateway"])
            check()
        finally:
            run([*base, "down", "-v", "--remove-orphans"], check=False)


class Local:
    """The same cycle with local processes: what a machine without Docker can check."""

    def __init__(self, tmp: Path, config: Path) -> None:
        self.tmp, self.config = tmp, config
        self.log = tmp / "gateway.log"
        self.env = {**os.environ, "HARPO_POLICY__LIVE_FILE": str(tmp / "state" / "policy.live.yaml"),
                    "HARPO_NO_BANNER": "1"}  # fmt: skip
        (tmp / "state").mkdir()
        self.gateway: subprocess.Popen[bytes] | None = None
        self.mock: subprocess.Popen[bytes] | None = None

    def harpo(self, *args: str, log: Path | None = None) -> subprocess.Popen[bytes]:
        out = open(log, "ab") if log else subprocess.DEVNULL  # noqa: SIM115
        return subprocess.Popen([sys.executable, "-m", "harpo_redact", *args], stdout=out, stderr=subprocess.STDOUT,  # noqa: S603
                                env=self.env)  # fmt: skip

    def start(self) -> None:
        self.mock = self.harpo("mock-upstream", "--host", "127.0.0.1", "--port", str(MOCK_PORT))
        self.gateway = self.harpo("serve", "--config", str(self.config), log=self.log)

    def terminate(self) -> int:
        assert self.gateway is not None
        self.gateway.send_signal(signal.SIGTERM)
        return self.gateway.wait(timeout=30)

    def restart(self) -> None:
        code = self.terminate()
        if code != 0:
            raise Failure(f"the gateway exited with status {code} on SIGTERM")
        self.gateway = self.harpo("serve", "--config", str(self.config), log=self.log)

    recreate = restart

    def logs(self) -> str:
        return self.log.read_text(errors="replace")

    def wait_healthy(self) -> None:
        ok("(no container health status without Docker)")

    def check_hardening(self) -> None:
        ok("(container hardening is checked only with Docker)")

    def stop(self) -> None:
        code = self.terminate()
        if code != 0:
            raise Failure(f"the gateway exited with status {code} on SIGTERM")
        ok("the gateway stopped on SIGTERM with exit status 0")

    def down(self) -> None:
        for proc in (self.gateway, self.mock):
            if proc and proc.poll() is None:
                proc.kill()
                proc.wait()

    def check_example_config(self) -> None:
        env = {**self.env, "OPENAI_API_KEY": "smoke", "ANTHROPIC_API_KEY": "smoke", "GEMINI_API_KEY": "smoke"}
        cmd = [
            sys.executable,
            "-m",
            "harpo_redact",
            "check-config",
            "--config",
            str(ROOT / "config" / "harpo.example.yaml"),
        ]
        done = subprocess.run(cmd, capture_output=True, text=True, env=env, check=False)  # noqa: S603
        if done.returncode != 0 or "ok: production configuration" not in done.stdout:
            raise Failure(f"check-config on the example said: {(done.stdout + done.stderr).strip()}")
        ok(done.stdout.strip().splitlines()[-1])

    def demo(self, check: Callable[[], None]) -> None:
        proc = self.harpo("demo", "--host", "127.0.0.1", "--port", str(PORT), "--no-browser")
        try:
            check()
        finally:
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=30)


def demo_check() -> None:
    wait_ready()
    status, _, text = openai_text("demo")
    if status != 200:
        raise Failure(f"the demo answered {status}: {text[:300]}")
    check_sanitized(text, "the demo")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--no-build", action="store_true", help=f"use the {IMAGE} image as it is")
    parser.add_argument("--local", action="store_true", help="local processes instead of containers (no Docker)")
    parser.add_argument("--keep", action="store_true", help="leave everything running after a failure")
    args = parser.parse_args(argv)

    app_key, admin_key = (f"harpo_{secrets.token_urlsafe(32)}" for _ in range(2))
    tmp = Path(tempfile.mkdtemp(prefix="harpo-smoke-"))
    config = tmp / "harpo.yaml"
    config.write_text(smoke_config("127.0.0.1" if args.local else "mock", *(hashlib.sha256(k.encode()).hexdigest()
                                                                           for k in (app_key, admin_key))))  # fmt: skip
    config.chmod(0o644)  # the container user reads it
    target: Docker | Local = Local(tmp, config) if args.local else Docker(tmp, config)
    started = time.monotonic()
    try:
        if not args.local and not args.no_build:
            step(f"Build {IMAGE}")
            run(["docker", "compose", "-f", str(ROOT / "docker-compose.yml"), "build", "gateway"])
        step("The shipped production example passes check-config")
        target.check_example_config()
        step("The demo answers, with placeholders")
        target.demo(demo_check)
        step("Production compose: up, healthy, ready")
        target.start()
        wait_ready()
        ok("/readyz answers 200")
        target.wait_healthy()
        status, _, _ = call("GET", "/healthz")
        if status != 200:
            raise Failure(f"/healthz answered {status}")
        ok("/healthz answers 200")
        step("Hardening")
        target.check_hardening()
        step("Sanitized requests")
        check_requests(app_key)
        step("Live policy: an admin key blocks EMAIL; every worker enforces it")
        expect_email(app_key, 200, "before")
        status, _, raw = call("PUT", "/v1/policy/live", key=app_key, body={"entities": {"EMAIL": "block"}})
        if status != 403:
            raise Failure(f"an app key changed the live policy ({status})")
        ok("an app key cannot change the live policy (403)")
        status, _, raw = call("PUT", "/v1/policy/live", key=admin_key, body={"entities": {"EMAIL": "block"}})
        if status != 200:
            raise Failure(f"saving the live policy answered {status}: {raw[:300]!r}")
        time.sleep(5)  # the other worker notices the file within its watch interval (2 s)
        expect_email(app_key, 403, "after the change")
        step("Restart: the policy holds")
        target.restart()
        wait_ready()
        expect_email(app_key, 403, "after a restart")
        step("Recreate the container: the policy, on its volume, holds; then reset it")
        target.recreate()
        wait_ready()
        expect_email(app_key, 403, "after a recreate")
        status, _, raw = call("DELETE", "/v1/policy/live", key=admin_key)
        if status != 200:
            raise Failure(f"resetting the live policy answered {status}: {raw[:300]!r}")
        time.sleep(5)
        expect_email(app_key, 200, "after the reset")
        step("Logs: no content, and the policy changes are audited")
        logs = target.logs()
        leaked = [value for value in [*VALUES, "jane.doe@acme.example"] if value in logs]
        if leaked:
            raise Failure(f"values sent appear in the gateway's logs: {leaked}")
        ok(f"{len(logs.splitlines())} log lines, none with a value sent")
        for event in ("policy_changed", "policy_reset"):
            if event not in logs:
                raise Failure(f"no {event} audit line in the logs")
        ok("policy_changed and policy_reset are audited")
        step("Shutdown")
        target.stop()
    except Failure as exc:
        print(f"\nFAILED: {exc}", file=sys.stderr)
        try:
            print(
                "\n-- gateway logs (last 80 lines) --\n" + "\n".join(target.logs().splitlines()[-80:]), file=sys.stderr
            )
        except Exception as log_error:
            print(f"(no logs: {log_error})", file=sys.stderr)
        if args.keep:
            print(f"left running; files in {tmp}", file=sys.stderr)
            return 1
        target.down()
        return 1
    target.down()
    print(f"\nSmoke test passed in {time.monotonic() - started:.0f} s.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
