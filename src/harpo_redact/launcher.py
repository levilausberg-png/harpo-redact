"""`harpo up | down | status`: start everything with one command, stop it with another.

The boot scripts (boot.ps1, boot.cmd, boot.sh) and stop scripts call these. State lives in .harpo/ next to the
config: pid files, logs, the gateway key and provider keys (the last two readable by you only). `up` starts Ollama
only when it is not running already, and `down` stops only what `up` started.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import importlib.util
import json
import os
import secrets
import shutil
import signal
import subprocess  # nosec B404  (fixed argument lists, never a shell)
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path
from typing import Any

import yaml

from . import KEY_PREFIX, banner
from .presets import COMPANIONS, MODEL_WHEELS, PROVIDERS, installed_language_models

STATE = Path(".harpo")
OLLAMA = (
    os.environ.get("HARPO_OLLAMA_URL") or os.environ.get("PRIVATEAI_OLLAMA_URL") or "http://127.0.0.1:11434"
).rstrip("/")  # another host works too; PRIVATEAI_OLLAMA_URL is the name before the rename
SUITES = ["gateway", "detection", "secrets", "egress", "slm"]
MARKS = dict(zip(("pass", "fail", "skip"), ("✓", "✗", "-"), strict=True))
_LOCAL = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # localhost must never go through a proxy


def say(msg: str = "") -> None:
    print(msg, flush=True)


def http(method: str, url: str, body: Any = None, key: str | None = None, timeout: float = 5.0) -> tuple[int, Any]:
    headers = {"content-type": "application/json"}
    if key:
        headers["authorization"] = f"Bearer {key}"
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with _LOCAL.open(req, timeout=timeout) as r:  # nosec B310  (http to localhost only)
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    except (urllib.error.URLError, OSError, TimeoutError):
        return 0, None
    try:
        return status, json.loads(raw or b"null")
    except ValueError:
        return status, None


def write_private(path: Path, text: str) -> None:
    """Create a file only the current user can read."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32":
        path.write_text(text, encoding="utf-8")
        user = os.environ.get("USERNAME")
        if user:
            grant = ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"]
            subprocess.run(grant, capture_output=True, check=False)  # nosec
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(path, 0o600)


def read_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            name, sep, value = line.partition("=")
            if sep and name.strip() and not name.lstrip().startswith("#"):
                out[name.strip()] = value.strip()
    return out


def alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes

        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(handle)
        return code.value == 259  # STILL_ACTIVE
    try:
        if os.waitpid(pid, os.WNOHANG)[0] == pid:
            return False  # our own child, already exited
    except ChildProcessError:
        pass
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    stat = Path(f"/proc/{pid}/stat")
    return not (stat.exists() and ") Z " in stat.read_text())


def stop_pid(pid: int) -> bool:
    if not alive(pid):
        return False
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, check=False)  # nosec
        return True
    os.kill(pid, signal.SIGTERM)
    for _ in range(100):
        if not alive(pid):
            return True
        time.sleep(0.1)
    os.kill(pid, signal.SIGKILL)
    return True


def spawn(cmd: list[str], log: Path, env: dict[str, str] | None = None) -> int:
    """Start a background process that outlives this one, with its output in `log`."""
    log.parent.mkdir(parents=True, exist_ok=True)
    io: dict[str, Any] = {"stderr": subprocess.STDOUT, "stdin": subprocess.DEVNULL, "env": env}
    with open(log, "ab") as out:
        if sys.platform == "win32":
            flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
            proc = subprocess.Popen(cmd, stdout=out, creationflags=flags, **io)  # nosec
        else:
            proc = subprocess.Popen(cmd, stdout=out, start_new_session=True, **io)  # nosec
    return proc.pid


def read_pid(path: Path) -> int:
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return 0


def tail(path: Path, n: int = 25) -> str:
    try:
        return "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[-n:])
    except OSError:
        return ""


def ensure_models() -> None:
    """Install the hash-pinned MIT spaCy models the Docker image ships, once."""
    missing = [(name, url, sha) for name, (url, sha) in MODEL_WHEELS.items() if importlib.util.find_spec(name) is None]
    if not missing:
        return
    say(f"  · installing {len(missing)} detection model(s), hash-checked (one time, about 50 MB)")
    for name, url, sha in missing:
        pip = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "-q", "--no-deps"]
        if subprocess.run([*pip, f"{url}#sha256={sha}"], check=False).returncode != 0:  # nosec
            say(f"  ! could not install {name}: names in that language are found by rules only until it is")
    importlib.invalidate_caches()


def ollama_binary() -> str | None:
    found = shutil.which("ollama")
    if found:
        return found
    if sys.platform == "win32":
        candidates = [os.path.expandvars(r"%LOCALAPPDATA%\Programs\Ollama\ollama.exe")]
    else:
        candidates = [
            "/Applications/Ollama.app/Contents/Resources/ollama",
            "/usr/local/bin/ollama",
            "/opt/homebrew/bin/ollama",
        ]
    return next((c for c in candidates if Path(c).exists()), None)


def ollama_models(url: str | None = None) -> list[dict[str, Any]] | None:
    status, body = http("GET", f"{url or OLLAMA}/api/tags", timeout=3)  # read at call time: OLLAMA can be overridden
    return body.get("models", []) if status == 200 and isinstance(body, dict) else None


def pick_model(models: list[dict[str, Any]], wanted: str) -> dict[str, Any] | None:
    """`phi3:latest` when present, else another tag of the same model (`phi3:mini`), never a different model."""
    names = {str(m.get("name") or m.get("model")): m for m in models}
    if wanted in names:
        return names[wanted]
    base = wanted.split(":")[0]
    if f"{base}:latest" in names:
        return names[f"{base}:latest"]
    same = sorted(n for n in names if n.split(":")[0] == base)
    return names[same[0]] if same else None


def start_ollama(state: Path) -> bool:
    binary = ollama_binary()
    if binary is None:
        return False
    say("  · starting Ollama (it was not running)")
    pid = spawn([binary, "serve"], state / "ollama.log")
    (state / "ollama.pid").write_text(str(pid))
    for _ in range(60):
        if ollama_models() is not None:
            return True
        time.sleep(0.5)
    return False


def pull(model: str) -> None:
    binary = ollama_binary()
    if binary:
        subprocess.run([binary, "pull", model], check=False)  # nosec
    else:
        http("POST", f"{OLLAMA}/api/pull", {"name": model, "stream": False}, timeout=3600)


def local_model(args: argparse.Namespace, state: Path) -> dict[str, Any] | None:
    """Find (and if needed start) Ollama and the wanted model. Returns its name and digest, or None."""
    if ollama_models() is None and not start_ollama(state):
        say("  ! Ollama is not installed or not reachable: continuing without the local model.")
        say("    Install it from https://ollama.com/download, then boot again.")
        return None
    models = ollama_models() or []
    found = pick_model(models, args.slm_model)
    ask = f"  ? {args.slm_model} is not installed. Download it now? [y/N] "
    if found is None and (args.pull or (sys.stdin.isatty() and input(ask).strip().lower() == "y")):
        pull(args.slm_model)
        found = pick_model(ollama_models() or [], args.slm_model)
    if found is None:
        names = ", ".join(sorted(str(m.get("name")) for m in models)) or "none"
        say(f"  ! {args.slm_model} is not in Ollama (installed: {names}).")
        say(f"    Run `ollama pull {args.slm_model}`, or pass --slm-model with one of those.")
        return None
    digest = str(found.get("digest", "")).lower().removeprefix("sha256:")
    return {"model": str(found.get("name") or found.get("model")), "digest": digest or None}


def render_config(
    provider: str, key_sha: str, port: int, slm: dict[str, Any] | None, *, host: str = "127.0.0.1", origin: str = "up"
) -> str:
    """The config file `up` (the boot scripts) and `init` write: one provider, a gateway key, safe defaults."""
    style, base_url, env_name, models = PROVIDERS[provider]
    production = base_url.startswith("https://") and env_name is not None
    langs = "".join(f"\n      {k}: {v}" for k, v in installed_language_models().items()) or " {}"
    writer = "`harpo up` (the boot scripts)" if origin == "up" else "`harpo init`"
    lines = [
        f"# Written by {writer}. Every option: config/harpo.example.yaml.",
        f"environment: {'production' if production else 'development'}",
        "server:",
        f"  host: {host}",
        f"  port: {port}",
        "auth:",
        "  enabled: true",
        "  keys:",
        "    - id: owner",
        f"      sha256: {key_sha}",
        "      admin: true             # sees all activity in the console",
        "upstreams:",
    ]
    entries = [(provider, style, base_url, env_name, models), *COMPANIONS.get(provider, [])]
    for name, u_style, u_url, u_env, u_models in entries:
        lines += [
            f"  - name: {name}",
            f"    style: {u_style}",
            f"    base_url: {u_url}",
            *([f"    api_key_env: {u_env}"] if u_env else []),
            # quoted: a bare * would be a YAML alias
            f"    models: [{', '.join(json.dumps(m) for m in u_models)}]",
        ]
        if "openrouter.ai" in u_url:
            lines += [
                "    openrouter:",
                "      data_collection: deny     # only providers that do not store prompts; clients cannot loosen it",
                "      zdr: false                # true: zero-data-retention endpoints only (strictest, fewer models)",
            ]
    lines += [
        "policy:",
        "  live_file: policy.live.yaml  # the console's Policy page saves here, next to this file",
        "detection:",
        "  ner:",
        f"    language_models:{langs}",
    ]
    if slm:
        lines += [
            "  slm:",
            "    enabled: true",
            f"    base_url: {OLLAMA}",
            f"    model: {slm['model']}",
            *([f"    model_digest: sha256:{slm['digest']}"] if slm.get("digest") else []),
            f"    timeout_ms: {slm['timeout_ms']}",
            f"    on_failure: {slm['on_failure']}",
            "    keep_alive: 30m",
        ]
    return "\n".join(lines) + "\n"


def choose_provider(given: str | None) -> str:
    if given:
        return given
    names = sorted(PROVIDERS)
    if not sys.stdin.isatty():
        raise SystemExit("error: the first run needs a provider: pass --provider (" + ", ".join(names) + ")")
    say("\n  Where should requests go?")
    for i, name in enumerate(names, 1):
        say(f"    {i}. {name:<11} {PROVIDERS[name][1]}")
    while True:
        answer = input("  Number or name [openai]: ").strip().lower() or "openai"
        if answer in PROVIDERS:
            return answer
        if answer.isdigit() and 1 <= int(answer) <= len(names):
            return names[int(answer) - 1]


def provider_env(provider: str, state: Path, env: dict[str, str]) -> None:
    """Make the provider key available to the gateway: environment first, then .harpo/.env, else ask once."""
    name = PROVIDERS[provider][2]
    if not name or env.get(name):
        return
    stored = read_env(state / ".env")
    if stored.get(name):
        env[name] = stored[name]
        return
    if not sys.stdin.isatty():
        say(f"  ! {name} is not set: the gateway does not start without it (set it, or add it to .harpo/.env)")
        return
    value = getpass.getpass(f"  {name} (hidden; stored in .harpo/.env, readable only by you): ").strip()
    if value:
        stored[name] = value
        write_private(state / ".env", "".join(f"{k}={v}\n" for k, v in stored.items()))
        env[name] = value


def copy_to_clipboard(text: str) -> bool:
    tools = (
        ["clip"],
        ["pbcopy"],
        ["wl-copy"],
        ["xclip", "-selection", "clipboard"],
        ["xsel", "--clipboard", "--input"],
    )
    for cmd in tools:
        if not shutil.which(cmd[0]):
            continue
        data = text.encode("utf-16le" if cmd[0] == "clip" else "utf-8")
        try:
            subprocess.run(cmd, input=data, check=True, timeout=5, capture_output=True)  # nosec
            return True
        except (subprocess.SubprocessError, OSError):
            continue
    return False


def slm_block(slm: dict[str, Any]) -> dict[str, Any]:
    pin = {"model_digest": f"sha256:{slm['digest']}"} if slm.get("digest") else {}
    return {"enabled": True, "base_url": OLLAMA, "model": slm["model"], **pin, "timeout_ms": slm["timeout_ms"],
            "on_failure": slm["on_failure"], "keep_alive": "30m"}  # fmt: skip


def update_slm_block(cfg_path: Path, slm: dict[str, Any] | None, want: bool) -> str | None:
    """Keep an existing config in step with the local model: add it, turn it off, or report a changed digest."""
    data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    current = (data.get("detection") or {}).get("slm") or {}
    if want and slm and not current.get("enabled"):
        data.setdefault("detection", {})["slm"] = slm_block(slm)
        cfg_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        return f"added {slm['model']} to {cfg_path}"
    if not want and current.get("enabled"):
        data["detection"]["slm"]["enabled"] = False
        cfg_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        return f"turned the local model off in {cfg_path}"
    pinned = str(current.get("model_digest") or "").lower().removeprefix("sha256:")
    if want and slm and current.get("enabled") and pinned and slm.get("digest") and pinned != slm["digest"]:
        say(f"  ! {slm['model']} changed since it was pinned, so the gateway treats it as unavailable.")
        say("    Trust the new version with --reconfigure.")
    return None


def _meta(state: Path) -> dict[str, Any]:
    path = state / "boot.json"
    return json.loads(path.read_text()) if path.exists() else {}


def _utf8_safe() -> None:
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure:
        reconfigure(errors="replace")


def adopt_legacy_state(root: Path = Path(".")) -> list[str]:
    """Before the rename, the boot scripts kept their state in .privateai/ and wrote config/gateway.yaml. Carry both
    over once, so an existing install keeps its gateway key, provider key and configuration."""
    notes: list[str] = []
    old, new = root / ".privateai", root / STATE.name
    if old.is_dir():
        new.mkdir(exist_ok=True)
        for item in sorted(old.iterdir()):
            target = new / item.name
            if not target.exists():
                item.rename(target)
            elif item.name == "install.stamp":
                item.unlink()
        try:
            old.rmdir()
            notes.append("moved .privateai/ to .harpo/")
        except OSError:
            notes.append("moved what .privateai/ held into .harpo/; the rest is still in .privateai/")
    old_cfg, new_cfg = root / "config" / "gateway.yaml", root / "config" / "harpo.yaml"
    if old_cfg.is_file() and not new_cfg.exists():
        old_cfg.rename(new_cfg)
        notes.append("renamed config/gateway.yaml to config/harpo.yaml")
        meta_file = new / "boot.json"
        if meta_file.is_file():
            meta = json.loads(meta_file.read_text() or "{}")
            if str(meta.get("config", "")).endswith("gateway.yaml"):
                meta["config"] = str(Path("config") / "harpo.yaml")
                meta_file.write_text(json.dumps(meta, indent=2))
    return notes


def up(args: argparse.Namespace) -> int:
    _utf8_safe()
    adopted = adopt_legacy_state()
    state, cfg = STATE.resolve(), Path(args.config)
    state.mkdir(exist_ok=True)
    meta = _meta(state)
    port = int(args.port or meta.get("port") or 8080)
    base = f"http://127.0.0.1:{port}"
    banner.show(banner.standard_lines(port, [], 0, False, False)[:3], sys.stdout)
    for change in adopted:
        say(f"  ✓ {change}")
    pid = read_pid(state / "gateway.pid")
    if pid and alive(pid) and http("GET", f"{base}/healthz")[0] == 200:
        say(f"  ✓ already running at {base} (pid {pid}). Stop it with stop.cmd or ./stop.sh")
        return 0
    if http("GET", f"{base}/healthz")[0]:
        raise SystemExit(f"error: port {port} is in use by another program; pass --port")
    ensure_models()
    slm = None
    if not args.no_slm:
        found = local_model(args, state)
        if found:
            mode = "fail_closed" if args.strict else "degrade"
            slm = {**found, "timeout_ms": args.slm_timeout_ms, "on_failure": mode}
    if args.reconfigure or not cfg.exists():
        provider = choose_provider(args.provider)
        key = KEY_PREFIX + secrets.token_urlsafe(32)
        write_private(state / "gateway-key.txt", key + "\n")
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text(render_config(provider, hashlib.sha256(key.encode()).hexdigest(), port, slm), encoding="utf-8")
        say(f"  ✓ wrote {cfg} for {provider}; gateway key in .harpo/gateway-key.txt (only you can read it)")
    else:
        upstreams = (yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}).get("upstreams") or [{}]
        provider = str(meta.get("provider") or upstreams[0].get("name") or "openai")
        note = update_slm_block(cfg, slm, not args.no_slm)
        if note:
            say(f"  ✓ {note}")
    key_file = state / "gateway-key.txt"
    key = key_file.read_text().strip() if key_file.exists() else ""
    meta.update(provider=provider, port=port, slm_model=slm["model"] if slm else None, config=str(cfg))
    (state / "boot.json").write_text(json.dumps(meta, indent=2))
    env = dict(os.environ)
    if provider in PROVIDERS:
        provider_env(provider, state, env)
    if slm:
        say(f"  · loading {slm['model']} into memory")
        warm = http(
            "POST", f"{OLLAMA}/api/generate", {"model": slm["model"], "prompt": "", "keep_alive": "30m"}, timeout=300
        )
        pin = slm["digest"][:12] if slm.get("digest") else "unpinned"
        if warm[0] == 200:
            say(f"  ✓ {slm['model']} ready (pinned {pin})")
        else:
            say(f"  ! {slm['model']} did not load (HTTP {warm[0]}); requests run without it until it does")
    log = state / "gateway.log"
    say("  · starting the gateway")
    serve = [sys.executable, "-m", "harpo_redact", "serve", "--config", str(cfg), "--port", str(port)]
    pid = spawn(serve, log, env)
    (state / "gateway.pid").write_text(str(pid))
    for _ in range(360):
        if http("GET", f"{base}/readyz")[0] == 200:
            break
        if not alive(pid):
            say(f"  ✗ the gateway stopped during startup. Last lines of {log}:\n{tail(log)}")
            return 1
        time.sleep(0.5)
    else:
        say(f"  ✗ the gateway did not become ready within 3 minutes. See {log}")
        return 1
    status, result = http("POST", f"{base}/v1/selftest/suites", {"suites": SUITES}, key=key, timeout=120)
    if status == 200 and isinstance(result, dict):
        say("  " + "   ".join(f"{MARKS.get(s['status'], '?')} {s['name']}" for s in result["suites"]))
        for s in result["suites"]:
            for t in s["tests"]:
                if t["status"] == "fail":
                    say(f"      ✗ {s['name']}: {t['name']}: {t['detail']}")
    copied = bool(key) and copy_to_clipboard(key)
    if not args.no_browser:
        webbrowser.open(f"{base}/")
    name = PROVIDERS[provider][2] if provider in PROVIDERS else None
    hint = "(gateway key copied: paste it there)" if copied else "(key: .harpo/gateway-key.txt)"
    local = (
        f"{slm['model']} via Ollama, {'fail-closed' if args.strict else 'degrades if unavailable'}" if slm else "off"
    )
    say(f"""
  Running.  Console   {base}/   {hint}
            OpenAI    {base}/v1        Anthropic  {base}
            Provider  {provider}{f" (key from {name})" if name else ""}
            Local SLM {local}
            Logs      {log}
  Stop:     stop.cmd (Windows)   ./stop.sh (macOS, Linux)
""")
    return 0


def down(args: argparse.Namespace) -> int:
    _utf8_safe()
    state = STATE.resolve()
    meta = _meta(state)
    pid = read_pid(state / "gateway.pid")
    say("\n  Harpo")
    say("  ✓ gateway stopped" if pid and stop_pid(pid) else "  · the gateway was not running")
    (state / "gateway.pid").unlink(missing_ok=True)
    model = meta.get("slm_model")
    unload = bool(model) and not args.keep_model and ollama_models() is not None
    if unload and http("POST", f"{OLLAMA}/api/generate", {"model": model, "keep_alive": 0}, timeout=30)[0] == 200:
        say(f"  ✓ {model} unloaded from memory")
    opid = read_pid(state / "ollama.pid")
    if opid and not args.keep_ollama:
        if stop_pid(opid):
            say("  ✓ Ollama stopped (boot had started it)")
        (state / "ollama.pid").unlink(missing_ok=True)
    elif ollama_models() is not None and not opid:
        say("  · Ollama left running (it was running before boot)")
    return 0


def status(args: argparse.Namespace) -> int:
    _utf8_safe()
    state = STATE.resolve()
    meta = _meta(state)
    port = int(meta.get("port") or 8080)
    pid = read_pid(state / "gateway.pid")
    running = bool(pid and alive(pid) and http("GET", f"http://127.0.0.1:{port}/healthz")[0] == 200)
    say(f"  gateway    {f'running at http://127.0.0.1:{port} (pid {pid})' if running else 'stopped'}")
    _, ps = http("GET", f"{OLLAMA}/api/ps", timeout=3)
    loaded = [str(m.get("name")) for m in ps.get("models", [])] if isinstance(ps, dict) else None
    say(f"  ollama     {'not reachable' if loaded is None else 'running; loaded: ' + (', '.join(loaded) or 'nothing')}")
    say(f"  config     {meta.get('config', 'config/harpo.yaml')}   provider {meta.get('provider', '?')}")
    say(f"  local SLM  {meta.get('slm_model') or 'off'}")
    return 0 if running else 3
