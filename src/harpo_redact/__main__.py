"""Command-line interface.

harpo serve [--config PATH] [--host H] [--port P]
harpo check-config [--config PATH]
harpo hash-key [--id NAME]
harpo scan [--config PATH] [--mode relational|generic] < input.txt
harpo mock-upstream [--port 9100]      (demo only)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
from typing import TYPE_CHECKING

from . import KEY_PREFIX, __version__
from .presets import (
    COMPANIONS,
    LANGUAGE_MODELS,
    MODEL_WHEELS,
    PROVIDERS,
    installed_language_models,
    missing_ner_models,
)

if TYPE_CHECKING:
    from .config import Settings


def _disable_core_dumps() -> None:
    # A core dump of a worker would contain prompts held in memory.
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, ValueError, OSError):
        pass


class ConfigError(Exception):
    pass


def _settings(config: str | None) -> Settings:
    from pydantic import ValidationError

    from .config import load_settings

    if config:
        os.environ["HARPO_CONFIG"] = config
    try:
        return load_settings()
    except FileNotFoundError as exc:
        raise ConfigError(str(exc)) from None
    except ValidationError as exc:
        lines = [f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()]
        raise ConfigError("invalid configuration:\n  " + "\n  ".join(lines)) from None


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .observability import configure_logging

    settings = _settings(args.config)
    problems = settings.production_problems()
    if problems:
        print("Refusing to start in production mode:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 2
    _require_models(settings)
    _banner(settings, args.port or settings.server.port)
    if settings.environment == "development":
        print("Development mode: production guards are off. Do not expose this instance.", file=sys.stderr)
    _disable_core_dumps()
    configure_logging(settings.logging.level)
    uvicorn.run(
        "harpo_redact.api:app_from_env",
        factory=True,
        host=args.host or settings.server.host,
        port=args.port or settings.server.port,
        workers=settings.server.workers,
        access_log=False,
        server_header=False,
        proxy_headers=False,
        log_config=None,
        timeout_graceful_shutdown=15,
        ssl_certfile=settings.server.tls_certfile,
        ssl_keyfile=settings.server.tls_keyfile,
    )
    return 0


def _missing_models(settings: Settings) -> list[str]:
    ner = settings.detection.ner
    return missing_ner_models(ner.model, {str(k): v for k, v in ner.language_models.items()}, ner.enabled)


def _require_models(settings: Settings) -> None:
    """A configured NER model that is not installed stops the command with how to install it, not a traceback."""
    if missing := _missing_models(settings):
        raise ConfigError("; ".join(missing))


def _banner(settings: Settings, port: int) -> None:
    from . import banner
    from .detectors.secret_library import load_library

    rules = load_library(extra_rules_file=settings.detection.secrets.extra_rules_file).rule_count
    names = [u.name for u in settings.upstreams]
    banner.show(
        banner.standard_lines(port, names, rules, settings.detection.ner.enabled, settings.detection.slm.enabled)
    )


def cmd_check_config(args: argparse.Namespace) -> int:
    from . import library, live_policy

    settings = _settings(args.config)
    problems = settings.production_problems() + _missing_models(settings)
    live_path = settings.policy.live_file
    effective = settings
    if live_path:
        try:
            effective = live_policy.apply(settings, live_policy.load(live_path))
        except ValueError as exc:
            problems.append(f"policy.live_file {live_path} is not valid: {exc}")
    for notice in settings.notices():
        print(f"notice: {notice}")
    if problems:
        for problem in problems:
            print(f"problem: {problem}")
        return 2
    customs = len(settings.detection.custom_types)
    extra = f", {customs} custom type(s)" if customs else ""
    print(f"ok: {settings.environment} configuration with {len(settings.upstreams)} upstream(s){extra}")
    source = " (with the live policy)" if effective is not settings else ""
    print(f"detection library{source}:")
    for line in library.summary_lines(effective):
        print(f"  {line}")
    return 0


def cmd_hash_key(args: argparse.Namespace) -> int:
    key = KEY_PREFIX + secrets.token_urlsafe(32)
    digest = hashlib.sha256(key.encode()).hexdigest()
    print("Gateway key (shown once; store it in your secret manager):")
    print(f"  {key}\n")
    print("Add this to harpo.yaml (the gateway stores only the hash):")
    print(f"auth:\n  keys:\n    - id: {args.id}\n      sha256: {digest}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    from .api import load_ner
    from .pipeline import Pipeline

    settings = _settings(args.config)
    _require_models(settings)
    ner = load_ner(settings.detection.ner) if settings.detection.ner.enabled else None
    pipeline = Pipeline(settings, ner=ner)
    text = sys.stdin.read()
    outcome = pipeline.scan_sync([text], mode=args.mode, context_repair=args.context_repair)
    json.dump(
        {
            "risk": outcome.risk.value,
            "reasons": [r.to_dict() for r in outcome.reasons],
            "redacted": outcome.texts[0],
            "entities": [f.to_dict() for f in outcome.findings[0]],
            "counts": outcome.counts,
        },
        sys.stdout,
        ensure_ascii=False,
        indent=2,
    )
    print()
    return 1 if outcome.blocked else 0


def cmd_redact_file(args: argparse.Namespace) -> int:
    import asyncio
    from pathlib import Path

    from .api import load_ner
    from .documents.runner import DocumentError, WorkerRunner
    from .documents.service import redact_document
    from .pipeline import Pipeline

    settings = _settings(args.config)
    _require_models(settings)
    source = Path(args.input)
    ner = load_ner(settings.detection.ner) if settings.detection.ner.enabled else None
    pipeline = Pipeline(settings, ner=ner)
    try:
        result = asyncio.run(
            redact_document(
                pipeline, settings.documents, WorkerRunner(settings.documents), source.read_bytes(), source.name, None,
                mode=args.mode, context_repair=args.context_repair, override=False, want_file=not args.text,
            )
        )  # fmt: skip
    except DocumentError as exc:
        print(f"error: {exc.code}: {exc.message}", file=sys.stderr)
        return 2
    summary: dict[str, object] = {
        "kind": result.kind,
        "risk": result.scan.risk.value,
        "reasons": [r.to_dict() for r in result.scan.reasons],
        "counts": result.scan.counts,
        "segments": result.segments,
        "info": result.info,
    }
    if result.scan.blocked:
        json.dump(summary, sys.stderr, indent=2)
        print(file=sys.stderr)
        return 1
    if args.text:
        print(result.text)
    elif result.data is not None:
        target = (
            Path(args.output)
            if args.output
            else source.with_name(f"{result.filename}.redacted.{result.extension or 'txt'}")
        )
        target.write_bytes(result.data)
        summary["output"] = str(target)
        summary["verified"] = result.verified
    json.dump(summary, sys.stderr, ensure_ascii=False, indent=2)
    print(file=sys.stderr)
    return 0


def cmd_mock_upstream(args: argparse.Namespace) -> int:
    import uvicorn

    from .mock_upstream import create_mock_app

    print("Starting the mock provider. Demo only: it echoes what it receives.", file=sys.stderr)
    uvicorn.run(create_mock_app(), host=args.host, port=args.port, access_log=False, server_header=False)
    return 0


_LANGUAGE_MODELS = LANGUAGE_MODELS


def _installed_language_models() -> dict[str, str]:
    return installed_language_models()


def _demo_slm(args: argparse.Namespace) -> dict[str, object] | None:
    if not args.slm:
        return None
    return {"enabled": True, "base_url": args.slm, "model": args.slm_model, "on_failure": "degrade"}


def cmd_demo(args: argparse.Namespace) -> int:
    """Gateway + fake provider in one process: the console, the API and every integration, no accounts."""
    import importlib.util
    import threading
    import webbrowser

    import httpx
    import uvicorn

    from .api import create_app
    from .config import Settings
    from .mock_upstream import create_mock_app

    has_ner = importlib.util.find_spec("en_core_web_sm") is not None
    if not has_ner:  # names need a spaCy model; everything else works without one
        url, digest = MODEL_WHEELS["en_core_web_sm"]
        print("  Note: en_core_web_sm is not installed, so names are not detected in this demo. Install it with\n"
              f'  pip install "{url}#sha256={digest}"', file=sys.stderr)  # fmt: skip
    import tempfile

    # A fresh live policy per run: the Policy page is editable, and every demo starts from the defaults.
    demo_policy = os.path.join(tempfile.mkdtemp(prefix="harpo-demo-"), "policy.live.yaml")
    settings = Settings(
        environment="development",
        auth={"enabled": False},
        server={"host": args.host, "port": args.port},
        policy={"live_file": demo_policy},
        upstreams=[
            {
                "name": "demo-openai",
                "style": "openai",
                "base_url": "http://mock.provider/v1",
                "models": ["demo-gpt", "demo-gpt-mini"],
            },
            {
                "name": "demo-anthropic",
                "style": "anthropic",
                "base_url": "http://mock.provider",
                "models": ["demo-claude"],
            },
        ],
        detection={
            "ner": {"enabled": has_ner, "language_models": _installed_language_models() if has_ner else {}},
            **({"slm": slm} if (slm := _demo_slm(args)) else {}),
        },
    )
    app = create_app(settings, upstream_transport=httpx.ASGITransport(app=create_mock_app()))
    base = f"http://{args.host}:{args.port}"
    _banner(settings, args.port)
    print(
        f"""
  Harpo demo is running. The provider is a fake that echoes what it receives,
  so you can see exactly what would leave your machine. Nothing is sent anywhere.

    Console          {base}/
    OpenAI style     {base}/v1         models: demo-gpt, demo-gpt-mini
    Anthropic style  {base}            model:  demo-claude
    API key          any value (auth is off in the demo)

  Try it:
    curl {base}/v1/chat/completions -H 'content-type: application/json' -d '{{"model": "demo-gpt",
      "messages": [{{"role": "user", "content": "Mail jane.doe@acme.com, card 4111 1111 1111 1111"}}]}}'
""",
        file=sys.stderr,
    )
    if not args.no_browser:
        threading.Timer(1.2, webbrowser.open, (f"{base}/",)).start()
    uvicorn.run(app, host=args.host, port=args.port, access_log=False, server_header=False, log_config=None)
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    """Write a working config: pick a provider, get a gateway key, see how to point any client at it."""
    import hashlib
    import secrets
    from pathlib import Path

    def ask(question: str, default: str) -> str:
        if args.yes or not sys.stdin.isatty():
            return default
        answer = input(f"{question} [{default}]: ").strip()
        return answer or default

    names = list(PROVIDERS)
    provider = args.provider or ask(f"Provider ({', '.join(names)})", "openai")
    if provider not in PROVIDERS:
        print(f"error: unknown provider {provider!r}; choose one of {', '.join(names)}", file=sys.stderr)
        return 2
    style, base_url, env_name, _models = PROVIDERS[provider]
    host = args.host or ask("Listen on (127.0.0.1 for this machine, 0.0.0.0 inside Docker)", "127.0.0.1")
    path = Path(args.output)
    if path.exists() and not args.force:
        print(f"error: {path} exists; use --force to overwrite", file=sys.stderr)
        return 2
    key = KEY_PREFIX + secrets.token_urlsafe(32)
    digest = hashlib.sha256(key.encode()).hexdigest()
    production = base_url.startswith("https://") and env_name is not None
    from .launcher import render_config

    config = render_config(provider, digest, 8080, None, host=host, origin="init")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(config)
    root = "http://127.0.0.1:8080"
    prefix = "/v1" if style == "openai" else ""
    start = f"export {env_name}=<your {provider} key>   # stays on this machine" if env_name else "(no provider key)"
    url_var, key_var = (
        ("OPENAI_BASE_URL", "OPENAI_API_KEY") if style == "openai" else ("ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY")
    )
    anthropic_too = style == "anthropic" or any(c[1] == "anthropic" for c in COMPANIONS.get(provider, []))
    claude_code = (
        f"\n  4. Claude Code and Anthropic SDKs: ANTHROPIC_BASE_URL={root} and ANTHROPIC_API_KEY=<the gateway key>."
        if anthropic_too and style == "openai"
        else ""
    )
    print(
        f"""
  Wrote {path}{"" if production else " (development: local http upstream)"}.

  Your gateway key (shown once, only its hash is stored):

      {key}

  1. Start it:      {start}
                    harpo serve --config {path}
  2. Point any client at it, with the gateway key instead of the provider key:
      base URL      {root}{prefix}
      env           {url_var}={root}{prefix}
                    {key_var}=<the gateway key above>
  3. Open {root}/ and paste the key: playground, live activity and copy-paste setup for 25+ tools.{claude_code}
"""
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="harpo",
        description="Harpo: a self-hosted privacy firewall for LLM APIs. Personal data and secrets stay here.",
    )
    parser.add_argument("--version", action="version", version=f"harpo-redact {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the gateway")
    serve.add_argument("--config")
    serve.add_argument("--host")
    serve.add_argument("--port", type=int)
    serve.set_defaults(func=cmd_serve)

    check = sub.add_parser("check-config", help="validate configuration and production guards")
    check.add_argument("--config")
    check.set_defaults(func=cmd_check_config)

    hash_key = sub.add_parser("hash-key", help="generate a gateway key and its SHA-256 hash")
    hash_key.add_argument("--id", default="default")
    hash_key.set_defaults(func=cmd_hash_key)

    scan = sub.add_parser("scan", help="redact stdin and print JSON (exit 1 if blocked)")
    scan.add_argument("--config")
    scan.add_argument("--mode", choices=["relational", "generic"])
    scan.add_argument("--context-repair", action="store_true", default=None)
    scan.set_defaults(func=cmd_scan)

    redact = sub.add_parser("redact-file", help="redact a PDF, docx, xlsx, pptx or text file (exit 1 if blocked)")
    redact.add_argument("input")
    redact.add_argument("-o", "--output", help="where to write the redacted file (default: next to the input)")
    redact.add_argument("--text", action="store_true", help="print the redacted text instead of writing a file")
    redact.add_argument("--config")
    redact.add_argument("--mode", choices=["relational", "generic"])
    redact.add_argument("--context-repair", action="store_true", default=None)
    redact.set_defaults(func=cmd_redact_file)

    mock = sub.add_parser("mock-upstream", help="run a fake provider for demos (never in production)")
    mock.add_argument("--host", default="127.0.0.1")
    mock.add_argument("--port", type=int, default=9100)
    mock.set_defaults(func=cmd_mock_upstream)

    demo = sub.add_parser("demo", help="try everything locally: console, API and a fake provider, no accounts")
    demo.add_argument("--host", default="127.0.0.1")
    demo.add_argument("--port", type=int, default=8080)
    demo.add_argument("--no-browser", action="store_true")
    demo.add_argument(
        "--slm", metavar="URL", help="attach a local Ollama-compatible model, e.g. http://127.0.0.1:11434"
    )
    demo.add_argument("--slm-model", default="llama3.2:3b")
    demo.set_defaults(func=cmd_demo)

    init = sub.add_parser("init", help="write a config for your provider and create a gateway key")
    init.add_argument("--provider", choices=sorted(PROVIDERS))
    init.add_argument("--host")
    init.add_argument("-o", "--output", default="config/harpo.yaml")
    init.add_argument("--force", action="store_true")
    init.add_argument("-y", "--yes", action="store_true", help="accept defaults, ask nothing")
    init.set_defaults(func=cmd_init)

    up = sub.add_parser(
        "up", help="start the gateway (and a local model via Ollama) in the background; boot scripts run this"
    )
    up.add_argument("--provider", choices=sorted(PROVIDERS), help="first run only: where requests go")
    up.add_argument("--slm-model", default="phi3:latest", help="local Ollama model (default phi3:latest; any phi3 tag)")
    up.add_argument("--no-slm", action="store_true", help="run without the local model")
    up.add_argument("--strict", action="store_true", help="refuse requests while the local model is unavailable")
    up.add_argument("--pull", action="store_true", help="download the local model if it is missing")
    up.add_argument("--slm-timeout-ms", type=int, default=20_000)
    up.add_argument("--reconfigure", action="store_true", help="choose the provider again and write a new config")
    up.add_argument("--no-browser", action="store_true")
    up.add_argument("--port", type=int)
    up.add_argument("--config", default="config/harpo.yaml")
    up.set_defaults(func=lambda a: __import__("harpo_redact.launcher", fromlist=["up"]).up(a))
    down = sub.add_parser(
        "down", help="stop what `up` started: the gateway, the model in memory, Ollama if up started it"
    )
    down.add_argument("--keep-ollama", action="store_true", help="leave Ollama running even if up started it")
    down.add_argument("--keep-model", action="store_true", help="leave the local model loaded in memory")
    down.set_defaults(func=lambda a: __import__("harpo_redact.launcher", fromlist=["down"]).down(a))
    status = sub.add_parser("status", help="is the gateway running, and with which local model")
    status.set_defaults(func=lambda a: __import__("harpo_redact.launcher", fromlist=["status"]).status(a))

    if not (sys.argv[1:] if argv is None else argv):
        parser.print_help()  # a bare `harpo` explains itself instead of erroring
        return 0
    args = parser.parse_args(argv)
    try:
        result: int = args.func(args)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return result


if __name__ == "__main__":
    raise SystemExit(main())
