"""The one-command launcher: model choice, config, private files, and a real up/down against a stand-in Ollama."""

from __future__ import annotations

import argparse
import json
import socket
import stat
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import uvicorn
import yaml
from fastapi import FastAPI, Request

from harpo_redact import launcher
from harpo_redact.config import Settings

PHI3 = {"name": "phi3:latest", "model": "phi3:latest", "digest": "4f2222927938" + "ab" * 26}


def test_pick_model_prefers_the_exact_tag_then_the_same_model_never_another() -> None:
    models = [{"name": "llama3.2:3b"}, {"name": "phi3:mini"}, {"name": "phi3.5:latest"}]
    assert launcher.pick_model([*models, PHI3], "phi3:latest") == PHI3
    assert launcher.pick_model(models, "phi3:latest")["name"] == "phi3:mini"  # type: ignore[index]
    assert launcher.pick_model([{"name": "phi3.5:latest"}, {"name": "llama3.2:3b"}], "phi3") is None


def test_rendered_config_loads_and_pins_the_model() -> None:
    slm = {"model": "phi3:latest", "digest": PHI3["digest"], "timeout_ms": 20000, "on_failure": "degrade"}
    text = launcher.render_config("openai", "a" * 64, 8080, slm)
    settings = Settings(**yaml.safe_load(text))
    assert settings.environment == "production" and settings.auth.keys[0].admin
    assert settings.detection.slm.enabled and settings.detection.slm.model == "phi3:latest"
    assert str(settings.detection.slm.model_digest).endswith(PHI3["digest"])
    assert (
        Settings(**yaml.safe_load(launcher.render_config("ollama", "b" * 64, 8080, None))).environment == "development"
    )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_keys_are_written_owner_only(tmp_path: Path) -> None:
    target = tmp_path / "state" / ".env"
    launcher.write_private(target, "OPENAI_API_KEY=sk-test\n")
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert launcher.read_env(target) == {"OPENAI_API_KEY": "sk-test"}


def test_existing_configs_gain_lose_or_keep_the_model(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg = tmp_path / "harpo.yaml"
    cfg.write_text(launcher.render_config("openai", "c" * 64, 8080, None))
    slm = {"model": "phi3:latest", "digest": "d" * 64, "timeout_ms": 20000, "on_failure": "degrade"}
    assert "added phi3:latest" in str(launcher.update_slm_block(cfg, slm, True))
    assert yaml.safe_load(cfg.read_text())["detection"]["slm"]["model_digest"] == "sha256:" + "d" * 64
    assert launcher.update_slm_block(cfg, {**slm, "digest": "e" * 64}, True) is None
    assert "changed since it was pinned" in capsys.readouterr().out
    assert "turned the local model off" in str(launcher.update_slm_block(cfg, None, False))


def test_first_run_without_a_terminal_needs_a_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    with pytest.raises(SystemExit, match="--provider"):
        launcher.choose_provider(None)


def test_a_missing_provider_key_without_a_terminal_is_said_to_stop_the_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    env: dict[str, str] = {}
    launcher.provider_env("openai", tmp_path, env)
    assert "OPENAI_API_KEY is not set: the gateway does not start without it" in capsys.readouterr().out
    assert env == {}
    # which is what the production configuration boot writes does: it refuses to start without the key
    settings = Settings(**yaml.safe_load(launcher.render_config("openai", "e" * 64, 8080, None)))
    assert "upstream openai: environment variable OPENAI_API_KEY is empty" in settings.production_problems({})


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture
def ollama(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[dict]]:  # type: ignore[type-arg]
    """A stand-in speaking Ollama's API with phi3:latest installed. Records generate calls (load and unload)."""
    calls: list[dict] = []  # type: ignore[type-arg]
    app = FastAPI()

    @app.get("/api/tags")
    async def tags() -> dict:  # type: ignore[type-arg]
        return {"models": [PHI3]}

    @app.post("/api/generate")
    async def generate(request: Request) -> dict:  # type: ignore[type-arg]
        calls.append(await request.json())
        return {"done": True}

    @app.post("/api/chat")
    async def chat() -> dict:  # type: ignore[type-arg]
        return {"message": {"role": "assistant", "content": json.dumps({"findings": []})}, "done": True}

    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    monkeypatch.setattr(launcher, "OLLAMA", f"http://127.0.0.1:{port}")
    for _ in range(50):
        if launcher.ollama_models() is not None:
            break
        time.sleep(0.1)
    yield calls
    server.should_exit = True
    thread.join(5)


def test_up_then_down_runs_a_real_gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ollama: list[dict]) -> None:  # type: ignore[type-arg]
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-launcher")
    port = _free_port()
    args = argparse.Namespace(provider="openai", slm_model="phi3:latest", no_slm=False, strict=False, pull=False,
                              slm_timeout_ms=20000, reconfigure=False, no_browser=True, port=port,
                              config="config/harpo.yaml")  # fmt: skip
    try:
        assert launcher.up(args) == 0
        pid = launcher.read_pid(tmp_path / ".harpo" / "gateway.pid")
        assert launcher.alive(pid)
        assert launcher.http("GET", f"http://127.0.0.1:{port}/readyz")[0] == 200
        assert any(c.get("keep_alive") == "30m" for c in ollama)  # loaded ahead of the first request
        assert "model_digest: sha256:" in (tmp_path / "config" / "harpo.yaml").read_text()
        assert launcher.up(args) == 0  # a second boot just reports it is running
    finally:
        assert launcher.down(argparse.Namespace(keep_ollama=False, keep_model=False)) == 0
    assert not launcher.alive(pid)
    assert any(c.get("keep_alive") == 0 for c in ollama)  # unloaded on stop


def test_openrouter_config_routes_both_apis_with_privacy_routing() -> None:
    settings = Settings(**yaml.safe_load(launcher.render_config("openrouter", "f" * 64, 8080, None)))
    styles = {u.style: u for u in settings.upstreams}
    assert set(styles) == {"openai", "anthropic"}
    for upstream in settings.upstreams:
        assert upstream.effective_dialect == "openrouter" and upstream.effective_auth_scheme == "bearer"
        assert upstream.openrouter.data_collection == "deny" and upstream.api_key_env == "OPENROUTER_API_KEY"
    assert styles["anthropic"].base_url == "https://openrouter.ai/api"  # the Messages API lives at /api/v1/messages
