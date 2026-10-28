"""Console, integrations and onboarding: /v1/models, count_tokens, /v1/stats, console assets, demo and init."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from harpo_redact import __main__ as cli
from harpo_redact.api import _ASSETS, LiveStats
from harpo_redact.config import load_settings

from .conftest import AUTH, KEY, chat

FAST = {"detection": {"ner": {"enabled": False}}}
ROOT = Path(__file__).resolve().parents[1]
CONSOLE = ROOT / "src/harpo_redact/console"


def sha(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def test_models_are_listed_in_both_formats_and_patterns_are_not(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(**FAST)
    openai = client.get("/v1/models", headers=AUTH).json()
    anthropic = client.get("/v1/models", headers={"x-api-key": KEY, "anthropic-version": "2023-06-01"}).json()
    assert openai["object"] == "list" and all(m["object"] == "model" for m in openai["data"])
    assert anthropic["has_more"] is False and all(m["type"] == "model" for m in anthropic["data"])
    assert not any(c in m["id"] for m in openai["data"] + anthropic["data"] for c in "*?[")
    assert client.get("/v1/models").status_code == 401


def test_count_tokens_is_sanitized_and_forwarded_to_the_count_endpoint(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(**FAST)
    body = {"model": "claude-test", "messages": [{"role": "user", "content": "Mail jane.doe@acme.com"}]}
    assert client.post("/v1/messages/count_tokens", headers={"x-api-key": KEY}, json=body).status_code == 200
    assert spy.requests[-1].url.path.endswith("/v1/messages/count_tokens")
    assert b"jane.doe@acme.com" not in spy.bodies[-1] and b"[EMAIL_1]" in spy.bodies[-1]


def test_stats_are_content_free_scoped_per_key_and_skip_previews(gateway) -> None:  # type: ignore[no-untyped-def]
    keys = {
        "keys": [{"id": "owner", "sha256": sha(KEY), "admin": True}, {"id": "team", "sha256": sha("team-key-123456")}]
    }
    client, _ = gateway(auth=keys, **FAST)
    team = {"authorization": "Bearer team-key-123456"}
    client.post("/v1/chat/completions", headers=AUTH, json=chat("Mail jane.doe@acme.com"))
    client.post("/v1/chat/completions", headers=team, json=chat("Card 4111 1111 1111 1111"))
    client.post("/v1/scan", headers={**AUTH, "x-harpo-preview": "1"}, json={"text": "preview jane@acme.com"})
    admin, own = client.get("/v1/stats", headers=AUTH).json(), client.get("/v1/stats", headers=team).json()
    assert admin["scope"] == "all" and admin["totals"]["requests"] == 2
    assert own["scope"] == "key" and own["totals"]["requests"] == 1 and own["by_type"] == {"CREDIT_CARD": 1}
    assert len(admin["series"]) == 60 and sum(s["requests"] for s in admin["series"]) == 2
    text = json.dumps(admin)
    assert "jane" not in text and "4111" not in text and "acme" not in text


def test_the_stats_window_follows_uptime() -> None:
    stats = LiveStats()
    stats.started -= 120
    assert stats.snapshot(None)["window_s"] == 300
    stats.started -= 7200
    assert stats.snapshot(None)["window_s"] == 3600


def test_console_assets_are_served_under_a_strict_policy_and_call_nothing_external(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(**FAST)
    page = client.get("/")
    csp = page.headers["content-security-policy"]
    assert (
        page.status_code == 200 and "script-src 'self'" in csp and "connect-src 'self'" in csp and "unsafe" not in csp
    )
    for path, (filename, media) in _ASSETS.items():
        assert (CONSOLE / filename).exists(), filename
        r = client.get(f"/console/{path}")
        assert r.status_code == 200 and r.headers["content-type"].startswith(media.split(";")[0])
    assert client.get("/console/../api.py").status_code == 404 and client.get("/console/nope.js").status_code == 404
    shipped = [f for f in CONSOLE.rglob("*") if f.suffix in (".html", ".js", ".css")]
    assert len(shipped) > 20  # the modular console: every module and stylesheet is checked
    for f in shipped:
        # No external hosts: the console only talks to this gateway. A loopback default (a local model) is not a call.
        assert not re.search(r"https?://(?!127\.0\.0\.1[:/]|localhost[:/])", f.read_text()), f.name


def test_the_integration_catalog_is_complete_and_uses_known_placeholders() -> None:
    catalog = json.loads((CONSOLE / "integrations.json").read_text())
    known = {"{OPENAI_BASE}", "{ANTHROPIC_BASE}", "{KEY}", "{MODEL}", "{CLAUDE_MODEL}"}
    ids = [x["id"] for x in catalog["items"]]
    assert len(ids) == len(set(ids)) >= 30
    for x in catalog["items"]:
        assert x["category"] in catalog["categories"] and (x["steps"] or x["snippets"]), x["id"]
        for text in [*x["steps"], *(s["code"] for s in x["snippets"])]:
            assert set(re.findall(r"(?<!\$)\{[A-Z_]+\}", text)) <= known, x["id"]
        assert (ROOT / "docs/integrations" / f"{x['id']}.md").exists()
    assert sum(x["verified"] for x in catalog["items"]) >= 9


def test_init_writes_a_config_that_passes_the_production_guards(tmp_path, monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    out = tmp_path / "harpo.yaml"
    assert cli.main(["init", "--provider", "anthropic", "-y", "-o", str(out)]) == 0
    key = re.search(r"harpo_[A-Za-z0-9_\-]{20,}", capsys.readouterr().out)
    assert key is not None
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    settings = load_settings(str(out))
    assert settings.environment == "production" and settings.production_problems() == []
    assert settings.auth.keys[0].sha256 == sha(key.group(0)) and settings.auth.keys[0].admin
    assert cli.main(["init", "--provider", "anthropic", "-y", "-o", str(out)]) == 2  # never overwrites silently


def test_demo_serves_both_api_styles_with_a_fake_provider(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import uvicorn

    captured: dict[str, object] = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: captured.update(app=app))
    assert cli.main(["demo", "--no-browser", "--port", "8099"]) == 0
    with TestClient(captured["app"]) as c:  # type: ignore[arg-type]
        assert [m["id"] for m in c.get("/v1/models").json()["data"]] == ["demo-gpt", "demo-gpt-mini"]
        r = c.post(
            "/v1/chat/completions",
            json={"model": "demo-gpt", "messages": [{"role": "user", "content": "Mail jane.doe@acme.com"}]},
        )
        assert r.status_code == 200 and "[EMAIL_1]" in r.text and "jane.doe" not in r.text
        body = {
            "model": "demo-claude",
            "max_tokens": 50,
            "messages": [{"role": "user", "content": "Mail jane.doe@acme.com"}],
        }
        r = c.post("/v1/messages", json=body)
        assert r.status_code == 200 and "[EMAIL_1]" in r.text


def test_the_fake_providers_stream_has_the_usage_sdks_need() -> None:
    from harpo_redact.mock_upstream import create_mock_app

    with TestClient(create_mock_app()) as c:
        body = {"model": "m", "max_tokens": 5, "stream": True, "messages": [{"role": "user", "content": "hi"}]}
        text = c.post("/v1/messages", json=body).text
    start = json.loads(text.split("data: ", 2)[1].split("\n", 1)[0])
    assert start["type"] == "message_start" and start["message"]["usage"]["input_tokens"] >= 1


@pytest.mark.parametrize("word", ["AccessDenied", "PowerPoint", "JavaScript"])
def test_camel_case_code_words_are_not_organizations(make_pipeline, word: str) -> None:  # type: ignore[no-untyped-def]
    out = make_pipeline().scan_sync([f"Why does {word} fail when Priya Raman runs it?"])
    assert word in out.texts[0] and "Priya Raman" not in out.texts[0]
