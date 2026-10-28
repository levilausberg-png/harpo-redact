"""Setup presets and request-trace fields: admin-only where it matters, content-free everywhere."""

from __future__ import annotations

import hashlib
import json

from .conftest import AUTH, KEY, chat

FAST = {"detection": {"ner": {"enabled": False}}}


def sha(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def test_setup_presets_are_admin_only_and_carry_no_secrets(gateway) -> None:  # type: ignore[no-untyped-def]
    keys = {
        "keys": [{"id": "owner", "sha256": sha(KEY), "admin": True}, {"id": "team", "sha256": sha("team-key-123456")}]
    }
    client, _ = gateway(auth=keys, **FAST)
    assert client.get("/v1/setup/presets", headers={"authorization": "Bearer team-key-123456"}).status_code == 403
    presets = client.get("/v1/setup/presets", headers=AUTH).json()["providers"]
    assert {"openai", "anthropic", "ollama"} <= {p["id"] for p in presets}
    assert all(set(p) == {"id", "style", "base_url", "key_env", "models", "companions"} for p in presets)
    # A companion is a second upstream a preset adds (OpenRouter's Anthropic-style API): names, never keys.
    companions = [c for p in presets for c in p["companions"]]
    assert companions and all(set(c) == {"name", "style", "base_url", "key_env", "models"} for c in companions)


def test_trace_fields_are_recorded_and_content_free(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(**FAST)
    assert client.post("/v1/chat/completions", headers=AUTH, json=chat("Mail jane.doe@acme.com")).status_code == 200
    event = client.get("/v1/stats?recent=5", headers=AUTH).json()["recent"][0]
    assert event["egress"] == "verified" and event["egress_ms"] >= 0 and event["upstream_ms"] >= 0
    assert "jane" not in json.dumps(event) and "acme" not in json.dumps(event)


def test_a_blocked_request_never_reaches_egress(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(policy={"entities": {"IBAN": {"action": "block"}}}, **FAST)
    assert (
        client.post("/v1/chat/completions", headers=AUTH, json=chat("refund to NL91ABNA0417164300")).status_code == 403
    )
    event = client.get("/v1/stats?recent=5", headers=AUTH).json()["recent"][0]
    assert event["decision"] == "blocked" and "egress" not in event and not spy.requests
