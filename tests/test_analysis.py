"""Configuration analyzer and diagnostic bundle: concrete findings, admin-only, content-free."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

from harpo_redact.analysis import analyze

from .conftest import AUTH, KEY, chat, make_settings

FAST = {"detection": {"ner": {"enabled": False}}}


def ids(settings) -> dict[str, str]:  # type: ignore[no-untyped-def]
    return {f["id"]: f["level"] for f in analyze(settings)}


def test_weakened_protections_are_required_or_recommended_findings() -> None:
    found = ids(make_settings(policy={"egress_verification": "off", "unknown_fields": "pass", "remote_mcp": "allow"}))
    assert (
        found["egress-off"] == "required"
        and found["unknown-pass"] == "recommended"
        and found["remote-mcp"] == "recommended"
    )


def test_auth_off_is_info_on_loopback_and_required_on_the_network() -> None:
    assert ids(make_settings(auth={"enabled": False}, server={"host": "127.0.0.1"}))["auth-off"] == "info"
    assert ids(make_settings(auth={"enabled": False}, server={"host": "0.0.0.0"}))["auth-off"] == "required"


def test_expiring_keys_and_an_unpinned_model_are_flagged() -> None:
    soon = (datetime.now(UTC) + timedelta(days=2)).isoformat()
    keys = {"keys": [{"id": "ci", "sha256": hashlib.sha256(b"x").hexdigest(), "expires_at": soon}]}
    found = ids(make_settings(auth=keys, detection={"slm": {"enabled": True}}))
    assert found["key-expiring-ci"] == "recommended" and found["slm-digest"] == "recommended"


def test_findings_name_their_setting_and_sort_by_level() -> None:
    findings = analyze(make_settings(policy={"egress_verification": "off"}))
    assert findings[0]["level"] == "required" and all(f["setting"] and f["title"] for f in findings)


def test_analysis_and_diagnostics_are_admin_only_and_content_free(gateway) -> None:  # type: ignore[no-untyped-def]
    sha = lambda k: hashlib.sha256(k.encode()).hexdigest()  # noqa: E731
    keys = {
        "keys": [{"id": "owner", "sha256": sha(KEY), "admin": True}, {"id": "team", "sha256": sha("team-key-123456")}]
    }
    client, _ = gateway(auth=keys, **FAST)
    team = {"authorization": "Bearer team-key-123456"}
    assert client.get("/v1/config/analysis", headers=team).status_code == 403
    assert client.get("/v1/diagnostics", headers=team).status_code == 403
    client.post("/v1/chat/completions", headers=AUTH, json=chat("Mail jane.doe@acme.example, card 4111 1111 1111 1111"))
    analysis = client.get("/v1/config/analysis", headers=AUTH).json()
    assert set(analysis["counts"]) == {"required", "recommended", "info"}
    bundle = client.get("/v1/diagnostics", headers=AUTH).json()
    text = json.dumps(bundle)
    assert bundle["kind"] == "harpo.diagnostics" and "prompts and responses" in bundle["excludes"]
    assert "jane" not in text and "4111" not in text and sha(KEY) not in text and "recent" not in bundle["stats"]


def test_openrouter_routing_findings() -> None:
    upstream = {"name": "openrouter", "style": "openai", "base_url": "https://openrouter.ai/api/v1", "models": ["*"]}
    found = ids(make_settings(upstreams=[{**upstream, "openrouter": {"data_collection": "client"}}]))
    assert found["openrouter-data-openrouter"] == "recommended" and found["openrouter-zdr-openrouter"] == "info"
    found = ids(make_settings(upstreams=[{**upstream, "openrouter": {"zdr": True}}]))
    assert "openrouter-data-openrouter" not in found and "openrouter-zdr-openrouter" not in found


def test_the_bundle_keeps_custom_type_terms_and_patterns_out(gateway, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Custom types hold what an organisation protects, so the bundle shows their names and counts only, for the
    configuration file's types and for the live policy's."""
    sha = lambda k: hashlib.sha256(k.encode()).hexdigest()  # noqa: E731
    keys = {"keys": [{"id": "owner", "sha256": sha(KEY), "admin": True}]}
    codename = {"name": "CODENAME", "terms": ["Project Nightjar"], "patterns": [r"\bNJ-\d{4}\b"], "action": "block"}
    client, _ = gateway(
        auth=keys,
        detection={"ner": {"enabled": False}, "custom_types": [codename]},
        policy={"live_file": str(tmp_path / "policy.live.yaml")},
    )
    text = json.dumps(client.get("/v1/diagnostics", headers=AUTH).json())
    assert "CODENAME" in text and "Nightjar" not in text and "NJ-" not in text
    staff = {"name": "EMPLOYEE_ID", "patterns": [r"\bEMP-\d{6}\b"], "terms": ["Wilhelmina Badge"]}
    assert client.put("/v1/policy/live", headers=AUTH, json={"custom_types": [codename, staff]}).status_code == 200
    bundle = client.get("/v1/diagnostics", headers=AUTH).json()
    text = json.dumps(bundle)
    assert "EMPLOYEE_ID" in text and "Wilhelmina" not in text and "EMP-" not in text and "Nightjar" not in text
    custom = {c["name"]: c for c in bundle["config"]["detection"]["custom_types"]}
    assert custom["EMPLOYEE_ID"]["patterns"] == "<1 entries hidden>" and "custom type terms and patterns" in text
