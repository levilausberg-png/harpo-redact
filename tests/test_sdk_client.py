"""The Python SDK's gateway clients (harpo_redact.sdk.GatewayClient / AsyncGatewayClient), against the real app.

A client must give the same objects as the local engine for the same configuration and input, keep the gateway's
authentication (a key per call, admin calls refused to other keys), and turn every gateway error into the SDK's
exceptions without quoting what was sent.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient

from harpo_redact.api import create_app
from harpo_redact.config import AuthKey
from harpo_redact.sdk import (
    AsyncGatewayClient,
    AuthenticationError,
    BlockedError,
    CustomType,
    DocumentError,
    GatewayClient,
    GatewayUnavailableError,
    Harpo,
    InvalidRequestError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    Risk,
    ScanResult,
)

from . import doc_fixtures as fx
from .conftest import KEY, SpyTransport, chat, make_settings
from .test_sdk import CANARIES, README_EXAMPLE, _comparable, _corpus, _models_or_skip, use_fresh_environment

FAST: dict[str, Any] = {"detection": {"ner": {"enabled": False}}}
TEAM_KEY = "harpo_team-key-for-the-sdk-tests-0123"
URL = "http://testserver"


@pytest.fixture(autouse=True)
def _fresh_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    use_fresh_environment(monkeypatch)


def sha(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def keys(**owner: Any) -> dict[str, Any]:
    return {
        "keys": [
            {"id": "owner", "sha256": sha(KEY), "admin": True, "can_override": True, **owner},
            {"id": "team", "sha256": sha(TEAM_KEY)},
        ]
    }


def connect(gateway: Any, **overrides: Any) -> tuple[GatewayClient, GatewayClient, SpyTransport, TestClient]:
    """An admin client and a team client on one gateway (an in-process app, through its TestClient)."""
    test_client, spy = gateway(auth=keys(), **overrides)
    return (
        GatewayClient(URL, api_key=KEY, http_client=test_client),
        GatewayClient(URL, api_key=TEAM_KEY, http_client=test_client),
        spy,
        test_client,
    )


def local_config(**overrides: Any) -> dict[str, Any]:
    return make_settings(auth=keys(), **overrides).model_dump(mode="json")


@pytest.fixture(scope="module")
def local() -> Iterator[Harpo]:
    _models_or_skip()
    with Harpo(local_config()) as engine:
        yield engine


# --------------------------------------------------------------------------- the same objects as the engine
def test_a_gateway_scan_equals_the_local_engine(gateway: Any, local: Harpo) -> None:
    admin, team, spy, _ = connect(gateway)
    for text in _corpus(120):
        remote = admin.scan(text)
        assert remote.request_id
        assert _comparable(remote) == _comparable(local.scan(text))
    several = ["Maria Jansen wrote.", "Reply to Maria Jansen at maria.jansen@northwind.example."]
    assert _comparable(team.scan(several)) == _comparable(local.scan(several))
    assert not spy.requests  # a scan never reaches a provider


def test_the_policy_view_is_the_same(gateway: Any, local: Harpo) -> None:
    admin, team, _, _ = connect(gateway)
    remote = admin.policy()
    mine = local.policy
    for field in ("default_mode", "context_repair", "entities", "always_redacted", "custom_types",
                  "egress_verification", "response_scan", "unknown_fields", "unsupported_content", "version"):  # fmt: skip
        assert getattr(remote, field) == getattr(mine, field), field
    assert remote.override_permitted and not team.policy().override_permitted  # per key
    assert remote.details["admin"] is True and team.policy().details["admin"] is False


def test_a_request_through_the_proxy_leaves_as_the_engine_redacts_it(gateway: Any, local: Harpo) -> None:
    admin, _, spy, _ = connect(gateway)
    answer = admin.chat_completion(chat(README_EXAMPLE))
    sent = json.loads(spy.bodies[-1])["messages"][0]["content"]
    assert sent == local.redact(README_EXAMPLE)
    assert answer.status == 200 and answer.risk == "yellow" and answer.redactions == 6 and answer.request_id
    assert "choices" in answer.body and not any(c in repr(answer) for c in CANARIES)
    claude = admin.message(
        {"model": "claude-test", "max_tokens": 64, "messages": [{"role": "user", "content": "mail a.b@example.com"}]}
    )
    assert claude.status == 200 and json.loads(spy.bodies[-1])["messages"][0]["content"] == "mail [EMAIL_1]"
    with pytest.raises(InvalidRequestError, match="stream"):
        admin.chat_completion({**chat("hi"), "stream": True})


def test_documents_over_http_equal_the_local_engine(gateway: Any, local: Harpo) -> None:
    admin, _, _, _ = connect(gateway)
    for data, name in ((f"Mail {fx.EMAIL} or call {fx.PHONE}.\n".encode(), "note.txt"), (fx.make_docx(), "n.docx")):
        remote, mine = admin.redact_document(data, filename=name), local.redact_document(data, filename=name)
        assert remote.data == mine.data and remote.text == mine.text and remote.filename == mine.filename
        assert remote.verified and remote.kind == mine.kind and dict(remote.counts) == dict(mine.counts)
    text_only = admin.redact_document(b"mail a.b@example.com\n", filename="a.txt", file=False)
    assert text_only.data is None and text_only.text == "mail [EMAIL_1]"
    with pytest.raises(DocumentError) as caught:
        admin.redact_document(b"\xd0\xcf\x11\xe0legacy", filename="old.doc")
    assert caught.value.code == "legacy_office" and caught.value.status == 415


# --------------------------------------------------------------------------- authentication and errors
def test_every_call_carries_the_key_and_admin_calls_need_an_admin_key(gateway: Any) -> None:
    admin, team, _, test_client = connect(gateway, **FAST)
    with pytest.raises(AuthenticationError) as missing:
        GatewayClient(URL, api_key="", http_client=test_client).scan("x")
    assert missing.value.status == 401 and missing.value.request_id
    with pytest.raises(AuthenticationError):
        GatewayClient(URL, api_key="harpo_not-a-key", http_client=test_client).policy()
    assert team.scan("mail a.b@example.com").text == "mail [EMAIL_1]"
    admin_calls = [
        lambda c: c.system(), lambda c: c.providers(), lambda c: c.list_keys(), lambda c: c.effective_config(),
        lambda c: c.config_analysis(), lambda c: c.selftest(), lambda c: c.generate_key("x"),
        lambda c: c.validate_config("{}"), lambda c: c.live_policy(), lambda c: c.diagnostics(),
        lambda c: c.attention(), lambda c: c.presets(), lambda c: c.preview_policy("x"),
    ]  # fmt: skip
    for call in admin_calls:
        with pytest.raises(PermissionDeniedError) as denied:
            call(team)
        assert denied.value.status == 403 and denied.value.type == "permission_error"
        call(admin)  # and the admin key may


def test_a_privacy_block_is_a_blocked_error_and_nothing_is_sent(gateway: Any) -> None:
    admin, team, spy, _ = connect(gateway, policy={"entities": {"US_SSN": {"action": "block"}}}, **FAST)
    for client in (admin, team):
        with pytest.raises(BlockedError) as caught:
            client.chat_completion(chat("my SSN is 536-90-4399"))
        error = caught.value
        assert error.status == 403 and error.request_id and error.blocked_types == ("US_SSN",)
        assert error.codes == ("blocked_entity",) and "536-90-4399" not in str(error)
        assert error.override_permitted is (client is admin)
    assert not spy.requests
    preview = admin.preview_egress("openai", chat("my SSN is 536-90-4399"))
    assert preview.decision == "blocked" and not preview.would_forward and preview.status == 403
    assert preview.reasons and preview.reasons[0].code == "blocked_entity"


def test_rate_limits_and_missing_features(gateway: Any) -> None:
    test_client, _ = gateway(auth=keys(requests_per_minute=1), documents={"enabled": False}, **FAST)
    client = GatewayClient(URL, api_key=KEY, http_client=test_client)
    client.scan("x")
    with pytest.raises(RateLimitError) as caught:
        client.scan("x")
    assert caught.value.retry_after and caught.value.retry_after >= 1
    other, _ = gateway(auth=keys(), documents={"enabled": False}, **FAST)
    with pytest.raises(NotFoundError):
        GatewayClient(URL, api_key=KEY, http_client=other).redact_document(b"x", filename="a.txt")


def test_an_unreachable_gateway() -> None:
    with (
        GatewayClient("http://127.0.0.1:9", api_key=KEY, timeout=3) as client,
        pytest.raises(GatewayUnavailableError) as caught,
    ):
        client.health()
    assert caught.value.type in ("connection_error", "timeout") and caught.value.status is None


def test_client_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HARPO_URL", "http://gateway.internal:8080/")
    monkeypatch.setenv("HARPO_KEY", KEY)
    client = GatewayClient()
    assert client.base_url == "http://gateway.internal:8080" and client.openai_base_url.endswith(":8080/v1")
    assert KEY not in repr(client) and "api_key=<set>" in repr(client)
    client.close()
    with pytest.raises(InvalidRequestError):
        GatewayClient("gateway.internal:8080")


# --------------------------------------------------------------------------- the control plane
def test_the_control_plane(gateway: Any, tmp_path: Path) -> None:
    admin, _, _, _ = connect(gateway, policy={"live_file": str(tmp_path / "policy.live.yaml")}, **FAST)
    assert admin.health().version == "2.5.0" and admin.ready().ready
    system = admin.system()
    assert system["version"] == "2.5.0" and system["detection"]["keys"] == "always redacted"
    assert {p["name"] for p in admin.providers()} == {"mock", "mock-anthropic"}
    check = admin.check_provider("mock")
    assert check.name == "mock" and check.reachable
    ids = {k.id: k for k in admin.list_keys()}
    assert set(ids) == {"owner", "team"} and ids["owner"].admin and len(ids["team"].fingerprint) == 8
    new = admin.generate_key("ci-bot", requests_per_minute=60)
    assert new.key.startswith("harpo_") and sha(new.key) == new.sha256 and new.key not in repr(new)
    assert AuthKey.model_validate(yaml.safe_load(new.yaml)[0]).requests_per_minute == 60
    effective = admin.effective_config()
    assert all(k["sha256"].endswith("…") for k in effective["config"]["auth"]["keys"])
    assert admin.validate_config("environment: development\n").valid
    bad = admin.validate_config("policy:\n  default_mode: loud\n")
    assert not bad.valid and bad.errors[0].path == "policy.default_mode" and bad.errors[0].line == 2
    assert all(f.level in ("required", "recommended", "info") for f in admin.config_analysis())
    view = admin.set_live_policy(entities={"EMAIL": "block"}, custom_types=[CustomType("CASE_ID", ("CASE-77",))])
    assert view["updated_by"] == "owner"
    with pytest.raises(BlockedError):
        admin.chat_completion(chat("mail a.b@example.com"))
    assert admin.live_policy()["custom_types"]
    preview = admin.preview_policy("about CASE-77 and a.b@example.com", entities={"EMAIL": "allow"})
    # A draft keeps the configuration file's custom types (none here), as the console's preview does.
    assert preview.text == "about CASE-77 and a.b@example.com"
    admin.reset_live_policy()
    assert admin.chat_completion(chat("mail a.b@example.com")).status == 200
    report = admin.selftest()
    assert report.passed and {r.id for r in report.results} >= {"INV-01", "INV-11"}
    assert admin.selftest_suites(["gateway"])["suites"]
    assert admin.presets()["providers"] and admin.diagnostics()["kind"] == "harpo.diagnostics"
    assert {"posture", "items", "timeline"} <= set(admin.attention())
    assert admin.stats()["scope"] == "all"
    trace = admin.trace("mail a.b@example.com")
    assert trace.data["final"]["text"] == "mail [EMAIL_1]"
    assert isinstance(admin.models(), list) and isinstance(admin.models("anthropic"), list)
    egress = admin.preview_egress("openai", chat("mail a.b@example.com"))
    assert egress.would_forward and egress.body and egress.body["messages"][0]["content"] == "mail [EMAIL_1]"
    assert "a.b@example.com" not in repr(egress)


def test_policy_preview_with_a_draft(gateway: Any) -> None:
    admin, _, _, _ = connect(gateway, **FAST)
    draft = admin.preview_policy("mail a.b@example.com", entities={"EMAIL": "block"})
    assert draft.blocked and draft.risk is Risk.RED and draft.findings[0].type == "EMAIL"
    unchanged = admin.preview_policy("mail a.b@example.com")
    assert unchanged.text == "mail [EMAIL_1]" and not unchanged.blocked


# --------------------------------------------------------------------------- asyncio
def test_the_async_client_equals_the_sync_client(gateway: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    policy = {"entities": {"US_SSN": {"action": "block"}}}
    admin, _, _, _ = connect(gateway, policy=policy, **FAST)
    expected = [_comparable(admin.scan(t)) for t in _corpus(30)]
    monkeypatch.setenv("TEST_UPSTREAM_KEY", "sk-upstream")
    settings = make_settings(auth=keys(), policy=policy, **FAST)
    app = create_app(settings, upstream_transport=SpyTransport())

    async def run() -> list[ScanResult]:
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport) as http:
                client = AsyncGatewayClient(URL, api_key=KEY, http_client=http)
                results = await asyncio.gather(*(client.scan(t) for t in _corpus(30)))
                with pytest.raises(BlockedError):
                    await client.chat_completion(chat("my SSN is 536-90-4399"))
                assert (await client.health()).status == "ok"
                assert (await client.policy()).entities["US_SSN"].action == "block"
                return list(results)

    assert [_comparable(r) for r in asyncio.run(run())] == expected
