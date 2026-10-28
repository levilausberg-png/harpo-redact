"""Control-plane API for the console: exact egress, system, providers, keys, configuration and self-test."""

from __future__ import annotations

import hashlib
import json

import pytest

from .conftest import AUTH, KEY, chat, make_settings

FAST = {"detection": {"ner": {"enabled": False}}}
PROVIDER_KEY = "sk-provider-canary-9f3a7c1e5b"


def sha(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def two_keys() -> dict[str, object]:
    return {
        "keys": [{"id": "owner", "sha256": sha(KEY), "admin": True}, {"id": "team", "sha256": sha("team-key-123456")}]
    }


def test_the_egress_preview_is_exactly_what_the_proxy_sends(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(**FAST)
    body = chat("Refund jane.doe@acme.com to IBAN NL91ABNA0417164300, call +31 20 794 6095")
    preview = client.post("/v1/egress/preview", headers=AUTH, json={"style": "openai", "body": body}).json()
    assert preview["decision"] == "would_forward" and not spy.requests
    assert client.post("/v1/chat/completions", headers=AUTH, json=body).status_code == 200
    assert preview["body"] == json.loads(spy.bodies[-1]) and "jane.doe" not in json.dumps(preview)
    assert preview["upstream"]["url"].endswith("/chat/completions") and "egress" in preview["timings_ms"]


def test_a_blocked_preview_says_why_and_sends_nothing(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(policy={"entities": {"IBAN": {"action": "block"}}}, **FAST)
    body = chat("refund to NL91ABNA0417164300")
    r = client.post("/v1/egress/preview", headers=AUTH, json={"style": "openai", "body": body}).json()
    assert r["decision"] == "blocked" and r["status"] == 403 and r["details"]["reasons"] and not spy.requests


def test_a_key_in_a_preview_goes_out_as_a_placeholder(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(**FAST)
    body = chat("deploy with AKIAZ4X7Q2LMWN3RT5PJ")
    r = client.post("/v1/egress/preview", headers=AUTH, json={"style": "openai", "body": body}).json()
    assert r["decision"] == "would_forward" and "AKIAZ4X7Q2LMWN3RT5PJ" not in json.dumps(r) and not spy.requests
    assert r["body"]["messages"][0]["content"] == "deploy with [SECRET_1]"


@pytest.mark.parametrize(
    ("method", "path"),
    [("get", "/v1/system"), ("get", "/v1/providers"), ("get", "/v1/keys"), ("get", "/v1/config/effective"),
     ("post", "/v1/config/validate"), ("post", "/v1/selftest"), ("post", "/v1/keys/generate"), ("post", "/v1/providers/x/check")],
)  # fmt: skip
def test_control_plane_endpoints_need_an_admin_key(gateway, method: str, path: str) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(auth=two_keys(), **FAST)
    r = getattr(client, method)(
        path, headers={"authorization": "Bearer team-key-123456"}, **({"json": {}} if method == "post" else {})
    )
    assert r.status_code == 403 and r.json()["error"]["type"] == "permission_error"


def test_no_provider_key_appears_anywhere(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(auth=two_keys(), **FAST)
    name = make_settings().upstreams[0].name
    check = client.post(f"/v1/providers/{name}/check", headers=AUTH).json()
    assert check["reachable"] and isinstance(check["status"], int)
    sent = {k.lower(): v for k, v in spy.requests[-1].headers.items()}
    provider_key = (sent.get("authorization", "").removeprefix("Bearer ") or sent.get("x-api-key", "")).strip()
    assert len(provider_key) > 8  # the check really authenticated with the configured key
    responses = [
        client.get(p, headers=AUTH) for p in ("/v1/system", "/v1/providers", "/v1/config/effective", "/v1/keys")
    ]
    assert all(r.status_code == 200 for r in responses)  # no vacuous pass on an error page
    for text in [*(r.text for r in responses), json.dumps(check)]:
        assert provider_key not in text and sha(KEY) not in text


def test_a_generated_key_is_shown_once_and_not_stored(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(auth=two_keys(), **FAST)
    r = client.post("/v1/keys/generate", headers=AUTH, json={"id": "ci-bot", "requests_per_minute": 60})
    data = r.json()
    assert r.headers["cache-control"] == "no-store" and data["persisted"] is False
    assert data["sha256"] == sha(data["key"]) and "ci-bot" in data["yaml"] and data["key"] not in data["yaml"]
    assert client.get("/v1/policy", headers={"authorization": f"Bearer {data['key']}"}).status_code == 401
    assert client.post("/v1/keys/generate", headers=AUTH, json={"id": "bad id!"}).status_code == 400


def test_configuration_validation_points_at_lines_and_never_saves(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(auth=two_keys(), **FAST)
    broken = client.post(
        "/v1/config/validate", headers=AUTH, json={"yaml": "policy:\n  unknown_fields: maybe\n"}
    ).json()
    assert (
        broken["valid"] is False
        and broken["errors"][0]["path"] == "policy.unknown_fields"
        and broken["errors"][0]["line"] == 2
    )
    syntax = client.post("/v1/config/validate", headers=AUTH, json={"yaml": "policy: [unclosed\n"}).json()
    assert syntax["valid"] is False and syntax["errors"][0]["line"]
    effective = client.get("/v1/config/effective", headers=AUTH).json()
    ok = client.post(
        "/v1/config/validate",
        headers=AUTH,
        json={"yaml": effective["yaml"].replace("unknown_fields: reject", "unknown_fields: pass")},
    ).json()
    assert ok["valid"] is True and ok["saved"] is False and "+  unknown_fields: pass" in ok["diff"]
    assert all(k["sha256"].endswith("…") for k in effective["config"]["auth"]["keys"])


def test_the_self_test_exercises_the_live_path(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(auth=two_keys(), **FAST)
    r = client.post("/v1/selftest", headers=AUTH).json()
    by_id = {x["id"]: x["status"] for x in r["results"]}
    assert r["passed"] and by_id["INV-01"] == "pass" and by_id["INV-08"] == "pass" and by_id["INV-04"] == "pass"
    assert by_id["INV-09"] == "pass" and not spy.requests  # nothing was sent anywhere
    assert client.get("/v1/stats", headers=AUTH).json()["totals"]["requests"] == 0  # and nothing was counted as traffic


def test_stats_carry_request_ids_stage_timings_and_upstreams(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(**FAST)
    r = client.post("/v1/chat/completions", headers=AUTH, json=chat("Mail jane.doe@acme.com"))
    st = client.get("/v1/stats?recent=200", headers=AUTH).json()
    event = st["recent"][0]
    assert event["request_id"] == r.headers["x-harpo-request-id"] and "patterns" in event["timings_ms"]
    assert st["stages"]["total"]["count"] == 1 and next(iter(st["upstreams"].values()))["requests"] == 1
