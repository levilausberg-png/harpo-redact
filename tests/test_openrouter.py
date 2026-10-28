"""OpenRouter: both APIs, enforced provider routing, model checks, bearer auth, aliases, key check, model list.

Field names and behaviour follow OpenRouter's API reference (https://openrouter.ai/docs/api/reference). The
provider is simulated with request handlers; nothing here talks to openrouter.ai.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import httpx
import pytest

from harpo_redact.config import Settings

from .conftest import ANTHROPIC_UPSTREAM_KEY, AUTH, KEY, UPSTREAM_KEY, chat

FAST = {"detection": {"ner": {"enabled": False}}}
ADMIN = {"keys": [{"id": "owner", "sha256": hashlib.sha256(KEY.encode()).hexdigest(), "admin": True}]}
MODEL = "anthropic/claude-sonnet-5.5"
EMAIL = "jane.doe@leak-test.example"


def upstreams(**over: Any) -> list[dict[str, Any]]:
    openai_style = {"name": "openrouter", "style": "openai", "base_url": "http://upstream.test/v1",
                    "dialect": "openrouter", "models": ["*"], "api_key_env": "TEST_UPSTREAM_KEY"}  # fmt: skip
    anthropic_style = {"name": "openrouter-messages", "style": "anthropic", "base_url": "http://upstream.test",
                       "dialect": "openrouter", "models": ["*"], "api_key_env": "TEST_ANTHROPIC_KEY"}  # fmt: skip
    return [{**openai_style, **over}, {**anthropic_style, **over}]


def sent(spy: Any) -> dict[str, Any]:
    return json.loads(spy.bodies[-1])


def ask(client: Any, **extra: Any) -> httpx.Response:
    return client.post(
        "/v1/chat/completions", headers=AUTH, json=chat("Summarize the release notes.", model=MODEL, **extra)
    )


# --------------------------------------------------------------------------- routing policy
def test_providers_that_store_data_are_refused_whatever_the_client_asks(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(upstreams=upstreams(), **FAST)
    assert ask(client).status_code == 200
    assert sent(spy)["provider"] == {"data_collection": "deny"}  # added when the client sent nothing
    assert ask(client, provider={"data_collection": "allow", "sort": "price"}).status_code == 200
    assert sent(spy)["provider"] == {"data_collection": "deny", "sort": "price"}  # loosening is overridden
    assert ask(client, provider={"zdr": True}).status_code == 200
    assert sent(spy)["provider"]["zdr"] is True  # tightening is kept
    event = client.get("/v1/stats?recent=1", headers=AUTH).json()["recent"][0]
    assert event["routing"] == {"data_collection": "deny", "zdr": True}


def test_zdr_only_and_ignore_policies(gateway) -> None:  # type: ignore[no-untyped-def]
    policy = {"zdr": True, "only": ["anthropic", "openai"], "ignore": ["deepinfra"]}
    client, spy = gateway(upstreams=upstreams(openrouter=policy), **FAST)
    assert ask(client, provider={"zdr": False, "only": ["openai", "groq"], "ignore": ["together"]}).status_code == 200
    provider = sent(spy)["provider"]
    assert (
        provider["zdr"] is True and provider["only"] == ["openai"] and provider["ignore"] == ["together", "deepinfra"]
    )
    assert ask(client).status_code == 200 and sent(spy)["provider"]["only"] == ["anthropic", "openai"]
    before = len(spy.requests)
    r = ask(client, provider={"only": ["groq"]})
    assert r.status_code == 403 and r.json()["error"]["code"] == "routing_policy" and len(spy.requests) == before


def test_the_client_may_choose_data_collection_only_when_policy_says_so(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(upstreams=upstreams(openrouter={"data_collection": "client"}), **FAST)
    assert ask(client, provider={"data_collection": "allow"}).status_code == 200
    assert sent(spy)["provider"] == {"data_collection": "allow"}
    assert ask(client).status_code == 200 and "provider" not in sent(spy)


# --------------------------------------------------------------------------- model checks
def test_fallback_models_and_model_choosing_plugins_respect_the_allow_list(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(upstreams=upstreams(models=["anthropic/*"]), **FAST)
    for extra in ({"models": ["openai/gpt-6.1-sol"]}, {"fallbacks": [{"model": "openai/gpt-6.1-sol"}]},
                  {"plugins": [{"id": "auto-router"}]}, {"plugins": [{"id": "fusion", "analysis_models": [MODEL]}]}):  # fmt: skip
        before = len(spy.requests)
        r = ask(client, **extra)
        assert r.status_code == 403 and r.json()["error"]["code"] == "model_not_allowed", extra
        assert len(spy.requests) == before
    assert ask(client, models=["anthropic/claude-opus-5.5"]).status_code == 200
    assert ask(client, plugins=[{"id": "fusion", "enabled": False}]).status_code == 200  # a disabled plugin is fine


def test_model_choosing_plugins_need_an_upstream_that_allows_any_model(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(upstreams=upstreams(), **FAST)
    assert ask(client, plugins=[{"id": "auto-router", "allowed_models": ["anthropic/*"]}]).status_code == 200
    client, _ = gateway(upstreams=upstreams(openrouter={"model_choosing_plugins": "block"}), **FAST)
    assert ask(client, plugins=[{"id": "auto-router"}]).status_code == 403


# --------------------------------------------------------------------------- what is scanned, stripped, refused
def test_openrouter_text_fields_are_redacted_and_identifiers_stripped(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(upstreams=upstreams(), **FAST)
    body = chat(f"Write to {EMAIL}", model=MODEL)
    body["messages"].append({"role": "assistant", "content": "Noted.", "reasoning": f"The user is {EMAIL}."})
    body["messages"].append({"role": "user", "content": "Go on."})
    body["plugins"] = [{"id": "web", "search_prompt": f"news about {EMAIL}", "user_location": {"city": "Utrecht"}}]
    body.update(session_id="user-42-session", trace={"trace_id": "t-1", "trace_name": "jane"})
    r = client.post("/v1/chat/completions", headers=AUTH, json=body)
    assert r.status_code == 200
    out = sent(spy)
    assert EMAIL not in spy.bodies[-1].decode()
    assert "[EMAIL_1]" in out["plugins"][0]["search_prompt"] and "user_location" not in out["plugins"][0]
    assert "[EMAIL_1]" in out["messages"][1]["reasoning"]  # the same value, the same placeholder
    assert "session_id" not in out and "trace" not in out


def test_signed_reasoning_is_forwarded_unchanged_or_not_at_all(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(upstreams=upstreams(), **FAST)
    details = [{"type": "reasoning.text", "text": "Checked the notes.", "signature": "sig-abc", "index": 0}]
    body = chat("Continue.", model=MODEL)
    body["messages"][0:0] = [{"role": "user", "content": "Start."},
                             {"role": "assistant", "content": "Ok.", "reasoning_details": details}]  # fmt: skip
    assert client.post("/v1/chat/completions", headers=AUTH, json=body).status_code == 200
    assert sent(spy)["messages"][1]["reasoning_details"] == details  # a signature must still match
    details[0]["text"] = f"Mail {EMAIL}"
    before = len(spy.requests)
    r = client.post("/v1/chat/completions", headers=AUTH, json=body)
    reasons = [x["code"] for x in r.json()["error"]["harpo"]["reasons"]]
    assert r.status_code == 403 and reasons == ["egress_verification"] and len(spy.requests) == before


def test_generated_images_are_refused_or_dropped_never_forwarded(gateway) -> None:  # type: ignore[no-untyped-def]
    body = chat("Describe it.", model=MODEL)
    image = [{"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}}]
    body["messages"][0:0] = [
        {"role": "user", "content": "Draw."},
        {"role": "assistant", "content": "Here.", "images": image},
    ]
    client, spy = gateway(upstreams=upstreams(), **FAST)
    assert client.post("/v1/chat/completions", headers=AUTH, json=body).status_code == 403 and not spy.requests
    client, spy = gateway(upstreams=upstreams(), policy={"unsupported_content": "drop"}, **FAST)
    assert client.post("/v1/chat/completions", headers=AUTH, json=body).status_code == 200
    assert "images" not in sent(spy)["messages"][1]


# --------------------------------------------------------------------------- transport
def test_bearer_auth_and_static_headers_on_both_apis(gateway) -> None:  # type: ignore[no-untyped-def]
    headers = {"HTTP-Referer": "https://gateway.internal", "X-OpenRouter-Title": "Harpo"}
    client, spy = gateway(upstreams=upstreams(headers=headers), **FAST)
    assert ask(client).status_code == 200
    h = {k.lower(): v for k, v in spy.requests[-1].headers.items()}
    assert h["authorization"] == f"Bearer {UPSTREAM_KEY}" and h["x-openrouter-title"] == "Harpo"
    r = client.post("/v1/messages", headers={"x-api-key": KEY},
                    json={"model": MODEL, "max_tokens": 50, "messages": [{"role": "user", "content": "hi"}]})  # fmt: skip
    h = {k.lower(): v for k, v in spy.requests[-1].headers.items()}
    assert r.status_code == 200 and spy.requests[-1].url.path == "/v1/messages"
    assert h["authorization"] == f"Bearer {ANTHROPIC_UPSTREAM_KEY}" and "x-api-key" not in h
    assert h["http-referer"] == "https://gateway.internal"


def test_anthropic_still_gets_its_own_header(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(**FAST)
    r = client.post("/v1/messages", headers={"x-api-key": KEY},
                    json={"model": "claude-x", "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]})  # fmt: skip
    h = {k.lower(): v for k, v in spy.requests[-1].headers.items()}
    assert r.status_code == 200 and h["x-api-key"] == ANTHROPIC_UPSTREAM_KEY and "authorization" not in h


@pytest.mark.parametrize("name", ["Authorization", "x-api-key", "Cookie", "Host", "bad name"])
def test_credential_and_reserved_headers_cannot_be_configured(name: str) -> None:
    with pytest.raises(ValueError, match="header"):
        Settings(upstreams=upstreams(headers={name: "value"}))


def test_api_v1_paths_for_openrouter_native_clients(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(upstreams=upstreams(), **FAST)
    r = client.post("/api/v1/chat/completions", headers=AUTH, json=chat(f"Mail {EMAIL}", model=MODEL))
    assert r.status_code == 200 and EMAIL not in spy.bodies[-1].decode()
    r = client.post("/api/v1/messages", headers={"x-api-key": KEY},
                    json={"model": MODEL, "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]})  # fmt: skip
    assert r.status_code == 200
    assert client.get("/api/v1/models", headers=AUTH).status_code == 200
    routes = [e["route"] for e in client.get("/v1/stats?recent=5", headers=AUTH).json()["recent"]]
    assert routes[:2] == ["/v1/messages", "/v1/chat/completions"]  # recorded under the canonical routes
    assert client.post("/api/v1/chat/completions", json=chat("hi", model=MODEL)).status_code == 401


def test_streamed_keepalive_comments_pass_through(gateway) -> None:  # type: ignore[no-untyped-def]
    stream = (b": OPENROUTER PROCESSING\n\n"
              b'data: {"choices":[{"delta":{"content":"Hi"},"index":0}]}\n\n'
              b": OPENROUTER PROCESSING\n\n"
              b'data: {"choices":[{"delta":{"reasoning":"ok"},"index":0,"finish_reason":"stop"}]}\n\n'
              b"data: [DONE]\n\n")  # fmt: skip

    def handler(request: httpx.Request) -> httpx.Response | None:
        if request.url.path.endswith("/chat/completions"):
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=stream)
        return None

    client, _ = gateway(handler, upstreams=upstreams(), **FAST)
    r = client.post("/v1/chat/completions", headers=AUTH, json=chat("hi", model=MODEL, stream=True))
    assert r.status_code == 200 and r.content == stream


def test_response_scanning_includes_reasoning(gateway) -> None:  # type: ignore[no-untyped-def]
    answer = {"id": "gen-1", "object": "chat.completion", "model": MODEL, "provider": "Anthropic",
              "choices": [{"index": 0, "finish_reason": "stop",
                           "message": {"role": "assistant", "content": "Done.", "reasoning": f"Found {EMAIL}."}}],
              "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7, "cost": 0.0001}}  # fmt: skip

    def handler(request: httpx.Request) -> httpx.Response | None:
        return httpx.Response(200, json=answer) if request.url.path.endswith("/chat/completions") else None

    client, _ = gateway(handler, upstreams=upstreams(), policy={"response_scan": "redact"}, **FAST)
    r = ask(client)
    assert r.status_code == 200 and EMAIL not in r.text and r.headers["x-harpo-response-findings"] == "1"
    assert r.json()["usage"]["cost"] == 0.0001  # everything else comes back as it was


# --------------------------------------------------------------------------- key check and model list
def test_key_check_uses_the_key_endpoint_and_reports_limits_only(gateway) -> None:  # type: ignore[no-untyped-def]
    account = {"label": "Jan's laptop key", "limit": 10, "limit_remaining": 7.5, "limit_reset": "monthly", "usage": 2.5,
               "usage_daily": 0.1, "usage_monthly": 2.5, "is_free_tier": False, "creator_user_id": "user_2abc",
               "organization_id": "org_9", "workspace_id": "ws_1", "allowed_data_regions": ["europe"],
               "expires_at": None}  # fmt: skip
    status = {"code": 200}

    def handler(request: httpx.Request) -> httpx.Response | None:
        if request.url.path == "/v1/key":
            ok = request.headers.get("authorization") == f"Bearer {UPSTREAM_KEY}" and status["code"] == 200
            return httpx.Response(200, json={"data": account}) if ok else httpx.Response(401, json={"error": {}})
        return None

    client, _ = gateway(handler, auth=ADMIN, upstreams=upstreams(), **FAST)
    check = client.post("/v1/providers/openrouter/check", headers=AUTH).json()
    assert check["auth"] == "accepted" and check["checked"] == "key endpoint"
    assert check["account"]["limit_remaining"] == 7.5 and check["account"]["allowed_data_regions"] == ["europe"]
    text = json.dumps(check)
    assert "Jan" not in text and "user_2abc" not in text and "org_9" not in text and "ws_1" not in text
    status["code"] = 401
    assert client.post("/v1/providers/openrouter/check", headers=AUTH).json()["auth"] == "rejected"
    provider = next(
        p for p in client.get("/v1/providers", headers=AUTH).json()["providers"] if p["name"] == "openrouter"
    )
    assert provider["dialect"] == "openrouter" and provider["routing"]["data_collection"] == "deny"


def test_model_list_adds_the_providers_matching_models_and_survives_failures(gateway) -> None:  # type: ignore[no-untyped-def]
    calls = {"n": 0, "fail": False}
    listing = {"data": [{"id": MODEL}, {"id": "anthropic/claude-opus-5.5"}, {"id": "openai/gpt-6.1-sol"},
                        {"id": "bad id\nwith a newline"}, {"no_id": True}]}  # fmt: skip

    def handler(request: httpx.Request) -> httpx.Response | None:
        if request.url.path == "/v1/models":
            calls["n"] += 1
            return httpx.Response(500) if calls["fail"] else httpx.Response(200, json=listing)
        return None

    client, _ = gateway(handler, upstreams=upstreams(models=["anthropic/*", "house-model"]), **FAST)
    ids = [m["id"] for m in client.get("/v1/models", headers=AUTH).json()["data"]]
    assert ids == ["house-model", MODEL, "anthropic/claude-opus-5.5"]
    client.get("/v1/models", headers=AUTH)
    assert calls["n"] == 1  # cached
    client, _ = gateway(handler, upstreams=upstreams(models=["anthropic/*", "house-model"]), **FAST)
    calls["fail"] = True
    assert [m["id"] for m in client.get("/v1/models", headers=AUTH).json()["data"]] == ["house-model"]


# --------------------------------------------------------------------------- Anthropic fields Claude Code sends
def test_current_anthropic_fields_are_understood(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(**FAST)
    schema = {"type": "object", "properties": {"note": {"type": "string", "description": f"Copy {EMAIL}"}}}
    body = {"model": "claude-x", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}],
            "output_config": {"effort": "high", "format": {"type": "json_schema", "schema": schema}},
            "cache_control": {"type": "ephemeral", "ttl": "1h"}, "speed": "fast", "inference_geo": "eu"}  # fmt: skip
    r = client.post("/v1/messages", headers={"x-api-key": KEY}, json=body)
    assert r.status_code == 200 and EMAIL not in spy.bodies[-1].decode()
    assert sent(spy)["output_config"]["effort"] == "high" and sent(spy)["speed"] == "fast"
    body["speed"] = f"fast {EMAIL}"  # identifiers are shape-checked: free text cannot ride in them
    assert client.post("/v1/messages", headers={"x-api-key": KEY}, json=body).status_code == 400


def test_egress_preview_accepts_api_styles_only(gateway) -> None:  # type: ignore[no-untyped-def]
    """Adapter names ("openrouter") are not API styles: the preview takes "openai" or "anthropic" and picks the
    adapter from the upstream, as the proxy does."""
    client, _ = gateway()
    body = {"model": "mock-provider", "messages": [{"role": "user", "content": "hi"}]}
    for style in ("openrouter", "openrouter_anthropic"):
        assert client.post("/v1/egress/preview", headers=AUTH, json={"style": style, "body": body}).status_code == 400
    assert client.post("/v1/egress/preview", headers=AUTH, json={"style": "openai", "body": body}).status_code == 200
