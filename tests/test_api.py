"""HTTP surface: auth, limits, headers, scan API, both proxies, streaming, upstream failures."""

from __future__ import annotations

import json

import httpx

from .conftest import ANTHROPIC_UPSTREAM_KEY, AUTH, KEY, UPSTREAM_KEY, chat

SECRET = "sk-proj-7Hq2LmV9xRt4KpZ8wNc3YbF6dJs1GaE5"


# ------------------------------------------------------------------ operational
def test_health_and_readiness(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway()
    assert client.get("/healthz").json()["status"] == "ok"
    ready = client.get("/readyz")
    assert ready.status_code == 200 and ready.json()["checks"]["ner"] == "ok"


def test_readiness_fails_in_production_without_provider_keys(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from fastapi.testclient import TestClient

    from harpo_redact.api import create_app

    from .conftest import make_settings

    monkeypatch.delenv("TEST_UPSTREAM_KEY", raising=False)
    monkeypatch.setenv("TEST_ANTHROPIC_KEY", "set")
    with TestClient(create_app(make_settings(environment="production"))) as client:
        r = client.get("/readyz")
    assert r.status_code == 503 and r.json()["checks"]["upstream_keys"] == "missing:mock"


def test_security_headers_on_every_response(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway()
    for response in (client.get("/healthz"), client.get("/"), client.post("/v1/scan", json={"text": "x"})):
        h = response.headers
        assert "default-src 'none'" in h["content-security-policy"]
        assert h["x-content-type-options"] == "nosniff"
        assert h["x-frame-options"] == "DENY"
        assert len(h["x-harpo-request-id"]) == 32
    assert client.get("/healthz").headers["cache-control"] == "no-store"


def test_console_assets_are_whitelisted(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway()
    assert client.get("/console/app/main.js").status_code == 200
    assert client.get("/console/../config.py").status_code == 404
    assert client.get("/console/fonts/OFL.txt").status_code == 404


def test_console_and_metrics_can_be_disabled(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(server={"console": False, "metrics": False})
    assert client.get("/").status_code == 404
    assert client.get("/metrics").status_code == 404


# ------------------------------------------------------------------ auth
def test_auth_required(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway()
    assert client.post("/v1/scan", json={"text": "x"}).status_code == 401
    assert client.post("/v1/scan", json={"text": "x"}, headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.post("/v1/scan", json={"text": "x"}, headers={"x-api-key": KEY}).status_code == 200
    r = client.post("/v1/messages", json={}, headers={"x-api-key": "nope"})
    assert r.status_code == 401 and r.json()["type"] == "error"  # Anthropic error shape


# ------------------------------------------------------------------ limits and validation
def test_body_size_limit(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(server={"max_body_bytes": 2048})
    r = client.post("/v1/chat/completions", headers=AUTH, content=b"{" + b" " * 5000 + b"}")
    assert r.status_code == 413 and r.json()["error"]["type"] == "request_too_large"


def test_text_and_message_limits(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(server={"max_total_chars": 1000, "max_messages": 2})
    assert client.post("/v1/chat/completions", headers=AUTH, json=chat("a" * 1001)).status_code == 413
    many = {"model": "mock-provider", "messages": [{"role": "user", "content": "hi"}] * 3}
    assert client.post("/v1/chat/completions", headers=AUTH, json=many).status_code == 413


def test_errors_never_echo_request_content(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway()
    marker = "jane.doe@example.com"
    bad_role = {"model": "mock-provider", "messages": [{"role": marker, "content": marker}]}
    r1 = client.post("/v1/chat/completions", headers=AUTH, json=bad_role)
    r2 = client.post("/v1/scan", headers=AUTH, json={"text": [marker]})
    r3 = client.post("/v1/chat/completions", headers=AUTH, content=marker.encode())
    for r in (r1, r2, r3):
        assert r.status_code == 400 and marker not in r.text


def test_model_allowlist(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway()
    r = client.post("/v1/chat/completions", headers=AUTH, json=chat("hi", model="gpt-4o"))
    assert r.status_code == 403 and r.json()["error"]["type"] == "model_not_allowed" and not spy.requests


# ------------------------------------------------------------------ scan API
def test_scan_api(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway()
    r = client.post("/v1/scan", headers=AUTH, json={"texts": ["Mail jane@example.com", "Mail jane@example.com"]})
    body = r.json()
    assert [x["redacted"] for x in body["results"]] == ["Mail [EMAIL_1]", "Mail [EMAIL_1]"]
    assert body["results"][0]["entities"][0] == {
        "type": "EMAIL", "start": 5, "end": 21, "placeholder": "[EMAIL_1]", "sources": ["pattern"],
    }  # fmt: skip
    assert client.post("/v1/scan", headers=AUTH, json={"text": "a", "texts": ["b"]}).status_code == 400


def test_policy_does_not_expose_protected_terms(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(policy={"allow_terms": ["Python"]}, detection={"registry": {"terms": ["Project Bluefin"]}})
    text = client.get("/v1/policy", headers=AUTH).text
    assert "Bluefin" not in text and "Python" not in text and "mock-provider" not in text


# ------------------------------------------------------------------ OpenAI-compatible proxy
def test_openai_request_is_rewritten(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway()
    body = {
        "model": "mock-provider", "user": "anna@corp.example", "store": True, "metadata": {"customer": "Anna"},
        "messages": [
            {"role": "system", "content": "You help Northwind Logistics support."},
            {"role": "user", "name": "Anna Jansen", "content": [
                {"type": "text", "text": "Email anna.jansen@corp.example about card 4111 1111 1111 1111."}]},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "c1", "type": "function", "function": {
                "name": "lookup", "arguments": json.dumps({"email": "anna.jansen@corp.example", "phone": 31207946095})}}]},
            {"role": "tool", "tool_call_id": "c1", "content": "Customer Anna Jansen, phone +31 20 794 6095"},
        ],
    }  # fmt: skip
    r = client.post("/v1/chat/completions", headers=AUTH, json=body)
    assert r.status_code == 200
    raw = spy.bodies[-1].decode()
    for value in ("anna.jansen@corp.example", "4111", "Anna", "Jansen", "794 6095", "31207946095"):
        assert value not in raw
    sent = spy.last_json()
    assert "user" not in sent and "metadata" not in sent and sent["store"] is False
    assert "name" not in sent["messages"][1]
    args = json.loads(sent["messages"][2]["tool_calls"][0]["function"]["arguments"])
    assert args == {"email": "[EMAIL_1]", "phone": "[PHONE_1]"}
    assert sent["messages"][3]["content"].endswith("phone [PHONE_1]")
    upstream = spy.requests[-1]
    assert upstream.headers["authorization"] == f"Bearer {UPSTREAM_KEY}"
    assert KEY not in json.dumps(dict(upstream.headers))
    assert str(upstream.url) == "http://upstream.test/v1/chat/completions"
    assert r.headers["x-harpo-mode"] == "relational" and int(r.headers["x-harpo-redactions"]) >= 6


def test_a_key_is_redacted_and_the_request_goes_on(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway()
    r = client.post("/v1/chat/completions", headers=AUTH, json=chat(f"deploy with {SECRET}"))
    assert r.status_code == 200 and r.headers["x-harpo-risk"] == "yellow"
    sent = spy.bodies[-1].decode()
    assert SECRET not in sent and "deploy with [SECRET_1]" in sent and SECRET not in r.text


def test_a_policy_block_can_be_overridden_and_sends_placeholders(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(policy={"entities": {"EMAIL": {"action": "block", "overridable": True}}})
    r = client.post("/v1/chat/completions", headers=AUTH, json=chat("Mail jane@example.com"))
    error = r.json()["error"]
    assert r.status_code == 403 and error["type"] == "privacy_block"
    assert error["harpo"]["overridable"] is True and error["harpo"]["blocked_types"] == ["EMAIL"]
    assert "jane@example.com" not in r.text and not spy.requests
    override = {**AUTH, "X-Harpo-Override": "true"}
    r = client.post("/v1/chat/completions", headers=override, json=chat("Mail jane@example.com"))
    assert r.status_code == 200 and r.headers["x-harpo-risk"] == "yellow"
    assert "jane@example.com" not in spy.bodies[-1].decode() and "[EMAIL_1]" in spy.bodies[-1].decode()


def test_mode_headers(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway()
    text = "Anna told Ben that Anna's card 4111 1111 1111 1111 was declined."
    headers = {**AUTH, "X-Harpo-Mode": "generic", "X-Harpo-Context-Repair": "true"}
    assert client.post("/v1/chat/completions", headers=headers, json=chat(text)).status_code == 200
    assert spy.last_json()["messages"][0]["content"].startswith("[PERSON_A] told [PERSON_B]")
    bad = client.post("/v1/chat/completions", headers={**AUTH, "X-Harpo-Mode": "loose"}, json=chat(text))
    assert bad.status_code == 400


def test_mode_headers_ignored_when_policy_forbids(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(policy={"client_may_choose_mode": False})
    client.post("/v1/chat/completions", headers={**AUTH, "X-Harpo-Mode": "generic"}, json=chat("Mail jane@example.com"))
    assert spy.last_json()["messages"][0]["content"] == "Mail [EMAIL_1]"


def test_images_block_by_default_and_drop_when_configured(gateway) -> None:  # type: ignore[no-untyped-def]
    content = [{"type": "text", "text": "What is in this picture?"},
               {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}}]  # fmt: skip
    body = {"model": "mock-provider", "messages": [{"role": "user", "content": content}]}
    client, spy = gateway()
    r = client.post("/v1/chat/completions", headers=AUTH, json=body)
    assert r.status_code == 403 and r.json()["error"]["harpo"]["reasons"][0]["code"] == "unsupported_content"
    client, spy = gateway(policy={"unsupported_content": "drop"})
    r = client.post("/v1/chat/completions", headers=AUTH, json=body)
    assert r.status_code == 200 and r.headers["x-harpo-risk"] == "yellow"
    parts = spy.last_json()["messages"][0]["content"]
    assert [p["type"] for p in parts] == ["text", "text"] and "removed by privacy gateway" in parts[1]["text"]


def test_upstream_errors_pass_through_with_safe_headers(gateway) -> None:  # type: ignore[no-untyped-def]
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429,
            json={"error": {"message": "Rate limit reached", "type": "rate_limit_error"}},
            headers={"retry-after": "7", "x-ratelimit-remaining-requests": "0", "set-cookie": "tracking=1"},
        )

    client, _ = gateway(handler)
    r = client.post("/v1/chat/completions", headers=AUTH, json=chat("hello"))
    assert r.status_code == 429 and r.json()["error"]["type"] == "rate_limit_error"
    assert r.headers["retry-after"] == "7" and r.headers["x-ratelimit-remaining-requests"] == "0"
    assert "set-cookie" not in r.headers


def test_upstream_timeout_and_connection_errors(gateway) -> None:  # type: ignore[no-untyped-def]
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    for handler, phrase in ((timeout, "in time"), (refused, "could not be reached")):
        client, _ = gateway(handler)
        r = client.post("/v1/chat/completions", headers=AUTH, json=chat("hello"))
        assert r.status_code == 502 and r.json()["error"]["type"] == "upstream_error" and phrase in r.text


def test_streaming_passthrough(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway()
    r = client.post("/v1/chat/completions", headers=AUTH, json=chat("Stream to bob@example.org", stream=True))
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
    assert r.text.rstrip().endswith("data: [DONE]") and "bob@example.org" not in r.text
    assert spy.last_json()["stream"] is True


# ------------------------------------------------------------------ Anthropic-compatible proxy
def test_anthropic_request_is_rewritten(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway()
    body = {
        "model": "claude-test", "max_tokens": 64, "metadata": {"user_id": "u-123"},
        "system": [{"type": "text", "text": "Assist Jan de Vries."}],
        "messages": [
            {"role": "user", "content": [
                {"type": "text", "text": "Call me at +31 20 794 6095"},
                {"type": "document", "source": {"type": "text", "media_type": "text/plain",
                                                 "data": "Contract for Priya Raman, IBAN NL91ABNA0417164300"}}]},
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": "Jan de Vries wants a call.", "signature": "sig"},
                {"type": "tool_use", "id": "t1", "name": "crm", "input": {"email": "jan@example.nl"}}]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t1", "content": [{"type": "text", "text": "jan@example.nl found"}]}]},
        ],
    }  # fmt: skip
    r = client.post("/v1/messages", headers={"x-api-key": KEY, "anthropic-version": "2023-06-01"}, json=body)
    assert r.status_code == 200 and r.json()["type"] == "message"
    sent = spy.last_json()
    assert "metadata" not in sent
    assert sent["system"][0]["text"] == "Assist [PERSON_1]."
    assert sent["messages"][0]["content"][0]["text"] == "Call me at [PHONE_1]"
    assert "NL91" not in sent["messages"][0]["content"][1]["source"]["data"]
    assert sent["messages"][1]["content"][0]["thinking"] == "Jan de Vries wants a call."  # signed: untouched
    assert sent["messages"][1]["content"][1]["input"] == {"email": "[EMAIL_1]"}
    assert sent["messages"][2]["content"][0]["content"][0]["text"] == "[EMAIL_1] found"
    upstream = spy.requests[-1]
    assert (
        upstream.headers["x-api-key"] == ANTHROPIC_UPSTREAM_KEY
        and upstream.headers["anthropic-version"] == "2023-06-01"
    )
    assert str(upstream.url) == "http://upstream.test/v1/messages"


def test_anthropic_streaming(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway()
    body = {"model": "claude-test", "max_tokens": 64, "stream": True, "messages": [{"role": "user", "content": "hi"}]}
    r = client.post("/v1/messages", headers={"x-api-key": KEY}, json=body)
    assert r.status_code == 200 and "event: message_stop" in r.text


# ------------------------------------------------------------------ hosts and metrics
def test_trusted_hosts(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(server={"allowed_hosts": ["gateway.internal"]})
    assert client.get("/healthz").status_code == 400  # TestClient sends Host: testserver
    assert client.get("/healthz", headers={"host": "gateway.internal"}).status_code == 200


def test_metrics_count_decisions_without_content(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(policy={"entities": {"IBAN": {"action": "block"}}})
    client.post("/v1/chat/completions", headers=AUTH, json=chat("Mail jane@example.com"))
    client.post("/v1/chat/completions", headers=AUTH, json=chat(f"key {SECRET}"))
    client.post("/v1/chat/completions", headers=AUTH, json=chat("Refund to NL91ABNA0417164300"))
    text = client.get("/metrics").text
    assert 'harpo_requests_total{decision="forwarded",risk="green",route="/v1/chat/completions"} 1.0' in text
    assert 'harpo_requests_total{decision="forwarded",risk="yellow",route="/v1/chat/completions"} 1.0' in text
    assert 'harpo_blocks_total{reason="blocked_entity"} 1.0' in text
    assert 'harpo_redactions_total{entity_type="EMAIL"} 1.0' in text
    assert 'harpo_redactions_total{entity_type="SECRET"} 1.0' in text
    assert "jane@example.com" not in text and SECRET not in text and "NL91" not in text
