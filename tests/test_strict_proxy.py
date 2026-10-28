"""Strict request handling: field allowlist, hidden text fields, remote tools, overrides, caps, NER cache."""

from __future__ import annotations

import json

import httpx

from harpo_redact.api import load_ner
from harpo_redact.config import Settings

from .conftest import AUTH, KEY, READONLY, chat

SECRET = "sk-proj-7Hq2LmV9xRt4KpZ8wNc3YbF6dJs1GaE5"


def test_unknown_fields_are_rejected_unless_policy_passes_them(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway()
    r = client.post("/v1/chat/completions", headers=AUTH, json=chat("hi", instructions="Anna Jansen"))
    assert r.status_code == 400 and "instructions" in r.json()["error"]["message"] and not spy.requests
    r = client.post("/v1/chat/completions", headers=AUTH, json=chat("hi", **{"Jane Doe <jane@x.com>": 1}))
    assert r.status_code == 400 and "jane" not in r.text.lower()  # odd field names are not echoed
    client, spy = gateway(policy={"unknown_fields": "pass"})
    assert client.post("/v1/chat/completions", headers=AUTH, json=chat("hi", instructions="x")).status_code == 200


def test_tool_definitions_and_stop_sequences_are_scanned(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway()
    body = chat(
        "Look up the customer",
        stop=["Thanks, Anna Jansen"],
        tools=[{"type": "function", "function": {
            "name": "lookup", "description": "Find orders for anna.jansen@corp.example",
            "parameters": {"type": "object", "properties": {"email": {"type": "string",
                           "description": "default jane.doe@example.com"}}}}}],
        response_format={"type": "json_schema", "json_schema": {"name": "r", "schema": {"type": "object",
                         "description": "Reply to +31 20 794 6095"}}},
        web_search_options={"user_location": {"type": "approximate", "approximate": {"city": "Utrecht"}}},
        prompt_cache_key="user-anna-jansen",
    )  # fmt: skip
    assert client.post("/v1/chat/completions", headers=AUTH, json=body).status_code == 200
    raw = spy.bodies[-1].decode()
    for value in ("anna.jansen@corp.example", "jane.doe@example.com", "794 6095", "Anna", "Utrecht", "user-anna"):
        assert value not in raw
    sent = spy.last_json()
    assert "user_location" not in sent["web_search_options"] and "prompt_cache_key" not in sent


def test_anthropic_tools_and_remote_mcp(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway()
    body = {"model": "claude-test", "max_tokens": 32, "stop_sequences": ["Regards, Lars Eriksen"],
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"name": "crm", "description": "CRM export, owner priya.raman@corp.example",
                       "input_schema": {"type": "object", "description": "Call +31 20 794 6095 first"}},
                      {"type": "web_search_20250305", "name": "web_search",
                       "user_location": {"type": "approximate", "city": "Rotterdam"}}]}  # fmt: skip
    assert client.post("/v1/messages", headers={"x-api-key": KEY}, json=body).status_code == 200
    raw = spy.bodies[-1].decode()
    assert "Lars" not in raw and "priya.raman" not in raw and "794 6095" not in raw and "Rotterdam" not in raw
    remote = {**body, "mcp_servers": [{"type": "url", "url": "https://mcp.example", "authorization_token": "t"}]}
    r = client.post("/v1/messages", headers={"x-api-key": KEY}, json=remote)
    assert r.status_code == 403 and r.json()["error"]["harpo"]["reasons"][0]["code"] == "remote_tools"


def test_override_is_a_per_key_permission(gateway) -> None:  # type: ignore[no-untyped-def]
    blocking = {"entities": {"IBAN": {"action": "block", "overridable": True}}}
    client, spy = gateway(policy=blocking)
    headers = {**READONLY, "X-Harpo-Override": "true"}
    r = client.post("/v1/chat/completions", headers=headers, json=chat("refund NL91ABNA0417164300"))
    assert r.status_code == 403 and r.json()["error"]["harpo"]["override_permitted"] is False
    assert r.json()["error"]["harpo"]["overridable"] is False and not spy.requests
    assert client.get("/v1/policy", headers=READONLY).json()["override_permitted"] is False
    assert client.get("/v1/policy", headers=AUTH).json()["override_permitted"] is True
    client, _ = gateway(policy={**blocking, "override": "never"})
    r = client.post(
        "/v1/chat/completions", headers={**AUTH, "X-Harpo-Override": "true"}, json=chat("NL91ABNA0417164300")
    )
    assert r.status_code == 403


def test_provider_responses_are_size_capped(gateway) -> None:  # type: ignore[no-untyped-def]
    def huge(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 5000, headers={"content-type": "application/json"})

    upstreams = [{"name": "mock", "style": "openai", "base_url": "http://upstream.test/v1", "models": ["mock-*"],
                  "max_response_bytes": 2048}]  # fmt: skip
    client, _ = gateway(huge, upstreams=upstreams)
    r = client.post("/v1/chat/completions", headers=AUTH, json=chat("hello"))
    assert r.status_code == 502 and "size limit" in r.json()["error"]["message"]


def test_ner_cache_reuses_results_without_storing_text() -> None:
    cfg = Settings(environment="development", detection={"ner": {"cache_entries": 100}}).detection.ner
    ner = load_ner(cfg)
    text = "Ask Lars Eriksen in Rotterdam about the refund."
    first = ner.detect_many([text])
    hits = ner.cache_hits
    second = ner.detect_many([text, "A brand new message."])
    assert [(s.start, s.end, s.type) for s in second[0]] == [(s.start, s.end, s.type) for s in first[0]]
    assert ner.cache_hits == hits + 1
    stored = json.dumps([[list(map(str, e)) for e in v[1]] for v in ner._cache.values()])
    assert "Lars" not in stored and "Rotterdam" not in stored
