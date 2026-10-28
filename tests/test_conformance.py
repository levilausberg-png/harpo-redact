"""Adapter conformance (roadmap 30, INV-07, INV-08): every slot of realistic requests, black-box."""

from __future__ import annotations

import re
from typing import Any

import httpx
import pytest

from harpo_redact import conformance
from harpo_redact.adapters import ADAPTERS

from .conftest import AUTH, KEY, chat

FAST = {"detection": {"ner": {"enabled": False}}}


def openai_sample() -> dict[str, Any]:
    return {
        "model": chat("x")["model"],
        "messages": [
            {"role": "system", "content": "You are a careful assistant."},
            {"role": "developer", "content": "Answer in English."},
            {"role": "user", "name": "alice", "content": [{"type": "text", "text": "Summarize the account notes."}]},
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": "lookup", "arguments": '{"query": "open tickets", "limit": 5}'}},
                {"id": "call_2", "type": "custom", "custom": {"name": "sql", "input": "SELECT count(*) FROM tickets"}}],
             "function_call": {"name": "lookup", "arguments": '{"query": "legacy"}'}},
            {"role": "assistant", "content": [{"type": "text", "text": "Partial."}, {"type": "refusal", "refusal": "I cannot share that."}]},
            {"role": "tool", "tool_call_id": "call_1", "content": "Three open tickets."},
            {"role": "assistant", "content": "There are three.", "refusal": "none needed",
             "annotations": [{"type": "url_citation", "url_citation": {"url": "https://example.com/doc", "title": "Doc", "start_index": 0, "end_index": 5}}]},
        ],
        "tools": [
            {"type": "function", "function": {"name": "lookup", "description": "Find tickets.", "parameters": {
                "type": "object", "properties": {"query": {"type": "string", "description": "Search text"}, "limit": {"type": "integer"}},
                "required": ["query"]}}},
            {"type": "custom", "custom": {"name": "sql", "description": "Run a query.", "format": {"type": "grammar", "syntax": "lark", "definition": "start: WORD"}}},
        ],
        "functions": [{"name": "lookup_legacy", "description": "Old style.", "parameters": {"type": "object", "properties": {}}}],
        "tool_choice": {"type": "function", "function": {"name": "lookup"}},
        "response_format": {"type": "json_schema", "json_schema": {"name": "answer", "description": "The answer", "schema": {
            "type": "object", "properties": {"text": {"type": "string"}}}}},
        "stop": ["END"],
        "prediction": {"type": "content", "content": "Expected answer text."},
        "seed": 12345678901,
        "logit_bias": {"50256": -100},
        "temperature": 0.2, "max_completion_tokens": 200, "reasoning_effort": "low", "service_tier": "auto", "verbosity": "low",
        "metadata": {"team": "support"}, "user": "user-123", "safety_identifier": "sid-1", "prompt_cache_key": "cache-1",
        "web_search_options": {"search_context_size": "low", "user_location": {"type": "approximate", "approximate": {"city": "Utrecht"}}},
        "extra_body": {"provider_option": {"mode": "fast"}},
    }  # fmt: skip


def anthropic_sample() -> dict[str, Any]:
    return {
        "model": "claude-test",
        "max_tokens": 128,
        "system": [{"type": "text", "text": "You are careful.", "cache_control": {"type": "ephemeral"}}],
        "messages": [
            {"role": "user", "content": [
                {"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": "Quarterly notes."},
                 "title": "Notes", "context": "Internal", "citations": {"enabled": True}},
                {"type": "search_result", "source": "https://example.com/a", "title": "Result",
                 "content": [{"type": "text", "text": "Snippet text."}]},
                {"type": "text", "text": "What changed?"}]},
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": "Let me look.", "signature": "sig123"},
                {"type": "text", "text": "Checking.", "citations": [{"type": "char_location", "cited_text": "notes", "document_index": 0,
                                                                     "document_title": "Notes", "start_char_index": 0, "end_char_index": 5}]},
                {"type": "tool_use", "id": "toolu_1", "name": "lookup", "input": {"query": "changes"}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": [{"type": "text", "text": "Two changes."}]}]},
        ],
        "tools": [
            {"name": "lookup", "description": "Find changes.", "input_schema": {"type": "object", "properties": {"query": {"type": "string"}}},
             "input_examples": [{"query": "recent"}]},
            {"type": "web_search_20250305", "name": "web_search", "max_uses": 3, "allowed_domains": ["example.com"],
             "user_location": {"type": "approximate", "city": "Utrecht"}},
        ],
        "tool_choice": {"type": "auto"},
        "thinking": {"type": "enabled", "budget_tokens": 1024},
        "stop_sequences": ["END"],
        "metadata": {"user_id": "u-1"},
        "output_format": {"type": "json_schema", "schema": {"type": "object", "properties": {"answer": {"type": "string"}}}},
        "output_config": {"effort": "high", "format": {"type": "json_schema", "schema": {"type": "object", "properties": {"note": {"type": "string"}}}}},
        "cache_control": {"type": "ephemeral", "ttl": "5m"},
        "speed": "fast",
        "inference_geo": "us",
        "service_tier": "auto",
    }  # fmt: skip


OPENROUTER_UPSTREAMS = [
    {"name": "openrouter", "style": "openai", "base_url": "http://upstream.test/v1", "dialect": "openrouter",
     "models": ["*"], "api_key_env": "TEST_UPSTREAM_KEY"},
    {"name": "openrouter-messages", "style": "anthropic", "base_url": "http://upstream.test", "dialect": "openrouter",
     "models": ["*"], "api_key_env": "TEST_ANTHROPIC_KEY"},
]  # fmt: skip


def _openrouter_extras() -> dict[str, Any]:
    """OpenRouter's fields common to both APIs (https://openrouter.ai/docs/api/reference)."""
    return {
        "models": ["anthropic/claude-sonnet-5.5", "openai/gpt-6.1-sol"],
        "fallbacks": [{"model": "google/gemini-3.8-flash"}],
        "route": "fallback",
        "provider": {"order": ["anthropic", "openai"], "only": ["anthropic", "openai", "google-vertex"],
                     "ignore": ["deepinfra"], "allow_fallbacks": True, "require_parameters": True,
                     "data_collection": "allow", "zdr": False, "quantizations": ["fp8"],
                     "sort": {"by": "price", "partition": "model"}, "max_price": {"prompt": "1.5", "completion": "3"},
                     "preferred_max_latency": {"p50": 2}, "options": {"vendor": {"note": "account notes"}}},
        "plugins": [
            {"id": "web", "enabled": True, "engine": "native", "max_results": 3, "search_prompt": "Recent releases",
             "include_domains": ["example.com"], "exclude_domains": ["*.invalid"],
             "user_location": {"type": "approximate", "city": "Utrecht"}, "x_search": {"note": "about releases"}},
            {"id": "file-parser", "pdf": {"engine": "pdf-text"}},
            {"id": "fusion", "analysis_models": ["openai/gpt-6.1-sol"], "model": "anthropic/claude-sonnet-5.5",
             "preset": "general-fast", "tools": [{"type": "web_search", "parameters": {"note": "query text"}}]},
            {"id": "alignment", "rules": ["Answer in English."], "mode": "audit"},
        ],
        "stop_server_tools_when": [{"type": "tool_calls", "note": "stop text"}],
        "session_id": "session-123",
        "trace": {"trace_id": "t-1", "trace_name": "support"},
    }  # fmt: skip


def openrouter_sample() -> dict[str, Any]:
    body = openai_sample()
    body["model"] = "anthropic/claude-sonnet-5.5"
    body["messages"].append(
        {
            "role": "assistant",
            "content": "Done.",
            "model": "openai/gpt-6.1-sol",
            "reasoning": "I looked at the notes.",
            "reasoning_details": [
                {
                    "type": "reasoning.text",
                    "text": "Looked.",
                    "signature": "sig-1",
                    "format": "anthropic-claude-v1",
                    "index": 0,
                }
            ],
        }
    )
    body["messages"][0]["configuration_update"] = {"reasoning": {"effort": "low"}}
    body["messages"][2]["content"][0]["cache_control"] = {"type": "ephemeral", "ttl": "5m"}
    body.update(_openrouter_extras())
    body.update(
        {
            "transforms": ["middle-out"],
            "reasoning": {"effort": "high", "summary": "auto", "max_tokens": 2000, "exclude": False},
            "usage": {"include": True},
            "debug": {"echo_upstream_body": False},
            "top_k": 40,
            "top_a": 0.1,
            "min_p": 0.05,
            "repetition_penalty": 1.1,
            "image_config": {"aspect_ratio": "16:9", "caption": "Chart"},
            "cache_control": {"type": "ephemeral"},
            "prompt_cache_options": {"mode": "explicit", "ttl": "1h"},
            "structured_outputs": True,
        }
    )
    return body  # fmt: skip


def openrouter_grammar_sample() -> dict[str, Any]:
    return {"model": "anthropic/claude-sonnet-5.5", "messages": [{"role": "user", "content": "Write a number."}],
            "response_format": {"type": "grammar", "grammar": "start: NUMBER"}}  # fmt: skip


def openrouter_anthropic_sample() -> dict[str, Any]:
    body = anthropic_sample()
    body["model"] = "anthropic/claude-sonnet-5.5"
    body.update(_openrouter_extras())
    body["user"] = "user-123"
    return body


def make_submit(client: Any, spy: Any, route: str, headers: dict[str, str]):  # type: ignore[no-untyped-def]
    def submit(body: dict[str, Any]) -> conformance.Submission:
        before = len(spy.bodies)
        r = client.post(route, headers=headers, json=body)
        forwarded = spy.bodies[-1].decode("utf-8", "replace") if len(spy.bodies) > before else None
        return conformance.Submission(r.status_code, forwarded, r.text)

    return submit


@pytest.mark.parametrize("mode", ["reject", "pass"])
def test_openai_adapter_conformance(gateway, mode: str) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(policy={"unknown_fields": mode}, **FAST)
    submit = make_submit(client, spy, "/v1/chat/completions", AUTH)
    failures = conformance.run(submit, [openai_sample()], type_confusion=mode == "reject")
    assert failures == []


@pytest.mark.parametrize("mode", ["reject", "pass"])
def test_anthropic_adapter_conformance(gateway, mode: str) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(policy={"unknown_fields": mode}, **FAST)
    submit = make_submit(client, spy, "/v1/messages", {"x-api-key": KEY})
    failures = conformance.run(submit, [anthropic_sample()], exempt=lambda p: False, type_confusion=mode == "reject")
    assert failures == []


@pytest.mark.parametrize(
    ("name", "samples"),
    [
        ("openai", [openai_sample]),
        ("anthropic", [anthropic_sample]),
        ("openrouter", [openrouter_sample, openrouter_grammar_sample]),
        ("openrouter_anthropic", [openrouter_anthropic_sample]),
    ],
)
def test_every_declared_surface_is_exercised_by_the_samples(name: str, samples) -> None:  # type: ignore[no-untyped-def]
    exercised = {conformance.pattern(path) for sample in samples for path, _ in conformance.slots(sample())}
    declared = [  # unsupported surfaces are refused, so a passing sample cannot hold them: tested separately
        s.path
        for s in ADAPTERS[name].surfaces
        if s.handling != "unsupported" and re.fullmatch(r"[A-Za-z_\[\]\.]+", s.path)
    ]
    missing = [
        d for d in declared if not any(e == d or e.startswith(d + ".") or e.startswith(d + "[]") for e in exercised)
    ]
    assert missing == []


@pytest.mark.parametrize("mode", ["reject", "pass"])
def test_openrouter_adapter_conformance(gateway, mode: str) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(policy={"unknown_fields": mode}, upstreams=OPENROUTER_UPSTREAMS, **FAST)
    submit = make_submit(client, spy, "/v1/chat/completions", AUTH)
    failures = conformance.run(
        submit, [openrouter_sample(), openrouter_grammar_sample()], exempt=lambda p: False,
        type_confusion=mode == "reject",
    )  # fmt: skip
    assert failures == []


@pytest.mark.parametrize("mode", ["reject", "pass"])
def test_openrouter_anthropic_adapter_conformance(gateway, mode: str) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(policy={"unknown_fields": mode}, upstreams=OPENROUTER_UPSTREAMS, **FAST)
    submit = make_submit(client, spy, "/v1/messages", {"x-api-key": KEY})
    failures = conformance.run(
        submit, [openrouter_anthropic_sample()], exempt=lambda p: False,
        type_confusion=mode == "reject",
    )  # fmt: skip
    assert failures == []


def test_credentials_never_cross_and_provider_keys_never_come_back(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(**FAST)
    r = client.post(
        "/v1/chat/completions",
        headers={**AUTH, "x-canary-header": conformance.CANARY, "cookie": "s=1"},
        json=chat("hi"),
    )
    assert r.status_code == 200
    sent = {k.lower(): v for k, v in spy.requests[-1].headers.items()}
    assert KEY not in " ".join(sent.values()) and conformance.CANARY not in " ".join(sent.values())
    assert (
        "cookie" not in sent and "x-canary-header" not in sent and sent.get("authorization", "").startswith("Bearer ")
    )
    assert not any(k.lower() in ("authorization", "x-api-key") for k in r.headers)


def test_provider_redirects_are_not_followed_or_relayed(gateway) -> None:  # type: ignore[no-untyped-def]
    def redirect(request: httpx.Request) -> httpx.Response:
        return httpx.Response(307, headers={"location": "https://evil.example/collect"})

    client, _ = gateway(redirect, **FAST)
    r = client.post("/v1/chat/completions", headers=AUTH, json=chat("hi"))
    assert r.status_code == 502 and "evil.example" not in r.text and "location" not in {k.lower() for k in r.headers}


def test_signed_blocks_cannot_carry_extra_fields(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(**FAST)
    body = anthropic_sample()
    body["messages"][1]["content"][0]["note"] = "Priya Raman"
    r = client.post("/v1/messages", headers={"x-api-key": KEY}, json=body)
    assert r.status_code == 400 and not spy.requests
