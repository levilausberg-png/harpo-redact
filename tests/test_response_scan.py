"""Response scanning (roadmap 22): what the model wrote back, checked with the deterministic layers."""

from __future__ import annotations

import json

import httpx

from .conftest import AUTH, KEY, chat

FAST = {"detection": {"ner": {"enabled": False}}}
LEAKY = "Sure: card 4111 1111 1111 1111, key AKIAZ4X7Q2LMWN3RT5PJ, mail ops.lead@corp.example. Ask Emily Thompson."


def openai_answer(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={
        "id": "c1", "object": "chat.completion",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": LEAKY, "tool_calls": [
            {"id": "t1", "type": "function", "function": {"name": "f", "arguments": json.dumps({"to": "ops.lead@corp.example"})}}]}}],
    })  # fmt: skip


def anthropic_answer(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={
        "id": "m1", "type": "message", "role": "assistant",
        "content": [{"type": "text", "text": LEAKY}, {"type": "tool_use", "id": "tu", "name": "f", "input": {"card": "4111111111111111"}}],
    })  # fmt: skip


def test_off_by_default_leaves_answers_alone(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(openai_answer, **FAST)
    r = client.post("/v1/chat/completions", headers=AUTH, json=chat("hi"))
    assert "4111 1111 1111 1111" in r.text and "x-harpo-response-scan" not in r.headers


def test_report_counts_without_changing_the_answer(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(openai_answer, policy={"response_scan": "report"}, **FAST)
    r = client.post("/v1/chat/completions", headers=AUTH, json=chat("hi"))
    assert r.headers["x-harpo-response-scan"] == "report" and int(r.headers["x-harpo-response-findings"]) == 4
    assert "4111 1111 1111 1111" in r.text


def test_redact_replaces_values_but_not_names(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(openai_answer, policy={"response_scan": "redact"}, **FAST)
    body = client.post("/v1/chat/completions", headers=AUTH, json=chat("hi")).json()
    message = body["choices"][0]["message"]
    assert "4111" not in message["content"] and "AKIAZ4X7Q2LMWN3RT5PJ" not in message["content"]
    assert "[CREDIT_CARD]" in message["content"] and "Emily Thompson" in message["content"]
    assert json.loads(message["tool_calls"][0]["function"]["arguments"]) == {"to": "[EMAIL]"}


def test_redact_anthropic_text_and_tool_input(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(anthropic_answer, policy={"response_scan": "redact"}, **FAST)
    body = {"model": "claude-test", "max_tokens": 8, "messages": [{"role": "user", "content": "hi"}]}
    out = client.post("/v1/messages", headers={"x-api-key": KEY}, json=body).json()
    assert "[EMAIL]" in out["content"][0]["text"] and out["content"][1]["input"] == {"card": "[CREDIT_CARD]"}


def test_streamed_answers_are_marked_as_not_scanned(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(policy={"response_scan": "redact"}, **FAST)
    with client.stream("POST", "/v1/chat/completions", headers=AUTH, json=chat("hi", stream=True)) as r:
        assert r.headers["x-harpo-response-scan"] == "not_scanned_stream"
