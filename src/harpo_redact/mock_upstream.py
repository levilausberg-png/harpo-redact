"""A stand-in provider for demos and local testing. Never use it in production.

It answers in the OpenAI and Anthropic wire formats (including streaming) and
echoes the last user message exactly as it arrived, which makes it easy to see
what a real provider would have received through the gateway.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import AsyncIterator
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from .entities import PLACEHOLDER_RE


def _last_user_text(messages: list[Any]) -> str:
    for message in reversed(messages):
        if not isinstance(message, dict) or message.get("role") != "user":
            continue
        content = message.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            return "\n".join(p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text")
    return ""


def compose_reply(messages: list[Any]) -> str:
    received = _last_user_text(messages)
    seen = list(dict.fromkeys(PLACEHOLDER_RE.findall(received)))
    lines = ["Mock provider, demo only. Your last message reached me as:", "", received.strip() or "(empty)", ""]
    if seen:
        listed = ", ".join(seen[:8]) + (" and more" if len(seen) > 8 else "")
        lines.append(f"I can refer to {listed}, but I never received the values behind them.")
    else:
        lines.append("It contained no placeholders.")
    return "\n".join(lines)


def _chunks(text: str, size: int = 24) -> list[str]:
    return [text[i : i + size] for i in range(0, len(text), size)]


def create_mock_app() -> FastAPI:
    app = FastAPI(title="Mock provider", docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/v1/chat/completions")
    async def chat(request: Request) -> Any:
        body = await request.json()
        reply = compose_reply(body.get("messages", []))
        model = body.get("model", "mock-provider")
        cid = f"chatcmpl-{uuid.uuid4().hex[:24]}"
        created = int(time.time())
        if body.get("stream"):

            async def events() -> AsyncIterator[bytes]:
                for piece in _chunks(reply):
                    chunk = {
                        "id": cid,
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": model,
                        "choices": [{"index": 0, "delta": {"content": piece}, "finish_reason": None}],
                    }
                    yield f"data: {json.dumps(chunk)}\n\n".encode()
                done = {
                    "id": cid,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                }
                yield f"data: {json.dumps(done)}\n\ndata: [DONE]\n\n".encode()

            return StreamingResponse(events(), media_type="text/event-stream")
        return JSONResponse(
            {
                "id": cid,
                "object": "chat.completion",
                "created": created,
                "model": model,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": reply}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            },
            headers={"x-request-id": f"req_{uuid.uuid4().hex[:16]}"},
        )

    @app.post("/v1/messages")
    async def messages(request: Request) -> Any:
        body = await request.json()
        reply = compose_reply(body.get("messages", []))
        model = body.get("model", "mock-provider")
        mid = f"msg_{uuid.uuid4().hex[:24]}"
        if body.get("stream"):

            async def events() -> AsyncIterator[bytes]:
                def event(name: str, data: dict[str, Any]) -> bytes:
                    return f"event: {name}\ndata: {json.dumps(data)}\n\n".encode()

                start = {  # the shape the real API sends; SDKs read usage from it
                    "id": mid, "type": "message", "role": "assistant", "model": model, "content": [],
                    "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1},
                }  # fmt: skip
                yield event("message_start", {"type": "message_start", "message": start})
                yield event(
                    "content_block_start",
                    {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
                )
                for piece in _chunks(reply):
                    yield event(
                        "content_block_delta",
                        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": piece}},
                    )
                yield event("content_block_stop", {"type": "content_block_stop", "index": 0})
                yield event(
                    "message_delta",
                    {
                        "type": "message_delta",
                        "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                        "usage": {"output_tokens": max(1, len(reply) // 4)},
                    },
                )
                yield event("message_stop", {"type": "message_stop"})

            return StreamingResponse(events(), media_type="text/event-stream")
        return JSONResponse(
            {
                "id": mid,
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": [{"type": "text", "text": reply}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 0, "output_tokens": 0},
            }
        )

    @app.post("/v1/messages/count_tokens")
    async def count_tokens(request: Request) -> Any:
        body = await request.json()
        return {"input_tokens": max(1, len(json.dumps(body.get("messages", []))) // 4)}

    return app
