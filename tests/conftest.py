"""Shared fixtures: settings factory, a recording upstream transport, an app client."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from collections.abc import Callable, Iterator
from typing import Any, NoReturn

import httpx
import pytest
from fastapi.testclient import TestClient

from harpo_redact.api import create_app, load_ner
from harpo_redact.config import Settings
from harpo_redact.mock_upstream import create_mock_app
from harpo_redact.pipeline import Pipeline

KEY = "harpo_unit-test-key-0123456789abcdef"
KEY_HASH = hashlib.sha256(KEY.encode()).hexdigest()
AUTH = {"Authorization": f"Bearer {KEY}"}
READONLY_KEY = "harpo_unit-test-readonly-key-9876543210"
READONLY = {"Authorization": f"Bearer {READONLY_KEY}"}
UPSTREAM_KEY = "sk-upstream-provider-key-000111222333"
ANTHROPIC_UPSTREAM_KEY = "sk-ant-upstream-provider-key-444555666"

# Tools some evidence needs: "browser" (Playwright and Chromium), "libreoffice", "models" (the spaCy language models).
# Missing locally, those tests skip. CI sets HARPO_REQUIRE=browser,libreoffice,models, and then a missing tool fails
# them instead: evidence that quietly stops running is not evidence.
REQUIRED = frozenset(part.strip() for part in os.environ.get("HARPO_REQUIRE", "").split(",") if part.strip())
CAPABILITIES = frozenset({"browser", "libreoffice", "models"})
if REQUIRED - CAPABILITIES:
    raise ValueError(f"HARPO_REQUIRE names unknown tools: {sorted(REQUIRED - CAPABILITIES)}")


def needs(capability: str, reason: str) -> NoReturn:
    """Skip the current test for want of a tool, or fail it when HARPO_REQUIRE says the tool must be there."""
    assert capability in CAPABILITIES, capability
    if capability in REQUIRED:
        pytest.fail(f"{reason}; HARPO_REQUIRE includes {capability}", pytrace=False)
    pytest.skip(reason)


def _merge(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def make_settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "environment": "development",
        "auth": {
            "enabled": True,
            "keys": [
                {"id": "tests", "sha256": KEY_HASH, "can_override": True},
                {"id": "readonly", "sha256": hashlib.sha256(READONLY_KEY.encode()).hexdigest()},
            ],
        },
        "upstreams": [
            {"name": "mock", "style": "openai", "base_url": "http://upstream.test/v1", "models": ["mock-*"],
             "api_key_env": "TEST_UPSTREAM_KEY"},
            {"name": "mock-anthropic", "style": "anthropic", "base_url": "http://upstream.test",
             "models": ["claude-*"], "api_key_env": "TEST_ANTHROPIC_KEY"},
        ],
    }  # fmt: skip
    return Settings(**_merge(base, overrides))


Handler = Callable[[httpx.Request], httpx.Response | None]


class SpyTransport(httpx.AsyncBaseTransport):
    """Records every upstream request, then answers with a handler or the mock provider."""

    def __init__(self, handler: Handler | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self.bodies: list[bytes] = []
        self._handler = handler
        self._mock = httpx.ASGITransport(app=create_mock_app())

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body = await request.aread()
        self.requests.append(request)
        self.bodies.append(body)
        if self._handler is not None:
            response = self._handler(request)
            if response is not None:
                return response
        return await self._mock.handle_async_request(request)

    def last_json(self) -> Any:
        return json.loads(self.bodies[-1])


@pytest.fixture(scope="session")
def ner():  # type: ignore[no-untyped-def]
    return load_ner(Settings(environment="development").detection.ner)


@pytest.fixture
def pipeline(ner) -> Pipeline:  # type: ignore[no-untyped-def]
    return Pipeline(make_settings(), ner=ner)


@pytest.fixture
def make_pipeline(ner) -> Callable[..., Pipeline]:  # type: ignore[no-untyped-def]
    def factory(**overrides: Any) -> Pipeline:
        settings = make_settings(**overrides)
        # The settings decide: NER off means off, other NER settings mean that model (load_ner caches per config).
        model = load_ner(settings.detection.ner) if settings.detection.ner.enabled else None
        return Pipeline(settings, ner=model)

    return factory


@pytest.fixture
def gateway(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[..., tuple[TestClient, SpyTransport]]]:
    clients: list[TestClient] = []

    def factory(
        handler: Handler | None = None, slm_transport: httpx.AsyncBaseTransport | None = None, **overrides: Any
    ) -> tuple[TestClient, SpyTransport]:
        monkeypatch.setenv("TEST_UPSTREAM_KEY", UPSTREAM_KEY)
        monkeypatch.setenv("TEST_ANTHROPIC_KEY", ANTHROPIC_UPSTREAM_KEY)
        spy = SpyTransport(handler)
        app = create_app(make_settings(**overrides), upstream_transport=spy, slm_transport=slm_transport)
        client = TestClient(app)
        client.__enter__()
        clients.append(client)
        return client, spy

    yield factory
    for client in clients:
        client.__exit__(None, None, None)


def chat(content: str, model: str = "mock-provider", **extra: Any) -> dict[str, Any]:
    return {"model": model, "messages": [{"role": "user", "content": content}], **extra}
