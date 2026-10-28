"""Precision on structured data: realistic payloads with nothing personal in them must pass unchanged.

The redaction matrix (tests/redaction_matrix.py) reads field names, table headers, encodings and markup to find
values. This is the other side: package manifests, compose files, schemas, CSV exports, metrics tables, logs,
code and API payloads full of field names that sound sensitive ("password_min_length", "passport_country",
"customer": "acme", "token_type") and values that look like IDs (versions, hashes, UUIDs, amounts, dates, page
tokens) must not lose a character, as message text or as tool-call arguments.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from harpo_redact.api import create_app

from .conftest import AUTH, UPSTREAM_KEY, SpyTransport, make_settings

FAST = {"ner": {"enabled": False}}

TEXTS: dict[str, str] = {
    "package.json": json.dumps(
        {
            "name": "billing-service",
            "version": "4.12.0",
            "license": "Apache-2.0",
            "scripts": {"test": "vitest run", "build": "tsc -p tsconfig.json"},
            "dependencies": {"fastify": "^4.26.2", "pg": "8.11.3", "zod": "3.23.8"},
            "engines": {"node": ">=20.11.1"},
        },
        indent=2,
    ),
    "docker-compose.yml": """services:
  db:
    image: postgres:16.3
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_USER: app
    ports:
      - "5432:5432"
  api:
    image: ghcr.io/acme/billing:4.12.0
    environment:
      DATABASE_URL: postgres://app:${POSTGRES_PASSWORD}@db:5432/billing
      API_KEY: ${API_KEY}
""",
    "openapi schema": json.dumps(
        {
            "components": {
                "schemas": {
                    "SignupRequest": {
                        "type": "object",
                        "required": ["email", "password"],
                        "properties": {
                            "password": {"type": "string", "minLength": 12, "format": "password"},
                            "password_hint": {"type": "string", "maxLength": 80},
                            "passport_country": {"type": "string", "example": "NL"},
                            "passport_expiry": {"type": "string", "format": "date", "example": "2031-05-01"},
                            "date_of_birth": {"type": "string", "format": "date"},
                            "customer_type": {"type": "string", "enum": ["retail", "business"]},
                        },
                    }
                }
            }
        }
    ),
    "api response": json.dumps(
        {
            "object": "list",
            "data": [
                {
                    "id": "inv_2024_000123",
                    "customer": "acme-corp",
                    "amount_due": 129900,
                    "currency": "eur",
                    "status": "open",
                    "created": "2024-03-14T09:30:00Z",
                    "account_balance": "1500.00",
                },
                {
                    "id": "inv_2024_000124",
                    "customer": "globex",
                    "amount_due": 2500000,
                    "currency": "usd",
                    "status": "paid",
                    "created": "2024-03-15T10:00:00Z",
                    "policy": "net-30",
                },
            ],
            "has_more": True,
            "next_page_token": "eyJwYWdlIjogMiwgInNpemUiOiA1MH0",
            "token_type": "bearer",
            "expires_in": 3600,
        }
    ),
    "products.csv": """sku,name,price,stock,updated
SKU-88213-XL,Rain jacket,129.95,42,2024-03-14
SKU-10442-M,Wool scarf,39.00,310,2024-03-12
SKU-77001-S,Trail shoe,149.00,7,2024-02-28
""",
    "metrics table": """| endpoint | p50 ms | p95 ms | requests |
|---|---:|---:|---:|
| /v1/chat/completions | 22.03 | 35.41 | 1204331 |
| /v1/messages | 19.80 | 31.07 | 998213 |
""",
    "pricing html": """<table><tr><th>Plan</th><th>Price</th><th>Seats</th></tr>
<tr><td>Team</td><td>&euro;30</td><td>5</td></tr><tr><td>Business</td><td>&euro;120</td><td>25</td></tr></table>""",
    "settings table": """| setting | value |
|---|---|
| password minimum length | 12 |
| session timeout | 30 minutes |
| account lockout | after 5 attempts |
""",
    "git log": """commit 9fceb02d0ae598e95dc970b74767f19372d61af8
Author: build-bot
Date:   Thu Mar 14 09:30:00 2024 +0100

    Bump zod from 3.22.4 to 3.23.8 (#1842)
""",
    "app log": """2024-03-14T09:30:00.123Z INFO request_id=6f1c2a9e-3b7d-4c55-9a1e-0d8f2b4c6e71 status=200 duration_ms=41
2024-03-14T09:30:01.456Z WARN retry attempt=2 backoff_ms=800 upstream=api.example.org
2024-03-14T09:30:02.789Z INFO cache hit key=sha256:3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b
""",
    "python code": """import os

DB_PASSWORD = os.environ["DB_PASSWORD"]
API_KEY = os.getenv("API_KEY")
password = settings.password
token = request.headers.get("Authorization")
MAX_TOKENS = 4096
""",
    "env template": """# Copy to .env and fill in
OPENAI_API_KEY=your-api-key-here
DATABASE_PASSWORD=changeme
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY_ID
""",
    "markdown docs": """## Authentication

Send your key in the `Authorization` header. The password must be at least 12 characters; the token expires
after 3600 seconds. Passport and ID card uploads are reviewed within 2 business days.
""",
    "hex and ids": "Build 3f2a9c1e7b4d done; image digest sha256:9b2f7c1d0e4a6b8c; trace 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    "spaced letters": "Rows A B C D E F G H I J are full; seats 1 2 3 4 5 6 are free.",
    "russian prose": "Привет! Это обычный текст: встреча в 10:30, комната 2В, этаж 3.",
    "url": "See https://docs.example.org/search?q=password+policy&page=2&lang=en for details.",
}


@pytest.mark.parametrize("name", list(TEXTS))
def test_benign_structured_text_passes_unchanged(make_pipeline, name: str) -> None:  # type: ignore[no-untyped-def]
    text = TEXTS[name]
    outcome = make_pipeline(detection=FAST).scan_sync([text])
    found = [(f.type.value, text[f.start : f.end] if f.start is not None else None) for f in outcome.findings[0]]
    assert found == [], found
    assert outcome.texts == [text]


TOOL_ARGUMENTS: dict[str, dict[str, Any]] = {
    "order lookup": {"order_id": "ORD-2024-000123", "customer": "acme-corp", "include": ["lines", "totals"]},
    "pagination": {"page_token": "eyJwYWdlIjogMn0", "limit": 50, "cursor": "c_9f8e7d6c5b4a"},
    "search": {"query": "password reset email not arriving", "filters": {"status": "open", "priority": "high"}},
    "schema-like": {"passport_country": "NL", "passport_expiry": "2031-05-01", "password_min_length": 12},
    "policy": {"policy": "allow-all-v2", "claim": 1500000, "insurance": "basic", "account": "prod-eu-1"},
    "headers": {"headers": [{"key": "Content-Type", "value": "application/json"}, {"key": "X-Request-Id",
                                                                                  "value": "req_7f3a9c"}]},
    "metrics": {"requests": 1204331, "p95_ms": 35.41, "version": "2.4.0", "sha": "9fceb02d0ae598e95dc970b7"},
}  # fmt: skip


@pytest.fixture(scope="module")
def proxy() -> Iterator[tuple[TestClient, SpyTransport]]:
    saved = os.environ.get("TEST_UPSTREAM_KEY")
    os.environ["TEST_UPSTREAM_KEY"] = UPSTREAM_KEY
    spy = SpyTransport()
    with TestClient(create_app(make_settings(detection=FAST), upstream_transport=spy)) as client:
        yield client, spy
    if saved is None:
        os.environ.pop("TEST_UPSTREAM_KEY", None)
    else:
        os.environ["TEST_UPSTREAM_KEY"] = saved


@pytest.mark.parametrize("name", list(TOOL_ARGUMENTS))
def test_benign_tool_arguments_are_forwarded_unchanged(proxy, name: str) -> None:  # type: ignore[no-untyped-def]
    client, spy = proxy
    arguments = json.dumps(TOOL_ARGUMENTS[name])
    body = {
        "model": "mock-provider",
        "messages": [
            {"role": "user", "content": "Run the tool."},
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": "run", "arguments": arguments}}]},
            {"role": "tool", "tool_call_id": "call_1", "content": "done"},
        ],
    }  # fmt: skip
    r = client.post("/v1/chat/completions", headers=AUTH, json=body)
    assert r.status_code == 200, r.text
    sent = json.loads(spy.bodies[-1])
    assert sent["messages"][1]["tool_calls"][0]["function"]["arguments"] == arguments
    assert r.headers["x-harpo-redactions"] == "0"
