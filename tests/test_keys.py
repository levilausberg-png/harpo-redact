"""Key expiry and per-key rate limits (roadmap 26)."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from .conftest import AUTH, KEY, chat, make_settings

FAST = {"detection": {"ner": {"enabled": False}}}


def keyset(**extra: Any) -> dict[str, Any]:
    return {"keys": [{"id": "team-a", "sha256": hashlib.sha256(KEY.encode()).hexdigest(), **extra}]}


def test_an_expired_key_is_refused(gateway) -> None:  # type: ignore[no-untyped-def]
    past = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    client, spy = gateway(auth=keyset(expires_at=past), **FAST)
    r = client.post("/v1/chat/completions", headers=AUTH, json=chat("hi"))
    assert r.status_code == 401 and "expired" in r.json()["error"]["message"] and not spy.requests


def test_a_key_works_until_it_expires(gateway) -> None:  # type: ignore[no-untyped-def]
    future = (datetime.now(UTC) + timedelta(days=30)).isoformat()
    client, _ = gateway(auth=keyset(expires_at=future), **FAST)
    assert client.post("/v1/chat/completions", headers=AUTH, json=chat("hi")).status_code == 200


def test_an_expiry_without_a_timezone_is_a_config_error() -> None:
    with pytest.raises(Exception, match="timezone"):
        make_settings(auth=keyset(expires_at="2027-01-31T00:00:00"))


def test_rate_limit_per_key(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(auth=keyset(requests_per_minute=2), **FAST)
    codes = [client.post("/v1/chat/completions", headers=AUTH, json=chat("hi")) for _ in range(3)]
    assert [r.status_code for r in codes] == [200, 200, 429] and len(spy.requests) == 2
    assert 1 <= int(codes[2].headers["retry-after"]) <= 60
