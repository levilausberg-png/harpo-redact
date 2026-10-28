"""Every protected value type through 31 carriers, against the real proxy (tests/redaction_matrix.py).

For each case and carrier the request goes through /v1/chat/completions or /v1/messages exactly as a client would
send it.
Every type is redacted, credentials included (keys are always redacted): the request is forwarded with nothing
recoverable left. A case can still expect a block (refused, nothing forwarded) for a type a policy blocks. Either way an independent oracle decodes everything that left and everything the client
got back. Near misses must arrive unchanged. NER is off: these guarantees come from the deterministic layers.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from harpo_redact.api import create_app

from . import redaction_matrix as rm
from .conftest import ANTHROPIC_UPSTREAM_KEY, AUTH, UPSTREAM_KEY, SpyTransport, make_settings

SETTINGS = {"detection": {"ner": {"enabled": False}, "registry": {"terms": ["Project Bluefin"]}}}


@pytest.fixture(scope="module")
def proxy() -> Iterator[tuple[TestClient, SpyTransport]]:
    saved = {k: os.environ.get(k) for k in ("TEST_UPSTREAM_KEY", "TEST_ANTHROPIC_KEY")}
    os.environ["TEST_UPSTREAM_KEY"] = UPSTREAM_KEY
    os.environ["TEST_ANTHROPIC_KEY"] = ANTHROPIC_UPSTREAM_KEY
    spy = SpyTransport()
    with TestClient(create_app(make_settings(**SETTINGS), upstream_transport=spy)) as client:
        yield client, spy
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def send(proxy: tuple[TestClient, SpyTransport], body: dict[str, Any], carrier: str) -> tuple[Any, str | None]:
    client, spy = proxy
    before = len(spy.bodies)
    r = client.post(rm.endpoint_for(carrier), headers=AUTH, json=body)
    return r, spy.bodies[-1].decode("utf-8", "replace") if len(spy.bodies) > before else None


def reasons(r: Any) -> str:
    try:
        return ",".join(x["code"] for x in r.json()["error"]["harpo"]["reasons"])
    except (KeyError, TypeError, ValueError):
        return "-"


@pytest.mark.parametrize("carrier", list(rm.ALL_CARRIERS))
@pytest.mark.parametrize("case", rm.CASES, ids=lambda c: c.id)
def test_value_is_protected_in_every_carrier(proxy, case: rm.Case, carrier: str) -> None:  # type: ignore[no-untyped-def]
    r, forwarded = send(proxy, rm.body_for(case, carrier), carrier)
    leaked = rm.leak(case.secret or case.value, [x for x in (forwarded, r.text) if x])
    assert leaked is None, f"LEAK ({r.status_code} {reasons(r)}): {leaked}"
    if case.expect == "block":
        assert r.status_code == 403 and forwarded is None, f"expected a block, got {r.status_code}"
    else:
        assert r.status_code == 200 and forwarded is not None, f"expected redaction, got {r.status_code} {reasons(r)}"


NEAR = [(c, k) for c in rm.CASES if c.near_miss for k in rm.NEAR_MISS_CARRIERS]


@pytest.mark.parametrize(("case", "carrier"), NEAR, ids=[f"{c.id}-{k}" for c, k in NEAR])
def test_near_misses_pass_through_unchanged(proxy, case: rm.Case, carrier: str) -> None:  # type: ignore[no-untyped-def]
    assert case.near_miss is not None
    r, forwarded = send(proxy, rm.body_for(case, carrier, near=True), carrier)
    assert r.status_code == 200 and forwarded is not None, f"near miss refused: {r.status_code} {reasons(r)}"
    assert rm.leak(case.near_miss, [forwarded]) is not None, "near miss was altered (over-redaction)"


# A failed checksum after the word that names it: the PAN's holder letter is checked by the validated layer only,
# since "PAN" also names a card's number, so it is not in this list.
NAMED = [c for c in rm.CASES if c.id in rm.CHECKED_WITHOUT_CUE and c.id != "in_pan"]


@pytest.mark.parametrize("case", NAMED, ids=[c.id for c in NAMED])
def test_a_failed_check_after_the_word_that_names_it_is_protected(proxy, case: rm.Case) -> None:  # type: ignore[no-untyped-def]
    assert case.near_miss is not None
    r, forwarded = send(proxy, rm.body_for(case, "sentence", near=True, own_label=True), "sentence")
    assert r.status_code == 200 and forwarded is not None, f"refused: {r.status_code} {reasons(r)}"
    assert rm.leak(case.near_miss, [forwarded]) is None, "a value named by its cue word left"
