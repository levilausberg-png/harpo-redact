"""Log hygiene: no request content in any log record, on any path, including crashes."""

from __future__ import annotations

import json
import logging
import re

import pytest

from harpo_redact.observability import JsonFormatter

from .conftest import AUTH, chat

SEEDS = [
    "jane.seed@example.com",
    "4111 1111 1111 1111",
    "NL91ABNA0417164300",
    "sk-proj-SeedSecret0123456789abcdefXYZ",
    "Wilhelmina Seedsworth",
    "+31 20 794 6095",
]
PROMPT = "Please help " + ", ".join(SEEDS) + "."


# Request ids are random hex (uuid4); a short seed fragment such as "6095" turns up inside one now and then.
_RANDOM_IDS = re.compile(r"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])")


def _all_log_text(caplog: pytest.LogCaptureFixture) -> str:
    formatter = JsonFormatter()
    return _RANDOM_IDS.sub("<id>", "\n".join(formatter.format(record) for record in caplog.records))


def test_no_content_in_logs_on_any_path(gateway, caplog) -> None:  # type: ignore[no-untyped-def]
    caplog.set_level(logging.DEBUG)
    client, _ = gateway(policy={"entities": {"PHONE": {"action": "block", "overridable": True}}})
    client.post("/v1/scan", headers=AUTH, json={"text": PROMPT})
    client.post("/v1/chat/completions", headers=AUTH, json=chat(PROMPT))  # blocked: contains a phone number
    client.post("/v1/chat/completions", headers={**AUTH, "X-Harpo-Override": "true"}, json=chat(PROMPT))
    client.post("/v1/chat/completions", headers={**AUTH, "X-Harpo-Override": "true"}, json=chat(PROMPT, stream=True))
    client.post("/v1/chat/completions", headers=AUTH, content=PROMPT.encode())  # invalid JSON
    client.post("/v1/chat/completions", headers=AUTH, json={"model": "mock-provider", "messages": [{"role": PROMPT}]})
    text = _all_log_text(caplog)
    audits = [json.loads(JsonFormatter().format(r)) for r in caplog.records if r.name == "harpo.audit"]
    assert len(audits) >= 5 and {"blocked", "forwarded", "scanned", "rejected"} <= {a["decision"] for a in audits}
    for seed in SEEDS:
        assert seed not in text
        assert seed.split()[-1] not in text


def test_unexpected_errors_are_content_free(gateway, caplog, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    caplog.set_level(logging.DEBUG)
    client, _ = gateway()

    async def explode(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise ValueError(f"could not parse {SEEDS[0]}")

    monkeypatch.setattr(client.app.state.pipeline, "scan", explode)
    r = client.post("/v1/chat/completions", headers=AUTH, json=chat(PROMPT))
    assert r.status_code == 500 and SEEDS[0] not in r.text
    assert r.json()["error"]["type"] == "api_error"
    text = _all_log_text(caplog)
    assert "ValueError" in text and SEEDS[0] not in text
