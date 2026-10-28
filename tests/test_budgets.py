"""Resource budgets (roadmap 24): past a budget the request is blocked, never sent half-inspected."""

from __future__ import annotations

import base64

from .conftest import AUTH, chat

FAST = {"ner": {"enabled": False}}


def test_too_many_detections_blocks(make_pipeline) -> None:  # type: ignore[no-untyped-def]
    p = make_pipeline(detection=FAST, server={"max_entities": 10})
    out = p.scan_sync([" ".join(f"user{i}@corp.example" for i in range(30))])
    assert out.blocked and [r.code for r in out.reasons] == ["scan_budget"] and "detections" in out.reasons[0].message
    assert make_pipeline(detection=FAST).scan_sync(["a@b.example c@d.example"]).blocked is False


def test_too_much_decoded_data_blocks(make_pipeline) -> None:  # type: ignore[no-untyped-def]
    blob = base64.b64encode(("contact jane.doe@example.com " * 400).encode()).decode()
    out = make_pipeline(detection=FAST, server={"max_decoded_bytes": 2_000}).scan_sync([f"payload {blob} end"])
    assert out.blocked and "decoded data" in out.reasons[0].message
    ok = make_pipeline(detection=FAST).scan_sync([f"payload {blob} end"])
    assert not ok.blocked and ok.counts.get("ENCODED_DATA") == 1


def test_running_out_of_time_blocks(make_pipeline) -> None:  # type: ignore[no-untyped-def]
    texts = [f"Paragraph {i}: please contact jane{i}@example.com about invoice {i}. " * 40 for i in range(200)]
    out = make_pipeline(detection=FAST, server={"max_scan_ms": 50}).scan_sync(texts)
    assert out.blocked and "time" in out.reasons[0].message


def test_a_budget_block_reaches_the_client_and_nothing_is_sent(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(detection=FAST, server={"max_entities": 10})
    r = client.post("/v1/chat/completions", headers=AUTH, json=chat(" ".join(f"u{i}@corp.example" for i in range(30))))
    assert (
        r.status_code == 403 and r.json()["error"]["harpo"]["reasons"][0]["code"] == "scan_budget" and not spy.requests
    )
