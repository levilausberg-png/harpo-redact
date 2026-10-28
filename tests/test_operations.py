"""Detector lab, self-test suites, attention center and the live event stream."""

from __future__ import annotations

import hashlib
import json
import socket
import threading
import time
from collections.abc import Iterator

import httpx
import pytest

from .conftest import AUTH, KEY, chat

FAST = {"detection": {"ner": {"enabled": False}}}
B64_EMAIL = "amFuZS5kb2VAbGVhay10ZXN0LmV4YW1wbGU="  # jane.doe@leak-test.example


def _keys() -> dict:  # type: ignore[type-arg]
    sha = lambda k: hashlib.sha256(k.encode()).hexdigest()  # noqa: E731
    return {
        "keys": [{"id": "owner", "sha256": sha(KEY), "admin": True}, {"id": "team", "sha256": sha("team-key-123456")}]
    }


def test_lab_shows_each_stage_and_records_nothing(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(**FAST)
    text = f"Mail jane\u200b.doe@leak-test.example, key AKIAZ4X7Q2LMWN3RT5PJ, blob {B64_EMAIL}"
    r = client.post("/v1/lab/detect", headers=AUTH, json={"text": text})
    assert r.status_code == 200
    lab = r.json()
    assert lab["normalized"]["changed"] and lab["normalized"]["removed_format_chars"] >= 1
    layers = {layer["id"]: layer for layer in lab["layers"]}
    assert any(s["value"] == "AKIAZ4X7Q2LMWN3RT5PJ" for s in layers["secrets"]["spans"])
    assert any(B64_EMAIL in s["value"] for layer in layers.values() for s in layer["spans"])
    final = lab["final"]["text"]
    assert "AKIAZ4X7Q2LMWN3RT5PJ" not in final and B64_EMAIL not in final and "leak-test.example" not in final
    assert client.get("/v1/stats", headers=AUTH).json()["totals"]["requests"] == 0  # the lab is never counted


def test_lab_requires_a_key_and_a_bounded_sample(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(**FAST)
    assert client.post("/v1/lab/detect", json={"text": "hi"}).status_code == 401
    assert client.post("/v1/lab/detect", headers=AUTH, json={"text": ""}).status_code == 400
    assert client.post("/v1/lab/detect", headers=AUTH, json={"text": "x" * 20_001}).status_code == 400


def test_selftest_suites_label_their_kind_and_pass_locally(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(auth=_keys(), **FAST)
    assert client.post("/v1/selftest/suites", headers={"authorization": "Bearer team-key-123456"}).status_code == 403
    out = client.post("/v1/selftest/suites", headers=AUTH, json={}).json()
    suites = {s["id"]: s for s in out["suites"]}
    assert {s["kind"] for s in out["suites"]} == {"local", "live", "config"}
    for sid in ("detection", "secrets", "egress", "adapters", "headers", "configuration"):
        assert suites[sid]["status"] == "pass", (sid, suites[sid]["tests"])
    assert suites["slm"]["status"] == "skip" and suites["documents"]["status"] in ("pass", "skip")
    only = client.post("/v1/selftest/suites", headers=AUTH, json={"suites": ["secrets"]}).json()
    assert [s["id"] for s in only["suites"]] == ["secrets"]


def test_attention_reports_a_weakened_boundary(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(auth=_keys(), policy={"egress_verification": "off"}, **FAST)
    assert client.get("/v1/attention", headers={"authorization": "Bearer team-key-123456"}).status_code == 403
    view = client.get("/v1/attention", headers=AUTH).json()
    assert view["posture"] == "critical"
    item = next(i for i in view["items"] if i["id"] == "egress-off")
    assert item["severity"] == "critical" and item["first_seen"] <= item["last_seen"]
    assert view["timeline"][0]["state"] == "critical"


def test_a_healthy_gateway_has_no_critical_items(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(auth=_keys(), **FAST)
    view = client.get("/v1/attention", headers=AUTH).json()
    assert all(i["severity"] != "critical" for i in view["items"]) and view["posture"] in ("healthy", "degraded")


@pytest.fixture(scope="module")
def live_server() -> Iterator[str]:
    import uvicorn

    from harpo_redact.api import create_app
    from harpo_redact.config import Settings
    from harpo_redact.mock_upstream import create_mock_app

    settings = Settings(
        environment="development",
        auth={"enabled": False},
        upstreams=[
            {"name": "demo-openai", "style": "openai", "base_url": "http://mock.provider/v1", "models": ["demo-gpt"]}
        ],
        detection={"ner": {"enabled": False}},
    )
    app = create_app(settings, upstream_transport=httpx.ASGITransport(app=create_mock_app()))
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            httpx.get(f"{url}/healthz", timeout=0.5)
            break
        except httpx.HTTPError:
            time.sleep(0.1)
    yield url
    server.should_exit = True
    thread.join(5)


def test_event_stream_delivers_content_free_records(live_server) -> None:  # type: ignore[no-untyped-def]
    def send() -> None:
        httpx.post(
            f"{live_server}/v1/chat/completions", json={**chat("Mail jane.doe@acme.example"), "model": "demo-gpt"}
        )

    timer = threading.Timer(0.6, send)
    got = None
    with httpx.stream("GET", f"{live_server}/v1/events", timeout=10) as r:
        assert r.headers["content-type"].startswith("text/event-stream")
        timer.start()
        event = ""
        for line in r.iter_lines():
            if line.startswith("event: "):
                event = line[7:]
            elif line.startswith("data: ") and event == "request":
                got = json.loads(line[6:])
                break
    timer.join()
    assert got is not None and got["decision"] == "forwarded" and got["seq"] >= 1
    assert "jane" not in json.dumps(got) and "acme" not in json.dumps(got)
