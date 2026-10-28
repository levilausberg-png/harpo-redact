"""Browser regressions for the console. Skipped when Playwright or Chromium is not installed; CI installs both and
sets HARPO_REQUIRE=browser, so there a missing browser fails these tests.

- no route scrolls sideways from 320 to 1920 px (the Playground once did, by 176 px)
- the command palette's fuzzy search, and the request-trace deep link
- browser storage holds UI preferences only: never prompts, values or keys
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from typing import Any

import httpx
import pytest

from .conftest import needs

try:
    from playwright import sync_api
except ImportError:  # the browser fixture reports it, as a skip or (under HARPO_REQUIRE) a failure
    sync_api = None

ROUTES = ["overview", "playground", "documents", "activity", "integrations", "providers", "setup", "policy", "detection",
          "access", "configuration", "observability", "leakbench", "guarantees", "system"]  # fmt: skip
WIDTHS = [320, 360, 375, 390, 430, 768, 1024, 1280, 1440, 1920]


def _serve(**policy: Any) -> Iterator[str]:
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
        policy=policy,
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


@pytest.fixture(scope="module")
def base_url() -> Iterator[str]:
    yield from _serve()


@pytest.fixture(scope="module")
def live_url(tmp_path_factory) -> Iterator[str]:  # type: ignore[no-untyped-def]
    """A gateway whose Policy page can save: policy.live_file in a temporary folder."""
    yield from _serve(live_file=str(tmp_path_factory.mktemp("live") / "policy.live.yaml"))


@pytest.fixture(scope="module")
def browser() -> Iterator[Any]:
    if sync_api is None:
        needs("browser", "Playwright is not installed")
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as exc:
            needs("browser", f"Chromium unavailable: {exc}")
        yield b
        b.close()


def _until(page, js: str, timeout: float = 10.0) -> None:  # type: ignore[no-untyped-def]
    """Poll a page condition from Python: the console's CSP (rightly) refuses Playwright's eval-based waits."""
    end = time.time() + timeout
    while time.time() < end:
        if page.evaluate(js):
            return
        page.wait_for_timeout(100)
    raise AssertionError(f"timed out waiting for: {js}")


def test_no_route_scrolls_sideways_at_any_width(browser, base_url) -> None:  # type: ignore[no-untyped-def]
    bad = []
    for width in WIDTHS:
        page = browser.new_page(viewport={"width": width, "height": 800})
        for route in ROUTES:
            page.goto(f"{base_url}/#/{route}")
            page.wait_for_timeout(300)
            over = page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
            if over > 2:
                bad.append(f"{width}px {route}: {over}px")
        page.close()
    assert bad == []


def test_palette_matches_fuzzily(browser, base_url) -> None:  # type: ignore[no-untyped-def]
    page = browser.new_page(viewport={"width": 1280, "height": 800})
    page.goto(f"{base_url}/#/overview")
    page.wait_for_selector(".side-search")
    page.keyboard.press("Control+k")
    page.keyboard.type("blokd")
    assert "blocked" in page.inner_text(".po.on").lower()
    page.keyboard.press("Escape")
    page.close()


def test_request_trace_deep_link_round_trip(browser, base_url) -> None:  # type: ignore[no-untyped-def]
    httpx.post(
        f"{base_url}/v1/chat/completions",
        json={"model": "demo-gpt", "messages": [{"role": "user", "content": "Mail a@b.example"}]},
    )
    page = browser.new_page(viewport={"width": 1280, "height": 800})
    page.goto(f"{base_url}/#/activity")
    page.locator("tbody tr.click").first.click()
    page.wait_for_selector(".wf-row")
    assert "/activity/request/" in page.url and page.locator(".wf-row").count() >= 4
    page.keyboard.press("Escape")
    page.wait_for_timeout(200)
    assert page.url.endswith("#/activity")
    page.close()


def test_browser_storage_holds_preferences_only(browser, base_url) -> None:  # type: ignore[no-untyped-def]
    page = browser.new_page(viewport={"width": 1280, "height": 800})
    page.goto(f"{base_url}/#/playground")
    page.locator("textarea").first.fill("Mail jane.doe@acme.example, card 4111 1111 1111 1111")
    page.wait_for_timeout(1200)
    page.goto(f"{base_url}/#/activity")
    page.wait_for_timeout(500)
    stored = page.evaluate("JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage)])")
    assert "jane" not in stored and "4111" not in stored and "acme" not in stored
    keys = page.evaluate("[...Object.keys(localStorage)]")
    assert set(keys) <= {"harpo.ui.v1"}
    page.close()


def test_a_chart_point_opens_exactly_its_requests(browser, base_url) -> None:  # type: ignore[no-untyped-def]
    httpx.post(
        f"{base_url}/v1/chat/completions", json={"model": "demo-gpt", "messages": [{"role": "user", "content": "hi"}]}
    )
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.goto(f"{base_url}/#/observability")
    box = page.locator("#obs-chart svg").bounding_box()
    page.mouse.click(box["x"] + box["width"] * 0.985, box["y"] + box["height"] * 0.5)
    page.wait_for_selector('[data-clear="time"]')
    assert "from=" in page.url and "to=" in page.url
    page.close()


def test_playground_panes_resize_and_persist_as_preferences_only(browser, base_url) -> None:  # type: ignore[no-untyped-def]
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.goto(f"{base_url}/#/playground")
    gutter = page.locator(".gutter").first.bounding_box()
    page.mouse.move(gutter["x"] + 6, gutter["y"] + 150)
    page.mouse.down()
    page.mouse.move(gutter["x"] + 140, gutter["y"] + 150, steps=5)
    page.mouse.up()
    page.click('#pg-layout button[data-v="egress"]')
    page.reload()
    page.wait_for_selector("#pg-grid")
    assert page.evaluate("document.querySelector('#pg-grid').dataset.focus") == "egress"
    stored = page.evaluate("localStorage.getItem('harpo.ui.v1')")
    assert '"playground"' in stored and "Priya" not in stored
    page.click('#pg-layout button[data-v="split"]')
    page.close()


def test_document_receipt_hash_matches_the_released_file(browser, base_url, tmp_path) -> None:  # type: ignore[no-untyped-def]
    import hashlib
    import json
    from pathlib import Path

    src = tmp_path / "note.txt"
    src.write_text("Contract for Priya Raman, priya.raman@northwind.example, IBAN NL91ABNA0417164300.\n")
    ctx = browser.new_context(viewport={"width": 1440, "height": 900}, accept_downloads=True)
    page = ctx.new_page()
    page.goto(f"{base_url}/#/documents")
    page.set_input_files("#file", str(src))
    page.wait_for_selector("[data-receipt]", timeout=30000)
    with page.expect_download() as receipt_dl:
        page.click("[data-receipt]")
    with page.expect_download() as file_dl:
        page.click("a[download]")
    receipt = json.loads(Path(receipt_dl.value.path()).read_text())
    released = Path(file_dl.value.path()).read_bytes()
    assert receipt["output"]["sha256"] == hashlib.sha256(released).hexdigest()
    assert "Priya" not in json.dumps(receipt) and "northwind" not in json.dumps(receipt) and receipt["redactions"] >= 2
    ctx.close()


def test_configuration_analysis_and_diagnostic_bundle(browser, base_url) -> None:  # type: ignore[no-untyped-def]
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.goto(f"{base_url}/#/configuration")
    page.wait_for_selector(".finding")
    assert page.locator(".finding").count() >= 1
    page.goto(f"{base_url}/#/system")
    page.click("#diag")
    page.wait_for_selector(".drawer pre")
    too_wide = page.evaluate(
        "(() => { const d = document.querySelector('.drawer'); return [...d.querySelectorAll('.db > *')]"
        ".filter(e => e.scrollWidth > d.clientWidth + 2 && getComputedStyle(e).overflowX === 'visible').length })()"
    )
    assert too_wide == 0
    page.close()


def test_detector_lab_shows_stages_and_decodes(browser, base_url) -> None:  # type: ignore[no-untyped-def]
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.goto(f"{base_url}/#/lab")
    page.click('#lab-s button[data-v="2"]')
    page.wait_for_selector(".spans .dec")
    assert page.locator(".lab-layers section").count() >= 6
    assert "jane.doe@leak-test.example" in page.inner_text(".spans .dec")
    page.close()


def test_live_stream_adds_rows_and_pause_holds_them(browser, base_url) -> None:  # type: ignore[no-untyped-def]
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.goto(f"{base_url}/#/activity")
    page.wait_for_selector('#live[data-state="live"]')
    page.wait_for_selector("#rows table, #rows .empty")
    httpx.post(
        f"{base_url}/v1/chat/completions", json={"model": "demo-gpt", "messages": [{"role": "user", "content": "one"}]}
    )
    _until(page, "document.querySelectorAll('#rows tr.fresh').length > 0")  # arrived through the stream, no reload
    page.click("#live-t")
    held = page.locator("tbody tr.click").count()
    httpx.post(
        f"{base_url}/v1/chat/completions", json={"model": "demo-gpt", "messages": [{"role": "user", "content": "two"}]}
    )
    _until(page, "/\\d+ new/.test(document.querySelector('#live-t').textContent)")
    assert page.locator("tbody tr.click").count() == held  # paused: rows do not move while you read
    page.click("#live-t")
    _until(page, f"document.querySelectorAll('tbody tr.click').length > {held}")
    page.close()


def test_row_context_menu_columns_and_saved_views(browser, base_url) -> None:  # type: ignore[no-untyped-def]
    httpx.post(
        f"{base_url}/v1/chat/completions", json={"model": "demo-gpt", "messages": [{"role": "user", "content": "hi"}]}
    )
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.goto(f"{base_url}/#/activity")
    page.locator("tbody tr.click").first.click(button="right")
    page.locator(".ctx-menu button", has_text="Filter by provider").click()
    assert "provider=demo-openai" in page.url
    page.click("#cols-btn")
    page.locator(".ctx-menu button", has_text="Model").first.click()
    page.keyboard.press("Escape")
    assert "Model" not in page.eval_on_selector_all("#rows thead th", "els => els.map(e => e.textContent.trim())")
    page.click("#views-btn")
    page.locator(".ctx-menu button", has_text="Save this view").click()
    page.fill("#sv-name", "Provider view")
    page.click("#sv-ok")
    page.keyboard.press("Control+k")
    page.keyboard.type("provider view")
    assert "Provider view" in page.inner_text(".po.on")
    page.keyboard.press("Escape")
    page.close()


def test_self_test_suite_and_attention_center(browser, base_url) -> None:  # type: ignore[no-untyped-def]
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.goto(f"{base_url}/#/guarantees")
    page.click('[data-run="secrets"]')
    _until(
        page,
        "[...document.querySelectorAll('.suite')].some(s => s.textContent.includes('Secrets') && s.querySelector('.st').textContent === 'pass')",
    )
    page.click("#att")
    page.wait_for_selector("[data-att]")
    assert "POSTURE TIMELINE" in page.inner_text(".drawer")
    page.close()


def test_tour_runs_to_the_end_and_is_remembered(browser, base_url) -> None:  # type: ignore[no-untyped-def]
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.goto(f"{base_url}/#/overview")
    page.click("[data-act=tour]")
    for _ in range(5):
        page.wait_for_selector(".tour-card")
        page.click('[data-t="next"]')
    _until(page, "!document.getElementById('tour')")
    assert '"tour":"done"' in page.evaluate("localStorage.getItem('harpo.ui.v1')")
    page.close()


def test_policy_editor_switches_adds_previews_applies_and_goes_back(browser, live_url) -> None:  # type: ignore[no-untyped-def]
    page = browser.new_page(viewport={"width": 1440, "height": 1000})
    page.goto(f"{live_url}/#/policy")
    page.wait_for_selector("#pol-types .pol-row")
    assert page.locator("#pol-types .pol-row.locked").count() == 2
    assert page.locator("#pol-types .pol-row.locked .pol-seg").count() == 0
    page.fill("#pol-text", "Mail jane@corp.example about EMP-123456")
    _until(page, "document.getElementById('pol-out').textContent.includes('[EMAIL_1]')")
    page.click('.pol-seg[data-t="EMAIL"] button[data-v="block"]')
    _until(page, "document.getElementById('pol-verdict').textContent.includes('blocked')")
    assert "1 change" in page.inner_text("#pol-bar")
    page.click("#pol-add")
    page.fill("#ct-name", "employee_id")  # written in lower case: the editor makes it a type name
    page.fill("#ct-pats", r"\bEMP-\d{6}\b")
    page.click("#ct-save")
    _until(page, "document.querySelector('.pol-ct .ent')?.textContent === 'EMPLOYEE_ID'")
    page.click('.pol-seg[data-t="EMAIL"] button[data-v="redact"]')
    _until(page, "document.getElementById('pol-out').textContent.includes('[EMPLOYEE_ID_1]')")
    page.click("#pol-apply")
    _until(page, "document.getElementById('pol-bar').hidden")
    assert [c["name"] for c in httpx.get(f"{live_url}/v1/policy/live").json()["custom_types"]] == ["EMPLOYEE_ID"]
    scan = httpx.post(f"{live_url}/v1/scan", json={"text": "badge EMP-654321"}).json()
    assert scan["results"][0]["redacted"] == "badge [EMPLOYEE_ID_1]"
    page.click("#pol-reset")
    page.click("#pol-go")
    _until(page, "!document.querySelector('.pol-ct')")
    assert httpx.post(f"{live_url}/v1/scan", json={"text": "seen EMP-654321"}).json()["results"][0]["redacted"] == (
        "seen EMP-654321"
    )
    page.close()


def test_detection_library_switches_a_family_and_keeps_keys_on(browser, live_url) -> None:  # type: ignore[no-untyped-def]
    page = browser.new_page(viewport={"width": 1440, "height": 1000})
    page.goto(f"{live_url}/#/policy")
    page.wait_for_selector("#pol-lib .pol-row")
    # credentials are listed, always on, with no switch
    keys = page.locator('#pol-lib .pol-row.locked:has-text("Credential library")')
    assert keys.count() == 1 and keys.locator(".pol-seg").count() == 0 and "Always on" in keys.inner_text()
    page.fill("#pol-text", "router MAC 00:1A:2B:3C:4D:5E in the hall")
    _until(page, "document.getElementById('pol-out').textContent.includes('[DEVICE_ID_1]')")
    page.click('.pol-seg[data-f="identifiers.devices"] button[data-v="off"]')
    _until(page, "document.getElementById('pol-out').textContent.includes('00:1A:2B:3C:4D:5E')")
    assert "1 change" in page.inner_text("#pol-bar") and "was on" in page.inner_text("#pol-lib")
    page.click("#pol-apply")
    _until(page, "document.getElementById('pol-bar').hidden")
    assert httpx.get(f"{live_url}/v1/policy/live").json()["library"]["groups"]
    scan = httpx.post(f"{live_url}/v1/scan", json={"text": "MAC 00:1A:2B:3C:4D:5E"}).json()
    assert scan["results"][0]["redacted"] == "MAC 00:1A:2B:3C:4D:5E"
    page.goto(f"{live_url}/#/detection")
    page.wait_for_selector(".lib-grid .mx")
    assert "off" in page.locator('.lib-grid .mx:has-text("Devices")').first.inner_text()
    page.goto(f"{live_url}/#/policy")
    page.wait_for_selector("#pol-lib .pol-row")
    page.click("#pol-reset")
    page.click("#pol-go")
    _until(page, "document.querySelector('.pol-seg[data-f=\"identifiers.devices\"] button.on')?.dataset.v === 'on'")
    scan = httpx.post(f"{live_url}/v1/scan", json={"text": "MAC 00:1A:2B:3C:4D:5E"}).json()
    assert scan["results"][0]["redacted"] == "MAC [DEVICE_ID_1]"
    page.close()


def test_policy_editor_fits_a_phone(browser, live_url) -> None:  # type: ignore[no-untyped-def]
    page = browser.new_page(viewport={"width": 360, "height": 800})
    page.goto(f"{live_url}/#/policy")
    page.wait_for_selector("#pol-types .pol-row")
    assert page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth") <= 2
    page.close()


def test_the_playground_sends_a_key_as_a_placeholder_and_says_so(browser, base_url) -> None:  # type: ignore[no-untyped-def]
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.goto(f"{base_url}/#/playground")
    page.get_by_text("Code with a secret", exact=True).click()
    note = '.verify.warn[data-code="keys_redacted"]'
    _until(page, f"!!document.querySelector('{note}')")
    assert "Keys are always redacted" in page.inner_text(note)
    sent = page.inner_text(".egress-body pre")
    assert "[SECRET_1]" in sent and "AKIAZ4X7Q2LMWN3RT5PJ" not in sent and "S3cure!Pass" not in sent
    page.close()


def test_long_values_never_run_over_their_labels(browser, base_url) -> None:  # type: ignore[no-untyped-def]
    page = browser.new_page(viewport={"width": 1080, "height": 900})
    page.goto(f"{base_url}/#/guarantees")
    page.wait_for_selector(".kv")
    overlaps = page.evaluate(
        """[...document.querySelectorAll('.kv')].filter((row) => {
             const [k, v] = row.children; if (!k || !v) return false;
             const text = (el) => { const r = document.createRange(); r.selectNodeContents(el); return r.getBoundingClientRect(); };
             const a = text(k), b = text(v);  // the text as drawn: it can overflow its box
             return a.right > b.left + 1 && a.bottom > b.top + 1 && b.bottom > a.top + 1;
           }).length"""
    )
    assert overlaps == 0
    page.close()
