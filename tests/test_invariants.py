"""Security invariants (docs/INVARIANTS.md). Every INV-NN has tests named test_invNN_*."""

from __future__ import annotations

import base64
import logging
import random
import re
import types
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from harpo_redact import proxy
from harpo_redact.adapters import ADAPTERS
from harpo_redact.documents.common import DocError, Limits
from harpo_redact.documents.runner import DocumentError, OpenResult
from harpo_redact.documents.service import redact_document
from harpo_redact.documents.worker import open_document
from harpo_redact.observability import JsonFormatter

from . import doc_fixtures as fx
from . import test_conformance
from .conftest import AUTH, KEY, chat, make_settings

FAST = {"detection": {"ner": {"enabled": False}}}
CANARY = "inv.canary.person@leak-test.example"
SECRET = "sk-proj-7Hq2LmV9xRt4KpZ8wNc3YbF6dJs1GaE5"
_rng = random.Random(9)
PRIVATE_KEY = (
    "-----BEGIN PRIVATE KEY-----\n"
    + "\n".join(base64.b64encode(_rng.randbytes(48)).decode() for _ in range(8))
    + "\n-----END PRIVATE KEY-----"
)


def code(r: Any) -> str:
    return str(r.json()["error"].get("harpo", {}).get("reasons", [{}])[0].get("code", ""))


# =========================================================================== INV-01
def test_inv01_egress_verification_catches_a_redaction_that_was_lost(gateway, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(**FAST)
    real = proxy.Collector.apply

    def lose_the_first(self: proxy.Collector, redacted: list[str]) -> None:  # a serialization bug
        real(self, [self.texts[0], *redacted[1:]])

    monkeypatch.setattr(proxy.Collector, "apply", lose_the_first)
    r = client.post("/v1/chat/completions", headers=AUTH, json=chat(f"mail {CANARY}"))
    assert r.status_code == 403 and code(r) == "egress_verification" and not spy.requests


VALUES = [CANARY, "4111 1111 1111 1111", "NL91ABNA0417164300", SECRET, "+31 20 794 6095"]


@settings(
    max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow]
)
@given(
    turns=st.lists(
        st.tuples(
            st.sampled_from(["system", "user", "assistant"]),
            st.text(max_size=60),
            st.sampled_from(VALUES),
            st.booleans(),
        ),
        min_size=1,
        max_size=5,
    )
)
def test_inv01_seeded_values_never_reach_the_provider(gateway, turns) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(**FAST)
    body = chat("x")
    body["messages"] = [
        {
            "role": role,
            "content": [{"type": "text", "text": f"{noise} {value} {noise}"}] if as_parts else f"{noise} {value}",
        }
        for role, noise, value, as_parts in turns
    ]
    r = client.post("/v1/chat/completions", headers=AUTH, json=body)
    assert r.status_code in (200, 400, 403)
    if spy.requests:
        sent = spy.bodies[-1].decode()
        assert not any(v in sent for v in VALUES)


# =========================================================================== INV-02
def reachable_strings(*roots: Any, limit: int = 400_000) -> list[str]:
    seen: set[int] = set()
    stack = list(roots)
    out: list[str] = []
    skip = (types.ModuleType, type, types.FunctionType, types.BuiltinFunctionType, types.MethodType)
    while stack and len(seen) < limit:
        obj = stack.pop()
        if id(obj) in seen:
            continue
        seen.add(id(obj))
        if isinstance(obj, str):
            out.append(obj)
        elif isinstance(obj, (bytes, bytearray)):
            out.append(bytes(obj).decode("utf-8", "ignore"))
        elif (
            obj is None
            or isinstance(obj, (int, float, complex, *skip))
            or (type(obj).__module__ or "").startswith(("spacy", "thinc", "numpy", "re2", "_re2"))
        ):
            continue
        elif isinstance(obj, dict):
            stack.extend(obj.keys())
            stack.extend(obj.values())
        elif isinstance(obj, (list, tuple, set, frozenset)):
            stack.extend(obj)
        else:
            if hasattr(obj, "__dict__"):
                stack.append(vars(obj))
            for slot in getattr(type(obj), "__slots__", ()) or ():
                if isinstance(slot, str):
                    stack.append(getattr(obj, slot, None))
    return out


def test_inv02_nothing_reachable_from_the_application_holds_original_values(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(**FAST)
    assert (
        client.post(
            "/v1/chat/completions", headers=AUTH, json=chat(f"mail {CANARY} card 4111 1111 1111 1111")
        ).status_code
        == 200
    )
    assert client.post("/v1/scan", headers=AUTH, json={"texts": [f"also {CANARY}"]}).status_code == 200
    doc = client.post(
        "/v1/documents/redact", headers={**AUTH, "X-Harpo-Filename": "n.txt"}, content=f"Mail {CANARY}".encode()
    )
    assert doc.status_code == 200
    strings = reachable_strings(client.app, client.app.state)
    assert len(strings) > 1000  # the walk really went through the application
    assert [s for s in strings if CANARY in s or "4111 1111 1111 1111" in s] == []


# =========================================================================== INV-03
async def test_inv03_a_model_that_finds_nothing_cannot_approve_what_the_rules_found() -> None:
    from .test_slm_hardening import ollama, pipeline

    out = await pipeline(ollama({"findings": []})).scan([f"deploy with {SECRET} and mail {CANARY}"])
    assert "[SECRET_1]" in out.texts[0] and "[EMAIL_1]" in out.texts[0] and SECRET not in out.texts[0]


def test_inv03_egress_verification_uses_no_model(make_pipeline, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    p = make_pipeline()
    if p.ner is not None:
        monkeypatch.setattr(p.ner, "detect_many", lambda texts: (_ for _ in ()).throw(AssertionError("model used")))
    assert p.residual_sync([f"mail {CANARY} or call +31 20 794 6095"]) == {"EMAIL": 1, "PHONE": 1}


# =========================================================================== INV-04
OPENAI_UNINSPECTABLE = [
    {"type": "image_url", "image_url": {"url": f"https://img.example/{CANARY}.png"}},
    {"type": "input_audio", "input_audio": {"data": "UklGRgAAAAA=", "format": "wav"}},
    {"type": "file", "file": {"file_id": "file-abc123"}},
    {"type": "video_url", "video_url": {"url": f"https://v.example/{CANARY}"}},
]


@pytest.mark.parametrize("part", OPENAI_UNINSPECTABLE, ids=lambda p: p["type"])
def test_inv04_uninspectable_parts_are_blocked_or_dropped_never_forwarded(gateway, part: dict[str, Any]) -> None:  # type: ignore[no-untyped-def]
    body = chat("look")
    body["messages"][0]["content"] = [{"type": "text", "text": "look"}, part]
    client, spy = gateway(**FAST)
    assert client.post("/v1/chat/completions", headers=AUTH, json=body).status_code == 403 and not spy.requests
    client, spy = gateway(policy={"unsupported_content": "drop"}, **FAST)
    assert client.post("/v1/chat/completions", headers=AUTH, json=body).status_code == 200
    sent = spy.bodies[-1].decode()
    assert CANARY not in sent and part["type"] not in sent and proxy.REMOVED_MARKER in sent


@pytest.mark.parametrize(
    "block",
    [
        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo="}},
        {"type": "document", "source": {"type": "url", "url": f"https://d.example/{CANARY}.pdf"}},
        {"type": "container_upload", "file_id": "file-1"},
    ],
    ids=lambda b: b["type"],
)
def test_inv04_uninspectable_anthropic_blocks(gateway, block: dict[str, Any]) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(**FAST)
    body = {
        "model": "claude-test",
        "max_tokens": 8,
        "messages": [{"role": "user", "content": [block, {"type": "text", "text": "hi"}]}],
    }
    assert client.post("/v1/messages", headers={"x-api-key": KEY}, json=body).status_code == 403 and not spy.requests


def test_inv04_remote_tools_are_blocked(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(**FAST)
    body = {"model": "claude-test", "max_tokens": 8, "messages": [{"role": "user", "content": "hi"}],
            "mcp_servers": [{"type": "url", "url": "https://mcp.example", "authorization_token": "t"}]}  # fmt: skip
    r = client.post("/v1/messages", headers={"x-api-key": KEY}, json=body)
    assert r.status_code == 403 and code(r) == "remote_tools" and not spy.requests


# =========================================================================== INV-05
def test_inv05_no_request_content_in_logs_metrics_or_error_responses(gateway, caplog, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    caplog.set_level(logging.DEBUG)
    client, _ = gateway(**FAST)
    small, _ = gateway(server={"max_body_bytes": 2_000}, **FAST)
    responses = []
    bad_shape = {"model": chat("x")["model"], "messages": [{"role": "user", "content": {"oops": CANARY}}]}
    responses.append(client.post("/v1/chat/completions", headers=AUTH, json=bad_shape))
    nested = chat("hi")
    nested["messages"][0]["x_extra"] = CANARY
    responses.append(client.post("/v1/chat/completions", headers=AUTH, json=nested))
    responses.append(client.post("/v1/chat/completions", headers=AUTH, json=chat(f"{SECRET} {CANARY}")))
    blocking, _ = gateway(policy={"entities": {"EMAIL": {"action": "block"}}}, **FAST)
    responses.append(blocking.post("/v1/chat/completions", headers=AUTH, json=chat(f"{SECRET} {CANARY}")))
    responses.append(small.post("/v1/chat/completions", headers=AUTH, json=chat(f"{CANARY} " * 200)))
    responses.append(
        client.post(
            "/v1/documents/redact",
            headers={**AUTH, "X-Harpo-Filename": f"{CANARY}.docx"},
            content=fx.make_docx(picture=True),
        )
    )

    async def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError(f"failed while handling {CANARY}")

    monkeypatch.setattr(client.app.state.pipeline, "scan", boom)
    responses.append(client.post("/v1/chat/completions", headers=AUTH, json=chat(f"mail {CANARY}")))
    assert {r.status_code for r in responses} >= {400, 403, 413, 422, 500}
    metrics = client.get("/metrics", headers=AUTH)
    logs = "\n".join(JsonFormatter().format(record) for record in caplog.records)
    for text in [logs, metrics.text, *(r.text for r in responses)]:
        assert CANARY not in text and "leak-test" not in text
    assert "failed while handling" not in logs  # exception messages are never logged


# =========================================================================== INV-06
def test_inv06_an_override_releases_the_request_never_the_value(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(**FAST)
    r = client.post(
        "/v1/chat/completions", headers={**AUTH, "X-Harpo-Override": "true"}, json=chat(f"deploy with {SECRET}")
    )
    sent = spy.bodies[-1].decode()
    assert r.status_code == 200 and SECRET not in sent and "[SECRET_1]" in sent


def test_inv06_some_blocks_cannot_be_overridden(gateway, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    override = {**AUTH, "X-Harpo-Override": "true"}
    client, spy = gateway(**FAST)
    r = client.post("/v1/chat/completions", headers=override, json=chat(f"key:\n{PRIVATE_KEY}"))
    assert r.status_code == 200 and "[PRIVATE_KEY_1]" in spy.bodies[-1].decode()  # a key is never sent, override or not
    assert not any(line in spy.bodies[-1].decode() for line in PRIVATE_KEY.splitlines()[1:-1])
    budget, _ = gateway(server={"max_entities": 10}, **FAST)
    many = " ".join(f"u{i}@corp.example" for i in range(30))
    assert budget.post("/v1/chat/completions", headers=override, json=chat(many)).status_code == 403
    real = proxy.Collector.apply
    monkeypatch.setattr(proxy.Collector, "apply", lambda self, red: real(self, [self.texts[0], *red[1:]]))
    sent = len(spy.requests)
    r = client.post("/v1/chat/completions", headers=override, json=chat(f"mail {CANARY}"))
    assert r.status_code == 403 and code(r) == "egress_verification" and len(spy.requests) == sent


# =========================================================================== INV-07
def test_inv07_every_adapter_declares_surfaces_and_the_gateway_publishes_them(gateway) -> None:  # type: ignore[no-untyped-def]
    for adapter in ADAPTERS.values():
        assert adapter.surfaces and adapter.identifier_rules and adapter.guarantees
    client, _ = gateway(**FAST)
    published = client.get("/v1/policy", headers=AUTH).json()["adapters"]
    assert set(published) == set(ADAPTERS) and all(published[name]["surfaces"]["scanned"] for name in ADAPTERS)


def test_inv07_every_adapter_has_a_conformance_run() -> None:
    for name in ADAPTERS:
        assert hasattr(test_conformance, f"test_{name}_adapter_conformance"), name


# =========================================================================== INV-08
@pytest.mark.parametrize("where", ["top", "message", "part", "tool"])
def test_inv08_unknown_fields_are_refused_by_default_and_scanned_when_passed(gateway, where: str) -> None:  # type: ignore[no-untyped-def]
    body = chat("hi")
    body["messages"][0]["content"] = [{"type": "text", "text": "hi"}]
    body["tools"] = [
        {"type": "function", "function": {"name": "lookup", "description": "Find.", "parameters": {"type": "object"}}}
    ]
    target = {"top": body, "message": body["messages"][0], "part": body["messages"][0]["content"][0],
              "tool": body["tools"][0]["function"]}[where]  # fmt: skip
    target["x_new_field"] = f"contact {CANARY}"
    client, spy = gateway(**FAST)
    r = client.post("/v1/chat/completions", headers=AUTH, json=body)
    assert r.status_code == 400 and not spy.requests and CANARY not in r.text and "x_new_field" in r.text
    client, spy = gateway(policy={"unknown_fields": "pass"}, **FAST)
    r = client.post("/v1/chat/completions", headers=AUTH, json=body)
    assert r.status_code == 200 and CANARY not in spy.bodies[-1].decode()


# =========================================================================== INV-09
class _InProcessSession:
    def __init__(self, fmt: str, name: str, data: bytes, sabotage: bool) -> None:
        self.fmt, self.name, self.data, self.sabotage = fmt, name, data, sabotage

    async def __aenter__(self) -> _InProcessSession:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None

    async def open(self, options: dict[str, Any]) -> OpenResult:
        self.doc = open_document(self.fmt, self.data, self.name, Limits.from_dict(options))
        return OpenResult([s.to_json() for s in self.doc.segments()], self.doc.info)

    async def apply(self, edits: dict[int, dict[str, Any]]) -> tuple[bytes, list[str], str, str]:
        output = self.data if self.sabotage else self.doc.apply(edits)  # sabotage: the edits are "forgotten"
        return output, self.doc.verify_strings(output), "application/octet-stream", "docx"


class _InProcessRunner:
    def __init__(self, sabotage: bool) -> None:
        self.sabotage = sabotage

    def session(self, fmt: str, name: str, data: bytes) -> _InProcessSession:
        return _InProcessSession(fmt, name, data, self.sabotage)


@pytest.mark.parametrize("sabotage", [False, True])
async def test_inv09_an_office_file_whose_edits_were_lost_is_not_released(make_pipeline, sabotage: bool) -> None:  # type: ignore[no-untyped-def]
    cfg = make_settings().documents
    run = redact_document(make_pipeline(), cfg, _InProcessRunner(sabotage), fx.make_docx(hidden=False), "a.docx", None,  # type: ignore[arg-type]
                          mode=None, context_repair=None, override=False, want_file=True)  # fmt: skip
    if not sabotage:
        assert (await run).verified
        return
    with pytest.raises(DocumentError) as info:
        await run
    assert info.value.code == "residual_sensitive_data"


def test_inv09_a_pdf_whose_boxes_did_not_paint_is_not_released(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from PIL import ImageDraw

    from harpo_redact.documents.pdf import PdfDocument

    doc = PdfDocument(fx.make_pdf(), "a.pdf", Limits())
    text = doc.segments()[0].text
    start = text.index(fx.EMAIL)
    real = ImageDraw.ImageDraw.rectangle

    def faulty(self: Any, xy: Any, fill: Any = None, outline: Any = None, width: int = 1) -> Any:
        return real(self, xy, fill=(250, 250, 250) if fill == (0, 0, 0) else fill, outline=outline, width=width)

    monkeypatch.setattr(ImageDraw.ImageDraw, "rectangle", faulty)
    with pytest.raises(DocError) as info:
        doc.apply({0: {"r": [[start, start + len(fx.EMAIL), "[EMAIL_1]"]]}})
    assert info.value.code == "verify_failed"


# =========================================================================== INV-10
def test_inv10_images_are_blocked_in_chat_and_refused_in_documents(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(**FAST)
    body = chat("look")
    body["messages"][0]["content"] = [{"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}}]
    assert client.post("/v1/chat/completions", headers=AUTH, json=body).status_code == 403 and not spy.requests
    r = client.post(
        "/v1/documents/redact", headers={**AUTH, "X-Harpo-Filename": "a.docx"}, content=fx.make_docx(picture=True)
    )
    assert r.status_code == 422 and r.json()["error"]["harpo"]["code"] == "images_present"


def test_inv10_there_is_no_ocr_mode() -> None:
    with pytest.raises(Exception, match="images"):
        make_settings(documents={"images": "ocr"})


# =========================================================================== the list itself
def test_inv11_keys_are_always_redacted(gateway) -> None:  # type: ignore[no-untyped-def]
    strict = {"entities": {"SECRET": {"action": "block"}, "PRIVATE_KEY": {"action": "block"}}}
    switches = {"library": False, "disabled_rules": ["openai"], "natural_language": False, "seed_phrases": False}
    client, spy = gateway(policy=strict, detection={"ner": {"enabled": False}, "secrets": switches})
    for text, placeholder in ((f"deploy {SECRET}", "[SECRET_1]"), (f"key:\n{PRIVATE_KEY}", "[PRIVATE_KEY_1]")):
        r = client.post("/v1/chat/completions", headers=AUTH, json=chat(text))
        assert r.status_code == 200 and placeholder in spy.bodies[-1].decode()
    assert SECRET not in spy.bodies[-2].decode()
    with pytest.raises(ValueError, match="always redacted"):
        make_settings(policy={"entities": {"SECRET": {"action": "allow"}}})


def test_every_invariant_is_tested() -> None:
    doc = (Path(__file__).resolve().parents[1] / "docs" / "INVARIANTS.md").read_text()
    ids = re.findall(r"^\| (INV-\d\d) \|", doc, re.MULTILINE)
    tests = [name for name in globals() if name.startswith("test_inv")]
    assert len(ids) == 11
    for inv in ids:
        assert any(name.startswith(f"test_inv{inv[4:]}_") for name in tests), inv
