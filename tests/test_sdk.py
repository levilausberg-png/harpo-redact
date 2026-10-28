"""The Python SDK's local engine (harpo_redact.sdk.Harpo / AsyncHarpo).

The engine is an interface, not a second implementation: every result must equal what the canonical path gives for
the same input (the pipeline the CLI and the benchmarks use, and the gateway's own HTTP answers in
test_sdk_client.py), and every invariant must hold through it.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import dataclasses
import hashlib
import importlib.util
import io
import json
import logging
import os
import random
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

from harpo_redact import live_policy
from harpo_redact.api import load_ner
from harpo_redact.config import AuthKey, Settings
from harpo_redact.documents.runner import WorkerRunner
from harpo_redact.documents.service import redact_document
from harpo_redact.pipeline import Pipeline
from harpo_redact.sdk import (
    AsyncHarpo,
    BlockedError,
    ConfigurationError,
    CustomType,
    DocumentError,
    Finding,
    GatewayKey,
    Harpo,
    HarpoError,
    InvalidRequestError,
    Risk,
    ScanResult,
    generate_key,
    validate_config,
)

from . import doc_fixtures as fx
from .conftest import needs

ROOT = Path(__file__).resolve().parents[1]
FAST: dict[str, Any] = {"detection": {"ner": {"enabled": False}}}
KEY_VALUE = "sk-proj-7Hq2LmV9xRt4KpZ8wNc3YbF6dJs1GaE5"  # invented
CANARIES = [
    "maria.jansen@northwind.example",
    "4111 1111 1111 1111",
    "NL91 ABNA 0417 1643 00",
    KEY_VALUE,
    "Maria Jansen",
]
README_EXAMPLE = (
    "Customer Maria Jansen (maria.jansen@northwind.example, +31 6 1234 5678) was charged twice on card "
    "4111 1111 1111 1111 and wants the refund on IBAN NL91 ABNA 0417 1643 00.\n"
    f"The refund job uses OPENAI_API_KEY={KEY_VALUE} and returns 401.\nDraft a reply to her and tell me what is wrong."
)


def _models_or_skip() -> None:
    if importlib.util.find_spec("en_core_web_sm") is None:
        needs("models", "en_core_web_sm is not installed")


def fresh_environment() -> dict[str, str]:
    """The environment without Harpo's own variables (the settings, $HARPO_CONFIG, $HARPO_URL, $HARPO_KEY and their
    PRIVATEAI_ names), as a new process has it. $HARPO_REQUIRE, the test suite's own switch, stays."""
    return {k: v for k, v in os.environ.items() if not k.startswith(("HARPO_", "PRIVATEAI_")) or k == "HARPO_REQUIRE"}


def use_fresh_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Other tests' command-line calls leave $HARPO_CONFIG behind (the CLI exports it for the processes it starts), and
    Harpo.from_env(), the CLI and GatewayClient() read it: each SDK test starts from a new process's environment."""
    for name in set(os.environ) - set(fresh_environment()):
        monkeypatch.delenv(name)


@pytest.fixture(autouse=True)
def _fresh_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    use_fresh_environment(monkeypatch)


@pytest.fixture(scope="module")
def harpo() -> Iterator[Harpo]:
    _models_or_skip()
    with Harpo() as engine:
        yield engine


@pytest.fixture(scope="module")
def fast() -> Iterator[Harpo]:
    with Harpo(FAST) as engine:
        yield engine


def _corpus(n: int = 260) -> list[str]:
    """Texts from LeakBench (every attack and language) and one per credential rule, plus the README's example."""
    rows = [json.loads(line) for line in (ROOT / "bench/leakbench/corpus.jsonl").read_text().splitlines() if line]
    rng = random.Random(25)
    texts = [r["text"] for r in rng.sample(rows, min(n, len(rows)))]
    samples = json.loads((ROOT / "tests/data/secret_samples.json").read_text())["samples"]
    texts += [s["text"] for s in list(samples.values())[:60]]
    return [README_EXAMPLE, *texts]


def _comparable(result: ScanResult) -> dict[str, Any]:
    data = dataclasses.asdict(result)
    data.pop("timings_ms")
    data.pop("request_id")
    return data


# --------------------------------------------------------------------------- one implementation
def test_scan_equals_the_pipeline_the_cli_uses(harpo: Harpo) -> None:
    """For every text, the SDK's result is the canonical pipeline's (`harpo scan`, the benchmarks): same redacted
    text, same findings with the same offsets, placeholders and sources, same risk and reasons."""
    settings = Settings.model_validate({})
    pipeline = Pipeline(settings, ner=load_ner(settings.detection.ner))
    for text in _corpus():
        outcome = pipeline.scan_sync([text])
        result = harpo.scan(text)
        assert result.text == outcome.texts[0]
        assert [dataclasses.astuple(f) for f in result.findings] == [
            (f.type, f.start, f.end, f.placeholder, f.sources) for f in outcome.findings[0]
        ]
        assert result.risk.value == outcome.risk.value
        assert [(r.code, r.message, r.entity_type, r.count) for r in result.reasons] == [
            (r.code, r.message, None if r.entity_type is None else str(r.entity_type), r.count) for r in outcome.reasons
        ]
        assert dict(result.counts) == outcome.counts


def test_scan_equals_the_harpo_scan_command(
    harpo: Harpo, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from harpo_redact.__main__ import main

    monkeypatch.chdir(tmp_path)  # no harpo.yaml to discover: the defaults, as Harpo() uses
    monkeypatch.setattr("sys.stdin", io.StringIO(README_EXAMPLE))
    assert main(["scan"]) == 0
    printed = json.loads(capsys.readouterr().out)
    result = harpo.scan(README_EXAMPLE)
    assert printed["redacted"] == result.text and printed["risk"] == result.risk.value
    assert printed["counts"] == dict(result.counts)
    assert printed["entities"] == [{**dataclasses.asdict(f), "sources": list(f.sources)} for f in result.findings]
    assert [r["code"] for r in printed["reasons"]] == [r.code for r in result.reasons]


def test_the_readme_example(harpo: Harpo) -> None:
    after = (ROOT / "README.md").read_text().split("```text\n")[2].split("```")[0].strip()
    result = harpo.scan(README_EXAMPLE)
    assert result.text == after
    assert result.risk is Risk.YELLOW and not result.blocked  # a key was redacted: an advisory, not a block
    assert result.redactions == 6
    assert harpo.redact(README_EXAMPLE) == after


def test_findings_point_into_the_original_text(harpo: Harpo) -> None:
    text = "Ask Maria Jansen at maria.jansen@northwind.example or +31 6 1234 5678."
    found = {f.type: text[f.start : f.end] for f in harpo.scan(text).findings if f.start is not None}
    assert found["EMAIL"] == "maria.jansen@northwind.example"
    assert found["PHONE"] == "+31 6 1234 5678"
    assert found["PERSON"] == "Maria Jansen"


def test_texts_are_scanned_together(harpo: Harpo) -> None:
    result = harpo.scan(["Maria Jansen wrote to us.", "Reply to Maria Jansen at maria.jansen@northwind.example."])
    assert result.texts == ("[PERSON_1] wrote to us.", "Reply to [PERSON_1] at [EMAIL_1].")
    assert len(result.items) == 2 and len(result.items[1].findings) == 2
    with pytest.raises(ValueError, match="2 texts"):
        _ = result.text
    assert harpo.redact(["Maria Jansen wrote", "to maria.jansen@northwind.example"]) == [
        "[PERSON_1] wrote",
        "to [EMAIL_1]",
    ]


def test_verify_is_the_egress_check(fast: Harpo) -> None:
    settings = Settings.model_validate(FAST)
    pipeline = Pipeline(settings)
    for text in _corpus(80):
        assert dict(fast.verify(text).counts) == pipeline.residual_sync([text])
    assert fast.verify("Mail [EMAIL_1] about [CREDIT_CARD_1]").clean
    assert not fast.verify("Mail maria.jansen@northwind.example").clean


def test_scan_response_is_the_response_scan(fast: Harpo) -> None:
    pipeline = Pipeline(Settings.model_validate(FAST))
    for text in _corpus(60):
        texts, counts = pipeline.redact_deterministic_sync([text])
        scanned = fast.scan_response(text)
        assert scanned.text == texts[0] and dict(scanned.counts) == counts
    assert fast.scan_response("Your key AKIAZ4X7Q2LMWN3RT5PJ is set").text == "Your key [SECRET] is set"


def test_documents_equal_the_document_service(harpo: Harpo) -> None:
    """The same file through the SDK and through redact_document (what `harpo redact-file` calls) is redacted
    identically, byte for byte."""
    settings = Settings.model_validate({})
    pipeline = Pipeline(settings, ner=load_ner(settings.detection.ner))
    data = fx.make_docx()
    expected = asyncio.run(
        redact_document(
            pipeline, settings.documents, WorkerRunner(settings.documents), data, "notes.docx", None,
            mode=None, context_repair=None, override=False, want_file=True,
        )
    )  # fmt: skip
    result = harpo.redact_document(data, filename="notes.docx")
    assert result.data == expected.data and result.text == expected.text and result.verified
    assert result.kind == "docx" and result.filename == "notes.redacted.docx"
    assert fx.canaries_in_package(result.data) == []
    assert dict(result.counts) == expected.scan.counts


# --------------------------------------------------------------------------- configuration
def test_configuration_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "harpo.yaml"
    path.write_text(yaml.safe_dump({"policy": {"default_mode": "generic"}, **FAST}))
    with Harpo(path) as from_file, Harpo(str(path)) as from_str:
        assert from_file.scan("mail a.b@example.com").text == "mail [EMAIL]"
        assert from_str.policy.default_mode == "generic"
    monkeypatch.setenv("HARPO_CONFIG", str(path))
    with Harpo.from_env() as from_env:
        assert from_env.policy.default_mode == "generic"
    monkeypatch.setenv("HARPO_POLICY__DEFAULT_MODE", "generic")  # HARPO_* variables apply, as for the gateway
    with Harpo(FAST) as from_variables:
        assert from_variables.policy.default_mode == "generic"


def test_an_invalid_configuration_names_the_setting_not_the_value() -> None:
    marker = "VALUE-THAT-MUST-NOT-BE-ECHOED"
    with pytest.raises(ConfigurationError) as caught:
        Harpo({"policy": {"default_mode": marker}})
    assert caught.value.issues and caught.value.issues[0].path == "policy.default_mode"
    assert marker not in str(caught.value)
    with pytest.raises(ConfigurationError, match="not found"):
        Harpo("/nonexistent/harpo.yaml")
    with pytest.raises(TypeError):
        Harpo(42)  # type: ignore[arg-type]


def test_a_missing_model_says_how_to_install_it() -> None:
    with pytest.raises(ConfigurationError, match="not installed") as caught:
        Harpo({"detection": {"ner": {"model": "xx_harpo_missing_sm"}}})
    assert caught.value.issues[0].path == "detection.ner"


def test_the_live_policy_file_is_laid_over_as_the_gateway_does(tmp_path: Path) -> None:
    live = tmp_path / "policy.live.yaml"
    live.write_text(yaml.safe_dump({"version": 1, "entities": {"EMAIL": "block"}}))
    with Harpo({**FAST, "policy": {"live_file": str(live)}}) as engine:
        assert engine.status().live_policy and engine.policy.entities["EMAIL"].action == "block"
        with pytest.raises(BlockedError):
            engine.redact("mail a.b@example.com")
    live.write_text("entities: {SECRET: allow}\n")  # keys are not part of the live policy
    with pytest.raises(ConfigurationError, match="live_file"):
        Harpo({**FAST, "policy": {"live_file": str(live)}})


def test_validate_config_reports_like_check_config(tmp_path: Path) -> None:
    good = validate_config({"environment": "development", **FAST})
    assert good.valid and good.ok and not good.problems
    production = validate_config({})  # production is the default: no keys, no upstreams
    assert production.valid and not production.ok
    assert any("auth.keys" in p for p in production.problems) and any("upstreams" in p for p in production.problems)
    bad = validate_config({"policy": {"entities": {"SECRET": {"action": "allow"}}}})
    assert not bad.valid and bad.errors[0].path.startswith("policy.entities")
    missing = validate_config({"environment": "development", "detection": {"ner": {"model": "xx_harpo_missing_sm"}}})
    assert missing.valid and missing.missing_models and not missing.ok
    notice = validate_config(
        {"environment": "development", "detection": {"ner": {"enabled": False}, "secrets": {"library": False}}}
    )
    assert notice.notices  # asked for, not honoured: keys are always redacted


# --------------------------------------------------------------------------- results and errors
def test_results_are_frozen_and_print_no_text(harpo: Harpo) -> None:
    result = harpo.scan(README_EXAMPLE)
    for shown in (repr(result), str(result), repr(result.items[0]), repr(result.findings)):
        assert not any(c in shown for c in CANARIES)
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.risk = Risk.GREEN  # type: ignore[misc]
    assert isinstance(result.findings[0], Finding) and result.findings[0].placeholder.startswith("[")
    document = harpo.redact_document(f"Contact {CANARIES[0]} today.".encode(), filename="note.txt")
    assert CANARIES[0] not in repr(document) and document.data == b"Contact [EMAIL_1] today."


def test_bad_arguments(fast: Harpo) -> None:
    with pytest.raises(InvalidRequestError):
        fast.scan([])
    with pytest.raises(TypeError):
        fast.scan(b"bytes")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        fast.scan(["ok", 3])  # type: ignore[list-item]
    with pytest.raises(InvalidRequestError, match="mode"):
        fast.scan("x", mode="loud")  # type: ignore[arg-type]
    with pytest.raises(InvalidRequestError, match="layers"):
        fast.scan("x", layers="all")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        fast.redact_document(12)  # type: ignore[arg-type]
    assert fast.scan("").text == ""


def test_a_closed_engine_refuses() -> None:
    engine = Harpo(FAST)
    engine.close()
    engine.close()  # twice is fine
    with pytest.raises(HarpoError, match="closed"):
        engine.scan("x")


def test_errors_inside_the_engine_do_not_quote_the_input(fast: Harpo, monkeypatch: pytest.MonkeyPatch) -> None:
    async def broken(*args: Any, **kwargs: Any) -> Any:
        raise ValueError(f"cannot handle {CANARIES[0]}")

    monkeypatch.setattr(fast._core._pipeline, "scan", broken)
    with pytest.raises(HarpoError) as caught:
        fast.scan(f"mail {CANARIES[0]}")
    assert CANARIES[0] not in str(caught.value) and caught.value.__cause__ is None
    assert isinstance(caught.value.original, ValueError)  # type: ignore[attr-defined]


def test_nothing_sensitive_is_logged(harpo: Harpo, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    harpo.scan(README_EXAMPLE)
    with pytest.raises(BlockedError) as caught, harpo.with_policy(entities={"IBAN": "block"}) as strict:
        strict.redact(README_EXAMPLE)
    logged = "\n".join(r.getMessage() + json.dumps(getattr(r, "fields", {}), default=str) for r in caplog.records)
    for canary in CANARIES:
        assert canary not in logged
        assert canary not in str(caught.value) and canary not in repr(caught.value)


# --------------------------------------------------------------------------- policy and invariants
def test_block_redact_and_allow(harpo: Harpo) -> None:
    ssn = "My SSN is 536-90-4399."
    with harpo.with_policy(entities={"US_SSN": "block", "ORGANIZATION": "allow"}) as strict:
        result = strict.scan(ssn)
        assert result.blocked and result.blocked_types == ("US_SSN",) and result.text == "My SSN is [US_SSN_1]."
        with pytest.raises(BlockedError) as caught:
            strict.redact(ssn)
        assert caught.value.codes == ("blocked_entity",) and caught.value.blocked_types == ("US_SSN",)
        assert "536-90-4399" not in str(caught.value)
        assert strict.policy.entities["US_SSN"].action == "block"
    with harpo.with_policy(entities={"EMAIL": "allow"}) as relaxed:
        assert relaxed.redact("mail a.b@example.com") == "mail a.b@example.com"


def test_custom_types(fast: Harpo) -> None:
    custom = [
        CustomType("EMPLOYEE_ID", patterns=(r"\bEMP-\d{6}\b",)),
        {"name": "PROJECT", "terms": ["Project Bluefin"], "action": "block"},
    ]
    with fast.with_policy(custom_types=custom) as engine:
        assert engine.redact("badge EMP-123456") == "badge [EMPLOYEE_ID_1]"
        with pytest.raises(BlockedError, match=r"PROJECT|protected"):
            engine.redact("status of project bluefin?")
        names = {c.name: c for c in engine.policy.custom_types}
        assert names["PROJECT"].terms == 1 and names["EMPLOYEE_ID"].patterns == 1  # counted, never listed
    with pytest.raises(ConfigurationError, match="EMAIL"):
        fast.with_policy(custom_types=[CustomType("EMAIL", terms=("x y",))])  # a built-in type's name
    with pytest.raises(ConfigurationError):
        fast.with_policy(custom_types=[CustomType("CODE", patterns=("(a)\\1",))])  # not RE2: no backreferences


def test_inv11_keys_are_always_redacted(fast: Harpo) -> None:
    """No policy, switch or override lets a key through, and a key never blocks (INV-11)."""
    for attempt in ({"SECRET": "allow"}, {"PRIVATE_KEY": "allow"}, {"SECRET": "block"}):
        with pytest.raises(ConfigurationError):
            fast.with_policy(entities=attempt)  # type: ignore[arg-type]
    with pytest.raises(ConfigurationError):
        Harpo({**FAST, "policy": {"entities": {"SECRET": {"action": "allow"}}}})
    text = f"deploy with {KEY_VALUE}"
    for override in (False, True):
        out = fast.redact(text, override=override)
        assert KEY_VALUE not in out and "[SECRET_1]" in out
    with Harpo({**FAST, "policy": {"allow_terms": [KEY_VALUE], "override": "any_key"}}) as lenient:
        assert KEY_VALUE not in lenient.redact(text, override=True)  # allow_terms never exempt a key
    assert set(fast.policy.always_redacted) == {"PRIVATE_KEY", "SECRET"}


def test_overrides_follow_the_policy(fast: Harpo) -> None:
    ssn = "SSN 536-90-4399"
    policy = {"US_SSN": {"action": "block", "overridable": True}}
    with Harpo({**FAST, "policy": {"entities": policy}}) as engine:
        blocked = engine.scan(ssn)
        assert blocked.blocked and blocked.overridable and engine.policy.override_permitted
        assert engine.redact(ssn, override=True) == "SSN [US_SSN_1]"
        assert "override_applied" in [r.code for r in engine.scan(ssn, override=True).reasons]
    with Harpo({**FAST, "policy": {"entities": policy, "override": "never"}}) as never:
        with pytest.raises(BlockedError) as caught:
            never.redact(ssn, override=True)
        assert not caught.value.override_permitted and not never.policy.override_permitted


def test_the_mode_is_the_callers_only_when_the_policy_says_so(fast: Harpo) -> None:
    assert fast.scan("mail a.b@example.com", mode="generic").text == "mail [EMAIL]"
    with Harpo({**FAST, "policy": {"client_may_choose_mode": False}}) as fixed:
        result = fixed.scan("mail a.b@example.com", mode="generic")  # ignored, as X-Harpo-Mode would be
        assert result.mode == "relational" and result.text == "mail [EMAIL_1]"


def test_egress_verification_stops_what_the_scan_left(fast: Harpo, monkeypatch: pytest.MonkeyPatch) -> None:
    """redact() runs the proxy's egress check: anything the deterministic layers still find stops it (INV-01)."""

    async def leftover(texts: list[str]) -> dict[str, int]:
        return {"EMAIL": 1}

    monkeypatch.setattr(fast._core._pipeline, "residual", leftover)
    with pytest.raises(BlockedError) as caught:
        fast.redact("nothing to see")
    assert caught.value.codes == ("egress_verification",) and caught.value.blocked_types == ("EMAIL",)
    assert fast.scan("nothing to see").risk is Risk.GREEN  # scan() is the scan, as POST /v1/scan
    with Harpo({**FAST, "policy": {"egress_verification": "off"}}) as off:
        monkeypatch.setattr(off._core._pipeline, "residual", leftover)
        assert off.redact("nothing to see") == "nothing to see"


def test_scan_budgets_block(fast: Harpo) -> None:
    with Harpo({**FAST, "server": {"max_entities": 10}}) as small:
        result = small.scan(" ".join(f"user{i}@example.com" for i in range(40)))
        assert result.blocked and [r.code for r in result.reasons] == ["scan_budget"]


# --------------------------------------------------------------------------- documents
def test_document_inputs_and_outputs(fast: Harpo, tmp_path: Path) -> None:
    source = tmp_path / "Priya Raman CV.txt"
    source.write_text(f"Mail {fx.EMAIL} or call {fx.PHONE}.\n")
    result = fast.redact_document(source)
    assert result.kind == "text" and result.verified and fx.EMAIL.encode() not in (result.data or b"")
    assert result.filename == "Priya Raman CV.redacted.txt" or result.filename == "document.redacted.txt"
    saved = result.save(tmp_path)
    assert saved.read_bytes() == result.data
    text_only = fast.redact_document(source, file=False)
    assert text_only.data is None and text_only.filename is None and fx.EMAIL not in text_only.text
    with pytest.raises(ValueError):
        text_only.save(tmp_path / "x.txt")
    with pytest.raises(DocumentError) as caught:
        fast.redact_document(b"\xd0\xcf\x11\xe0legacy", filename="old.doc")
    assert caught.value.code == "legacy_office"
    with fast.with_policy(entities={"EMAIL": "block"}) as strict, pytest.raises(BlockedError):
        strict.redact_document(source)


def test_office_and_pdf_documents(harpo: Harpo) -> None:
    for data, name in ((fx.make_xlsx(), "sheet.xlsx"), (fx.make_pptx(), "deck.pptx"), (fx.make_pdf(), "scan.pdf")):
        result = harpo.redact_document(data, filename=name)
        assert result.verified and result.redactions > 0 and result.data
        assert fx.EMAIL not in result.text


# --------------------------------------------------------------------------- sync and async
def test_async_engine_equals_the_sync_engine(harpo: Harpo) -> None:
    texts = _corpus(40)

    async def run() -> list[ScanResult]:
        async with AsyncHarpo() as engine:
            results = await asyncio.gather(*(engine.scan(t) for t in texts))
            assert await engine.redact(README_EXAMPLE) == harpo.redact(README_EXAMPLE)
            document = await engine.redact_document(b"Mail a.b@example.com\n", filename="a.txt")
            assert document.data == b"Mail [EMAIL_1]\n"
            assert (await engine.verify("a.b@example.com")).counts == {"EMAIL": 1}
            assert (await engine.status()).ner_models == ("en_core_web_sm",)
            stricter = await engine.with_policy(entities={"EMAIL": "block"})
            with pytest.raises(BlockedError):
                await stricter.redact("a.b@example.com")
            await stricter.aclose()
            return list(results)

    for text, result in zip(texts, asyncio.run(run()), strict=True):
        assert _comparable(result) == _comparable(harpo.scan(text))


def test_async_engine_starts_on_first_use() -> None:
    async def run() -> str:
        engine = AsyncHarpo(FAST)
        try:
            return await engine.redact("mail a.b@example.com")
        finally:
            await engine.aclose()

    assert asyncio.run(run()) == "mail [EMAIL_1]"


def test_the_sync_engine_is_thread_safe_and_works_inside_an_event_loop(harpo: Harpo) -> None:
    texts = _corpus(48)
    expected = [harpo.scan(t).texts for t in texts]
    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        assert [r.texts for r in pool.map(harpo.scan, texts)] == expected

    async def inside() -> str:
        return harpo.redact("mail a.b@example.com")  # a blocking call from a coroutine, as in a notebook

    assert asyncio.run(inside()) == "mail [EMAIL_1]"


# --------------------------------------------------------------------------- the rest of the surface
def test_status_policy_library_analysis_and_trace(harpo: Harpo) -> None:
    status = harpo.status()
    assert status.version == "2.5.0" and status.secret_rules >= 221 and status.slm is None
    families = [f for g in harpo.detection_library()["groups"] for f in g["families"]]
    assert families and all("enabled" in f for f in families)
    assert {f.level for f in harpo.analyze()} <= {"required", "recommended", "info"}
    trace = harpo.trace(README_EXAMPLE)
    assert trace.data["final"]["text"] == harpo.redact(README_EXAMPLE)
    assert not any(c in repr(trace) for c in CANARIES)


def test_generated_keys_are_gateway_keys() -> None:
    key = generate_key("ci-bot", can_override=True, requests_per_minute=60)
    assert isinstance(key, GatewayKey) and key.key.startswith("harpo_") and len(key.key) == 6 + 43
    assert hashlib.sha256(key.key.encode()).hexdigest() == key.sha256
    entry = AuthKey.model_validate(yaml.safe_load(key.yaml)[0])
    assert entry.id == "ci-bot" and entry.can_override and entry.requests_per_minute == 60
    assert key.key not in repr(key) and key.key not in key.yaml
    with pytest.raises(InvalidRequestError, match="id"):
        generate_key("not a valid id!")
    assert generate_key("x").key != generate_key("x").key


def test_top_level_imports_stay_light() -> None:
    """The document worker imports the package: the SDK and the pipeline load only when they are used."""
    code = (
        "import sys, harpo_redact; assert 'harpo_redact.sdk' not in sys.modules; "
        "assert 'harpo_redact.pipeline' not in sys.modules; "
        "from harpo_redact.sdk import GatewayClient; assert 'harpo_redact.pipeline' not in sys.modules; "
        "from harpo_redact import Harpo, AsyncHarpo, AsyncGatewayClient; "
        "import harpo_redact.sdk as sdk; assert all(hasattr(sdk, n) for n in sdk.__all__); print('ok')"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
    assert out.stdout.strip() == "ok", out.stderr


def test_the_public_surface_is_declared() -> None:
    import harpo_redact.sdk as sdk

    public = {name for name in dir(sdk) if not name.startswith("_")} - {"annotations", "TYPE_CHECKING", "Any"}
    assert public <= set(sdk.__all__) | {"EntityType", "Harpo", "AsyncHarpo", "generate_key", "validate_config"}
    for name in sdk.__all__:
        obj = getattr(sdk, name)
        assert getattr(obj, "__doc__", None), f"{name} has no docstring"
    assert (ROOT / "src/harpo_redact/py.typed").exists()


def test_live_policy_overlay_is_the_consoles() -> None:
    """with_policy() is live_policy.apply: the same combination the console's Policy page saves."""
    base = Settings.model_validate(FAST)
    overlay = live_policy.LivePolicy.model_validate({"entities": {"PHONE": "block"}})
    expected = live_policy.apply(base, overlay)
    with Harpo(FAST) as engine, engine.with_policy(entities={"PHONE": "block"}) as changed:
        assert changed._core.settings.model_dump() == expected.model_dump()
        assert changed.scan("call +31 20 794 6095").blocked
