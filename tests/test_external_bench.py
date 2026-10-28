"""The external-benchmark scorer (bench/external): what counts as protected, partly protected or leaked, the scope
rule, the dev/holdout halves, ProwlBench's own metric, the loaders, and the doc's tables against the results."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bench" / "external"))

import corpora  # noqa: E402
import harness  # noqa: E402
import report  # noqa: E402
import run as runner  # noqa: E402
from corpora import Doc, Gold, half_of  # noqa: E402
from scope import scope_of  # noqa: E402


def _doc(text: str, *spans: tuple[str, str], secret: bool | None = None) -> Doc:
    gold = []
    for value, label in spans:
        start = text.index(value)
        gold.append(Gold(start, start + len(value), (label,)))
    return Doc("d1", text, gold, {"half": "dev"}, secret=secret)


def _at(text: str, value: str, kind: str) -> tuple[int, int, str]:
    start = text.index(value)
    return (start, start + len(value), kind)


def test_only_letters_and_digits_must_be_covered() -> None:
    text = "call +31 (0)6-1234 5678 now"
    doc = _doc(text, ("+31 (0)6-1234 5678", "TELEPHONENUM"))
    pieces = [_at(text, "31", "PHONE"), _at(text, "0)6-1234", "PHONE"), _at(text, "5678", "PHONE")]
    [span] = harness.score(doc, pieces, False, "openpii")["spans"]
    assert span["status"] == "redacted" and span["coverage"] == 1.0  # "+", "(", "-" and blanks left are not the value


def test_partly_covered_and_untouched_values() -> None:
    text = "IBAN NL91ABNA0417164300 and NL20INGB0001234567"
    doc = _doc(text, ("NL91ABNA0417164300", "iban"), ("NL20INGB0001234567", "iban"))
    first, second = harness.score(doc, [_at(text, "NL91ABNA0", "IBAN")], False, "nemotron")["spans"]
    assert first["status"] == "partial" and first["coverage"] == 0.5
    assert second["status"] == "leaked" and second["coverage"] == 0.0


def test_a_blocked_request_protects_every_value() -> None:
    text = "password hunter2 for bob@example.com"
    doc = _doc(text, ("hunter2", "password"), ("bob@example.com", "email"))
    result = harness.score(doc, [], True, "gretel")
    assert {s["status"] for s in result["spans"]} == {"blocked"}
    totals = harness._recall(result["spans"])
    assert totals["recall"] == 1.0 and totals["blocked"] == 2


def test_collateral_counts_redacted_characters_outside_the_gold_spans_by_type() -> None:
    text = "Anna Smith at Acme Corp"
    doc = _doc(text, ("Anna Smith", "name"))
    result = harness.score(
        doc, [_at(text, "Anna Smith", "PERSON"), _at(text, "Acme Corp", "ORGANIZATION")], False, "nemotron"
    )
    assert result["spans"][0]["status"] == "redacted"
    assert result["collateral"] == {"ORGANIZATION": 8}  # letters of "Acme Corp"; the blank is not counted
    assert result["outside_chars"] == sum(c.isalnum() for c in "  at Acme Corp")


def test_a_finding_without_a_position_is_counted_not_placed() -> None:
    result = harness.score(_doc("token abc", ("abc", "secret")), [(None, None, "SECRET")], False, "prowlbench")
    assert result["unplaced_findings"] == 1 and result["spans"][0]["status"] == "leaked"


def test_recall_strict_and_any_part() -> None:
    rows = [{"status": s} for s in ("redacted", "blocked", "partial", "leaked")]
    assert harness._recall(rows) == {
        "spans": 4,
        "redacted": 1,
        "blocked": 1,
        "partial": 1,
        "leaked": 1,
        "recall": 0.5,
        "recall_any": 0.75,
    }
    assert harness._recall([])["recall"] is None


def test_scope_rule() -> None:
    assert scope_of("openpii", ["GIVENNAME"]) == "in"
    assert scope_of("openpii", ["AGE"]) == "out"
    assert scope_of("openpii", ["SOMETHING_NEW"]) == "unmapped"
    assert scope_of("gretel", ["date", "name"]) == "in"  # in scope when any label is
    assert scope_of("redactionbench", ["mandatory"]) == "in"
    assert scope_of("redactionbench", ["contextual"]) == "out"
    assert scope_of("prowlbench", ["secret"]) == "in"


def test_halves_are_fixed_and_balanced() -> None:
    assert [half_of(f"pb-{i:05d}") for i in range(4)] == [half_of(f"pb-{i:05d}") for i in range(4)]
    ids = [f"pb-{i:05d}" for i in range(20000)]
    share = sum(half_of(i) == "dev" for i in ids) / len(ids)
    assert 0.48 < share < 0.52
    # pinned, so a change to the salt or the hash shows up here rather than as a silently different holdout
    assert "".join("d" if half_of(f"pb-{i:05d}") == "dev" else "h" for i in range(12)) == PINNED_HALVES


PINNED_HALVES = "hdddddhdddhh"


def _result(id_: str, flagged: bool, secret: bool, tier: str, named: bool | None = None) -> dict[str, Any]:
    meta = {"tier": tier, "lang": "en", "source": "code", "type": "t_pos" if secret else "neg_t", "half": "dev"}
    return {"id": id_, "key_flag": flagged, "secret": secret, "meta": meta, "credential_named": named}


def test_prowlbench_metric_is_a_flag_per_snippet() -> None:
    results = [
        _result("a", True, True, "T1_structured"),
        _result("b", True, True, "T2_generic_context"),
        _result("c", False, True, "T2_generic_context"),
        _result("d", True, False, "T4_hard_negative", named=True),
        _result("e", False, False, "T4_hard_negative", named=False),
        _result("f", False, False, "T4_hard_negative", named=False),
    ]
    m = harness.prowl_metrics(results)
    assert (m["precision"], m["recall"], m["accuracy"]) == (round(2 / 3, 4), round(2 / 3, 4), round(4 / 6, 4))
    assert m["f1"] == round(2 / 3, 4)
    assert m["per_tier"]["T1_structured"] == {"recall": 1.0, "n": 1}
    assert m["per_tier"]["T2_generic_context"] == {"recall": 0.5, "n": 2}
    assert m["per_tier"]["T4_hard_negative"] == {"fp_rate": round(1 / 3, 4), "n": 3}
    assert m["negatives"] == {"credential_named": {"fp_rate": 1.0, "n": 1}, "other": {"fp_rate": 0.0, "n": 2}}
    assert m["per_type"] == {
        "neg_t": {"fp_rate": round(1 / 3, 4), "n": 3},
        "t_pos": {"recall": round(2 / 3, 4), "n": 3},
    }
    # another tool's flags, scored the same way
    assert harness.prowl_metrics(results, flagged={"a", "b", "c"})["recall"] == 1.0


def test_credential_named_negatives() -> None:
    named = harness.CREDENTIAL_NAMED_RE
    assert named.search("API_KEY=2e455592-1a63-4557-a439-a23b2fad1799 found in logs")
    assert named.search("the staging secret is auth_service_gateway_68")
    assert named.search('"password": "dummytoken"')
    assert not named.search("cache buster d41d8cd98f00b204e9800998ecf8427e")
    assert not named.search("the password policy changed")


def test_jsonl_loaders(tmp_path: Path) -> None:
    openpii = tmp_path / "openpii.jsonl"
    openpii.write_text(
        json.dumps(
            {
                "uid": "u1",
                "source_text": "Hi Anna, mail anna@example.com",
                "privacy_mask": [{"label": "GIVENNAME", "start": 3, "end": 7, "value": "Anna"}],
                "language": "en",
            }
        )
        + "\n\n"
    )
    [doc] = corpora.openpii(openpii)
    assert (doc.id, doc.text[doc.gold[0].start : doc.gold[0].end], doc.meta["language"]) == ("u1", "Anna", "en")

    prowl = tmp_path / "prowl.jsonl"
    rows = [
        {"id": "pb-00001", "text": "key=ghp_x", "label": 1, "span": [4, 9], "tier": "T1_structured", "type": "github"},
        {"id": "pb-00002", "text": "sha 3086d24", "label": 0, "span": None, "tier": "T4_hard_negative"},
        {"id": "pb-00003", "text": "real one", "label": 1, "span": None, "tier": "T2_generic_context"},
    ]
    prowl.write_text("".join(json.dumps(r) + "\n" for r in rows))
    docs = list(corpora.prowlbench(prowl))
    assert [d.secret for d in docs] == [True, False, True]
    assert [len(d.gold) for d in docs] == [1, 0, 0]  # a positive without a span is scored by its flag alone
    assert docs[0].meta["half"] == half_of("pb-00001")


TABLE: list[dict[str, Any]] = []


def test_parquet_loaders_read_spans_entities_and_offsets(monkeypatch: pytest.MonkeyPatch) -> None:
    def rows(_: Path) -> Any:
        return iter(TABLE)

    monkeypatch.setattr(corpora, "_parquet_rows", rows)
    TABLE[:] = [{"uid": "n1", "text": "Call Ann on 555-0100", "domain": "health", "document_format": "email",
                 "spans": '[{"start": 5, "end": 8, "label": "first_name"}, {"start": 12, "end": 20, "label": "phone_number"}]'}]  # fmt: skip
    [doc] = corpora.nemotron(Path("x"))
    assert [(g.labels, doc.text[g.start : g.end]) for g in doc.gold] == [
        (("first_name",), "Ann"),
        (("phone_number",), "555-0100"),
    ]

    TABLE[:] = [{"uid": "g1", "text": "Ann met Ann; code 42", "domain": "x",
                 "entities": [{"entity": "Ann", "types": ["first_name"]}, {"entity": "Bob", "types": ["name"]}]}]  # fmt: skip
    [doc] = corpora.gretel(Path("x"))
    assert [(g.start, g.end) for g in doc.gold] == [(0, 3), (8, 11)]  # every occurrence of a value without offsets
    assert doc.unlocated == 1  # "Bob" is not in the text: counted, not scored

    TABLE[:] = [{"raw_text": "Name: Ann", "category": "medical", "is_synthetic": True,
                 "spans": "[{'start': 6, 'end': 9, 'label': 'mandatory'}]"}]  # fmt: skip
    [doc] = corpora.redactionbench(Path("x"))
    assert (doc.id, doc.gold[0].labels, doc.meta["synthetic"], doc.meta["half"]) == (
        "rb-000",
        ("mandatory",),
        "True",
        half_of("rb-000"),
    )


def test_a_run_writes_its_identity_and_scores(tmp_path: Path) -> None:
    data = tmp_path / "prowl.jsonl"
    key = "sk-proj-Qz7vB3nK9xLm2PwR8tYc4HdJ6fGs"
    text = f"export OPENAI_API_KEY={key}"
    rows = [
        {"id": "pb-00001", "text": text, "label": 1, "span": [text.index(key), len(text)], "tier": "T1_structured",
         "lang": "en", "source": "code", "origin": "synthetic", "type": "openai"},
        {"id": "pb-00002", "text": "git sha 3086d2477 is not a secret", "label": 0, "span": None,
         "tier": "T4_hard_negative", "lang": "en", "source": "slack", "origin": "synthetic", "type": "neg_git_sha"},
    ]  # fmt: skip
    data.write_text("".join(json.dumps(r) + "\n" for r in rows))
    out = tmp_path / "results"
    assert runner.main(["prowlbench", str(data), "--out", str(out), "--config", "deterministic", "--workers", "1"]) == 0
    record = json.loads((out / "prowlbench-deterministic.json").read_text())
    assert record["harpo"]["version"] and len(record["harpo"]["package_sha256"]) == 64
    assert record["documents"] == 2 and record["metrics"]["in_scope"]["redacted"] == 1
    assert record["prowlbench"]["harpo"]["precision"] == 1.0 and record["prowlbench"]["harpo"]["recall"] == 1.0


def test_the_documented_tables_are_the_recorded_results() -> None:
    doc = (ROOT / "docs" / "EXTERNAL_BENCHMARKS.md").read_text()
    assert report.refresh(doc) == doc, "regenerate with: python bench/external/report.py"


# RedactionBench's R-Score (bench/external/rscore.py), on hand-made documents.
import rscore  # noqa: E402

FORM = "Name: Ann Lee  Tel: (555) 010-2233  Dept: Sales"


def _labelled(text: str, *parts: tuple[str, str]) -> list[tuple[int, int, str]]:
    """Spans by value, in order: each value is found after the previous one."""
    out, at = [], 0
    for value, label in parts:
        start = text.index(value, at)
        out.append((start, start + len(value), label))
        at = start + len(value)
    return out


FORM_SPANS = _labelled(
    FORM,
    ("Ann", "mandatory"), (" ", "contextual"), ("Lee", "mandatory"),
    ("(", "contextual"), ("555", "mandatory"), (") ", "contextual"), ("010", "mandatory"), ("-", "contextual"),
    ("2233", "mandatory"), ("Sales", "contextual"),
)  # fmt: skip


def _mask(text: str, *values: str) -> bytearray:
    out = bytearray(len(text))
    for value in values:
        start = text.index(value)
        out[start : start + len(value)] = b"\x01" * len(value)
    return out


def test_glue_joins_the_parts_of_one_entity() -> None:
    groups = rscore.entities(FORM, FORM_SPANS)
    shown = [(g.label, [FORM[s:e] for s, e in g.parts]) for g in groups]
    assert shown == [
        ("mandatory", ["Ann", "Lee"]),  # a blank between two mandatory parts joins them
        ("contextual", ["("]),  # glue with nothing labelled on its left stands alone
        ("mandatory", ["555", "010", "2233"]),
        ("contextual", ["Sales"]),
    ]


def test_every_mandatory_entity_removed_scores_one() -> None:
    result = rscore.document_score(FORM, FORM_SPANS, _mask(FORM, "Ann Lee", "(555) 010-2233"))
    assert result["score"] == 1.0 and result["mandatory_entities"] == 2 and result["false_runs"] == 0


def test_a_mandatory_entity_counts_the_mean_of_its_parts() -> None:
    result = rscore.document_score(FORM, FORM_SPANS, _mask(FORM, "Ann"))
    assert result["score"] == 0.25  # the name half removed, the phone not: 0.5 of 2


def test_a_contextual_entity_costs_only_when_half_done() -> None:
    whole = rscore.document_score(FORM, FORM_SPANS, _mask(FORM, "Ann Lee", "(555) 010-2233", "Sales"))
    assert whole["score"] == 1.0  # all of it removed: free
    half = rscore.document_score(FORM, FORM_SPANS, _mask(FORM, "Ann Lee", "(555) 010-2233", "Sal"))
    assert half["score"] == round(2 / 2.4, 6) and half["contextual_penalty"] == 0.4


def test_redactions_outside_the_labels_are_false_positives() -> None:
    one = rscore.document_score(FORM, FORM_SPANS, _mask(FORM, "Ann Lee", "(555) 010-2233", "Dept"))
    assert one["score"] == round(2 / 3, 6) and one["false_runs"] == 1 and one["whole_gaps"] == 0
    blank = rscore.document_score(FORM, FORM_SPANS, _mask(FORM, "Ann Lee  ", "(555) 010-2233"))
    assert blank["score"] == 1.0  # blanks next to a value are formatting, not a false positive
    text = "Ann and Lee"
    spans = _labelled(text, ("Ann", "mandatory"), ("Lee", "mandatory"))
    gap = rscore.document_score(text, spans, _mask(text, "Ann and Lee"))
    assert gap["whole_gaps"] == 1 and gap["score"] == 0.5  # the whole gap between two values costs two


def test_a_document_with_only_contextual_spans() -> None:
    text = "Meet on 03/08/2026 at noon"
    spans = _labelled(
        text,
        ("03", "contextual"),
        ("/", "contextual"),
        ("08", "contextual"),
        ("/", "contextual"),
        ("2026", "contextual"),
    )
    assert rscore.document_score(text, spans, bytearray(len(text)))["score"] == 1.0  # nothing to do, nothing done
    part = rscore.document_score(text, spans, _mask(text, "2026"))
    assert part["all_contextual"] and part["score"] == round(1 / 3, 6)  # one part of three, earned not charged
    assert rscore.document_score(text, spans, _mask(text, "03/08/2026"))["score"] == 1.0


def test_r_score_summary_and_blocked_documents() -> None:
    doc = Doc("rb-x", FORM, [corpora.Gold(s, e, (label,)) for s, e, label in FORM_SPANS], {"category": "academic"})
    blocked = harness.score(doc, [], True, "redactionbench")["r_score"]
    # everything removed: both values, "(" and Sales, and the three gaps between them ("Name: ", "  Tel: ",
    # "  Dept: "), each a whole gap of three or more characters, so each costs two
    assert (blocked["false_runs"], blocked["whole_gaps"], blocked["score"]) == (3, 3, 0.25)
    assert rscore.summarize([1.0, 0.5, 0.0, 0.75, 0.25]) == {"documents": 5, "mean": 0.5, "p50": 0.5, "p20": 0.25}
    rows = [{"meta": {"category": "academic", "half": "dev", "synthetic": "False"}, "r_score": {"score": 1.0}}]
    rows[0]["r_score"] |= {"num": 1, "mandatory_entities": 1, "contextual_attempted": 0, "contextual_penalty": 0,
                           "false_runs": 0, "whole_gaps": 0, "all_contextual": False}  # fmt: skip
    summary = harness.r_score_summary(rows)
    assert summary["mean"] == 1.0 and summary["unstructured"]["documents"] == 1
    assert summary["by_category"]["academic"]["mean"] == 1.0 and summary["macro_by_category"] == 1.0
