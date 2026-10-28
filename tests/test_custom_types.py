"""Custom types: your own names for values the gateway treats as sensitive (detection.custom_types).

Placeholders carry the name ([EMPLOYEE_ID_1]); each type has its own action; findings, counts, reasons, the lab,
egress verification, decoded payloads and line breaks all know the name.
"""

from __future__ import annotations

import base64
import random
import re

import pytest
from pydantic import ValidationError

from harpo_redact.detectors.custom import terms_regex
from harpo_redact.detectors.secrets import _term_pattern
from harpo_redact.entities import PLACEHOLDER_RE
from harpo_redact.lab import lab_run
from harpo_redact.pipeline import Pipeline

from .conftest import AUTH, chat, make_settings

EMPLOYEE = {"name": "EMPLOYEE_ID", "patterns": [r"\bEMP-\d{6}\b"], "description": "Staff numbers"}
PROJECT = {"name": "PROJECT", "terms": ["Project Bluefin", "Falcon"], "action": "block", "overridable": True}


def pipe(*types: dict, **policy: object) -> Pipeline:  # type: ignore[type-arg]
    detection = {"ner": {"enabled": False}, "custom_types": list(types)}
    return Pipeline(make_settings(detection=detection, **({"policy": policy} if policy else {})))


def test_each_type_numbers_its_own_placeholders() -> None:
    out = pipe(EMPLOYEE).scan_sync(["EMP-123456 and EMP-654321, then EMP-123456 again; mail jane@corp.example"])
    assert out.texts == ["[EMPLOYEE_ID_1] and [EMPLOYEE_ID_2], then [EMPLOYEE_ID_1] again; mail [EMAIL_1]"]
    assert out.counts == {"EMPLOYEE_ID": 3, "EMAIL": 1}
    assert [f.type for f in out.findings[0]][:2] == ["EMPLOYEE_ID", "EMPLOYEE_ID"]


def test_generic_mode_and_context_repair_use_the_name() -> None:
    p = pipe(EMPLOYEE)
    assert p.scan_sync(["EMP-123456 met EMP-654321."], mode="generic").texts == ["[EMPLOYEE_ID] met [EMPLOYEE_ID]."]
    repaired = p.scan_sync(["EMP-123456 met EMP-654321."], mode="generic", context_repair=True).texts
    assert repaired == ["[EMPLOYEE_ID_A] met [EMPLOYEE_ID_B]."]


def test_a_type_can_block_and_be_overridden() -> None:
    p = pipe(PROJECT)
    blocked = p.scan_sync(["ship Project Bluefin on friday"])
    assert blocked.blocked and blocked.overridable and blocked.blocked_types == ["PROJECT"]
    assert "PROJECT value" in blocked.reasons[0].message
    released = p.scan_sync(["ship Project Bluefin on friday"], override=True)
    assert not released.blocked and released.texts == ["ship [PROJECT_1] on friday"]


def test_off_means_not_looked_for() -> None:
    out = pipe({**EMPLOYEE, "action": "allow"}).scan_sync(["seen EMP-123456"])
    assert out.texts == ["seen EMP-123456"] and out.counts == {}


def test_a_custom_type_names_what_a_cue_word_only_suggests() -> None:
    # "badge" makes the value a badge number on its own; a type the user named for it gives the name.
    assert pipe().scan_sync(["badge EMP-123456"]).texts == ["badge [ACCOUNT_ID_1]"]
    assert pipe(EMPLOYEE).scan_sync(["badge EMP-123456"]).texts == ["badge [EMPLOYEE_ID_1]"]


def test_the_protected_term_policy_does_not_decide_for_a_custom_type() -> None:
    p = pipe(EMPLOYEE, entities={"PROTECTED_TERM": {"action": "block"}})
    assert p.scan_sync(["badge EMP-123456"]).texts == ["badge [EMPLOYEE_ID_1]"]
    # Allowing protected terms does not switch custom types off: not in the scan, not at egress.
    p = pipe(EMPLOYEE, PROJECT, entities={"PROTECTED_TERM": {"action": "allow"}})
    assert p.scan_sync(["badge EMP-123456"]).texts == ["badge [EMPLOYEE_ID_1]"]
    assert p.scan_sync(["ship Project Bluefin"]).blocked_types == ["PROJECT"]
    assert p.residual_sync(["badge EMP-123456"]) == {"EMPLOYEE_ID": 1}


def test_terms_match_whole_words_in_any_case_and_as_identifiers() -> None:
    p = pipe(PROJECT)
    custom = pipe({**PROJECT, "action": "redact"})
    text = "project bluefin, PROJECT-BLUEFIN, project_bluefin, Project\nBluefin and Falconry"
    out = custom.scan_sync([text]).texts[0]
    assert out == "[PROJECT_1], [PROJECT_1], [PROJECT_1], [PROJECT_1] and Falconry"  # one value, one placeholder
    assert p.scan_sync(["nothing here"]).texts == ["nothing here"]


def test_a_value_inside_base64_still_gets_its_types_action() -> None:
    wrapped = base64.b64encode(b"Project Bluefin ships Friday").decode()
    assert pipe(PROJECT).scan_sync([f"payload {wrapped}"]).blocked
    redacted = pipe({**PROJECT, "action": "redact"}).scan_sync([f"payload {wrapped}"])
    assert not redacted.blocked and redacted.texts == ["payload [ENCODED_DATA_1]"]


def test_placeholders_from_earlier_replies_are_left_alone_and_pass_egress() -> None:
    p = pipe(EMPLOYEE)
    assert p.scan_sync(["As I said, [EMPLOYEE_ID_1] asked for EMP-777777."]).texts == [
        "As I said, [EMPLOYEE_ID_1] asked for [EMPLOYEE_ID_1]."
    ]
    assert p.residual_sync(["badge [EMPLOYEE_ID_1] and [EMPLOYEE_ID_2]"]) == {}
    assert PLACEHOLDER_RE.fullmatch("[EMPLOYEE_ID_12]") and not PLACEHOLDER_RE.fullmatch("[NOT_A_TYPE_1]")


def test_response_scanning_and_the_lab_know_the_name() -> None:
    p = pipe(EMPLOYEE)
    texts, found = p.redact_deterministic_sync(["your badge is EMP-123456"])
    assert texts == ["your badge is [EMPLOYEE_ID]"] and found == {"EMPLOYEE_ID": 1}
    lab = lab_run(p, "badge EMP-123456")
    custom = next(layer for layer in lab["layers"] if layer["id"] == "custom")
    assert [s["type"] for s in custom["spans"]] == ["EMPLOYEE_ID"] and lab["final"]["findings"][0][
        "type"
    ] == "EMPLOYEE_ID"


def test_through_the_proxy_with_reasons_and_counts(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(detection={"ner": {"enabled": False}, "custom_types": [EMPLOYEE, PROJECT]})
    r = client.post("/v1/chat/completions", headers=AUTH, json=chat("badge EMP-123456 for jane@corp.example"))
    assert r.status_code == 200 and "badge [EMPLOYEE_ID_1] for [EMAIL_1]" in spy.bodies[-1].decode()
    blocked = client.post("/v1/chat/completions", headers=AUTH, json=chat("about Project Bluefin"))
    assert blocked.status_code == 403 and blocked.json()["error"]["harpo"]["blocked_types"] == ["PROJECT"]
    policy = client.get("/v1/policy", headers=AUTH).json()["custom_types"]
    assert [(c["name"], c["action"], c["terms"], c["patterns"]) for c in policy] == [
        ("EMPLOYEE_ID", "redact", 0, 1),
        ("PROJECT", "block", 2, 0),
    ]
    assert "Bluefin" not in str(policy) and "EMP-" not in str(policy)


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ({"name": "employee_id", "terms": ["x1"]}, "should match pattern"),
        ({"name": "EMAIL", "terms": ["x1"]}, "built-in type"),
        ({"name": "EMAIL_ID", "terms": ["x1"]}, "would read as EMAIL"),
        ({"name": "PERSON_7", "terms": ["x1"]}, "would read as PERSON"),
        ({"name": "NOTHING"}, "at least one term or pattern"),
        ({"name": "LOOK", "patterns": ["(?<=a)b"]}, "not a valid RE2 expression"),
        ({"name": "EMPTY", "patterns": ["x*"]}, "matches the empty string"),
        ({"name": "SHORT", "terms": ["x"]}, "2 to 200 characters"),
        ({"name": "PRIVATE", "terms": ["x1"]}, "could read as PRIVATE_KEY"),  # its letter labels reach KEY
        ({"name": "US", "terms": ["x1"]}, "could read as US_"),
        ({"name": "DASHES", "terms": ["- - -"]}, "needs a letter or digit"),
    ],
)
def test_bad_custom_types_are_refused_with_a_reason(spec: dict, message: str) -> None:  # type: ignore[type-arg]
    with pytest.raises(ValidationError, match=re.escape(message)):
        make_settings(detection={"custom_types": [spec]})


def test_names_must_be_unique_and_must_not_shadow_each_other() -> None:
    with pytest.raises(ValidationError, match="must be unique"):
        make_settings(detection={"custom_types": [EMPLOYEE, EMPLOYEE]})
    with pytest.raises(ValidationError, match="read as CASE"):  # CASE_ID reads as CASE's, CASE can print [CASE_ID]
        make_settings(
            detection={"custom_types": [{"name": "CASE", "terms": ["c1"]}, {"name": "CASE_ID", "terms": ["c2"]}]}
        )
    assert make_settings(detection={"custom_types": [{"name": "EMAIL_DOMAIN", "terms": ["corp.example"]}]})


def test_the_prefix_tree_matches_exactly_like_the_plain_alternation() -> None:
    words = [
        "alpha",
        "alp",
        "beta",
        "project bluefin",
        "Project Bluefin Alpha",
        "x-ray",
        "c3po",
        "ab",
        "abc",
        "bluefin",
    ]
    plain = re.compile(
        r"(?<!\w)(?:" + "|".join(_term_pattern(t) for t in sorted(set(words), key=len, reverse=True)) + r")(?!\w)",
        re.IGNORECASE,
    )
    tree = terms_regex(words)
    assert tree is not None
    pool = [
        *words,
        "Alpha",
        "ALP",
        "project_bluefin",
        "project-bluefin",
        "projectbluefin",
        "betas",
        "xray",
        "\n",
        ".",
        "abc_d",
    ]
    rnd = random.Random(11)
    for _ in range(3000):
        text = " ".join(rnd.choice(pool) for _ in range(rnd.randint(1, 8)))
        assert [m.span() for m in tree.finditer(text)] == [m.span() for m in plain.finditer(text)], text


def test_thousands_of_terms_stay_fast() -> None:
    import time

    terms = [f"codename{i:05d}" for i in range(5000)]
    p = pipe({"name": "CODENAME", "terms": terms})
    text = ("lorem ipsum dolor " * 2000) + "codename04711"
    started = time.perf_counter()
    out = p.scan_sync([text])
    assert out.texts[0].endswith("[CODENAME_1]") and time.perf_counter() - started < 5


def test_a_term_of_separators_cannot_make_the_scan_slow() -> None:
    """Terms were compiled with backtracking: "- - - ... z" took 12 s on a line of dashes. A term's parts are its
    letters and digits now, with at most three separators between them, so any term is linear."""
    import time

    p = pipe({"name": "DASHY", "terms": ["- - - - - - - - - - - - z", "a - - - - - - - - - - - b"]})
    started = time.process_time()  # CPU time: a busy machine must not look like a slow scan
    out = p.scan_sync(["-" * 60 + "!", "a" + "-" * 60 + "!", "z and a-b"])
    assert time.process_time() - started < 2
    assert out.texts == ["-" * 60 + "!", "a" + "-" * 60 + "!", "[DASHY_1] and [DASHY_2]"]
