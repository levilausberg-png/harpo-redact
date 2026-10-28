"""Hostile and unusual input: catastrophic backtracking, obfuscation, look-alikes, prose, odd Unicode."""

from __future__ import annotations

import base64
import re
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from harpo_redact import normalize, pipeline, proxy, redactor
from harpo_redact.detectors import fields, identifiers, names, opaque, patterns, secret_library, secrets, views
from harpo_redact.entities import EntityType as E

MODULES = [
    patterns,
    identifiers,
    secrets,
    names,
    normalize,
    redactor,
    proxy,
    pipeline,
    views,
    fields,
    secret_library,
    opaque,
]


def all_regexes() -> Iterator[tuple[str, re.Pattern[str]]]:
    for mod in MODULES:
        for name, value in vars(mod).items():
            if isinstance(value, re.Pattern):
                yield f"{mod.__name__}.{name}", value
            elif isinstance(value, (tuple, list)) and value and all(isinstance(v, re.Pattern) for v in value):
                for i, v in enumerate(value):
                    yield f"{mod.__name__}.{name}[{i}]", v
    for scheme in identifiers._SCHEMES:
        yield f"scheme {scheme.module}", scheme.pattern


K = 6_000
HOSTILE = [
    "a" * K, "1" * K, "1 " * K, "a@" * K, "a." * K, "a-" * K, "A1" * K, "@." * K, "+1 " * K, "x" * K + "@",
    "1-" * K, "1." * K, "Aa " * K, "\t" * K, "%41" * K, "&#64;" * K, "9" * K + "x", "ÿ" * K, "a1-" * K,
    "Street " * K, "1 Main " * K, "Mr " * K, "ab_" * K, "=" * K, "/" * K, "a/" * K, "0x" + "a" * K,
    "eyJ" + "a" * K, "sk-" + "a" * K, "-----BEGIN PRIVATE KEY-----" + "A" * K, "password is " * K, "a b " * K,
    # Cue gaps, tables, markup, spaced runs and hex dumps (the redaction matrix hardening)
    "date of birth " * K, "born on " * K, "passport number is " * K, "account " * K, "passport (" * K,
    "<td>" * K, "<tr><td>a</td>" * K, "</td>" * K, "| a " * K, "a,\n" * K, "\"a\": " * K, "a  " * K,
    "ab " * K, "ab:" * K, "0x" + "ab" * K, "insurance " * K, "_" * K, "a_b " * K, "\\\"" * K,
]  # fmt: skip


def _cpu_time(regex: re.Pattern[str], text: str) -> float:
    started = time.process_time()
    for _ in regex.finditer(text):
        pass
    return time.process_time() - started


@pytest.mark.parametrize(("name", "regex"), list(all_regexes()), ids=lambda v: v if isinstance(v, str) else "")
def test_no_regex_backtracks_catastrophically(name: str, regex: re.Pattern[str]) -> None:
    worst = 0.0
    for text in HOSTILE:
        # CPU time, best of two: a machine that stalls for half a second must not look like a ReDoS.
        worst = max(worst, min(_cpu_time(regex, text), _cpu_time(regex, text)))
    assert worst < 0.5, f"{name} took {worst:.2f}s of CPU on hostile input"


UNITS = [
    "a", "1", "1 ", "a@", "a.", "a-", "A1", "@.", "+1 ", "1-", "1.", "Aa ", " ", "%41", "&#64;", "9", "ÿ", "a1-", "Street ",
    "1 Main ", "Mr ", "ab_", "=", "/", "a/", "a b ", "a:", "a=", "-", "0x", "ab", "1 2 ", "x.y@", "a.b.", "\n", ",", "\u200b",
]  # fmt: skip
FRAMES = [
    ("", ""),
    ("x", "@"),
    ("0x", ""),
    ("sk-", ""),
    ("eyJ", ""),
    ("password is ", ""),
    ("bearer ", ""),
    ("http://", ""),
]


def _slowest(regex: re.Pattern[str], text: str) -> float:
    best = 9.0
    for _ in range(2):
        started = time.perf_counter()
        for _m in regex.finditer(text):
            pass
        best = min(best, time.perf_counter() - started)
    return best


def _cpu_time(regex: re.Pattern[str], text: str) -> float:
    started = time.process_time()
    for _ in regex.finditer(text):
        pass
    return time.process_time() - started


@pytest.mark.parametrize(("name", "regex"), list(all_regexes()), ids=lambda v: v if isinstance(v, str) else "")
def test_regex_time_grows_linearly_with_input(name: str, regex: re.Pattern[str]) -> None:
    """Quadratic patterns hide below an absolute limit on small input; the growth ratio exposes them.

    Four times the input should cost about four times the time. Sixteen times is quadratic.
    """
    offenders = []
    for unit in UNITS:
        for prefix, suffix in FRAMES:
            small = prefix + unit * 1_500 + suffix
            large = prefix + unit * 6_000 + suffix
            t_small, t_large = _slowest(regex, small), _slowest(regex, large)
            if t_large > 0.05 and t_large / max(t_small, 1e-4) > 9:
                offenders.append((unit, prefix, round(t_small, 3), round(t_large, 3)))
    assert offenders == [], f"{name} grows faster than linearly: {offenders[:3]}"


def test_pipeline_time_grows_linearly_with_input(make_pipeline) -> None:  # type: ignore[no-untyped-def]
    p = make_pipeline(detection={"ner": {"enabled": False}})
    offenders = []
    for unit in UNITS:
        small, large = unit * 3_000, unit * 12_000
        t0 = time.perf_counter()
        p.scan_sync([small])
        t1 = time.perf_counter()
        p.scan_sync([large])
        t2 = time.perf_counter()
        if (t2 - t1) > 0.4 and (t2 - t1) / max(t1 - t0, 1e-3) > 9:
            offenders.append((unit, round(t1 - t0, 3), round(t2 - t1, 3)))
    assert offenders == []


def test_whole_deterministic_pipeline_stays_fast_on_hostile_input(make_pipeline) -> None:  # type: ignore[no-untyped-def]
    p = make_pipeline(detection={"ner": {"enabled": False}})
    for text in HOSTILE:
        started = time.perf_counter()
        p.scan_sync([text])
        assert time.perf_counter() - started < 5.0, text[:20]


def test_lone_surrogates_do_not_crash(make_pipeline) -> None:  # type: ignore[no-untyped-def]
    p = make_pipeline(detection={"ner": {"enabled": False}})
    out = p.scan_sync(["mail jane@example.com \ud800 and \udfff end", "\\ud83d escaped"]).texts
    assert "[EMAIL_1]" in out[0] and "\ud800" not in out[0]


# --------------------------------------------------------------------------- obfuscation
CARD = "4111111111111111"
OBFUSCATED = [
    ("Card ４１１１ １１１１ １１１１ １１１１ thanks", E.CREDIT_CARD),
    ("Card ٤١١١١١١١١١١١١١١١ thanks", E.CREDIT_CARD),
    ("Card 4111.1111.1111.1111 thanks", E.CREDIT_CARD),
    ("Card 4111\u200b1111\u200b1111\u200b1111 thanks", E.CREDIT_CARD),
    ("Mail ja\u200bne@exa\u200bmple.com now", E.EMAIL),
    ("Mail jаne@example.com now", E.EMAIL),
    ("Mail jane%40example.com now", E.EMAIL),
    ("Mail jane%2540example.com now", E.EMAIL),
    ("Mail jane&#64;example.com now", E.EMAIL),
    ("Mail jane&commat;example.com now", E.EMAIL),
    ('{"to": "jane\\u0040example.com"}', E.EMAIL),
    ("Mail jane [at] example [dot] com now", E.EMAIL),
    ("Mail JANE.DOE@EXAMPLE.COM now", E.EMAIL),
    ("IBAN nl91abna0417164300 please", E.IBAN),
    ("IBAN NL91-ABNA-0417-1643-00 please", E.IBAN),
    ("Call +31 (0)20 794 6095 today", E.PHONE),
    ("SSN 123 45 6789 on file", E.US_SSN),
    ("NINO ab 12 34 56 c on file", E.UK_NINO),
    ("ghp_\u200bR8xvT2mQ9wLk4ZpN7yHc3BdF6sJa1EuG5oVi", E.SECRET),
    ("payload " + base64.b64encode(b"contact jane.doe@example.com").decode() + " end", E.ENCODED_DATA),
]


@pytest.mark.parametrize(("text", "etype"), OBFUSCATED)
def test_obfuscated_values_are_still_redacted(make_pipeline, text: str, etype: E) -> None:  # type: ignore[no-untyped-def]
    out = make_pipeline(detection={"ner": {"enabled": False}}).scan_sync([text]).texts[0]
    assert f"[{etype.value}_1]" in out, out


# --------------------------------------------------------------------------- look-alikes
HIGH_RISK = {
    E.CREDIT_CARD, E.IBAN, E.US_SSN, E.NL_BSN, E.UK_NINO, E.NATIONAL_ID, E.ID_DOCUMENT, E.ACCOUNT_ID,
    E.CRYPTO_ADDRESS, E.DEVICE_ID, E.SECRET, E.PRIVATE_KEY, E.ENCODED_DATA, E.PHONE, E.EMAIL,
}  # fmt: skip
LOOKALIKES = [
    "Request id 550e8400-e29b-41d4-a716-446655440000 failed.",
    "Fixed in commit e83c5163316f89bfbde7d9ab23ca2e25604af290 yesterday.",
    "sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "ISBN 978-3-16-148410-0 and 9780306406157 are both in stock.",
    "EAN 4006381333931 scanned at the till.",
    "UPS 1Z999AA10123456784, FedEx 449044304137821, USPS 9400111899223197428490.",
    "Epoch 1727875200000 equals 2026-10-02T09:12:00Z.",
    "Prices: €1.299,00 and $12,345.67 and 1,000,000 units.",
    "Windows build 10.0.19045.3693 and version v2.10.3 shipped.",
    "See CVE-2024-3094, RFC 9110, ISO 27001 and Art. 9(2)(a) GDPR.",
    "Invoice INV-2026-000123 for order #100045678, SKU-88213-XL.",
    "Coordinates 52.3676 N, 4.9041 E; colour #1A2B3C; margin: 0 auto;",
    "The account is closed and the passport photo was rejected.",
    "Model number 1234567890123 and part 9876543210987.",
    "password = os.environ['DB_PASSWORD']  # read at runtime",
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
    "kubectl get pods -n kube-system -o wide --field-selector status.phase=Running",
    "Temperature 36.6 C, pressure 1013 hPa, 120/80 mmHg.",
    "Room 1204, floor 12, building 3; ext 4021.",
]


@pytest.mark.parametrize("text", LOOKALIKES)
def test_lookalikes_are_not_flagged(make_pipeline, text: str) -> None:  # type: ignore[no-untyped-def]
    outcome = make_pipeline(detection={"ner": {"enabled": False}}).scan_sync([text])
    flagged = {k: v for k, v in outcome.counts.items() if E(k) in HIGH_RISK}
    assert flagged == {}, outcome.texts[0]


def test_public_domain_prose_has_no_false_positives(make_pipeline) -> None:  # type: ignore[no-untyped-def]
    text = (Path(__file__).parent / "data" / "prose_sample.txt").read_text()
    chunks = [text[i : i + 8000] for i in range(0, len(text), 8000)]
    outcome = make_pipeline(detection={"ner": {"enabled": False}}).scan_sync(chunks)
    flagged = {k: v for k, v in outcome.counts.items() if E(k) in HIGH_RISK}
    assert len(text) > 250_000
    assert flagged == {}


# --------------------------------------------------------------------------- fuzzing
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

SEEDED = [
    "jane.doe@example.com",
    "4111 1111 1111 1111",
    "5500-0000-0000-0004",
    "3782 822463 10005",
    "NL91ABNA0417164300",
    "NL91 ABNA 0417 1643 00",
    "123-45-6789",
    "AB 12 34 56 C",
    "+31 20 794 6095",
    "0x52908400098527886E0F7030069857D2E4169EE7",
    "ghp_R8xvT2mQ9wLk4ZpN7yHc3BdF6sJa1EuG5oVi",
]
_NOISE = st.text(alphabet=st.characters(blacklist_categories=("Cs",), max_codepoint=0x2FFFF), max_size=300)


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(before=_NOISE, between=_NOISE, after=_NOISE, picks=st.lists(st.sampled_from(SEEDED), min_size=1, max_size=4))
def test_fuzz_seeded_values_never_survive_and_output_is_stable(pipeline_cache, before, between, after, picks) -> None:  # type: ignore[no-untyped-def]
    text = before + " " + (" " + between + " ").join(picks) + " " + after
    first = pipeline_cache.scan_sync([text])
    for value in picks:
        assert value not in first.texts[0]
    for finding in first.findings[0]:
        assert finding.start is None or 0 <= finding.start < finding.end <= len(text)
    second = pipeline_cache.scan_sync([first.texts[0]])
    risky = {k: v for k, v in second.counts.items() if E(k) in HIGH_RISK}
    assert risky == {}, (text, first.texts[0])


@pytest.fixture(scope="module")
def pipeline_cache():  # type: ignore[no-untyped-def]
    from harpo_redact.config import Settings
    from harpo_redact.pipeline import Pipeline

    return Pipeline(Settings(environment="development", detection={"ner": {"enabled": False}}))


def test_adjacent_card_numbers_are_both_found() -> None:
    """Found by the fuzzer: a stray digit group between two cards used to swallow the second one."""
    text = " 4111 1111 1111 1111 0 4111 1111 1111 1111 "
    spans = [s for s in patterns.find_cards(text) if s.type is E.CREDIT_CARD]
    assert [text[s.start : s.end] for s in spans] == ["4111 1111 1111 1111"] * 2
    assert list(patterns.find_cards("1 " * 6000)) == [] and list(patterns.find_cards("4 " * 6000)) == []
