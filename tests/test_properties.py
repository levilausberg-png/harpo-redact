"""Property tests: seeded identifiers never survive, and redaction is idempotent."""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from harpo_redact.config import Settings
from harpo_redact.pipeline import Pipeline

# Deterministic layers only: properties must hold without any model.
PIPE = Pipeline(Settings(environment="development", detection={"ner": {"enabled": False}}))

FILLER = st.lists(
    st.sampled_from(["please", "check", "the", "order", "status", "for", "today", "and", "reply", "soon", ",", "."]),
    min_size=0,
    max_size=8,
).map(" ".join)


def _luhn_complete(prefix: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(prefix)):
        d = int(ch)
        if i % 2 == 0:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return prefix + str((10 - total % 10) % 10)


emails = st.builds(
    lambda user, domain: f"{user}@{domain}.example",
    st.from_regex(r"[a-z]{2,8}(\.[a-z]{2,8})?", fullmatch=True),
    st.from_regex(r"[a-z]{3,10}", fullmatch=True),
)
cards = st.from_regex(r"4[0-9]{14}", fullmatch=True).map(_luhn_complete)
spaced_cards = cards.map(lambda c: " ".join(c[i : i + 4] for i in range(0, 16, 4)))
nl_phones = st.integers(min_value=1000000, max_value=9999999).map(lambda n: f"+31 20 {str(n)[:3]} {str(n)[3:]}")


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(before=FILLER, after=FILLER, email=emails, card=st.one_of(cards, spaced_cards), phone=nl_phones)
def test_seeded_values_never_reach_the_output(before: str, after: str, email: str, card: str, phone: str) -> None:
    text = f"{before} mail {email} card {card} call {phone} {after}"
    out = PIPE.scan_sync([text]).texts[0]
    digits = "".join(c for c in out if c.isdigit())
    assert email not in out
    assert card.replace(" ", "") not in digits
    assert phone.replace(" ", "").lstrip("+") not in digits


@settings(max_examples=100, deadline=None)
@given(before=FILLER, email=emails, card=cards)
def test_redaction_is_idempotent(before: str, email: str, card: str) -> None:
    once = PIPE.scan_sync([f"{before} {email} {card}"]).texts
    assert PIPE.scan_sync(once).texts == once


@settings(max_examples=100, deadline=None)
@given(text=st.text(max_size=300))
def test_any_text_is_handled_and_offsets_are_valid(text: str) -> None:
    out = PIPE.scan_sync([text])
    for finding in out.findings[0]:
        if finding.start is not None:
            assert 0 <= finding.start < finding.end <= len(text)
