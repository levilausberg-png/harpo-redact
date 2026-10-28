"""Normalisation offsets and rule-based name cues."""

from __future__ import annotations

import pytest

from harpo_redact.detectors.names import find_name_cues
from harpo_redact.normalize import normalize


def test_unchanged_text_maps_identically() -> None:
    n = normalize("plain text")
    assert n.text == "plain text" and n.to_original(0, 5) == (0, 5)


def test_zero_width_characters_are_removed_and_counted() -> None:
    original = "j\u200bohn@example.com"
    n = normalize(original)
    assert n.text == "john@example.com"
    assert n.removed_format_chars == 1
    assert n.to_original(0, len(n.text)) == (0, len(original))


def test_full_width_digits_fold_to_ascii() -> None:
    n = normalize("\uff14\uff11\uff15")
    assert n.text == "415"
    assert n.to_original(0, 3) == (0, 3)


def test_mixed_script_tokens_are_counted() -> None:
    assert normalize("K\u0430zan").mixed_script_tokens == 1  # Cyrillic a inside a Latin word
    assert normalize("Kazan").mixed_script_tokens == 0


def names(text: str) -> list[str]:
    return [text[s.start : s.end] for s in find_name_cues(text)]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Write to Jan de Vries.", ["Jan de Vries"]),
        ("Email Anna about the refund.", ["Anna"]),
        ("Please draft a reply to Sophie Martin.", ["Sophie Martin"]),
        ("Dear Anna's team", ["Anna"]),
        ("Kind regards,\nLars Eriksen", ["Lars Eriksen"]),
        ("From: Lars Eriksen <lars@example.com>", ["Lars Eriksen"]),
        ("Name: Anna Jansen\nPatient: Emily Watson", ["Anna Jansen", "Emily Watson"]),
        ("Hi, I'm Priya Raman, ops lead.", ["Priya Raman"]),
        ("Dr. Emily Watson met Mrs Jansen.", ["Emily Watson", "Jansen"]),
        ("Meet with Ana dos Santos on Friday.", ["Ana dos Santos"]),
        ("Hi team, email Anna about it.", ["Anna"]),
    ],
)
def test_name_cues_find_names(text: str, expected: list[str]) -> None:
    assert names(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "email support about it",
        "Contact Support about the outage.",
        "Thanks for the update, see you Monday.",
        "Best practices for Python logging.",
        "Please draft a note to the drafting team.",
        "Thanks, Let's go.",
    ],
)
def test_name_cues_ignore_non_names(text: str) -> None:
    assert names(text) == []
