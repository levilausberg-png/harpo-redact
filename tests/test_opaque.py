"""Opaque codes: values that no language writes (detectors/opaque.py), and the cue rules that use the same test."""

from __future__ import annotations

import pytest

from harpo_redact.detectors.cued import find_cued_values
from harpo_redact.detectors.opaque import find_opaque_codes, opacity, opaque_capitals, random_letters
from harpo_redact.detectors.statements import find_statements
from harpo_redact.entities import EntityType as E

GENERATED_CAPITALS = ["FXJPIUZXKH", "MKWBOOYWMV", "QWWNIDFGQE", "BOWCBXSUKO", "H5U8VOVWPQ", "NBHOZG6SG6"]
# Words, names and places in capitals, in the languages Harpo reads; constants; hashes, masks and test strings.
NOT_CODES = [
    "CONFIDENTIAL", "VERTROUWELIJK", "WACHTWOORD", "PERSONALAUSWEIS", "RIJBEWIJS", "IDENTITEITSKAART", "AMSTERDAM",
    "MAASTRICHT", "SCHWARZENEGGER", "KOWALCZYK", "SZCZEPANSKI", "WOJCIECHOWSKI", "KRZYSZTOF", "NGUYEN", "XIAOMING",
    "CHONGQING", "MASSACHUSETTS", "PHILADELPHIA", "ALBUQUERQUE", "ECONNREFUSED", "NVARCHAR", "DOCKERFILE",
    "DEADBEEF01", "ABCDEFGHIJ", "XXXXXXXXXX", "QWERTYUIOP",
]  # fmt: skip
GENERATED_LETTERS = ["BfnMnQaGjPdc", "SapvTxMwDwTV", "sTeKsMKvJMcU", "tqoCmDcgjGqo", "mBUGaVqQYtGM"]
IDENTIFIERS = [
    "getElementById", "XMLHttpRequest", "PostgreSQL", "McDonald", "addEventListener", "kCFBooleanTrue",
    "UITableViewController", "GlaxoSmithKline", "DuckDuckGo", "innerHTML", "HbA1cLevel", "kWhPerDay", "JavaScript",
]  # fmt: skip


@pytest.mark.parametrize("value", GENERATED_CAPITALS)
def test_generated_capitals_are_opaque(value: str) -> None:
    assert opaque_capitals(value)


@pytest.mark.parametrize("value", NOT_CODES)
def test_words_names_and_masks_in_capitals_are_not(value: str) -> None:
    assert not opaque_capitals(value)


@pytest.mark.parametrize("value", GENERATED_LETTERS)
def test_generated_letters_are_random(value: str) -> None:
    assert random_letters(value)


@pytest.mark.parametrize("value", IDENTIFIERS)
def test_identifiers_of_code_and_brands_are_not(value: str) -> None:
    assert not random_letters(value)
    assert not random_letters(value, cued=True)  # not even right after a password word
    assert opacity(value) <= 3


def _found(text: str) -> list[tuple[str, E]]:
    return [(text[s.start : s.end], s.type) for s in find_opaque_codes(text)]


def test_a_code_in_a_sentence_is_found() -> None:
    assert _found("Please bring your MKWBOOYWMV and the signed form.") == [("MKWBOOYWMV", E.ACCOUNT_ID)]
    assert _found("Veuillez réinitialiser votre tqoCmDcgjGqo en suivant le lien.") == [("tqoCmDcgjGqo", E.SECRET)]


def test_a_code_glued_to_chinese_japanese_or_korean_is_found() -> None:
    # These scripts put no blank before Latin letters, and a sentence in them has no small letters to show it is one.
    assert _found("到达东城区后,请携带有效的FXJPIUZXKH办理手续。") == [("FXJPIUZXKH", E.ACCOUNT_ID)]
    assert _found("予約の際はMKWBOOYWMVをご提示ください。") == [("MKWBOOYWMV", E.ACCOUNT_ID)]
    assert _found("고객님의 코드 QWWNIDFGQE 를 입력하세요") == [("QWWNIDFGQE", E.ACCOUNT_ID)]
    assert _found("我们在Instagram和PostgreSQL上使用JavaScript") == []  # words and brands, glued or not
    assert _found("路径/api/FXJPIUZXKH/items是接口") == []  # part of a path


def test_codes_in_headings_paths_and_identifiers_are_left() -> None:
    assert _found("URGENT NOTICE FXJPIUZXKH") == []  # a line in capitals: a heading or a constant
    assert _found("see https://example.com/api/FXJPIUZXKH/items for the list") == []
    assert _found("the user_FXJPIUZXKH record and FXJPIUZXKH.json are here") == []
    assert _found("the payload was dGhpcyBpcyBhIHRlc3Q+YQ== in base64") == []


def _statements(text: str) -> list[str]:
    return [text[a:b] for a, b, _ in find_statements(text)]


def test_random_letters_after_a_password_word() -> None:
    assert "DVSqTIIxXPUq" in _statements("Personal Loan Account and password DVSqTIIxXPUq for joining the course")
    assert "BfnMnQaGjPdc" in _statements("Passwort möglicherweise 15/01/1990 und BfnMnQaGjPdc für unsere Kurse")
    found = _statements("We found leaked passwords, including SwiHUSxCiN3I and hYzsNGBVkghS. Rotate them.")
    assert "hYzsNGBVkghS" in found


def test_a_password_word_does_not_make_a_name_a_password() -> None:
    assert _statements("Enter the password for PostgreSQL or the password reset page") == []
    assert _statements("The password policy changed. FXJPIUZXKH is the next ticket.") == []  # another sentence


def _cued(text: str) -> list[str]:
    return [text[s.start : s.end] for s in find_cued_values(text)]


def test_a_code_in_capitals_after_its_cue() -> None:
    assert _cued("linked to my driver's license number CLYAFCWFNSIMY and the card") == ["CLYAFCWFNSIMY"]
    assert _cued("a copy of your driver's licence (KAMER 791150 K9 342) for verification") == ["KAMER 791150 K9 342"]
    assert _cued("driver's licence BAJRU 941162 B9 449, please") == ["BAJRU 941162 B9 449"]
    assert _cued("driver's license number REQUIRED before the trip") == []
    assert _cued("passport number PENDING, see below") == []
