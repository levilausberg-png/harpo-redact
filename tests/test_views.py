"""Shadow views and multilingual NER: the fixes LeakBench pointed at, each with its benign look-alike."""

from __future__ import annotations

import base64
import importlib.util

import pytest

from harpo_redact.detectors.language import detect_language
from harpo_redact.detectors.ner import case_view
from harpo_redact.normalize import normalize

from .conftest import needs

FAST = {"ner": {"enabled": False}}


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Card 4111 1111\n 1111 1111 on file.", "Card [CREDIT_CARD_1] on file."),
        ("IBAN NL91ABNA04\n17164300 please.", "IBAN [IBAN_1] please."),
        ("Call +31 6 1\n234 5678 now.", "Call [PHONE_1] now."),
        ("token ghp_8c2Kd9QeLm4Rz7Tb1Nf\n6Hs3Wv5Xy0Ua2Pi8Ok today", "token [SECRET_1] today"),
        ("BSN one two three four five six seven eight two", "BSN [NL_BSN_1]"),
        ("BSN een twee drie vier vijf zes zeven acht twee", "BSN [NL_BSN_1]"),
        (
            "Karte vier eins eins eins eins eins eins eins eins eins eins eins eins eins eins eins.",
            "Karte [CREDIT_CARD_1].",
        ),
        ("IBAN N L 9 1 A B N A 0 4 1 7 1 6 4 3 0 0", "IBAN [IBAN_1]"),
        ("Mail j4n3.d03@3x4mpl3.c0m today", "Mail [EMAIL_1] today"),
        ("BSN " + base64.b64encode(b"111222333").decode(), "BSN [ENCODED_DATA_1]"),
        ("SSN " + base64.b64encode(b"123-45-6789").decode() + " noted", "SSN [ENCODED_DATA_1] noted"),
        ("Write to jаne.dое@example.com", "Write to [EMAIL_1]"),  # Cyrillic а and о
    ],
)
def test_attacks_are_read_through(make_pipeline, text: str, expected: str) -> None:  # type: ignore[no-untyped-def]
    assert make_pipeline(detection=FAST).scan_sync([text]).texts == [expected]


@pytest.mark.parametrize(
    "text",
    [
        "Regards and thanks,\nthe team\n\nThe meeting is at 10\n30 people attend.",
        "Call 020\n7946095 is two lines of figures, not one number.",  # national numbers are not rejoined
        "Count one two three four five six seven and stop.",
        "The letters a b c d e f g h are on the board.",
        "We use JavaScript and PowerPoint at McDonald's.",
        "Привет, как дела? Это обычный русский текст.",
        "Order 12345\n67890 shipped.",
    ],
)
def test_look_alikes_stay_readable(make_pipeline, text: str) -> None:  # type: ignore[no-untyped-def]
    assert make_pipeline(detection=FAST).scan_sync([text]).texts == [text]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("お支払いは4111111111111111でお願いします", "お支払いは[CREDIT_CARD_1]でお願いします"),
        ("请联系jane.doe@corp.example获取资料", "请联系[EMAIL_1]获取资料"),
        ("전화번호 +82 10-1234-5678으로 연락하세요", "전화번호 [PHONE_1]으로 연락하세요"),
        ("電話は03 1234 5678までお願いします", "電話は[PHONE_1]までお願いします"),  # a number in groups is one run
        ("合計 12 345 678円です。人口は 1 234 567人です", "合計 12 345 678円です。人口は 1 234 567人です"),
    ],
)
def test_values_glued_to_chinese_japanese_and_korean_are_read(make_pipeline, text: str, expected: str) -> None:  # type: ignore[no-untyped-def]
    assert make_pipeline(detection=FAST).scan_sync([text]).texts == [expected]


def test_dates_glued_to_the_script_open_no_spacing_window_unless_dates_are_redacted() -> None:
    from harpo_redact.detectors.views import script_spacing_view

    text = "회의는 26/11/1937에 시작했고 会議は2024-03-14T09:30:00に始まります"
    assert script_spacing_view(text) is None  # dates are words of the text when the policy lets them through
    spaced = script_spacing_view(text, dates=True)
    assert spaced is not None and "26/11/1937 에" in spaced.text
    assert script_spacing_view("전화 09012345678으로") is not None  # a number still gets its blank


def test_confusables_fold_only_inside_mixed_words() -> None:
    assert normalize("jаne").text == "jane" and normalize("Привет мир").text == "Привет мир"


def test_case_view_titles_names_in_running_text_but_not_headings() -> None:
    assert case_view("please call EMILY THOMPSON today") == "please call Emily Thompson today"
    assert case_view("QUARTERLY REPORT\nbody text") == "QUARTERLY REPORT\nbody text"
    assert len(case_view("ask JÜRGEN MÜLLER now")) == len("ask JÜRGEN MÜLLER now")


@pytest.mark.parametrize(
    ("text", "lang"),
    [
        ("Hi Bob, can you check the report for me?", "en"),
        ("Wil je Sanne vragen het dossier te controleren? Bedankt voor het rapport.", "nl"),
        ("Bitte Lukas bitten, die Akte zu prüfen. Danke für den Bericht.", "de"),
        ("Merci de demander à Théo de vérifier le dossier.", "fr"),
        ("Pide a Lucía que revise el expediente. Gracias por el informe.", "es"),
        ("Hi", "und"),
        ("jane@example.com", "und"),
        ("Привет, как дела? Это обычный русский текст.", "xx"),
    ],
)
def test_language_detection(text: str, lang: str) -> None:
    assert detect_language(text) == lang


@pytest.fixture
def _language_models() -> None:
    if not all(importlib.util.find_spec(m) for m in ("nl_core_news_sm", "de_core_news_sm")):
        needs("models", "language models not installed")


needs_models = pytest.mark.usefixtures("_language_models")


@needs_models
def test_language_models_stop_english_ner_from_reading_german_nouns(make_pipeline) -> None:  # type: ignore[no-untyped-def]
    text = "Bitte Lukas Becker bitten, die Akte zu prüfen. Danke für den Bericht."
    english = make_pipeline(detection={"ner": {"other_languages": "english", "cache_entries": 0}}).scan_sync([text])
    routed = make_pipeline(
        detection={"ner": {"language_models": {"de": "de_core_news_sm"}, "cache_entries": 0}}
    ).scan_sync([text])
    # The problem being fixed: the English model reads German words as names ("Danke", "Akte", "Bericht").
    assert "die Akte zu prüfen" not in english.texts[0] or "Danke für den Bericht" not in english.texts[0]
    assert "die Akte zu prüfen" in routed.texts[0] and "Danke für den Bericht" in routed.texts[0]
    assert "Lukas Becker" not in routed.texts[0]


@needs_models
def test_skip_mode_runs_no_ner_on_languages_without_a_model(make_pipeline) -> None:  # type: ignore[no-untyped-def]
    text = "Wil je Sanne Bakker vragen het dossier te controleren? Bedankt voor het rapport."
    out = make_pipeline(detection={"ner": {"other_languages": "skip", "cache_entries": 0}}).scan_sync([text])
    assert out.texts == [text]


def test_codes_are_not_names(make_pipeline) -> None:  # type: ignore[no-untyped-def]
    out = make_pipeline().scan_sync(
        ["Please restock SKU-88213-XL and check invoice INV-2026-000123 for Emily Thompson."]
    )
    assert "SKU-88213-XL" in out.texts[0] and "INV-2026-000123" in out.texts[0] and "Emily Thompson" not in out.texts[0]


def test_a_line_break_after_a_complete_value_is_a_real_break(make_pipeline) -> None:  # type: ignore[no-untyped-def]
    """Found by the document suite: "...@corp.example\\nfiller" was read as one longer email."""
    text = "reach me at priya.raman@corp.example\nfiller words follow"
    assert make_pipeline(detection=FAST).scan_sync([text]).texts == ["reach me at [EMAIL_1]\nfiller words follow"]
