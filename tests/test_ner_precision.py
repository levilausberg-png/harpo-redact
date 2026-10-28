"""The NER model's precision filter (detectors/ner.py): what a small model tags that cannot be a name is dropped,
and what a person hides by writing it oddly (in lower case, in leetspeak) is kept.

The model-free tests call the rules directly. The model tests run the configuration the Docker image ships (English,
German and the multilingual model), on phrasings of our own.
"""

from __future__ import annotations

from typing import Any

import pytest

from harpo_redact.api import load_ner
from harpo_redact.config import Settings
from harpo_redact.detectors.ner import (
    _capitalised_sentences,
    _leetspeak,
    _sentence_initial,
    _sentence_opening,
    case_view,
    instruction_verb,
    lowercase_words,
    plausible_entity,
    software_ranges,
)
from harpo_redact.entities import EntityType as E

NONE: frozenset[str] = frozenset()


# --------------------------------------------------------------------------- the rules, without a model
@pytest.mark.parametrize(
    ("surface", "line", "kind"),
    [
        ("Monday", "We meet on Monday at nine", "person"),  # a word of the vocabulary
        ("UTC", "The job runs at 10:00 UTC every day", "org"),  # an acronym in a line of mixed case
        ("MEDCONFAC", "Send the forms to MEDCONFAC before Friday", "org"),  # one word of capitals, an abbreviation
        ("HPV4", "We ordered HPV4 for the clinic", "org"),  # an organisation holds no digits
        ("DatabaseDSN", "set DatabaseDSN in the config", "person"),  # an identifier in code
        ("IPTABLES", "IPTABLES DROP IN=eth0 OUT= PROTO=TCP SPT=443", "org"),  # a line of settings
        ("MRK", "CRS CODE    TITLE      WGT   MRK  GRD  CRS AVG", "org"),  # a table's header row
        ("Application to Register Permanent Residence", "I-485, Application to Register Permanent Residence", "org"),
        ("Verklaring van Geschiktheid", "Verklaring van Geschiktheid", "person"),  # a document's title
        ("NEW PATIENT", "NEW PATIENT INTAKE FORM", "place"),  # a heading in capitals that names a document
        ("je mi", "je mi sais pas", "org"),  # lower case: names keep their capital
    ],
)
def test_what_cannot_be_a_name_is_dropped(surface: str, line: str, kind: str) -> None:
    flags = {"person": kind == "person", "org": kind == "org", "place": kind == "place"}
    assert not plausible_entity(surface, line, NONE, **flags)


@pytest.mark.parametrize(
    ("surface", "line", "kind"),
    [
        ("USA", "Shipped from the USA last week", "place"),  # a place code, whatever its case
        ("McDonald", "Ask Mr McDonald about it", "person"),
        ("DeShawn", "DeShawn signed the form", "person"),
        ("El1f", "El1f R4m4n was in the notes", "org"),  # a name in leetspeak keeps its digits
        ("JOHN SMITH CONSENT FORM", "JOHN SMITH CONSENT FORM", "person"),  # a name before the document word
        ("Plan International", "Plan International sent the report", "org"),
        ("emily bennett", "emily bennett was in the notes", "person"),  # a full name lowered to slip past
    ],
)
def test_names_and_places_stay(surface: str, line: str, kind: str) -> None:
    flags = {"person": kind == "person", "org": kind == "org", "place": kind == "place"}
    assert plausible_entity(surface, line, NONE, **flags)


def test_words_the_text_also_writes_in_lower_case_are_not_names() -> None:
    lower = lowercase_words("Patient Intake. The patient is seen by the nurse.")
    assert not plausible_entity("Patient", "Patient Intake.", lower, person=True)


def test_terms_a_document_defines_and_abbreviations_it_spells_out() -> None:
    text = 'Acme Labs (the "Sponsor") pays. The Sponsor keeps protected health information (PHI) safe.'
    assert {"sponsor", "phi"} <= lowercase_words(text)


def test_verbs_that_open_an_instruction() -> None:
    text = "Mark all that apply. Mark Visser signed."
    assert instruction_verb(text, 0, 4)
    assert not instruction_verb(text, text.index("Mark Visser"), text.index("Mark Visser") + 4)


def test_a_browser_user_agent_names_software() -> None:
    text = "UA: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/605.1"
    start, end = software_ranges(text)[0]
    assert text[start:end].startswith("Mozilla/5.0") and "Gecko" in text[start:end]


def test_capitals_inside_mixed_text_are_shown_to_the_model_in_title_case() -> None:
    assert case_view("please call EMILY THOMPSON today") == "please call Emily Thompson today"
    assert case_view("NEW PATIENT INTAKE FORM") == "NEW PATIENT INTAKE FORM"  # a line in capitals stays


def test_where_sentences_open() -> None:
    text = "Wil je het dossier controleren? sanne bakker stond in de notities. Bedankt voor het rapport."
    at = text.index("sanne")
    assert _sentence_initial(text, at) and _capitalised_sentences(text)
    assert _sentence_opening(text, text.index("bakker")) == at  # the second word of a sentence opened in lower case
    assert _sentence_opening(text, text.index("notities")) is None
    assert not _capitalised_sentences("hey. can u ask jan. thx")  # a text in lower case throughout


def test_leetspeak() -> None:
    assert _leetspeak("El1f") and _leetspeak("J0hn") and _leetspeak("R4m4n")
    assert not _leetspeak("HPV4") and not _leetspeak("B2B") and not _leetspeak("EC2")


# --------------------------------------------------------------------------- with the models the image ships
@pytest.fixture(scope="module")
def image_ner() -> Any:
    ner = {"cache_entries": 0, "language_models": {"de": "de_core_news_sm", "other": "xx_ent_wiki_sm"}}
    return load_ner(Settings(environment="development", detection={"ner": ner}).detection.ner)


def _kept(ner: Any, text: str) -> list[tuple[str, E]]:
    return [(text[s.start : s.end], s.type) for s, ok in ner._detect_marked([text])[0] if ok]


@pytest.mark.parametrize(
    ("text", "name"),
    [
        ("Please ask the team to check the file. emily bennett was in the notes. Thanks for the report.",
         "emily bennett"),
        ("Wil je het team vragen het dossier te controleren? jeroen de vries stond in de notities. Bedankt.",
         "jeroen de vries"),
        ("Pide al equipo que revise el expediente. iker garcía aparecía en las notas. Gracias por el informe.",
         "iker garcía"),
    ],
)  # fmt: skip
def test_a_name_lowered_to_slip_past_is_kept(image_ner: Any, text: str, name: str) -> None:
    kept = _kept(image_ner, text)
    assert any(name in surface and etype is E.PERSON for surface, etype in kept), kept


def test_titles_and_headings_are_not_names(image_ner: Any) -> None:
    for text in (
        "USCIS notice: I-485, Application to Register Permanent Residence or Adjust Status.",
        "NEW PATIENT INTAKE FORM\nPlease fill in every field.",
    ):
        assert _kept(image_ner, text) == [], text
