"""Every bug the redaction matrix, the fuzzer and the robustness probes found, as a minimal permanent test.

The matrix (tests/test_redaction_matrix.py) covers each case in every carrier. These pin the individual causes,
so a regression names the exact thing that broke. Grouped by what was wrong; each test says what used to happen.
"""

from __future__ import annotations

import base64
import json
import time

import pytest

from harpo_redact.detectors import fields, views
from harpo_redact.detectors.identifiers import decode_escapes, find_cued_numbers, find_national_ids
from harpo_redact.detectors.patterns import find_dates_of_birth, find_ibans
from harpo_redact.detectors.secret_library import load_library
from harpo_redact.detectors.secrets import Registry, find_encoded, find_secrets, is_encoded_text
from harpo_redact.entities import EntityType as E
from harpo_redact.normalize import normalize
from harpo_redact.proxy import Collector

FAST = {"ner": {"enabled": False}, "registry": {"terms": ["Project Bluefin"]}}


@pytest.fixture(scope="module")
def library():  # type: ignore[no-untyped-def]
    return load_library()


def redacted(make_pipeline, text: str) -> str:  # type: ignore[no-untyped-def]
    return make_pipeline(detection=FAST).scan_sync([text]).texts[0]


def types(make_pipeline, text: str) -> set[str]:  # type: ignore[no-untyped-def]
    return set(make_pipeline(detection=FAST).scan_sync([text]).counts)


# --------------------------------------------------------------------------- leaks in the released 2.3.0
@pytest.mark.parametrize("text", ["Ref AB12 NL91 ABNA 0417 1643 00", " jane.doe@example.com AA00 NL91ABNA0417164300 "])
def test_an_iban_after_an_iban_shaped_token_is_found(text: str) -> None:
    """Found by the fuzzer: the IBAN candidate run started at "AB12", only that start was tried, the IBAN leaked."""
    assert [text[s.start : s.end].replace(" ", "") for s in find_ibans(text)] == ["NL91ABNA0417164300"]


def test_a_long_token_before_an_at_sign_scans_in_linear_time(make_pipeline) -> None:  # type: ignore[no-untyped-def]
    """Found by the robustness probe: the leetspeak-email view backtracked from every position of a long token,
    so 60,000 characters and an "@" took 8.5 seconds to scan (a denial of service)."""
    started = time.perf_counter()
    make_pipeline(detection=FAST).scan_sync(["a" * 60_000 + "@"])
    assert time.perf_counter() - started < 3.0


def test_a_template_in_a_connection_url_is_not_a_password() -> None:
    text = "DATABASE_URL: postgres://app:${POSTGRES_PASSWORD}@db:5432/billing"
    assert list(find_secrets(text)) == []
    assert [s.type for s in find_secrets("postgres://app:Wq3hT9mZx7Lp@db:5432/billing")] == [E.SECRET]


# --------------------------------------------------------------------------- field names as cues
@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ('{"nhs_number": "409 740 2358"}', "gb.nhs"),
        ('{"socialInsuranceNumber": "337 384 804"}', "ca.sin"),
        ("rijksregisternummer=85.07.35-473.20", "be.nn"),
        ('<record steuer_id="38 273 301 463"/>', "de.idnr"),
        ("aadhaar_number: 2311 2587 8762", "in_.aadhaar"),
        ("tax_file_number,816 567 024", "au.tfn"),
    ],
)
def test_cue_words_written_as_field_names_count(text: str, kind: str) -> None:
    """Cue words were matched only as prose words: "\\bnhs\\b" never matched "nhs_number"."""
    assert any(s.sources == {f"identifier:{kind}"} for s in find_national_ids(text))


@pytest.mark.parametrize(
    "text",
    [
        '{"date_of_birth": "14 March 1985"}',
        "dateOfBirth=14 March 1985",
        'The date of birth on file is "14 March 1985".',
        "<tr><th>date of birth</th><td>14 March 1985</td></tr>",
        "| date of birth | 14 March 1985 |",
        "date of birth (DD Month YYYY): 14 March 1985",
        "born in Utrecht on 14 March 1985",
    ],
)
def test_date_of_birth_cues_in_every_shape(text: str) -> None:
    """The cue had to be followed by spaces, a colon or a dash: quotes, markup, field names and words broke it."""
    assert [text[s.start : s.end] for s in find_dates_of_birth(text)] == ["14 March 1985"]


def test_a_date_without_a_birth_cue_is_not_a_date_of_birth() -> None:
    assert list(find_dates_of_birth("date of birth unknown, see the note from 14 March 1985")) == []
    assert list(find_dates_of_birth("Shipped on 03/14/1985")) == []


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ('{"passport_number": "X8R2K4L19"}', "X8R2K4L19"),
        ('The passport number on file is "X8R2K4L19".', "X8R2K4L19"),
        ("passport number (as printed): X8R2K4L19", "X8R2K4L19"),
        ("set account_number='7729341056' on the profile", "7729341056"),
        ("account no. 000123456789", "000123456789"),
        ("MRN: A1234567", "A1234567"),
        ("customer 4471209", "4471209"),
    ],
)
def test_cued_numbers_in_every_shape(text: str, value: str) -> None:
    assert value.upper() in {text[s.start : s.end].upper() for s in find_cued_numbers(text)}


@pytest.mark.parametrize(
    "text",
    [
        "passport number (base64): WDhSMks0TDE5",  # "(base64)" was taken as the passport number
        '"policy": "net-30"',  # a payment policy is not a policy number
        '"claim": "1500000"',  # an amount
        '"account": "prod-eu-1"',  # an account's name
        "social insurance number (base64): MzM3IDM4NCA4MDU=",  # "insurance number" + a base64 blob
        "The passport expired and the account is closed.",
    ],
)
def test_cue_words_do_not_turn_formats_amounts_or_names_into_ids(text: str) -> None:
    assert list(find_cued_numbers(text)) == []


# --------------------------------------------------------------------------- labelled values
@pytest.mark.parametrize(
    ("label", "value", "etype"),
    [
        ("bsn", "298163871", E.NL_BSN),
        ("ssn_index", "159744517", E.US_SSN),
        ("passport_number_index", "X8R2K4L19", E.ID_DOCUMENT),
        ("Passport Number", "X8R2K4L19", E.ID_DOCUMENT),
        ("dateOfBirth", "1985-03-14", E.DATE_OF_BIRTH),
        ("Steuer-ID", "38 273 301 463", E.NATIONAL_ID),
        ("rekeningnummer", "7729341056", E.ACCOUNT_ID),
        ("imei", "35-987100-570061-3", E.DEVICE_ID),
        ("password", "sunshine", E.SECRET),
        ("aws_secret_access_key", "wJalrXUtnFEMIK7MDENGbPxRfiCYq8Lk3Hz5vT2n", E.SECRET),
        ("pin", "8831", E.SECRET),
    ],
)
def test_a_value_is_checked_against_its_label(label: str, value: str, etype: E) -> None:
    assert [s.type for s in fields.find_labelled(label, value)] == [etype]


@pytest.mark.parametrize(
    ("label", "value"),
    [
        ("passport_expiry", "2030-01-01"),
        ("password_hint", "favourite colour"),
        ("password", "required"),
        ("password", "${DB_PASSWORD}"),
        ("access_key_id", "AKIAZ4X7Q2LMWN3RT5PJ"),  # an identifier, not the secret (gitleaks agrees)
        ("customer", "on file"),
        ("claim", "1500000"),
        ("account_balance", "1500.00"),
        ("policy", "allow-all-v2"),
        ("next_page_token", "5f3c9a1b7e2d4c6a8b0f"),
        ("csrf_token", "a8Fj29dK3mPq0Lz7Xc"),
        ("sin", "0.5"),
        ("born_city", "Utrecht"),
        ("license", "Apache-2"),
        ("bsn", "298163872"),  # the eleven-test fails
        ("passport", "WEtSVExNV1BR"),  # base64 text: judged by what it decodes to
    ],
)
def test_a_label_cannot_make_an_ordinary_value_sensitive(label: str, value: str) -> None:
    assert fields.find_labelled(label, value) == []


def test_label_words_split_field_names() -> None:
    assert fields.label_words("passport_number_index") == ("passport", "number", "index")
    assert fields.label_words("dateOfBirth") == ("date", "of", "birth")
    assert fields.label_words("Steuer-ID") == ("steuer", "id")
    assert fields.label_words("rekeningnummer") == ("rekening", "nummer")
    assert fields.label_words("burgerservicenummer") == ("burgerservicenummer",)


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("name,date_of_birth,city\nJ. Smit,14 March 1985,Utrecht", "14 March 1985"),
        ('id;bsn\n1;"298163871"', "298163871"),
        ("name\tssn\nJ. Smit\t159744517", "159744517"),
        ("| field | value |\n|---|---|\n| password | Tr0ub4dor&3x |", "Tr0ub4dor&3x"),
        ("<tr><th>password</th><td><b>Tr0ub4dor&3x</b></td></tr>", "Tr0ub4dor&3x"),
        ("<table><tr><th>Name</th><th>Passport</th></tr><tr><td>J. Smit</td><td>X8R2K4L19</td></tr></table>",
         "X8R2K4L19"),
    ],
)  # fmt: skip
def test_table_cells_are_checked_against_their_header_or_row_label(text: str, value: str) -> None:
    """A value in a CSV column, a Markdown row or an HTML table had no cue next to it."""
    assert value in {text[s.start : s.end] for s in fields.find_table_fields(text)}


def test_a_blank_line_ends_a_table() -> None:
    text = "name,bsn\nJ. Smit,on file\n\n1,298163871"
    found = {text[s.start : s.end] for s in fields.find_table_fields(text)}
    assert "298163871" not in found  # the line after the blank one is not under the "bsn" column
    assert found <= {"J. Smit"}  # the name is: a "name" column in a table that has a BSN column holds people


def test_json_leaves_and_keys_are_labelled_with_the_nearest_field_name() -> None:
    collector = Collector(drop_unsupported=False)
    tree = {
        "tools": {"properties": {"bsn": {"type": "string", "default": "298163871", "examples": ["298163871"]}}},
        "passport_number_index": {"X8R2K4L19": {"status": "verified"}},
        "record": {"fields": [{"name": "date_of_birth", "value": "14 March 1985"}]},
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq": "wallet",
    }
    collector.add_json_tree(tree)
    labelled = dict(zip(collector.texts, collector.labels, strict=True))
    assert labelled["298163871"] == "tools.bsn"  # "properties", "default" and "examples" are structure
    assert labelled["X8R2K4L19"] == "passport_number_index"  # a key that is data takes its parent's name
    assert labelled["14 March 1985"] == "date_of_birth"  # name/value records: the sibling name ("record" and
    # "fields" are structure, like "properties")
    assert "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" in labelled  # lowercase keys with digits are scanned
    assert "verified" in labelled and labelled["verified"] == "passport_number_index.status"


# --------------------------------------------------------------------------- encodings
def test_hex_encoded_text_is_decoded_and_scanned(make_pipeline) -> None:  # type: ignore[no-untyped-def]
    for text in ("IMEI (hex): 33352d3938373130302d3537303036312d33", "dump: 6a 61 6e 65 40 61 63 6d 65 2e 69 6f"):
        assert "[ENCODED_DATA_1]" in redacted(make_pipeline, text), text


def test_hashes_and_keys_in_hex_are_left_alone() -> None:
    sha = "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b"
    assert list(find_encoded(f"sha256 {sha}", lambda s: [])) == []


def test_short_base64_with_padding_and_a_distant_cue(make_pipeline) -> None:  # type: ignore[no-untyped-def]
    """Runs of 8 to 11 characters were skipped ("U1cxQSAxQUE=" is "SW1A 1AA"), and only 24 characters before a run
    travelled with it, so "rijksregisternummer (base64): ..." lost its cue."""
    assert "[ENCODED_DATA_1]" in redacted(make_pipeline, "postcode (base64): U1cxQSAxQUE=")
    blob = base64.b64encode(b"85.07.35-473.20").decode()
    assert "[ENCODED_DATA_1]" in redacted(make_pipeline, f"rijksregisternummer (base64): {blob}")


def test_base64_of_readable_text_is_judged_by_what_it_says(library) -> None:  # type: ignore[no-untyped-def]
    """Generic entropy rules blocked "token payload: <base64 of an email in JSON>" as an API key."""
    blob = base64.urlsafe_b64encode(json.dumps({"email": "maria.jansen@kpn-zakelijk.nl"}).encode()).decode()
    assert is_encoded_text(blob.rstrip("="))
    assert library.find(f"token payload: {blob}") == []
    assert not is_encoded_text("Tr0ub4dor&3x") and not is_encoded_text("X8R2K4L19")


def test_json_inside_a_json_string_is_unescaped() -> None:
    text = json.dumps({"payload": json.dumps({"date_of_birth": "14 March 1985"})})
    view = decode_escapes(text)
    assert view is not None and '"date_of_birth": "14 March 1985"' in view[0]


# --------------------------------------------------------------------------- shadow views
def test_a_right_to_left_override_is_read_in_display_order(make_pipeline) -> None:  # type: ignore[no-untyped-def]
    """The override was stripped and the stored, reversed digits were scanned: a card shown in full passed."""
    stored = "4103 9471 7534 1114"[::-1]  # displays as the card number under the override
    text = f"card: \u202e{stored}\u202c thanks"
    assert normalize(text).reversed_runs == ((6, 6 + len(stored)),)
    assert "[CREDIT_CARD_1]" in redacted(make_pipeline, text)


def test_look_alike_letters_next_to_digits_are_read_as_latin(make_pipeline) -> None:  # type: ignore[no-untyped-def]
    """Normalisation folds look-alikes only in words that mix them with Latin letters; "74913826С" (Cyrillic С)
    and "1АА" have none, so a DNI and a postcode passed."""
    assert "[NATIONAL_ID_1]" in redacted(make_pipeline, "DNI: 74913826С")
    assert "[ADDRESS_1]" in redacted(make_pipeline, "postcode: SW1A 1АА")
    russian = "Привет! Это обычный текст: комната 2В, этаж 3."
    assert redacted(make_pipeline, russian) == russian
    assert views.lookalike_view("Это обычный текст") is None


@pytest.mark.parametrize(
    "text",
    [
        "card: 4 1 0 3   9 4 7 1   7 5 3 4   1 1 1 4",
        "mail: m a r i a . j a n s e n @ k p n - z a k e l i j k . n l",
        "postcode: S W 1 A   1 A A",
    ],
)
def test_spaced_values_with_word_gaps_and_punctuation(make_pipeline, text: str) -> None:  # type: ignore[no-untyped-def]
    assert "_1]" in redacted(make_pipeline, text)


@pytest.mark.parametrize(
    "text",
    [
        "date of birth: 14 Mar\nch 1985",
        "address: Keizersg\nracht 123",
        "address: 1600 Pennsyl\nvania Avenue",
        "phone: 020 79\n4 6095",
        "codename: Projec\nt Bluefin",
        "seed phrase: decorate good butter tonight infant b\niology gate acid control knife select sleep",
    ],
)
def test_values_broken_inside_a_word_are_rejoined(make_pipeline, text: str) -> None:  # type: ignore[no-untyped-def]
    out = make_pipeline(detection=FAST).scan_sync([text])
    assert out.counts, text


def test_a_secret_cut_by_a_line_break_is_redacted_in_full(make_pipeline) -> None:  # type: ignore[no-untyped-def]
    """The first half was found whole and the join view was dropped as "a real break": the rest leaked."""
    out = make_pipeline(detection=FAST).scan_sync(["password: Tr0ub4\ndor&3x (copied)"], override=True)
    assert "dor&3x" not in out.texts[0]


def test_national_numbers_join_only_after_a_phone_word(make_pipeline) -> None:  # type: ignore[no-untyped-def]
    text = "Call 020\n7946095 is two lines of figures, not one number."
    assert redacted(make_pipeline, text) == text


def test_protected_terms_match_as_identifiers_and_across_lines() -> None:
    registry = Registry(["Project Bluefin"], [])
    for text in ("project_bluefin", "Project-Bluefin", "ProjectBluefin", "Project\nBluefin"):
        assert [s.type for s in registry.find(text)] == [E.PROTECTED_TERM], text


# --------------------------------------------------------------------------- credentials
def test_documentation_placeholders_are_not_credentials(library) -> None:  # type: ignore[no-untyped-def]
    for text in ('{"password": "required"}', "token: ghp_" + "x" * 36, "aws_access_key_id = YOUR_ACCESS_KEY_ID"):
        assert list(find_secrets(text)) == [] and library.find(text) == [], text


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("Please use AWS secret access key wJalrXUtnFEMIK7MDENGbPxRfiCYq8Lk3Hz5vT2n today", True),
        ("the password Tr0ub4dor&3x works", True),
        ("our password manager handles it", False),
        ("API key rotation2024 is due", False),
    ],
)
def test_a_credential_right_after_its_cue_word(library, text: str, secret: bool) -> None:  # type: ignore[no-untyped-def]
    """No linking word or sign: the value must look generated (three of upper, lower, digits, symbols)."""
    assert bool(library.find(text)) is secret


def test_a_token_in_a_url_query_ends_at_the_ampersand(library) -> None:  # type: ignore[no-untyped-def]
    text = "Open https://registry.example.org/?npm_token=npm_aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5&lang=en"
    assert any("npm" in r for s in library.find(text) for r in s.sources)


def test_a_seed_phrase_label_made_of_wordlist_words_is_not_a_phrase(library) -> None:  # type: ignore[no-untyped-def]
    """Kept as found: "word list" + twelve wordlist words is a run of fifteen, and one twelve-word window can pass
    the four-bit checksum by chance. The matrix's near miss avoids wordlist words in its label for that reason."""
    near = "decorate good butter tonight infant biology gate acid control knife select select"
    assert library.find(f"dictation homework: {near}") == []


# --------------------------------------------------------------------------- source hygiene
def test_no_invisible_or_bidirectional_characters_in_source() -> None:
    """Found by bandit (B613, "trojan source"): a right-to-left override had been typed into a docstring. Code and
    tests write such characters as escapes ("\\u202e"), so what a reviewer sees is what runs."""
    import pathlib
    import unicodedata

    root = pathlib.Path(__file__).resolve().parents[1]
    found = []
    for path in [*root.joinpath("src").rglob("*"), *root.joinpath("tests").rglob("*.py")]:
        if path.suffix not in (".py", ".js", ".css", ".html", ".md", ".json", ".toml") or "__pycache__" in path.parts:
            continue
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if any(unicodedata.category(c) == "Cf" and c != "﻿" for c in line):
                found.append(f"{path.relative_to(root)}:{n}")
    assert found == []


def test_snake_case_field_names_are_not_names(make_pipeline) -> None:  # type: ignore[no-untyped-def]
    """Found in the live demo: NER tagged the CSV header "date_of_birth" as a person and "customer_id" as a place."""
    pipeline = make_pipeline()  # NER on
    text = "first_name,last_name,customer_id,created_at,date_of_birth"
    assert pipeline.scan_sync([text]).texts == [text]
