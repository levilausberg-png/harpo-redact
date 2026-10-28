"""Deterministic detectors: validated patterns, secrets, encoded data, registry."""

from __future__ import annotations

import base64

import pytest

from harpo_redact.detectors import patterns
from harpo_redact.detectors.secrets import Registry, find_encoded, find_secrets
from harpo_redact.entities import EntityType as E

REGIONS = ["US", "GB", "NL", "DE"]


def found(text: str) -> list[tuple[E, str]]:
    return sorted((s.type, text[s.start : s.end]) for s in patterns.find_all(text, REGIONS))


def test_email_excludes_trailing_punctuation() -> None:
    assert found("Mail jane.doe@example.com.") == [(E.EMAIL, "jane.doe@example.com")]


@pytest.mark.parametrize("number", ["+31 20 794 6095", "+1 415 867 5309", "+44 20 7946 0958", "(415) 867-5309"])
def test_valid_phone_numbers(number: str) -> None:
    assert (E.PHONE, number) in found(f"Call {number} today")


def test_phone_formats_share_one_canonical_value() -> None:
    a = next(s for s in patterns.find_all("+31 20 794 6095", REGIONS) if s.type is E.PHONE)
    b = next(s for s in patterns.find_all("+31207946095", REGIONS) if s.type is E.PHONE)
    assert a.canonical == b.canonical


def test_short_numbers_are_not_phones() -> None:
    assert found("Invoice 4471 is due in 30 days") == []


def test_card_requires_luhn() -> None:
    assert found("card 4111 1111 1111 1111") == [(E.CREDIT_CARD, "4111 1111 1111 1111")]
    assert found("card 4111 1111 1111 1112") == []


def test_iban_requires_checksum() -> None:
    assert found("pay NL91ABNA0417164300") == [(E.IBAN, "NL91ABNA0417164300")]
    assert found("pay NL91ABNA0417164301") == []


def test_us_ssn_with_valid_area() -> None:
    assert (E.US_SSN, "123-45-6789") in found("SSN: 123-45-6789")
    assert not any(t is E.US_SSN for t, _ in found("SSN: 000-45-6789"))


def test_dutch_bsn_eleven_proof() -> None:
    assert (E.NL_BSN, "111222333") in found("BSN: 111222333")
    assert not any(t is E.NL_BSN for t, _ in found("BSN: 111222334"))


def test_ip_addresses_skip_loopback() -> None:
    assert (E.IP_ADDRESS, "203.0.113.7") in found("login from 203.0.113.7")
    assert found("listening on 127.0.0.1") == []


def test_date_of_birth_needs_a_cue() -> None:
    assert (E.DATE_OF_BIRTH, "03/14/1985") in found("DOB 03/14/1985")
    assert not any(t is E.DATE_OF_BIRTH for t, _ in found("Shipped on 03/14/1985"))


@pytest.mark.parametrize(
    "text",
    [
        "key sk-proj-7Hq2LmV9xRt4KpZ8wNc3YbF6dJs1GaE5",
        "aws AKIAIOSFODNN7EXAMPLE",
        "token ghp_0123456789abcdefghijklmnopqrstuvwxyzAB",
        "password=Hunter2!x",
        "Authorization: Bearer abcdefghijklmnop0123456789",
        "postgres://app:s3cr3t-pa55@db.internal:5432/app",
    ],
)
def test_secrets(text: str) -> None:
    assert [s.type for s in find_secrets(text)] == [E.SECRET]


@pytest.mark.parametrize("text", ["the secret is Paris", "password=${DB_PASSWORD}", "api_key=<your key>"])
def test_not_secrets(text: str) -> None:
    assert list(find_secrets(text)) == []


def test_pem_private_key_block() -> None:
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234\n-----END RSA PRIVATE KEY-----"
    assert [s.type for s in find_secrets(pem)] == [E.PRIVATE_KEY]


def _scan(text: str) -> list:  # type: ignore[type-arg]
    return patterns.find_all(text, REGIONS) + list(find_secrets(text))


def test_base64_wrapped_email_is_encoded_data() -> None:
    blob = base64.b64encode(b'{"email": "jane.doe@example.com", "plan": "pro"}').decode()
    spans = list(find_encoded(f"payload {blob}", _scan))
    assert len(spans) == 1 and spans[0].type is E.ENCODED_DATA and E.EMAIL in spans[0].inner


def test_double_encoded_private_key_reports_inner_type() -> None:
    pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
    blob = base64.b64encode(base64.b64encode(pem.encode())).decode()
    spans = list(find_encoded(blob, _scan, max_depth=2))
    assert spans and E.PRIVATE_KEY in spans[0].inner


def test_harmless_base64_is_ignored() -> None:
    blob = base64.b64encode(b"just an ordinary sentence with no identifiers at all").decode()
    assert list(find_encoded(blob, _scan)) == []


def test_registry_terms_and_patterns() -> None:
    registry = Registry(["Project Bluefin"], [r"\bINC-\d{6}\b"])
    text = "Status of project bluefin, see INC-004211."
    assert sorted(text[s.start : s.end] for s in registry.find(text)) == ["INC-004211", "project bluefin"]


def test_a_date_of_birth_under_a_markdown_label() -> None:
    from harpo_redact.detectors.patterns import find_dates_of_birth

    for text in ("- **Date of Birth**: 1981-04-17", "**Date of Birth:** 17/04/1981", "__DOB__: 04/17/1981"):
        assert [text[s.start : s.end] for s in find_dates_of_birth(text)] in (
            ["1981-04-17"],
            ["17/04/1981"],
            ["04/17/1981"],
        )
