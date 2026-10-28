"""Validated identifiers: national IDs, cue-gated numbers, devices, crypto, addresses, escapes."""

from __future__ import annotations

from importlib import import_module

import pytest

from harpo_redact.detectors.identifiers import (
    base58check_ok,
    bech32_ok,
    decode_escapes,
    find_addresses,
    find_crypto,
    find_cued_numbers,
    find_devices,
    find_national_ids,
    find_spoken_emails,
    vin_check_digit_ok,
)
from harpo_redact.detectors.patterns import card_brand_ok
from harpo_redact.entities import EntityType as E

NATIONAL_IDS = [
    ("gb.nhs", "NHS number 943 476 5870", "943 476 5870"),
    ("ca.sin", "SIN 123-456-782", "123-456-782"),
    ("fr.nir", "NIR 2 95 10 99 126 111 93", "2 95 10 99 126 111 93"),
    ("es.dni", "DNI 54362315K", "54362315K"),
    ("es.nie", "NIE X2482300W", "X2482300W"),
    ("it.codicefiscale", "codice fiscale RCCMNL83S18D969H", "RCCMNL83S18D969H"),
    ("be.nn", "rijksregister 85.07.30-033 28", "85.07.30-033 28"),
    ("de.idnr", "Steuer-ID 36 574 261 809", "36 574 261 809"),
    ("in_.aadhaar", "Aadhaar 2341 2341 2346", "2341 2341 2346"),
    ("in_.pan", "PAN ACUPA7085R", "ACUPA7085R"),
    ("au.tfn", "TFN 123 456 782", "123 456 782"),
    ("br.cpf", "CPF 390.533.447-05", "390.533.447-05"),
    ("mx.curp", "CURP BOXW310820HNERXN09", "BOXW310820HNERXN09"),
    ("us.itin", "ITIN 912-90-3456", "912-90-3456"),
    ("us.ein", "EIN 04-2103594", "04-2103594"),
]


@pytest.mark.parametrize(("module", "text", "value"), NATIONAL_IDS)
def test_national_ids(module: str, text: str, value: str) -> None:
    assert import_module(f"stdnum.{module}").is_valid(value), "test value must be valid"
    spans = list(find_national_ids(text))
    assert any(f"identifier:{module}" in s.sources and text[s.start : s.end] == value for s in spans)


def test_ambiguous_formats_need_a_cue() -> None:
    assert list(find_national_ids("Call 943 476 5870 tomorrow")) == []  # valid NHS checksum, but no cue
    assert list(find_national_ids("Order 2341 2341 2346 shipped")) == []  # valid Aadhaar checksum, no cue


def test_cued_numbers() -> None:
    text = "Routing 111000025, account no. 000123456789, MRN: A1234567, passport number NX4R82KL1"
    found = {(s.type, text[s.start : s.end]) for s in find_cued_numbers(text)}
    assert found == {
        (E.ACCOUNT_ID, "111000025"),
        (E.ACCOUNT_ID, "000123456789"),
        (E.ACCOUNT_ID, "A1234567"),
        (E.ID_DOCUMENT, "NX4R82KL1"),
    }
    assert list(find_cued_numbers("The passport expired and the account is closed.")) == []


def test_devices() -> None:
    text = "IMEI 35-209900-176148-1, MAC 00:1A:2B:3C:4D:5E, VIN 1M8GDM9AXKP042788, serial no SN-88213X"
    assert len([s for s in find_devices(text) if s.type is E.DEVICE_ID]) == 4
    assert vin_check_digit_ok("1M8GDM9AXKP042788")
    assert not vin_check_digit_ok("1M8GDM9AYKP042788")


def test_crypto_addresses_are_checksum_validated() -> None:
    assert base58check_ok("1BoatSLRHtKNngkdXEeobR76b53LETtpyT")
    assert not base58check_ok("1BoatSLRHtKNngkdXEeobR76b53LETtpyU")
    assert bech32_ok("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
    text = "Pay 1BoatSLRHtKNngkdXEeobR76b53LETtpyT or 0x52908400098527886E0F7030069857D2E4169EE7"
    assert len(list(find_crypto(text))) == 2


def test_card_brands_reject_imeis_and_hex() -> None:
    assert card_brand_ok("4111111111111111") and card_brand_ok("378282246310005")
    assert not card_brand_ok("352099001761481")  # an IMEI, Luhn-valid but no card network


@pytest.mark.parametrize(
    "text",
    [
        "742 Evergreen Terrace, Springfield",
        "Ship to 1600 Pennsylvania Avenue NW",
        "Kerkstraat 12, Amsterdam",
        "1017 GL Amsterdam",
        "Hauptstraße 5, 10115 Berlin",
        "London SW1A 1AA",
        "Springfield, IL 62704",
    ],
)
def test_addresses(text: str) -> None:
    assert list(find_addresses(text)), text


@pytest.mark.parametrize("text", ["the 10 Best Way to learn", "2021 AD history", "4 GB RAM", "version 1.2.3"])
def test_not_addresses(text: str) -> None:
    assert list(find_addresses(text)) == []


def test_escaped_and_spoken_emails() -> None:
    decoded, starts, ends = decode_escapes("mail jane.doe%40example.com now") or ("", [], [])
    assert decoded == "mail jane.doe@example.com now"
    at = decoded.index("@")
    assert (starts[at], ends[at]) == (13, 16)
    assert decode_escapes("plain text") is None
    spans = list(find_spoken_emails("write to carla at northwind dot com today"))
    assert spans and spans[0].canonical == "carla@northwind.com"


def test_pipeline_redacts_escaped_values(pipeline) -> None:  # type: ignore[no-untyped-def]
    out = pipeline.scan_sync(["Contact jane.doe%40example.com or bob&#64;corp.example"]).texts[0]
    assert out == "Contact [EMAIL_1] or [EMAIL_2]"


def test_dates_follow_policy(make_pipeline) -> None:  # type: ignore[no-untyped-def]
    text = "Admitted on 03/14/2024 and discharged on 2024-03-20."
    assert make_pipeline().scan_sync([text]).texts[0] == text  # dates are allowed by default
    hipaa = make_pipeline(policy={"entities": {"DATE": {"action": "redact"}}})
    assert hipaa.scan_sync([text]).texts[0] == "Admitted on [DATE_1] and discharged on [DATE_2]."
