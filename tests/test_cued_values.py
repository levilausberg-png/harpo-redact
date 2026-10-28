"""Values named by the words in front of them (detectors/cued.py), in the languages people write.

Every value here is made up and most fail their country's checksum on purpose: after a cue word, the shape is
enough. The negatives are the everyday text the cues also appear in.
"""

from __future__ import annotations

import pytest

from harpo_redact.detectors.cued import find_cued_values, find_value_shapes, fold
from harpo_redact.entities import EntityType as E
from harpo_redact.normalize import normalize


def found(text: str) -> list[tuple[str, E]]:
    text = normalize(text).text
    spans = [*find_cued_values(text), *find_value_shapes(text)]
    return sorted({(text[s.start : s.end], s.type) for s in spans}, key=lambda x: (x[0], x[1].value))


def values(text: str, etype: E) -> list[str]:
    return [v for v, t in found(text) if t is etype]


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("Call me on 555-0147 tomorrow.", "555-0147"),
        ("Telefon: 0221 9 87 65 43 (Büro)", "0221 9 87 65 43"),
        ("Téléphone : 04.98.76.54.32", "04.98.76.54.32"),
        ("Rufen Sie mich unter der Telefonnummer 0176-1234567 an.", "0176-1234567"),
        ("puede llamar al teléfono 912 345 678 por la tarde", "912 345 678"),
        ("il mio cellulare è 333 1234567", "333 1234567"),
        ("ring venligst på 31 41 59 26", "31 41 59 26"),
        ("Puhelin 040 123 4567", "040 123 4567"),
        ("zadzwoń pod numer 601 234 567", "601 234 567"),
        ("telefonu 8 612 34567", "8 612 34567"),
        ("τηλέφωνο 210 123 4567", "210 123 4567"),
        ("phoneNumber: 555 0100 22", "555 0100 22"),
        ("kontakt os på +4512 655 8872 i morgen", "+4512 655 8872"),  # no country's plan has it; the word decides
        ("contact our desk at +1 194.886-9696 or drop by", "+1 194.886-9696"),
        ("電話番号は090-1234-5678です", "090-1234-5678"),
        ("联系电话：138 0013 8000", "138 0013 8000"),
        ("전화번호: 010-1234-5678", "010-1234-5678"),
        ("Fax‑Nr.: 089 1234 5678", "089 1234 5678"),
    ],
)
def test_a_number_after_a_phone_cue_is_a_phone_number(text: str, value: str) -> None:
    assert value in values(text, E.PHONE)


def test_a_second_number_joined_by_or_is_the_same_kind() -> None:
    assert set(values("Telefon 030 1234567 oder 0171 2345678 bitte", E.PHONE)) == {"030 1234567", "0171 2345678"}


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("+44 20 0000 0000", "+44 20 0000 0000"),
        ("reach the desk at +33.140.12.34.56 today", "+33.140.12.34.56"),
        ("(555) 010-0199 is the front desk", "(555) 010-0199"),
    ],
)
def test_international_and_bracketed_numbers_are_phones_without_a_cue(text: str, value: str) -> None:
    assert value in values(text, E.PHONE)


@pytest.mark.parametrize(
    ("text", "value", "etype"),
    [
        ("Kreditkarte 4000 1234 5678 9010 (Visa)", "4000 1234 5678 9010", E.CREDIT_CARD),
        ("the credit card ending in 5100000000000000", "5100000000000000", E.CREDIT_CARD),
        ("número de tarjeta: 3700 000000 00000", "3700 000000 00000", E.CREDIT_CARD),
        ("Kreditkarte (letzte 4 Ziffern): 4123456789012345", "4123456789012345", E.CREDIT_CARD),
        ("creditCardNumber=4111222233334444", "4111222233334444", E.CREDIT_CARD),
        ("Sozialversicherungsnummer: 756.1234.5678.90", "756.1234.5678.90", E.NATIONAL_ID),
        ("Steuer‑Nr.: CHE-123.456.789 und", "CHE-123.456.789", E.NATIONAL_ID),
        ("tax identification number CZ1234567890 for", "CZ1234567890", E.NATIONAL_ID),
        ("mi número de seguro social 123456789012", "123456789012", E.NATIONAL_ID),
        ("davčna številka 12345678", "12345678", E.NATIONAL_ID),
        ("asmens kodas 38001010000", "38001010000", E.NATIONAL_ID),
        ("Personnummer: 800101-1234", "800101-1234", E.NATIONAL_ID),
        ("社保号 310101199001011234", "310101199001011234", E.NATIONAL_ID),
        ("Reisepass‑Nr.: C01X00T47", "C01X00T47", E.ID_DOCUMENT),
        ("Numéro de permis de conduire : AB12CD34EF", "AB12CD34EF", E.ID_DOCUMENT),
        ("his passport (XK1234567).", "XK1234567", E.ID_DOCUMENT),
        ("numărul certificatului de naștere AB123456", "AB123456", E.ID_DOCUMENT),
        ("číslo řidičského průkazu: EA 123456", "EA 123456", E.ID_DOCUMENT),
        ("护照号码E12345678以及", "E12345678", E.ID_DOCUMENT),
        ("Postleitzahl: 80331", "80331", E.ADDRESS),
        ("code postal 75011.", "75011", E.ADDRESS),
        ("PSČ 110 00 Praha", "110 00", E.ADDRESS),
        ("ZIP: SW1A 1AA", "SW1A 1AA", E.ADDRESS),
        ("Health Plan Beneficiary Number: HPB-55512-B", "HPB-55512-B", E.ACCOUNT_ID),
        ("customer ID: CUST-000123", "CUST-000123", E.ACCOUNT_ID),
        ("Kundennummer 7712093", "7712093", E.ACCOUNT_ID),
        ("Account number: 884400213 MR #: 5512009 Date", "5512009", E.ACCOUNT_ID),
        ("Account Number(s) Requested: 12345-6789-01", "12345-6789-01", E.ACCOUNT_ID),
        ("bank routing number 021000021, and", "021000021", E.ACCOUNT_ID),
        ("sort code 12-34-56", "12-34-56", E.ACCOUNT_ID),
        ("IBAN: DE00 1234 5678 9012 3456 78 please", "DE00 1234 5678 9012 3456 78", E.IBAN),
        ("Trip Record Locator : K3QZ7P", "K3QZ7P", E.ACCOUNT_ID),
        ("PIN Code: 482913", "482913", E.SECRET),
        ("keep your pin 7391 to yourself", "7391", E.SECRET),
        ("the CVV is 913.", "913", E.SECRET),
        ("Vehicle Identifier: 1HG0000000A123456", "1HG0000000A123456", E.DEVICE_ID),
        (
            "device identifier 7c0f3a9e-5b1d-4e2a-9f00-1234567890ab.",
            "7c0f3a9e-5b1d-4e2a-9f00-1234567890ab",
            E.DEVICE_ID,
        ),
        ('"deviceID": "D3V1C3-00042-X"', "D3V1C3-00042-X", E.DEVICE_ID),
    ],
)
def test_a_value_after_its_cue_is_what_the_cue_says(text: str, value: str, etype: E) -> None:
    assert value in values(text, etype)


@pytest.mark.parametrize(
    "text",
    [
        "Telefonkonferenz am 12.03.2024 um 1030",  # a compound about something else
        "Steuer 19% auf 1.234,56 EUR",  # an amount
        "our customers in 2023 grew",  # a year after a person word
        "image tag: v2.4.0",  # a version
        "the GSM 900/1800 bands",  # frequencies
        "the routing table 10.0.0.0/8 via eth0",  # a network
        '{"policy": "allow-all-v2", "claim": 1500000, "insurance": "basic"}',  # names and amounts
        "Passport expires 14.03.2030",  # a date
        "account for 25% of revenue",
        "GPIO pin 12 is high",  # a hardware pin
        "Le vin 2019 était bon",  # wine, not a vehicle
        "passive 12345 mode",
        "vérifiez le dossier. ISBN 978-3-16-148410-0 figurait dans les notes",  # the next sentence
        "revise el expediente. Request id 550e8400-e29b-41d4-a716-446655440000 aparecía",
    ],
)
def test_cue_words_in_ordinary_text_find_nothing(text: str) -> None:
    assert found(text) == []


def test_the_nearest_cue_decides() -> None:
    text = "Steueridentifikationsnummer CHE-111.222.333 sowie Ihre Sozialversicherungsnummer 756.0000.1111.22"
    assert values(text, E.NATIONAL_ID) == ["756.0000.1111.22", "CHE-111.222.333"]


def test_a_vin_is_found_by_its_shape() -> None:
    assert values("Fahrgestell WVWZZZ1KZ6W000001 zugelassen", E.DEVICE_ID) == ["WVWZZZ1KZ6W000001"]
    assert values("order ORD20240101000123 shipped", E.DEVICE_ID) == []  # contains an O: not a VIN


def test_grouped_card_numbers_need_a_card_network_prefix() -> None:
    assert values("paid with 4532 0151 1283 0366", E.CREDIT_CARD) == ["4532 0151 1283 0366"]
    assert values("tracking 9999 1234 5678 0000", E.CREDIT_CARD) == []


def test_folding_removes_case_and_accents() -> None:
    assert fold("Téléphone") == "telephone"
    assert fold("Kørekort") == "korekort"
    assert fold("ΑΦΜ") == "αφμ"


def test_scan_time_grows_linearly() -> None:
    import time

    def timed(n: int) -> float:
        text = "Telefon Steuer Kreditkarte passport " * n + "1"
        start = time.perf_counter()
        list(find_cued_values(text))
        return time.perf_counter() - start

    small, large = timed(2_000), timed(8_000)
    assert large < small * 8 + 0.05


def test_a_value_stops_before_the_next_label() -> None:
    assert values("Account number: 884400213 MR #: 5512009", E.ACCOUNT_ID) == ["5512009", "884400213"]


def test_letters_inside_a_code_are_not_a_cue() -> None:
    text = "Driving licence – QX7HPLR2DL, badge 4TKWZM8PAN, permis MR55KD7Z3W"
    assert values(text, E.ID_DOCUMENT) == ["MR55KD7Z3W", "QX7HPLR2DL"]
    assert values(text, E.ACCOUNT_ID) == ["4TKWZM8PAN"]


def test_a_bare_id_label_heads_its_field() -> None:
    assert values("Visitor form\nID: TRW448120\nName: Ada", E.ACCOUNT_ID) == ["TRW448120"]
    assert values("signed by Ada Lind (ID: 55120938871) today", E.ACCOUNT_ID) == ["55120938871"]
    assert values("Name: Ada, ID: 778812, Role: editor", E.ACCOUNT_ID) == ["778812"]
    assert found("Visitor form\nID: 42\n") == []  # a row number, not a code
    assert found("see row (ID: 1042) below") == []
    assert found("the ID: TRW448120 in the middle of a sentence") == []


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("Steuernummer: 21.334.905.117", "21.334.905.117"),  # dots group identifiers too
        ("TAJ szám: 512 334 906", "512 334 906"),
        ("NINO: QQ 12 34 56 C", "QQ 12 34 56 C"),  # the closing letter belongs to the number
    ],
)
def test_grouped_identifiers_are_not_amounts(text: str, value: str) -> None:
    assert value in values(text, E.NATIONAL_ID)


@pytest.mark.parametrize(
    "text",
    [
        "Die Steuer beträgt 12.345 Euro",
        "Steuer: 12.345",
        "Steuernummer bitte nicht mit 1.250.000 EUR verwechseln",
        "tax number 1,250,000",
        "Kontostand des Kontos: 1.250.000",
        "tax id: 192.168.10.20",
    ],
)
def test_amounts_and_addresses_after_a_cue_stay(text: str) -> None:
    assert found(text) == []


@pytest.mark.parametrize(
    ("text", "value", "etype"),
    [
        ("podaj numer klienta 50217 przy wpłacie", "50217", E.ACCOUNT_ID),  # the number word comes first
        ("sebutkan nomor pajak 3175020911880003 di formulir", "3175020911880003", E.NATIONAL_ID),
        ("le numéro de dossier 48213 est en cours", "48213", E.ACCOUNT_ID),
        ("okazać dowód tożsamości KRT441902 przy wejściu", "KRT441902", E.ID_DOCUMENT),
        ("Teie isikut tõendav number on KP7713380.", "KP7713380", E.ID_DOCUMENT),
        ("Adresse Fjordvej 12, Postnr. 8240, By Risskov", "8240", E.ADDRESS),  # an abbreviation, not a sentence's end
        ("podatke o kreditni kartici 4929120055318841 v nastavitvah", "4929120055318841", E.CREDIT_CARD),
        ("the payment method ending in 5274011837764101 failed", "5274011837764101", E.CREDIT_CARD),
        ("lampirkan nomor identitas QD7731025 Anda", "QD7731025", E.ID_DOCUMENT),
    ],
)
def test_a_number_word_before_the_cue_counts(text: str, value: str, etype: E) -> None:
    assert value in values(text, etype)


def test_two_groups_of_capitals_can_lead_a_licence_number() -> None:
    assert values("Nursing licence number: OR-RN-552019 (active)", E.ID_DOCUMENT) == ["OR-RN-552019"]
    assert values("certificates such as QC-7741203 are on file", E.ACCOUNT_ID) == ["QC-7741203"]


def test_codes_that_open_doors_are_secrets() -> None:
    assert values("Door code: 772419, alarm code 0921", E.SECRET) == ["0921", "772419"]


def test_a_phone_number_leaves_the_sentences_bracket() -> None:
    assert values("Refund Anna (anna@acme.example, +31 20 794 6095), IBAN follows", E.PHONE) == ["+31 20 794 6095"]


def test_a_driving_licence_can_open_with_five_letters_of_the_surname() -> None:
    assert values("a copy of your driver's licence (MORGA 753116 SM9IJ) for", E.ID_DOCUMENT) == ["MORGA 753116 SM9IJ"]
