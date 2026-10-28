"""Generated valid and corrupted identifiers for every validated scheme.

Valid values come from the scheme's own check-digit algorithm (python-stdnum),
so every assertion is about thousands of real-shaped values, not a few examples.
"""

from __future__ import annotations

import hashlib
import random
import string
from importlib import import_module

import phonenumbers
import pytest
from stdnum import iban as std_iban
from stdnum import luhn, verhoeff

from harpo_redact.detectors import patterns
from harpo_redact.detectors.identifiers import (
    find_crypto,
    find_cued_numbers,
    find_devices,
    find_national_ids,
    vin_check_digit_ok,
)
from harpo_redact.entities import EntityType as E

N = 40
REGIONS = ["US", "GB", "NL", "DE"]


def _digits(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(string.digits) for _ in range(n))


def _date(rng: random.Random) -> tuple[str, str, str]:
    return f"{rng.randint(0, 99):02d}", f"{rng.randint(1, 12):02d}", f"{rng.randint(1, 28):02d}"


def _make(module: str, rng: random.Random) -> str:
    mod = import_module(f"stdnum.{module}")
    if module in ("gb.nhs", "ca.sin", "au.tfn"):
        return _digits(rng, {"gb.nhs": 10, "ca.sin": 9, "au.tfn": 9}[module])
    if module == "fr.nir":
        yy, mm, _ = _date(rng)
        dept = f"{rng.choice([d for d in range(1, 96) if d != 20]):02d}"
        body = f"{rng.choice('12')}{yy}{mm}{dept}{_digits(rng, 3)}{_digits(rng, 3)}"
        return body + f"{97 - int(body) % 97:02d}"
    if module == "es.dni":
        n = _digits(rng, 8)
        return n + "TRWAGMYFPDXBNJZSQVHLCKE"[int(n) % 23]
    if module == "es.nie":
        lead, n = rng.choice("XYZ"), _digits(rng, 7)
        return lead + n + "TRWAGMYFPDXBNJZSQVHLCKE"[int(str("XYZ".index(lead)) + n) % 23]
    if module == "it.codicefiscale":
        yy, _, dd = _date(rng)
        day = f"{int(dd) + rng.choice([0, 40]):02d}"
        body = (
            "".join(rng.choice(string.ascii_uppercase) for _ in range(6)) + yy + rng.choice("ABCDEHLMPRST") + day
            + rng.choice(string.ascii_uppercase) + _digits(rng, 3)
        )  # fmt: skip
        return body + mod.calc_check_digit(body)
    if module == "be.nn":
        yy, mm, dd = _date(rng)
        body = f"{yy}{mm}{dd}{rng.randint(1, 997):03d}"
        return body + f"{97 - int(body) % 97:02d}"
    if module == "de.idnr":
        return _digits(rng, 11)
    if module == "in_.aadhaar":
        body = rng.choice("23456789") + _digits(rng, 10)
        return body + verhoeff.calc_check_digit(body)
    if module == "in_.pan":
        letters = string.ascii_uppercase
        return (
            "".join(rng.choice(letters) for _ in range(3))
            + rng.choice("ABCFGHLJPT")
            + rng.choice(letters)
            + _digits(rng, 4)
            + rng.choice(letters)
        )
    if module == "br.cpf":
        body = _digits(rng, 9)
        d1 = sum(int(body[i]) * (10 - i) for i in range(9)) * 10 % 11 % 10
        d2 = sum(int((body + str(d1))[i]) * (11 - i) for i in range(10)) * 10 % 11 % 10
        return f"{body}{d1}{d2}"
    if module == "mx.curp":
        yy, mm, dd = _date(rng)
        consonants = "BCDFGHJKLMNPQRSTVWXYZ"
        body = (
            rng.choice(consonants) + rng.choice("AEIOU") + rng.choice(consonants) + rng.choice(consonants)
            + yy + mm + dd + rng.choice("HM") + rng.choice(["AS", "BC", "CL", "DF", "JC", "NL", "VZ", "YN"])
            + "".join(rng.choice(consonants) for _ in range(3)) + rng.choice(string.digits)
        )  # fmt: skip
        return body + mod.calc_check_digit(body)
    if module == "us.itin":
        return "9" + _digits(rng, 2) + rng.choice(["70", "78", "88", "90", "94", "99"]) + _digits(rng, 4)
    if module == "us.ein":
        return rng.choice(["01", "04", "10", "20", "27", "45", "68", "94"]) + _digits(rng, 7)
    raise AssertionError(module)


SCHEMES = {  # module -> cue written before the value (empty: none needed)
    "gb.nhs": "NHS number",
    "ca.sin": "SIN",
    "fr.nir": "",
    "es.dni": "",
    "es.nie": "",
    "it.codicefiscale": "",
    "be.nn": "rijksregisternummer",
    "de.idnr": "Steuer-ID",
    "in_.aadhaar": "Aadhaar",
    "in_.pan": "",
    "au.tfn": "TFN",
    "br.cpf": "CPF",
    "mx.curp": "",
    "us.itin": "",
    "us.ein": "EIN",
}
CHECKSUMMED = set(SCHEMES) - {"in_.pan", "us.itin", "us.ein"}
LETTERED = {"es.dni", "es.nie", "it.codicefiscale", "in_.pan", "mx.curp"}


def valid_values(module: str) -> list[str]:
    rng = random.Random(module)
    mod = import_module(f"stdnum.{module}")
    out: list[str] = []
    for _ in range(20_000):
        value = _make(module, rng)
        if mod.is_valid(value) and value not in out:
            out.append(value)
            if len(out) == N:
                return out
    raise AssertionError(f"could not generate {N} valid {module} values")


def _hits(text: str, module: str) -> list[str]:
    return [text[s.start : s.end] for s in find_national_ids(text) if f"identifier:{module}" in s.sources]


@pytest.mark.parametrize("module", sorted(SCHEMES))
def test_valid_values_are_found_in_every_format(module: str) -> None:
    mod = import_module(f"stdnum.{module}")
    cue = SCHEMES[module]
    misses = []
    for value in valid_values(module):
        variants = {value}
        if hasattr(mod, "format"):
            variants.add(mod.format(value))
        for v in variants:
            if v not in _hits(f"Record: {cue} {v}, please check.", module):
                misses.append(v)
    assert misses == []


@pytest.mark.parametrize("module", sorted(LETTERED))
def test_lowercase_values_are_found(module: str) -> None:
    cue = SCHEMES[module]
    misses = [v for v in valid_values(module) if not _hits(f"{cue} {v.lower()} on file", module)]
    assert misses == []


@pytest.mark.parametrize("module", sorted(CHECKSUMMED))
def test_corrupted_check_digits_are_rejected(module: str) -> None:
    mod = import_module(f"stdnum.{module}")
    cue = SCHEMES[module]
    accepted = []
    for value in valid_values(module):
        last = value[-1]
        bad = value[:-1] + (str((int(last) + 1) % 10) if last.isdigit() else ("A" if last != "A" else "B"))
        if not mod.is_valid(bad) and _hits(f"{cue} {bad}", module):
            accepted.append(bad)
    assert accepted == []


@pytest.mark.parametrize("module", sorted(m for m, cue in SCHEMES.items() if cue))
def test_ambiguous_formats_need_their_cue(module: str) -> None:
    assert [v for v in valid_values(module) if _hits(f"Reference {v} attached.", module)] == []


# --------------------------------------------------------------------------- cards
BRANDS = {  # prefix choices, lengths
    "visa": (["4"], [13, 16, 19]),
    "mastercard": (["51", "53", "55", "2221", "2720"], [16]),
    "amex": (["34", "37"], [15]),
    "discover": (["6011", "65", "644", "649"], [16, 19]),
    "jcb": (["3528", "3589"], [16]),
    "diners": (["300", "305", "36", "38"], [14]),
    "unionpay": (["62"], [16, 19]),
    "maestro": (["50", "56", "69"], [13, 16, 19]),
    "mir": (["2200", "2204"], [16]),
}


def cards(brand: str) -> list[str]:
    rng = random.Random(brand)
    prefixes, lengths = BRANDS[brand]
    out = []
    for _ in range(N):
        prefix, length = rng.choice(prefixes), rng.choice(lengths)
        body = prefix + _digits(rng, length - len(prefix) - 1)
        out.append(body + luhn.calc_check_digit(body))
    return out


def _grouped(number: str, sep: str) -> str:
    if len(number) == 15:  # Amex grouping 4-6-5
        return sep.join((number[:4], number[4:10], number[10:]))
    return sep.join(number[i : i + 4] for i in range(0, len(number), 4))


@pytest.mark.parametrize("brand", sorted(BRANDS))
def test_cards_found_compact_spaced_and_dashed(brand: str) -> None:
    misses = []
    for number in cards(brand):
        for variant in (number, _grouped(number, " "), _grouped(number, "-")):
            spans = [s for s in patterns.find_cards(f"Card: {variant} exp 04/29") if s.type is E.CREDIT_CARD]
            if not any(s.canonical == number for s in spans):
                misses.append(variant)
    assert misses == []


@pytest.mark.parametrize("brand", sorted(BRANDS))
def test_cards_with_one_wrong_digit_are_rejected(brand: str) -> None:
    accepted = []
    for number in cards(brand):
        i = len(number) // 2
        bad = number[:i] + str((int(number[i]) + 1) % 10) + number[i + 1 :]
        if any(s.type is E.CREDIT_CARD for s in patterns.find_cards(f"Card: {bad}")):
            accepted.append(bad)
    assert accepted == []


# --------------------------------------------------------------------------- IBAN
IBAN_EXAMPLES = [
    "AL47212110090000000235698741",
    "AD1200012030200359100100",
    "AT611904300234573201",
    "AZ21NABZ00000000137010001944",
    "BH67BMAG00001299123456",
    "BE68539007547034",
    "BA391290079401028494",
    "BG80BNBG96611020345678",
    "HR1210010051863000160",
    "CY17002001280000001200527600",
    "CZ6508000000192000145399",
    "DK5000400440116243",
    "EE382200221020145685",
    "FO6264600001631634",
    "FI2112345600000785",
    "FR1420041010050500013M02606",
    "GE29NB0000000101904917",
    "DE89370400440532013000",
    "GI75NWBK000000007099453",
    "GR1601101250000000012300695",
    "GL8964710001000206",
    "HU42117730161111101800000000",
    "IS140159260076545510730339",
    "IE29AIBK93115212345678",
    "IL620108000000099999999",
    "IT60X0542811101000000123456",
    "JO94CBJO0010000000000131000302",
    "KZ86125KZT5004100100",
    "XK051212012345678906",
    "KW81CBKU0000000000001234560101",
    "LV80BANK0000435195001",
    "LB62099900000001001901229114",
    "LI21088100002324013AA",
    "LT121000011101001000",
    "LU280019400644750000",
    "MK07250120000058984",
    "MT84MALT011000012345MTLCAST001S",
    "MR1300020001010000123456753",
    "MD24AG000225100013104168",
    "MC5811222000010123456789030",
    "ME25505000012345678951",
    "NL91ABNA0417164300",
    "NO9386011117947",
    "PK36SCBL0000001123456702",
    "PL61109010140000071219812874",
    "PT50000201231234567890154",
    "QA58DOHB00001234567890ABCDEFG",
    "RO49AAAA1B31007593840000",
    "SM86U0322509800000000270100",
    "SA0380000000608010167519",
    "RS35260005601001611379",
    "SK3112000000198742637541",
    "SI56263300012039086",
    "ES9121000418450200051332",
    "SE4550000000058398257466",
    "CH9300762011623852957",
    "TN5910006035183598478831",
    "TR330006100519786457841326",
    "AE070331234567890123456",
    "GB29NWBK60161331926819",
    "VG96VPVG0000012345678901",
    "BR1800360305000010009795493C1",
    "CR05015202001026284066",
    "DO28BAGR00000001212453611324",
    "UA213223130000026007233566001",
]
IBANS = [i for i in IBAN_EXAMPLES if std_iban.is_valid(i)]


def test_iban_examples_are_valid() -> None:
    assert len(IBANS) >= 55


@pytest.mark.parametrize("variant", ["compact", "grouped", "lower", "grouped-lower"])
def test_ibans_found(variant: str) -> None:
    misses = []
    for value in IBANS:
        text = {
            "compact": value,
            "grouped": " ".join(value[i : i + 4] for i in range(0, len(value), 4)),
            "lower": value.lower(),
            "grouped-lower": " ".join(value[i : i + 4] for i in range(0, len(value), 4)).lower(),
        }[variant]
        if not any(s.type is E.IBAN for s in patterns.find_all(f"Pay to {text} today.", REGIONS)):
            misses.append(text)
    assert misses == []


def test_ibans_with_wrong_check_digits_are_rejected() -> None:
    accepted = []
    for value in IBANS:
        bad = value[:2] + f"{(int(value[2:4]) + 1) % 100:02d}" + value[4:]
        if not std_iban.is_valid(bad) and any(s.type is E.IBAN for s in patterns.find_all(bad, REGIONS)):
            accepted.append(bad)
    assert accepted == []


# --------------------------------------------------------------------------- phones
def _region_numbers() -> list[tuple[str, phonenumbers.PhoneNumber]]:
    out = []
    for region in sorted(phonenumbers.SUPPORTED_REGIONS):
        for kind in (phonenumbers.PhoneNumberType.FIXED_LINE, phonenumbers.PhoneNumberType.MOBILE):
            number = phonenumbers.example_number_for_type(region, kind)
            if number is not None and phonenumbers.is_valid_number(number):
                out.append((region, number))
    return out


@pytest.mark.parametrize("fmt", ["INTERNATIONAL", "E164"])
def test_every_country_international_number_is_found(fmt: str) -> None:
    style = getattr(phonenumbers.PhoneNumberFormat, fmt)
    numbers = _region_numbers()
    misses = []
    for region, number in numbers:
        shown = phonenumbers.format_number(number, style)
        text = f"Call me on {shown} tomorrow."
        start = text.index(shown)
        if not any(s.type is E.PHONE and s.start <= start + 1 and s.end >= start + len(shown) - 1
                   for s in patterns.find_all(text, REGIONS)):  # fmt: skip
            misses.append(f"{region} {shown}")
    assert len(numbers) > 400
    assert misses == []


@pytest.mark.parametrize("region", REGIONS)
def test_national_format_in_configured_regions(region: str) -> None:
    misses = []
    for kind in (phonenumbers.PhoneNumberType.FIXED_LINE, phonenumbers.PhoneNumberType.MOBILE):
        number = phonenumbers.example_number_for_type(region, kind)
        shown = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.NATIONAL)
        if not any(s.type is E.PHONE for s in patterns.find_all(f"tel {shown}", REGIONS)):
            misses.append(shown)
    assert misses == []


# --------------------------------------------------------------------------- emails
@pytest.mark.parametrize(
    "email",
    [
        "jane.doe@example.com", "JANE.DOE@EXAMPLE.COM", "jane+tag@sub.example.co.uk", "j_o-e.x@mail-example.org",
        "x@y.io", "first.last@xn--bcher-kva.de", "jane@bücher.de", "o'connor@example.ie", "1234567890@example.com",
        "jane.doe@example.museum", "user@[192.168.1.10]",
    ],
)  # fmt: skip
@pytest.mark.parametrize("wrap", ["{}", "<{}>", "({})", "mailto:{}", '"{}"', "{}.", "{},", "email:{}"])
def test_emails_in_any_wrapping(email: str, wrap: str) -> None:
    text = f"Contact {wrap.format(email)} today"
    assert any(s.type is E.EMAIL for s in patterns.find_all(text, REGIONS)), text


# --------------------------------------------------------------------------- crypto, devices
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _b58check(version: int, payload: bytes) -> str:
    raw = bytes([version]) + payload
    raw += hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    n, out = int.from_bytes(raw, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def _polymod(values: list[int]) -> int:
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i, g in enumerate((0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)):
            chk ^= g if (top >> i) & 1 else 0
    return chk


def _segwit(hrp: str, version: int, program: bytes) -> str:
    acc = bits = 0
    data = [version]
    for byte in program:
        acc, bits = (acc << 8) | byte, bits + 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    pm = _polymod(expanded + data + [0] * 6) ^ (1 if version == 0 else 0x2BC830A3)
    return hrp + "1" + "".join(_BECH[d] for d in data + [(pm >> 5 * (5 - i)) & 31 for i in range(6)])


def test_bitcoin_and_ethereum_addresses() -> None:
    rng = random.Random(7)
    addresses = []
    for _ in range(N):
        addresses.append(_b58check(rng.choice([0, 5]), rng.randbytes(20)))
        addresses.append(_segwit("bc", 0, rng.randbytes(20)))
        addresses.append(_segwit("bc", 1, rng.randbytes(32)))
        addresses.append("0x" + rng.randbytes(20).hex())
    misses = [a for a in addresses if not any(s.type is E.CRYPTO_ADDRESS for s in find_crypto(f"send to {a} now"))]
    assert misses == []
    corrupted = [a[:-1] + ("2" if a[-1] != "2" else "3") for a in addresses if not a.startswith("0x")]
    assert [a for a in corrupted if any(find_crypto(f"send to {a}"))] == []


def _vin(rng: random.Random) -> str:
    chars = "ABCDEFGHJKLMNPRSTUVWXYZ0123456789"
    body = [rng.choice(chars) for _ in range(17)]
    for check in "0123456789X":
        body[8] = check
        if vin_check_digit_ok("".join(body)):
            return "".join(body)
    raise AssertionError


def test_devices_vin_imei_mac() -> None:
    rng = random.Random(11)
    misses = []
    for _ in range(N):
        vin = _vin(rng)
        if not any(s.type is E.DEVICE_ID for s in find_devices(f"car {vin} sold")):
            misses.append(vin)
        imei = _digits(rng, 14)
        imei += luhn.calc_check_digit(imei)
        if not any(s.type is E.DEVICE_ID for s in find_devices(f"IMEI {imei}")):
            misses.append(imei)
        mac = rng.randbytes(6).hex()
        for shown in (":".join(mac[i : i + 2] for i in range(0, 12, 2)), "-".join(mac[i : i + 2] for i in range(0, 12, 2)).upper(),
                      ".".join(mac[i : i + 4] for i in range(0, 12, 4))):  # fmt: skip
            if not any(s.type is E.DEVICE_ID for s in find_devices(f"MAC {shown}")):
                misses.append(shown)
    assert misses == []


def test_routing_numbers_need_a_valid_checksum() -> None:
    from stdnum.us import rtn

    rng = random.Random(3)
    for _ in range(N):
        body = _digits(rng, 8)
        good = body + rtn.calc_check_digit(body)
        bad = body + str((int(good[-1]) + 1) % 10)
        assert any(s.type is E.ACCOUNT_ID for s in find_cued_numbers(f"routing number {good}"))
        assert not any("routing" in src for s in find_cued_numbers(f"routing number {bad}") for src in s.sources)
