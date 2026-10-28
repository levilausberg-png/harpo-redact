"""Layer 2b: identifiers beyond the core set, each validated before it counts.

* 15 national and tax ID types across 12 countries, checked with python-stdnum. Formats
  that collide with other numbers (10-digit NHS, 9-digit SIN) also need a cue
  word just before the value.
* Account, routing, medical record, member, policy and claim numbers;
  passports and driving licences: cue word required.
* Devices: MAC addresses, IMEI (Luhn + cue), VIN (check digit or cue).
* Crypto addresses: Bitcoin base58check and bech32/bech32m checksums,
  Ethereum 0x addresses.
* Street addresses (US, UK, NL, DE, BE), UK postcodes, US state + ZIP, NL
  postcode + city.
* All dates (typed DATE; allowed by default, redacted under HIPAA-style policy).
* Escaped text: %40, &#64;, \\u0040 and "jane at example dot com" are decoded
  in a shadow view so encoded emails, cards and keys are still found.

Every pattern here is linear in Python's engine: no nested quantifiers.
"""

from __future__ import annotations

import hashlib
import html
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from datetime import date
from importlib import import_module

from ..entities import EntityType as E
from ..entities import Span, make_span
from .addresses import find_labelled_addresses, find_street_addresses
from .cjk import find_cjk_addresses
from .cued import find_cued_values, find_value_shapes
from .formats import find_formats
from .opaque import find_opaque_codes
from .patterns import _DATE
from .regional import find_regional
from .secrets import is_encoded_text

SOURCE = "identifier"


def cue_words(phrase: str) -> str:
    """A cue phrase as a pattern that also matches it as a field name.

    "social insurance" matches "Social Insurance", "social_insurance", "socialInsurance" and "SOCIAL-INSURANCE".
    A cue is a whole word on the left. On the right it may run into the next part of a field name ("nhs_number",
    "nhsNumber") but not into more lowercase letters; a phrase ending in "*" is a prefix ("rijksregister*" also
    matches "rijksregisternummer"). Words are regex fragments matched case-insensitively.
    """
    prefix = phrase.endswith("*")
    words = phrase.rstrip("*").split(" ")
    body = r"[\s_.\-]{0,3}".join(f"(?i:{w})" for w in words)
    return rf"(?<![A-Za-z]){body}" + ("" if prefix else r"(?![a-z])")


def _cue(*parts: str, case_sensitive: tuple[str, ...] = ()) -> re.Pattern[str]:
    alternatives = [cue_words(p) for p in parts] + [rf"(?<![A-Za-z]){p}(?![A-Za-z])" for p in case_sensitive]
    return re.compile("|".join(alternatives))


def _has_cue(text: str, start: int, cue: re.Pattern[str], window: int = 48) -> bool:
    return cue.search(text, max(0, start - window), start) is not None


# --------------------------------------------------------------------------- national IDs
@dataclass(frozen=True, slots=True)
class _Scheme:
    module: str
    pattern: re.Pattern[str]
    cue: re.Pattern[str] | None
    validator: Callable[[str], bool]


def _stdnum(module: str) -> Callable[[str], bool]:
    mod = import_module(f"stdnum.{module}")

    def check(value: str) -> bool:
        try:
            return bool(mod.is_valid(value))
        except Exception:  # stdnum raises various ValueError subclasses
            return False

    return check


def _scheme(module: str, pattern: str, cue: re.Pattern[str] | None = None, *, letters: bool = False) -> _Scheme:
    # Lettered IDs are matched in any case ("x2482300w") and validated upper-cased.
    return _Scheme(module, re.compile(pattern, re.IGNORECASE if letters else 0), cue, _stdnum(module))


def _date_ok(year: int, month: int, day: int) -> bool:
    try:
        date(year, month, day)
    except ValueError:
        return False
    return True


def _cn_ric(value: str) -> bool:
    """China's resident identity number: an area, the birth date, a sequence and a check character. The birth date
    must be a real one; the check character is not required (a mistyped last character is still the number)."""
    return _date_ok(int(value[6:10]), int(value[10:12]), int(value[12:14]))


def _kr_rrn(value: str) -> bool:
    """Korea's resident registration number, YYMMDD-GNNNNNN: G gives the century, so the birth date can be checked.
    Numbers issued since October 2020 carry no check digit, so none is required."""
    digits = value.replace("-", "")
    century = {"9": 1800, "0": 1800, "1": 1900, "2": 1900, "5": 1900, "6": 1900}.get(digits[6], 2000)
    return _date_ok(century + int(digits[:2]), int(digits[2:4]), int(digits[4:6]))


_SCHEMES: tuple[_Scheme, ...] = (
    _Scheme(
        "cn.ric",
        re.compile(
            r"(?<![\dA-Za-z])[1-8]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![\dA-Za-z])"
        ),
        None,
        _cn_ric,
    ),
    _Scheme(
        "kr.rrn",
        re.compile(r"(?<![\d\-])\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])-[1-8]\d{6}(?![\d\-])"),
        None,
        _kr_rrn,
    ),
    _scheme("gb.nhs", r"(?<!\d)\d{3}[ -]?\d{3}[ -]?\d{4}(?!\d)", _cue("nhs")),
    _scheme("ca.sin", r"(?<!\d)\d{3}[ -]?\d{3}[ -]?\d{3}(?!\d)", _cue("social insurance*", case_sensitive=("SIN",))),
    _scheme("fr.nir", r"(?<!\d)[12] ?\d{2} ?(?:0[1-9]|1[0-2]|[2-9]\d) ?(?:\d{2}|2[AB]) ?\d{3} ?\d{3} ?\d{2}(?!\d)"),
    _scheme("es.dni", r"(?<![\dA-Za-z])\d{8}-?[A-HJ-NP-TV-Z](?![\dA-Za-z])", letters=True),
    _scheme("es.nie", r"(?<![\dA-Za-z])[XYZ]-?\d{7}-?[A-HJ-NP-TV-Z](?![\dA-Za-z])", letters=True),
    _scheme(
        "it.codicefiscale",
        r"(?<![A-Z0-9])[A-Z]{6}[0-9LMNPQRSTUV]{2}[ABCDEHLMPRST][0-9LMNPQRSTUV]{2}[A-Z][0-9LMNPQRSTUV]{3}[A-Z](?![A-Z0-9])",
        letters=True,
    ),
    _scheme(
        "be.nn",
        r"(?<!\d)\d{2}\.?\d{2}\.?\d{2}[- ]?\d{3}\.? ?\d{2}(?!\d)",
        _cue("rijksregister*", "national (?:number|register)*", "num[ée]ro national*", "insz", "niss"),
    ),
    _scheme(
        "de.idnr",
        r"(?<!\d)\d{2} ?\d{3} ?\d{3} ?\d{3}(?!\d)",
        _cue("steuer*", "idnr", "identifikationsnummer*", "tax id*"),
    ),
    _scheme("in_.aadhaar", r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)", _cue("aadhaa?r*", "uidai")),
    _scheme("in_.pan", r"(?<![A-Z0-9])[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z](?![A-Z0-9])", letters=True),
    _scheme("au.tfn", r"(?<!\d)\d{3} ?\d{3} ?\d{2,3}(?!\d)", _cue("tfn", "tax file*")),
    _scheme("br.cpf", r"(?<!\d)\d{3}\.\d{3}\.\d{3}-\d{2}(?!\d)"),
    _scheme("br.cpf", r"(?<!\d)\d{11}(?!\d)", _cue("cpf")),
    _scheme("mx.curp", r"(?<![A-Z0-9])[A-Z]{4}\d{6}[HMX][A-Z]{5}[0-9A-Z]\d(?![A-Z0-9])", letters=True),
    _scheme("us.itin", r"(?<!\d)9\d{2}-?(?:5\d|6[0-5]|7\d|8[0-8]|9[0-24-9])-?\d{4}(?!\d)"),
    _scheme("us.ein", r"(?<!\d)\d{2}-?\d{7}(?!\d)", _cue("f?ein", "employer identification*", "tax id*")),
)


def find_national_ids(text: str) -> Iterator[Span]:
    for scheme in _SCHEMES:
        if scheme.cue is not None and scheme.cue.search(text) is None:
            continue  # no cue word anywhere: skip the scan (most prose)
        for m in scheme.pattern.finditer(text):
            if scheme.cue is not None and not _has_cue(text, m.start(), scheme.cue):
                continue
            value = m.group()
            if scheme.validator(value.upper()):
                canonical = re.sub(r"[\s.\-]", "", value).upper()
                yield make_span(m.start(), m.end(), E.NATIONAL_ID, f"{SOURCE}:{scheme.module}", canonical, 0.95)


# --------------------------------------------------------------------------- numbers that need a cue word
_NOUN = r"(?:(?:number|nummer|numero|numéro|num|id|no|nr)(?![a-z])\.?|#)"
_LINK = r"(?:is|was|=>|->|:|#|=|\|)"
# Between a cue and its value: a field-name joint, the noun, a parenthetical, quotes, a linking word or sign and
# markup ("passport_number": "X", passport_number='X', | passport number | X |, <th>Passport</th><td>X</td>,
# "passport number (as printed): X"). Every piece is bounded, so matching stays linear.
_VALUE = (
    rf"[\s_.\-]{{0,3}}{_NOUN}?(?:\s{{0,2}}\([^()\n]{{0,30}}\))?[\"'`]?(?:\s{{0,3}}{_LINK})?"
    rf"(?:\s{{0,3}}</?[A-Za-z][^<>\n]{{0,40}}>){{0,4}}\s{{0,3}}[\"'`]?\s{{0,2}}"
    r"(?!(?:base(?:64|32|58)|hex|sha\d*|md5|utf-?8|ascii)\b)"  # "passport number (base64): ..." names a format
)
# Words between the noun and the value in prose: "passport number on file is X", "account number we hold was X".
_FILLED = rf"[\s_.\-]{{0,3}}{_NOUN}(?:\s{{1,3}}[A-Za-z]{{2,12}}){{1,4}}?\s{{1,3}}(?:is|was|reads)\s{{1,3}}[\"'`]?"
_GAP = rf"(?:{_FILLED}|{_VALUE})"
_SEP = r"[\s_.\-]{0,3}"
_ACCOUNT_RE = re.compile(
    rf"(?i)(?<![A-Za-z])(?P<cue>(?:bank{_SEP})?account|acct|a/c|rekening(?:nummer)?|konto(?:nummer)?|mrn"
    rf"|medical{_SEP}record|patient|member|policy|health{_SEP}plan|beneficiary|claim|subscriber|customer"
    # "social insurance number" and "national insurance number" have their own checked formats (SIN, NINO)
    rf"|(?<!social.)(?<!national.)(?<!social)(?<!national)insurance)" + _GAP + r"(?P<value>[A-Z0-9][A-Z0-9-]{3,22})\b"
)
# How much a cue says on its own. Explicit ones name an account or record number ("MRN: A1234567"). A person word
# ("customer", "account") without "number", "no", "id" or "#" names a number only when the value is all digits:
# "account: prod-eu-1" is an account's name. "policy", "claim" and "insurance" also hold amounts and names
# ("policy": "net-30", "claim": 1500000), so they need the noun.
_EXPLICIT_ACCOUNT_RE = re.compile(r"(?i)acct|a/c|mrn|medical|rekening|konto")
_AMOUNT_CUE_RE = re.compile(r"(?i)policy|claim|insurance|health")
_NOUN_RE = re.compile(r"(?i)(?<![a-z])(?:number|nummer|numero|numéro|num|id|no|nr)(?![a-z])|#")
_ANY_DATE_SHAPE_RE = re.compile(r"\d{1,4}[-/.]\d{1,2}(?:[-/.]\d{1,4})?")
_ROUTING_RE = re.compile(r"(?i)(?<![A-Za-z])(?:routing|aba|rtn)" + _GAP + r"(\d{9})\b")
_DOCUMENT_RE = re.compile(
    rf"(?i)(?<![A-Za-z])(?:passport|paspoort|reisepass|passeport|driver'?s?{_SEP}licen[cs]e|driving{_SEP}licen[cs]e"
    rf"|rijbewijs|f(?:ü|ue)hrerschein|id{_SEP}card|identity{_SEP}card|national{_SEP}id(?:{_SEP}card)?)"
    + _GAP
    + r"([A-Z0-9][A-Z0-9-]{4,15})\b"
)


def _has_digit(value: str) -> bool:
    return any(c.isdigit() for c in value)


def _cued_value(value: str) -> bool:
    """A cued account or document number has a digit. A base64 run of readable text is not one: it is encoded
    content, decoded and judged by what it says (secrets.find_encoded). Account and passport numbers never decode
    to readable text (0 in 200,000 generated ones), so nothing real is lost."""
    return _has_digit(value) and not is_encoded_text(value)


def _account_cue_fits(cue: str, gap: str, value: str) -> bool:
    if _EXPLICIT_ACCOUNT_RE.match(cue) or _NOUN_RE.search(gap):
        return True
    if _AMOUNT_CUE_RE.match(cue):
        return False
    digits = re.sub(r"[\s.\-]", "", value)
    return digits.isdigit() and len(digits) >= 6 and not _ANY_DATE_SHAPE_RE.fullmatch(value)


def find_cued_numbers(text: str) -> Iterator[Span]:
    for m in _ROUTING_RE.finditer(text):
        if _stdnum("us.rtn")(m.group(1)):
            yield make_span(m.start(1), m.end(1), E.ACCOUNT_ID, f"{SOURCE}:routing", m.group(1), 0.9)
    for m in _ACCOUNT_RE.finditer(text):
        value = m.group("value")
        gap = text[m.end("cue") : m.start("value")]
        if not _cued_value(value) or not _account_cue_fits(m.group("cue"), gap, value):
            continue
        yield make_span(m.start("value"), m.end("value"), E.ACCOUNT_ID, f"{SOURCE}:account", value.upper(), 0.8)
    for m in _DOCUMENT_RE.finditer(text):
        if _cued_value(m.group(1)):
            value = m.group(1)
            yield make_span(m.start(1), m.end(1), E.ID_DOCUMENT, f"{SOURCE}:document", value.upper(), 0.8)


# --------------------------------------------------------------------------- devices
_MAC_RE = re.compile(r"(?<![0-9A-Fa-f:-])[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])")
_MAC_DOTTED_RE = re.compile(r"(?<![0-9A-Fa-f.])[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}(?![0-9A-Fa-f.])")
_IMEI_RE = re.compile(r"(?<!\d)\d{2}[- ]?\d{6}[- ]?\d{6}[- ]?\d(?!\d)")
_IMEI_CUE = _cue("imei")
_MAC_CUE = _cue("mac", "hardware address*")
_VIN_RE = re.compile(r"(?<![A-Z0-9])[A-HJ-NPR-Z0-9]{17}(?![A-Z0-9])")
_VIN_CUE = _cue("vin", "chassis*", "vehicle identification*")
_SERIAL_RE = re.compile(r"(?i)(?<![A-Za-z])(?:serial|s/n)" + _GAP + r"([A-Z0-9][A-Z0-9-]{4,24})\b")
_VIN_VALUES = {**{str(d): d for d in range(10)}, **dict(zip("ABCDEFGH", range(1, 9), strict=True))}
_VIN_VALUES.update(dict(zip("JKLMNPR", (1, 2, 3, 4, 5, 7, 9), strict=True)))
_VIN_VALUES.update(dict(zip("STUVWXYZ", range(2, 10), strict=True)))
_VIN_WEIGHTS = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def vin_check_digit_ok(vin: str) -> bool:
    total = sum(_VIN_VALUES[c] * w for c, w in zip(vin, _VIN_WEIGHTS, strict=True))
    expected = "X" if total % 11 == 10 else str(total % 11)
    return vin[8] == expected


def find_devices(text: str) -> Iterator[Span]:
    for m in _MAC_RE.finditer(text):
        yield make_span(m.start(), m.end(), E.DEVICE_ID, f"{SOURCE}:mac", m.group().lower().replace("-", ":"), 0.9)
    for m in _MAC_DOTTED_RE.finditer(text):  # Cisco style aabb.ccdd.eeff
        if any(c.isalpha() for c in m.group()) or _has_cue(text, m.start(), _MAC_CUE):
            yield make_span(m.start(), m.end(), E.DEVICE_ID, f"{SOURCE}:mac", m.group().lower(), 0.85)
    for m in _IMEI_RE.finditer(text) if _IMEI_CUE.search(text) else ():
        digits = re.sub(r"\D", "", m.group())
        if _has_cue(text, m.start(), _IMEI_CUE) and _luhn_ok(digits):
            yield make_span(m.start(), m.end(), E.DEVICE_ID, f"{SOURCE}:imei", digits, 0.9)
    for m in _VIN_RE.finditer(text):
        vin = m.group()
        if not (_has_digit(vin) and any(c.isalpha() for c in vin)):
            continue
        if vin_check_digit_ok(vin) or _has_cue(text, m.start(), _VIN_CUE):
            yield make_span(m.start(), m.end(), E.DEVICE_ID, f"{SOURCE}:vin", vin, 0.9)
    for m in _SERIAL_RE.finditer(text):
        if _has_digit(m.group(1)):
            yield make_span(m.start(1), m.end(1), E.DEVICE_ID, f"{SOURCE}:serial", m.group(1).upper(), 0.8)


# --------------------------------------------------------------------------- crypto addresses
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_RE = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[13][1-9A-HJ-NP-Za-km-z]{25,34}(?![1-9A-HJ-NP-Za-km-z])")
_BECH32_RE = re.compile(r"(?<![a-z0-9])(?:bc|tb)1[02-9ac-hj-np-z]{11,71}(?![a-z0-9])")
_ETH_RE = re.compile(r"(?<![0-9A-Za-z])0x[0-9a-fA-F]{40}(?![0-9A-Za-z])")
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def base58check_ok(address: str) -> bool:
    number = 0
    for ch in address:
        number = number * 58 + _B58.index(ch)
    raw = number.to_bytes(25, "big") if number.bit_length() <= 200 else b""
    if len(raw) != 25:
        return False
    return hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] == raw[21:]


def bech32_ok(address: str) -> bool:
    hrp, _, data = address.rpartition("1")
    values = [_BECH32_CHARSET.find(c) for c in data]
    if not hrp or len(values) < 6 or -1 in values:
        return False
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + values:
        top = checksum >> 25
        checksum = (checksum & 0x1FFFFFF) << 5 ^ value
        for i, g in enumerate(generator):
            checksum ^= g if (top >> i) & 1 else 0
    return checksum in (1, 0x2BC830A3)  # bech32 or bech32m


def find_crypto(text: str) -> Iterator[Span]:
    for m in _B58_RE.finditer(text):
        if base58check_ok(m.group()):
            yield make_span(m.start(), m.end(), E.CRYPTO_ADDRESS, f"{SOURCE}:btc", m.group(), 0.95)
    for m in _BECH32_RE.finditer(text):
        if bech32_ok(m.group()):
            yield make_span(m.start(), m.end(), E.CRYPTO_ADDRESS, f"{SOURCE}:btc", m.group(), 0.95)
    for m in _ETH_RE.finditer(text):
        yield make_span(m.start(), m.end(), E.CRYPTO_ADDRESS, f"{SOURCE}:eth", m.group().lower(), 0.9)


# --------------------------------------------------------------------------- addresses
_US_SUFFIX = (
    r"Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Terrace|Ter|Parkway|Pkwy|Highway|Hwy"
    r"|Crescent|Cres|Mews|Trail|Trl|Alley|Aly"
)
_US_SUFFIX_AMBIGUOUS = r"Way|Place|Pl|Court|Ct|Circle|Cir|Square|Sq|Close|Grove"
_UNIT = r"(?:,?\s+(?:Apt|Apartment|Suite|Ste|Unit|Floor|Fl|#)\.?\s*[\w-]{1,6})?"
_US_STREET_BODY = (
    r"\b\d{1,6}[A-Za-z]?\s+(?:(?:N|S|E|W|NE|NW|SE|SW|North|South|East|West)\.?\s+)?"
    r"(?:[A-Z][a-z]+\.?\s+|\d{1,3}(?:st|nd|rd|th)\s+){1,4}"
)
_US_DIRECTION = r"(?:[ \t]+(?:N|S|E|W|NE|NW|SE|SW)\b\.?)?"  # "Peachtree St NE"
_US_STREET_RE = re.compile(_US_STREET_BODY + rf"(?:{_US_SUFFIX})\b\.?" + _US_DIRECTION + _UNIT)
_US_STREET_AMBIGUOUS_RE = re.compile(
    _US_STREET_BODY + rf"(?:{_US_SUFFIX_AMBIGUOUS})\b\.?" + _US_DIRECTION + _UNIT + r"(?=\s*(?:,|\n|$))"
)
# A post office box ("P.O. Box 1234", "Postbus 512", "Postfach 10 20 30", "Apartado de Correos 45") and a US military
# address ("PSC 1234, Box 5678", "APO AE 09204").
_PO_BOX_RE = re.compile(
    r"(?<![\w.])(?:P\.?[ \t]?O\.?[ \t]?Box|Post[ \t]+Office[ \t]+Box|Postbus|Postfach|Antwoordnummer"
    r"|Bo[îi]te[ \t]+postale|Apartado(?:[ \t]+de[ \t]+[Cc]orreos)?|Casella[ \t]+[Pp]ostale|Caixa[ \t]+[Pp]ostal|PMB"
    r"|PSC[ \t]+\d{1,5},?[ \t]+Box)"
    r"[ \t]*#?[ \t]*\d{1,6}(?:[ \t]\d{2}){0,2}(?![\w])"
    r"|(?<![\w])(?:APO|FPO|DPO)[ \t]+(?:AE|AP|AA)[ \t]+\d{5}(?:-\d{4})?(?![\w])"
)
# Dutch house numbers carry a letter, a number or a word after them: "12a", "12-3", "201bis", "79 hs", "14 II".
_HOUSE_SUFFIX = (
    r"(?:\s?(?:bis|hs|huis|rood|zw|[a-zA-Z])(?![a-zA-Z]))?(?:[-/]\d{1,4}[a-zA-Z]?)?(?:\s(?:I{1,3}|IV|hs|bis)(?![\w]))?"
)
_EU_STREET_RE = re.compile(
    r"\b(?:[A-Z][\w'’-]*\s){0,2}[A-Z][a-zäöüßéèëï'-]*"
    r"(?:straat|laan|weg|plein|gracht|kade|singel|dijk|dreef|steeg|stra(?:ß|ss)e|str\.|gasse|allee|platz|damm|ufer"
    r"|hof|park|markt|pad|wal|burgwal|dam|baan|veld|erf|oord|plantsoen|zijde|haven|brug|poort|straatweg|steenweg"
    r"|lei|kaai|vliet|wetering|ring|hoven|dreef|werf|gaarde|schans|rak|boulevard|rue|avenue)\s+\d{1,5}" + _HOUSE_SUFFIX
)
# A street without a street word, named by the small words Dutch and German streets start with ("Am Markt 26",
# "Aan de Amstel 12", "Unter den Linden 77").
_PREFIXED_STREET_RE = re.compile(
    r"(?<![^\W_])(?:Am|An[ \t]+der|An[ \t]+den|Auf[ \t]+dem|Auf[ \t]+der|Im|In[ \t]+der|In[ \t]+den|Zum|Zur"
    r"|Unter[ \t]+den|Hinter[ \t]+dem|Vor[ \t]+dem|Aan[ \t]+de|Aan[ \t]+het|Op[ \t]+de|Op[ \t]+het|In[ \t]+de"
    r"|In[ \t]+het"
    r"|Achter[ \t]+de|Bij[ \t]+de|Over[ \t]+de|Langs[ \t]+de|Voor[ \t]+de|Naast[ \t]+de)"
    r"[ \t]+[A-Z][\w'’\-]+(?:[ \t][A-Z][\w'’\-]+)?[ \t]+\d{1,5}" + _HOUSE_SUFFIX + r"(?=[ \t]*(?:[,;\n]|$))"
)
_UK_POSTCODE_RE = re.compile(
    r"\b(?:GIR ?0AA|[A-PR-UWYZ](?:\d{1,2}|[A-HK-Y]\d{1,2}|\d[A-HJKPSTUW]|[A-HK-Y]\d[ABEHMNPRV-Y])"
    r" ?\d[ABD-HJLNP-UW-Z]{2})\b"
)
_US_STATE_ZIP_RE = re.compile(
    r"\b(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND"
    r"|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)\s+\d{5}(?:-\d{4})?\b"
)
_NL_TOWN = (
    r"(?:['’]s-|['’]t[ \t])?(?:IJ[a-z]+|[A-Z][a-zé]+)(?:[ -](?:IJ[a-z]+|[A-Z][a-zé]+|aan|den|de|op|ter|ten|bij|in"
    r"|het|onder|over)){0,4}"
)
_NL_POSTCODE_CITY_RE = re.compile(
    r"\b[1-9]\d{3} ?(?!SA|SD|SS|MB|GB|KB|TB|PB|AD|BC|CE|AM|PM|HZ|KM|KG)[A-Z]{2}\s+" + _NL_TOWN + r"(?![\w'’-])"
)
_DE_PLZ_CITY_RE = re.compile(
    r"(?:(?<=, )|(?<=,)|(?<=\n))\d{5}\s+[A-Z][a-zäöüß]+(?:[ -](?:[A-Z][a-zäöüß]+|am|an|der|im|ob|bei|in|vor|zu)){0,3}"
    r"(?![\w-])"
)


# Words a post office box or a military address needs, and the small words a Dutch or German street can open with:
# a text without one of them is not scanned for those two patterns.
_PO_BOX_HINTS = tuple("box postbus postfach antwoordnummer postal apartado pmb psc apo fpo dpo".split())  # noqa: SIM905
_PREFIX_HINTS = tuple(
    f"{w} "
    for w in "Am An Auf Im In Zum Zur Unter Hinter Vor Aan Op Achter Bij Over Langs Voor Naast".split()  # noqa: SIM905
)


def find_addresses(text: str) -> Iterator[Span]:
    lowered = text.lower()
    patterns = [_US_STREET_RE, _US_STREET_AMBIGUOUS_RE, _EU_STREET_RE, _UK_POSTCODE_RE, _US_STATE_ZIP_RE,
                _NL_POSTCODE_CITY_RE, _DE_PLZ_CITY_RE]  # fmt: skip
    if any(hint in lowered for hint in _PO_BOX_HINTS):
        patterns.append(_PO_BOX_RE)
    if any(hint in text for hint in _PREFIX_HINTS):
        patterns.append(_PREFIXED_STREET_RE)
    for pattern in patterns:
        for m in pattern.finditer(text):
            canonical = " ".join(m.group().split()).casefold()
            yield make_span(m.start(), m.end(), E.ADDRESS, f"{SOURCE}:address", canonical, 0.85)


# --------------------------------------------------------------------------- dates
_ANY_DATE_RE = re.compile(rf"(?<![\d/.\-]){_DATE}(?![\d/\-]|\.\d)", re.IGNORECASE)


def find_dates(text: str) -> Iterator[Span]:
    for m in _ANY_DATE_RE.finditer(text):
        yield make_span(m.start(), m.end(), E.DATE, f"{SOURCE}:date", m.group().lower(), 0.8)


# --------------------------------------------------------------------------- escaped text
# Percent, HTML and backslash escapes, and the JSON string escapes (\\" \\\\ \\/ \\n \\r \\t) that wrap a JSON
# document inside another one.
_ESCAPE_RE = re.compile(
    r"%[0-9A-Fa-f]{2}|&#\d{2,7};|&#[xX][0-9A-Fa-f]{1,6};|&[A-Za-z]{2,8};|\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}"
    r'|\\["\\/nrt]'
)
_JSON_ESCAPES = {'\\"': '"', "\\\\": "\\", "\\/": "/", "\\n": "\n", "\\r": "\r", "\\t": "\t"}
_SPOKEN_EMAIL_RE = re.compile(
    r"(?i)(?<![\w.%+-])([a-z0-9][a-z0-9._%+-]{0,63})\s+(?:at|\(at\)|\[at\])\s+([a-z0-9-]{2,63})"
    r"((?:\s+(?:dot|\(dot\)|\[dot\])\s+[a-z0-9-]{2,24}){1,3})\b"
)


def _decode_one(token: str) -> str | None:
    if token.startswith("%"):
        value = int(token[1:], 16)
        return chr(value) if value < 128 else None  # multi-byte UTF-8 escapes stay as they are
    if token in _JSON_ESCAPES:
        return _JSON_ESCAPES[token]
    if token.startswith(("\\u", "\\x")):
        value = int(token[2:], 16)
        return None if 0xD800 <= value <= 0xDFFF else chr(value)  # lone surrogates stay encoded
    decoded = html.unescape(token)
    return decoded if decoded != token and len(decoded) == 1 else None


def decode_escapes(text: str) -> tuple[str, list[int], list[int]] | None:
    """A shadow copy with escapes decoded, plus per-character source ranges.

    Two rounds, so double encoding (%2540 -> %40 -> @) is undone too. Returns
    None when nothing is escaped, which is the common case.
    """
    first = _decode_once(text)
    if first is None:
        return None
    decoded, starts, ends = first
    second = _decode_once(decoded)
    if second is None:
        return first
    decoded2, starts2, ends2 = second
    return decoded2, [starts[i] for i in starts2], [ends[i - 1] for i in ends2]


def _decode_once(text: str) -> tuple[str, list[int], list[int]] | None:
    if not _ESCAPE_RE.search(text):
        return None
    out: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    cursor = 0
    for m in _ESCAPE_RE.finditer(text):
        decoded = _decode_one(m.group())
        if decoded is None:
            continue
        for i in range(cursor, m.start()):
            out.append(text[i])
            starts.append(i)
            ends.append(i + 1)
        out.append(decoded)
        starts.append(m.start())
        ends.append(m.end())
        cursor = m.end()
    if not out:
        return None
    for i in range(cursor, len(text)):
        out.append(text[i])
        starts.append(i)
        ends.append(i + 1)
    return "".join(out), starts, ends


def find_spoken_emails(text: str) -> Iterator[Span]:
    for m in _SPOKEN_EMAIL_RE.finditer(text):
        labels = re.findall(r"(?:dot|\(dot\)|\[dot\])\s+([a-z0-9-]+)", m.group(3), flags=re.IGNORECASE)
        canonical = f"{m.group(1)}@{m.group(2)}.{'.'.join(labels)}".lower()
        yield make_span(m.start(), m.end(), E.EMAIL, f"{SOURCE}:spoken-email", canonical, 0.8)


def find_identifiers(text: str, *, national_ids: bool, addresses: bool, devices: bool, crypto: bool,
                     cued_numbers: bool, dates: bool, spoken_emails: bool, regions: tuple[str, ...] = (),
                     machine_formats: bool = True, opaque_codes: bool = True,
                     context: bool = True) -> list[Span]:  # fmt: skip
    """``context`` runs the layers that read the words around a value (cue words, address grammar, formats). The
    shadow views (views.py: lines joined, characters spaced out, look-alikes, reversed text) skip them: they repair a
    value's characters, and the words around it are read in the text itself."""
    spans: list[Span] = []
    if national_ids:
        spans.extend(find_national_ids(text))
    if cued_numbers:
        spans.extend(find_cued_numbers(text))
        spans.extend(find_value_shapes(text))
        if context:
            spans.extend(find_cued_values(text))
    if opaque_codes and context:
        spans.extend(find_opaque_codes(text))
    if devices:
        spans.extend(find_devices(text))
    if context:
        spans.extend(find_formats(text, personal=machine_formats, crypto=crypto))
    if crypto:
        spans.extend(find_crypto(text))
    if addresses:
        spans.extend(find_addresses(text))
        if context:
            spans.extend(find_street_addresses(text))
            spans.extend(find_labelled_addresses(text))
            spans.extend(find_cjk_addresses(text))
    if dates:
        spans.extend(find_dates(text))
    if spoken_emails:
        spans.extend(find_spoken_emails(text))
    if regions:
        spans.extend(find_regional(text, regions))
    return spans


def remap(span: Span, starts: list[int], ends: list[int]) -> Span:
    """Move a span found in a decoded view back onto the text it came from."""
    return replace(span, start=starts[span.start], end=ends[span.end - 1], sources=span.sources | {"decoded"})
