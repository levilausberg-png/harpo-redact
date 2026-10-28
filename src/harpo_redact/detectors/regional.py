"""Layer 2g: region packs, for identifiers whose format is distinctive enough to find without a cue word.

The cue layer (detectors/cued.py) already finds any value after a word that names it, in some 30 languages. A pack
adds what a country or the EU writes in a format of its own, checked the way that format is checked, so the value is
found wherever it stands:

* ``nl``, the Netherlands: the btw-identificatienummer ("NL859221365B01", old and new checksums) and the
  loonheffingennummer ("859221365L01", the RSIN's eleven test).
* ``us``, the United States: a Social Security number with all but its last four digits masked ("XXX-XX-4820",
  "***-**-4820", "SSN ending in 4820": the last four are the part that is used to verify someone), the ATIN
  ("9XX-93-XXXX"), the Medicare Beneficiary Identifier in its printed form ("1EG4-TE5-MK73"), USCIS receipt numbers
  ("EAC2190012345", "WAC-22-012-50960") and the A-Number after its cue or in its own forms ("A-123-456-789",
  "A# 123456789").
* ``eu``, shared across the European Union: VAT identification numbers of every member state with their country
  prefix, checked against that state's check digits (python-stdnum's eu.vat), the BIC (ISO 9362) after its cue, and
  the unique identifier of an EU Digital COVID Certificate ("URN:UVCI:01:NL:...").

Machine-readable zones of passports and identity cards (ICAO 9303) are read by the machine formats layer
(detectors/formats.py). Every pattern is bounded, so a scan is linear in the length of the text.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator

from ..entities import EntityType as E
from ..entities import Span, make_span

SOURCE = "region"
REGIONS = ("nl", "us", "eu")


def _stdnum(module: str) -> Callable[[str], bool]:
    from importlib import import_module

    mod = import_module(f"stdnum.{module}")

    def check(value: str) -> bool:
        try:
            return bool(mod.is_valid(value))
        except Exception:  # stdnum raises various ValueError subclasses
            return False

    return check


def _compact(value: str) -> str:
    return re.sub(r"[\s.\-]", "", value).upper()


# --------------------------------------------------------------------------- the Netherlands
_NL_BTW_RE = re.compile(
    r"(?<![A-Za-z0-9])NL[ \t]?\d{4}[ .]?\d{2}[ .]?\d{3}[ .]?B[ .]?\d{2}(?![A-Za-z0-9])", re.IGNORECASE
)
_NL_LOONHEFFING_RE = re.compile(r"(?<![A-Za-z0-9])\d{9}[ .]?L[ .]?\d{2}(?![A-Za-z0-9])")
_nl_btw_ok = _stdnum("nl.btw")


def _eleven(digits: str) -> bool:
    """The eleven test of a BSN or RSIN: weights 9 down to 2, and -1 for the last digit."""
    weights = (9, 8, 7, 6, 5, 4, 3, 2, -1)
    return sum(int(d) * w for d, w in zip(digits, weights, strict=True)) % 11 == 0 and digits[:8] != "00000000"


def find_nl(text: str) -> Iterator[Span]:
    if "NL" in text or "nl" in text:
        for m in _NL_BTW_RE.finditer(text):
            if _nl_btw_ok(_compact(m.group())):
                yield make_span(m.start(), m.end(), E.NATIONAL_ID, f"{SOURCE}:nl.btw", _compact(m.group()), 0.95)
    if "L" in text:
        for m in _NL_LOONHEFFING_RE.finditer(text):
            digits = _compact(m.group())[:9]
            if _eleven(digits):
                yield make_span(m.start(), m.end(), E.NATIONAL_ID, f"{SOURCE}:nl.loonheffing", _compact(m.group()), 0.9)


# --------------------------------------------------------------------------- the United States
# The masked part, then the last four: "XXX-XX-4820", "***-**-4820", "xxx xx 4820", "###-##-4820".
_MASKED_SSN_RE = re.compile(r"(?<![\w*#])(?:[Xx*#•]{3})([ \-]?)(?:[Xx*#•]{2})\1(\d{4})(?![\d\-])")
# The last four after the words that name them: "SSN ending in 4820", "last four of your social: 4820",
# "SSN (last 4): 4820", "last 4 SSN 4820".
_SSN_WORDS = r"(?:ssn|social(?:[ \t]+security)?(?:[ \t]+(?:number|no\.?|#))?|ss[ \t]?#)"
_LAST4_RE = re.compile(
    rf"(?i)(?<![\w])(?:{_SSN_WORDS}[^\n\d]{{0,30}}?(?:ending|ends)[ \t]+(?:in|with)"
    rf"|{_SSN_WORDS}[ \t]*\([ \t]*last[ \t]+(?:4|four)[ \t]*\)"
    rf"|last[ \t]+(?:4|four)(?:[ \t]+digits)?(?:[ \t]+of)?(?:[ \t]+(?:the|my|your|his|her|their))?[ \t]+{_SSN_WORDS}"
    rf"(?:[ \t]+(?:is|was|are))?)"
    # the digits on the same line, or on the next one when the words ask for them ("...of your social?\nme: 4820")
    r"[^\d\n]{0,24}?(?:\n[^\d\n]{0,30}?)?(\d{4})(?!\d)"
)
_ATIN_RE = re.compile(r"(?<![\d-])9\d{2}-93-\d{4}(?![\d-])")
_MBI_LETTER = "ACDEFGHJKMNPQRTUVWXY"
_MBI_PRINTED_RE = re.compile(
    rf"[1-9](?<![A-Za-z0-9].)[{_MBI_LETTER}][{_MBI_LETTER}0-9]\d-[{_MBI_LETTER}][{_MBI_LETTER}0-9]\d-[{_MBI_LETTER}]{{2}}\d{{2}}"
    r"(?![A-Za-z0-9])"
)
_USCIS_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:EAC|WAC|LIN|SRC|NBC|MSC|IOE|YSC|TSC|VSC|NSC|CSC|ESC|SSC|BCI|ZLA|ZNY)"
    r"(?:\d{10}|[ \-]\d{2}[ \-]\d{3}[ \-]\d{5}|[ \-]\d{10})(?![A-Za-z0-9])"
)
_A_NUMBER_CUE = (
    r"(?:A[\-‐ ]?(?:Number|No\.?|Nr\.?|#)|Alien[ \t]+(?:Registration[ \t]+)?(?:Number|No\.?|#)"
    r"|USCIS[ \t]*(?:Number|No\.?|#)"
    r"|Alien[ \t]+File[ \t]+Number)"
)
_A_NUMBER_RE = re.compile(
    r"(?i:(?=[au]))"  # what every alternative starts with, tested first
    rf"(?:(?i:{_A_NUMBER_CUE})[ \t]*[:#=]?[ \t]*"
    rf"(?P<value>A?[ \t]?[#\-]?[ \t]?\d{{3}}[ \-]?\d{{3}}[ \-]?\d{{2,3}})(?![\d\-])"
    r"|(?<![A-Za-z0-9])(?P<own>A(?:-\d{3}-\d{3}-\d{3}|-\d{2}-\d{3}-\d{3}|#[ \t]?\d{8,9}))(?![\d\-]))"
)
_I94_RE = re.compile(
    r"(?i)(?<![\w])(?:I-?94|admission)[ \t]+(?:record[ \t]+)?(?:number|no\.?|#)[ \t]*[:#=]?[ \t]*(?P<value>\d{11}"
    r"|\d{9}[A-Z]\d)(?![\w])"
)


_USCIS_CENTRES = tuple("EAC WAC LIN SRC NBC MSC IOE YSC TSC VSC NSC CSC ESC SSC BCI ZLA ZNY".split())  # noqa: SIM905
# What an A-Number needs nearby: its cue ("A-Number", "Alien Registration No.", "USCIS #") or its own form ("A-...",
# "A#..."). Cheap substring checks first, so text without one is not scanned.
_A_NUMBER_HINTS = ("alien", "uscis", "a-", "a#", "a\u2010", "a number", "a no", "a nr", "anumber", "a #")


def find_us(text: str) -> Iterator[Span]:
    lowered = text.casefold()
    if "xxx" in lowered or "***" in text or "###" in text or "\u2022\u2022\u2022" in text:
        for m in _MASKED_SSN_RE.finditer(text):
            yield make_span(m.start(2), m.end(2), E.US_SSN, f"{SOURCE}:us.ssn-last4", m.group(2), 0.85)
    if "ssn" in lowered or "social" in lowered or "ss#" in lowered or "ss #" in lowered:
        for m in _LAST4_RE.finditer(text):
            yield make_span(m.start(1), m.end(1), E.US_SSN, f"{SOURCE}:us.ssn-last4", m.group(1), 0.85)
    if "-93-" in text:
        for m in _ATIN_RE.finditer(text):
            yield make_span(m.start(), m.end(), E.NATIONAL_ID, f"{SOURCE}:us.atin", m.group().replace("-", ""), 0.9)
    if "-" in text:
        for m in _MBI_PRINTED_RE.finditer(text):
            yield make_span(m.start(), m.end(), E.ACCOUNT_ID, f"{SOURCE}:us.mbi", m.group().replace("-", ""), 0.9)
    if any(centre in text for centre in _USCIS_CENTRES):
        for m in _USCIS_RE.finditer(text):
            yield make_span(m.start(), m.end(), E.ACCOUNT_ID, f"{SOURCE}:us.uscis", _compact(m.group()), 0.9)
    if any(hint in lowered for hint in _A_NUMBER_HINTS):
        for m in _A_NUMBER_RE.finditer(text):
            group = "value" if m.group("value") else "own"
            yield make_span(
                m.start(group), m.end(group), E.ID_DOCUMENT, f"{SOURCE}:us.a-number", _compact(m.group(group)), 0.85
            )
    if "94" in text or "admission" in lowered:
        for m in _I94_RE.finditer(text):
            yield make_span(m.start("value"), m.end("value"), E.ID_DOCUMENT, f"{SOURCE}:us.i94", m.group("value"), 0.85)


# --------------------------------------------------------------------------- the European Union
# The country code comes first and the check that nothing is glued before it second, so a scan only stops at capitals.
_EU_VAT_RE = re.compile(
    r"(?P<cc>AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK|XI)(?<![A-Za-z0-9]..)"
    r"[ \t]?(?P<body>[0-9A-Z](?:[0-9A-Z]|[ .\-](?=[0-9A-Z])){6,15})(?![A-Za-z0-9])"
)
_eu_vat_ok = _stdnum("eu.vat")
# The cue in any case ("BIC", "Swift code"), the code in capitals as it is written: "of swift destruction" is prose.
_BIC_CUE_RE = re.compile(
    r"(?<![\w])(?i:BIC|SWIFT)(?:[ \t\-]?(?i:code|nr\.?|no\.?|number|nummer|address))?[ \t]*[:#=/]?[ \t]*"
    r"(?P<value>[A-Z]{4}[ \t]?[A-Z]{2}[ \t]?[A-Z0-9]{2}(?:[ \t]?[A-Z0-9]{3})?)(?![A-Za-z0-9])"
)
_bic_ok = _stdnum("bic")
_UVCI_RE = re.compile(r"(?i)(?<![\w:])URN:UVCI:\d{2}:[A-Z]{2}:[A-Z0-9/#:\-]{6,80}(?![A-Za-z0-9])")


def find_eu(text: str) -> Iterator[Span]:
    for m in _EU_VAT_RE.finditer(text):
        compact = m.group("cc") + _compact(m.group("body"))
        if sum(c.isdigit() for c in compact) >= 7 and _eu_vat_ok(compact):
            yield make_span(m.start(), m.end(), E.NATIONAL_ID, f"{SOURCE}:eu.vat", compact, 0.9)
    lowered = text.casefold()
    if "bic" in lowered or "swift" in lowered:
        for m in _BIC_CUE_RE.finditer(text):
            if _bic_ok(_compact(m.group("value"))):
                yield make_span(
                    m.start("value"), m.end("value"), E.ACCOUNT_ID, f"{SOURCE}:eu.bic", _compact(m.group("value")), 0.85
                )
    if "uvci" in lowered:
        for m in _UVCI_RE.finditer(text):
            yield make_span(m.start(), m.end(), E.ID_DOCUMENT, f"{SOURCE}:eu.uvci", m.group().upper(), 0.9)


_FINDERS: dict[str, Callable[[str], Iterator[Span]]] = {"nl": find_nl, "us": find_us, "eu": find_eu}


def find_regional(text: str, regions: tuple[str, ...] | frozenset[str]) -> list[Span]:
    spans: list[Span] = []
    for region in REGIONS:
        if region in regions:
            spans.extend(_FINDERS[region](text))
    return spans
