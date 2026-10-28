"""Layer 2: validated patterns.

Each detector finds candidates with a regular expression, then confirms them
with a checksum or rule (Luhn, IBAN mod-97, BSN 11-proef, SSN area rules,
libphonenumber validity). Candidates that fail validation are dropped, which
keeps false positives low enough to redact without asking.
"""

from __future__ import annotations

import functools
import ipaddress
import re
from collections.abc import Iterable, Iterator

import phonenumbers
from phonenumbers import Leniency, PhoneNumberMatcher
from stdnum import iban as std_iban
from stdnum import luhn
from stdnum.nl import bsn as std_bsn
from stdnum.us import ssn as std_ssn

from ..entities import EntityType as E
from ..entities import Span, make_span

SOURCE = "pattern"

# --------------------------------------------------------------------------- email
_LOCAL = r"[\w!#$%&'*+/=?^`{|}~-]+(?:\.[\w!#$%&'*+/=?^`{|}~-]+)*"
# A top-level domain in Latin letters ends where the Latin letters do: Chinese, Japanese and Korean text runs straight
# on ("jane@corp.example宛に", "user@aol.com로"). One in another script (".рф", ".中国") ends at a non-word character.
_TLD = r"(?:[A-Za-z]{2,63}(?![A-Za-z0-9_-])|[^\W\d_A-Za-z][^\W\d_]{1,62}(?![\w-]))"
_DOMAIN = rf"(?:[^\W_](?:[\w-]{{0,61}}[^\W_])?\.)+{_TLD}"
# The lookbehind excludes every local-part character, so a long run of them can
# only start a match at its first character: linear time on hostile input.
_IP_LITERAL = r"\[(?:(?:\d{1,3}\.){3}\d{1,3}|IPv6:[0-9A-Fa-f:.]{2,45})\]"
EMAIL_RE = re.compile(rf"(?<![\w!#$%&'*+/=?^`{{|}}~.-]){_LOCAL}@(?:{_DOMAIN}|{_IP_LITERAL}(?![\w-]))")
# Where Chinese, Japanese or Korean text meets Latin letters or digits: a local part starts at the last such seam
# ("本人確認のためTTVH00CN62としょうた柴田@outlook.com" has the local part "としょうた柴田").
_CJK = "\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uac00-\ud7af\uf900-\ufaff"
_LOCAL_SEAM_RE = re.compile(f"(?<=[{_CJK}])(?=[A-Za-z0-9])|(?<=[A-Za-z0-9])(?=[{_CJK}])")

_AT_TOKEN = r"(?:[\[\(\{<]\s*at\s*[\]\)\}>])"  # regex or label, not a credential  # noqa: S105  # nosec B105
_DOT_TOKEN = r"(?:[\[\(\{<]\s*dot\s*[\]\)\}>])"  # regex or label, not a credential  # noqa: S105  # nosec B105
OBF_EMAIL_RE = re.compile(
    rf"(?<![\w.+-])[\w.+-]+\s*(?:@|{_AT_TOKEN})\s*(?:[\w-]+\s*(?:{_DOT_TOKEN}|\.)\s*)+[^\W\d_]{{2,24}}(?!\w)",
    re.IGNORECASE,
)
_OBF_TOKEN_RE = re.compile(rf"{_AT_TOKEN}|{_DOT_TOKEN}", re.IGNORECASE)


def _canonical_email(raw: str) -> str:
    s = re.sub(_AT_TOKEN, "@", raw, flags=re.IGNORECASE)
    s = re.sub(_DOT_TOKEN, ".", s, flags=re.IGNORECASE)
    return re.sub(r"\s+", "", s).lower()


# The password in a connection URL (group 1). It runs to the last "@" before the host ("app:P@ssw0rd!@db"), may hold
# a "#" people forget to escape ("app:1nt#CP@db"), and the user name may be empty ("redis://:pw@cache"). The
# lookbehind lets a match start only at the beginning of a scheme-like run, and every repeat is bounded, so no
# position is rescanned at length.
URL_CREDENTIALS_RE = re.compile(
    r"(?<![a-z0-9+.\-])[a-z][a-z0-9+.\-]{0,30}://[^\s:/@]{0,256}:([^\s/?]{1,256}?)@(?=[^\s/?#@]{0,256}(?:[/?#\s]|\Z))",
    re.IGNORECASE,
)


def url_passwords(text: str) -> list[tuple[int, int]]:
    """Where the passwords of connection URLs are: secrets (detectors/secrets.py), not the local part of an email."""
    return [m.span(1) for m in URL_CREDENTIALS_RE.finditer(text)] if "://" in text else []


def find_emails(text: str) -> Iterator[Span]:
    passwords = url_passwords(text)
    for m in EMAIL_RE.finditer(text):
        # "postgres://app:Hunter2isMyPass9@db.internal" is a password and a host: the host stays readable.
        if any(a <= m.start() < b for a, b in passwords):
            continue
        start = m.start()
        at = text.index("@", start)
        for seam in _LOCAL_SEAM_RE.finditer(text, start + 1, at):
            start = seam.start()
        yield make_span(start, m.end(), E.EMAIL, SOURCE, text[start : m.end()].lower())
    for m in OBF_EMAIL_RE.finditer(text):
        if _OBF_TOKEN_RE.search(m.group()):
            yield make_span(m.start(), m.end(), E.EMAIL, SOURCE, _canonical_email(m.group()))


# --------------------------------------------------------------------------- phone
PHONE_CANDIDATE_RE = re.compile(r"(?<![\w+/.])(?:\+|00|\()?\d[\d \t().\-/]{5,22}\d(?![\w])")
_IPV4_SHAPE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
# A date written with separators reads as a national number in some regions ("09-15-2023" is a valid German number):
# a run that is a real date is a date.
_DATE_SHAPE_RE = re.compile(
    r"\(?(?:(?P<a>\d{1,2})[\-/.](?P<b>\d{1,2})[\-/.](?P<y>(?:19|20)\d{2})|(?P<y2>(?:19|20)\d{2})[\-/.](?P<m2>\d{1,2})[\-/.](?P<d2>\d{1,2}))\)?"
)


def _date_shaped(raw: str) -> bool:
    m = _DATE_SHAPE_RE.fullmatch(raw.strip())
    if m is None:
        return False
    if m.group("y2"):
        return 1 <= int(m.group("m2")) <= 12 and 1 <= int(m.group("d2")) <= 31
    a, b = int(m.group("a")), int(m.group("b"))
    return (1 <= a <= 12 and 1 <= b <= 31) or (1 <= b <= 12 and 1 <= a <= 31)


@functools.lru_cache(maxsize=4096)
def _valid_phone(window: str, region: str) -> str | None:
    """E.164 of a window that is, as a whole, a valid phone number; None otherwise."""
    try:
        number = phonenumbers.parse(window, region)
    except phonenumbers.NumberParseException:
        return None
    if not phonenumbers.is_valid_number(number):
        return None
    return phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)


def _international_windows(raw: str, region: str) -> Iterator[tuple[int, int, str]]:
    """Valid "+CC ..." numbers at the start of a longer run of digit groups.

    "+31 20 794 6095  4111 1111" is a phone number followed by something else.
    The library's matcher is not reliable for numbers embedded in a longer run,
    so try whole tokens, longest first, anchored at the start.
    """
    pos = 0
    while pos < len(raw):
        if not raw.startswith(("+", "00"), pos):
            return
        tokens = [(m.start() + pos, m.end() + pos) for m in re.finditer(r"\S+", raw[pos:])]
        found = None
        for last in range(len(tokens) - 1, 0, -1):
            window = raw[pos : tokens[last][1]]
            digits = sum(c.isdigit() for c in window)
            if not 8 <= digits <= 15:
                continue
            e164 = _valid_phone(window, region)
            if e164:
                found = (pos, tokens[last][1], e164)
                break
        if found is None:
            return
        yield found
        pos = found[1]
        while pos < len(raw) and raw[pos] in " \t":
            pos += 1


def find_phones(text: str, regions: Iterable[str]) -> Iterator[Span]:
    regions = list(regions) or ["US"]
    for cand in PHONE_CANDIDATE_RE.finditer(text):
        start = cand.start()
        if start >= 2 and text[start - 1] in "-_/#" and text[start - 2].isalnum():
            continue  # part of a reference code such as INV-2026-000123
        raw = cand.group()
        digits = sum(c.isdigit() for c in raw)
        if digits < 7 or _IPV4_SHAPE.fullmatch(raw.strip()) or _date_shaped(raw):
            continue
        international = raw.startswith(("+", "00"))
        if digits > 15 and not international:
            continue  # a long national-looking run is an account number, an IMEI or two numbers: stay out
        if raw.startswith("00"):
            raw = " +" + raw[2:]  # "0031 6 ..." is "+31 6 ...": 00 dials abroad from most countries
        tries = regions[:1] if international else regions
        for region in tries:
            matches = list(PhoneNumberMatcher(raw, region, leniency=Leniency.VALID)) if digits <= 15 else []
            if matches:
                for pm in matches:
                    e164 = phonenumbers.format_number(pm.number, phonenumbers.PhoneNumberFormat.E164)
                    a = 0 if pm.start == 1 and raw.startswith(" +") else pm.start
                    yield make_span(start + a, start + pm.end, E.PHONE, SOURCE, e164)
                break
            if international:
                windows = list(_international_windows(raw.lstrip(" "), region))
                shift = len(raw) - len(raw.lstrip(" "))
                for a, b, e164 in windows:
                    yield make_span(start + (0 if shift else a), start + b + shift, E.PHONE, SOURCE, e164)
                if windows:
                    break


# --------------------------------------------------------------------------- cards
CARD_CHAIN_RE = re.compile(r"(?<![\dA-Za-z.-])\d+(?:[ .\-]\d+)*")
_DIGIT_GROUP_RE = re.compile(r"\d+")


def card_brand_ok(digits: str) -> bool:
    """Issuer prefix and length of a real card network (Visa, Mastercard, Amex, Discover, JCB,
    Diners, UnionPay, Maestro, Mir). An IMEI or an account number rarely passes both."""
    n = len(digits)
    if not 13 <= n <= 19:
        return False
    p2, p3, p4, p6 = int(digits[:2]), int(digits[:3]), int(digits[:4]), int(digits[:6])
    return (
        (digits[0] == "4" and n in (13, 16, 19))
        or ((51 <= p2 <= 55 or 2221 <= p4 <= 2720) and n == 16)
        or (p2 in (34, 37) and n == 15)
        or ((p4 == 6011 or p2 == 65 or 644 <= p3 <= 649 or 622126 <= p6 <= 622925) and n >= 16)
        or (3528 <= p4 <= 3589 and n >= 16)
        or ((300 <= p3 <= 305 or p2 in (36, 38, 39)) and n >= 14)
        or (p2 == 62 and n >= 16)
        or ((p2 == 50 or 56 <= p2 <= 69) and n >= 13)
        or (2200 <= p4 <= 2204 and n >= 16)
    )


def find_cards(text: str) -> Iterator[Span]:
    """Slide a window over each chain of digit groups ("4111 1111 1111 1111 0 4111 ...").

    A chain is never cut at a fixed length, so a stray digit group next to a card
    cannot swallow the start of the next card. Work per chain is linear: a window
    can only begin on a plausible first digit and spans at most 19 digits.
    """
    for chain in CARD_CHAIN_RE.finditer(text):
        raw, base = chain.group(), chain.start()
        groups = [(g.start(), g.end()) for g in _DIGIT_GROUP_RE.finditer(raw)]
        i, n = 0, len(groups)
        while i < n:
            if raw[groups[i][0]] not in "23456":
                i += 1
                continue
            ends, total = [], 0
            for j in range(i, n):
                total += groups[j][1] - groups[j][0]
                if total > 19:
                    break
                if total >= 13:
                    ends.append(j)
            match = None
            for j in reversed(ends):  # longest window first
                after = text[base + groups[j][1] : base + groups[j][1] + 2]
                if after[:1].isalnum() or (after[:1] == "." and after[1:].isdigit()):
                    continue  # glued to a longer token: an IMEI, a hash, "1.2.3"
                digits = "".join(raw[a:b] for a, b in groups[i : j + 1])
                if card_brand_ok(digits) and luhn.is_valid(digits):
                    match = (j, digits)
                    break
            if match is None:
                i += 1
                continue
            j, digits = match
            yield make_span(base + groups[i][0], base + groups[j][1], E.CREDIT_CARD, SOURCE, digits)
            i = j + 1


# --------------------------------------------------------------------------- IBAN
IBAN_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{2}\d{2}(?:[ -]?[A-Za-z0-9]{1,4}){3,9}(?![A-Za-z0-9])")


def _iban_from(raw: str, start: int) -> tuple[int, str] | None:
    """The longest valid IBAN starting at ``raw[start]``: (end in raw, compact form), else None."""
    positions = [k for k in range(start, len(raw)) if raw[k] not in " -"]
    compact = "".join(raw[k] for k in positions).upper()
    for length in range(min(len(compact), 34), 14, -1):
        if std_iban.is_valid(compact[:length]):
            return positions[length - 1] + 1, compact[:length]
    return None


def find_ibans(text: str) -> Iterator[Span]:
    """Every IBAN in a run of letter and digit groups. A run can start with something else that looks like the
    start of an IBAN ("Ref AB12 NL91 ABNA 0417 1643 00"), so each place an IBAN could start is tried, left to
    right. Found by the fuzzer: before, only the run's start was tried and the IBAN after "AB12" leaked."""
    for cand in IBAN_CANDIDATE_RE.finditer(text):
        raw, base = cand.group(), cand.start()
        k = 0
        while k <= len(raw) - 15:
            if not (raw[k : k + 2].isalpha() and raw[k + 2 : k + 4].isdigit()):
                k += 1
                continue
            hit = _iban_from(raw, k)
            if hit is None:
                k += 1
                continue
            end, compact = hit
            yield make_span(base + k, base + end, E.IBAN, SOURCE, compact)
            k = end


# --------------------------------------------------------------------------- national IDs
SSN_FORMATTED_RE = re.compile(r"(?<![\d-])\d{3}([- ])\d{2}\1\d{4}(?![\d-])")
NINE_DIGITS_RE = re.compile(r"(?<![\d.])(?:\d[ .]?){8}\d(?!\d|\.\d)")  # a sentence-final period is fine
# Cue words as prose or as field names (ssn, social_security_number, socialSecurityNumber, BSN-nummer).
_J = r"[\s_.\-]{0,3}"
SSN_CONTEXT_RE = re.compile(rf"(?<![A-Za-z])(?i:ssn|social{_J}security|soc\.?{_J}sec)")
BSN_CONTEXT_RE = re.compile(rf"(?<![A-Za-z])(?i:bsn|burgerservicenummer|sofi-?nummer|citizen{_J}service{_J}number)")
NINO_RE = re.compile(
    r"(?<![A-Za-z0-9])([A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]) ?(\d{2}) ?(\d{2}) ?(\d{2}) ?([A-D])(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_NINO_BAD_PREFIX = frozenset({"BG", "GB", "KN", "NK", "NT", "TN", "ZZ"})


def _context_before(text: str, start: int, pattern: re.Pattern[str], window: int = 60) -> bool:
    return pattern.search(text, max(0, start - window), start) is not None


def find_national_ids(text: str) -> Iterator[Span]:
    for m in SSN_FORMATTED_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if std_ssn.is_valid(digits):
            yield make_span(m.start(), m.end(), E.US_SSN, SOURCE, digits)
    for m in NINE_DIGITS_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if len(digits) != 9:
            continue
        if _context_before(text, m.start(), SSN_CONTEXT_RE) and std_ssn.is_valid(digits):
            yield make_span(m.start(), m.end(), E.US_SSN, SOURCE, digits)
        elif _context_before(text, m.start(), BSN_CONTEXT_RE) and std_bsn.is_valid(digits):
            yield make_span(m.start(), m.end(), E.NL_BSN, SOURCE, digits)
    for m in NINO_RE.finditer(text):
        if m.group(1).upper() not in _NINO_BAD_PREFIX:
            yield make_span(m.start(), m.end(), E.UK_NINO, SOURCE, "".join(m.groups()).upper())


# --------------------------------------------------------------------------- IP addresses
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w])(?!\.\d)")
IPV6_RE = re.compile(r"(?<![\w:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])")


def _reportable_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast)


# A version in a product token is not an address: "Chrome/120.0.0.0", "Edg/122.0.0.0" in a user agent.
_PRODUCT_BEFORE_RE = re.compile(r"(?<![\w/:.])[A-Za-z][A-Za-z0-9_.\-]{1,30}/$")
# An address with its port as tcpdump writes it ("10.0.1.44.33901 > 185.220.101.33.4444:"), and one inside a
# wildcard DNS name ("app.10.0.0.5.nip.io", "exfil.185.220.101.33.sslip.io").
_TCPDUMP_RE = re.compile(r"(?<![\w.])(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\.\d{1,5}(?=:?[ \t]|:$|,)")
_WILDCARD_DNS_RE = re.compile(
    r"(?<=[A-Za-z0-9\-]\.)(?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?=\.(?:nip\.io|sslip\.io|xip\.io|traefik\.me|localtest\.me)\b)"
)


def find_ips(text: str) -> Iterator[Span]:
    for m in IPV4_RE.finditer(text):
        try:
            ip4 = ipaddress.IPv4Address(m.group())
        except ValueError:
            continue
        if _PRODUCT_BEFORE_RE.search(text, max(0, m.start() - 32), m.start()):
            continue
        if _reportable_ip(ip4):
            yield make_span(m.start(), m.end(), E.IP_ADDRESS, SOURCE, str(ip4))
    extra: list[re.Match[str]] = []
    if " > " in text:
        extra.extend(_TCPDUMP_RE.finditer(text))
    if "ip.io" in text or ".me" in text:
        extra.extend(_WILDCARD_DNS_RE.finditer(text))
    for m in extra:
        try:
            ip4 = ipaddress.IPv4Address(m.group("ip"))
        except ValueError:
            continue
        if _reportable_ip(ip4):
            yield make_span(m.start("ip"), m.end("ip"), E.IP_ADDRESS, SOURCE, str(ip4))
    for m in IPV6_RE.finditer(text):
        token = m.group()
        if sum(1 for g in token.split(":") if g) < 3:
            continue
        try:
            ip6 = ipaddress.IPv6Address(token)
        except ValueError:
            continue
        if _reportable_ip(ip6):
            yield make_span(m.start(), m.end(), E.IP_ADDRESS, SOURCE, ip6.compressed)


# --------------------------------------------------------------------------- date of birth
# Month names in English, Dutch, German, French, Spanish, Italian and Portuguese, with their abbreviations.
_MONTHS = (
    r"(?:jan(?:uary|uari|uar|vier)?|jänner|feb(?:ruary|ruari|ruar)?|février|fevereiro|mar(?:ch|zo|s)?|mrt|maart|märz"
    r"|março|apr(?:il|ile)?|avril|abril|may|mayo|mei|mai|maggio|maio|june?|juni|juin|junio|giugno|junho|july?|juli"
    r"|juillet|julio|luglio|julho|aug(?:ust|ustus)?|août|agosto|sep(?:t(?:ember|embre)?)?|septiembre|setiembre"
    r"|settembre|setembro|oct(?:ober|obre|ubre)?|okt(?:ober)?|ottobre|outubro|nov(?:ember|embre|iembre)?|novembro"
    r"|dec(?:ember)?|dez(?:ember)?|décembre|dic(?:iembre|embre)?|dezembro|gen(?:naio)?|enero|ene|janeiro)"
)
_DATE = (
    rf"(?:\d{{1,2}}[/.\-]\d{{1,2}}[/.\-]\d{{2,4}}|\d{{4}}-\d{{2}}-\d{{2}}"
    rf"|\d{{1,2}}(?:st|nd|rd|th|er|e|º|ª)?\.?\s+(?:de\s+)?{_MONTHS}\.?,?\s+(?:de\s+)?\d{{4}}"
    rf"|{_MONTHS}\.?\s+\d{{1,2}}(?:st|nd|rd|th)?,?\s+\d{{4}})"
)
_DOB_CUE = (
    rf"(?<![A-Za-z])(?:d\.?o\.?b(?![a-z])\.?|date{_J}of{_J}birth|birth{_J}date|birthday|born(?:\s+on)?(?![a-z])"
    rf"|geboren(?:\s+(?:op|am|den))?(?![a-z])|geb\.(?:{_J}datum)?|geboortedatum|geburtsdatum|geburtstag"
    rf"|date{_J}de{_J}naissance|n[ée]e?{_J}le|fecha{_J}de{_J}nacimiento|nacid[oa]{_J}el|data{_J}di{_J}nascita"
    rf"|nat[oa]{_J}il|data{_J}de{_J}nascimento|nascid[oa]{_J}(?:em|a)|data{_J}urodzenia|datum{_J}narozen[ií]"
    rf"|datum{_J}ro[dđ]enja|sz[üu]let[ée]si{_J}d[áa]tum|f[øo]dselsdato|f[öo]delsedatum|syntym[äa]aika"
    rf"|do[gğ]um{_J}tarihi)"
)
# After the cue: up to four words ("on file is", "in Utrecht on"), then quotes, signs, markup (HTML tags, Markdown's
# "**") and a parenthetical ("(DD-MM-YYYY)", "(base64)") in any order, at most eight pieces, then the date. Bounded,
# so linear.
DOB_RE = re.compile(
    rf"{_DOB_CUE}(?:\s{{1,3}}[A-Za-z]{{2,12}}){{0,4}}?"
    rf"(?:[\s:,\-(|=>\"'`*_]|<[^<>\n]{{1,40}}>|\([^()\n]{{0,30}}\)){{0,8}}({_DATE})",
    re.IGNORECASE,
)


def find_dates_of_birth(text: str) -> Iterator[Span]:
    for m in DOB_RE.finditer(text):
        yield make_span(m.start(1), m.end(1), E.DATE_OF_BIRTH, SOURCE, m.group(1).lower())


def is_valid_phone(candidate: str) -> bool:
    try:
        return bool(phonenumbers.is_valid_number(phonenumbers.parse(candidate, None)))
    except phonenumbers.NumberParseException:
        return False


def find_all(text: str, phone_regions: Iterable[str]) -> list[Span]:
    spans: list[Span] = []
    for finder in (find_emails, find_cards, find_ibans, find_national_ids, find_ips, find_dates_of_birth):
        spans.extend(finder(text))
    spans.extend(find_phones(_mask_for_phones(text, spans), phone_regions))
    return spans


_DATE_SHAPES_RE = re.compile(
    r"(?<![\d-])(?:"
    r"(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"  # 2024-03-14
    r"|(?:0?[1-9]|[12]\d|3[01])[/.](?:0?[1-9]|1[0-2])[/.](?:19|20)\d{2}"  # 14/03/2024, 14.03.2024
    r"|(?:0?[1-9]|1[0-2])/(?:0?[1-9]|[12]\d|3[01])/(?:19|20)\d{2}"  # 03/14/2024
    r"|\d{1,2}:\d{2}(?::\d{2})?"  # 09:30, 09:30:15
    r")(?![\d-])"
)  # phone numbers never use a colon, and rarely a four-digit year in the middle of a group run


_MASKABLE = frozenset({E.CREDIT_CARD, E.IBAN, E.EMAIL, E.IP_ADDRESS})


def _mask_for_phones(text: str, found: list[Span]) -> str:
    """Hide entities already found, plus unambiguous dates and times, behind a character
    that no phone candidate can contain, so "2024-03-14 020 794 6095" or a card number
    next to a phone number cannot merge into one over-long candidate. Offsets are kept.
    Two-digit-year dates are left alone: "45-56-78" is a normal phone number group."""
    # Only strongly validated types: a formatted SSN is just a shape, and "+992 372 12 3456"
    # is a phone number whose tail happens to look like one.
    ranges = [(sp.start, sp.end) for sp in found if sp.type in _MASKABLE]
    ranges += [m.span() for m in _DATE_SHAPES_RE.finditer(text)]
    if not ranges:
        return text
    chars = list(text)
    for a, b in ranges:
        chars[a:b] = "\x00" * (b - a)
    return "".join(chars)
