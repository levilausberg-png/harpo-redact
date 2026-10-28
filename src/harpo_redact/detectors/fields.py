"""Layer 2c: values whose field name says what they are.

Structured data names its values: a JSON key, a CSV or Markdown column header, the first cell of a two-column
table. "298163871" alone is just nine digits; under a key called ``bsn`` it is a citizen service number, and it is
checked as one. The label only decides *which* check a value gets: the value still has to pass that check
(the same checksums and shapes the rest of the deterministic layers use), so a label cannot make anything out of
"on file" or "required".

* ``label_kinds`` reads a label ("passport_number_index", "dateOfBirth", "Steuer-ID") as words and returns what a
  value under it would be. Words that change the meaning ("passport_expiry", "password_hint", "key_id") cancel it.
* ``find_labelled`` checks one value against its label. The proxy uses it for JSON leaves and keys, with the
  nearest meaningful key as the label (proxy.Collector).
* ``find_table_fields`` finds tables in text (CSV, TSV, semicolon-separated, Markdown pipes) and checks every
  cell against its column header, and the second cell of a two-column row against the first. Beyond the validated
  kinds above, a header in any language the cue words know (detectors/cued.py) types its cells by shape, and
  headers for a person's name, a postal address or a place type cells that hold one whole.

Found by the redaction matrix (tests/redaction_matrix.py): cue words were matched only in prose order, so a value
in a CSV column, a JSON schema default or under an object key was not checked against what it was.
"""

from __future__ import annotations

import functools
import re
import unicodedata
from collections.abc import Callable, Iterator

from stdnum.nl import bsn as std_bsn
from stdnum.us import ssn as std_ssn

from ..entities import PLACEHOLDER_RE, Span, make_span
from ..entities import EntityType as E
from .addresses import (
    address_label,
    number_label,
    place_label,
    street_label,
    table_address,
    table_house_number,
    table_place,
    table_street,
)
from .cued import _KIND_TYPE, label_kind, table_value
from .cued import SOURCE as CUE_SOURCE
from .identifiers import _luhn_ok, _stdnum
from .names import person_label, table_name
from .patterns import _DATE, _NINO_BAD_PREFIX, NINO_RE
from .secret_library import _NOT_A_VALUE, _TEMPLATE_RE, looks_like_placeholder, shannon_entropy
from .secrets import CODE_REFERENCE_RE, is_encoded_text

SOURCE = "field"

# --------------------------------------------------------------------------- labels as words
_PART_RE = re.compile(r"[^\W_]+")
_CAMEL_RE = re.compile(r"(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|(?<=[A-Za-z])(?=\d)|(?<=\d)(?=[A-Za-z])")
_NOUN_SUFFIXES = ("number", "nummer", "numero", "nr", "no", "num", "id", "code")
_NOUNS = frozenset({"number", "nummer", "numero", "nr", "no", "num", "id", "code", "ref", "reference"})


def _fold(word: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", word) if not unicodedata.combining(c)).lower()


@functools.lru_cache(maxsize=4096)
def label_words(label: str) -> tuple[str, ...]:
    """'passport_number_index' -> (passport, number, index); 'dateOfBirth' -> (date, of, birth);
    'rekeningnummer' -> (rekening, nummer)."""
    words: list[str] = []
    for part in _PART_RE.findall(label[:200]):
        for piece in _CAMEL_RE.split(part):
            word = _fold(piece)
            if not word:
                continue
            for suffix in _NOUN_SUFFIXES:  # "passportnumber", "rekeningnummer"
                if word.endswith(suffix) and len(word) - len(suffix) >= 3 and word not in _JOINED_CUES:
                    words += [word[: -len(suffix)], suffix]
                    break
            else:
                words.append(word)
    return tuple(words)


# kind -> word sequences that name it. A sequence also matches written as one word ("dateofbirth").
_CUES: dict[str, tuple[tuple[str, ...], ...]] = {
    "us_ssn": (("ssn",), ("social", "security")),
    "nl_bsn": (("bsn",), ("burgerservicenummer",), ("sofinummer",), ("sofi",), ("citizen", "service")),
    "uk_nino": (("nino",), ("national", "insurance")),
    "gb.nhs": (("nhs",),),
    "ca.sin": (("sin",), ("social", "insurance")),
    "be.nn": (("rijksregisternummer",), ("rijksregister",), ("national", "register"), ("insz",), ("niss",),
              ("numero", "national"), ("national", "number")),
    "de.idnr": (("steuer", "id"), ("steuerid",), ("steueridentifikationsnummer",), ("idnr",),
                ("identifikationsnummer",), ("tax", "id")),
    "in_.aadhaar": (("aadhaar",), ("aadhar",), ("uidai",)),
    "au.tfn": (("tfn",), ("tax", "file")),
    "br.cpf": (("cpf",),),
    "us.ein": (("ein",), ("fein",), ("employer", "identification"), ("tax", "id")),
    "us.itin": (("itin",),),
    "in_.pan": (("pan",), ("permanent", "account")),
    "es.dni": (("dni",),),
    "es.nie": (("nie",),),
    "fr.nir": (("nir",), ("securite", "sociale"), ("insee",)),
    "it.codicefiscale": (("codice", "fiscale"),),
    "mx.curp": (("curp",),),
    "document": (("passport",), ("paspoort",), ("reisepass",), ("passeport",), ("pasaporte",), ("passaporto",),
                 ("driver", "license"), ("drivers", "license"), ("driver", "licence"), ("drivers", "licence"),
                 ("driving", "license"), ("driving", "licence"), ("rijbewijs",), ("fuhrerschein",),
                 ("fuehrerschein",), ("id", "card"), ("identity", "card"), ("national", "id"),
                 ("identiteitskaart",), ("personalausweis",), ("license", "number"), ("licence", "number")),
    "account": (("account",), ("acct",), ("rekening",), ("konto",), ("mrn",), ("medical", "record"),
                ("member",), ("policy",), ("health", "plan"), ("insurance",), ("beneficiary",), ("claim",),
                ("subscriber",), ("customer",), ("patient",)),
    "routing": (("routing",), ("aba",), ("rtn",)),
    "imei": (("imei",),),
    "dob": (("dob",), ("date", "of", "birth"), ("birth", "date"), ("birthdate",), ("birthday",), ("born",),
            ("geboortedatum",), ("geburtsdatum",), ("date", "de", "naissance"), ("fecha", "de", "nacimiento"),
            ("data", "di", "nascita")),
    # Credentials: "password" accepts any value but a placeholder; the others need a value that looks generated.
    "password": (("password",), ("passwd",), ("passphrase",), ("pwd",), ("wachtwoord",), ("passwort",),
                 ("kennwort",), ("mot", "de", "passe"), ("contrasena",)),
    "credential": (("passcode",), ("pin",), ("pin", "code"), ("security", "code"), ("verification", "code"),
                   ("one", "time", "code"), ("otp",), ("recovery", "code"), ("backup", "code"),
                   *((a, b) for a in ("api", "access", "secret", "auth", "private", "client", "signing", "encryption")
                     for b in ("key", "token", "secret"))),
    "generic_secret": (("token",), ("secret",), ("key",), ("credential",), ("credentials",), ("creds",), ("auth",)),
}  # fmt: skip
_JOINED_CUES = frozenset("".join(seq) for seqs in _CUES.values() for seq in seqs)
# Words that make a label about something else: "passport_expiry", "password_hint", "account_balance", "key_id".
_MODIFIERS = frozenset(
    """expiry expires expiration expire exp issued issue issuing country nationality type kind status state
    verified verification valid validity photo image scan picture url uri link href file path filename policy
    hint length len size min max minimum maximum format pattern regex rule rules required enabled flag count
    label placeholder prompt description desc note notes comment message error reason template example sample
    mask masked last4 hash salt strength score updated changed created reset rotation rotated age history
    balance currency amount limit holder name names title field fields mode method provider issuer authority
    office place city version alias endpoint header headers schema""".split()  # noqa: SIM905
)  # fmt: skip
# Further words that make a credential label about something other than the secret itself.
_SECRET_MODIFIERS = frozenset(
    {"id", "ids", "public", "pub", "ref", "reference", "csrf", "xsrf", "page", "next", "cursor", "continuation",
     "pagination", "sync", "etag"}
)  # fmt: skip
_ACCOUNT_EXPLICIT = frozenset({"acct", "mrn", "rekening", "konto"})  # account numbers by name alone
# Labels that hold a person's number when the value is all digits ({"customer": "4471209"}). "policy", "claim" and
# "insurance" also hold amounts and names, so they need an ID word ("policy_number", "claim_id").
_ACCOUNT_BARE = frozenset({"account", "customer", "patient", "member", "subscriber", "beneficiary"})


def _has_sequence(words: tuple[str, ...], seq: tuple[str, ...]) -> bool:
    if len(seq) == 1:
        return seq[0] in words
    joined = "".join(seq)
    if joined in words:
        return True
    n = len(seq)
    return any(words[i : i + n] == seq for i in range(len(words) - n + 1))


@functools.lru_cache(maxsize=4096)
def label_kinds(label: str) -> frozenset[str]:
    """What a value under this label would be; empty when the label says nothing or speaks about something else."""
    words = label_words(label)
    if not words:
        return frozenset()
    found: set[str] = set()
    for kind, sequences in _CUES.items():
        cue_words = {w for seq in sequences if _has_sequence(words, seq) for w in seq}
        if not cue_words:
            continue
        others = set(words) - cue_words
        if kind != "dob" and others & _MODIFIERS:
            continue
        if kind == "dob" and others & (_MODIFIERS - {"date"}):
            continue
        if kind in ("password", "credential", "generic_secret") and others & _SECRET_MODIFIERS:
            continue
        found.add(kind)
    if found & {"password", "credential"}:
        found.discard("generic_secret")
    return frozenset(found)


# --------------------------------------------------------------------------- values
_DOCUMENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{4,15}")
_ACCOUNT_VALUE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.\-/]{3,30}")
_DATE_RE = re.compile(
    rf"(?:{_DATE}|\d{{4}}[/.]\d{{1,2}}[/.]\d{{1,2}}|(?:19|20)\d{{2}}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01]))"
    r"(?:[T ]\d{1,2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?",
    re.IGNORECASE,
)
_SEPARATORS_RE = re.compile(r"[\s.\-/]")
_GENERIC_VALUE_RE = re.compile(r"[\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3}", re.IGNORECASE)
_STRIP = " \t\r\n\"'`"
_NATIONAL_KINDS = ("gb.nhs", "ca.sin", "be.nn", "de.idnr", "in_.aadhaar", "au.tfn", "br.cpf", "us.ein", "us.itin",
                   "in_.pan", "es.dni", "es.nie", "fr.nir", "it.codicefiscale", "mx.curp")  # fmt: skip


_VALIDATORS: dict[str, Callable[[str], bool]] = {k: _stdnum(k) for k in (*_NATIONAL_KINDS, "us.rtn")}


def _digits(value: str) -> str:
    return _SEPARATORS_RE.sub("", value)


def _secret_like(value: str, kind: str) -> bool:
    if any(c.isspace() for c in value):
        return False
    core = value.rstrip(".,;:!?)]}>")
    if len(core) < 3 or core.lower() in _NOT_A_VALUE or PLACEHOLDER_RE.fullmatch(core):
        return False
    if looks_like_placeholder(core) or _TEMPLATE_RE.match(core) or CODE_REFERENCE_RE.match(core):
        return False
    if set(core) <= {"*", "x", "X", ".", "#", "-", "_"}:
        return False
    if kind == "password":
        return True  # "password": "sunshine" is a password, as "my password is sunshine" is
    has_digit = any(c.isdigit() for c in core)
    if kind == "credential":  # a PIN or code needs a digit; a key or token needs more than a plain word
        return has_digit or any(not c.isalnum() for c in core) or (core[1:] != core[1:].lower() and len(core) >= 8)
    # gitleaks' generic-api-key rule: its value shape, entropy above 3.5 and a digit
    return bool(_GENERIC_VALUE_RE.fullmatch(core)) and has_digit and shannon_entropy(core) > 3.5


def _check(kind: str, value: str, label_words_: tuple[str, ...]) -> tuple[E, str] | None:
    """(type, canonical) when the value is what its label says, else None."""
    upper = value.upper()
    if kind == "us_ssn":
        digits = _digits(value)
        return (E.US_SSN, digits) if len(digits) == 9 and std_ssn.is_valid(digits) else None
    if kind == "nl_bsn":
        digits = _digits(value)
        return (E.NL_BSN, digits) if len(digits) == 9 and digits.isdigit() and std_bsn.is_valid(digits) else None
    if kind == "uk_nino":
        m = NINO_RE.fullmatch(value)
        if m and m.group(1).upper() not in _NINO_BAD_PREFIX:
            return E.UK_NINO, "".join(m.groups()).upper()
        return None
    if kind in _NATIONAL_KINDS:
        if len(value) > 32 or not any(c.isdigit() for c in value):
            return None
        return (E.NATIONAL_ID, _digits(upper)) if _VALIDATORS[kind](upper) else None
    if kind in ("document", "account", "password", "credential", "generic_secret") and is_encoded_text(value):
        return None  # encoded content: judged by what it decodes to (secrets.find_encoded)
    if kind == "document":
        if _DOCUMENT_RE.fullmatch(value) and any(c.isdigit() for c in value) and not _DATE_RE.fullmatch(value):
            return E.ID_DOCUMENT, upper
        return None
    if kind == "account":
        if not (_ACCOUNT_VALUE_RE.fullmatch(value) and any(c.isdigit() for c in value)) or _DATE_RE.fullmatch(value):
            return None
        words = set(label_words_)
        explicit = bool(_ACCOUNT_EXPLICIT & words) or _has_sequence(label_words_, ("medical", "record"))
        digits = _digits(value)
        if explicit or bool(_NOUNS & words) or (bool(_ACCOUNT_BARE & words) and digits.isdigit() and len(digits) >= 6):
            return E.ACCOUNT_ID, upper
        return None
    if kind == "routing":
        digits = _digits(value)
        return (E.ACCOUNT_ID, digits) if len(digits) == 9 and _VALIDATORS["us.rtn"](digits) else None
    if kind == "imei":
        digits = _digits(value)
        return (E.DEVICE_ID, digits) if len(digits) == 15 and digits.isdigit() and _luhn_ok(digits) else None
    if kind == "dob":
        return (E.DATE_OF_BIRTH, value.lower()) if _DATE_RE.fullmatch(value) else None
    if kind in ("password", "credential", "generic_secret"):
        return (E.SECRET, value) if _secret_like(value, kind) else None
    return None


def find_labelled(label: str, text: str, offset: int = 0) -> list[Span]:
    """Spans for ``text`` (a whole value) when it is what ``label`` says it is."""
    kinds = label_kinds(label)
    if not kinds:
        return []
    start, end = 0, len(text)
    while start < end and text[start] in _STRIP:
        start += 1
    while end > start and text[end - 1] in _STRIP:
        end -= 1
    value = text[start:end]
    if not value or len(value) > 256:
        return []
    words = label_words(label)
    spans: list[Span] = []
    for kind in sorted(kinds):
        hit = _check(kind, value, words)
        if hit is not None:
            etype, canonical = hit
            spans.append(make_span(offset + start, offset + end, etype, f"{SOURCE}:{kind}", canonical, 0.9))
    return spans


# --------------------------------------------------------------------------- tables in text
_TABLE_DELIMITERS = ("\t", "|", ";", ",")
# A Markdown header rule: |---|:---:|. Written so no two blank runs can trade characters (linear on any line).
_MD_RULE_RE = re.compile(r"(?<![ \t])[ \t]*(?:\|[ \t]*)?:?-{3,}:?(?:[ \t]*\|[ \t]*:?-{3,}:?)*[ \t]*(?:\|[ \t]*)?")
_MAX_LABEL = 64


def _cells(text: str, start: int, end: int, delimiter: str) -> list[tuple[int, int]]:
    """[start, end) of each cell's content on one line: surrounding blanks trimmed, CSV quotes removed."""
    cells: list[tuple[int, int]] = []
    i = start
    while True:
        while i < end and text[i] in " \t" and text[i] != delimiter:
            i += 1
        if i < end and text[i] == '"' and delimiter != "|":
            k = i + 1
            while k < end:
                if text[k] == '"':
                    if k + 1 < end and text[k + 1] == '"':
                        k += 2
                        continue
                    break
                k += 1
            cells.append((i + 1, min(k, end)))
            nxt = text.find(delimiter, min(k + 1, end), end)
        else:
            nxt = text.find(delimiter, i, end)
            stop = end if nxt == -1 else nxt
            last = stop
            while last > i and text[last - 1] in " \t\r":
                last -= 1
            cells.append((i, last))
        if nxt == -1:
            return cells
        i = nxt + 1


def _row(text: str, start: int, end: int, delimiter: str) -> list[tuple[int, int]] | None:
    if delimiter not in text[start:end]:
        return None
    cells = _cells(text, start, end, delimiter)
    if delimiter == "|":  # Markdown: "| a | b |" has nothing before the first pipe or after the last
        if cells and cells[0][0] == cells[0][1]:
            cells = cells[1:]
        if cells and cells[-1][0] == cells[-1][1]:
            cells = cells[:-1]
    return cells if len(cells) >= 2 else None


def _label_like(text: str, cell: tuple[int, int]) -> bool:
    value = text[cell[0] : cell[1]]
    return 0 < len(value) <= _MAX_LABEL and any(c.isalpha() for c in value)


_TR_OPEN_RE = re.compile(r"<tr\b[^<>]{0,200}>", re.IGNORECASE)
_TR_CLOSE_RE = re.compile(r"</tr\s*>", re.IGNORECASE)
_CELL_OPEN_RE = re.compile(r"<t[hd]\b[^<>]{0,200}>", re.IGNORECASE)
_CELL_CLOSE_RE = re.compile(r"</t[hd]\s*>", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^<>]{0,200}>")


def _paired(opens: list[re.Match[str]], closes: list[re.Match[str]]) -> Iterator[tuple[int, int]]:
    """(content start, content end) of each element: an opening tag up to the first closing tag after it, if that
    comes before the next opening tag. Linear: no regex has to look for the closing tag."""
    k = 0
    for i, opened in enumerate(opens):
        while k < len(closes) and closes[k].start() < opened.end():
            k += 1
        if k == len(closes):
            return
        limit = opens[i + 1].start() if i + 1 < len(opens) else None
        if limit is None or closes[k].start() <= limit:
            yield opened.end(), closes[k].start()


def _cell_text(text: str, start: int, end: int) -> tuple[int, int]:
    """A cell's text without the markup around it ("<td><b>Tr0ub4dor</b></td>"): its longest stretch between tags."""
    best = (start, start)
    cursor = start
    for m in [*_TAG_RE.finditer(text, start, end), None]:
        stop = m.start() if m is not None else end
        a, b = cursor, stop
        while a < b and text[a].isspace():
            a += 1
        while b > a and text[b - 1].isspace():
            b -= 1
        if b - a > best[1] - best[0]:
            best = (a, b)
        if m is None:
            break
        cursor = m.end()
    return best


def _html_rows(text: str) -> list[list[tuple[int, int]]]:
    if "<" not in text:
        return []
    rows = []
    for start, end in _paired(list(_TR_OPEN_RE.finditer(text)), list(_TR_CLOSE_RE.finditer(text))):
        opens = list(_CELL_OPEN_RE.finditer(text, start, end))
        closes = list(_CELL_CLOSE_RE.finditer(text, start, end))
        cells = [_cell_text(text, a, b) for a, b in _paired(opens, closes)]
        if len(cells) >= 2:
            rows.append(cells)
    return rows


def table_cells(text: str) -> Iterator[tuple[str, int, int]]:
    """(label, start, end) for each table cell whose column header, or row label, could say what it holds."""
    html_rows = _html_rows(text)
    if html_rows:
        yield from _block_cells(text, html_rows)
    if "\n" not in text or not any(d in text for d in _TABLE_DELIMITERS):
        return
    lines: list[tuple[int, int]] = []
    pos = 0
    for raw in text.split("\n"):  # blank lines stay in, so they end a table
        lines.append((pos, pos + len(raw)))
        pos += len(raw) + 1
    for delimiter in _TABLE_DELIMITERS:
        if delimiter not in text:
            continue
        block: list[list[tuple[int, int]]] = []
        width = 0
        gap = False
        for start, end in [*lines, (-1, -1)]:
            if start >= 0 and delimiter == "|" and _MD_RULE_RE.fullmatch(text, start, end):
                continue  # the |---|---| line under a Markdown header
            row = _row(text, start, end, delimiter) if start >= 0 else None
            if row is None and start >= 0 and len(block) == 1 and not gap and not text[start:end].strip():
                gap = True  # "name,phone\n\nAda,+1 613 396 0112": one blank line under a header does not end it
                continue
            if row is not None and (not block or len(row) == width):
                block.append(row)
                width = len(row)
                gap = False
                continue
            gap = False
            if len(block) >= 2:
                yield from _block_cells(text, block)
            block = [row] if row is not None else []
            width = len(row) if row is not None else 0


def _block_cells(text: str, block: list[list[tuple[int, int]]]) -> Iterator[tuple[str, int, int]]:
    """Each cell under its column header (when the first row is one), and the value of a two-column row under
    the row's own label ("| date of birth | 14 March 1985 |")."""
    head = block[0]
    has_header = (
        len(block) >= 2
        and all(_label_like(text, c) for c in head)
        and not any(_digits(text[a:b]).isdigit() for a, b in head)
    )
    for row in block[1:] if has_header else block:
        if has_header:
            for (ha, hb), (a, b) in zip(head, row, strict=False):
                if b > a:
                    yield text[ha:hb], a, b
        if len(row) == 2 and _label_like(text, row[0]) and row[1][1] > row[1][0]:
            yield text[row[0][0] : row[0][1]], row[1][0], row[1][1]


_PERSON_KINDS = frozenset({"phone", "national", "document", "pin", "card"})
_PERSON_FIELDS = frozenset({"dob", "us_ssn", "nl_bsn", "uk_nino", "document"})


@functools.lru_cache(maxsize=4096)
def _about_a_person(label: str) -> bool:
    """A column a table about people has: an e-mail, a phone, a birth date, a first or last name, an address."""
    lowered = label.casefold()
    if "mail" in lowered or "phone" in lowered or "birth" in lowered:
        return True
    person = person_label(label)
    named = label_kind(label)
    return (
        (person is not None and not person[1])
        or address_label(label)
        or (named is not None and named[0] in _PERSON_KINDS)
        or bool(label_kinds(label) & _PERSON_FIELDS)
    )


def _named_cell(label: str, text: str, start: int, end: int, people: Callable[[], bool]) -> Span | None:
    """The cell typed by what its label names, when it holds a value of that kind whole. ``people()``: the table has
    columns about people (asked only when a label needs to know)."""
    surface = " ".join(text[start:end].split())
    person = person_label(label)
    if person is not None:
        least, needs_people = person
        if (not needs_people or people()) and table_name(text, start, end, least):
            return make_span(start, end, E.PERSON, f"{SOURCE}:person", surface.casefold(), 0.7)
        return None
    if street_label(label) and table_street(text, start, end):
        return make_span(start, end, E.ADDRESS, f"{SOURCE}:address", surface.casefold(), 0.85)
    if number_label(label):
        if table_house_number(text, start, end):
            return make_span(start, end, E.ADDRESS, f"{SOURCE}:address", surface.casefold(), 0.8)
        return None
    if address_label(label):
        if table_address(text, start, end):
            return make_span(start, end, E.ADDRESS, f"{SOURCE}:address", surface.casefold(), 0.85)
        return None
    if place_label(label):  # "State" also heads a ticket's status: only in a table about people
        if people() and table_place(text, start, end):
            return make_span(start, end, E.LOCATION, f"{SOURCE}:place", surface.casefold(), 0.8)
        return None
    named = label_kind(label)
    if named is None:
        return None
    hit = table_value(text, start, end, *named)
    if hit is None:
        return None
    kind = named[0]
    return make_span(hit[0], hit[1], _KIND_TYPE[kind], f"{CUE_SOURCE}:{kind}", text[hit[0] : hit[1]].upper(), 0.8)


# A JSON object written into text ("klant": {"woonplaats": "Tilburg"}), and the "Label: value" lines of a form or a
# YAML file ("Huisnummer: 12a", "  plaats: Venlo"): each value under the key or label that names it, read the way
# the second cell of a two-column table row is.
_JSON_PAIR_RE = re.compile(r'"(?P<key>[^"\n\\]{1,60})"[ \t]*:[ \t]*"(?P<value>[^"\n\\]{1,200})"')
# The number of a form's item before its label: "12. ", "49.c. ", "3a) ", "b. ".
_ITEM = r"(?:(?:\d{1,3}[a-z]?|[a-z])(?:\.[a-z0-9]{1,2})?[.)][ \t]+)?"
_FORM_LINE_RE = re.compile(
    r"(?m)^[ \t]*"
    + _ITEM
    + r"(?:[-*•][ \t]*)?(?:\*\*)?(?P<key>[^\W\d_][^:：\n]{0,40}?)(?:\*\*)?[ \t]*[:：](?:\*\*)?[ \t]+"
    r"(?P<value>[^\n]{1,200}?)[ \t]*$"
)


# A printed form puts the value after its label with a run of blanks instead of a colon: "City or Town  Raleigh",
# "(Last Name)   Mercer". Only labels that name a person's data count, so a heading over columns does not.
_SPACED_LINE_RE = re.compile(
    r"(?m)^[ \t]*" + _ITEM + r"\(?(?P<key>[^\W\d_][^\W\d_ ()]{0,20}(?: [^\W\d_][^\W\d_ ()]{0,20}){0,3})\)?[ \t]{2,}"
    r"(?P<value>[^\s(][^\t\n]{0,58}?)[ \t]*$"
)


def _spaced_label(label: str) -> bool:
    return person_label(label) is not None or address_label(label) or place_label(label) or number_label(label)


def form_cells(text: str) -> Iterator[tuple[str, int, int]]:
    """(label, start, end) for each value of a JSON pair, a "Label: value" line or a "Label   value" line."""
    if '":' in text or '" :' in text:
        for m in _JSON_PAIR_RE.finditer(text):
            yield m.group("key"), m.start("value"), m.end("value")
    if ":" in text or "：" in text:
        for m in _FORM_LINE_RE.finditer(text):
            yield m.group("key"), m.start("value"), m.end("value")
    if "  " in text:
        for m in _SPACED_LINE_RE.finditer(text):
            if "  " not in m.group("value") and _spaced_label(m.group("key")):
                yield m.group("key"), m.start("value"), m.end("value")


def find_table_fields(text: str) -> list[Span]:
    spans: list[Span] = []
    cells = list(table_cells(text))
    forms = list(form_cells(text))
    labels = {cell[0] for cell in cells + forms}
    known: list[bool] = []

    def people() -> bool:
        if not known:
            known.append(any(_about_a_person(label) for label in labels))
        return known[0]

    for label, start, end in cells:
        spans.extend(find_labelled(label, text[start:end], start))
    # Credentials and checked identifiers in a form line or a JSON pair are read in prose order already
    # (detectors/statements.py, cued.py), which knows a hash from a password: only the kinds a label alone decides
    # here (names, addresses, places, cued shapes) are added for them.
    for label, start, end in cells + forms:
        named = _named_cell(label, text, start, end, people)
        if named is not None:
            spans.append(named)
    return spans
