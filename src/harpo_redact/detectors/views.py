"""Shadow views: transformed copies of a text whose findings map back onto the original.

* **line joins**: a value broken over a line ("NL91 ABNA\\n0417 1643 00") read as one line
* **compact runs**: spelled-out digits ("four one one one ...", also Dutch, German, French and Spanish) and
  characters spaced one by one ("N L 9 1   A B N A ...", words apart by two to four spaces) read as what they spell
* **leet emails**: "j4n3@3x4mpl3.c0m" read with digits as the letters they stand for
* **display order**: text under a right-to-left override, stored backwards, read the way it is displayed
* **look-alikes**: Cyrillic and Greek letters next to digits or Latin text ("1АА", "арі03") read as Latin. The
  outgoing text folds them only inside mixed-script words, so Russian and Greek prose stays intact.
* **script spacing**: a blank where Chinese, Japanese or Korean text runs straight into Latin letters or digits
  ("jane@corp.example宛に", "4111111111111111で"), so values glued to a word of those scripts are read whole.

Each view says which parts of the original it changed. Callers keep only findings that involve a changed part,
and for line joins only types with strong validation, so a view cannot invent findings in ordinary text.
Built from what LeakBench and the redaction matrix found (bench/leakbench.py, tests/redaction_matrix.py).
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Sequence
from dataclasses import dataclass

from ..entities import EntityType as E
from ..normalize import CONFUSABLE_CHARS, fold_all_confusables

_DIGIT_WORDS = {
    **dict.fromkeys(["zero", "oh", "nul", "null", "zéro", "zero", "cero"], "0"),
    **dict.fromkeys(["one", "een", "eins", "un", "une", "uno"], "1"),
    **dict.fromkeys(["two", "twee", "zwei", "zwo", "deux", "dos"], "2"),
    **dict.fromkeys(["three", "drie", "drei", "trois", "tres"], "3"),
    **dict.fromkeys(["four", "vier", "quatre", "cuatro"], "4"),
    **dict.fromkeys(["five", "vijf", "fünf", "cinq", "cinco"], "5"),
    **dict.fromkeys(["six", "zes", "sechs", "seis"], "6"),
    **dict.fromkeys(["seven", "zeven", "sieben", "sept", "siete"], "7"),
    **dict.fromkeys(["eight", "acht", "huit", "ocho"], "8"),
    **dict.fromkeys(["nine", "negen", "neun", "neuf", "nueve"], "9"),
}
_DIGIT_WORD_RE = re.compile(
    r"(?<![^\W\d_])(?:" + "|".join(sorted(map(re.escape, _DIGIT_WORDS), key=len, reverse=True)) + r")(?![^\W\d_])",
    re.IGNORECASE,
)
_SEPARATOR_RE = re.compile(r"[\s,\-]*")
_MIN_SPELLED = 7  # a phone number or longer; "one, two, three" in prose stays prose
# Single characters, one space apart within a word and two to four spaces between words.
_SPACED_RE = re.compile(r"(?<!\S)\S(?= )(?: {1,4}\S(?!\S)){5,}")  # six or more: "S W 1 A   1 A A"
_LEET = str.maketrans("013457", "oieast")
# A match can start only where a token starts. Without the lookbehind every position of a long token before an
# "@" was a new start, so "aaaa...a@" took quadratic time (found by tests/test_robustness.py).
_LEET_EMAIL_RE = re.compile(r"(?<![^\s@<>()\[\]\"'])[^\s@<>()\[\]\"']+@[^\s@<>()\[\]\"']+\.[^\s@<>()\[\]\"']+")
# Types whose validation is strong enough to trust across a line break. A phone number joins in international
# form, or nationally when a phone cue comes just before it.
LINE_JOIN_TYPES = frozenset(
    {E.CREDIT_CARD, E.IBAN, E.SECRET, E.PRIVATE_KEY, E.EMAIL, E.CRYPTO_ADDRESS, E.US_SSN, E.NL_BSN, E.UK_NINO,
     E.NATIONAL_ID, E.ENCODED_DATA, E.PHONE, E.ID_DOCUMENT, E.ACCOUNT_ID, E.DEVICE_ID, E.IP_ADDRESS,
     E.DATE_OF_BIRTH, E.ADDRESS, E.PROTECTED_TERM}
)  # fmt: skip
# Joined across a break even when it ends a value found whole on the first line: stopping at the break would let
# the rest of a key cut in two ("Tr0ub\n4dor&3x") through. A line that starts a new entry still ends it
# (line_starts_new_entry).
BLOCKING_TYPES = frozenset({E.SECRET, E.PRIVATE_KEY, E.ENCODED_DATA})
# Two lines are separate entries when both are assignments of the same kind: "A=1" then "B=2" (.env, INI, a diff of
# either, "export A=1"), or "a: 1" then "b: 2" (YAML, also "- a: 1" and a bare parent "b:").
_ASSIGN_EQ_RE = re.compile(r"(?m)^[ \t]{0,32}[+\-]?[ \t]{0,4}(?:export[ \t]{1,4})?[A-Za-z_][\w.\-]{0,63}[ \t]{0,4}=")
_ASSIGN_COLON_RE = re.compile(
    r"(?m)^[ \t]{0,32}[+\-]?[ \t]{0,4}(?:-[ \t]{1,4})?[\"']?[A-Za-z_][\w.\-]{0,63}[\"']?[ \t]{0,4}:(?=[ \t\r\n]|\Z)"
)
# A line no key continues into: a log line's timestamp or level, a shell prompt, a comment, a list item, a quote, a
# URL, a heredoc end, a code fence, a lone tag or bracket, a shell block's end ("done", "fi < x"), a .netrc entry, or
# prose ("Can you check ..."). Every repeat is bounded, so the pattern is linear even when searched (as the robustness
# test does).
_NEW_LINE_RE = re.compile(
    r"(?m)^[ \t]{0,32}(?:"
    r"\[?\d{4}[-/.]\d{2}[-/.]\d{2}(?:[T \t]\d|\b)"
    r"|\[?\d{1,2}:\d{2}(?::\d{2})?\b"
    r"|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[ \t]{1,2}\d{1,2}\b"
    r"|(?:INFO|WARN|WARNING|ERROR|DEBUG|TRACE|FATAL|CRITICAL)\b"
    r"|[$%>#*+\-][ \t]"
    r"|[a-z][a-z0-9+.\-]{1,15}://"
    r"|(?:EOF|END|```|~~~|</?[A-Za-z][\w\-]{0,30}>|[\]})]{1,3}[,;]?)[ \t]{0,8}(?=\r?\n|\Z)"
    r"|(?:done|fi|esac|then|else|do)(?:[ \t]{0,8}(?=\r?\n|\Z)|[ \t]{0,4}[;|&<>])"
    r"|(?:machine|login|password|account|macdef)[ \t]{1,4}[^ \t\r\n]"
    r"|[A-Z][a-z]{1,15}(?:'[a-z]{1,3})?[ \t]{1,4}[a-z]{2}"
    r")"
)
# Words that say a number is a phone number. Not "call" or "number": "Call 020\n7946095" can be two figures.
PHONE_CUE_RE = re.compile(
    r"(?i)(?<![a-z])(?:phone|tel|telephone|mobile|mobiel|cell|gsm|fax|whatsapp|telefoon|telefon|telefono"
    r"|t[ée]l[ée]phone|handy|portable|movil|móvil)(?![a-z])"
)


@dataclass(frozen=True)
class View:
    text: str
    starts: list[int]  # per view character: [start, end) in the original
    ends: list[int]
    changed: list[tuple[int, int]]  # original ranges the view rewrote
    spelled: tuple[tuple[int, int, str], ...] = ()  # (start, end, digits) of each spelled-out run

    def to_original(self, start: int, end: int) -> tuple[int, int]:
        """The original range a [start, end) range of the view came from. Works for reordered views too."""
        return min(self.starts[start:end]), max(self.ends[start:end])


def line_starts_new_entry(text: str, a: int, b: int) -> bool:
    """Whether the line at ``b`` is a new entry rather than the rest of a value cut by the break at ``a``..``b``:
    a line no key continues into, or an assignment of the same kind as the line the value is on."""
    if _NEW_LINE_RE.match(text, b):
        return True
    line = text.rfind("\n", 0, a) + 1
    return any(rx.match(text, line) and rx.match(text, b) for rx in (_ASSIGN_EQ_RE, _ASSIGN_COLON_RE))


def line_join_view(text: str, *, everywhere: bool = False) -> View | None:
    """Single line breaks removed. A blank line (paragraph break) is kept.

    By default only breaks next to digits or an "@" are joined (a value worth rejoining); ``everywhere`` joins
    every single break, for detectors that are exact matches anyway (protected terms, seed phrases).
    """
    if "\n" not in text:
        return None
    out: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    changed: list[tuple[int, int]] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "\r\n":
            j = i + 2 if text.startswith("\r\n", i) else i + 1
            blank = text.startswith("\n", j) or text.startswith("\r\n", j) or (i > 0 and text[i - 1] == "\n")
            if not blank and out and j < n and (everywhere or _value_like_join(text, i, j)):
                changed.append((i, j))
                i = j
                continue
        out.append(c)
        starts.append(i)
        ends.append(i + 1)
        i += 1
    if not changed:
        return None
    return View("".join(out), starts, ends, changed)


def _value_like_join(text: str, i: int, j: int) -> bool:
    """Only breaks near digits or an "@" (within two words either side) can split a value worth rejoining:
    "14 Mar|ch 1985", "1600 Pennsyl|vania Avenue". Wrapped prose is left alone."""
    around = text[max(0, i - 48) : i].split()[-2:] + text[j : j + 48].split()[:2]
    return any(c.isdigit() or c == "@" for word in around for c in word)


def windows(view: View, margin: int) -> list[tuple[int, int]]:
    """Ranges of the view around what it changed, merged: the only places worth scanning."""
    spans: list[tuple[int, int]] = []
    k = 0
    for start, end in sorted(view.changed):
        while k < len(view.starts) and view.ends[k] <= start:
            k += 1
        first = k
        while k < len(view.starts) and view.starts[k] < end:
            k += 1
        spans.append((max(0, first - margin), min(len(view.text), max(k, first + 1) + margin)))
    merged: list[tuple[int, int]] = []
    for s, e in sorted(spans):
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))
    return merged


def _spaced_pieces(m: re.Match[str]) -> list[tuple[str, int, int]]:
    """The characters of a spaced run; a gap of two or more spaces is the space between two words."""
    pieces: list[tuple[str, int, int]] = []
    run, base = m.group(), m.start()
    k = 0
    while k < len(run):
        if run[k] != " ":
            pieces.append((run[k], base + k, base + k + 1))
            k += 1
            continue
        gap_end = k
        while gap_end < len(run) and run[gap_end] == " ":
            gap_end += 1
        if gap_end - k >= 2:
            pieces.append((" ", base + k, base + gap_end))
        k = gap_end
    return pieces


def compact_view(text: str) -> View | None:
    """Spelled-out digit runs and one-by-one spaced characters, read as what they spell."""
    edits: list[tuple[int, int, list[tuple[str, int, int]]]] = []  # (start, end, [(char, src_start, src_end)])
    run: list[re.Match[str]] = []
    spelled: list[tuple[int, int, str]] = []

    def flush() -> None:
        if len(run) >= _MIN_SPELLED:
            pieces = [(_DIGIT_WORDS[m.group().casefold()], m.start(), m.end()) for m in run]
            edits.append((run[0].start(), run[-1].end(), pieces))
            spelled.append((run[0].start(), run[-1].end(), "".join(p[0] for p in pieces)))
        run.clear()

    for m in _DIGIT_WORD_RE.finditer(text):
        if run and not _SEPARATOR_RE.fullmatch(text, run[-1].end(), m.start()):
            flush()
        run.append(m)
    flush()
    edits.extend((m.start(), m.end(), _spaced_pieces(m)) for m in _SPACED_RE.finditer(text))
    if not edits:
        return None
    edits.sort()
    out: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    changed: list[tuple[int, int]] = []
    cursor = 0
    for start, end, pieces in edits:
        if start < cursor:
            continue  # overlapping edits: the first one wins
        for k in range(cursor, start):
            out.append(text[k])
            starts.append(k)
            ends.append(k + 1)
        for ch, s, e in pieces:
            out.append(ch)
            starts.append(s)
            ends.append(e)
        changed.append((start, end))
        cursor = end
    for k in range(cursor, len(text)):
        out.append(text[k])
        starts.append(k)
        ends.append(k + 1)
    return View("".join(out), starts, ends, changed, tuple(spelled))


def leet_email_view(text: str) -> View | None:
    """Same length as the text: digits inside email-shaped tokens read as letters."""
    if "@" not in text:
        return None
    changed: list[tuple[int, int]] = []
    chars = list(text)
    for m in _LEET_EMAIL_RE.finditer(text):
        token = m.group()
        if not any(c in "013457" for c in token.rsplit(".", 1)[-1] + token.split("@", 1)[1]):
            continue  # an ordinary email; the email detector has it already
        chars[m.start() : m.end()] = token.translate(_LEET)
        changed.append((m.start(), m.end()))
    if not changed:
        return None
    return View("".join(chars), list(range(len(text))), list(range(1, len(text) + 1)), changed)


def display_order_view(text: str, runs: Sequence[tuple[int, int]]) -> View | None:
    """Stretches under a right-to-left override, reversed back into the order they are displayed in."""
    if not runs:
        return None
    chars = list(text)
    starts = list(range(len(text)))
    for a, b in runs:
        chars[a:b] = text[a:b][::-1]
        starts[a:b] = range(b - 1, a - 1, -1)
    return View("".join(chars), starts, [s + 1 for s in starts], [(a, b) for a, b in runs])


_TOKEN_RE = re.compile(r"\S+")


def lookalike_view(text: str) -> View | None:
    """Same length as the text: look-alike letters folded in tokens that also hold ASCII letters or digits."""
    if text.isascii():
        return None
    chars: list[str] | None = None
    changed: list[tuple[int, int]] = []
    for m in _TOKEN_RE.finditer(text):
        token = m.group()
        if token.isascii() or not any(c in CONFUSABLE_CHARS for c in token):
            continue
        if not any(c.isascii() and c.isalnum() for c in token):
            continue  # a Russian or Greek word: not a disguise
        if chars is None:
            chars = list(text)
        chars[m.start() : m.end()] = fold_all_confusables(token)
        changed.append((m.start(), m.end()))
    if chars is None:
        return None
    return View("".join(chars), list(range(len(text))), list(range(1, len(text) + 1)), changed)


# Chinese, Japanese and Korean put no blank between a word and the Latin letters or digits next to it
# ("4111111111111111で支払う", "jane@corp.example宛に", "+82 10-1234-5678으로"), so a pattern that needs a word to
# end there finds nothing. The spacing view puts a blank at each such seam.
_CJK_CHAR = "\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uac00-\ud7af\uf900-\ufaff"
_SEAM_RE = re.compile(f"(?<=[{_CJK_CHAR}])(?=[A-Za-z0-9+])|(?<=[A-Za-z0-9])(?=[{_CJK_CHAR}])")


_RUN_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@.+_-/:")


# A date or a time in figures ("26/11/1937에", "2024-03-14T09:30:00に", "October/48に"): a value at a seam only when
# the policy redacts dates.
_MONTH = (
    "january|february|march|april|may|june|july|august|september|october|november|december"
    "|jan|feb|mar|apr|jun|jul|aug|sep|sept|oct|nov|dec"
)
_DATE_RUN_RE = re.compile(
    r"\d{1,4}[/.\-]\d{1,2}[/.\-]\d{1,4}(?:T\d{1,2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?Z?)?"
    r"|\d{1,2}:\d{2}(?::\d{2})?"
    rf"|(?i:{_MONTH})[/.\-]\d{{1,4}}(?:[/.\-]\d{{1,4}})?"
)


_DIGITS = frozenset("0123456789")


def _digit_gap(text: str, i: int) -> bool:
    """A blank between two digits: the gap inside a number written in groups."""
    return text[i] == " " and text[i - 1 : i] in _DIGITS and text[i + 1 : i + 2] in _DIGITS


def _seam_run(text: str, seam: int, dates: bool = False) -> tuple[int, int] | None:
    """The Latin run at a seam when it could hold a value: an e-mail address, five digits or more, or eight
    characters or more with a digit. A number in groups is one run ("07 5871 2555で"). "2024年", "500円", "PDFで" and
    "Instagramで" are numbers and words of the text, and a date is one too unless ``dates`` (the policy redacts
    dates)."""
    start = end = seam
    if seam < len(text) and text[seam] in _RUN_CHARS:  # the run starts at the seam
        while end < len(text) and end - seam < 80 and (text[end] in _RUN_CHARS or _digit_gap(text, end)):
            end += 1
    else:  # the run ends at the seam
        while start > 0 and seam - start < 80 and (text[start - 1] in _RUN_CHARS or _digit_gap(text, start - 1)):
            start -= 1
    run = text[start:end]
    digits = sum(c.isdigit() for c in run)
    if not ("@" in run or digits >= 5 or (digits and len(run) >= 8)):
        return None
    if not dates and _DATE_RUN_RE.fullmatch(run.strip("._-/:+")):
        return None
    return start, end


def script_spacing_view(text: str, covered: Sequence[tuple[int, int]] = (), *, dates: bool = False) -> View | None:
    """A blank at every seam between a Chinese, Japanese or Korean character and a Latin run that could hold a
    value and that no finding in ``covered`` holds already (``dates``: dates count as values). ``changed`` holds the
    seams as empty ranges: a finding counts only if it starts or ends at one."""
    if text.isascii():
        return None  # no Chinese, Japanese or Korean in it
    seams = []
    for m in _SEAM_RE.finditer(text):
        run = _seam_run(text, m.start(), dates)
        if run is not None and not any(a <= run[0] and run[1] <= b for a, b in covered):
            seams.append(m.start())
    if not seams:
        return None
    out: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    previous = 0
    for seam in seams:
        out.append(text[previous:seam])
        starts.extend(range(previous, seam))
        ends.extend(range(previous + 1, seam + 1))
        out.append(" ")
        starts.append(seam)
        ends.append(seam)
        previous = seam
    out.append(text[previous:])
    starts.extend(range(previous, len(text)))
    ends.extend(range(previous + 1, len(text) + 1))
    return View("".join(out), starts, ends, [(seam, seam) for seam in seams])


def touches(start: int, end: int, changed: list[tuple[int, int]]) -> bool:
    return any(start < e and s < end for s, e in changed)


def meets(start: int, end: int, seams: list[tuple[int, int]]) -> bool:
    """Whether a finding starts or ends at a seam of the spacing view (or runs across one). ``seams`` is sorted."""
    i = bisect.bisect_left(seams, (start, start))
    return i < len(seams) and seams[i][0] <= end
