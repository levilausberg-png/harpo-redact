"""Obfuscation guard: Unicode normalisation with an exact map back to the input.

The outgoing text is the *normalised* text: NFKC-folded (full-width digits,
ligatures and other compatibility forms become their plain equivalents) and
stripped of every Unicode format character (category ``Cf``). That removes
zero-width joiners used to split identifiers, bidi overrides used to disguise
text, and the tag characters used for invisible prompt smuggling.

Detection runs on the normalised text. Offsets are mapped back to the original
input so the console can highlight exactly what the user typed.

A right-to-left override (U+202E) makes the characters after it display in
reverse order: a card number can be stored backwards after one and still be
shown the right way round. The override is stripped like any format character,
and the stretch it covered is recorded (``reversed_runs``) so detection can
also read it the way it is displayed.
"""

from __future__ import annotations

import functools
import re
import unicodedata
from dataclasses import dataclass, field

_WORD_RE = re.compile(r"\w+")
_SURROGATE_RE = re.compile("[\ud800-\udfff]")
_NON_ASCII_DIGIT_RE = re.compile(r"(?![0-9])\d")


@functools.cache
def _format_chars() -> re.Pattern[str]:
    """A class of every format character (category Cf) Unicode has, built once: what normalising strips."""
    ranges: list[tuple[int, int]] = []
    for low, high in ((0x80, 0x30000), (0xE0000, 0xE1000)):
        for code in range(low, high):
            if unicodedata.category(chr(code)) == "Cf":
                if ranges and ranges[-1][1] == code - 1:
                    ranges[-1] = (ranges[-1][0], code)
                else:
                    ranges.append((code, code))
    return re.compile("[" + "".join(f"\\U{a:08x}-\\U{b:08x}" for a, b in ranges) + "]")


@dataclass(slots=True)
class Normalized:
    text: str
    removed_format_chars: int = 0
    mixed_script_tokens: int = 0
    # Per character of ``text``: [start, end) of the source cluster in the original.
    _starts: list[int] | None = field(default=None, repr=False)
    _ends: list[int] | None = field(default=None, repr=False)
    exact_mapping: bool = True
    changed: bool = False
    # [start, end) ranges of ``text`` that a right-to-left override displays in reverse order.
    reversed_runs: tuple[tuple[int, int], ...] = ()

    def to_original(self, start: int, end: int) -> tuple[int, int] | None:
        """Map a [start, end) range in ``text`` back to the original input."""
        if not self.changed:
            return start, end
        if not self.exact_mapping or self._starts is None or self._ends is None:
            return None
        if start >= end or end > len(self._starts):
            return None
        return self._starts[start], self._ends[end - 1]


def _is_mark(ch: str) -> bool:
    return unicodedata.combining(ch) != 0 or unicodedata.category(ch) in ("Mn", "Mc", "Me")


def _script(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    for script in ("LATIN", "CYRILLIC", "GREEK"):
        if name.startswith(script):
            return script
    return None


def count_mixed_script_tokens(text: str) -> int:
    """Count words mixing Latin with Cyrillic or Greek letters (homoglyph spoofing)."""
    if text.isascii():
        return 0
    count = 0
    for m in _WORD_RE.finditer(text):
        word = m.group()
        if word.isascii():
            continue
        scripts = {s for s in (_script(c) for c in word) if s}
        if "LATIN" in scripts and len(scripts) > 1:
            count += 1
    return count


# Cyrillic and Greek letters that look like Latin ones. Folded only inside words that mix them with Latin
# letters ("jаne" with a Cyrillic а), one character for one, so offsets stay exact. Russian or Greek text
# (no Latin in the word) is left alone.
_CONFUSABLES = str.maketrans(
    "аеорсухіјѕһԁԛԝӏАВЕКМНОРСТХУІЈЅαονικτυχΑΒΕΖΗΙΚΜΝΟΡΤΥΧ",
    "aeopcyxijshdqwlABEKMHOPCTXYIJSaovikutxABEZHIKMNOPTYX",
)


def fold_confusables(text: str) -> str:
    def fix(m: re.Match[str]) -> str:
        word = m.group()
        scripts = {sc for sc in (_script(c) for c in word) if sc}
        return word.translate(_CONFUSABLES) if "LATIN" in scripts and len(scripts) > 1 else word

    return _WORD_RE.sub(fix, text)


CONFUSABLE_CHARS = frozenset(chr(k) for k in _CONFUSABLES)

_RLO = "\u202e"
# What ends a right-to-left override: pop (PDF), the other embeddings and overrides, and the isolates.
_OVERRIDE_ENDS = frozenset("\u202a\u202b\u202c\u202d\u2066\u2067\u2068\u2069")


def fold_all_confusables(text: str) -> str:
    """Every look-alike letter read as its Latin twin, one for one (for shadow views, never for output)."""
    return text.translate(_CONFUSABLES)


def _fold(c: str) -> str:
    """Any Unicode decimal digit becomes its ASCII digit (Arabic-Indic, Devanagari, ...)."""
    if c.isascii():
        return c
    value = unicodedata.decimal(c, None)
    return str(value) if value is not None else c


def normalize(original: str) -> Normalized:
    if original.isascii():
        # NFKC is the identity on ASCII and ASCII has no format characters.
        return Normalized(text=original)
    if (
        _format_chars().search(original) is None
        and _SURROGATE_RE.search(original) is None
        and _NON_ASCII_DIGIT_RE.search(original) is None
        and unicodedata.is_normalized("NFKC", original)
        and not count_mixed_script_tokens(original)
    ):
        return Normalized(text=original)  # nothing to strip, fold or map: the text is its own normal form
    source = original
    if any("\ud800" <= c <= "\udfff" for c in original):
        # Lone surrogates (JSON allows "\ud800") can't be encoded; replace them 1:1.
        source = "".join("\ufffd" if "\ud800" <= c <= "\udfff" else c for c in original)

    out: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    removed = 0
    runs: list[tuple[int, int]] = []
    override_at: int | None = None  # where the open right-to-left override starts in ``out``
    i, n = 0, len(source)
    while i < n:
        ch = source[i]
        if override_at is not None and (ch in _OVERRIDE_ENDS or ch in "\n\r "):
            if len(out) - override_at >= 2:
                runs.append((override_at, len(out)))
            override_at = None
        if unicodedata.category(ch) == "Cf":
            if ch == _RLO and override_at is None:
                override_at = len(out)
            removed += 1
            i += 1
            continue
        j = i + 1
        while j < n and _is_mark(source[j]):
            j += 1
        folded = unicodedata.normalize("NFKC", source[i:j])
        for c in folded:
            if unicodedata.category(c) == "Cf":  # NFKC can surface format chars
                continue
            out.append(_fold(c))
            starts.append(i)
            ends.append(j)
        i = j
    if override_at is not None and len(out) - override_at >= 2:
        runs.append((override_at, len(out)))

    text = "".join(out)
    stripped = "".join(c for c in source if unicodedata.category(c) != "Cf")
    whole = unicodedata.normalize("NFKC", stripped)
    whole = "".join(_fold(c) for c in whole if unicodedata.category(c) != "Cf")
    exact = whole == text
    if not exact:
        # Rare: composition across clusters (e.g. conjoining Hangul jamo).
        # The whole-string form is authoritative; offsets fall back to it.
        text = whole

    mixed = count_mixed_script_tokens(text)
    if mixed:
        text = fold_confusables(text)
    return Normalized(
        text=text,
        removed_format_chars=removed,
        mixed_script_tokens=mixed,
        _starts=starts if exact else None,
        _ends=ends if exact else None,
        exact_mapping=exact,
        changed=text != original,
        reversed_runs=tuple(runs) if exact else (),
    )
