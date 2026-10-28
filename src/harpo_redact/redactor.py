"""Turn detected spans into placeholders.

Modes
-----
relational  ``[PERSON_1]``  same value -> same index across the whole request
generic     ``[PERSON]``    no linkability at all
generic + context repair    ``[PERSON_A]`` / ``[PERSON_B]`` only inside a sentence
                            that mentions two different values of one type;
                            letters restart every sentence

Nothing here is reversible: the value-to-index map is a local variable that is
discarded when ``render`` returns.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from dataclasses import dataclass, replace
from typing import Literal

from .entities import PLACEHOLDER_RE, PRIORITY, EntityType, Span

Mode = Literal["relational", "generic"]

HONORIFICS = frozenset({"mr", "mrs", "ms", "miss", "mx", "dr", "prof", "sir", "madam", "dame", "lord", "lady"})
_ABBREVIATIONS = frozenset(
    {
        "mr",
        "mrs",
        "ms",
        "mx",
        "dr",
        "prof",
        "st",
        "inc",
        "ltd",
        "jr",
        "sr",
        "vs",
        "etc",
        "eg",
        "ie",
        "no",
        "fig",
        "co",
        "corp",
        "dept",
        "mt",
        "approx",
        "est",
    }
)
_BOUNDARY_RE = re.compile(r"[.!?]+[\"')\]]*\s+|\n\s*\n")
_WORD_RE = re.compile(r"\S+")


def _previous_word(text: str, end: int) -> str:
    """The run of ASCII letters and dots that ends at ``end``. Abbreviations are short, so the walk
    stops after 40 characters instead of rescanning from the start of the text for every period."""
    i = end
    while i > 0 and end - i < 40 and text[i - 1].isascii() and (text[i - 1].isalpha() or text[i - 1] == "."):
        i -= 1
    while i < end and text[i] == ".":
        i += 1
    return text[i:end]


@dataclass(frozen=True, slots=True)
class Redaction:
    start: int
    end: int
    type: str  # the placeholder's name: a built-in type, or a custom type ("EMPLOYEE_ID")
    placeholder: str
    sources: frozenset[str]


@dataclass(slots=True)
class RenderResult:
    texts: list[str]
    redactions: list[list[Redaction]]
    collapsed_sentences: int
    repaired_sentences: int
    placeholder_ratio: float
    words: int


# --------------------------------------------------------------------------- span hygiene
def protect_placeholders(text: str, spans: list[Span]) -> list[Span]:
    """Cut existing placeholders (e.g. from earlier model replies) out of spans."""
    regions = [(m.start(), m.end()) for m in PLACEHOLDER_RE.finditer(text)]
    if not regions:
        return spans
    kept: list[Span] = []
    for span in spans:
        pieces = [(span.start, span.end)]
        for a, b in regions:
            nxt: list[tuple[int, int]] = []
            for x, y in pieces:
                if b <= x or a >= y:
                    nxt.append((x, y))
                    continue
                if x < a:
                    nxt.append((x, a))
                if b < y:
                    nxt.append((b, y))
            pieces = nxt
        if pieces == [(span.start, span.end)]:
            kept.append(span)
            continue
        for x, y in pieces:
            while x < y and not text[x].isalnum():
                x += 1
            while y > x and not text[y - 1].isalnum():
                y -= 1
            if sum(c.isalnum() for c in text[x:y]) >= 2:
                kept.append(replace(span, start=x, end=y))
    return kept


def merge_spans(text: str, spans: list[Span]) -> list[Span]:
    """Union overlapping spans; the merged span takes the highest-priority type.

    Using the union (not the "winner") guarantees no fragment of any detected
    value is left exposed next to a placeholder.
    """
    if not spans:
        return []
    ordered = sorted(spans, key=lambda s: (s.start, -s.end))
    merged = [ordered[0]]
    for span in ordered[1:]:
        last = merged[-1]
        if span.start < last.end:
            merged[-1] = _combine(text, last, span)
        else:
            merged.append(span)
    return merged


def _combine(text: str, a: Span, b: Span) -> Span:
    start, end = min(a.start, b.start), max(a.end, b.end)
    winner = a if PRIORITY[a.type] >= PRIORITY[b.type] else b
    if (start, end) == (winner.start, winner.end):
        canonical = winner.canonical
    else:
        canonical = " ".join(text[start:end].split()).casefold()
    inner = (a.inner | b.inner | {a.type, b.type}) - {winner.type}
    return Span(start, end, winner.type, a.sources | b.sources, canonical, max(a.confidence, b.confidence), inner)


# --------------------------------------------------------------------------- sentences
def sentence_bounds(text: str) -> list[tuple[int, int]]:
    bounds: list[tuple[int, int]] = []
    start = 0
    for m in _BOUNDARY_RE.finditer(text):
        if m.group()[0] == ".":
            prev = _previous_word(text, m.start())
            if prev:
                word = prev.replace(".", "").lower()
                if word in _ABBREVIATIONS or len(word) == 1:
                    continue
        bounds.append((start, m.end()))
        start = m.end()
    if start < len(text):
        bounds.append((start, len(text)))
    return bounds or [(0, len(text))]


# --------------------------------------------------------------------------- linking keys
# A key is (label, canonical value): the label is the type, or a custom type's name, so each custom type
# numbers its own placeholders ([EMPLOYEE_ID_1], [EMPLOYEE_ID_2]).
_Key = tuple[str, str]
_PERSON = EntityType.PERSON.value


def _key(span: Span) -> _Key:
    canonical = span.canonical
    if span.type is EntityType.PERSON:
        tokens = [t.strip(".,") for t in canonical.split()]
        while len(tokens) > 1 and tokens[0] in HONORIFICS:
            tokens = tokens[1:]
        canonical = " ".join(tokens) or canonical
    return span.label, canonical


def _person_aliases(keys: list[_Key]) -> dict[_Key, _Key]:
    """Link "Smith" / "de Vries" to the one longer name that starts or ends with it."""
    people = [k for k in keys if k[0] == _PERSON]
    aliases: dict[_Key, _Key] = {}
    for short in people:
        short_tokens = short[1].split()
        candidates = []
        for long in people:
            long_tokens = long[1].split()
            if len(long_tokens) <= len(short_tokens):
                continue
            n = len(short_tokens)
            if long_tokens[:n] == short_tokens or long_tokens[-n:] == short_tokens:
                candidates.append(long)
        if candidates:
            longest = max(len(c[1].split()) for c in candidates)
            top = [c for c in candidates if len(c[1].split()) == longest]
            if len(top) == 1:
                aliases[short] = top[0]
    return aliases


def _letters(n: int) -> str:
    out = ""
    n += 1
    while n:
        n, rem = divmod(n - 1, 26)
        out = chr(65 + rem) + out
    return out


# --------------------------------------------------------------------------- render
def render(
    texts: list[str],
    spans_per_text: list[list[Span]],
    mode: Mode,
    context_repair: bool,
) -> RenderResult:
    keys_in_order: list[_Key] = []
    seen: set[_Key] = set()
    for spans in spans_per_text:
        for span in spans:
            k = _key(span)
            if k not in seen:
                seen.add(k)
                keys_in_order.append(k)
    aliases = _person_aliases(keys_in_order)

    def resolve(span: Span) -> _Key:
        k = _key(span)
        return aliases.get(k, k)

    index: dict[_Key, int] = {}
    counters: dict[str, int] = {}
    for spans in spans_per_text:
        for span in spans:
            k = resolve(span)
            if k not in index:
                counters[k[0]] = counters.get(k[0], 0) + 1
                index[k] = counters[k[0]]

    out_texts: list[str] = []
    out_redactions: list[list[Redaction]] = []
    collapsed = repaired = 0
    for text, spans in zip(texts, spans_per_text, strict=True):
        labels: dict[int, str] = {}
        if mode == "relational":
            for i, span in enumerate(spans):
                labels[i] = f"[{span.label}_{index[resolve(span)]}]"
        else:
            for s0, s1 in sentence_bounds(text):
                members = [(i, sp) for i, sp in enumerate(spans) if s0 <= sp.start < s1]
                per_type: dict[str, OrderedDict[_Key, None]] = {}
                for _, sp in members:
                    per_type.setdefault(sp.label, OrderedDict())[resolve(sp)] = None
                ambiguous = {t for t, ks in per_type.items() if len(ks) >= 2}
                if ambiguous and context_repair:
                    repaired += 1
                elif ambiguous:
                    collapsed += 1
                for i, sp in members:
                    if context_repair and sp.label in ambiguous:
                        position = list(per_type[sp.label]).index(resolve(sp))
                        labels[i] = f"[{sp.label}_{_letters(position)}]"
                    else:
                        labels[i] = f"[{sp.label}]"
        pieces: list[str] = []
        redactions: list[Redaction] = []
        cursor = 0
        for i, span in enumerate(spans):
            label = labels[i]
            pieces.append(text[cursor : span.start])
            pieces.append(label)
            redactions.append(Redaction(span.start, span.end, span.label, label, span.sources))
            cursor = span.end
        pieces.append(text[cursor:])
        out_texts.append("".join(pieces))
        out_redactions.append(redactions)

    words = placeholders = 0
    for out in out_texts:
        words += len(_WORD_RE.findall(out))
        placeholders += len(PLACEHOLDER_RE.findall(out))
    ratio = placeholders / words if words else 0.0
    return RenderResult(out_texts, out_redactions, collapsed, repaired, ratio, words)
