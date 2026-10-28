"""Custom types: your own names for values the gateway treats as sensitive.

Each type has exact terms and RE2 patterns (``detection.custom_types`` in the configuration, or the Policy page
of the console). A hit is a PROTECTED_TERM span that carries the type's name as a source ("custom:EMPLOYEE_ID"),
so the placeholder, the policy decision and the counts all use the name: ``[EMPLOYEE_ID_1]``.

* Terms match whole, in any case. The parts of a term (split at blanks, "_", "." and "-") may be apart by up to
  three separators or written as one identifier ("project_bluefin", "Project-Bluefin"), as in the protected
  registry. All terms of a type are compiled into one prefix tree, so a long list costs about as much as a short
  one, and the parts never overlap the separators, so the pattern runs in linear time.
* Patterns run on RE2, which matches in time linear in the input: a pattern typed into the console cannot make
  a prompt take seconds.
* A type whose action is "allow" is switched off: it is not looked for at all.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from typing import Any, Protocol

import re2

from ..entities import CUSTOM_SOURCE, EntityType, Span, make_span
from .secret_library import quiet_re2
from .secrets import term_chunks

# Between the words of a term: up to three spaces, underscores, dots or dashes (also a line break).
_SEPARATOR = r"[\s_.\-]{0,3}"
_SEP = "\x00"  # stands for the separator inside the prefix tree
_SEPARATORS = re.compile(r"[\s_.\-]+")


class CustomTypeSpec(Protocol):
    @property
    def name(self) -> str: ...
    @property
    def terms(self) -> list[str]: ...
    @property
    def patterns(self) -> list[str]: ...
    @property
    def action(self) -> str: ...


def _tokens(term: str) -> list[str]:
    out: list[str] = []
    for i, chunk in enumerate(term_chunks(term)):
        if i:
            out.append(_SEP)
        out.extend(chunk.lower())
    return out


def terms_regex(terms: Iterable[str]) -> re.Pattern[str] | None:
    """One case-insensitive pattern for many terms, built as a prefix tree so that matching does not try every
    term at every position. Same matches as ``(?<!\\w)(?:term1|term2|...)(?!\\w)`` with the separator rule."""
    cleaned = sorted({" ".join(t.split()) for t in terms if term_chunks(t)})
    if not cleaned:
        return None
    trie: dict[str, Any] = {}
    for term in cleaned:
        node = trie
        for token in _tokens(term):
            node = node.setdefault(token, {})
        node[""] = {}

    def build(node: dict[str, Any]) -> str:
        ends_here = "" in node
        branches = []
        for token in sorted(k for k in node if k):
            head = _SEPARATOR if token == _SEP else re.escape(token)
            branches.append(head + build(node[token]))
        if not branches:
            return ""
        body = branches[0] if len(branches) == 1 else "(?:" + "|".join(branches) + ")"
        if ends_here:  # a shorter term ends here; the longer ones are tried first
            return "(?:" + body + ")?"
        return body

    return re.compile(r"(?<!\w)(?:" + build(trie) + r")(?!\w)", re.IGNORECASE)


class CustomTypes:
    """The custom types in force, ready to scan."""

    def __init__(self, types: Iterable[CustomTypeSpec]) -> None:
        options = quiet_re2()
        self._types: list[tuple[str, re.Pattern[str] | None, list[Any]]] = []
        for spec in types:
            if spec.action == "allow":
                continue
            patterns = [re2.compile(p, options) for p in spec.patterns]
            self._types.append((CUSTOM_SOURCE + spec.name, terms_regex(spec.terms), patterns))

    @property
    def empty(self) -> bool:
        return not self._types

    def find(self, text: str) -> Iterator[Span]:
        for source, terms, patterns in self._types:
            if terms is not None:
                for m in terms.finditer(text):
                    # "Project Bluefin", "PROJECT-BLUEFIN" and "project_bluefin" are one value: one placeholder.
                    canonical = _SEPARATORS.sub("", m.group()).casefold()
                    yield make_span(m.start(), m.end(), EntityType.PROTECTED_TERM, source, canonical)
            for pattern in patterns:
                for m in pattern.finditer(text):
                    if m.end() > m.start():
                        yield make_span(m.start(), m.end(), EntityType.PROTECTED_TERM, source, m.group().casefold())
