"""Entity types and the span model shared by every detection layer."""

from __future__ import annotations

import re
import threading
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from enum import StrEnum


class EntityType(StrEnum):
    """Every type the gateway can redact, listed from highest to lowest priority.

    When two detections overlap, the merged span takes the type that appears
    first in this list.
    """

    PRIVATE_KEY = "PRIVATE_KEY"
    SECRET = "SECRET"  # regex or label, not a credential  # noqa: S105  # nosec B105
    ENCODED_DATA = "ENCODED_DATA"
    CREDIT_CARD = "CREDIT_CARD"
    IBAN = "IBAN"
    US_SSN = "US_SSN"
    NL_BSN = "NL_BSN"
    UK_NINO = "UK_NINO"
    NATIONAL_ID = "NATIONAL_ID"
    ID_DOCUMENT = "ID_DOCUMENT"
    ACCOUNT_ID = "ACCOUNT_ID"
    CRYPTO_ADDRESS = "CRYPTO_ADDRESS"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    IP_ADDRESS = "IP_ADDRESS"
    DEVICE_ID = "DEVICE_ID"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    ADDRESS = "ADDRESS"
    PROTECTED_TERM = "PROTECTED_TERM"
    PERSON = "PERSON"
    ORGANIZATION = "ORGANIZATION"
    LOCATION = "LOCATION"
    QUASI_ID = "QUASI_ID"
    DATE = "DATE"


_ORDER = list(EntityType)
PRIORITY: dict[EntityType, int] = {t: len(_ORDER) - i for i, t in enumerate(_ORDER)}

# Types that are never exempted by allow_terms and never "allowed" by accident.
CRITICAL_TYPES = frozenset({EntityType.PRIVATE_KEY, EntityType.SECRET, EntityType.ENCODED_DATA})

# Credentials: API keys, tokens, passwords and private keys. They are always redacted: never blocked, never
# allowed, never switched off. The request goes on with a placeholder where the key was.
ALWAYS_REDACTED = frozenset({EntityType.PRIVATE_KEY, EntityType.SECRET})

# Spans found by a custom type carry its name as a source: "custom:EMPLOYEE_ID". Sources are merged as a union,
# so the name survives overlaps, shadow views and decoding.
CUSTOM_SOURCE = "custom:"


class _Placeholders:
    """A placeholder the gateway itself emits: [PERSON], [PERSON_3], [PERSON_A], and the same shapes for the
    custom types in the configuration ([EMPLOYEE_ID_2]).

    The vocabulary only grows. Once a name is known its placeholders stay recognised for the life of the
    process, so a policy change never turns a placeholder from an earlier reply back into text to scan. Only
    exact names match: ``[ANYTHING_1]`` is not a placeholder, so nothing can hide inside that shape.
    """

    __slots__ = ("_lock", "_names", "_re")

    def __init__(self, names: Iterable[str]) -> None:
        self._lock = threading.Lock()
        self._names: tuple[str, ...] = tuple(names)
        self._re = self._compile(self._names)

    @staticmethod
    def _compile(names: tuple[str, ...]) -> re.Pattern[str]:
        alternation = "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))
        return re.compile(r"\[(?:" + alternation + r")(?:_(?:\d{1,6}|[A-Z]{1,3}))?\]")

    def register(self, names: Iterable[str]) -> None:
        with self._lock:
            new = tuple(n for n in dict.fromkeys(names) if n not in self._names)
            if new:
                names_now = self._names + new
                self._re = self._compile(names_now)  # publish the pattern first: readers never see a half update
                self._names = names_now

    @property
    def pattern(self) -> str:
        return self._re.pattern

    def finditer(self, text: str) -> Iterator[re.Match[str]]:
        return self._re.finditer(text)

    def findall(self, text: str) -> list[str]:
        return self._re.findall(text)

    def search(self, text: str) -> re.Match[str] | None:
        return self._re.search(text)

    def match(self, text: str) -> re.Match[str] | None:
        return self._re.match(text)

    def fullmatch(self, text: str) -> re.Match[str] | None:
        return self._re.fullmatch(text)

    def sub(self, repl: str, text: str) -> str:
        return self._re.sub(repl, text)


PLACEHOLDER_RE = _Placeholders(t.value for t in _ORDER)


def custom_names(sources: Iterable[str]) -> list[str]:
    """The custom types named in a span's sources, sorted."""
    return sorted(s[len(CUSTOM_SOURCE) :] for s in sources if s.startswith(CUSTOM_SOURCE))


@dataclass(frozen=True, slots=True)
class Span:
    """A detected value inside one text segment.

    ``canonical`` is the normalised value used to give repeated values the same
    index. It holds raw personal data, so it is excluded from ``repr`` and must
    never be serialised, logged or returned by the API.
    """

    start: int
    end: int
    type: EntityType
    sources: frozenset[str]
    canonical: str = field(repr=False, compare=False)
    confidence: float = 1.0
    # Other types this span stands for: values found inside an encoded blob,
    # or lower-priority detections absorbed when overlapping spans merged.
    # Policy checks them too, so a base64-wrapped private key blocks exactly
    # like a plain one.
    inner: frozenset[EntityType] = field(default=frozenset(), compare=False)

    @property
    def priority(self) -> int:
        return PRIORITY[self.type]

    @property
    def label(self) -> str:
        """The name the placeholder carries: the type, or the custom type that found a protected term."""
        if self.type is EntityType.PROTECTED_TERM:
            names = custom_names(self.sources)
            if names:
                return names[0]
        return self.type.value


def make_span(
    start: int,
    end: int,
    etype: EntityType,
    source: str,
    canonical: str,
    confidence: float = 1.0,
) -> Span:
    return Span(start, end, etype, frozenset({source}), canonical, confidence)
