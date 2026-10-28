"""The scan pipeline.

    normalise -> deterministic layers -> NER       (worker thread)
              -> local SLM on masked text          (async, optional)
              -> propagate -> allow filters -> protect placeholders
              -> merge -> render -> policy -> risk  (worker thread)

All texts of one request are scanned together, so relational indices are
consistent across the whole message array.
"""

from __future__ import annotations

import asyncio
import bisect
import contextvars
import functools
import re
import time
from dataclasses import dataclass, field, replace
from typing import Any, Literal

from . import risk
from .config import CustomType, Mode, Settings
from .detectors import fields, patterns, views
from .detectors.custom import CustomTypes
from .detectors.identifiers import decode_escapes, find_identifiers, remap
from .detectors.names import find_name_cues
from .detectors.ner import (
    NERDetector,
    instruction_verb,
    line_around,
    lowercase_words,
    plausible_entity,
    software_ranges,
)
from .detectors.secret_library import SecretLibrary, load_library
from .detectors.secrets import Registry, find_encoded, find_secrets
from .detectors.slm import FAILURES as SLM_FAILURES
from .detectors.slm import SLMDetector
from .entities import (
    ALWAYS_REDACTED,
    CRITICAL_TYPES,
    CUSTOM_SOURCE,
    PLACEHOLDER_RE,
    PRIORITY,
    EntityType,
    Span,
    custom_names,
    make_span,
)
from .normalize import Normalized, normalize
from .redactor import merge_spans, protect_placeholders, render
from .risk import Level, Reason

Layers = Literal["fast", "full"]

_PROPAGATED_TYPES = frozenset({EntityType.PERSON, EntityType.ORGANIZATION, EntityType.LOCATION, EntityType.QUASI_ID})
# Two-letter state codes that are also words or keywords.
_CODE_WORDS = frozenset("in or me ok hi as id oh pa ma al co la de mi ms md ne wa va so is it no to on at by".split())  # noqa: SIM905
_MODEL_SOURCES = frozenset({"ner", "slm", "name-rule"})
_NAME_PART_STOP = frozenset(
    {
        "mr", "mrs", "ms", "miss", "mx", "dr", "prof", "sir", "madam", "dame", "lord", "lady",
        "dear", "hi", "hello", "hey", "thanks", "customer", "client", "patient", "user", "team",
        "van", "von", "de", "der", "den", "la", "le", "da", "di", "del", "du", "st", "jr", "sr",
        "january", "february", "march", "april", "may", "june", "july", "august", "september",
        "october", "november", "december", "monday", "tuesday", "wednesday", "thursday", "friday",
        "saturday", "sunday", "the", "and", "of",
    }
)  # fmt: skip
_POSSESSIVE_RE = re.compile(r"(?:'s|’s)$")
_LOCAL_PART_SPLIT_RE = re.compile(r"[._+\-0-9]+")
_ROLE_MAILBOXES = frozenset(
    {
        "info", "support", "admin", "sales", "contact", "hello", "team", "noreply", "reply", "office", "billing",
        "jobs", "careers", "press", "help", "service", "security", "privacy", "legal", "finance", "accounts",
        "mail", "email", "user", "test", "example", "marketing", "news", "webmaster", "postmaster", "abuse",
    }
)  # fmt: skip


_BUILTIN_TYPES = {t.value: t for t in EntityType}


def _as_type(name: str) -> EntityType | str:
    """A built-in type by its name, or the custom type's name as it is."""
    return _BUILTIN_TYPES.get(name, name)


def _priority(name: str) -> int:
    builtin = _BUILTIN_TYPES.get(name)
    return PRIORITY[builtin] if builtin is not None else PRIORITY[EntityType.PROTECTED_TERM]


@functools.cache
def _library(gitleaks: bool, disabled: tuple[str, ...], extra: str | None, natural: bool, seeds: bool) -> SecretLibrary:
    return load_library(
        gitleaks=gitleaks, disabled=disabled, extra_rules_file=extra, natural_language=natural, seed_phrases=seeds
    )


class BudgetExceeded(Exception):
    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


@dataclass
class ScanBudget:
    """Per-scan limits (roadmap 24): time, decoded bytes, raw detections. Shared with worker threads
    through a context variable, because one Pipeline serves concurrent requests."""

    deadline: float
    decoded_left: int
    entities_left: int

    def time(self) -> None:
        if time.monotonic() > self.deadline:
            raise BudgetExceeded("time")

    def decoded(self, size: int) -> None:
        self.decoded_left -= size
        if self.decoded_left < 0:
            raise BudgetExceeded("decoded data")

    def entities(self, count: int) -> None:
        self.entities_left -= count
        if self.entities_left < 0:
            raise BudgetExceeded("detections")


_BUDGET: contextvars.ContextVar[ScanBudget | None] = contextvars.ContextVar("harpo_scan_budget", default=None)


def _ms(seconds: float) -> float:
    return round(seconds * 1000, 2)


@dataclass(frozen=True, slots=True)
class Finding:
    """One redaction, with offsets into the caller's original text (code points)."""

    type: str  # a built-in type, or a custom type's name
    start: int | None
    end: int | None
    placeholder: str
    sources: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": str(self.type),
            "start": self.start,
            "end": self.end,
            "placeholder": self.placeholder,
            "sources": list(self.sources),
        }


@dataclass(slots=True)
class ScanOutcome:
    texts: list[str]
    findings: list[list[Finding]]
    reasons: list[Reason]
    risk: Level
    counts: dict[str, int]
    mode: Mode
    context_repair: bool
    rot_score: float
    flags: dict[str, int]
    slm_status: str
    timings_ms: dict[str, float]
    overridable: bool
    secret_rules: dict[str, int] = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return self.risk is Level.RED

    @property
    def redactions(self) -> int:
        return sum(len(f) for f in self.findings)

    @property
    def blocked_types(self) -> list[str]:
        return [str(r.entity_type) for r in self.reasons if r.code == "blocked_entity" and r.entity_type]


@dataclass(slots=True)
class _Detected:
    norms: list[Normalized]
    spans: list[list[Span]]
    timings: dict[str, float]


@dataclass(slots=True)
class _Masked:
    """Text with known spans replaced by ``[TYPE]``, plus a map back to the source."""

    text: str
    starts: list[int]
    runs: list[tuple[int, int, int]]

    def to_source(self, start: int, end: int) -> tuple[int, int] | None:
        i = bisect.bisect_right(self.starts, start) - 1
        if i < 0:
            return None
        m_start, m_end, src = self.runs[i]
        if start >= m_start and end <= m_end:
            return src + start - m_start, src + end - m_start
        return None


def _mask(text: str, spans: list[Span]) -> _Masked:
    out: list[str] = []
    runs: list[tuple[int, int, int]] = []
    cursor = pos = 0
    for span in merge_spans(text, spans):
        if span.start > cursor:
            piece = text[cursor : span.start]
            runs.append((pos, pos + len(piece), cursor))
            out.append(piece)
            pos += len(piece)
        label = f"[{span.label}]"
        out.append(label)
        pos += len(label)
        cursor = span.end
    if cursor < len(text):
        piece = text[cursor:]
        runs.append((pos, pos + len(piece), cursor))
        out.append(piece)
    return _Masked("".join(out), [r[0] for r in runs], runs)


def _name_parts(surface: str) -> list[str]:
    tokens = surface.split()
    if len(tokens) < 2:
        return []
    parts: list[str] = []
    for token in tokens:
        token = _POSSESSIVE_RE.sub("", token.strip(".,;:!?\"'()[]{}"))
        if len(token) < 2 or not token[0].isupper() or token.casefold() in _NAME_PART_STOP:
            continue
        if token.isupper() and len(token) <= 3:
            continue
        parts.append(token)
    return parts


# Detections that take a value for what the word or the column in front of it suggests (detectors/cued.py, table
# cells in detectors/fields.py), rather than for a format they checked.
_GUESS_SOURCES = ("cue:", "field:person", "field:address", "field:place")


def _yield_to_custom(spans: list[Span]) -> list[Span]:
    """A value a cue word only suggests ("badge EMP-123456": an account number?) is what a custom type the user named
    says it is, when that type matches it: the guess gives way, so the placeholder carries the user's name."""
    ranges = [(s.start, s.end) for s in spans if any(src.startswith(CUSTOM_SOURCE) for src in s.sources)]
    if not ranges:
        return spans
    return [
        s
        for s in spans
        if not (
            all(src.startswith(_GUESS_SOURCES) for src in s.sources)
            and any(a <= s.start and s.end <= b for a, b in ranges)
        )
    ]


def _word_char(c: str) -> bool:
    return c.isalnum() or c == "_"


def _occurrences(text: str, surfaces: list[str]) -> list[tuple[int, int]]:
    """Where the surfaces stand in ``text`` as whole words of running text, the longest first where two start
    together and none inside another: not a piece of a host name, an e-mail address, a path or a setting
    ("DC01.VANTARA.LOCAL", "user=anna"), nor followed by an escape other than \\n, \\r, \\t or \\".
    Plain substring search, so a request's names cost no pattern to compile."""
    found: list[tuple[int, int]] = []
    n = len(text)
    for surface in surfaces:
        at = text.find(surface)
        while at >= 0:
            end = at + len(surface)
            before = text[at - 1] if at else ""
            ok = not before or not (_word_char(before) or before in ".@/\\=")
            if ok and end < n:
                after = text[end]
                if _word_char(after) or after in "@/=":
                    ok = False
                elif after == "\\":
                    ok = end + 1 < n and text[end + 1] in '"nrt'
                elif after == "." and end + 1 < n and _word_char(text[end + 1]):
                    ok = False
            if ok:
                found.append((at, end))
            at = text.find(surface, at + 1)
    found.sort(key=lambda x: (x[0], x[0] - x[1]))
    taken: list[tuple[int, int]] = []
    last = -1
    for start, end in found:
        if start >= last:
            taken.append((start, end))
            last = end
    return taken


def _custom_only(span: Span) -> bool:
    """A PROTECTED_TERM span found by custom types only (not by the registry)."""
    return "registry" not in span.sources and any(src.startswith(CUSTOM_SOURCE) for src in span.sources)


def _placeholder_ends_at(text: str, at: int) -> bool:
    """Whether one of the gateway's placeholders ends exactly at ``at`` ("OPENAI_API_KEY=[SECRET_1]|\n")."""
    if at == 0 or text[at - 1] != "]":
        return False
    window = text[max(0, at - 48) : at]
    return any(m.end() == len(window) for m in PLACEHOLDER_RE.finditer(window))


class Pipeline:
    def __init__(self, settings: Settings, ner: NERDetector | None = None, slm: SLMDetector | None = None) -> None:
        self.settings = settings
        self.ner = ner
        self.slm = slm
        detection = settings.detection
        self._policy = settings.policy
        self._regions = detection.phone_regions
        self._encoded_depth = detection.encoded_max_depth
        self._registry = Registry(detection.registry.terms, detection.registry.patterns)
        # Custom types: switched-off ones ("allow") are not looked for; every name stays a known placeholder.
        self._custom = CustomTypes(detection.custom_types)
        self._custom_policy: dict[str, CustomType] = {c.name: c for c in detection.custom_types}
        PLACEHOLDER_RE.register(self._custom_policy)
        self._propagate_enabled = detection.ner.propagate
        self._max_scan_s = settings.server.max_scan_ms / 1000
        self._max_decoded = settings.server.max_decoded_bytes
        self._max_entities = settings.server.max_entities
        # Keys are always redacted, so the whole credential library always runs: every gitleaks rule, the
        # prompt rules and seed phrases, plus any rules from extra_rules_file.
        self._secret_library: SecretLibrary | None = _library(True, (), detection.secrets.extra_rules_file, True, True)
        ids = detection.identifiers
        self._identifier_options: dict[str, Any] = {
            "national_ids": ids.national_ids,
            "cued_numbers": ids.cued_numbers,
            "opaque_codes": ids.opaque_codes,
            "devices": ids.devices,
            "crypto": ids.crypto,
            "addresses": ids.addresses,
            "spoken_emails": ids.spoken_emails,
            "regions": tuple(r for r in ("nl", "us", "eu") if getattr(ids.regions, r)),
            "machine_formats": ids.machine_formats,
            # Dates are only worth finding when policy does something with them.
            "dates": settings.policy.entities[EntityType.DATE].action != "allow",
        }
        self._decode_escapes = ids.decode_escapes
        self._table_fields = ids.table_fields
        self._precision_filter = detection.ner.precision_filter
        self._name_rules = detection.ner.name_rules
        self._slm_fail_closed = detection.slm.on_failure == "fail_closed"
        self._allow_terms = frozenset(t.casefold() for t in settings.policy.allow_terms)
        self._allowed_types = frozenset(t for t, p in settings.policy.entities.items() if p.action == "allow")
        self._semaphore = asyncio.Semaphore(settings.server.max_concurrent_scans)

    # ------------------------------------------------------------------ public
    async def scan(
        self,
        texts: list[str],
        *,
        mode: Mode | None = None,
        context_repair: bool | None = None,
        layers: Layers = "full",
        override: bool = False,
        unsupported: int = 0,
        dropped: int = 0,
        labels: list[str | None] | None = None,
    ) -> ScanOutcome:
        """``labels`` (optional, one per text) name what a text is: the JSON key a value was found under. A
        value is then also checked against its label (detectors/fields.py), the way a cue word works in prose."""
        mode = mode or self._policy.default_mode
        repair = self._policy.context_repair if context_repair is None else context_repair
        async with self._semaphore:
            started = time.perf_counter()
            budget = ScanBudget(time.monotonic() + self._max_scan_s, self._max_decoded, self._max_entities)
            token = _BUDGET.set(budget)
            try:
                return await self._scan_within(
                    texts, mode, repair, layers, override, unsupported, dropped, started, labels
                )
            except BudgetExceeded as exc:
                return self._over_budget(texts, exc.kind, mode, repair, started)
            finally:
                _BUDGET.reset(token)

    def _over_budget(self, texts: list[str], kind: str, mode: Mode, repair: bool, started: float) -> ScanOutcome:
        """Not fully inspected means not forwarded: a red verdict, like any other block."""
        return ScanOutcome(
            texts=list(texts),
            findings=[[] for _ in texts],
            reasons=[risk.scan_budget(kind)],
            risk=risk.Level.RED,
            counts={},
            mode=mode,
            context_repair=repair,
            rot_score=0.0,
            flags={},
            slm_status="skipped",
            timings_ms={"total": _ms(time.perf_counter() - started)},
            overridable=False,
        )

    async def _scan_within(
        self,
        texts: list[str],
        mode: Mode,
        repair: bool,
        layers: Layers,
        override: bool,
        unsupported: int,
        dropped: int,
        started: float,
        labels: list[str | None] | None = None,
    ) -> ScanOutcome:
        detected = await asyncio.to_thread(self._detect, texts, labels)
        slm_status = "disabled"
        slm_spans: list[list[Span]] = [[] for _ in texts]
        discarded = 0
        if self.slm is not None:
            if layers == "full":
                t = time.perf_counter()
                slm_status, slm_spans, discarded = await self._run_slm(detected)
                detected.timings["slm"] = _ms(time.perf_counter() - t)
            else:
                slm_status = "skipped"
        outcome = await asyncio.to_thread(
            self._finish, detected, slm_spans, mode, repair, override, slm_status, discarded, unsupported, dropped
        )
        outcome.timings_ms["total"] = _ms(time.perf_counter() - started)
        return outcome

    def scan_sync(
        self,
        texts: list[str],
        *,
        mode: Mode | None = None,
        context_repair: bool | None = None,
        override: bool = False,
        labels: list[str | None] | None = None,
    ) -> ScanOutcome:
        """Deterministic layers and NER only, on the calling thread (CLI, benchmarks)."""
        mode = mode or self._policy.default_mode
        repair = self._policy.context_repair if context_repair is None else context_repair
        started = time.perf_counter()
        token = _BUDGET.set(ScanBudget(time.monotonic() + self._max_scan_s, self._max_decoded, self._max_entities))
        try:
            detected = self._detect(texts, labels)
            empty: list[list[Span]] = [[] for _ in texts]
            status = "disabled" if self.slm is None else "skipped"
            outcome = self._finish(detected, empty, mode, repair, override, status, 0, 0, 0)
        except BudgetExceeded as exc:
            return self._over_budget(texts, exc.kind, mode, repair, started)
        finally:
            _BUDGET.reset(token)
        outcome.timings_ms["total"] = _ms(time.perf_counter() - started)
        return outcome

    def residual_sync(self, texts: list[str]) -> dict[str, int]:
        """What the deterministic layers still find, one count per value (several rules may find the same phone
        number). Used to verify a redacted document or request before release."""
        found: dict[str, int] = {}
        for text in texts:
            norm = normalize(text)
            spans = self._filter(norm.text, self._deterministic(norm.text, norm.reversed_runs))
            for span in merge_spans(norm.text, spans):
                found[span.label] = found.get(span.label, 0) + 1
        return found

    def redact_deterministic_sync(self, texts: list[str]) -> tuple[list[str], dict[str, int]]:
        """Deterministic layers only, with plain labels: for provider responses (policy.response_scan).
        No NER: an answer naming the people or places the user asked about is not a leak."""
        out: list[str] = []
        found: dict[str, int] = {}
        for text in texts:
            norm = normalize(text)
            spans = merge_spans(norm.text, self._filter(norm.text, self._deterministic(norm.text, norm.reversed_runs)))
            if not spans:
                out.append(text)
                continue
            pieces: list[str] = []
            cursor = 0
            for span in spans:
                found[span.label] = found.get(span.label, 0) + 1
                mapped = norm.to_original(span.start, span.end)
                if mapped is None:  # offsets lost in normalisation: drop the whole text rather than guess
                    pieces, cursor = [f"[{span.label}]"], len(text)
                    break
                start, end = mapped
                if start < cursor:
                    continue
                pieces += [text[cursor:start], f"[{span.label}]"]
                cursor = end
            pieces.append(text[cursor:])
            out.append("".join(pieces))
        return out, found

    async def redact_deterministic(self, texts: list[str]) -> tuple[list[str], dict[str, int]]:
        async with self._semaphore:
            return await asyncio.to_thread(self.redact_deterministic_sync, texts)

    async def residual(self, texts: list[str]) -> dict[str, int]:
        async with self._semaphore:
            return await asyncio.to_thread(self.residual_sync, texts)

    def warmup(self) -> None:
        """Load lazy metadata (phone regions, NER weights) before the first request."""
        sample = "Call Jane Doe on +1 415 867 5309 or jane@example.com about card 4111 1111 1111 1111."
        regional = {"GB": "+44 20 7946 0958", "NL": "+31 20 794 6095", "DE": "+49 30 901820"}
        texts = [sample] + [f"Number {regional.get(r, '+1 212 555 0100')} for {r}" for r in self._regions]
        self.scan_sync(texts)

    # ------------------------------------------------------------------ stage 1
    def _core(self, text: str, context: bool = True) -> list[Span]:
        """Patterns, secrets, identifiers and the registry: no model involved. ``context`` (see find_identifiers)
        is off for the views that only change characters."""
        spans = patterns.find_all(text, self._regions)
        spans.extend(find_secrets(text))
        if self._secret_library is not None:
            spans.extend(self._secret_library.find(text))
        spans.extend(find_identifiers(text, **self._identifier_options, context=context))
        if not self._registry.empty:
            spans.extend(self._registry.find(text))
        if not self._custom.empty:
            spans.extend(self._custom.find(text))
        return spans

    def _deterministic(self, text: str, reversed_runs: tuple[tuple[int, int], ...] = ()) -> list[Span]:
        spans = self._core(text)
        if self._table_fields:
            spans.extend(fields.find_table_fields(text))
        if self._decode_escapes:
            view = decode_escapes(text)
            if view is not None:
                decoded, starts, ends = view
                spans.extend(remap(s, starts, ends) for s in self._core(decoded))
                if self._table_fields:
                    spans.extend(remap(s, starts, ends) for s in fields.find_table_fields(decoded))
        if self._encoded_depth > 0:
            spans.extend(find_encoded(text, self._scan_decoded_budgeted, max_depth=self._encoded_depth))
        spans.extend(self._shadow_views(text, spans, reversed_runs))
        if not self._custom.empty:
            spans = _yield_to_custom(spans)
        return spans

    def _labelled(self, text: str, label: str, reversed_runs: tuple[tuple[int, int], ...] = ()) -> list[Span]:
        """A value scanned with its field name in front, as if it were written ``"label": "value"``, so every cue
        rule sees the key (a JSON leaf "298163871" under ``bsn``). Only spans inside the value are kept."""
        name = normalize(label[:120]).text.replace("\n", " ")
        prefix = f'"{name}": "'
        shifted = tuple((a + len(prefix), b + len(prefix)) for a, b in reversed_runs)
        spans: list[Span] = []
        for s in self._deterministic(prefix + text + '"', shifted):
            start, end = max(s.start - len(prefix), 0), min(s.end - len(prefix), len(text))
            if end > start:
                spans.append(replace(s, start=start, end=end))
        spans.extend(fields.find_labelled(label, text))
        return spans

    def _shadow_views(
        self, text: str, found_already: list[Span], reversed_runs: tuple[tuple[int, int], ...] = ()
    ) -> list[Span]:
        """Values broken over lines, spelled out, spaced one by one, in leetspeak, reversed under a right-to-left
        override, or written with look-alike letters (detectors/views.py)."""
        found: list[Span] = []
        joined = views.line_join_view(text)
        if joined is not None:
            for start, end in views.windows(joined, 200):
                for s in self._core(joined.text[start:end], context=False):
                    s = replace(s, start=s.start + start, end=s.end + start)
                    if s.type not in views.LINE_JOIN_TYPES:
                        continue
                    if s.type is EntityType.PHONE and not self._phone_joins(joined.text, s):
                        continue  # national numbers are too easy to make out of two lines of figures
                    mapped = remap(s, joined.starts, joined.ends)
                    # A line that starts a new entry ends the value at the break before it: a key at the end of a
                    # .env line does not take the lines after it, while a key cut in two is still read whole.
                    for a, b in joined.changed:
                        if mapped.start < a < mapped.end and views.line_starts_new_entry(text, a, b):
                            mapped = replace(mapped, end=a, canonical=text[mapped.start : a])
                            break
                    crossed = [(a, b) for a, b in joined.changed if mapped.start < a and b <= mapped.end]
                    if not crossed:
                        continue
                    # A break that ends a value already found whole ("...@corp.example\nfiller") is a real break.
                    # Not for keys: the line after a password cut in two ("Tr0ub\n4dor&3x") is the rest of it.
                    if mapped.type not in views.BLOCKING_TYPES and any(
                        o.type is mapped.type and (o.end == a or o.start == b)
                        for o in found_already
                        for a, b in crossed
                    ):
                        continue
                    # In the sanitized text that egress verification scans, "KEY=[SECRET_1]" ended its line, and a new
                    # entry after it is not its value (the match starts right after that break, when the cue and the
                    # placeholder were glued onto the next line).
                    if any(
                        _placeholder_ends_at(text, a) and views.line_starts_new_entry(text, a, b)
                        for a, b in joined.changed
                        if a < mapped.end and b >= mapped.start
                    ):
                        continue
                    found.append(mapped)
        found.extend(self._exact_across_lines(text))
        compact = views.compact_view(text)
        if compact is not None:
            for start, end in views.windows(compact, 64):
                for s in self._core(compact.text[start:end], context=False):
                    mapped = remap(replace(s, start=s.start + start, end=s.end + start), compact.starts, compact.ends)
                    if views.touches(mapped.start, mapped.end, compact.changed):
                        found.append(mapped)
            for start, end, digits in compact.spelled:  # spoken numbers lose the "+": try them as international
                if 10 <= len(digits) <= 15 and patterns.is_valid_phone(f"+{digits}"):
                    found.append(make_span(start, end, EntityType.PHONE, "phone", digits, 0.9))
        leet = views.leet_email_view(text)
        if leet is not None:
            found.extend(
                replace(s, sources=s.sources | {"decoded"})
                for s in patterns.find_emails(leet.text)
                if views.touches(s.start, s.end, leet.changed)
            )
        spaced = views.script_spacing_view(
            text, [(s.start, s.end) for s in found_already], dates=self._identifier_options["dates"]
        )
        if spaced is not None:
            # Only the stretches around the seams: a value glued to Chinese, Japanese or Korean text starts or ends
            # at one, and the words that name it are near (these scripts say much in few characters).
            for start, end in views.windows(spaced, 64):
                for s in self._core(spaced.text[start:end]):
                    if any(src.startswith("cjk:") for src in s.sources):
                        continue  # the CJK rules read the text as it is written, without the blanks
                    a, b = spaced.to_original(s.start + start, s.end + start)
                    if b > a and views.meets(a, b, spaced.changed):
                        found.append(replace(s, start=a, end=b, sources=s.sources | {"decoded"}))
        for view in (views.display_order_view(text, reversed_runs), views.lookalike_view(text)):
            if view is None:
                continue
            for start, end in views.windows(view, 64):
                for s in self._core(view.text[start:end], context=False):
                    a, b = view.to_original(s.start + start, s.end + start)
                    if views.touches(a, b, view.changed):
                        found.append(replace(s, start=a, end=b, sources=s.sources | {"decoded"}))
        return found

    @staticmethod
    def _phone_joins(joined: str, span: Span) -> bool:
        if joined.startswith(("+", "00"), span.start):
            return True
        return views.PHONE_CUE_RE.search(joined, max(0, span.start - 40), span.start) is not None

    def _exact_across_lines(self, text: str) -> list[Span]:
        """Protected terms and seed phrases broken anywhere by a line break, also inside a word ("Projec\nt")."""
        if "\n" not in text:
            return []
        seeds = self._secret_library is not None and self._secret_library.may_hold_seed_phrase(text, 5)
        if self._registry.empty and self._custom.empty and not seeds:
            return []
        view = views.line_join_view(text, everywhere=True)
        if view is None:
            return []
        candidates: list[Span] = list(self._registry.find(view.text)) if not self._registry.empty else []
        if not self._custom.empty:
            candidates.extend(self._custom.find(view.text))
        if seeds and self._secret_library is not None:
            candidates.extend(self._secret_library.seed_phrase_spans(view.text))
        found = []
        for s in candidates:
            mapped = remap(s, view.starts, view.ends)
            if any(mapped.start < a and b <= mapped.end for a, b in view.changed):
                found.append(mapped)
        return found

    def _scan_decoded_budgeted(self, decoded: str) -> list[Span]:
        budget = _BUDGET.get()
        if budget is not None:
            budget.decoded(len(decoded))
            budget.time()
        return self._scan_decoded(decoded)

    def _scan_decoded(self, decoded: str) -> list[Span]:
        return self._core(normalize(decoded).text)

    def _detect(self, texts: list[str], labels: list[str | None] | None = None) -> _Detected:
        t0 = time.perf_counter()
        norms = [normalize(t) for t in texts]
        t1 = time.perf_counter()
        budget = _BUDGET.get()
        if labels is not None and len(labels) != len(texts):
            raise ValueError("labels must match texts one for one")
        spans = []
        for k, n in enumerate(norms):
            if budget is not None:
                budget.time()
            label = labels[k] if labels is not None else None
            found = (
                self._labelled(n.text, label, n.reversed_runs)
                if label
                else self._deterministic(n.text, n.reversed_runs)
            )
            if budget is not None:
                budget.entities(len(found))
            spans.append(found)
        if budget is not None:
            budget.time()
        t2 = time.perf_counter()
        timings = {"normalize": _ms(t1 - t0), "patterns": _ms(t2 - t1)}
        if self._name_rules:
            for bucket, norm in zip(spans, norms, strict=True):
                bucket.extend(find_name_cues(norm.text))
        if self.ner is not None:
            found_all = self.ner.detect_many([n.text for n in norms], precision_filter=self._precision_filter)
            for bucket, found in zip(spans, found_all, strict=True):
                bucket.extend(found)
        if self._name_rules or self.ner is not None:
            timings["ner"] = _ms(time.perf_counter() - t2)
        return _Detected(norms, spans, timings)

    # ------------------------------------------------------------------ stage 2
    async def _run_slm(self, detected: _Detected) -> tuple[str, list[list[Span]], int]:
        if self.slm is None:
            raise RuntimeError("SLM layer is not configured")
        # The SLM sees text with every known identifier already masked, as in
        # the v1 layering: it only has to find what the other layers missed.
        masked = [_mask(n.text, spans) for n, spans in zip(detected.norms, detected.spans, strict=True)]
        outcome = await self.slm.detect([m.text for m in masked])
        if outcome.status != "ok":
            return outcome.status, [[] for _ in masked], 0
        mapped: list[list[Span]] = []
        discarded = outcome.discarded
        for view, spans in zip(masked, outcome.spans, strict=True):
            bucket: list[Span] = []
            for span in spans:
                source = view.to_source(span.start, span.end)
                if source is None:
                    discarded += 1
                    continue
                bucket.append(replace(span, start=source[0], end=source[1]))
            mapped.append(bucket)
        return "ok", mapped, discarded

    # ------------------------------------------------------------------ stage 3
    def _propagate(self, texts: list[str], spans_per_text: list[list[Span]]) -> list[list[Span]]:
        """Redact every other occurrence of a name or place the models found once. Only what could be a name is
        spread: a common word the model tagged once ("Agreement", "the", "UTC") would otherwise be redacted
        wherever it occurs (detectors/ner.py, plausible_entity)."""
        surfaces: dict[str, tuple[EntityType, str]] = {}
        common: list[frozenset[str]] = []

        def lowercase() -> frozenset[str]:  # the words the texts write in lower case, read when first needed
            if not common:
                common.append(frozenset().union(*(lowercase_words(t) for t in texts)))
            return common[0]

        for text, spans in zip(texts, spans_per_text, strict=True):
            for span in spans:
                if span.type not in _PROPAGATED_TYPES or not (span.sources & _MODEL_SOURCES):
                    continue
                surface = text[span.start : span.end]
                if sum(c.isalnum() for c in surface) < 2:
                    continue
                line = line_around(text, span.start, span.end)
                if self._precision_filter and not plausible_entity(
                    surface, line, lowercase(), place=span.type is EntityType.LOCATION,
                    person=span.type is EntityType.PERSON, org=span.type is EntityType.ORGANIZATION,
                ):  # fmt: skip
                    continue
                if len(surface) == 2 and (surface.lower() in _CODE_WORDS or surface.lower() in lowercase()):
                    continue  # "OR" (Oregon) is also a SQL keyword and "IN" a word: found where the model saw it
                surfaces.setdefault(surface, (span.type, span.canonical))
                if span.type is EntityType.PERSON:
                    for part in _name_parts(surface):
                        if not self._precision_filter or plausible_entity(part, line, lowercase()):
                            surfaces.setdefault(part, (EntityType.PERSON, part.casefold()))
            # "anna.jansen@corp.example" names its owner: find "Anna" and "Jansen" in prose.
            for span in spans:
                if span.type is not EntityType.EMAIL:
                    continue
                local = span.canonical.split("@", 1)[0]
                for token in _LOCAL_PART_SPLIT_RE.split(local):
                    if len(token) < 3 or not token.isalpha() or token in _ROLE_MAILBOXES:
                        continue
                    if not self._precision_filter or plausible_entity(token.capitalize(), "", lowercase()):
                        surfaces.setdefault(token.capitalize(), (EntityType.PERSON, token))
        if not surfaces:
            return spans_per_text
        # One pattern per type: a name inside a longer organisation surface
        # ("Customer Jan de Vries" tagged ORG) is still found and merged.
        by_type: dict[EntityType, list[str]] = {}
        for surface, (etype, _) in surfaces.items():
            by_type.setdefault(etype, []).append(surface)
        out: list[list[Span]] = []
        for text, spans in zip(texts, spans_per_text, strict=True):
            extra = []
            software = software_ranges(text)
            for group in by_type.values():
                for start, end in _occurrences(text, group):
                    if software and any(a <= start and end <= b for a, b in software):
                        continue  # "Gecko", "KHTML" in a user agent name software
                    surface = text[start:end]
                    etype, canonical = surfaces[surface]
                    one_word = etype is EntityType.PERSON and " " not in surface
                    if self._precision_filter and one_word and instruction_verb(text, start, end):
                        continue  # "Mark all that apply": the verb, wherever the name "Mark" was found
                    extra.append(make_span(start, end, etype, "propagated", canonical, 0.8))
            out.append(spans + extra)
        return out

    @property
    def secret_rule_count(self) -> int:
        """Key rules in force: the gitleaks rules plus any from extra_rules_file."""
        return self._secret_library.rule_count if self._secret_library is not None else 0

    def _overridable(self, name: str) -> bool:
        custom = self._custom_policy.get(name)
        if custom is not None:
            return custom.overridable
        return self._policy.entities[EntityType(name)].overridable

    def _filter(self, text: str, spans: list[Span]) -> list[Span]:
        kept = []
        for span in spans:
            # A custom type is decided by its own action, never by PROTECTED_TERM's: allowing registry terms must
            # not switch off an EMPLOYEE_ID type set to block.
            if span.type in self._allowed_types and not _custom_only(span):
                continue
            if (
                self._allow_terms
                and span.type not in CRITICAL_TYPES
                and text[span.start : span.end].casefold() in self._allow_terms
            ):
                continue
            kept.append(span)
        return protect_placeholders(text, kept)

    def _finish(
        self,
        detected: _Detected,
        slm_spans: list[list[Span]],
        mode: Mode,
        context_repair: bool,
        override: bool,
        slm_status: str,
        slm_discarded: int,
        unsupported: int,
        dropped: int,
    ) -> ScanOutcome:
        t0 = time.perf_counter()
        texts = [n.text for n in detected.norms]
        spans_per_text = [a + b for a, b in zip(detected.spans, slm_spans, strict=True)]
        if self._propagate_enabled:
            spans_per_text = self._propagate(texts, spans_per_text)
        merged = [merge_spans(t, self._filter(t, s)) for t, s in zip(texts, spans_per_text, strict=True)]
        repair = context_repair and mode == "generic"
        result = render(texts, merged, mode, repair)

        counts: dict[str, int] = {}
        rules: dict[str, int] = {}
        blocked: dict[str, int] = {}  # by built-in type or custom type name
        keys = 0
        for spans in merged:
            for span in spans:
                counts[span.label] = counts.get(span.label, 0) + 1
                for source in span.sources:
                    if source.startswith("secret:"):
                        rules[source[7:]] = rules.get(source[7:], 0) + 1
                types = {span.type} | span.inner
                names = custom_names(span.sources)
                if names and "registry" not in span.sources:
                    types.discard(EntityType.PROTECTED_TERM)  # found by a custom type: its own action decides
                for etype in types:
                    if self._policy.entities[etype].action == "block":
                        blocked[etype.value] = blocked.get(etype.value, 0) + 1
                for name in names:
                    custom = self._custom_policy.get(name)
                    if custom is not None and custom.action == "block":
                        blocked[name] = blocked.get(name, 0) + 1
                if types & ALWAYS_REDACTED:
                    keys += 1

        reasons: list[Reason] = []
        overridden: list[EntityType | str] = []
        for name in sorted(blocked, key=lambda n: (-_priority(n), n)):
            overridable = self._overridable(name)
            if overridable and override:
                overridden.append(_as_type(name))
            else:
                reasons.append(risk.blocked_entity(_as_type(name), blocked[name], overridable))
        if keys:
            reasons.append(risk.keys_redacted(keys))
        if unsupported:
            reasons.append(risk.unsupported_content(unsupported))
        if slm_status in SLM_FAILURES:
            reasons.append(risk.slm_unavailable(slm_status) if self._slm_fail_closed else risk.slm_degraded(slm_status))
        if overridden:
            reasons.append(risk.override_applied(overridden))
        if dropped:
            reasons.append(risk.content_dropped(dropped))
        if result.words >= self._policy.rot_min_words and result.placeholder_ratio > self._policy.rot_threshold:
            reasons.append(risk.context_rot(result.placeholder_ratio))
        if result.collapsed_sentences:
            reasons.append(risk.collapsed(result.collapsed_sentences))
        mixed = sum(n.mixed_script_tokens for n in detected.norms)
        if mixed:
            reasons.append(risk.mixed_script(mixed))
        hidden = sum(n.removed_format_chars for n in detected.norms)
        if hidden:
            reasons.append(risk.hidden_characters(hidden))

        level = risk.overall(reasons)
        red = [r for r in reasons if r.level is Level.RED]
        overridable_only = bool(red) and all(r.code == "blocked_entity" and r.overridable for r in red)

        findings: list[list[Finding]] = []
        for norm, redactions in zip(detected.norms, result.redactions, strict=True):
            bucket = []
            for r in redactions:
                mapped = norm.to_original(r.start, r.end)
                bucket.append(
                    Finding(
                        r.type,
                        mapped[0] if mapped else None,
                        mapped[1] if mapped else None,
                        r.placeholder,
                        tuple(sorted(r.sources)),
                    )
                )
            findings.append(bucket)

        timings = dict(detected.timings)
        timings["render"] = _ms(time.perf_counter() - t0)
        return ScanOutcome(
            texts=result.texts,
            findings=findings,
            reasons=reasons,
            risk=level,
            counts=counts,
            mode=mode,
            context_repair=repair,
            rot_score=round(result.placeholder_ratio, 4),
            flags={
                "hidden_characters": hidden,
                "mixed_script_tokens": mixed,
                "collapsed_sentences": result.collapsed_sentences,
                "repaired_sentences": result.repaired_sentences,
                "slm_discarded": slm_discarded,
            },
            slm_status=slm_status,
            timings_ms=timings,
            overridable=overridable_only,
            secret_rules=rules,
        )
