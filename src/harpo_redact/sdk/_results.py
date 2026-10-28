"""The SDK's result types: frozen, typed, and safe to print.

``repr()`` of every result shows types, counts and decisions, never text: a redacted text can still hold something
the detectors missed, so it is only ever handed over on request (``.text``, ``.texts``, ``.data``).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class Risk(StrEnum):
    """The verdict on a scan, as the gateway gives it."""

    GREEN = "green"  # nothing to report
    YELLOW = "yellow"  # goes on, with an advisory (a key was redacted, many placeholders, hidden characters, ...)
    RED = "red"  # blocked: nothing may be sent


@dataclass(frozen=True, slots=True)
class Reason:
    """Why a scan has its risk. The message names what was found, never the value."""

    code: str  # blocked_entity, keys_redacted, egress_verification, scan_budget, context_rot, ...
    level: Risk
    message: str
    entity_type: str | None = None  # a built-in type or a custom type's name
    count: int | None = None
    overridable: bool = False  # a blocked type that a caller who may override can send as a placeholder


@dataclass(frozen=True, slots=True)
class Finding:
    """One redaction: where it is in the text you passed in (code points), and what replaced it.

    The value itself is not kept: ``original[finding.start:finding.end]`` is in your own text. ``start`` and
    ``end`` are ``None`` in the rare case normalisation made the offsets impossible to map back."""

    type: str  # EMAIL, PERSON, SECRET, ... or a custom type's name
    start: int | None
    end: int | None
    placeholder: str  # [EMAIL_1], [PERSON], [EMPLOYEE_ID_2], ...
    sources: tuple[str, ...]  # the detectors that found it


@dataclass(frozen=True, slots=True, repr=False)
class ScannedText:
    """One scanned text: the redacted text and its findings."""

    text: str
    findings: tuple[Finding, ...]

    def __repr__(self) -> str:
        return f"ScannedText(chars={len(self.text)}, findings={len(self.findings)})"


@dataclass(frozen=True, slots=True, repr=False)
class ScanResult:
    """What a scan found and decided, the same as ``POST /v1/scan`` answers.

    Check ``blocked`` before you use ``text``: a blocked result is one the policy says must not be sent."""

    items: tuple[ScannedText, ...]  # one per text scanned, in order
    risk: Risk
    reasons: tuple[Reason, ...]
    counts: Mapping[str, int]  # redactions by type
    overridable: bool  # blocked only by types this caller may send as placeholders, with override=True
    mode: str  # relational ([PERSON_1]) or generic ([PERSON])
    context_repair: bool
    layers: str  # full, or fast (without the local SLM)
    rot_score: float  # share of the text that became placeholders
    flags: Mapping[str, int]
    slm: str  # the local SLM's status: disabled, ok, skipped, ...
    timings_ms: Mapping[str, float]
    request_id: str | None = None  # set when a gateway answered

    @property
    def blocked(self) -> bool:
        """The policy blocks this content: send nothing."""
        return self.risk is Risk.RED

    @property
    def redactions(self) -> int:
        return sum(len(item.findings) for item in self.items)

    @property
    def blocked_types(self) -> tuple[str, ...]:
        return tuple(r.entity_type for r in self.reasons if r.code == "blocked_entity" and r.entity_type)

    @property
    def texts(self) -> tuple[str, ...]:
        """Every redacted text, in the order they were passed in."""
        return tuple(item.text for item in self.items)

    @property
    def text(self) -> str:
        """The redacted text of a scan of one text."""
        return self._single().text

    @property
    def findings(self) -> tuple[Finding, ...]:
        """The findings of a scan of one text."""
        return self._single().findings

    def _single(self) -> ScannedText:
        if len(self.items) != 1:
            raise ValueError(f"this result holds {len(self.items)} texts: use .items or .texts")
        return self.items[0]

    def __repr__(self) -> str:
        return (
            f"ScanResult(risk={self.risk.value!r}, blocked={self.blocked}, texts={len(self.items)}, "
            f"redactions={self.redactions}, counts={dict(self.counts)!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class DocumentResult:
    """A redacted document. ``data`` is the redacted file (``None`` when only the text was asked for); it was
    opened again and scanned before release (``verified``)."""

    kind: str  # pdf, docx, xlsx, pptx or text
    text: str  # the redacted document as readable text
    data: bytes | None
    filename: str | None  # a name for the redacted file: <name>.redacted.<ext>
    content_type: str | None
    verified: bool
    risk: Risk
    reasons: tuple[Reason, ...]
    counts: Mapping[str, int]
    redactions: int
    mode: str
    segments: int  # pieces of text the document was read as
    info: Mapping[str, Any]  # pages, sheets, slides, ... as the document reader reports them
    request_id: str | None = None

    def save(self, path: str | os.PathLike[str]) -> Path:
        """Write the redacted file to ``path`` (a file, or a folder to put ``filename`` in) and return where."""
        if self.data is None:
            raise ValueError("no redacted file was produced: ask for one with file=True")
        target = Path(path)
        if target.is_dir():
            target = target / (self.filename or f"document.redacted.{self.kind}")
        target.write_bytes(self.data)
        return target

    def __repr__(self) -> str:
        size = "none" if self.data is None else f"{len(self.data)} bytes"
        return (
            f"DocumentResult(kind={self.kind!r}, file={size}, verified={self.verified}, risk={self.risk.value!r}, "
            f"redactions={self.redactions}, counts={dict(self.counts)!r})"
        )


@dataclass(frozen=True, slots=True)
class Verification:
    """What the deterministic layers still find in texts about to leave: the check egress verification runs."""

    counts: Mapping[str, int]  # by type; empty when nothing is found

    @property
    def clean(self) -> bool:
        return not self.counts


@dataclass(frozen=True, slots=True, repr=False)
class ResponseScan:
    """A provider answer after the deterministic layers, as ``policy.response_scan`` treats answers."""

    texts: tuple[str, ...]  # with plain labels ([EMAIL]) where something was found
    counts: Mapping[str, int]

    @property
    def text(self) -> str:
        if len(self.texts) != 1:
            raise ValueError(f"this result holds {len(self.texts)} texts: use .texts")
        return self.texts[0]

    @property
    def changed(self) -> bool:
        return bool(self.counts)

    def __repr__(self) -> str:
        return f"ResponseScan(texts={len(self.texts)}, counts={dict(self.counts)!r})"


@dataclass(frozen=True, slots=True)
class EntityRule:
    """What the policy does with one type."""

    action: str  # redact, block or allow
    overridable: bool


@dataclass(frozen=True, slots=True)
class CustomTypeInfo:
    """A custom type as the policy shows it: its terms and patterns are counted, not listed."""

    name: str
    description: str
    action: str
    overridable: bool
    terms: int
    patterns: int


@dataclass(frozen=True, slots=True)
class PolicyView:
    """The policy scans run with: an action per type, the custom types, and the settings around them."""

    default_mode: str
    context_repair: bool
    client_may_choose_mode: bool
    entities: Mapping[str, EntityRule]
    always_redacted: tuple[str, ...]  # credentials: no policy, switch or override changes them
    custom_types: tuple[CustomTypeInfo, ...]
    override_permitted: bool
    egress_verification: str
    response_scan: str
    unknown_fields: str
    unsupported_content: str
    version: str
    details: Mapping[str, Any] = field(default_factory=dict)  # everything else the source reports


@dataclass(frozen=True, slots=True)
class ConfigIssue:
    """A configuration error: where (a dotted path, and the YAML line when known) and what."""

    path: str
    message: str
    line: int | None = None


@dataclass(frozen=True, slots=True)
class ConfigReport:
    """A configuration checked the way ``harpo check-config`` checks it."""

    valid: bool  # it loads
    errors: tuple[ConfigIssue, ...]  # why it does not
    problems: tuple[str, ...]  # why it must not serve production traffic (production mode only)
    notices: tuple[str, ...]  # settings it asks for that are not honoured (keys are always redacted)
    missing_models: tuple[str, ...]  # language models it names that are not installed, with how to install them
    diff: str | None = None  # from a gateway: the staged configuration against the running one

    @property
    def ok(self) -> bool:
        return self.valid and not self.problems and not self.missing_models


@dataclass(frozen=True, slots=True)
class ConfigFinding:
    """A hardening finding on a configuration: the exact setting, its value and what to set instead."""

    id: str
    level: str  # required, recommended or info
    title: str
    detail: str
    setting: str
    current: Any = None
    suggested: Any = None
    invariant: str | None = None


@dataclass(frozen=True, slots=True)
class EngineStatus:
    """What a local engine runs with."""

    version: str
    environment: str
    ner_models: tuple[str, ...]  # loaded spaCy models; empty with NER off
    slm: str | None  # the local SLM's model, or None when it is off
    slm_reachable: bool | None
    secret_rules: int
    custom_types: tuple[str, ...]
    live_policy: bool  # policy.live_file was laid over the configuration


@dataclass(frozen=True, slots=True, repr=False)
class Trace:
    """One sample through the detection stages (the console's detector lab). It holds your text: keep it out of
    logs. ``data`` has the stages, the shadow views, the final result with its findings and the timings."""

    data: Mapping[str, Any]

    def __repr__(self) -> str:
        final = self.data.get("final", {}) if isinstance(self.data, Mapping) else {}
        return (
            f"Trace(layers={len(self.data.get('layers', []))}, findings={len(final.get('findings', []))}, "
            f"risk={final.get('risk')!r})"
        )


@dataclass(frozen=True, slots=True)
class Health:
    """``GET /healthz``: the gateway process answers."""

    status: str
    version: str


@dataclass(frozen=True, slots=True)
class Readiness:
    """``GET /readyz``: whether the gateway can serve, with each check."""

    ready: bool
    checks: Mapping[str, str]


@dataclass(frozen=True, slots=True, repr=False)
class EgressPreview:
    """What a gateway would send for a request, without sending it: the proxy's own sanitize path."""

    decision: str  # would_forward, blocked or rejected
    body: Mapping[str, Any] | None  # the exact body that would leave (placeholders only)
    upstream: str | None
    url: str | None
    risk: Risk | None
    redactions: int
    counts: Mapping[str, int]
    mode: str | None
    reasons: tuple[Reason, ...]
    status: int | None  # for a refused request: the status the proxy would answer with
    message: str | None
    details: Mapping[str, Any]

    @property
    def would_forward(self) -> bool:
        return self.decision == "would_forward"

    def __repr__(self) -> str:
        risk = self.risk.value if self.risk else None
        return (
            f"EgressPreview(decision={self.decision!r}, upstream={self.upstream!r}, risk={risk!r}, "
            f"redactions={self.redactions})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class PolicyPreview:
    """A text run through a draft policy that is not saved: nothing is sent, saved or recorded."""

    text: str
    risk: Risk
    findings: tuple[Finding, ...]
    reasons: tuple[Reason, ...]
    counts: Mapping[str, int]

    @property
    def blocked(self) -> bool:
        return self.risk is Risk.RED

    def __repr__(self) -> str:
        return f"PolicyPreview(risk={self.risk.value!r}, findings={len(self.findings)}, counts={dict(self.counts)!r})"


@dataclass(frozen=True, slots=True, repr=False)
class ProxyResponse:
    """A provider's answer through the gateway, with the gateway's verdict on the request."""

    body: Mapping[str, Any]  # the provider's JSON answer
    status: int
    risk: str | None  # x-harpo-risk
    redactions: int | None  # x-harpo-redactions
    mode: str | None
    response_scan: str | None  # off, report, redact, or not_scanned_stream
    response_findings: int | None
    request_id: str | None

    def __repr__(self) -> str:
        return f"ProxyResponse(status={self.status}, risk={self.risk!r}, redactions={self.redactions})"


@dataclass(frozen=True, slots=True)
class InvariantCheck:
    """One invariant's self-test: its id (docs/INVARIANTS.md), pass, fail or skipped, and what was checked."""

    id: str  # INV-01, INV-11, ...
    status: str  # pass, fail or skipped
    detail: str


@dataclass(frozen=True, slots=True)
class SelfTestReport:
    """The gateway's live self-test: canaries through the real request path. Nothing is sent or recorded."""

    passed: bool
    ran_at: str
    results: tuple[InvariantCheck, ...]


@dataclass(frozen=True, slots=True)
class KeyInfo:
    """A gateway key as the gateway lists it: a fingerprint of its hash, never the key."""

    id: str
    fingerprint: str
    admin: bool
    can_override: bool
    expires_at: str | None
    expired: bool
    requests_per_minute: int | None
    requests: int
    last_seen: str | None


@dataclass(frozen=True, slots=True, repr=False)
class GatewayKey:
    """A new gateway key. ``key`` is shown once: store it in your secret manager. The gateway keeps only
    ``sha256``; ``yaml`` is the entry for ``auth.keys``."""

    id: str
    key: str
    sha256: str
    yaml: str

    def __repr__(self) -> str:
        return f"GatewayKey(id={self.id!r}, sha256={self.sha256[:8]!r}..., key=<hidden>)"


@dataclass(frozen=True, slots=True)
class ProviderCheck:
    """A content-free connection test of one upstream: the provider's model list, with the configured key."""

    name: str
    reachable: bool
    status: int | None
    latency_ms: float | None
    auth: str | None  # accepted, rejected, not confirmed, not needed
    error: str | None
    details: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class CustomType:
    """A type of your own: values its terms or RE2 patterns find become [NAME_1], [NAME_2], ...

    Checked by the same rules as the configuration file (an upper-case name that is not a built-in type, terms of 2
    to 200 characters, linear-time RE2 patterns that cannot match the empty string)."""

    name: str
    terms: tuple[str, ...] = ()
    patterns: tuple[str, ...] = ()
    action: str = "redact"  # redact, block, or allow (defined but switched off)
    overridable: bool = False
    description: str = ""

    def as_config(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "terms": list(self.terms),
            "patterns": list(self.patterns),
            "action": self.action,
            "overridable": self.overridable,
        }
