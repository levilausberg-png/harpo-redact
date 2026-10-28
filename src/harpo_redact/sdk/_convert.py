"""From the gateway's JSON shapes to the SDK's types.

The local engine builds the same shapes from the pipeline's own objects (``_engine``) and passes them through these
functions too, so a local scan and a gateway's ``POST /v1/scan`` of the same text become identical objects.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ._errors import BlockedError
from ._results import (
    ConfigFinding,
    CustomTypeInfo,
    DocumentResult,
    EntityRule,
    Finding,
    PolicyView,
    Reason,
    Risk,
    ScannedText,
    ScanResult,
)


def _int(value: Any, default: int = 0) -> int:
    return int(value) if isinstance(value, int | float) and not isinstance(value, bool) else default


def reason(data: Mapping[str, Any]) -> Reason:
    entity = data.get("entity_type")
    count = data.get("count")
    return Reason(
        code=str(data.get("code", "")),
        level=Risk(str(data.get("level", "yellow"))),
        message=str(data.get("message", "")),
        entity_type=str(entity) if entity is not None else None,
        count=count if isinstance(count, int) else None,
        overridable=bool(data.get("overridable", False)),
    )


def finding(data: Mapping[str, Any]) -> Finding:
    start, end = data.get("start"), data.get("end")
    return Finding(
        type=str(data.get("type", "")),
        start=start if isinstance(start, int) else None,
        end=end if isinstance(end, int) else None,
        placeholder=str(data.get("placeholder", "")),
        sources=tuple(str(s) for s in data.get("sources", ())),
    )


def scan_result(payload: Mapping[str, Any], *, request_id: str | None = None) -> ScanResult:
    """``POST /v1/scan``'s answer."""
    items = tuple(
        ScannedText(str(r.get("redacted", "")), tuple(finding(f) for f in r.get("entities", ())))
        for r in payload.get("results", ())
    )
    return ScanResult(
        items=items,
        risk=Risk(str(payload.get("risk", "green"))),
        reasons=tuple(reason(r) for r in payload.get("reasons", ())),
        counts={str(k): _int(v) for k, v in dict(payload.get("counts") or {}).items()},
        overridable=bool(payload.get("overridable", False)),
        mode=str(payload.get("mode", "")),
        context_repair=bool(payload.get("context_repair", False)),
        layers=str(payload.get("layers", "full")),
        rot_score=float(payload.get("rot_score", 0.0)),
        flags={str(k): _int(v) for k, v in dict(payload.get("flags") or {}).items()},
        slm=str(payload.get("slm", "disabled")),
        timings_ms={str(k): float(v) for k, v in dict(payload.get("timings_ms") or {}).items()},
        request_id=request_id or payload.get("request_id"),
    )


def document_result(payload: Mapping[str, Any], data: bytes | None, *, request_id: str | None = None) -> DocumentResult:
    """``POST /v1/documents/redact?response=json``'s answer, with the file already decoded."""
    file = payload.get("file") or {}
    return DocumentResult(
        kind=str(payload.get("kind", "")),
        text=str(payload.get("text", "")),
        data=data,
        filename=str(file["filename"]) if data is not None and file.get("filename") else None,
        content_type=str(file["content_type"]) if data is not None and file.get("content_type") else None,
        verified=bool(payload.get("verified", False)),
        risk=Risk(str(payload.get("risk", "green"))),
        reasons=tuple(reason(r) for r in payload.get("reasons", ())),
        counts={str(k): _int(v) for k, v in dict(payload.get("counts") or {}).items()},
        redactions=_int(payload.get("redactions")),
        mode=str(payload.get("mode", "")),
        segments=_int(payload.get("segments")),
        info=dict(payload.get("info") or {}),
        request_id=request_id or payload.get("request_id"),
    )


def blocked(
    message: str, details: Mapping[str, Any], *, status: int | None = None, request_id: str | None = None
) -> BlockedError:
    """A privacy block, from the ``harpo`` details of the gateway's 403 (or the same fields built locally). The
    message is made from the red reasons, which name types and counts, never values."""
    reasons = [reason(r) for r in details.get("reasons", ())]
    red = " ".join(r.message for r in reasons if r.level is Risk.RED)
    return BlockedError(
        f"Blocked by privacy policy: {red}" if red else (message or "Blocked by privacy policy."),
        reasons=reasons,
        blocked_types=[str(t) for t in details.get("blocked_types", ())],
        overridable=bool(details.get("overridable", False)),
        override_permitted=bool(details.get("override_permitted", False)),
        status=status,
        request_id=request_id,
    )


_POLICY_FIELDS = {
    "default_mode", "context_repair", "client_may_choose_mode", "entities", "always_redacted", "custom_types",
    "override_permitted", "egress_verification", "response_scan", "unknown_fields", "unsupported_content", "version",
}  # fmt: skip


def policy_view(payload: Mapping[str, Any]) -> PolicyView:
    """``GET /v1/policy``'s answer."""
    entities = {
        str(name): EntityRule(str(rule.get("action", "redact")), bool(rule.get("overridable", False)))
        for name, rule in dict(payload.get("entities") or {}).items()
    }
    customs = tuple(
        CustomTypeInfo(
            name=str(c.get("name", "")),
            description=str(c.get("description", "")),
            action=str(c.get("action", "redact")),
            overridable=bool(c.get("overridable", False)),
            terms=_int(c.get("terms")),
            patterns=_int(c.get("patterns")),
        )
        for c in payload.get("custom_types", ())
    )
    return PolicyView(
        default_mode=str(payload.get("default_mode", "")),
        context_repair=bool(payload.get("context_repair", False)),
        client_may_choose_mode=bool(payload.get("client_may_choose_mode", False)),
        entities=entities,
        always_redacted=tuple(str(t) for t in payload.get("always_redacted", ())),
        custom_types=customs,
        override_permitted=bool(payload.get("override_permitted", False)),
        egress_verification=str(payload.get("egress_verification", "")),
        response_scan=str(payload.get("response_scan", "")),
        unknown_fields=str(payload.get("unknown_fields", "")),
        unsupported_content=str(payload.get("unsupported_content", "")),
        version=str(payload.get("version", "")),
        details={k: v for k, v in payload.items() if k not in _POLICY_FIELDS},
    )


def config_finding(data: Mapping[str, Any]) -> ConfigFinding:
    invariant = data.get("invariant")
    return ConfigFinding(
        id=str(data.get("id", "")),
        level=str(data.get("level", "")),
        title=str(data.get("title", "")),
        detail=str(data.get("detail", "")),
        setting=str(data.get("setting", "")),
        current=data.get("current"),
        suggested=data.get("suggested"),
        invariant=str(invariant) if invariant else None,
    )
