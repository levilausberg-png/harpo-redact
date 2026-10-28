"""Detector lab: one sample through the detection stages, each stage's output kept apart. Transient by design:
the caller gets their own text back annotated; nothing is stored, logged or counted."""

from __future__ import annotations

import time
from typing import Any

from .detectors.identifiers import decode_escapes
from .detectors.views import compact_view, display_order_view, leet_email_view, line_join_view, lookalike_view
from .normalize import normalize
from .pipeline import Pipeline

LAYERS = (
    ("patterns", "Validated patterns and identifiers", "deterministic"),
    ("secrets", "Secrets", "deterministic"),
    ("registry", "Protected registry", "deterministic"),
    ("custom", "Custom types", "deterministic"),
    ("names", "Name rules", "deterministic"),
    ("decoded", "Encoded data, field labels and shadow views", "deterministic"),
)
_SHADOW = ("decod", "encod", "base64", "escape", "view", "spell", "leet", "join", "compact", "field")


def _group(sources: Any) -> str:
    s = [str(x).lower() for x in sources]
    if any(x.startswith("secret") or x.startswith("prompt") for x in s):
        return "secrets"
    if any(x.startswith("custom:") for x in s):
        return "custom"
    if any("registry" in x for x in s):
        return "registry"
    if any(x.startswith("name") for x in s):
        return "names"
    if any(any(k in x for k in _SHADOW) for x in s):
        return "decoded"
    return "patterns"


def _value(x: Any) -> Any:
    return getattr(x, "value", x)


def _span(s: Any, text: str) -> dict[str, Any]:
    return {
        "start": s.start,
        "end": s.end,
        "type": getattr(s, "label", None) or _value(s.type),
        "sources": sorted(map(str, getattr(s, "sources", ()))),
        "value": text[s.start : s.end],
    }


def _ms(t: float) -> float:
    return round((time.perf_counter() - t) * 1000, 2)


def lab_run(pipeline: Pipeline, text: str) -> dict[str, Any]:
    timings: dict[str, float] = {}
    t = time.perf_counter()
    norm = normalize(text)
    timings["normalize"] = _ms(t)
    t = time.perf_counter()
    core = pipeline._core(norm.text)
    full = pipeline._deterministic(norm.text, norm.reversed_runs)
    timings["deterministic"] = _ms(t)
    groups: dict[str, list[dict[str, Any]]] = {k: [] for k, _, _ in LAYERS}
    seen = {(s.start, s.end, _value(s.type)) for s in core}
    for s in core:
        groups[_group(getattr(s, "sources", ()))].append(_span(s, norm.text))
    for s in full:  # found only through a decoded copy or a shadow view
        if (s.start, s.end, _value(s.type)) not in seen:
            groups["decoded"].append(_span(s, norm.text))
    ner: list[dict[str, Any]] | None = None
    if pipeline.ner is not None:
        t = time.perf_counter()
        precision = pipeline.settings.detection.ner.precision_filter
        ner = [_span(s, norm.text) for s in pipeline.ner.detect_many([norm.text], precision_filter=precision)[0]]
        timings["ner"] = _ms(t)
    t = time.perf_counter()
    out = pipeline.scan_sync([text])
    timings["full_scan"] = _ms(t)
    views: list[dict[str, str]] = []
    esc = decode_escapes(norm.text)
    if esc and esc[0] != norm.text:
        views.append({"name": "Escapes decoded", "text": esc[0]})
    for name, v in (
        ("Line breaks joined", line_join_view(norm.text)),
        ("Spelled and spaced runs compacted", compact_view(norm.text)),
        ("Leetspeak emails", leet_email_view(norm.text)),
        ("Right-to-left override read in display order", display_order_view(norm.text, norm.reversed_runs)),
        ("Look-alike letters read as Latin", lookalike_view(norm.text)),
    ):
        if v is not None and v.text != norm.text:
            views.append({"name": name, "text": v.text})
    findings = [
        {
            "type": _value(f.type),
            "start": f.start,
            "end": f.end,
            "placeholder": getattr(f, "placeholder", None),
            "sources": sorted(map(str, getattr(f, "sources", ()))),
            "value": text[f.start : f.end],
        }
        for f in out.findings[0]
    ]
    reasons = [{"code": getattr(r, "code", str(r)), "message": getattr(r, "message", "")} for r in out.reasons]
    layers = [
        {"id": k, "name": n, "kind": kind, "enabled": True, "spans": sorted(groups[k], key=lambda x: x["start"])}
        for k, n, kind in LAYERS
    ]
    layers.append(
        {
            "id": "ner",
            "name": "Named entities (NER)",
            "kind": "probabilistic",
            "enabled": ner is not None,
            "spans": ner or [],
        }
    )
    return {
        "normalized": {
            "text": norm.text,
            "changed": norm.changed,
            "removed_format_chars": norm.removed_format_chars,
            "mixed_script_tokens": norm.mixed_script_tokens,
        },
        "shadow_views": views,
        "layers": layers,
        "slm": {
            "enabled": pipeline.slm is not None,
            "note": "The lab runs the deterministic layers and NER. The Playground runs the full pipeline.",
        },
        "final": {
            "text": out.texts[0],
            "risk": _value(getattr(out, "risk", None)),
            "reasons": reasons,
            "findings": findings,
        },
        "timings_ms": timings,
    }
