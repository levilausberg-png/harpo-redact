"""HTTP surface: the scan API, the two provider-compatible proxies and the console."""

from __future__ import annotations

import asyncio
import base64
import collections
import difflib
import hashlib
import hmac
import importlib.metadata
import json
import logging
import math
import os
import platform
import re
import secrets
import threading
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote, unquote

import httpx
import yaml
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from . import KEY_PREFIX, __version__, library, live_policy
from .adapters import ADAPTERS, UncoveredField, adapter_for, egress_strings, enforce_coverage
from .analysis import analyze
from .config import AuthKey, Mode, NERSettings, Settings, Style, UpstreamSettings, load_settings
from .detectors.ner import NERDetector
from .detectors.secret_library import load_library
from .detectors.slm import SLMDetector
from .documents.runner import DocumentError, WorkerRunner
from .documents.service import STATUS as DOCUMENT_STATUS
from .documents.service import clean_filename, convert_chat_documents, redact_document
from .entities import ALWAYS_REDACTED
from .lab import lab_run
from .live_policy import LivePolicy
from .observability import APP_LOGGER, Metrics, audit, describe_exception
from .pipeline import Pipeline, ScanOutcome
from .posture import PostureMonitor
from .presets import COMPANIONS, PROVIDERS
from .proxy import (
    Collector,
    ModelNotAllowed,
    RemoteToolsBlocked,
    RequestShapeError,
    RoutingPolicyError,
    TooManyMessages,
    error_body,
)
from .risk import Level

log = logging.getLogger(APP_LOGGER)

CONSOLE_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
_FORWARDED_RESPONSE_HEADERS = frozenset(
    {"content-type", "retry-after", "request-id", "x-request-id", "openai-processing-ms", "openai-version"}
)
_FORWARDED_PREFIXES = ("x-ratelimit-", "anthropic-ratelimit-")
_FIELD_NAME_RE = re.compile(r"[a-z_]{1,40}")
_KNOWN_ROUTES = frozenset(
    {
        "/v1/scan",
        "/v1/documents/redact",
        "/v1/chat/completions",
        "/v1/messages",
        "/v1/policy",
        "/healthz",
        "/readyz",
        "/metrics",
        "/",
    }
)
_CONSOLE_DIR = Path(__file__).resolve().parent / "console"
_CONSOLE_TYPES = {".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml",
                  ".json": "application/json", ".woff2": "font/woff2", ".png": "image/png"}  # fmt: skip
# Exactly the files that ship, by exact relative path: no path from a request ever reaches the filesystem.
_ASSETS: dict[str, tuple[str, str]] = {
    f.relative_to(_CONSOLE_DIR).as_posix(): (f.relative_to(_CONSOLE_DIR).as_posix(), _CONSOLE_TYPES[f.suffix])
    for f in sorted(_CONSOLE_DIR.rglob("*"))
    if f.is_file() and f.suffix in _CONSOLE_TYPES
}


# --------------------------------------------------------------------------- errors
class GatewayError(Exception):
    def __init__(
        self,
        status: int,
        etype: str,
        message: str,
        style: Style = "openai",
        *,
        extra: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        decision: str = "rejected",
        risk: str = "none",
    ) -> None:
        super().__init__(etype)
        self.status = status
        self.etype = etype
        self.message = message
        self.style = style
        self.extra = extra
        self.headers = headers or {}
        self.decision = decision
        self.risk = risk


@dataclass
class _LiveState:
    """The live policy in force in this process, and what its file looked like when it was read."""

    policy: LivePolicy | None = None
    seen: live_policy.FileState = field(default_factory=lambda: live_policy.FileState(False))
    error: str | None = None  # the file changed but was not valid: the previous policy stays in force


def _validation_errors(exc: Exception) -> list[dict[str, str]]:
    if isinstance(exc, ValidationError):
        return [
            {"path": ".".join(str(x) for x in e["loc"]), "message": str(e["msg"]).removeprefix("Value error, ")}
            for e in exc.errors()
        ]
    return [{"path": "", "message": str(exc)}]


def _policy_changes(before: LivePolicy | None, after: LivePolicy | None) -> dict[str, Any]:
    """What a live-policy change did, for the audit log: types, custom type names and detector switches, never terms
    or patterns."""
    old = before.entities if before else {}
    new = after.entities if after else {}
    changed = {t.value: a for t, a in new.items() if old.get(t) != a}
    reset = sorted(t.value for t in old if t not in new)
    customs = after.custom_types if after and after.custom_types is not None else None
    was = before.detectors if before else {}
    now = after.detectors if after else {}
    return {
        "entities": changed,
        "entities_reset": reset,
        "custom_types": None if customs is None else {c.name: c.action for c in customs},
        "detectors": {f: on for f, on in now.items() if was.get(f) != on},
        "detectors_reset": sorted(f for f in was if f not in now),
    }


# OpenRouter-native clients and SDKs use /api/v1/...: the same handlers, limits, records and audit.
_ALIASES = {
    "/api/v1/chat/completions": "/v1/chat/completions",
    "/api/v1/messages": "/v1/messages",
    "/api/v1/messages/count_tokens": "/v1/messages/count_tokens",
    "/api/v1/models": "/v1/models",
}


def auth_headers(upstream: UpstreamSettings, key: str) -> dict[str, str]:
    """The provider key in the header this upstream expects (OpenRouter: bearer on both APIs)."""
    if upstream.effective_auth_scheme == "bearer":
        return {"authorization": f"Bearer {key}"}
    return {"x-api-key": key}


def api_root(upstream: UpstreamSettings) -> str:
    """The provider's /v1 root: OpenAI-style base URLs already end in it, Anthropic-style ones do not."""
    return upstream.base_url if upstream.style == "openai" else f"{upstream.base_url}/v1"


_MODEL_ID_RE = re.compile(r"[^\s\x00-\x1f\x7f]{1,200}")


def _style_for(path: str) -> Style:
    return "anthropic" if path.startswith("/v1/messages") else "openai"


def _route_label(path: str) -> str:
    return path if path in _KNOWN_ROUTES else "other"


# --------------------------------------------------------------------------- NER cache
_NER_CACHE: dict[tuple[Any, ...], NERDetector] = {}
_NER_LOCK = threading.Lock()


def load_ner(cfg: NERSettings) -> NERDetector:
    """Load (once per process) the spaCy model for this configuration."""
    key = (
        cfg.model,
        tuple(sorted((k, v.value) for k, v in cfg.labels.items())),
        cfg.chunk_chars,
        tuple(cfg.ignore),
        cfg.cache_entries,
        cfg.cache_ttl_s,
        tuple(sorted(cfg.language_models.items())),
        cfg.other_languages,
    )
    with _NER_LOCK:
        if key not in _NER_CACHE:
            _NER_CACHE[key] = NERDetector(
                cfg.model, cfg.labels, cfg.chunk_chars, cfg.ignore, cfg.cache_entries, cfg.cache_ttl_s,
                language_models={str(k): v for k, v in cfg.language_models.items()},
                other_languages=cfg.other_languages,
            )  # fmt: skip
        return _NER_CACHE[key]


@dataclass
class Sanitized:
    """A request after sanitization: what the proxy forwards and the egress preview shows."""

    body: dict[str, Any]
    upstream: UpstreamSettings
    stream: bool
    privacy_headers: dict[str, str]
    outcome: ScanOutcome
    egress_ms: float


# --------------------------------------------------------------------------- live stats for the console
_STATS_ROUTES = frozenset({"/v1/chat/completions", "/v1/messages", "/v1/messages/count_tokens", "/v1/scan",
                           "/v1/documents/redact"})  # fmt: skip
_EVENT_FIELDS = (
    "route", "status", "decision", "risk", "key_id", "model", "upstream", "redactions", "reasons", "total_ms", "slm",
    "mode", "request_id", "upstream_ms", "timings_ms", "response_findings", "stream", "egress", "egress_ms",
    "response_scan", "error", "document", "segments", "routing",
)  # fmt: skip
_STAGES = ("normalize", "patterns", "ner", "slm", "render", "total")


class LiveStats:
    """What the console shows: the same content-free fields as the audit log (INV-05), kept in memory."""

    def __init__(self, keep: int = 5_000) -> None:
        self.started = time.time()
        self._events: collections.deque[dict[str, Any]] = collections.deque(maxlen=keep)
        self._lock = threading.Lock()
        self.seq = 0

    def record(self, record: dict[str, Any]) -> None:
        event = {k: record[k] for k in _EVENT_FIELDS if k in record}
        event["ts"] = round(time.time(), 3)
        with self._lock:
            self.seq += 1
            event["seq"] = self.seq
            self._events.append(event)

    def since(self, seq: int, key_id: str | None) -> list[dict[str, Any]]:
        """Events after `seq`, oldest first: what the event stream sends next."""
        out: list[dict[str, Any]] = []
        with self._lock:
            for e in reversed(self._events):
                if e["seq"] <= seq:
                    break
                if key_id is None or e.get("key_id") == key_id:
                    out.append(dict(e))
        return out[::-1]

    def window(self, seconds: float) -> list[dict[str, Any]]:
        now = time.time()
        with self._lock:
            return [dict(e) for e in self._events if now - e["ts"] <= seconds]

    def key_usage(self) -> dict[str, dict[str, Any]]:
        usage: dict[str, dict[str, Any]] = {}
        with self._lock:
            for e in self._events:
                if e.get("key_id"):
                    u = usage.setdefault(str(e["key_id"]), {"requests": 0, "last_seen": None})
                    u["requests"] += 1
                    u["last_seen"] = e["ts"]
        return usage

    def snapshot(self, key_id: str | None, recent_n: int = 60) -> dict[str, Any]:
        now = time.time()
        with self._lock:
            events = [e for e in self._events if key_id is None or e.get("key_id") == key_id]
        recent = events[-recent_n:]
        events = [e for e in events if now - e["ts"] <= 3600]  # the totals are "the last hour"
        # A fresh gateway shows its first minutes across the chart, not squeezed into the last pixel of an hour.
        uptime = now - self.started
        window = 3600 if uptime >= 3300 else max(300, int(math.ceil((uptime + 1) / 300) * 300))
        step = window / 60
        by_type: dict[str, int] = {}
        by_reason: dict[str, int] = {}
        latencies: list[float] = []
        series = [
            {"t": round(now - window + (i + 1) * step), "requests": 0, "blocked": 0, "redactions": 0} for i in range(60)
        ]
        totals = {"requests": 0, "forwarded": 0, "blocked": 0, "scanned": 0, "errors": 0, "redactions": 0}
        for e in events:
            totals["requests"] += 1
            decision = str(e.get("decision", ""))
            if decision in ("forwarded", "blocked", "scanned"):
                totals[decision] += 1
            if int(e.get("status", 200)) >= 500 or decision in ("upstream_error", "error"):
                totals["errors"] += 1
            raw = e.get("redactions")
            counts: dict[str, Any] = raw if isinstance(raw, dict) else {}
            found = sum(int(v) for v in counts.values())
            totals["redactions"] += found
            for t, n in counts.items():
                by_type[t] = by_type.get(t, 0) + int(n)
            if decision == "blocked":
                for code in e.get("reasons") or []:
                    by_reason[str(code)] = by_reason.get(str(code), 0) + 1
            if decision in ("forwarded", "scanned") and isinstance(e.get("total_ms"), (int, float)):
                latencies.append(float(e["total_ms"]))
            slot = int((e["ts"] - (now - window)) // step)
            if 0 <= slot < 60:
                bucket = series[slot]
                bucket["requests"] += 1
                bucket["blocked"] += decision == "blocked"
                bucket["redactions"] += found
        latencies.sort()

        def pcts(values: list[float]) -> dict[str, Any]:
            values = sorted(values)
            if not values:
                return {"p50": None, "p95": None, "count": 0}
            top = values[min(len(values) - 1, int(0.95 * len(values)))]
            return {"p50": round(values[len(values) // 2], 2), "p95": round(top, 2), "count": len(values)}

        stage_values: dict[str, list[float]] = {k: [] for k in _STAGES}
        ups: dict[str, dict[str, Any]] = {}
        routes: dict[str, int] = {}
        decisions: dict[str, int] = {}
        slm_states: dict[str, int] = {}
        doc_latency: list[float] = []
        doc_jobs = doc_failed = response_findings = 0
        for e in events:
            routes[str(e.get("route"))] = routes.get(str(e.get("route")), 0) + 1
            decisions[str(e.get("decision"))] = decisions.get(str(e.get("decision")), 0) + 1
            if e.get("slm"):
                slm_states[str(e["slm"])] = slm_states.get(str(e["slm"]), 0) + 1
            raw_timings = e.get("timings_ms")
            timings: dict[str, Any] = raw_timings if isinstance(raw_timings, dict) else {}
            for k in _STAGES:
                if isinstance(timings.get(k), (int, float)):
                    stage_values[k].append(float(timings[k]))
            if e.get("upstream"):
                u = ups.setdefault(str(e["upstream"]), {"requests": 0, "errors": 0, "blocked": 0, "latencies": []})
                u["requests"] += 1
                u["errors"] += int(e.get("decision") == "upstream_error" or int(e.get("status", 200)) >= 500)
                u["blocked"] += int(e.get("decision") == "blocked")
                if isinstance(e.get("upstream_ms"), (int, float)):
                    u["latencies"].append(float(e["upstream_ms"]))
            if e.get("route") == "/v1/documents/redact":
                doc_jobs += 1
                doc_failed += int(int(e.get("status", 200)) >= 400)
                if isinstance(e.get("total_ms"), (int, float)):
                    doc_latency.append(float(e["total_ms"]))
            raw_findings = e.get("response_findings")
            if isinstance(raw_findings, dict):
                response_findings += sum(int(v) for v in raw_findings.values())

        def pct(q: float) -> float | None:
            return round(latencies[min(len(latencies) - 1, int(q * len(latencies)))], 1) if latencies else None

        return {
            "uptime_s": int(now - self.started),
            "totals": totals,
            "by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
            "by_reason": dict(sorted(by_reason.items(), key=lambda kv: -kv[1])),
            "latency_ms": {"p50": pct(0.5), "p95": pct(0.95), "p99": pct(0.99)},
            "window_s": window,
            "stages": {k: pcts(v) for k, v in stage_values.items()},
            "upstreams": {
                n: {"requests": u["requests"], "errors": u["errors"], "blocked": u["blocked"], **pcts(u["latencies"])}
                for n, u in ups.items()
            },
            "routes": routes,
            "decisions": decisions,
            "slm_states": slm_states,
            "documents": {"jobs": doc_jobs, "failed": doc_failed, **pcts(doc_latency)},
            "response_findings": response_findings,
            "series": series,
            "recent": list(reversed(recent)),
        }


# --------------------------------------------------------------------------- per-key rate limits
class RateLimiter:
    """A sliding one-minute window per key. In memory, per process: with N workers the effective limit is N times
    the configured one; put a shared limiter in front for exact global limits."""

    def __init__(self) -> None:
        self._hits: dict[str, collections.deque[float]] = {}
        self._lock = threading.Lock()

    def take(self, key_id: str, per_minute: int) -> float:
        """0 if the request may go ahead (and counts it), else the seconds until it could."""
        now = time.monotonic()
        with self._lock:
            hits = self._hits.setdefault(key_id, collections.deque())
            while hits and now - hits[0] >= 60.0:
                hits.popleft()
            if len(hits) >= per_minute:
                return 60.0 - (now - hits[0])
            hits.append(now)
            return 0.0


# --------------------------------------------------------------------------- response scanning
def _answer_strings(style: Style, payload: Any) -> list[tuple[Any, Any]]:
    """(container, key) of the free text in a provider answer: what the model wrote, tool arguments included."""
    refs: list[tuple[Any, Any]] = []

    def tree(node: Any) -> None:
        items = node.items() if isinstance(node, dict) else enumerate(node) if isinstance(node, list) else []
        for key, value in items:
            if isinstance(value, str):
                refs.append((node, key))
            elif isinstance(value, (dict, list)):
                tree(value)

    if not isinstance(payload, dict):
        return refs
    if style == "openai":
        for choice in payload.get("choices") or []:
            message = choice.get("message") if isinstance(choice, dict) else None
            if not isinstance(message, dict):
                continue
            # reasoning: the readable reasoning text some providers (OpenRouter) return next to the answer
            refs.extend(
                (message, key) for key in ("content", "refusal", "reasoning") if isinstance(message.get(key), str)
            )
            for call in message.get("tool_calls") or []:
                function = call.get("function") if isinstance(call, dict) else None
                if isinstance(function, dict) and isinstance(function.get("arguments"), str):
                    refs.append((function, "arguments"))
    else:
        for block in payload.get("content") or []:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                refs.append((block, "text"))
            elif isinstance(block, dict) and isinstance(block.get("input"), (dict, list)):
                tree(block["input"])
    return refs


async def scan_response(pipeline: Pipeline, style: Style, content: bytes, redact: bool) -> tuple[bytes, dict[str, int]]:
    try:
        payload = json.loads(content)
    except (ValueError, UnicodeDecodeError):
        return content, {}
    refs = _answer_strings(style, payload)
    if not refs:
        return content, {}
    texts, findings = await pipeline.redact_deterministic([c[k] for c, k in refs])
    if not redact or not findings:
        return content, findings
    for (container, key), text in zip(refs, texts, strict=True):
        container[key] = text
    return json.dumps(payload, ensure_ascii=False).encode(), findings


# --------------------------------------------------------------------------- ASGI middleware
class GatewayMiddleware:
    """Request ids, an early body-size check and security headers on every response."""

    def __init__(
        self,
        app: ASGIApp,
        max_body_bytes: int,
        hsts: bool,
        metrics: Metrics,
        route_limits: dict[str, int] | None = None,
    ) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.route_limits = route_limits or {}  # routes that accept files get a larger limit
        self.hsts = hsts
        self.metrics = metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        alias = _ALIASES.get(scope.get("path", ""))
        if alias is not None:
            scope = {**scope, "path": alias, "raw_path": alias.encode()}
        request_id = uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id
        path: str = scope.get("path", "")
        started = False

        async def send_with_headers(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                headers = list(message.get("headers", []))
                present = {k.lower() for k, _ in headers}
                extra = [
                    (b"x-harpo-request-id", request_id.encode()),
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"x-frame-options", b"DENY"),
                    (b"cross-origin-opener-policy", b"same-origin"),
                    (b"cross-origin-resource-policy", b"same-origin"),
                    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), interest-cohort=()"),
                    (b"content-security-policy", CONSOLE_CSP.encode()),
                ]
                if b"cache-control" not in present:
                    extra.append((b"cache-control", b"no-store"))
                if self.hsts:
                    extra.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                message["headers"] = headers + [h for h in extra if h[0] not in present]
            await send(message)

        for name, value in scope.get("headers", []):
            if name == b"content-length":
                limit = self.route_limits.get(path, self.max_body_bytes)
                try:
                    too_big = int(value) > limit
                except ValueError:
                    too_big = True
                if too_big:
                    body = json.dumps(
                        error_body(
                            _style_for(path),
                            "request_too_large",
                            f"Request body exceeds {limit} bytes.",
                        )
                    ).encode()
                    await send_with_headers(
                        {
                            "type": "http.response.start",
                            "status": 413,
                            "headers": [
                                (b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode()),
                            ],
                        }
                    )
                    await send_with_headers({"type": "http.response.body", "body": body})
                    return
                break
        try:
            await self.app(scope, receive, send_with_headers)
        except Exception as exc:
            # Last line of defence. Handled here so the server never logs a
            # traceback whose message could quote request content.
            log.error(
                "unhandled_error",
                extra={
                    "fields": {"request_id": request_id, "route": _route_label(path), "error": describe_exception(exc)}
                },
            )
            self.metrics.requests.labels(_route_label(path), "error", "none").inc()
            if not started:
                body = json.dumps(
                    error_body(_style_for(path), "api_error", f"Internal gateway error. Request id {request_id}.")
                ).encode()
                await send_with_headers(
                    {
                        "type": "http.response.start",
                        "status": 500,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode()),
                        ],
                    }
                )
                await send_with_headers({"type": "http.response.body", "body": body})


# --------------------------------------------------------------------------- scan API model
class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str | None = None
    texts: list[str] | None = None
    mode: Mode | None = None
    context_repair: bool | None = None
    layers: Literal["fast", "full"] = "full"
    override: bool = False


def _validation_message(exc: ValidationError) -> str:
    # Only field locations and error kinds: never the offending input.
    parts = []
    for error in exc.errors()[:5]:
        location = ".".join(str(p) for p in error.get("loc", ())) or "body"
        parts.append(f"{location}: {error.get('msg', 'invalid')}")
    return "; ".join(parts)


# --------------------------------------------------------------------------- app factory
def create_app(
    settings: Settings,
    *,
    upstream_transport: httpx.AsyncBaseTransport | None = None,
    slm_transport: httpx.AsyncBaseTransport | None = None,
    ner_detector: NERDetector | None = None,
) -> FastAPI:
    metrics = Metrics()
    live_state = _LiveState()
    live_lock = asyncio.Lock()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        ner = None
        if settings.detection.ner.enabled:
            ner = ner_detector or await asyncio.to_thread(load_ner, settings.detection.ner)
        slm = None
        slm_client = None
        if settings.detection.slm.enabled:
            cfg = settings.detection.slm
            slm_client = httpx.AsyncClient(
                base_url=cfg.base_url,
                transport=slm_transport,
                timeout=cfg.timeout_ms / 1000 + 1,
                follow_redirects=False,
            )
            slm = SLMDetector(
                slm_client, cfg.model, cfg.timeout_ms, cfg.max_chunk_chars, cfg.max_concurrency, cfg.keep_alive,
                max_input_chars=cfg.max_input_chars, model_digest=cfg.model_digest,
            )  # fmt: skip
        clients: dict[str, httpx.AsyncClient] = {}
        keys: dict[str, str | None] = {}
        for upstream in settings.upstreams:
            clients[upstream.name] = httpx.AsyncClient(
                transport=upstream_transport,
                timeout=httpx.Timeout(upstream.timeout_s, connect=upstream.connect_timeout_s),
                limits=httpx.Limits(max_connections=upstream.max_connections),
                follow_redirects=False,
            )
            keys[upstream.name] = os.environ.get(upstream.api_key_env) if upstream.api_key_env else None
        # The live policy (console changes) is laid over the configuration. An invalid file stops startup,
        # exactly like an invalid configuration: nothing runs on a policy nobody can read.
        effective = settings
        live_path = settings.policy.live_file
        if live_path:
            live_state.seen = live_policy.file_state(live_path)
            try:
                live_state.policy = live_policy.load(live_path)
                effective = live_policy.apply(settings, live_state.policy)
            except ValueError as exc:
                problems = "; ".join(f"{e['path']}: {e['message']}" for e in _validation_errors(exc))
                raise RuntimeError(f"policy.live_file {live_path} is not valid: {problems}") from None
        pipeline = Pipeline(effective, ner=ner, slm=slm)
        await asyncio.to_thread(pipeline.warmup)
        app.state.pipeline = pipeline
        for notice in settings.notices():
            log.warning("config_notice", extra={"fields": {"notice": notice}})
        app.state.slm = slm
        app.state.clients = clients
        app.state.keys = keys
        log.info(
            "started",
            extra={
                "fields": {
                    "version": __version__,
                    "environment": settings.environment,
                    "ner": ner.model_name if ner else None,
                    "slm": settings.detection.slm.model if slm else None,
                    "upstreams": [u.name for u in settings.upstreams],
                }
            },
        )
        try:
            posture_task = asyncio.create_task(posture_loop())
            watch_task = asyncio.create_task(watch_live_policy()) if live_path else None
            yield
            posture_task.cancel()
            if watch_task is not None:
                watch_task.cancel()
        finally:
            for client in clients.values():
                await client.aclose()
            if slm_client is not None:
                await slm_client.aclose()

    app = FastAPI(
        title="Harpo",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.metrics = metrics
    app.state.settings = settings
    app.state.doc_runner = WorkerRunner(settings.documents)
    doc_cfg = settings.documents
    route_limits: dict[str, int] = {}
    if doc_cfg.enabled:
        route_limits["/v1/documents/redact"] = doc_cfg.max_bytes + 65_536
    if doc_cfg.in_chat:  # base64 inflates a file by a third
        chat_limit = settings.server.max_body_bytes + doc_cfg.max_bytes * 4 // 3 + 65_536
        route_limits["/v1/chat/completions"] = route_limits["/v1/messages"] = chat_limit

    # ------------------------------------------------------------------ helpers
    def finish_audit(request: Request, status: int, decision: str, risk: str, **fields: Any) -> None:
        metrics.requests.labels(_route_label(request.url.path), decision, risk).inc()
        if request.url.path in _STATS_ROUTES and request.headers.get("x-harpo-preview") != "1":
            started = getattr(request.state, "started", None)
            live.record(
                {
                    **getattr(request.state, "audit", {}),
                    **fields,
                    "route": request.url.path,
                    "status": status,
                    "request_id": getattr(request.state, "request_id", None),
                    "decision": decision,
                    "risk": risk,
                    **({"total_ms": round((time.perf_counter() - started) * 1000, 2)} if started is not None else {}),
                }
            )
        if not settings.logging.audit or not request.url.path.startswith("/v1/"):
            return
        record = dict(getattr(request.state, "audit", {}))
        record.update(fields)
        record.update(
            request_id=request.state.request_id,
            route=request.url.path,
            status=status,
            decision=decision,
            risk=risk,
        )
        started = getattr(request.state, "started", None)
        if started is not None:
            record["total_ms"] = round((time.perf_counter() - started) * 1000, 2)
        audit(record)

    rate_limiter = RateLimiter()
    live = LiveStats()

    def authenticate(request: Request, style: Style) -> str:
        request.state.started = time.perf_counter()
        request.state.audit = {}
        mode = settings.policy.override
        if not settings.auth.enabled:
            key_id = "anonymous"
            request.state.can_override = mode != "never"
            request.state.admin = True
        else:
            token = ""  # empty initial value  # nosec B105
            header = request.headers.get("authorization", "")
            if header[:7].lower() == "bearer ":
                token = header[7:].strip()
            if not token:
                token = request.headers.get("x-api-key", "").strip()
            if not token:
                raise GatewayError(
                    401,
                    "authentication_error",
                    "Missing gateway key. Send it as Authorization: Bearer <key> or x-api-key.",
                    style,
                )
            digest = hashlib.sha256(token.encode()).hexdigest()
            key_id = ""
            can_override = False
            matched: AuthKey | None = None
            for key in settings.auth.keys:  # no early exit: constant work per request
                if hmac.compare_digest(digest, key.sha256):
                    key_id = key.id
                    can_override = key.can_override
                    matched = key
            if not key_id or matched is None:
                raise GatewayError(401, "authentication_error", "Unknown gateway key.", style)
            if matched.expires_at is not None and datetime.now(UTC) >= matched.expires_at:
                request.state.audit["key_id"] = key_id
                raise GatewayError(401, "authentication_error", "This gateway key has expired.", style)
            if matched.requests_per_minute is not None:
                wait = rate_limiter.take(key_id, matched.requests_per_minute)
                if wait > 0:
                    request.state.audit["key_id"] = key_id
                    raise GatewayError(
                        429, "rate_limit_error", "Too many requests for this gateway key. Try again shortly.", style,
                        headers={"retry-after": str(max(1, math.ceil(wait)))},
                    )  # fmt: skip
            request.state.can_override = mode == "any_key" or (mode == "listed_keys" and can_override)
            request.state.admin = matched.admin
        request.state.audit["key_id"] = key_id
        return key_id

    async def read_bytes(request: Request, limit: int, style: Style) -> bytes:
        chunks: list[bytes] = []
        total = 0
        async for chunk in request.stream():
            total += len(chunk)
            if total > limit:
                raise GatewayError(413, "request_too_large", f"Request body exceeds {limit} bytes.", style)
            chunks.append(chunk)
        return b"".join(chunks)

    async def read_json(request: Request, style: Style) -> dict[str, Any]:
        raw = await read_bytes(request, route_limits.get(request.url.path, settings.server.max_body_bytes), style)
        try:
            body = json.loads(raw)
        except (ValueError, RecursionError):
            raise GatewayError(400, "invalid_request_error", "Request body is not valid JSON.", style) from None
        if not isinstance(body, dict):
            raise GatewayError(400, "invalid_request_error", "Request body must be a JSON object.", style)
        return body

    def parse_bool(raw: str, header: str, style: Style) -> bool:
        value = raw.strip().lower()
        if value in ("true", "1", "yes"):
            return True
        if value in ("false", "0", "no", ""):
            return False
        raise GatewayError(400, "invalid_request_error", f"{header} must be true or false.", style)

    def privacy_options(request: Request, style: Style) -> tuple[Mode, bool, bool]:
        policy = settings.policy
        mode: Mode = policy.default_mode
        repair = policy.context_repair
        if policy.client_may_choose_mode:
            raw_mode = request.headers.get("x-harpo-mode")
            if raw_mode is not None:
                value = raw_mode.strip().lower()
                if value == "relational":
                    mode = "relational"
                elif value == "generic":
                    mode = "generic"
                else:
                    raise GatewayError(
                        400, "invalid_request_error", "X-Harpo-Mode must be relational or generic.", style
                    )
            raw_repair = request.headers.get("x-harpo-context-repair")
            if raw_repair is not None:
                repair = parse_bool(raw_repair, "X-Harpo-Context-Repair", style)
        override = parse_bool(request.headers.get("x-harpo-override", ""), "X-Harpo-Override", style)
        return mode, repair, override and request.state.can_override

    async def require_layers(style: Style) -> None:
        slm: SLMDetector | None = app.state.slm
        if slm is not None and settings.detection.slm.on_failure == "fail_closed" and not await slm.ping():
            raise GatewayError(503, "not_ready", "A required detection layer (local SLM) is unavailable.", style)

    def scan_fields(outcome: ScanOutcome) -> dict[str, Any]:
        return {
            "mode": outcome.mode,
            "context_repair": outcome.context_repair,
            "reasons": [r.code for r in outcome.reasons],
            "redactions": outcome.counts,
            "secret_rules": outcome.secret_rules,
            "slm": outcome.slm_status,
            "timings_ms": outcome.timings_ms,
        }

    def block_details(outcome: ScanOutcome, can_override: bool) -> dict[str, Any]:
        return {
            "risk": outcome.risk.value,
            "overridable": outcome.overridable and can_override,
            "override_permitted": can_override,
            "blocked_types": outcome.blocked_types,
            "reasons": [r.to_dict() for r in outcome.reasons],
        }

    # ------------------------------------------------------------------ exception handlers
    @app.exception_handler(GatewayError)
    async def on_gateway_error(request: Request, exc: GatewayError) -> JSONResponse:
        finish_audit(request, exc.status, exc.decision, exc.risk, error=exc.etype)
        return JSONResponse(
            error_body(exc.style, exc.etype, exc.message, exc.extra), status_code=exc.status, headers=exc.headers
        )

    @app.exception_handler(RequestValidationError)
    async def on_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        style = _style_for(request.url.path)
        return JSONResponse(error_body(style, "invalid_request_error", "Invalid request."), status_code=400)

    @app.exception_handler(StarletteHTTPException)
    async def on_http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        style = _style_for(request.url.path)
        etype = {404: "not_found_error", 405: "invalid_request_error"}.get(exc.status_code, "invalid_request_error")
        message = {404: "Not found.", 405: "Method not allowed."}.get(exc.status_code, "Request rejected.")
        metrics.requests.labels(_route_label(request.url.path), "rejected", "none").inc()
        return JSONResponse(error_body(style, etype, message), status_code=exc.status_code)

    # ------------------------------------------------------------------ operational routes
    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/readyz")
    async def readyz(request: Request) -> JSONResponse:
        ready, checks = await readiness()
        status = "ready" if ready else "not_ready"
        return JSONResponse({"status": status, "checks": checks}, status_code=200 if ready else 503)

    @app.get("/metrics")
    async def metrics_endpoint() -> Response:
        if not settings.server.metrics:
            raise StarletteHTTPException(404)
        return Response(metrics.render(), media_type="text/plain; version=0.0.4; charset=utf-8")

    # ------------------------------------------------------------------ console
    console_dir = resources.files("harpo_redact") / "console"

    @app.get("/")
    async def console() -> Response:
        if not settings.server.console:
            raise StarletteHTTPException(404)
        html = (console_dir / "index.html").read_bytes()
        return Response(html, media_type="text/html; charset=utf-8")

    @app.get("/console/{path:path}")
    async def console_asset(path: str) -> Response:
        entry = _ASSETS.get(path)
        if not settings.server.console or entry is None:
            raise StarletteHTTPException(404)
        filename, media_type = entry
        data = (console_dir / filename).read_bytes()
        return Response(data, media_type=media_type, headers={"cache-control": "public, max-age=3600"})

    # ------------------------------------------------------------------ v1 API
    @app.get("/v1/policy")
    async def policy(request: Request) -> dict[str, Any]:
        authenticate(request, "openai")
        effective = effective_settings()
        p = effective.policy
        models = [m for u in settings.upstreams if u.style == "openai" for m in u.literal_models]
        return {
            "version": __version__,
            "environment": settings.environment,
            "default_mode": p.default_mode,
            "context_repair": p.context_repair,
            "client_may_choose_mode": p.client_may_choose_mode,
            "entities": {t.value: {"action": e.action, "overridable": e.overridable} for t, e in p.entities.items()},
            "always_redacted": sorted(t.value for t in ALWAYS_REDACTED),
            # Names and actions only; terms and patterns are for admin keys (GET /v1/policy/live).
            "custom_types": [
                {
                    "name": c.name,
                    "description": c.description,
                    "action": c.action,
                    "overridable": c.overridable,
                    "terms": len(c.terms),
                    "patterns": len(c.patterns),
                }
                for c in effective.detection.custom_types
            ],
            "live_policy": {
                "enabled": bool(settings.policy.live_file),
                "updated_at": live_state.policy.updated_at if live_state.policy else None,
            },
            "rot_threshold": p.rot_threshold,
            "unsupported_content": p.unsupported_content,
            "upstreams": [{"name": u.name, "style": u.style, "models": u.models} for u in settings.upstreams],
            "models": models,
            "ner": {"enabled": settings.detection.ner.enabled, "model": settings.detection.ner.model},
            "slm": {"enabled": settings.detection.slm.enabled, "on_failure": settings.detection.slm.on_failure},
            "auth": {"enabled": settings.auth.enabled},
            "override_permitted": request.state.can_override,
            "admin": bool(getattr(request.state, "admin", False)),
            "unknown_fields": p.unknown_fields,
            "remote_mcp": p.remote_mcp,
            "egress_verification": p.egress_verification,
            "response_scan": p.response_scan,
            "adapters": {
                name: {
                    **adapter.describe(),
                    "in_use": any(adapter_for(u.style, u.effective_dialect).name == name for u in settings.upstreams),
                }
                for name, adapter in ADAPTERS.items()
            },
            "documents": {
                "enabled": settings.documents.enabled,
                "in_chat": settings.documents.in_chat,
                "formats": settings.documents.formats,
                "max_bytes": settings.documents.max_bytes,
                "max_pages": settings.documents.max_pages,
                "images": settings.documents.images,
            },
            "limits": {
                "max_body_bytes": settings.server.max_body_bytes,
                "max_messages": settings.server.max_messages,
                "max_total_chars": settings.server.max_total_chars,
            },
        }

    @app.post("/v1/scan")
    async def scan(request: Request) -> JSONResponse:
        authenticate(request, "openai")
        body = await read_json(request, "openai")
        try:
            params = ScanRequest.model_validate(body)
        except ValidationError as exc:
            raise GatewayError(400, "invalid_request_error", _validation_message(exc)) from None
        if (params.text is None) == (params.texts is None):
            raise GatewayError(400, "invalid_request_error", "Send exactly one of text or texts.")
        texts = [params.text] if params.text is not None else list(params.texts or [])
        if len(texts) > settings.server.max_messages:
            raise GatewayError(413, "request_too_large", f"At most {settings.server.max_messages} texts per scan.")
        if sum(len(t) for t in texts) > settings.server.max_total_chars:
            raise GatewayError(
                413, "request_too_large", f"Texts exceed {settings.server.max_total_chars} characters in total."
            )
        mode = params.mode if settings.policy.client_may_choose_mode else None
        repair = params.context_repair if settings.policy.client_may_choose_mode else None
        if params.layers == "full":
            await require_layers("openai")
        outcome = await app.state.pipeline.scan(
            texts,
            mode=mode,
            context_repair=repair,
            layers=params.layers,
            override=params.override and request.state.can_override,
        )
        metrics.observe_scan(outcome.timings_ms, outcome.counts, outcome.slm_status)
        finish_audit(request, 200, "scanned", outcome.risk.value, layers=params.layers, **scan_fields(outcome))
        return JSONResponse(
            {
                "request_id": request.state.request_id,
                "risk": outcome.risk.value,
                "overridable": outcome.overridable and request.state.can_override,
                "reasons": [r.to_dict() for r in outcome.reasons],
                "mode": outcome.mode,
                "context_repair": outcome.context_repair,
                "layers": params.layers,
                "results": [
                    {"redacted": text, "entities": [f.to_dict() for f in findings]}
                    for text, findings in zip(outcome.texts, outcome.findings, strict=True)
                ],
                "counts": outcome.counts,
                "redactions": outcome.redactions,
                "rot_score": outcome.rot_score,
                "flags": outcome.flags,
                "slm": outcome.slm_status,
                "timings_ms": outcome.timings_ms,
            }
        )

    @app.post("/v1/documents/redact")
    async def documents_redact(request: Request) -> Response:
        authenticate(request, "openai")
        cfg = settings.documents
        if not cfg.enabled:
            raise GatewayError(404, "not_found", "Document redaction is not enabled.")
        mode, repair, override = privacy_options(request, "openai")
        reply = (request.headers.get("x-harpo-response") or request.query_params.get("response") or "file").lower()
        if reply not in ("file", "json"):
            raise GatewayError(400, "invalid_request_error", "response must be file or json.")
        with_file = not (reply == "json" and request.query_params.get("file", "true").lower() == "false")
        # The name travels in a header, percent-encoded: a URL is logged by every proxy on the way, a header is not.
        filename = clean_filename(unquote(request.headers.get("x-harpo-filename") or ""))
        data = await read_bytes(request, cfg.max_bytes, "openai")
        if not data:
            raise GatewayError(
                400, "invalid_request_error", "The request body is empty: send the file itself as the body."
            )
        await require_layers("openai")
        try:
            result = await redact_document(
                app.state.pipeline, cfg, app.state.doc_runner, data, filename, request.headers.get("content-type"),
                mode=mode, context_repair=repair, override=override, want_file=with_file,
            )  # fmt: skip
        except DocumentError as exc:
            raise GatewayError(
                DOCUMENT_STATUS.get(exc.code, 422), "document_error", exc.message, "openai", extra={"code": exc.code}
            ) from None
        outcome = result.scan
        metrics.observe_scan(outcome.timings_ms, outcome.counts, outcome.slm_status)
        request.state.audit.update(scan_fields(outcome))
        request.state.audit.update(document=result.kind, segments=result.segments)
        privacy_headers = {
            "x-harpo-risk": outcome.risk.value,
            "x-harpo-redactions": str(outcome.redactions),
            "x-harpo-mode": outcome.mode,
            "x-harpo-document": result.kind,
            "x-harpo-segments": str(result.segments),
            "x-harpo-verified": "true",  # released only after reconstruction verification (INV-09)
        }
        if outcome.blocked:
            for reason in outcome.reasons:
                if reason.level is Level.RED:
                    metrics.blocks.labels(reason.code).inc()
            raise GatewayError(
                403, "privacy_block", "Document blocked by privacy policy. See error.harpo.reasons.", "openai",
                extra=block_details(outcome, request.state.can_override), headers=privacy_headers,
                decision="blocked", risk="red",
            )  # fmt: skip
        finish_audit(request, 200, "redacted", outcome.risk.value, document=result.kind, segments=result.segments)
        out_name = f"{result.filename}.redacted.{result.extension or 'txt'}" if result.data is not None else None
        if reply == "json":
            payload: dict[str, Any] = {
                "request_id": request.state.request_id,
                "risk": outcome.risk.value,
                "kind": result.kind,
                "overridable": outcome.overridable and request.state.can_override,
                "reasons": [r.to_dict() for r in outcome.reasons],
                "mode": outcome.mode,
                "counts": outcome.counts,
                "redactions": outcome.redactions,
                "segments": result.segments,
                "info": result.info,
                "text": result.text,
                "verified": result.verified,
                "file": None,
            }
            if result.data is not None and out_name is not None:
                payload["file"] = {
                    "filename": out_name,
                    "content_type": result.content_type,
                    "base64": base64.b64encode(result.data).decode("ascii"),
                }
            return JSONResponse(payload, headers=privacy_headers)
        if result.data is None or out_name is None:  # a file response always produces a file
            raise GatewayError(500, "server_error", "The redacted file was not produced.", "openai")
        ascii_name = out_name.encode("ascii", "replace").decode().replace("?", "_")
        return Response(
            result.data,
            media_type=result.content_type or "application/octet-stream",
            headers={
                **privacy_headers,
                "x-harpo-verified": "true" if result.verified else "false",
                "content-disposition": f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(out_name)}",
            },
        )

    async def proxy(request: Request, style: Style, endpoint: str | None = None) -> Response:
        authenticate(request, style)
        body = await read_json(request, style)
        ready = await sanitize(request, style, body)
        return await forward(
            request,
            style,
            ready.upstream,
            ready.body,
            ready.stream,
            ready.privacy_headers,
            ready.outcome.risk.value,
            endpoint=endpoint,
        )

    async def sanitize(request: Request, style: Style, body: dict[str, Any], record: bool = True) -> Sanitized:
        """Everything between receiving a request and sending it on. The proxy and the egress preview both use
        this, so the preview shows exactly what would leave. record=False keeps self-tests out of the metrics."""
        mode, repair, override = privacy_options(request, style)
        model = body.get("model")
        if not isinstance(model, str) or not model:
            raise GatewayError(400, "invalid_request_error", "model is required.", style)
        upstream = settings.upstream_for(style, model)
        if upstream is None:
            raise GatewayError(403, "model_not_allowed", "This model is not allowed by gateway policy.", style)
        stream = body.get("stream") is True
        request.state.audit.update(upstream=upstream.name, model=model, stream=stream)
        adapter = adapter_for(style, upstream.effective_dialect)
        if settings.policy.unknown_fields == "reject":
            unknown = next((k for k in body if k not in adapter.allowed_fields), None)
            if unknown is not None:
                name = unknown if _FIELD_NAME_RE.fullmatch(unknown) else "(unnamed)"
                raise GatewayError(
                    400, "invalid_request_error", f"Field '{name}' is not allowed by gateway policy.", style
                )
        attached_chars = 0
        if settings.documents.enabled and settings.documents.in_chat:
            try:
                attached, attached_chars = await convert_chat_documents(
                    body, style, settings.documents, app.state.doc_runner
                )
            except DocumentError as exc:
                raise GatewayError(
                    DOCUMENT_STATUS.get(exc.code, 422), "document_error", exc.message, style, extra={"code": exc.code}
                ) from None
            request.state.audit.update(documents=attached)
        collector = Collector(drop_unsupported=settings.policy.unsupported_content == "drop")
        try:
            adapter.prepare(
                body,
                collector,
                settings.server.max_messages,
                remote_mcp=settings.policy.remote_mcp == "allow",
                upstream=upstream,
            )
            enforce_coverage(body, collector, adapter, settings.policy.unknown_fields)
        except RemoteToolsBlocked:
            remote_reason = {
                "code": "remote_tools",
                "level": "red",
                "message": "Remote MCP servers are blocked: the provider would call them with your credentials.",
                "entity_type": None,
                "count": 1,
                "overridable": False,
            }
            raise GatewayError(
                403, "privacy_block", "Request blocked by privacy policy. See error.harpo.reasons.", style,
                extra={"risk": "red", "overridable": False, "override_permitted": request.state.can_override,
                       "blocked_types": [], "reasons": [remote_reason]},
                decision="blocked", risk="red",
            ) from None  # fmt: skip
        except TooManyMessages:
            raise GatewayError(
                413, "request_too_large", f"At most {settings.server.max_messages} messages are allowed.", style
            ) from None
        except ModelNotAllowed as exc:  # the message names a field or plugin, never request content
            raise GatewayError(403, "model_not_allowed", f"Not allowed by gateway policy: {exc}.", style) from None
        except RoutingPolicyError as exc:
            raise GatewayError(403, "routing_policy", f"Not allowed by gateway routing policy: {exc}.", style) from None
        except UncoveredField as exc:  # paths only, never values
            raise GatewayError(
                400, "invalid_request_error", f"Not inspected by the gateway, so not allowed by policy: {exc}.", style
            ) from None
        except RequestShapeError as exc:
            raise GatewayError(400, "invalid_request_error", f"Unsupported request shape: {exc}.", style) from None
        except (TypeError, AttributeError, KeyError, IndexError, ValueError):
            # A shape no adapter rule anticipated: refuse it rather than guess (and never answer with a 500).
            raise GatewayError(400, "invalid_request_error", "Unsupported request shape.", style) from None
        if collector.notes.get("routing"):
            request.state.audit["routing"] = collector.notes["routing"]
        if collector.total_chars > settings.server.max_total_chars + attached_chars:  # attachments have their own cap
            raise GatewayError(
                413, "request_too_large", f"Text exceeds {settings.server.max_total_chars} characters in total.", style
            )
        await require_layers(style)
        # One policy per request: a live-policy change mid-request must not mix the scan and egress check.
        pipeline: Pipeline = app.state.pipeline
        outcome: ScanOutcome = await pipeline.scan(
            collector.texts,
            mode=mode,
            context_repair=repair,
            layers="full",
            override=override,
            unsupported=collector.unsupported,
            dropped=collector.dropped,
            labels=collector.labels,
        )
        if record:
            metrics.observe_scan(outcome.timings_ms, outcome.counts, outcome.slm_status)
        request.state.audit.update(scan_fields(outcome))
        privacy_headers = {
            "x-harpo-risk": outcome.risk.value,
            "x-harpo-redactions": str(outcome.redactions),
            "x-harpo-mode": outcome.mode,
        }
        if outcome.blocked:
            for reason in outcome.reasons:
                if reason.level is Level.RED:
                    metrics.blocks.labels(reason.code).inc()
            raise GatewayError(
                403,
                "privacy_block",
                "Request blocked by privacy policy. See error.harpo.reasons.",
                style,
                extra=block_details(outcome, request.state.can_override),
                headers=privacy_headers,
                decision="blocked",
                risk="red",
            )
        collector.apply(outcome.texts)
        egress_started = time.perf_counter()
        if settings.policy.egress_verification == "full":
            # INV-01: whatever is about to leave is scanned once more, all of it, values and keys.
            leftover = await pipeline.residual(list(egress_strings(body, adapter)))
            if leftover:
                metrics.blocks.labels("egress_verification").inc()
                egress_reason = {
                    "code": "egress_verification",
                    "level": "red",
                    "message": "The sanitized request still contained detectable data, so it was not sent.",
                    "entity_type": None,
                    "count": sum(leftover.values()),
                    "overridable": False,
                }
                raise GatewayError(
                    403, "privacy_block", "Request blocked by privacy policy. See error.harpo.reasons.", style,
                    extra={"risk": "red", "overridable": False, "override_permitted": request.state.can_override,
                           "blocked_types": sorted(leftover), "reasons": [egress_reason]},
                    headers=privacy_headers, decision="blocked", risk="red",
                )  # fmt: skip
        egress_ms = round((time.perf_counter() - egress_started) * 1000, 2)
        request.state.audit.update(
            egress="verified" if settings.policy.egress_verification == "full" else "off", egress_ms=egress_ms
        )
        return Sanitized(body, upstream, stream, privacy_headers, outcome, egress_ms)

    async def forward(
        request: Request,
        style: Style,
        upstream: UpstreamSettings,
        body: dict[str, Any],
        stream: bool,
        privacy_headers: dict[str, str],
        risk: str,
        endpoint: str | None = None,
    ) -> Response:
        client: httpx.AsyncClient = app.state.clients[upstream.name]
        key: str | None = app.state.keys.get(upstream.name)
        headers = {
            "content-type": "application/json",
            "accept": request.headers.get("accept") or "application/json",
            "user-agent": f"harpo-redact/{__version__}",
        }
        headers.update(upstream.headers)  # static, non-secret (validated: never credentials or hop-by-hop)
        if style == "anthropic":
            url = f"{upstream.base_url}{endpoint or '/v1/messages'}"
            headers["anthropic-version"] = request.headers.get("anthropic-version") or "2023-06-01"
            beta = request.headers.get("anthropic-beta")
            if beta:
                headers["anthropic-beta"] = beta
        else:
            url = f"{upstream.base_url}/chat/completions"
        if key:
            headers.update(auth_headers(upstream, key))
        payload = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
        upstream_started = time.perf_counter()
        try:
            response = await client.send(
                client.build_request("POST", url, headers=headers, content=payload), stream=True
            )
        except httpx.TimeoutException:
            raise GatewayError(
                502, "upstream_error", "The provider did not respond in time.", style,
                headers=privacy_headers, decision="upstream_error", risk=risk,
            ) from None  # fmt: skip
        except httpx.HTTPError:
            raise GatewayError(
                502, "upstream_error", "The provider could not be reached.", style,
                headers=privacy_headers, decision="upstream_error", risk=risk,
            ) from None  # fmt: skip
        metrics.upstream_responses.labels(upstream.name, f"{response.status_code // 100}xx").inc()
        if 300 <= response.status_code < 400:  # never followed, never handed to the client
            await response.aclose()
            raise GatewayError(
                502, "upstream_error", "The provider answered with a redirect, which the gateway does not follow.",
                style, headers=privacy_headers, decision="upstream_error", risk=risk,
            )  # fmt: skip
        out_headers = {
            k: v
            for k, v in response.headers.items()
            if k.lower() in _FORWARDED_RESPONSE_HEADERS or k.lower().startswith(_FORWARDED_PREFIXES)
        }
        out_headers.update(privacy_headers)
        is_sse = response.headers.get("content-type", "").startswith("text/event-stream")
        response_scan = settings.policy.response_scan
        if response_scan != "off":
            out_headers["x-harpo-response-scan"] = "not_scanned_stream" if is_sse else response_scan
            request.state.audit["response_scan"] = out_headers["x-harpo-response-scan"]

        limit = upstream.max_response_bytes
        if stream and response.status_code == 200 and is_sse:

            async def relay() -> AsyncIterator[bytes]:
                completed = False
                sent = 0
                try:
                    async for chunk in response.aiter_bytes():
                        sent += len(chunk)
                        if sent > limit:
                            log.warning(
                                "upstream_stream_too_large",
                                extra={"fields": {"request_id": request.state.request_id, "limit": limit}},
                            )
                            break
                        yield chunk
                    else:
                        completed = True
                except httpx.HTTPError as exc:
                    log.warning(
                        "upstream_stream_interrupted",
                        extra={"fields": {"request_id": request.state.request_id, "error": type(exc).__name__}},
                    )
                finally:
                    await response.aclose()
                    finish_audit(
                        request, 200, "forwarded", risk,
                        upstream_status=200, stream_completed=completed,
                        upstream_ms=round((time.perf_counter() - upstream_started) * 1000, 2),
                    )  # fmt: skip

            return StreamingResponse(relay(), status_code=200, headers=out_headers)

        chunks: list[bytes] = []
        total = 0
        try:
            async for chunk in response.aiter_bytes():
                total += len(chunk)
                if total > limit:
                    raise GatewayError(
                        502, "upstream_error", "The provider response exceeded the gateway's size limit.", style,
                        headers=privacy_headers, decision="upstream_error", risk=risk,
                    )  # fmt: skip
                chunks.append(chunk)
            content = b"".join(chunks)
        except httpx.HTTPError:
            raise GatewayError(
                502, "upstream_error", "The provider connection failed mid-response.", style,
                headers=privacy_headers, decision="upstream_error", risk=risk,
            ) from None  # fmt: skip
        finally:
            await response.aclose()
        if response_scan != "off" and response.status_code == 200 and not is_sse:
            content, findings = await scan_response(app.state.pipeline, style, content, response_scan == "redact")
            out_headers["x-harpo-response-findings"] = str(sum(findings.values()))
            request.state.audit["response_findings"] = findings
        finish_audit(
            request, response.status_code, "forwarded", risk,
            upstream_status=response.status_code,
            upstream_ms=round((time.perf_counter() - upstream_started) * 1000, 2),
        )  # fmt: skip
        return Response(content=content, status_code=response.status_code, headers=out_headers)

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Response:
        return await proxy(request, "openai")

    @app.post("/v1/messages")
    async def messages(request: Request) -> Response:
        return await proxy(request, "anthropic")

    @app.post("/v1/messages/count_tokens")
    async def count_tokens(request: Request) -> Response:
        """Claude Code and the Anthropic SDK count tokens before sending: the same text, so the same redaction."""
        return await proxy(request, "anthropic", endpoint="/v1/messages/count_tokens")

    model_cache: dict[str, tuple[float, list[str]]] = {}
    model_locks: dict[str, asyncio.Lock] = {}

    async def upstream_models(upstream: UpstreamSettings) -> list[str]:
        """The provider's own model list, filtered by the upstream's patterns; cached 10 minutes (failures 1)."""
        hit = model_cache.get(upstream.name)
        if hit and time.monotonic() < hit[0]:
            return hit[1]
        lock = model_locks.setdefault(upstream.name, asyncio.Lock())
        async with lock:
            hit = model_cache.get(upstream.name)
            if hit and time.monotonic() < hit[0]:
                return hit[1]
            ids: list[str] = []
            ttl = 60.0
            key = app.state.keys.get(upstream.name)
            headers = {**upstream.headers, **(auth_headers(upstream, key) if key else {})}
            if upstream.style == "anthropic":
                headers["anthropic-version"] = "2023-06-01"
            try:
                response = await app.state.clients[upstream.name].get(
                    f"{api_root(upstream)}/models", headers=headers, timeout=10.0
                )
                raw = await response.aread()
                await response.aclose()
                if response.status_code == 200 and len(raw) <= 32_000_000:
                    entries = json.loads(raw).get("data") or []
                    ids = [
                        e["id"]
                        for e in entries[:20_000]
                        if isinstance(e, dict)
                        and isinstance(e.get("id"), str)
                        and _MODEL_ID_RE.fullmatch(e["id"])
                        and upstream.matches(e["id"])
                    ]
                    ttl = 600.0
            except (httpx.HTTPError, ValueError, AttributeError, TypeError):
                log.warning("upstream_models_unavailable", extra={"fields": {"upstream": upstream.name}})
            model_cache[upstream.name] = (time.monotonic() + ttl, ids)
            return ids

    @app.get("/v1/models")
    async def list_models(request: Request) -> dict[str, Any]:
        """What chat apps and SDKs list in their model pickers. Patterns (claude-*) cannot be listed, but
        upstreams with `list_models: upstream` (OpenRouter by default) add the provider's matching models."""
        style: Style = "anthropic" if "anthropic-version" in request.headers else "openai"
        authenticate(request, style)
        owners: dict[str, str] = {}
        for upstream in settings.upstreams:
            if upstream.style == style:
                for name in upstream.literal_models:
                    owners.setdefault(name, upstream.name)
        for upstream in settings.upstreams:
            if upstream.style == style and upstream.lists_upstream_models:
                for name in await upstream_models(upstream):
                    owners.setdefault(name, upstream.name)
        if style == "openai":
            return {
                "object": "list",
                "data": [{"id": m, "object": "model", "created": 0, "owned_by": o} for m, o in owners.items()],
            }
        data = [{"type": "model", "id": m, "display_name": m, "created_at": "1970-01-01T00:00:00Z"} for m in owners]
        return {
            "data": data,
            "has_more": False,
            "first_id": data[0]["id"] if data else None,
            "last_id": data[-1]["id"] if data else None,
        }

    def require_admin(request: Request) -> str:
        key_id = authenticate(request, "openai")
        if not getattr(request.state, "admin", False):
            raise GatewayError(403, "permission_error", "This needs an admin gateway key.", "openai")
        return key_id

    def redacted_config(cfg: Settings) -> dict[str, Any]:
        """The configuration as the console may show it: key hashes shortened, registry contents hidden."""
        data = cfg.model_dump(mode="json")
        for key in data.get("auth", {}).get("keys", []):
            key["sha256"] = str(key.get("sha256", ""))[:8] + "…"
        registry = data.get("detection", {}).get("registry", {})
        for name, value in list(registry.items()):
            if isinstance(value, list):
                registry[name] = f"<{len(value)} entries hidden>"
        if isinstance(data.get("policy", {}).get("allow_terms"), list):
            data["policy"]["allow_terms"] = f"<{len(data['policy']['allow_terms'])} entries hidden>"
        for custom in data.get("detection", {}).get("custom_types", []):  # their terms and patterns are what they hide
            for name in ("terms", "patterns"):
                if isinstance(custom.get(name), list):
                    custom[name] = f"<{len(custom[name])} entries hidden>"
        return data

    def restore_hidden(data: dict[str, Any]) -> None:
        """A masked value in a staged config means "unchanged": put the running value back before validating."""
        running = settings.model_dump(mode="json")
        hashes = {k["id"]: k["sha256"] for k in running.get("auth", {}).get("keys", [])}
        auth = data.get("auth")
        keys = auth.get("keys") if isinstance(auth, dict) else None
        for key in keys if isinstance(keys, list) else []:
            masked = isinstance(key, dict) and isinstance(key.get("sha256"), str) and key["sha256"].endswith("…")
            if masked and key.get("id") in hashes:
                key["sha256"] = hashes[key["id"]]
        detection = data.get("detection")
        registry = detection.get("registry") if isinstance(detection, dict) else None
        if isinstance(registry, dict):
            for name, value in list(registry.items()):
                if isinstance(value, str) and value.endswith("entries hidden>"):
                    registry[name] = running["detection"]["registry"].get(name, [])
        policy = data.get("policy")
        if (
            isinstance(policy, dict)
            and isinstance(policy.get("allow_terms"), str)
            and policy["allow_terms"].endswith("entries hidden>")
        ):
            policy["allow_terms"] = running["policy"].get("allow_terms", [])
        customs = detection.get("custom_types") if isinstance(detection, dict) else None
        known = {c["name"]: c for c in running.get("detection", {}).get("custom_types", [])}
        for custom in customs if isinstance(customs, list) else []:
            for name in ("terms", "patterns"):
                value = custom.get(name) if isinstance(custom, dict) else None
                if isinstance(value, str) and value.endswith("entries hidden>"):
                    custom[name] = known.get(custom.get("name"), {}).get(name, [])

    def yaml_line(text: str, path: list[Any]) -> int | None:
        """The line of a path in YAML text, so validation errors point somewhere."""
        try:
            node: Any = yaml.compose(text)
        except yaml.YAMLError:
            return None
        line = None
        for step in path:
            if isinstance(node, yaml.MappingNode):
                match = next((v for k, v in node.value if getattr(k, "value", None) == str(step)), None)
                if match is None:
                    break
                node = match
            elif isinstance(node, yaml.SequenceNode) and isinstance(step, int) and step < len(node.value):
                node = node.value[step]
            else:
                break
            line = node.start_mark.line + 1
        return line

    async def readiness() -> tuple[bool, dict[str, str]]:
        checks: dict[str, str] = {}
        ready = hasattr(app.state, "pipeline")
        if settings.detection.ner.enabled:
            ok = ready and app.state.pipeline.ner is not None
            checks["ner"] = "ok" if ok else "not_loaded"
            ready = ready and ok
        slm: SLMDetector | None = getattr(app.state, "slm", None)
        if slm is not None:
            reachable = await slm.ping(cache_seconds=2.0)
            checks["slm"] = "ok" if reachable else "unreachable"
            if settings.detection.slm.on_failure == "fail_closed":
                ready = ready and reachable
        missing = [u.name for u in settings.upstreams if u.api_key_env and not app.state.keys.get(u.name)]
        checks["upstream_keys"] = "ok" if not missing else "missing:" + ",".join(missing)
        if missing and settings.environment == "production":
            ready = False
        return ready, checks

    secret_rule_count = load_library().rule_count

    @app.get("/v1/system")
    async def system_view(request: Request) -> dict[str, Any]:
        require_admin(request)
        ok, checks = await readiness()
        effective = effective_settings()  # the configuration with the live policy laid over it
        ner = effective.detection.ner
        models = []
        for name in [ner.model, *ner.language_models.values()] if ner.enabled else []:
            try:
                meta = importlib.metadata.metadata(name)
                models.append({"name": name, "version": meta["Version"], "license": meta.get("License")})
            except importlib.metadata.PackageNotFoundError:
                models.append({"name": name, "version": None, "license": None})
        runner: WorkerRunner = app.state.doc_runner
        slm_cfg = settings.detection.slm
        registry = settings.detection.registry.model_dump()
        server = settings.server
        limits: tuple[str, ...] = ("max_body_bytes", "max_messages", "max_total_chars", "max_scan_ms")
        limits += ("max_decoded_bytes", "max_entities", "max_concurrent_scans")
        return {
            "version": __version__,
            "python": platform.python_version(),
            "environment": settings.environment,
            "uptime_s": int(time.time() - live.started),
            "workers": server.workers,
            "readiness": {"status": "ready" if ok else "not_ready", "checks": checks},
            "detection": {
                "secret_rules": secret_rule_count,
                "extra_secret_rules": max(0, app.state.pipeline.secret_rule_count - secret_rule_count),
                "keys": "always redacted",
                "custom_types": [
                    {"name": c.name, "action": c.action, "terms": len(c.terms), "patterns": len(c.patterns)}
                    for c in effective.detection.custom_types
                ],
                "phone_regions": settings.detection.phone_regions,
                "encoded_max_depth": settings.detection.encoded_max_depth,
                "library": library.describe(effective),
                "identifiers": effective.detection.identifiers.model_dump(mode="json"),
                "secrets": settings.detection.secrets.model_dump(mode="json"),
                "registry": {k: (len(v) if isinstance(v, list) else v) for k, v in registry.items()},
                "ner": {
                    "enabled": ner.enabled,
                    "model": ner.model,
                    "language_models": dict(ner.language_models),
                    "other_languages": ner.other_languages,
                    "propagate": ner.propagate,
                    "name_rules": ner.name_rules,
                    "precision_filter": ner.precision_filter,
                    "labels": {k: v.value for k, v in ner.labels.items()},
                    "models": models,
                },
                "slm": {
                    "enabled": slm_cfg.enabled,
                    "model": slm_cfg.model,
                    "endpoint": slm_cfg.base_url,
                    "timeout_ms": slm_cfg.timeout_ms,
                    "on_failure": slm_cfg.on_failure,
                    "max_concurrency": slm_cfg.max_concurrency,
                    "max_input_chars": slm_cfg.max_input_chars,
                    "digest_pinned": bool(slm_cfg.model_digest),
                    "reachable": checks.get("slm"),
                },
            },
            "documents": {
                **settings.documents.model_dump(mode="json"),
                "active": settings.documents.max_concurrent - runner.semaphore._value,
                "waiting": runner.waiting,
                "queue_capacity": runner.max_waiting,
            },
            "upstreams": [
                {
                    "name": u.name,
                    "style": u.style,
                    "base_url": u.base_url,
                    "models": u.models,
                    "key_env": u.api_key_env,
                    "key_present": bool(app.state.keys.get(u.name)),
                    "dialect": u.effective_dialect,
                    "auth_scheme": u.effective_auth_scheme,
                    "header_names": sorted(u.headers),
                    "list_models": "upstream" if u.lists_upstream_models else "configured",
                    **({"routing": u.openrouter.model_dump()} if u.effective_dialect == "openrouter" else {}),
                }
                for u in settings.upstreams
            ],
            "limits": {k: getattr(server, k) for k in limits},
        }

    @app.get("/v1/providers")
    async def providers_view(request: Request) -> dict[str, Any]:
        require_admin(request)
        traffic = live.snapshot(None)["upstreams"]
        idle = {"requests": 0, "errors": 0, "blocked": 0, "p50": None, "p95": None, "count": 0}
        return {
            "providers": [
                {
                    "name": u.name,
                    "style": u.style,
                    "base_url": u.base_url,
                    "models": u.models,
                    "key_env": u.api_key_env,
                    "key_present": bool(app.state.keys.get(u.name)),
                    "dialect": u.effective_dialect,
                    "auth_scheme": u.effective_auth_scheme,
                    "header_names": sorted(u.headers),
                    "list_models": "upstream" if u.lists_upstream_models else "configured",
                    **({"routing": u.openrouter.model_dump()} if u.effective_dialect == "openrouter" else {}),
                    "timeout_s": u.timeout_s,
                    "max_connections": u.max_connections,
                    "max_response_bytes": u.max_response_bytes,
                    "traffic": traffic.get(u.name, idle),
                }
                for u in settings.upstreams
            ]
        }

    @app.post("/v1/providers/{name}/check")
    async def provider_check(request: Request, name: str) -> dict[str, Any]:
        """A content-free connection test: list the provider's models with the configured key."""
        require_admin(request)
        upstream = next((u for u in settings.upstreams if u.name == name), None)
        if upstream is None:
            raise GatewayError(404, "not_found_error", "No upstream with that name.", "openai")
        key = app.state.keys.get(upstream.name)
        headers: dict[str, str] = dict(upstream.headers)
        if upstream.style == "anthropic":
            headers["anthropic-version"] = "2023-06-01"
        if key:
            headers.update(auth_headers(upstream, key))
        openrouter = upstream.effective_dialect == "openrouter"
        # OpenRouter lists models to anyone, so only its key endpoint shows whether the key is accepted.
        url = f"{api_root(upstream)}/key" if openrouter else f"{api_root(upstream)}/models"
        started = time.perf_counter()
        try:
            response = await app.state.clients[upstream.name].get(url, headers=headers, timeout=10.0)
        except httpx.HTTPError as exc:
            took = round((time.perf_counter() - started) * 1000, 1)
            return {"name": name, "reachable": False, "error": type(exc).__name__, "latency_ms": took}
        code = response.status_code
        account: dict[str, Any] | None = None
        if openrouter and code == 200:
            try:
                data = json.loads(await response.aread())["data"]
                # Spend and limits only: no key label, user, organization or workspace identifiers.
                keep = ("limit", "limit_remaining", "limit_reset", "usage", "usage_daily", "usage_monthly",
                        "is_free_tier", "expires_at", "allowed_data_regions")  # fmt: skip
                account = {k: data.get(k) for k in keep if k in data}
            except (ValueError, KeyError, TypeError):
                account = None
        await response.aclose()
        auth = "accepted" if 200 <= code < 300 else "rejected" if code in (401, 403) else "not confirmed"
        if not key and auth == "accepted":
            auth = "not needed"
        took = round((time.perf_counter() - started) * 1000, 1)
        result: dict[str, Any] = {"name": name, "reachable": True, "status": code, "latency_ms": took, "auth": auth}
        if openrouter:
            result["checked"] = "key endpoint"
        if account is not None:
            result["account"] = account
        return result

    @app.get("/v1/keys")
    async def keys_view(request: Request) -> dict[str, Any]:
        require_admin(request)
        usage, now = live.key_usage(), datetime.now(UTC)
        return {
            "auth_enabled": settings.auth.enabled,
            "override_policy": settings.policy.override,
            "keys": [
                {
                    "id": k.id,
                    "fingerprint": k.sha256[:8],
                    "admin": k.admin,
                    "can_override": k.can_override,
                    "expires_at": k.expires_at.isoformat() if k.expires_at else None,
                    "expired": bool(k.expires_at and now >= k.expires_at),
                    "requests_per_minute": k.requests_per_minute,
                    **usage.get(k.id, {"requests": 0, "last_seen": None}),
                }
                for k in settings.auth.keys
            ],
        }

    @app.post("/v1/keys/generate")
    async def key_generate(request: Request) -> JSONResponse:
        """A new key, shown once. Not stored: the config file stays the source of truth."""
        require_admin(request)
        spec = await read_json(request, "openai")
        key = KEY_PREFIX + secrets.token_urlsafe(32)
        try:
            entry = AuthKey(
                id=spec.get("id"),
                sha256=hashlib.sha256(key.encode()).hexdigest(),
                admin=bool(spec.get("admin")),
                can_override=bool(spec.get("can_override")),
                expires_at=spec.get("expires_at") or None,
                requests_per_minute=spec.get("requests_per_minute") or None,
            )
        except ValidationError as exc:
            first = exc.errors()[0]
            where = ".".join(str(x) for x in first["loc"])
            raise GatewayError(
                400, "invalid_request_error", f"Invalid key setting {where}: {first['msg']}.", "openai"
            ) from None
        if any(k.id == entry.id for k in settings.auth.keys):
            raise GatewayError(409, "conflict_error", "A key with that id already exists.", "openai")
        snippet = yaml.safe_dump([entry.model_dump(mode="json", exclude_none=True)], sort_keys=False)
        body = {"key": key, "sha256": entry.sha256, "yaml": snippet, "persisted": False}
        return JSONResponse(body, headers={"cache-control": "no-store"})

    @app.get("/v1/config/effective")
    async def config_effective(request: Request) -> dict[str, Any]:
        require_admin(request)
        data = redacted_config(effective_settings())
        return {"config": data, "yaml": yaml.safe_dump(data, sort_keys=False)}

    @app.post("/v1/config/validate")
    async def config_validate(request: Request) -> dict[str, Any]:
        """Validate a staged configuration. Nothing is saved or applied."""
        require_admin(request)
        payload = await read_json(request, "openai")
        text = payload.get("yaml")
        if not isinstance(text, str) or len(text) > 512_000:
            raise GatewayError(400, "invalid_request_error", 'Send {"yaml": "..."} (at most 512 kB).', "openai")
        try:
            data = yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            error = {
                "path": "",
                "line": mark.line + 1 if mark else None,
                "message": str(getattr(exc, "problem", "") or "invalid YAML"),
            }
            return {"valid": False, "saved": False, "errors": [error], "problems": []}
        if not isinstance(data, dict):
            error = {"path": "", "line": 1, "message": "the top level must be a mapping"}
            return {"valid": False, "saved": False, "errors": [error], "problems": []}
        restore_hidden(data)
        try:
            candidate = Settings.model_validate(data)
        except ValidationError as exc:
            errors = [
                {
                    "path": ".".join(str(x) for x in e["loc"]),
                    "line": yaml_line(text, list(e["loc"])),
                    "message": e["msg"],
                }
                for e in exc.errors()
            ]
            return {"valid": False, "saved": False, "errors": errors, "problems": []}
        running = yaml.safe_dump(redacted_config(settings), sort_keys=False).splitlines(keepends=True)
        staged = yaml.safe_dump(redacted_config(candidate), sort_keys=False).splitlines(keepends=True)
        problems = candidate.production_problems() if candidate.environment == "production" else []
        diff = "".join(difflib.unified_diff(running, staged, "running", "staged", n=2))
        return {"valid": True, "saved": False, "errors": [], "problems": problems, "diff": diff}

    # ------------------------------------------------------------------ live policy
    def effective_settings() -> Settings:
        """The configuration with the live policy laid over it: what new requests are scanned with."""
        current: Settings = app.state.pipeline.settings
        return current

    async def build_pipeline(effective: Settings) -> Pipeline:
        """A pipeline for a new policy, ready before it is swapped in. The loaded models are shared."""
        old: Pipeline = app.state.pipeline
        candidate = Pipeline(effective, ner=old.ner, slm=old.slm)
        await asyncio.to_thread(candidate.warmup)
        return candidate

    def parse_live(payload: dict[str, Any]) -> LivePolicy:
        unknown = sorted(set(payload) - {"entities", "custom_types", "detectors"})
        if unknown:
            raise GatewayError(400, "invalid_request_error", f"Unknown fields: {', '.join(unknown)}.", "openai")
        try:
            return LivePolicy.model_validate(payload)
        except ValidationError as exc:
            raise GatewayError(
                422, "invalid_request_error", "The policy is not valid.", "openai",
                extra={"errors": _validation_errors(exc)},
            ) from None  # fmt: skip

    def combined(candidate: LivePolicy) -> Settings:
        try:
            return live_policy.apply(settings, candidate)
        except ValueError as exc:
            raise GatewayError(
                422, "invalid_request_error", "The policy is not valid.", "openai",
                extra={"errors": _validation_errors(exc)},
            ) from None  # fmt: skip

    async def reload_live_policy() -> None:
        """Pick up a change to policy.live_file: another worker saved it, or someone edited it by hand."""
        path = settings.policy.live_file
        if not path or live_policy.file_state(path) == live_state.seen:
            return
        async with live_lock:
            seen = live_policy.file_state(path)
            if seen == live_state.seen:
                return
            try:
                policy = live_policy.load(path) if seen.exists else None
                pipeline = await build_pipeline(live_policy.apply(settings, policy))
            except ValueError as exc:
                errors = _validation_errors(exc)
                live_state.seen = seen
                live_state.error = "; ".join(
                    f"{e['path']}: {e['message']}" if e["path"] else e["message"] for e in errors
                )
                # Paths only: a message can quote a term from the file, and terms stay out of the logs.
                fields = {"file": path, "errors": [e["path"] for e in errors]}
                log.error("live_policy_invalid", extra={"fields": fields})
                return
            app.state.pipeline = pipeline
            live_state.policy, live_state.seen, live_state.error = policy, seen, None
            log.info("live_policy_applied", extra={"fields": {"source": "file", "file": path}})

    async def watch_live_policy() -> None:
        while True:
            await asyncio.sleep(live_policy.WATCH_INTERVAL_S)
            try:
                await reload_live_policy()
            except Exception:
                log.warning("live_policy_watch_failed")

    def live_view() -> dict[str, Any]:
        path = settings.policy.live_file
        view = live_policy.describe(settings, effective_settings(), live_state.policy, path)
        view["error"] = live_state.error
        return view

    @app.get("/v1/policy/live")
    async def policy_live_view(request: Request) -> dict[str, Any]:
        """The Policy editor's state: each type's action now and in the configuration, custom types, file."""
        require_admin(request)
        await reload_live_policy()
        return live_view()

    @app.put("/v1/policy/live")
    async def policy_live_save(request: Request) -> dict[str, Any]:
        """Save and apply a live policy: an action per type and the custom types. Keys stay redacted."""
        key_id = require_admin(request)
        candidate = parse_live(await read_json(request, "openai"))
        path = settings.policy.live_file
        ok, reason = live_policy.writable(path)
        if not ok or path is None:
            raise GatewayError(
                409, "live_policy_read_only", reason or "The live policy cannot be saved.", "openai",
                extra={"yaml": live_policy.to_yaml(candidate), "config_yaml": live_policy.config_snippet(candidate)},
            )  # fmt: skip
        effective = combined(candidate)
        async with live_lock:
            pipeline = await build_pipeline(effective)  # ready before anything is saved
            stamped = live_policy.stamp(candidate, key_id)
            try:
                seen = await asyncio.to_thread(live_policy.save, path, stamped)
            except OSError as exc:
                raise GatewayError(
                    409, "live_policy_read_only", f"The policy could not be saved ({exc.strerror or 'write failed'}).",
                    "openai",
                    extra={"yaml": live_policy.to_yaml(stamped), "config_yaml": live_policy.config_snippet(stamped)},
                ) from None  # fmt: skip
            previous = live_state.policy
            app.state.pipeline = pipeline
            live_state.policy, live_state.seen, live_state.error = stamped, seen, None
        audit({"event": "policy_changed", "key_id": key_id, "route": "/v1/policy/live",
               "changes": _policy_changes(previous, stamped)})  # fmt: skip
        log.info("live_policy_applied", extra={"fields": {"source": "console", "key_id": key_id}})
        return live_view()

    @app.delete("/v1/policy/live")
    async def policy_live_reset(request: Request) -> dict[str, Any]:
        """Remove the live policy: the configuration file alone decides again."""
        key_id = require_admin(request)
        path = settings.policy.live_file
        ok, reason = live_policy.writable(path)
        if not ok or path is None:
            raise GatewayError(409, "live_policy_read_only", reason or "The live policy cannot be changed.", "openai")
        async with live_lock:
            pipeline = await build_pipeline(settings)
            await asyncio.to_thread(live_policy.remove, path)
            previous = live_state.policy
            app.state.pipeline = pipeline
            live_state.policy, live_state.seen, live_state.error = None, live_policy.file_state(path), None
        audit({"event": "policy_reset", "key_id": key_id, "route": "/v1/policy/live",
               "changes": _policy_changes(previous, None)})  # fmt: skip
        return live_view()

    @app.post("/v1/policy/preview")
    async def policy_preview(request: Request) -> dict[str, Any]:
        """Run text through a policy that is not saved yet. Nothing is sent, saved or recorded."""
        require_admin(request)
        payload = await read_json(request, "openai")
        text = payload.get("text")
        if not isinstance(text, str) or not text or len(text) > 20_000:
            raise GatewayError(
                400, "invalid_request_error", 'Send {"text": "...", "policy": {...}} with 1 to 20,000 characters.'
            )
        old: Pipeline = app.state.pipeline
        pipeline = old
        draft = payload.get("policy")
        if draft is not None:
            if not isinstance(draft, dict):
                raise GatewayError(400, "invalid_request_error", "policy must be an object.")
            pipeline = Pipeline(combined(parse_live(draft)), ner=old.ner, slm=None)
        outcome = await asyncio.to_thread(pipeline.scan_sync, [text])
        return {
            "text": outcome.texts[0],
            "risk": outcome.risk.value,
            "blocked": outcome.blocked,
            "findings": [f.to_dict() for f in outcome.findings[0]],
            "reasons": [r.to_dict() for r in outcome.reasons],
            "counts": outcome.counts,
        }

    @app.post("/v1/egress/preview")
    async def egress_preview(request: Request) -> JSONResponse:
        """Exactly what the proxy would send for a request, without sending it: the same sanitize() path."""
        authenticate(request, "openai")
        payload = await read_json(request, "openai")
        style, body = payload.get("style"), payload.get("body")
        if style not in ("openai", "anthropic") or not isinstance(body, dict):  # API styles, not adapter names
            raise GatewayError(
                400, "invalid_request_error", 'Send {"style": "openai" | "anthropic", "body": {...}}.', "openai"
            )
        try:
            ready = await sanitize(request, style, body)
        except GatewayError as exc:
            refused = {
                "decision": exc.decision or "rejected",
                "status": exc.status,
                "message": str(exc.message),
                "details": exc.extra or {},
            }
            return JSONResponse(refused)
        up, out = ready.upstream, ready.outcome
        url = f"{up.base_url}/chat/completions" if style == "openai" else f"{up.base_url}/v1/messages"
        auth_name = "authorization" if style == "openai" else "x-api-key"
        return JSONResponse(
            {
                "decision": "would_forward",
                "style": style,
                "upstream": {"name": up.name, "url": url},
                "auth": {"header": auth_name, "from_env": up.api_key_env} if up.api_key_env else None,
                "body": ready.body,
                "risk": out.risk.value,
                "redactions": out.redactions,
                "counts": out.counts,
                "mode": out.mode,
                "reasons": [{"code": r.code, "level": r.level.value, "message": r.message} for r in out.reasons],
                "timings_ms": {**out.timings_ms, "egress": ready.egress_ms},
                "slm": out.slm_status,
                "egress_verification": settings.policy.egress_verification,
            }
        )

    @app.post("/v1/selftest")
    async def selftest(request: Request) -> dict[str, Any]:
        """Real canary checks of the invariants through the live sanitize path. Nothing is sent or recorded."""
        require_admin(request)
        canaries = ("selftest.canary@leak-test.example", "4111 1111 1111 1111", "NL91ABNA0417164300")
        key_canary = "AKIAZ4X7Q2LMWN3RT5PJ"

        def model_for(style: str) -> str | None:
            for u in settings.upstreams:
                if u.style == style and u.models:
                    return re.sub(r"[*?]", "x", re.sub(r"\[.*?\]", "x", u.models[0]))
            return None

        def probe(headers: dict[str, str] | None = None) -> Request:
            scope: dict[str, Any] = {
                "type": "http",
                "method": "POST",
                "path": "/v1/selftest",
                "query_string": b"",
                "headers": [(k.encode(), v.encode()) for k, v in (headers or {}).items()],
            }
            req = Request(scope)
            req.state.audit, req.state.can_override, req.state.admin = {}, True, True
            return req

        async def attempt(body: dict[str, Any], headers: dict[str, str] | None = None) -> tuple[str | None, int | None]:
            try:
                ready = await sanitize(probe(headers), "openai", body, record=False)
                return json.dumps(ready.body, ensure_ascii=False), None
            except GatewayError as exc:
                return None, exc.status

        results: list[dict[str, str]] = []
        model = model_for("openai")
        if model is None:
            results.append(
                {"id": "INV-01", "status": "skipped", "detail": "no OpenAI-compatible upstream to test against"}
            )
        else:
            sent, status = await attempt(
                {"model": model, "messages": [{"role": "user", "content": "Mail " + ", ".join(canaries)}]}
            )
            ok = sent is not None and not any(c in sent for c in canaries)
            detail = "canary email, card and IBAN replaced before egress" if ok else f"request refused ({status})"
            results.append({"id": "INV-01", "status": "pass" if ok or status == 403 else "fail", "detail": detail})
            sent, status = await attempt(
                {"model": model, "messages": [{"role": "user", "content": f"key {key_canary}"}]},
                {"x-harpo-override": "true"},
            )
            ok = (sent is not None and key_canary not in sent and "[SECRET" in sent) or status == 403
            detail = "an override sent the secret as a placeholder" if sent else "the block held"
            results.append({"id": "INV-06", "status": "pass" if ok else "fail", "detail": detail})
            sent, status = await attempt(
                {"model": model, "messages": [{"role": "user", "content": f"deploy {key_canary}"}]}
            )
            ok = sent is not None and key_canary not in sent and "[SECRET" in sent
            detail = (
                "a key became a placeholder and the request went on" if ok
                else f"the request was refused ({status})" if status else "the key was not replaced"
            )  # fmt: skip
            results.append({"id": "INV-11", "status": "pass" if ok else "fail", "detail": detail})
            sent, status = await attempt(
                {"model": model, "messages": [{"role": "user", "content": "hi", "x_selftest": canaries[0]}]}
            )
            ok = status == 400 or (sent is not None and canaries[0] not in sent)
            detail = "unknown field refused" if status == 400 else "unknown field scanned as text"
            results.append({"id": "INV-08", "status": "pass" if ok else "fail", "detail": detail})
            image = {"type": "image_url", "image_url": {"url": f"https://img.example/{canaries[0]}.png"}}
            parts = [{"type": "text", "text": "look"}, image]
            sent, status = await attempt({"model": model, "messages": [{"role": "user", "content": parts}]})
            ok = status == 403 or (sent is not None and "img.example" not in sent)
            results.append(
                {
                    "id": "INV-04",
                    "status": "pass" if ok else "fail",
                    "detail": "image blocked" if status == 403 else "image dropped with a marker",
                }
            )
            results.append(
                {
                    "id": "INV-10",
                    "status": results[-1]["status"],
                    "detail": "no OCR path: an image is never read, so it never passes",
                }
            )
        adapters_ok = all(a.surfaces for a in ADAPTERS.values())
        results.append(
            {
                "id": "INV-07",
                "status": "pass" if adapters_ok else "fail",
                "detail": f"{len(ADAPTERS)} adapters declare their surfaces",
            }
        )
        if settings.documents.enabled:
            try:
                doc = await redact_document(
                    app.state.pipeline,
                    settings.documents,
                    app.state.doc_runner,
                    f"Contact {canaries[0]} today.".encode(),
                    "selftest.txt",
                    None,
                    mode=None,
                    context_repair=None,
                    override=False,
                    want_file=True,
                )
                ok = doc.data is not None and canaries[0].encode() not in doc.data
                results.append(
                    {
                        "id": "INV-09",
                        "status": "pass" if ok else "fail",
                        "detail": "a text document was redacted and verified",
                    }
                )
            except DocumentError as exc:
                results.append({"id": "INV-09", "status": "fail", "detail": f"document check failed: {exc.code}"})
        passed = all(r["status"] != "fail" for r in results)
        return {"ran_at": datetime.now(UTC).isoformat(), "results": results, "passed": passed}

    @app.get("/v1/setup/presets")
    async def setup_presets(request: Request) -> dict[str, Any]:
        """Provider presets for the setup wizard: the same table `harpo init` uses. No secrets."""
        require_admin(request)
        return {"providers": [
            {"id": pid, "style": style, "base_url": url, "key_env": env, "models": models,
             "companions": [{"name": n, "style": st, "base_url": u, "key_env": e, "models": m}
                            for n, st, u, e, m in COMPANIONS.get(pid, [])]}
            for pid, (style, url, env, models) in PROVIDERS.items()]}  # fmt: skip

    @app.get("/v1/config/analysis")
    async def config_analysis(request: Request) -> dict[str, Any]:
        """Concrete hardening findings for the running configuration, by level, each with its setting."""
        require_admin(request)
        findings = analyze(effective_settings())
        counts = {lvl: sum(f["level"] == lvl for f in findings) for lvl in ("required", "recommended", "info")}
        return {"findings": findings, "counts": counts}

    @app.get("/v1/diagnostics")
    async def diagnostics(request: Request) -> dict[str, Any]:
        """A bundle for issue reports. Built only from content-free sources; it says what it includes and excludes."""
        require_admin(request)
        snap = live.snapshot(None)
        keep = (
            "uptime_s",
            "window_s",
            "totals",
            "by_type",
            "by_reason",
            "latency_ms",
            "stages",
            "upstreams",
            "documents",
        )
        return {
            "kind": "harpo.diagnostics",
            "schema": 1,
            "generated_at": datetime.now(UTC).isoformat(),
            "includes": [
                "gateway version, runtime and readiness checks",
                "effective configuration (key hashes, and every term and pattern, reduced to counts)",
                "configuration analysis",
                "aggregate counters and latency percentiles",
                "adapter surface declarations",
            ],
            "excludes": [
                "prompts and responses",
                "documents",
                "request records",
                "gateway keys and their hashes",
                "provider keys",
                "protected terms",
                "custom type terms and patterns",
            ],
            "system": await system_view(request),
            "config": (await config_effective(request))["config"],
            "analysis": analyze(settings),
            "stats": {k: snap[k] for k in keep if k in snap},
            "adapters": {name: adapter.describe() for name, adapter in ADAPTERS.items()},
        }

    monitor = PostureMonitor()
    app.state.posture = monitor

    async def posture_conditions() -> list[dict[str, Any]]:
        """Actionable states only. Each condition says what is wrong and where to act. No request content."""
        out: list[dict[str, Any]] = []

        def add(cid: str, severity: str, subsystem: str, title: str, detail: str, action: str) -> None:
            out.append(
                {
                    "id": cid,
                    "severity": severity,
                    "subsystem": subsystem,
                    "title": title,
                    "detail": detail,
                    "action": action,
                }
            )

        if settings.policy.egress_verification != "full":
            add(
                "egress-off",
                "critical",
                "egress verification",
                "Egress verification is off",
                "Sanitized requests are not scanned again before they leave.",
                "configuration",
            )
        slm = app.state.slm
        if slm is not None and not await slm.ping(cache_seconds=10.0):
            closed = settings.detection.slm.on_failure == "fail_closed"
            add(
                "slm-down",
                "critical" if closed else "warning",
                "local SLM",
                "Local SLM unavailable",
                "Requests are refused until it is back."
                if closed
                else "Deterministic layers and NER still run; requests are marked degraded.",
                "detection",
            )
        for u in settings.upstreams:
            if u.api_key_env and not os.environ.get(u.api_key_env):
                add(
                    f"key-missing-{u.name}",
                    "warning",
                    "upstreams",
                    f"{u.name}: provider key not set",
                    f"{u.api_key_env} is not set on the gateway host.",
                    "providers",
                )
        recent = live.window(900)
        per: dict[str, list[int]] = {}
        for e in recent:
            if e.get("upstream"):
                c = per.setdefault(str(e["upstream"]), [0, 0])
                c[0] += 1
                c[1] += e.get("decision") == "upstream_error"
        for name, (n, err) in per.items():
            if n >= 5 and err / n >= 0.2:
                add(
                    f"provider-errors-{name}",
                    "warning",
                    "upstreams",
                    f"{name}: {err} of {n} requests failed",
                    "Provider errors in the last 15 minutes.",
                    "providers",
                )
        held = sum("egress_verification" in (e.get("reasons") or []) for e in recent)
        if held:
            add(
                "egress-held",
                "warning",
                "egress verification",
                f"Egress verification held back {held} request(s)",
                "A protected value survived redaction and was stopped at the boundary.",
                "activity?decision=blocked",
            )
        budget = sum("scan_budget" in (e.get("reasons") or []) for e in recent)
        if budget:
            add(
                "scan-budget",
                "warning",
                "inspection budgets",
                f"{budget} request(s) exceeded an inspection budget",
                "Oversized or hostile inputs are refused; see the server limits.",
                "configuration",
            )
        decided = [e for e in recent if e.get("decision") in ("forwarded", "blocked")]
        blocked = sum(e.get("decision") == "blocked" for e in decided)
        if len(decided) >= 10 and blocked / len(decided) >= 0.5:
            add(
                "block-rate",
                "info",
                "policy",
                f"{blocked} of {len(decided)} requests blocked",
                "A high block rate in the last 15 minutes. It may be correct: check the reasons.",
                "activity?decision=blocked",
            )
        found = sum(bool(e.get("response_findings")) for e in recent)
        if found:
            add(
                "response-findings",
                "info",
                "response scanning",
                f"{found} provider answer(s) contained findings",
                "Non-streamed answers with secrets or identifiers in the last 15 minutes.",
                "activity",
            )
        now = datetime.now(UTC)
        for k in settings.auth.keys:
            if k.expires_at and (left := (k.expires_at - now).total_seconds()) < 7 * 86400:
                add(
                    f"key-expiry-{k.id}",
                    "info" if left <= 0 else "warning",
                    "access",
                    f"Key {k.id} {'has expired' if left <= 0 else 'expires within 7 days'}",
                    "Generate a replacement and update your clients.",
                    "access",
                )
        for f in analyze(settings):
            if f["level"] == "required" and f["id"] != "egress-off":
                add(f"config-{f['id']}", "critical", "configuration", f["title"], f["detail"], "configuration")
        return out

    async def posture_loop() -> None:
        while True:
            try:
                monitor.update(await posture_conditions())
            except Exception:
                log.debug("posture evaluation failed", exc_info=True)
            await asyncio.sleep(15)

    @app.get("/v1/attention")
    async def attention(request: Request) -> dict[str, Any]:
        """Actionable system states and the posture timeline. Admin only; content-free."""
        require_admin(request)
        monitor.update(await posture_conditions())
        return monitor.view()

    @app.get("/v1/events")
    async def events(request: Request) -> StreamingResponse:
        """A server-sent event stream of the same content-free records the console shows, as they happen."""
        key_id = authenticate(request, "openai")
        everyone = bool(getattr(request.state, "admin", False))

        async def stream() -> AsyncIterator[bytes]:
            last, posture_seen, beat = live.seq, len(monitor.timeline), time.monotonic()
            yield b"retry: 3000\n\n"
            while not await request.is_disconnected():
                for e in live.since(last, None if everyone else key_id):
                    last = e["seq"]
                    yield f"event: request\ndata: {json.dumps(e)}\n\n".encode()
                if everyone and len(monitor.timeline) != posture_seen:
                    posture_seen = len(monitor.timeline)
                    yield f"event: posture\ndata: {json.dumps(monitor.timeline[-1])}\n\n".encode()
                if time.monotonic() - beat > 15:
                    beat = time.monotonic()
                    yield b": keep-alive\n\n"
                await asyncio.sleep(0.5)

        return StreamingResponse(
            stream(), media_type="text/event-stream", headers={"cache-control": "no-store", "x-accel-buffering": "no"}
        )

    @app.post("/v1/lab/detect")
    async def lab_detect(request: Request) -> dict[str, Any]:
        """One sample through the detection stages. Transient: nothing is stored, logged or counted."""
        authenticate(request, "openai")
        try:
            body = json.loads(await request.body() or b"{}")
        except ValueError as exc:
            raise GatewayError(400, "invalid_request_error", "Send a JSON object.", "openai") from exc
        text = body.get("text") if isinstance(body, dict) else None
        if not isinstance(text, str) or not text.strip() or len(text) > 20_000:
            raise GatewayError(400, "invalid_request_error", 'Send {"text": "..."}, up to 20,000 characters.', "openai")
        return await asyncio.to_thread(lab_run, app.state.pipeline, text)

    @app.post("/v1/selftest/suites")
    async def selftest_suites(request: Request) -> dict[str, Any]:
        """Self-test by subsystem; each suite says if it tests local logic, a live dependency or configuration."""
        require_admin(request)
        try:
            body = json.loads(await request.body() or b"{}")
        except ValueError as exc:
            raise GatewayError(400, "invalid_request_error", "Send a JSON object.", "openai") from exc
        wanted = set(body.get("suites") or []) if isinstance(body, dict) else set()
        pipeline = app.state.pipeline
        suites: list[dict[str, Any]] = []

        def outcome(name: str, ok: bool | None, detail: str) -> dict[str, Any]:
            return {"name": name, "status": "skip" if ok is None else "pass" if ok else "fail", "detail": detail}

        async def run(sid: str, name: str, kind: str, fn: Any) -> None:
            if wanted and sid not in wanted:
                return
            started = time.perf_counter()
            try:
                tests = await fn()
            except Exception as exc:
                tests = [outcome("suite ran", False, f"failed: {type(exc).__name__}")]
            states = {t["status"] for t in tests}
            status = "fail" if "fail" in states else "skip" if states <= {"skip"} else "pass"
            suites.append(
                {
                    "id": sid,
                    "name": name,
                    "kind": kind,
                    "status": status,
                    "tests": tests,
                    "ms": round((time.perf_counter() - started) * 1000, 1),
                }
            )

        async def gateway_suite() -> list[dict[str, Any]]:
            sysv = await system_view(request)
            checks = sysv["readiness"]["checks"]
            rules = sysv["detection"]["secret_rules"]
            return [outcome(f"readiness: {k.replace('_', ' ')}", v == "ok", str(v)) for k, v in checks.items()] + [
                outcome("secret rules loaded", rules > 0, f"{rules} rules"),
                outcome(
                    "egress verification enabled",
                    settings.policy.egress_verification == "full",
                    settings.policy.egress_verification,
                ),
            ]

        def survives(text: str, value: str) -> tuple[bool, str]:
            out = pipeline.scan_sync([text])
            kinds = sorted({str(getattr(f.type, "value", f.type)) for f in out.findings[0]})
            return value in out.texts[0], ", ".join(kinds) or "nothing found"

        async def detection_suite() -> list[dict[str, Any]]:
            b64 = base64.b64encode(b"jane.doe@leak-test.example").decode()
            cases = [
                ("email", "Mail jane.doe@leak-test.example", "jane.doe@leak-test.example"),
                ("payment card (Luhn)", "Card 4111 1111 1111 1111", "4111 1111 1111 1111"),
                ("IBAN (mod-97)", "IBAN NL91ABNA0417164300", "NL91ABNA0417164300"),
                ("phone (libphonenumber)", "Call +31 20 794 6095", "+31 20 794 6095"),
                ("base64-encoded email", f"payload {b64}", b64),
                ("escaped email", "jane.doe%40leak-test.example", "jane.doe%40leak-test.example"),
            ]
            results = []
            for name, text, value in cases:
                leaked, kinds = await asyncio.to_thread(survives, text, value)
                results.append(outcome(name, not leaked, f"redacted as {kinds}" if not leaked else "value survived"))
            return results

        async def secrets_suite() -> list[dict[str, Any]]:
            body64 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"
            pem = f"-----BEGIN PRIVATE KEY-----\n{body64}\n-----END PRIVATE KEY-----"
            results = []
            for name, text, value in (
                ("cloud access key", "deploy with AKIAZ4X7Q2LMWN3RT5PJ", "AKIAZ4X7Q2LMWN3RT5PJ"),
                ("private key block", pem, body64),
            ):
                leaked, kinds = await asyncio.to_thread(survives, text, value)
                results.append(outcome(name, not leaked, f"caught as {kinds}" if not leaked else "value survived"))
            return results

        live_results: list[dict[str, Any]] = []

        async def canaries() -> list[dict[str, Any]]:
            if not live_results:
                live_results.extend((await selftest(request))["results"])
            return live_results

        async def egress_suite() -> list[dict[str, Any]]:
            return [
                outcome(f"{r['id']}: {r['detail']}", r["status"] == "pass", r["status"])
                for r in await canaries()
                if r["id"] not in ("INV-04", "INV-07", "INV-08")
            ]

        async def adapters_suite() -> list[dict[str, Any]]:
            return [
                outcome(f"{r['id']}: {r['detail']}", r["status"] == "pass", r["status"])
                for r in await canaries()
                if r["id"] in ("INV-04", "INV-07", "INV-08")
            ]

        async def headers_suite() -> list[dict[str, Any]]:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://selftest.local") as client:
                r = await client.get("/healthz")
                page = await client.get("/console/") if settings.server.console else None
            h = r.headers
            out = [
                outcome(
                    "X-Frame-Options: DENY", h.get("x-frame-options") == "DENY", h.get("x-frame-options", "missing")
                ),
                outcome(
                    "X-Content-Type-Options: nosniff",
                    h.get("x-content-type-options") == "nosniff",
                    h.get("x-content-type-options", "missing"),
                ),
                outcome(
                    "Referrer-Policy: no-referrer",
                    h.get("referrer-policy") == "no-referrer",
                    h.get("referrer-policy", "missing"),
                ),
                outcome(
                    "Cross-Origin-Opener-Policy: same-origin",
                    h.get("cross-origin-opener-policy") == "same-origin",
                    h.get("cross-origin-opener-policy", "missing"),
                ),
            ]
            if page is not None:
                csp = page.headers.get("content-security-policy", "")
                out.append(
                    outcome(
                        "console CSP: scripts from self only, nothing unsafe",
                        "script-src 'self'" in csp and "unsafe" not in csp,
                        csp[:80] or "missing",
                    )
                )
            return out

        async def configuration_suite() -> list[dict[str, Any]]:
            found = analyze(settings)
            required = [f["title"] for f in found if f["level"] == "required"]
            recommended = sum(f["level"] == "recommended" for f in found)
            return [
                outcome("no required findings", not required, "; ".join(required) or "none"),
                outcome(
                    "recommended hardening",
                    None if recommended else True,
                    f"{recommended} recommendation(s): see Configuration" if recommended else "none",
                ),
            ]

        async def documents_suite() -> list[dict[str, Any]]:
            if not settings.documents.enabled:
                return [outcome("document worker", None, "documents are off")]
            started = time.perf_counter()
            result = await redact_document(
                pipeline,
                settings.documents,
                app.state.doc_runner,
                b"Contact jane.doe@leak-test.example about the renewal.\n",
                "selftest.txt",
                "text/plain",
                mode=None,
                context_repair=None,
                override=False,
                want_file=True,
            )
            took = round((time.perf_counter() - started) * 1000)
            clean = b"jane.doe@leak-test.example" not in (result.data or b"")
            return [
                outcome(
                    "isolated worker parse, redact, rebuild and verify",
                    clean,
                    f"text file released in {took} ms" if clean else "canary survived",
                )
            ]

        async def providers_suite() -> list[dict[str, Any]]:
            out = []
            for u in settings.upstreams:
                r = await provider_check(request, u.name)
                ok = bool(r.get("reachable")) and r.get("auth") != "rejected"
                out.append(
                    outcome(
                        u.name,
                        ok,
                        f"HTTP {r.get('status')} · key {r.get('auth')}"
                        if r.get("reachable")
                        else f"unreachable: {r.get('error') or 'no answer'}",
                    )
                )
            return out or [outcome("providers", None, "none configured")]

        async def slm_suite() -> list[dict[str, Any]]:
            slm = app.state.slm
            if slm is None:
                return [outcome("local model", None, "not configured")]
            ok = await slm.ping(cache_seconds=0)
            pinned = bool(settings.detection.slm.model_digest)
            return [
                outcome(
                    "reachable and trusted", ok, settings.detection.slm.model if ok else "unreachable or untrusted"
                ),
                outcome("model digest pinned", True if pinned else None, "pinned" if pinned else "not pinned"),
            ]

        await run("gateway", "Gateway", "config", gateway_suite)
        await run("detection", "Detection", "local", detection_suite)
        await run("secrets", "Secrets", "local", secrets_suite)
        await run("egress", "Egress", "local", egress_suite)
        await run("adapters", "Adapters", "local", adapters_suite)
        await run("headers", "Security headers", "local", headers_suite)
        await run("configuration", "Configuration", "config", configuration_suite)
        await run("documents", "Documents", "live", documents_suite)
        await run("providers", "Providers", "live", providers_suite)
        await run("slm", "Local SLM", "live", slm_suite)
        ran = [x for x in suites if x["status"] != "skip"]
        return {
            "ran_at": datetime.now(UTC).isoformat(),
            "suites": suites,
            "passed": all(x["status"] == "pass" for x in ran),
        }

    @app.get("/v1/stats")
    async def stats_view(request: Request) -> dict[str, Any]:
        """Content-free activity for the console. Admin keys (and a gateway without auth) see every key."""
        key_id = authenticate(request, "openai")
        everyone = bool(getattr(request.state, "admin", False))
        try:
            recent_n = max(1, min(500, int(request.query_params.get("recent", "60"))))
        except ValueError:
            recent_n = 60
        snap = live.snapshot(None if everyone else key_id, recent_n)
        ner = settings.detection.ner
        snap.update(
            version=__version__,
            scope="all" if everyone else "key",
            layers={
                "deterministic": True,
                "secrets": True,
                "ner": {
                    "enabled": ner.enabled,
                    "languages": ["en", *sorted(k for k in ner.language_models if k != "other")],
                },
                "slm": {"enabled": settings.detection.slm.enabled, "model": settings.detection.slm.model},
                "egress_verification": settings.policy.egress_verification,
                "response_scan": settings.policy.response_scan,
                "documents": settings.documents.enabled,
            },
        )
        return snap

    # The last middleware added is the outermost: GatewayMiddleware wraps the
    # host check so even its 400s carry request ids and security headers.
    if settings.server.allowed_hosts != ["*"]:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.server.allowed_hosts)
    app.add_middleware(
        GatewayMiddleware,
        max_body_bytes=settings.server.max_body_bytes,
        hsts=settings.server.hsts,
        metrics=metrics,
        route_limits=route_limits,
    )
    return app


def app_from_env() -> FastAPI:
    """Uvicorn factory: settings come from $HARPO_CONFIG and HARPO_* variables.

    Called once per worker process, so logging is configured here as well.
    """
    from .observability import configure_logging

    settings = load_settings()
    configure_logging(settings.logging.level)
    return create_app(settings)
