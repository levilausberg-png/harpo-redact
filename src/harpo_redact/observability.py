"""Content-free JSON logging, the audit trail, and Prometheus metrics.

Nothing in this module ever receives request text. Callers pass counts, codes
and timings only; the log-hygiene tests seed identifiers into requests and
assert that no log record contains them.
"""

from __future__ import annotations

import json
import logging
import sys
import time
import traceback
from typing import Any

from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest

AUDIT_LOGGER = "harpo.audit"
APP_LOGGER = "harpo.gateway"

_RESERVED = set(logging.LogRecord("", 0, "", 0, "", None, None).__dict__) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    """One JSON object per line. Extra fields come from ``extra={"fields": {...}}``."""

    def format(self, record: logging.LogRecord) -> str:
        out: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            out.update(fields)
        if record.exc_info and record.exc_info[0] is not None:
            out["error"] = describe_exception(record.exc_info[1])
        return json.dumps(out, ensure_ascii=False, default=str)


def describe_exception(exc: BaseException | None) -> dict[str, Any]:
    """Exception type and stack frames, without the message.

    Exception messages can quote input (a KeyError on a user-supplied key, a
    decode error with a snippet), so they are never logged.
    """
    if exc is None:
        return {}
    frames = [f"{f.filename.rsplit('/', 1)[-1]}:{f.lineno}:{f.name}" for f in traceback.extract_tb(exc.__traceback__)]
    return {"type": type(exc).__name__, "frames": frames[-8:]}


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    # httpx/httpcore log URLs at INFO and headers at DEBUG; uvicorn's access log
    # is disabled at the server level. Keep third parties quiet.
    for name in ("httpx", "httpcore", "hpack", "urllib3", "asyncio"):
        logging.getLogger(name).setLevel(logging.WARNING)
    for name in ("uvicorn", "uvicorn.error"):
        lg = logging.getLogger(name)
        lg.handlers[:] = []
        lg.propagate = True
    access = logging.getLogger("uvicorn.access")
    access.handlers[:] = []
    access.propagate = False
    access.disabled = True


def audit(fields: dict[str, Any]) -> None:
    logging.getLogger(AUDIT_LOGGER).info("request", extra={"fields": fields})


class Metrics:
    """Per-app registry so tests can build many apps in one process."""

    def __init__(self) -> None:
        self.registry = CollectorRegistry(auto_describe=True)
        self.requests = Counter(
            "harpo_requests_total",
            "Requests by route, decision and risk level",
            ["route", "decision", "risk"],
            registry=self.registry,
        )
        self.redactions = Counter(
            "harpo_redactions_total", "Redacted values by entity type", ["entity_type"], registry=self.registry
        )
        self.blocks = Counter(
            "harpo_blocks_total", "Blocked requests by reason code", ["reason"], registry=self.registry
        )
        self.stage_seconds = Histogram(
            "harpo_stage_seconds",
            "Time spent per pipeline stage",
            ["stage"],
            buckets=(0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
            registry=self.registry,
        )
        self.upstream_responses = Counter(
            "harpo_upstream_responses_total",
            "Provider responses by upstream and status class",
            ["upstream", "status_class"],
            registry=self.registry,
        )
        self.slm_outcomes = Counter(
            "harpo_slm_outcomes_total", "Local SLM layer outcomes", ["status"], registry=self.registry
        )

    def observe_scan(self, timings_ms: dict[str, float], counts: dict[str, int], slm_status: str) -> None:
        for stage, value in timings_ms.items():
            self.stage_seconds.labels(stage).observe(value / 1000)
        for etype, n in counts.items():
            self.redactions.labels(etype).inc(n)
        if slm_status not in ("disabled",):
            self.slm_outcomes.labels(slm_status).inc()

    def render(self) -> bytes:
        return generate_latest(self.registry)
