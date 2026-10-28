"""Static security analysis of the effective configuration: concrete findings with the exact setting, never a score.

Levels: "required" (a protection is off where it matters), "recommended" (hardening with a clear benefit),
"info" (worth knowing, often fine for a local demo).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from .config import Settings

_ORDER = {"required": 0, "recommended": 1, "info": 2}
_LOOPBACK = ("127.0.0.1", "localhost", "::1")


def analyze(settings: Settings, now: datetime | None = None) -> list[dict[str, Any]]:
    now = now or datetime.now(UTC)
    out: list[dict[str, Any]] = []

    def add(level: str, fid: str, title: str, detail: str, setting: str, current: Any, suggested: Any = None,
            invariant: str | None = None) -> None:  # fmt: skip
        out.append({"id": fid, "level": level, "title": title, "detail": detail, "setting": setting, "current": current,
                    "suggested": suggested, "invariant": invariant})  # fmt: skip

    p, s, d = settings.policy, settings.server, settings.detection
    local = s.host in _LOOPBACK
    if not settings.auth.enabled:
        add("info" if local else "required", "auth-off", "Authentication is off",
            "Anyone who can reach the gateway can use it and its control plane."
            + (" It listens on this machine only, which suits a local demo." if local else ""),
            "auth.enabled", False, True)  # fmt: skip
    if p.egress_verification != "full":
        add("required", "egress-off", "Egress verification is off",
            "The sanitized request is not scanned again before it leaves.", "policy.egress_verification",
            p.egress_verification, "full", "INV-01")  # fmt: skip
    if p.unknown_fields != "reject":
        add("recommended", "unknown-pass", "Undeclared request fields are scanned, not refused",
            "Fields an adapter does not declare cross after a text scan instead of being refused with their path.",
            "policy.unknown_fields", p.unknown_fields, "reject", "INV-08")  # fmt: skip
    if p.remote_mcp != "block":
        add("recommended", "remote-mcp", "Remote MCP servers are allowed",
            "The provider may call the configured remote tools with your token; that traffic never passes the gateway.",
            "policy.remote_mcp", p.remote_mcp, "block", "INV-04")  # fmt: skip
    if p.unsupported_content != "block":
        add("info", "unsupported-drop", "Images and audio are dropped, not refused",
            "Requests continue without them and carry a visible marker.", "policy.unsupported_content",
            p.unsupported_content, "block", "INV-04")  # fmt: skip
    if p.response_scan == "off":
        add("info", "response-scan-off", "Provider answers are not scanned",
            "report counts secrets and identifiers in non-streamed answers; redact removes them.",
            "policy.response_scan", "off", "report")  # fmt: skip
    if "*" in (s.allowed_hosts or []) and not local:
        add(
            "recommended",
            "hosts-any",
            "Any Host header is accepted",
            "Restrict allowed_hosts to the names your clients use.",
            "server.allowed_hosts",
            ["*"],
            ["gateway.internal"],
        )
    if not s.tls_certfile and not local:
        add("recommended", "tls-off", "No TLS on a network listener",
            "Terminate TLS here or in front of the gateway: prompts and gateway keys travel on this connection.",
            "server.tls_certfile", None, "a certificate path")  # fmt: skip
    if str(settings.logging.level).upper() == "DEBUG":
        add(
            "recommended",
            "debug-logs",
            "Debug logging",
            "Logs stay content-free, but debug volume makes them harder to review.",
            "logging.level",
            "DEBUG",
            "INFO",
        )
    if not d.ner.enabled:
        add(
            "recommended",
            "ner-off",
            "Named-entity detection is off",
            "Names, places and organizations are found by rules only.",
            "detection.ner.enabled",
            False,
            True,
        )
    elif not d.ner.language_models:
        add("info", "ner-english", "NER has English models only",
            "Other languages are read by the English model (docs/LEAKBENCH.md measures the effect).",
            "detection.ner.language_models", {}, {"de": "de_core_news_sm", "other": "xx_ent_wiki_sm"})  # fmt: skip
    if d.slm.enabled:
        if d.slm.on_failure != "fail_closed" and settings.environment == "production":
            add("recommended", "slm-degrade", "Requests continue when the local model is down",
                "Deterministic layers still run, but indirect identifiers are not looked for.",
                "detection.slm.on_failure", d.slm.on_failure, "fail_closed", "INV-03")  # fmt: skip
        if not d.slm.model_digest:
            add("recommended", "slm-digest", "The local model is not pinned",
                "Pin model_digest so a swapped model is treated as unavailable.", "detection.slm.model_digest",
                None, "sha256:<digest>", "INV-03")  # fmt: skip
    for key in settings.auth.keys:
        if key.expires_at:
            left = key.expires_at - now
            if left.total_seconds() <= 0:
                add("info", f"key-expired-{key.id}", f"Key {key.id} has expired", "It is refused; remove it.",
                    f"auth.keys[{key.id}].expires_at", key.expires_at.isoformat())  # fmt: skip
            elif left < timedelta(days=7):
                add("recommended", f"key-expiring-{key.id}", f"Key {key.id} expires in {max(1, left.days)} day(s)",
                    "Generate a replacement before it lapses.", f"auth.keys[{key.id}].expires_at",
                    key.expires_at.isoformat())  # fmt: skip
        elif key.admin:
            add(
                "info",
                f"key-admin-{key.id}",
                f"Admin key {key.id} never expires",
                "An expiry date makes rotation routine.",
                f"auth.keys[{key.id}].expires_at",
                None,
                "a date",
            )
    for u in settings.upstreams:
        if u.effective_dialect != "openrouter":
            continue
        if u.openrouter.data_collection != "deny":
            title = f"{u.name}: OpenRouter may use providers that store prompts"
            add("recommended", f"openrouter-data-{u.name}", title,
                "With data_collection: deny the gateway restricts every request to providers that do not store "
                "them, whatever the client asks.", f"upstreams[{u.name}].openrouter.data_collection",
                u.openrouter.data_collection, "deny")  # fmt: skip
        if not u.openrouter.zdr:
            add("info", f"openrouter-zdr-{u.name}", f"{u.name}: zero-data-retention routing is off",
                "zdr: true limits routing to endpoints that retain nothing, at the cost of fewer available models.",
                f"upstreams[{u.name}].openrouter.zdr", False, True)  # fmt: skip
    if not d.registry.terms and not d.registry.patterns:
        add("info", "registry-empty", "No protected terms",
            "Project names, customers or internal hostnames can be listed so they are always redacted.",
            "detection.registry.terms", [], ["your terms"])  # fmt: skip
    if settings.documents.enabled and settings.documents.images == "blank":
        add("info", "images-blank", "Pictures in documents are blanked",
            "Files are released without their pictures; text inside pictures is never read.", "documents.images",
            "blank", "block", "INV-10")  # fmt: skip
    if settings.environment != "production":
        add(
            "info",
            "dev-mode",
            "Development mode",
            "Production startup guards (keys, https upstreams) are off.",
            "environment",
            settings.environment,
            "production",
        )
    for notice in settings.notices():
        setting = notice.split(":", 1)[0].split(" (", 1)[0]
        add("recommended", "ignored-setting", "A setting has no effect: keys are always redacted",
            f"{notice}. Remove it from the configuration so the file says what the gateway does.", setting,
            "set", "remove")  # fmt: skip
    return sorted(out, key=lambda f: _ORDER[f["level"]])
