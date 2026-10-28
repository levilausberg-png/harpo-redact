"""Typed configuration.

Sources, highest precedence first:
1. keyword arguments (tests),
2. environment variables ``HARPO_<SECTION>__<KEY>`` (for example
   ``HARPO_SERVER__PORT=9000``),
3. the YAML file named by ``HARPO_CONFIG``, or else ``harpo.yaml`` in the working directory or in ``config/``.

Variables named before the rename (``PRIVATEAI_*``) are still read, with a notice.

Every section forbids unknown keys, so a typo fails at startup instead of
silently leaving a protection switched off.
"""

from __future__ import annotations

import fnmatch
import os
import re
from collections.abc import MutableMapping
from contextvars import ContextVar
from datetime import datetime
from typing import Any, Literal
from urllib.parse import urlsplit

import phonenumbers
import re2
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ModelWrapValidatorHandler,
    PrivateAttr,
    field_validator,
    model_validator,
)
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

from .entities import ALWAYS_REDACTED, CRITICAL_TYPES, EntityType

Mode = Literal["relational", "generic"]
Style = Literal["openai", "anthropic"]


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ServerSettings(_Section):
    host: str = "127.0.0.1"
    port: int = Field(8080, ge=1, le=65535)
    workers: int = Field(1, ge=1, le=64)
    max_body_bytes: int = Field(2_000_000, ge=1024)
    max_messages: int = Field(256, ge=1)
    max_total_chars: int = Field(200_000, ge=100)
    max_scan_ms: int = Field(15_000, ge=50, le=600_000)  # scan budget: past it the request is blocked, not sent
    max_decoded_bytes: int = Field(4_000_000, ge=1_000)  # all base64 and similar payloads decoded for one request
    max_entities: int = Field(20_000, ge=10)  # raw detections in one request
    max_concurrent_scans: int = Field(8, ge=1, le=256)
    console: bool = True
    metrics: bool = True
    hsts: bool = False
    # Host headers accepted; set to the gateway's DNS names to stop DNS rebinding.
    allowed_hosts: list[str] = Field(default_factory=lambda: ["*"])
    tls_certfile: str | None = None
    tls_keyfile: str | None = None


class AuthKey(_Section):
    id: str = Field(pattern=r"^[A-Za-z0-9_.\-]{1,64}$")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    can_override: bool = False  # may send overridable blocked values as placeholders
    admin: bool = False  # sees every key's activity in the console (others see their own)
    expires_at: datetime | None = None  # ISO 8601 with a timezone; after it the key is refused
    requests_per_minute: int | None = Field(None, ge=1, le=1_000_000)  # per gateway process

    @field_validator("expires_at", mode="after")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("expires_at needs a timezone, e.g. 2027-01-31T00:00:00Z")
        return value


class AuthSettings(_Section):
    enabled: bool = True
    keys: list[AuthKey] = Field(default_factory=list)


class EntityPolicy(_Section):
    action: Literal["redact", "block", "allow"] = "redact"
    overridable: bool = False


def default_entity_policies() -> dict[EntityType, EntityPolicy]:
    # Everything is redacted unless configured otherwise. Credentials (ALWAYS_REDACTED) cannot be configured.
    policies = {t: EntityPolicy() for t in EntityType}
    # Dates are detected but sent as they are unless a policy (HIPAA-style) redacts them.
    policies[EntityType.DATE] = EntityPolicy(action="allow")
    return policies


class PolicySettings(_Section):
    # Where the console saves policy changes (actions per type, custom types). Unset: the console shows the
    # policy read-only and offers the YAML to paste into this file instead.
    live_file: str | None = None
    default_mode: Mode = "relational"
    context_repair: bool = False
    client_may_choose_mode: bool = True
    entities: dict[EntityType, EntityPolicy] = Field(default_factory=default_entity_policies)
    allow_terms: list[str] = Field(default_factory=list)
    rot_threshold: float = Field(0.35, gt=0, le=1)
    rot_min_words: int = Field(12, ge=1)
    unsupported_content: Literal["block", "drop"] = "block"
    override: Literal["any_key", "listed_keys", "never"] = "listed_keys"
    unknown_fields: Literal["reject", "pass"] = "reject"  # anything the adapter does not inspect, at any depth
    remote_mcp: Literal["block", "allow"] = "block"  # Anthropic mcp_servers: the provider calls them with your token
    egress_verification: Literal["full", "off"] = "full"  # rescan the whole sanitized body before it leaves
    # Provider answers: "report" counts deterministic findings in a header and the audit log, "redact" replaces
    # them. Non-streaming responses only; a streamed answer is marked as not scanned.
    response_scan: Literal["off", "report", "redact"] = "off"

    # Settings this file asks for that the gateway does not honour (keys are always redacted), for notices.
    _ignored: list[str] = PrivateAttr(default_factory=list)

    @model_validator(mode="wrap")
    @classmethod
    def _note_key_settings(cls, data: Any, handler: ModelWrapValidatorHandler[PolicySettings]) -> PolicySettings:
        ignored: list[str] = []
        entities = data.get("entities") if isinstance(data, dict) else None
        if isinstance(entities, dict):
            keys = {t.value for t in ALWAYS_REDACTED}
            for key, value in entities.items():
                name = str(getattr(key, "value", key))
                if name not in keys:
                    continue
                if isinstance(value, EntityPolicy):
                    value = value.model_dump()
                if not isinstance(value, dict):
                    continue
                if value.get("action", "redact") == "block":
                    ignored.append(f"policy.entities.{name}.action: block (keys are always redacted)")
                if value.get("overridable"):
                    ignored.append(f"policy.entities.{name}.overridable (a redacted key needs no override)")
        model = handler(data)
        model._ignored = ignored
        return model

    @field_validator("response_scan", "egress_verification", mode="before")
    @classmethod
    def _yaml_off(cls, value: object) -> object:
        return "off" if value is False else value  # YAML reads a bare `off` as false

    @field_validator("live_file", mode="after")
    @classmethod
    def _beside_config(cls, value: str | None) -> str | None:
        """A relative live_file is relative to the configuration file it is written in."""
        if value and not os.path.isabs(value):
            source = _yaml_path.get()
            if source:
                return os.path.join(os.path.dirname(os.path.abspath(source)), value)
        return value

    @field_validator("entities", mode="after")
    @classmethod
    def _merge_defaults(cls, value: dict[EntityType, EntityPolicy]) -> dict[EntityType, EntityPolicy]:
        merged = default_entity_policies()
        merged.update(value)
        for etype in CRITICAL_TYPES:
            if merged[etype].action == "allow":
                if etype in ALWAYS_REDACTED:
                    raise ValueError(f"{etype.value} is always redacted; it cannot be set to allow")
                raise ValueError(f"{etype.value} cannot be set to allow")
        # Keys are always redacted: never blocked, never allowed, never overridden. An older file that asks
        # for "block" still loads; the request now goes on with a placeholder, and a notice says so.
        for etype in ALWAYS_REDACTED:
            merged[etype] = EntityPolicy(action="redact", overridable=False)
        return merged

    @field_validator("allow_terms", mode="after")
    @classmethod
    def _clean_terms(cls, value: list[str]) -> list[str]:
        return [t.strip() for t in value if t.strip()]


class RegistrySettings(_Section):
    terms: list[str] = Field(default_factory=list)
    patterns: list[str] = Field(default_factory=list)

    @field_validator("patterns", mode="after")
    @classmethod
    def _compile(cls, value: list[str]) -> list[str]:
        for i, pattern in enumerate(value):
            try:
                compiled = re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"patterns[{i}] is not a valid regular expression: {exc.msg}") from None
            if compiled.fullmatch(""):
                raise ValueError(f"patterns[{i}] matches the empty string")
        return value


def _default_labels() -> dict[str, EntityType]:
    return {
        "PERSON": EntityType.PERSON,
        "PER": EntityType.PERSON,
        "ORG": EntityType.ORGANIZATION,
        "GPE": EntityType.LOCATION,
        "LOC": EntityType.LOCATION,
        "FAC": EntityType.LOCATION,
    }


class NERSettings(_Section):
    enabled: bool = True
    model: str = "en_core_web_sm"  # English text, and text too short to tell
    # Models for other languages, e.g. {"nl": "nl_core_news_sm", "de": "de_core_news_sm", "other": "xx_ent_wiki_sm"}.
    language_models: dict[Literal["nl", "de", "fr", "es", "other"], str] = Field(default_factory=dict)
    # Text in a detected language without a model: skip NER for it, or run the English model anyway.
    other_languages: Literal["skip", "english"] = "english"
    labels: dict[str, EntityType] = Field(default_factory=_default_labels)
    chunk_chars: int = Field(10_000, ge=500, le=100_000)
    propagate: bool = True
    name_rules: bool = True
    precision_filter: bool = True  # drop common words, labels, codes and keywords the model tags as names
    # Results for texts seen before (chat history) are reused. The cache keeps
    # offsets and types only, keyed by an HMAC with a per-process random key.
    cache_entries: int = Field(10_000, ge=0, le=1_000_000)
    cache_ttl_s: int = Field(900, ge=1, le=86_400)
    # Field labels and acronyms that small NER models tag as organisations.
    ignore: list[str] = Field(
        default_factory=lambda: [
            "SSN", "BSN", "IBAN", "DOB", "PIN", "ID", "VAT", "API", "IP", "URL", "CSV", "PDF", "JSON",
            "SQL", "CEO", "CFO", "CTO", "HR", "IT", "AI", "LLM", "GDPR", "CCPA", "PII", "NDA", "SLA",
            "MAC", "VIN", "IMEI", "MRN", "PAN", "NIR", "DNI", "NIE", "NHS", "SIN", "TFN", "CPF", "CURP", "ITIN",
            "ISBN", "SKU", "CVE", "UUID", "SHA", "EAN", "UPC", "INV",
            "EIN", "FEIN", "PIN", "OTP", "BTC", "ETH", "ZIP", "HIPAA", "PHI",
        ]
    )  # fmt: skip


class SLMSettings(_Section):
    enabled: bool = False
    base_url: str = "http://ollama:11434"
    model: str = "llama3.2:3b"
    timeout_ms: int = Field(3000, ge=100, le=120_000)
    on_failure: Literal["fail_closed", "degrade"] = "fail_closed"
    max_chunk_chars: int = Field(2000, ge=200, le=20_000)
    max_concurrency: int = Field(2, ge=1, le=32)  # shared by all requests
    keep_alive: str = "30m"
    max_input_chars: int = Field(50_000, ge=1_000, le=2_000_000)  # more text than this: "over_budget", by policy
    model_digest: str | None = Field(None, pattern=r"^(sha256:)?[0-9a-f]{64}$")  # pin the exact model


class RegionSettings(_Section):
    """Region packs: identifiers a country or the EU writes in a format of its own, found without a cue word."""

    nl: bool = True  # btw-identificatienummer, loonheffingennummer
    us: bool = True  # masked SSNs (last four), ATIN, Medicare MBI, USCIS receipt numbers, A-Numbers, I-94
    eu: bool = True  # VAT numbers of every member state, BIC after its cue, EU Digital COVID Certificate ids


class IdentifierSettings(_Section):
    """The deterministic families of the detection library (library.py), in the order of its umbrellas."""

    # Identity numbers
    national_ids: bool = True  # checked national and tax IDs: 17 schemes in 14 countries
    cued_numbers: bool = True  # any value named by the word in front of it, in 30+ languages
    opaque_codes: bool = True  # codes no language writes, in a sentence: "FXJPIUZXKH", "BfnMnQaGjPdc"
    regions: RegionSettings = Field(default_factory=RegionSettings)  # region packs: NL, US, EU
    # Forms, tables and fields
    table_fields: bool = True  # values under a column, a form label or a JSON key that names them
    # Addresses and places
    addresses: bool = True  # street addresses in 30+ languages, postcodes, PO boxes, CJK address units
    # Devices, networks and machine formats
    devices: bool = True  # MAC, IMEI, VIN, serial numbers
    machine_formats: bool = True  # MRZ, HL7, AWS identities, user names in logs (typed credentials always run)
    # Crypto
    crypto: bool = True  # Bitcoin and Ethereum addresses
    # Hidden and encoded text
    spoken_emails: bool = True  # "jane at example dot com"
    decode_escapes: bool = True  # %40, &#64;, \u0040 decoded in a shadow view; always on (a key in escapes is a key)


class SecretsSettings(_Section):
    # Credentials are always detected and always redacted: 221 gitleaks rules plus prompt rules, on RE2.
    # Add rules with extra_rules_file. The four switches below are kept so older files load; turning one off
    # has no effect, and check-config and the console say so.
    extra_rules_file: str | None = None  # more key rules in gitleaks TOML format; checked when the config loads
    library: bool = True
    disabled_rules: list[str] = Field(default_factory=list)
    natural_language: bool = True  # "my password is ..."
    seed_phrases: bool = True  # BIP39 wallet recovery phrases
    _ignored: list[str] = PrivateAttr(default_factory=list)

    @field_validator("extra_rules_file", mode="after")
    @classmethod
    def _rules_file(cls, value: str | None) -> str | None:
        if value is not None:
            from .detectors.secret_library import check_rules_file

            check_rules_file(value)
        return value

    @model_validator(mode="after")
    def _always_on(self) -> SecretsSettings:
        ignored: list[str] = []
        if not self.library:
            ignored.append("detection.secrets.library: false (the key library is always on)")
        if self.disabled_rules:
            shown = ", ".join(self.disabled_rules[:4]) + (" …" if len(self.disabled_rules) > 4 else "")
            ignored.append(f"detection.secrets.disabled_rules: {shown} (key rules cannot be switched off)")
        if not self.natural_language:
            ignored.append("detection.secrets.natural_language: false (passwords in prose are always found)")
        if not self.seed_phrases:
            ignored.append("detection.secrets.seed_phrases: false (recovery phrases are always found)")
        self.library, self.disabled_rules, self.natural_language, self.seed_phrases = True, [], True, True
        self._ignored = ignored
        return self


_CUSTOM_NAME_RE = r"^[A-Z][A-Z0-9_]{1,39}$"
_PLACEHOLDER_SUFFIX_RE = re.compile(r"\d{1,6}|[A-Z]{1,3}")


class CustomType(_Section):
    """A type of your own. Values its terms or patterns find are replaced with [NAME_1], [NAME_2], ..."""

    name: str = Field(pattern=_CUSTOM_NAME_RE)  # upper case: EMPLOYEE_ID, PROJECT, CASE_NUMBER
    description: str = Field("", max_length=200)
    terms: list[str] = Field(default_factory=list, max_length=5_000)  # exact words or phrases, any case
    patterns: list[str] = Field(default_factory=list, max_length=50)  # RE2 expressions (linear time)
    action: Literal["redact", "block", "allow"] = "redact"  # allow: defined but switched off
    overridable: bool = False  # with action block: keys with can_override may send it as a placeholder

    @field_validator("terms", mode="after")
    @classmethod
    def _terms(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for term in value:
            text = " ".join(term.split())
            if not 2 <= len(text) <= 200:
                raise ValueError(f"term {term[:40]!r} must be 2 to 200 characters")
            if not any(ch.isalnum() for ch in text):
                raise ValueError(f"term {term[:40]!r} needs a letter or digit")
            cleaned.append(text)
        return list(dict.fromkeys(cleaned))

    @field_validator("patterns", mode="after")
    @classmethod
    def _patterns(cls, value: list[str]) -> list[str]:
        from .detectors.secret_library import quiet_re2, re2_message

        options = quiet_re2()
        for i, pattern in enumerate(value):
            if not pattern or len(pattern) > 500:
                raise ValueError(f"patterns[{i}] must be 1 to 500 characters")
            try:
                compiled = re2.compile(pattern, options)
            except re2.error as exc:
                raise ValueError(
                    f"patterns[{i}] is not a valid RE2 expression ({re2_message(exc)}); "
                    "RE2 has no lookarounds or backreferences"
                ) from None
            if compiled.search("") is not None:
                raise ValueError(f"patterns[{i}] matches the empty string")
        return value

    @model_validator(mode="after")
    def _something_to_find(self) -> CustomType:
        if not self.terms and not self.patterns:
            raise ValueError(f"custom type {self.name}: give at least one term or pattern")
        return self


def check_custom_names(custom: list[CustomType]) -> None:
    """Names must be unique, must not be a built-in type, and must not make placeholders that read as another
    type's ([EMAIL_A] is EMAIL's own label in generic mode, so EMAIL_A cannot be a custom name)."""
    builtin = {t.value for t in EntityType}
    names = [c.name for c in custom]
    if len(names) > 64:
        raise ValueError("at most 64 custom types")
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        raise ValueError(f"custom type names must be unique: {', '.join(dupes)}")
    every = builtin | set(names)
    for name in names:
        if name in builtin:
            raise ValueError(f"custom type {name}: that is a built-in type; choose another name")
        for other in every:
            rest = name[len(other) + 1 :]
            if other != name and name.startswith(other + "_") and _PLACEHOLDER_SUFFIX_RE.fullmatch(rest):
                raise ValueError(
                    f"custom type {name}: its placeholders would read as {other}'s ([{name}]); choose another name"
                )
            # and the other way round: PRIVATE's placeholder [PRIVATE_KEY] would read as the type PRIVATE_KEY
            tail = other[len(name) + 1 :]
            if other != name and other.startswith(name + "_") and _PLACEHOLDER_SUFFIX_RE.fullmatch(tail):
                raise ValueError(
                    f"custom type {name}: a placeholder of it could read as {other} ([{other}]); choose another name"
                )


class DetectionSettings(_Section):
    phone_regions: list[str] = Field(default_factory=lambda: ["US", "GB", "NL", "DE"])
    encoded_max_depth: int = Field(2, ge=0, le=4)  # at least 1: a key inside base64 is still a key
    registry: RegistrySettings = Field(default_factory=RegistrySettings)
    custom_types: list[CustomType] = Field(default_factory=list)
    secrets: SecretsSettings = Field(default_factory=SecretsSettings)
    identifiers: IdentifierSettings = Field(default_factory=IdentifierSettings)
    ner: NERSettings = Field(default_factory=NERSettings)
    slm: SLMSettings = Field(default_factory=SLMSettings)

    _ignored: list[str] = PrivateAttr(default_factory=list)

    @field_validator("custom_types", mode="after")
    @classmethod
    def _custom_names(cls, value: list[CustomType]) -> list[CustomType]:
        check_custom_names(value)
        return value

    @model_validator(mode="after")
    def _keys_stay_decoded(self) -> DetectionSettings:
        """Keys hidden in base64, hex or escapes are keys too, so the decoders that find them stay on."""
        ignored: list[str] = []
        if self.encoded_max_depth < 1:
            ignored.append("detection.encoded_max_depth: 0 (encoded text is always decoded once: a key in it is a key)")
            self.encoded_max_depth = 1
        if not self.identifiers.decode_escapes:
            ignored.append("detection.identifiers.decode_escapes: false (escaped text is always decoded for keys)")
            self.identifiers.decode_escapes = True
        if self.secrets.extra_rules_file:
            from .detectors.secret_library import rules_file_global_allowlist

            if rules_file_global_allowlist(self.secrets.extra_rules_file):
                ignored.append(
                    "detection.secrets.extra_rules_file: [allowlist] (cannot exempt keys; each rule's own allowlist "
                    "still applies)"
                )
        self._ignored = ignored
        return self

    @field_validator("phone_regions", mode="after")
    @classmethod
    def _regions(cls, value: list[str]) -> list[str]:
        regions = [r.upper() for r in value]
        unknown = [r for r in regions if r not in phonenumbers.SUPPORTED_REGIONS]
        if unknown:
            raise ValueError(f"unknown phone regions: {', '.join(unknown)}")
        if not regions:
            raise ValueError("at least one phone region is required")
        return regions


_SLUG_RE = r"^[a-z0-9][a-z0-9_.\-/]{0,63}$"
# Headers the gateway sets itself, or that would carry credentials or break the request: never configurable.
_RESERVED_HEADERS = frozenset(
    {
        "authorization", "proxy-authorization", "x-api-key", "api-key", "cookie", "set-cookie", "host",
        "content-length", "content-type", "content-encoding", "transfer-encoding", "connection", "upgrade", "te",
        "trailer", "keep-alive", "accept", "accept-encoding", "user-agent", "anthropic-version", "anthropic-beta",
        "x-forwarded-for", "x-real-ip", "forwarded",
    }
)  # fmt: skip


class OpenRouterSettings(_Section):
    """Provider-routing policy the gateway enforces on every request to OpenRouter. Clients can tighten it,
    never loosen it: a request asking for providers that store data is rewritten to the policy below."""

    data_collection: Literal["deny", "client"] = "deny"  # deny: only providers that do not store prompts
    zdr: bool = False  # true: only zero-data-retention endpoints (strictest; fewer models are available)
    only: list[str] = Field(default_factory=list)  # provider slugs allowed (the client's list is intersected)
    ignore: list[str] = Field(default_factory=list)  # provider slugs never used (added to the client's list)
    # Router and fusion plugins let OpenRouter pick the model. Allowed only when this upstream allows any model.
    model_choosing_plugins: Literal["if_any_model", "block"] = "if_any_model"

    @field_validator("only", "ignore", mode="after")
    @classmethod
    def _slugs(cls, value: list[str]) -> list[str]:
        for slug in value:
            if not re.fullmatch(_SLUG_RE, slug):
                raise ValueError(f"{slug!r} is not a provider slug (lowercase, e.g. anthropic or deepinfra/fp8)")
        return value


class UpstreamSettings(_Section):
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_\-]{0,31}$")
    style: Style
    base_url: str
    api_key_env: str | None = None
    models: list[str] = Field(min_length=1)
    timeout_s: float = Field(120.0, gt=0, le=900)
    connect_timeout_s: float = Field(10.0, gt=0, le=120)
    max_connections: int = Field(100, ge=1, le=10_000)
    max_response_bytes: int = Field(50_000_000, ge=1024, le=1_000_000_000)
    # "auto": OpenRouter when the host is openrouter.ai. The dialect decides which extra request fields the
    # adapter understands (OpenRouter's provider routing, plugins, reasoning) and how the key is checked.
    dialect: Literal["auto", "standard", "openrouter"] = "auto"
    # "auto": Authorization: Bearer for OpenAI-style and OpenRouter, x-api-key for Anthropic-style.
    auth_scheme: Literal["auto", "bearer", "x-api-key"] = "auto"
    # Static, non-secret headers sent with every request, e.g. OpenRouter's HTTP-Referer and X-OpenRouter-Title.
    headers: dict[str, str] = Field(default_factory=dict)
    # "upstream": /v1/models also lists the provider's own models that match `models` (cached for 10 minutes).
    list_models: Literal["auto", "configured", "upstream"] = "auto"
    openrouter: OpenRouterSettings = Field(default_factory=OpenRouterSettings)

    @field_validator("headers", mode="after")
    @classmethod
    def _headers(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 16:
            raise ValueError("at most 16 headers")
        for name, text in value.items():
            if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", name):
                raise ValueError(f"header name {name!r} is not valid")
            if name.lower() in _RESERVED_HEADERS:
                raise ValueError(
                    f"header {name!r} is set by the gateway or carries credentials; it cannot be configured"
                )
            if len(text) > 512 or any(c in text for c in "\r\n\x00"):
                raise ValueError(f"header {name!r} must be one line of at most 512 characters")
        return value

    @property
    def effective_dialect(self) -> Literal["standard", "openrouter"]:
        if self.dialect != "auto":
            return self.dialect
        host = (urlsplit(self.base_url).hostname or "").lower()
        return "openrouter" if host == "openrouter.ai" or host.endswith(".openrouter.ai") else "standard"

    @property
    def effective_auth_scheme(self) -> Literal["bearer", "x-api-key"]:
        if self.auth_scheme != "auto":
            return self.auth_scheme
        return "x-api-key" if self.style == "anthropic" and self.effective_dialect == "standard" else "bearer"

    @property
    def lists_upstream_models(self) -> bool:
        if self.list_models != "auto":
            return self.list_models == "upstream"
        return self.effective_dialect == "openrouter"

    @property
    def any_model(self) -> bool:
        return "*" in self.models

    @field_validator("base_url", mode="after")
    @classmethod
    def _url(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("base_url must be an http(s) URL")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError("base_url must not contain credentials, a query or a fragment")
        return value.rstrip("/")

    def matches(self, model: str) -> bool:
        return any(fnmatch.fnmatchcase(model, pattern) for pattern in self.models)

    @property
    def literal_models(self) -> list[str]:
        return [m for m in self.models if not any(c in m for c in "*?[")]


class LoggingSettings(_Section):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    audit: bool = True


_yaml_path: ContextVar[str | None] = ContextVar("harpo_yaml_path", default=None)


DocFormat = Literal["pdf", "docx", "xlsx", "pptx", "text"]


def _all_formats() -> list[DocFormat]:
    return ["pdf", "docx", "xlsx", "pptx", "text"]


class DocumentSettings(_Section):
    enabled: bool = True  # POST /v1/documents/redact
    in_chat: bool = False  # redact files attached to chat requests instead of blocking them
    formats: list[DocFormat] = Field(default_factory=lambda: _all_formats())
    max_bytes: int = Field(20_000_000, ge=1_000, le=500_000_000)
    max_chars: int = Field(1_000_000, ge=1_000, le=50_000_000)
    max_segments: int = Field(50_000, ge=10, le=2_000_000)
    max_pages: int = Field(150, ge=1, le=5_000)
    images: Literal["block", "blank"] = "block"  # pictures and scanned pages cannot be inspected
    pdf_dpi: int = Field(150, ge=72, le=300)
    worker_memory_mb: int = Field(768, ge=128, le=16_384)
    worker_cpu_s: int = Field(60, ge=5, le=3_600)
    timeout_s: int = Field(120, ge=5, le=3_600)
    max_concurrent: int = Field(2, ge=1, le=64)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HARPO_", env_nested_delimiter="__", extra="forbid")

    environment: Literal["development", "production"] = "production"
    server: ServerSettings = Field(default_factory=ServerSettings)
    auth: AuthSettings = Field(default_factory=AuthSettings)
    policy: PolicySettings = Field(default_factory=PolicySettings)
    detection: DetectionSettings = Field(default_factory=DetectionSettings)
    upstreams: list[UpstreamSettings] = Field(default_factory=list)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    documents: DocumentSettings = Field(default_factory=DocumentSettings)

    _legacy: list[str] = PrivateAttr(default_factory=list)  # PRIVATEAI_* variables read under their new names

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        sources: list[PydanticBaseSettingsSource] = [init_settings, env_settings]
        path = _yaml_path.get()
        if path:
            sources.append(YamlConfigSettingsSource(settings_cls, yaml_file=path))
        return tuple(sources)

    @model_validator(mode="after")
    def _unique_upstreams(self) -> Settings:
        names = [u.name for u in self.upstreams]
        if len(names) != len(set(names)):
            raise ValueError("upstream names must be unique")
        return self

    def upstream_for(self, style: Style, model: str) -> UpstreamSettings | None:
        for upstream in self.upstreams:
            if upstream.style == style and upstream.matches(model):
                return upstream
        return None

    def notices(self) -> list[str]:
        """Settings the gateway does not honour (keys are always redacted), and names from before the rename."""
        return [*self.policy._ignored, *self.detection.secrets._ignored, *self.detection._ignored, *self._legacy]

    def production_problems(self, environ: dict[str, str] | None = None) -> list[str]:
        """Reasons this configuration must not serve production traffic."""
        env = os.environ if environ is None else environ
        problems: list[str] = []
        if self.environment != "production":
            return problems
        if not self.auth.enabled:
            problems.append("auth.enabled must be true in production")
        elif not self.auth.keys:
            problems.append("auth.keys is empty; create one with `harpo hash-key`")
        if not self.upstreams:
            problems.append("no upstreams are configured")
        for upstream in self.upstreams:
            if not upstream.base_url.startswith("https://"):
                problems.append(f"upstream {upstream.name}: base_url must use https in production")
            if not upstream.api_key_env:
                problems.append(f"upstream {upstream.name}: api_key_env is not set")
            elif not env.get(upstream.api_key_env):
                problems.append(f"upstream {upstream.name}: environment variable {upstream.api_key_env} is empty")
        if self.logging.level == "DEBUG":
            problems.append("logging.level DEBUG is not allowed in production (libraries log headers at debug)")
        if bool(self.server.tls_certfile) != bool(self.server.tls_keyfile):
            problems.append("server.tls_certfile and server.tls_keyfile must be set together")
        return problems


LEGACY_ENV_PREFIX = "PRIVATEAI_"  # the prefix before the rename to Harpo
DISCOVERED_CONFIGS = ("harpo.yaml", os.path.join("config", "harpo.yaml"))


def adopt_legacy_env(environ: MutableMapping[str, str] | None = None) -> list[str]:
    """Variables named before the rename (``PRIVATEAI_*``) still work: each is read as its ``HARPO_*`` name when that
    one is not set. Returns the old names, so the operator can be told to rename them."""
    env = os.environ if environ is None else environ
    adopted = []
    for name in sorted(env):
        if name.startswith(LEGACY_ENV_PREFIX):
            new = "HARPO_" + name[len(LEGACY_ENV_PREFIX) :]
            if new not in env:
                env[new] = env[name]
                adopted.append(name)
    return adopted


def load_settings(path: str | None = None, **overrides: object) -> Settings:
    """Load settings from ``path`` (or ``$HARPO_CONFIG``, or a harpo.yaml here or in config/) plus the environment."""
    legacy = adopt_legacy_env()
    path = path or os.environ.get("HARPO_CONFIG") or next((p for p in DISCOVERED_CONFIGS if os.path.isfile(p)), None)
    if path and not os.path.isfile(path):
        raise FileNotFoundError(f"config file not found: {path}")
    token = _yaml_path.set(path)
    try:
        settings = Settings(**overrides)  # type: ignore[arg-type]
    finally:
        _yaml_path.reset(token)
    settings._legacy = [f"{name} (read as HARPO_{name[len(LEGACY_ENV_PREFIX) :]}; rename it)" for name in legacy]
    return settings
