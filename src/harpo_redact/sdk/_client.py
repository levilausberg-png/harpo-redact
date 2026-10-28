"""Clients for a running Harpo gateway: its HTTP API, behind its own authentication, checks and audit.

The gateway does the work; a client builds requests and turns answers into the SDK's types and exceptions. The
same calls exist twice, in :class:`GatewayClient` (blocking) and :class:`AsyncGatewayClient` (asyncio): each call
is described once, by the ``_Call`` its ``_c_*`` method builds.
"""

from __future__ import annotations

import base64
import mimetypes
import os
import ssl
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, TypeVar
from urllib.parse import quote

import httpx

from .. import __version__
from . import _convert
from ._errors import (
    AuthenticationError,
    ConflictError,
    DocumentError,
    GatewayError,
    GatewayUnavailableError,
    HarpoError,
    InvalidRequestError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    RequestTooLargeError,
)
from ._results import (
    ConfigFinding,
    ConfigIssue,
    ConfigReport,
    CustomType,
    DocumentResult,
    EgressPreview,
    GatewayKey,
    Health,
    InvariantCheck,
    KeyInfo,
    PolicyPreview,
    PolicyView,
    ProviderCheck,
    ProxyResponse,
    Readiness,
    Risk,
    ScanResult,
    SelfTestReport,
    Trace,
)

_T = TypeVar("_T")
Mode = Literal["relational", "generic"]
Style = Literal["openai", "anthropic"]
Action = Literal["redact", "block", "allow"]

DEFAULT_URL = "http://127.0.0.1:8080"
ANTHROPIC_VERSION = "2023-06-01"
_STATUS_ERRORS: dict[int, type[GatewayError]] = {
    401: AuthenticationError,
    403: PermissionDeniedError,
    404: NotFoundError,
    409: ConflictError,
    413: RequestTooLargeError,
    429: RateLimitError,
    502: GatewayUnavailableError,
    503: GatewayUnavailableError,
    504: GatewayUnavailableError,
}


# --------------------------------------------------------------------------- answers
def _json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        raise GatewayError(
            "the gateway's answer is not JSON",
            error_type="invalid_response",
            status=response.status_code,
            request_id=response.headers.get("x-harpo-request-id"),
        ) from None


def _error(response: httpx.Response) -> HarpoError:
    """The exception for an error answer: the gateway's error shape (OpenAI's or Anthropic's, with its ``harpo``
    details), or a provider's error the gateway passed on."""
    status = response.status_code
    request_id = response.headers.get("x-harpo-request-id")
    error: Mapping[str, Any] = {}
    try:
        body = response.json()
    except ValueError:
        body = None
    if isinstance(body, dict) and isinstance(body.get("error"), dict):
        error = body["error"]
    error_type = str(error.get("type") or error.get("code") or "api_error")
    message = str(error.get("message") or response.reason_phrase or "error")
    details: Mapping[str, Any] = error["harpo"] if isinstance(error.get("harpo"), dict) else {}
    if error_type == "privacy_block":
        return _convert.blocked(message, details, status=status, request_id=request_id)
    if error_type == "document_error":
        return DocumentError(str(details.get("code") or error_type), message, status=status, request_id=request_id)
    if status in (400, 422):
        return InvalidRequestError(message, status=status, request_id=request_id, details=details)
    kind = _STATUS_ERRORS.get(status, GatewayError)
    if kind is RateLimitError:
        try:
            retry_after: float | None = float(response.headers.get("retry-after", ""))
        except ValueError:
            retry_after = None
        return RateLimitError(
            message, retry_after=retry_after, error_type=error_type, status=status, request_id=request_id,
            details=details,
        )  # fmt: skip
    return kind(message, error_type=error_type, status=status, request_id=request_id, details=details)


def _request_id(response: httpx.Response) -> str | None:
    value = response.headers.get("x-harpo-request-id")
    return str(value) if value is not None else None


def _header_int(response: httpx.Response, name: str) -> int | None:
    value = response.headers.get(name)
    return int(value) if value and value.isdigit() else None


def _health(response: httpx.Response) -> Health:
    data = _json(response)
    return Health(str(data.get("status", "")), str(data.get("version", "")))


def _readiness(response: httpx.Response) -> Readiness:
    data = _json(response)
    return Readiness(data.get("status") == "ready", {str(k): str(v) for k, v in dict(data.get("checks") or {}).items()})


def _scan(response: httpx.Response) -> ScanResult:
    return _convert.scan_result(_json(response), request_id=_request_id(response))


def _document(response: httpx.Response) -> DocumentResult:
    payload = _json(response)
    file = payload.get("file") or {}
    data = base64.b64decode(file["base64"]) if isinstance(file.get("base64"), str) else None
    return _convert.document_result(payload, data, request_id=_request_id(response))


def _proxy(response: httpx.Response) -> ProxyResponse:
    body = _json(response)
    return ProxyResponse(
        body=body if isinstance(body, dict) else {"data": body},
        status=response.status_code,
        risk=response.headers.get("x-harpo-risk"),
        redactions=_header_int(response, "x-harpo-redactions"),
        mode=response.headers.get("x-harpo-mode"),
        response_scan=response.headers.get("x-harpo-response-scan"),
        response_findings=_header_int(response, "x-harpo-response-findings"),
        request_id=_request_id(response),
    )


def _models(response: httpx.Response) -> list[str]:
    return [str(m["id"]) for m in _json(response).get("data", []) if isinstance(m, dict) and "id" in m]


def _egress(response: httpx.Response) -> EgressPreview:
    data = _json(response)
    decision = str(data.get("decision", ""))
    if decision == "would_forward":
        upstream = data.get("upstream") or {}
        extra = ("style", "auth", "timings_ms", "slm", "egress_verification")
        return EgressPreview(
            decision=decision,
            body=data.get("body"),
            upstream=upstream.get("name"),
            url=upstream.get("url"),
            risk=Risk(str(data.get("risk", "green"))),
            redactions=int(data.get("redactions") or 0),
            counts=dict(data.get("counts") or {}),
            mode=data.get("mode"),
            reasons=tuple(_convert.reason(r) for r in data.get("reasons", ())),
            status=None,
            message=None,
            details={k: data[k] for k in extra if k in data},
        )
    details = dict(data.get("details") or {})
    return EgressPreview(
        decision=decision,
        body=None,
        upstream=None,
        url=None,
        risk=Risk(str(details["risk"])) if details.get("risk") else (Risk.RED if decision == "blocked" else None),
        redactions=0,
        counts={},
        mode=None,
        reasons=tuple(_convert.reason(r) for r in details.get("reasons", ())),
        status=data.get("status"),
        message=data.get("message"),
        details=details,
    )


def _trace(response: httpx.Response) -> Trace:
    return Trace(_json(response))


def _dict(response: httpx.Response) -> dict[str, Any]:
    data = _json(response)
    return data if isinstance(data, dict) else {"data": data}


def _providers(response: httpx.Response) -> list[dict[str, Any]]:
    return list(_json(response).get("providers", []))


def _provider_check(response: httpx.Response) -> ProviderCheck:
    data = _json(response)
    known = ("name", "reachable", "status", "latency_ms", "auth", "error")
    return ProviderCheck(
        name=str(data.get("name", "")),
        reachable=bool(data.get("reachable", False)),
        status=data.get("status"),
        latency_ms=data.get("latency_ms"),
        auth=data.get("auth"),
        error=data.get("error"),
        details={k: v for k, v in data.items() if k not in known},
    )


def _keys(response: httpx.Response) -> tuple[KeyInfo, ...]:
    return tuple(
        KeyInfo(
            id=str(k.get("id", "")),
            fingerprint=str(k.get("fingerprint", "")),
            admin=bool(k.get("admin", False)),
            can_override=bool(k.get("can_override", False)),
            expires_at=k.get("expires_at"),
            expired=bool(k.get("expired", False)),
            requests_per_minute=k.get("requests_per_minute"),
            requests=int(k.get("requests") or 0),
            last_seen=k.get("last_seen"),
        )
        for k in _json(response).get("keys", [])
    )


def _config_report(response: httpx.Response) -> ConfigReport:
    data = _json(response)
    errors = tuple(
        ConfigIssue(str(e.get("path", "")), str(e.get("message", "")), e.get("line")) for e in data.get("errors", [])
    )
    return ConfigReport(
        valid=bool(data.get("valid", False)),
        errors=errors,
        problems=tuple(str(p) for p in data.get("problems", [])),
        notices=(),
        missing_models=(),
        diff=data.get("diff"),
    )


def _analysis(response: httpx.Response) -> tuple[ConfigFinding, ...]:
    return tuple(_convert.config_finding(f) for f in _json(response).get("findings", []))


def _policy(response: httpx.Response) -> PolicyView:
    return _convert.policy_view(_json(response))


def _policy_preview(response: httpx.Response) -> PolicyPreview:
    data = _json(response)
    return PolicyPreview(
        text=str(data.get("text", "")),
        risk=Risk(str(data.get("risk", "green"))),
        findings=tuple(_convert.finding(f) for f in data.get("findings", [])),
        reasons=tuple(_convert.reason(r) for r in data.get("reasons", [])),
        counts=dict(data.get("counts") or {}),
    )


def _selftest(response: httpx.Response) -> SelfTestReport:
    data = _json(response)
    results = tuple(
        InvariantCheck(str(r.get("id", "")), str(r.get("status", "")), str(r.get("detail", "")))
        for r in data.get("results", [])
    )
    return SelfTestReport(bool(data.get("passed", False)), str(data.get("ran_at", "")), results)


# --------------------------------------------------------------------------- requests
@dataclass(frozen=True)
class _Call[T]:
    method: str
    path: str
    parse: Callable[[httpx.Response], T]
    json: Any = None
    content: bytes | None = None
    headers: Mapping[str, str] = field(default_factory=dict)
    params: Mapping[str, str] = field(default_factory=dict)
    ok: tuple[int, ...] = (200,)  # statuses that are answers, not errors


def _texts(text: str | Sequence[str]) -> dict[str, Any]:
    if isinstance(text, str):
        return {"text": text}
    if isinstance(text, bytes | bytearray) or not isinstance(text, Sequence):
        raise TypeError(f"text must be a str or a sequence of str, not {type(text).__name__}")
    texts = list(text)
    if not texts:
        raise InvalidRequestError("give at least one text")
    for i, item in enumerate(texts):
        if not isinstance(item, str):
            raise TypeError(f"texts[{i}] is {type(item).__name__}, not str")
    return {"texts": texts}


def _privacy_headers(mode: Mode | None, context_repair: bool | None, override: bool) -> dict[str, str]:
    """The headers that ask for a mode or an override; the gateway decides whether they apply."""
    headers: dict[str, str] = {}
    if mode is not None:
        if mode not in ("relational", "generic"):
            raise InvalidRequestError("mode must be relational or generic")
        headers["x-harpo-mode"] = mode
    if context_repair is not None:
        headers["x-harpo-context-repair"] = "true" if context_repair else "false"
    if override:
        headers["x-harpo-override"] = "true"
    return headers


def _policy_body(
    entities: Mapping[str, Action] | None,
    custom_types: Sequence[CustomType | Mapping[str, Any]] | None,
    detectors: Mapping[str, bool] | None,
) -> dict[str, Any]:
    body: dict[str, Any] = {}
    if entities is not None:
        body["entities"] = {str(getattr(k, "value", k)): v for k, v in entities.items()}
    if custom_types is not None:
        body["custom_types"] = [c.as_config() if isinstance(c, CustomType) else dict(c) for c in custom_types]
    if detectors is not None:
        body["detectors"] = dict(detectors)
    return body


def _no_stream(body: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(body, Mapping):
        raise TypeError(f"body must be a mapping, not {type(body).__name__}")
    if body.get("stream") is True:
        raise InvalidRequestError("streaming is not supported here: use the provider's SDK with the gateway's base URL")
    return dict(body)


class _Base:
    """Configuration and the request builders both clients share."""

    def __init__(self, base_url: str | None, api_key: str | None, headers: Mapping[str, str] | None) -> None:
        url = (base_url or os.environ.get("HARPO_URL") or DEFAULT_URL).rstrip("/")
        if not url.startswith(("http://", "https://")):
            raise InvalidRequestError("base_url must start with http:// or https://")
        self.base_url = url
        self._api_key = api_key if api_key is not None else os.environ.get("HARPO_KEY")
        self._extra_headers = dict(headers or {})

    def __repr__(self) -> str:
        key = "<set>" if self._api_key else None
        return f"{type(self).__name__}(base_url={self.base_url!r}, api_key={key})"

    @property
    def openai_base_url(self) -> str:
        """For OpenAI-compatible clients: ``OpenAI(base_url=client.openai_base_url, api_key=<gateway key>)``."""
        return f"{self.base_url}/v1"

    @property
    def anthropic_base_url(self) -> str:
        """For Anthropic-compatible clients: ``Anthropic(base_url=client.anthropic_base_url, api_key=<key>)``."""
        return self.base_url

    def _headers(self, call: _Call[Any]) -> dict[str, str]:
        headers = {"user-agent": f"harpo-redact-sdk/{__version__}", **self._extra_headers}
        if self._api_key:
            headers["authorization"] = f"Bearer {self._api_key}"
        headers.update(call.headers)
        return headers

    def _answer(self, call: _Call[_T], response: httpx.Response) -> _T:
        if response.status_code not in call.ok:
            raise _error(response)
        return call.parse(response)

    @staticmethod
    def _unreachable(base_url: str, exc: httpx.HTTPError) -> GatewayUnavailableError:
        if isinstance(exc, httpx.TimeoutException):
            return GatewayUnavailableError(f"the gateway at {base_url} did not answer in time", error_type="timeout")
        return GatewayUnavailableError(
            f"could not reach the gateway at {base_url} ({type(exc).__name__})", error_type="connection_error"
        )

    # ------------------------------------------------------------------ the calls
    def _c_health(self) -> _Call[Health]:
        return _Call("GET", "/healthz", _health)

    def _c_ready(self) -> _Call[Readiness]:
        return _Call("GET", "/readyz", _readiness, ok=(200, 503))

    def _c_policy(self) -> _Call[PolicyView]:
        return _Call("GET", "/v1/policy", _policy)

    def _c_scan(
        self,
        text: str | Sequence[str],
        mode: Mode | None,
        context_repair: bool | None,
        layers: Literal["full", "fast"],
        override: bool,
    ) -> _Call[ScanResult]:
        body: dict[str, Any] = {**_texts(text), "layers": layers, "override": override}
        if mode is not None:
            if mode not in ("relational", "generic"):
                raise InvalidRequestError("mode must be relational or generic")
            body["mode"] = mode
        if context_repair is not None:
            body["context_repair"] = context_repair
        if layers not in ("full", "fast"):
            raise InvalidRequestError("layers must be full or fast")
        return _Call("POST", "/v1/scan", _scan, json=body)

    def _c_document(
        self,
        source: bytes | str | os.PathLike[str],
        filename: str | None,
        content_type: str | None,
        mode: Mode | None,
        context_repair: bool | None,
        override: bool,
        file: bool,
    ) -> _Call[DocumentResult]:
        if isinstance(source, bytes | bytearray | memoryview):
            data, name = bytes(source), filename or ""
        elif isinstance(source, str | os.PathLike):
            path = Path(source)
            data, name = path.read_bytes(), filename or path.name
        else:
            raise TypeError(f"source must be a path or the file's bytes, not {type(source).__name__}")
        kind = content_type or (mimetypes.guess_type(name)[0] if name else None) or "application/octet-stream"
        # The name goes in a header, percent-encoded: a URL is logged by every proxy on the way, a header is not.
        headers = {"content-type": kind, "x-harpo-response": "json", **_privacy_headers(mode, context_repair, override)}
        if name:
            headers["x-harpo-filename"] = quote(name)
        params = {} if file else {"file": "false"}
        return _Call("POST", "/v1/documents/redact", _document, content=data, headers=headers, params=params)

    def _c_chat(
        self, body: Mapping[str, Any], mode: Mode | None, context_repair: bool | None, override: bool
    ) -> _Call[ProxyResponse]:
        headers = _privacy_headers(mode, context_repair, override)
        return _Call("POST", "/v1/chat/completions", _proxy, json=_no_stream(body), headers=headers)

    def _c_message(
        self,
        body: Mapping[str, Any],
        mode: Mode | None,
        context_repair: bool | None,
        override: bool,
        anthropic_version: str,
    ) -> _Call[ProxyResponse]:
        headers = {"anthropic-version": anthropic_version, **_privacy_headers(mode, context_repair, override)}
        return _Call("POST", "/v1/messages", _proxy, json=_no_stream(body), headers=headers)

    def _c_models(self, style: Style) -> _Call[list[str]]:
        if style not in ("openai", "anthropic"):
            raise InvalidRequestError("style must be openai or anthropic")
        headers = {"anthropic-version": ANTHROPIC_VERSION} if style == "anthropic" else {}
        return _Call("GET", "/v1/models", _models, headers=headers)

    def _c_egress(
        self, style: Style, body: Mapping[str, Any], mode: Mode | None, override: bool
    ) -> _Call[EgressPreview]:
        if style not in ("openai", "anthropic"):
            raise InvalidRequestError("style must be openai or anthropic")
        if not isinstance(body, Mapping):
            raise TypeError(f"body must be a mapping, not {type(body).__name__}")
        headers = _privacy_headers(mode, None, override)
        return _Call("POST", "/v1/egress/preview", _egress, json={"style": style, "body": dict(body)}, headers=headers)

    def _c_trace(self, text: str) -> _Call[Trace]:
        if not isinstance(text, str):
            raise TypeError(f"text must be a str, not {type(text).__name__}")
        return _Call("POST", "/v1/lab/detect", _trace, json={"text": text})

    def _c_stats(self, recent: int) -> _Call[dict[str, Any]]:
        return _Call("GET", "/v1/stats", _dict, params={"recent": str(int(recent))})

    def _c_get(self, path: str) -> _Call[dict[str, Any]]:
        return _Call("GET", path, _dict)

    def _c_providers(self) -> _Call[list[dict[str, Any]]]:
        return _Call("GET", "/v1/providers", _providers)

    def _c_check_provider(self, name: str) -> _Call[ProviderCheck]:
        return _Call("POST", f"/v1/providers/{quote(name, safe='')}/check", _provider_check)

    def _c_list_keys(self) -> _Call[tuple[KeyInfo, ...]]:
        return _Call("GET", "/v1/keys", _keys)

    def _c_generate_key(
        self,
        key_id: str,
        admin: bool,
        can_override: bool,
        expires_at: datetime | str | None,
        requests_per_minute: int | None,
    ) -> _Call[GatewayKey]:
        spec: dict[str, Any] = {"id": key_id, "admin": admin, "can_override": can_override}
        if expires_at is not None:
            spec["expires_at"] = expires_at.isoformat() if isinstance(expires_at, datetime) else expires_at
        if requests_per_minute is not None:
            spec["requests_per_minute"] = requests_per_minute

        def parse(response: httpx.Response) -> GatewayKey:
            data = _json(response)
            return GatewayKey(id=key_id, key=str(data["key"]), sha256=str(data["sha256"]), yaml=str(data["yaml"]))

        return _Call("POST", "/v1/keys/generate", parse, json=spec)

    def _c_validate_config(self, yaml_text: str) -> _Call[ConfigReport]:
        if not isinstance(yaml_text, str):
            raise TypeError(f"yaml_text must be a str, not {type(yaml_text).__name__}")
        return _Call("POST", "/v1/config/validate", _config_report, json={"yaml": yaml_text})

    def _c_analysis(self) -> _Call[tuple[ConfigFinding, ...]]:
        return _Call("GET", "/v1/config/analysis", _analysis)

    def _c_set_live_policy(
        self,
        entities: Mapping[str, Action] | None,
        custom_types: Sequence[CustomType | Mapping[str, Any]] | None,
        detectors: Mapping[str, bool] | None,
    ) -> _Call[dict[str, Any]]:
        return _Call("PUT", "/v1/policy/live", _dict, json=_policy_body(entities, custom_types, detectors))

    def _c_reset_live_policy(self) -> _Call[dict[str, Any]]:
        return _Call("DELETE", "/v1/policy/live", _dict)

    def _c_preview_policy(
        self,
        text: str,
        entities: Mapping[str, Action] | None,
        custom_types: Sequence[CustomType | Mapping[str, Any]] | None,
        detectors: Mapping[str, bool] | None,
    ) -> _Call[PolicyPreview]:
        if not isinstance(text, str):
            raise TypeError(f"text must be a str, not {type(text).__name__}")
        body: dict[str, Any] = {"text": text}
        if entities is not None or custom_types is not None or detectors is not None:
            body["policy"] = _policy_body(entities, custom_types, detectors)
        return _Call("POST", "/v1/policy/preview", _policy_preview, json=body)

    def _c_selftest(self) -> _Call[SelfTestReport]:
        return _Call("POST", "/v1/selftest", _selftest)

    def _c_selftest_suites(self, suites: Sequence[str] | None) -> _Call[dict[str, Any]]:
        return _Call("POST", "/v1/selftest/suites", _dict, json={"suites": list(suites or [])})


class GatewayClient(_Base):
    """A running gateway, from Python: scans, documents, requests to providers through it, and its control plane.

    ::

        from harpo_redact.sdk import GatewayClient

        with GatewayClient("http://127.0.0.1:8080", api_key="harpo_...") as gateway:
            result = gateway.scan("Mail jane.doe@example.com")

    ``base_url`` defaults to ``$HARPO_URL`` (else http://127.0.0.1:8080) and ``api_key`` to ``$HARPO_KEY``: a gateway
    key, sent as ``Authorization: Bearer``. Calls marked *admin* need an admin key. Errors raise the SDK's exceptions
    (``AuthenticationError``, ``BlockedError``, ...), whose messages never quote what you sent. ``http_client`` lets
    you bring a configured ``httpx.Client`` (proxies, client certificates); it is then yours to close."""

    def __init__(
        self,
        base_url: str | None = None,
        *,
        api_key: str | None = None,
        timeout: float = 60.0,
        verify: bool | ssl.SSLContext = True,
        headers: Mapping[str, str] | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        super().__init__(base_url, api_key, headers)
        self._owns_client = http_client is None
        self._http = http_client or httpx.Client(timeout=timeout, verify=verify, follow_redirects=False)

    def _run(self, call: _Call[_T]) -> _T:
        try:
            response = self._http.request(
                call.method,
                self.base_url + call.path,
                json=call.json,
                content=call.content,
                headers=self._headers(call),
                params=call.params or None,
            )
        except httpx.HTTPError as exc:
            raise self._unreachable(self.base_url, exc) from None
        return self._answer(call, response)

    def close(self) -> None:
        if self._owns_client:
            self._http.close()

    def __enter__(self) -> GatewayClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ any key
    def health(self) -> Health:
        """``GET /healthz``: the process answers. No key needed."""
        return self._run(self._c_health())

    def ready(self) -> Readiness:
        """``GET /readyz``: whether it can serve (models loaded, required layers and provider keys present)."""
        return self._run(self._c_ready())

    def policy(self) -> PolicyView:
        """``GET /v1/policy``: the policy the gateway scans with, and what this key may do."""
        return self._run(self._c_policy())

    def scan(
        self,
        text: str | Sequence[str],
        /,
        *,
        mode: Mode | None = None,
        context_repair: bool | None = None,
        layers: Literal["full", "fast"] = "full",
        override: bool = False,
    ) -> ScanResult:
        """``POST /v1/scan``: what the gateway finds and decides for these texts. Nothing is sent to a provider.
        Returned even when the policy blocks: check ``result.blocked``."""
        return self._run(self._c_scan(text, mode, context_repair, layers, override))

    def redact_document(
        self,
        source: bytes | str | os.PathLike[str],
        /,
        *,
        filename: str | None = None,
        content_type: str | None = None,
        mode: Mode | None = None,
        context_repair: bool | None = None,
        override: bool = False,
        file: bool = True,
    ) -> DocumentResult:
        """``POST /v1/documents/redact``: a redacted PDF, Word, Excel, PowerPoint or text file, verified before
        release. ``BlockedError`` when the policy blocks it, ``DocumentError`` when it cannot be processed."""
        return self._run(self._c_document(source, filename, content_type, mode, context_repair, override, file))

    def chat_completion(
        self,
        body: Mapping[str, Any],
        *,
        mode: Mode | None = None,
        context_repair: bool | None = None,
        override: bool = False,
    ) -> ProxyResponse:
        """``POST /v1/chat/completions``: an OpenAI-style request through the gateway to the provider, sanitized and
        verified on the way out. ``BlockedError`` when the policy blocks it. Not streamed: for streaming, point the
        provider's SDK at :attr:`openai_base_url`."""
        return self._run(self._c_chat(body, mode, context_repair, override))

    def message(
        self,
        body: Mapping[str, Any],
        *,
        mode: Mode | None = None,
        context_repair: bool | None = None,
        override: bool = False,
        anthropic_version: str = ANTHROPIC_VERSION,
    ) -> ProxyResponse:
        """``POST /v1/messages``: an Anthropic-style request through the gateway (see :meth:`chat_completion`)."""
        return self._run(self._c_message(body, mode, context_repair, override, anthropic_version))

    def models(self, style: Style = "openai") -> list[str]:
        """``GET /v1/models``: the models this gateway routes, in one API style."""
        return self._run(self._c_models(style))

    def preview_egress(
        self, style: Style, body: Mapping[str, Any], *, mode: Mode | None = None, override: bool = False
    ) -> EgressPreview:
        """``POST /v1/egress/preview``: exactly what the gateway would send for this request, without sending it."""
        return self._run(self._c_egress(style, body, mode, override))

    def trace(self, text: str, /) -> Trace:
        """``POST /v1/lab/detect``: one sample through the detection stages. Nothing is stored, logged or counted."""
        return self._run(self._c_trace(text))

    def stats(self, *, recent: int = 60) -> dict[str, Any]:
        """``GET /v1/stats``: content-free activity (all keys for an admin key, this key's otherwise)."""
        return self._run(self._c_stats(recent))

    # ------------------------------------------------------------------ admin
    def system(self) -> dict[str, Any]:
        """*Admin.* ``GET /v1/system``: version, readiness, detection, documents, upstreams and limits."""
        return self._run(self._c_get("/v1/system"))

    def providers(self) -> list[dict[str, Any]]:
        """*Admin.* ``GET /v1/providers``: each upstream with its settings and traffic."""
        return self._run(self._c_providers())

    def check_provider(self, name: str) -> ProviderCheck:
        """*Admin.* ``POST /v1/providers/{name}/check``: a content-free connection test with the configured key."""
        return self._run(self._c_check_provider(name))

    def list_keys(self) -> tuple[KeyInfo, ...]:
        """*Admin.* ``GET /v1/keys``: the gateway keys, by id and fingerprint, with their use."""
        return self._run(self._c_list_keys())

    def generate_key(
        self,
        key_id: str,
        *,
        admin: bool = False,
        can_override: bool = False,
        expires_at: datetime | str | None = None,
        requests_per_minute: int | None = None,
    ) -> GatewayKey:
        """*Admin.* ``POST /v1/keys/generate``: a new key, shown once. The gateway does not store it: add ``yaml`` to
        ``auth.keys`` in its configuration."""
        return self._run(self._c_generate_key(key_id, admin, can_override, expires_at, requests_per_minute))

    def effective_config(self) -> dict[str, Any]:
        """*Admin.* ``GET /v1/config/effective``: the running configuration, key hashes shortened and terms hidden."""
        return self._run(self._c_get("/v1/config/effective"))

    def validate_config(self, yaml_text: str) -> ConfigReport:
        """*Admin.* ``POST /v1/config/validate``: check a configuration against the running one. Nothing is saved."""
        return self._run(self._c_validate_config(yaml_text))

    def config_analysis(self) -> tuple[ConfigFinding, ...]:
        """*Admin.* ``GET /v1/config/analysis``: hardening findings on the running configuration."""
        return self._run(self._c_analysis())

    def live_policy(self) -> dict[str, Any]:
        """*Admin.* ``GET /v1/policy/live``: the Policy page's state, every type's action now and in the file."""
        return self._run(self._c_get("/v1/policy/live"))

    def set_live_policy(
        self,
        *,
        entities: Mapping[str, Action] | None = None,
        custom_types: Sequence[CustomType | Mapping[str, Any]] | None = None,
        detectors: Mapping[str, bool] | None = None,
    ) -> dict[str, Any]:
        """*Admin.* ``PUT /v1/policy/live``: save and apply a live policy, on every worker, without a restart.
        Keys stay redacted. The change is audited with this key's id."""
        return self._run(self._c_set_live_policy(entities, custom_types, detectors))

    def reset_live_policy(self) -> dict[str, Any]:
        """*Admin.* ``DELETE /v1/policy/live``: back to the configuration file's policy."""
        return self._run(self._c_reset_live_policy())

    def preview_policy(
        self,
        text: str,
        /,
        *,
        entities: Mapping[str, Action] | None = None,
        custom_types: Sequence[CustomType | Mapping[str, Any]] | None = None,
        detectors: Mapping[str, bool] | None = None,
    ) -> PolicyPreview:
        """*Admin.* ``POST /v1/policy/preview``: a text through a draft policy. Nothing is sent, saved or recorded."""
        return self._run(self._c_preview_policy(text, entities, custom_types, detectors))

    def selftest(self) -> SelfTestReport:
        """*Admin.* ``POST /v1/selftest``: canaries through the live request path, one check per invariant."""
        return self._run(self._c_selftest())

    def selftest_suites(self, suites: Sequence[str] | None = None) -> dict[str, Any]:
        """*Admin.* ``POST /v1/selftest/suites``: the self-test by subsystem (all of them, or those named)."""
        return self._run(self._c_selftest_suites(suites))

    def presets(self) -> dict[str, Any]:
        """*Admin.* ``GET /v1/setup/presets``: the provider presets ``harpo init`` uses."""
        return self._run(self._c_get("/v1/setup/presets"))

    def diagnostics(self) -> dict[str, Any]:
        """*Admin.* ``GET /v1/diagnostics``: a content-free bundle for an issue report."""
        return self._run(self._c_get("/v1/diagnostics"))

    def attention(self) -> dict[str, Any]:
        """*Admin.* ``GET /v1/attention``: actionable states and the posture timeline."""
        return self._run(self._c_get("/v1/attention"))


class AsyncGatewayClient(_Base):
    """:class:`GatewayClient` for asyncio code: the same calls, as coroutines.

    ::

        async with AsyncGatewayClient(api_key="harpo_...") as gateway:
            result = await gateway.scan("Mail jane.doe@example.com")
    """

    def __init__(
        self,
        base_url: str | None = None,
        *,
        api_key: str | None = None,
        timeout: float = 60.0,
        verify: bool | ssl.SSLContext = True,
        headers: Mapping[str, str] | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__(base_url, api_key, headers)
        self._owns_client = http_client is None
        self._http = http_client or httpx.AsyncClient(timeout=timeout, verify=verify, follow_redirects=False)

    async def _run(self, call: _Call[_T]) -> _T:
        try:
            response = await self._http.request(
                call.method,
                self.base_url + call.path,
                json=call.json,
                content=call.content,
                headers=self._headers(call),
                params=call.params or None,
            )
        except httpx.HTTPError as exc:
            raise self._unreachable(self.base_url, exc) from None
        return self._answer(call, response)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._http.aclose()

    async def __aenter__(self) -> AsyncGatewayClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def health(self) -> Health:
        """See :meth:`GatewayClient.health`."""
        return await self._run(self._c_health())

    async def ready(self) -> Readiness:
        """See :meth:`GatewayClient.ready`."""
        return await self._run(self._c_ready())

    async def policy(self) -> PolicyView:
        """See :meth:`GatewayClient.policy`."""
        return await self._run(self._c_policy())

    async def scan(
        self,
        text: str | Sequence[str],
        /,
        *,
        mode: Mode | None = None,
        context_repair: bool | None = None,
        layers: Literal["full", "fast"] = "full",
        override: bool = False,
    ) -> ScanResult:
        """See :meth:`GatewayClient.scan`."""
        return await self._run(self._c_scan(text, mode, context_repair, layers, override))

    async def redact_document(
        self,
        source: bytes | str | os.PathLike[str],
        /,
        *,
        filename: str | None = None,
        content_type: str | None = None,
        mode: Mode | None = None,
        context_repair: bool | None = None,
        override: bool = False,
        file: bool = True,
    ) -> DocumentResult:
        """See :meth:`GatewayClient.redact_document`."""
        return await self._run(self._c_document(source, filename, content_type, mode, context_repair, override, file))

    async def chat_completion(
        self,
        body: Mapping[str, Any],
        *,
        mode: Mode | None = None,
        context_repair: bool | None = None,
        override: bool = False,
    ) -> ProxyResponse:
        """See :meth:`GatewayClient.chat_completion`."""
        return await self._run(self._c_chat(body, mode, context_repair, override))

    async def message(
        self,
        body: Mapping[str, Any],
        *,
        mode: Mode | None = None,
        context_repair: bool | None = None,
        override: bool = False,
        anthropic_version: str = ANTHROPIC_VERSION,
    ) -> ProxyResponse:
        """See :meth:`GatewayClient.message`."""
        return await self._run(self._c_message(body, mode, context_repair, override, anthropic_version))

    async def models(self, style: Style = "openai") -> list[str]:
        """See :meth:`GatewayClient.models`."""
        return await self._run(self._c_models(style))

    async def preview_egress(
        self, style: Style, body: Mapping[str, Any], *, mode: Mode | None = None, override: bool = False
    ) -> EgressPreview:
        """See :meth:`GatewayClient.preview_egress`."""
        return await self._run(self._c_egress(style, body, mode, override))

    async def trace(self, text: str, /) -> Trace:
        """See :meth:`GatewayClient.trace`."""
        return await self._run(self._c_trace(text))

    async def stats(self, *, recent: int = 60) -> dict[str, Any]:
        """See :meth:`GatewayClient.stats`."""
        return await self._run(self._c_stats(recent))

    async def system(self) -> dict[str, Any]:
        """See :meth:`GatewayClient.system`."""
        return await self._run(self._c_get("/v1/system"))

    async def providers(self) -> list[dict[str, Any]]:
        """See :meth:`GatewayClient.providers`."""
        return await self._run(self._c_providers())

    async def check_provider(self, name: str) -> ProviderCheck:
        """See :meth:`GatewayClient.check_provider`."""
        return await self._run(self._c_check_provider(name))

    async def list_keys(self) -> tuple[KeyInfo, ...]:
        """See :meth:`GatewayClient.list_keys`."""
        return await self._run(self._c_list_keys())

    async def generate_key(
        self,
        key_id: str,
        *,
        admin: bool = False,
        can_override: bool = False,
        expires_at: datetime | str | None = None,
        requests_per_minute: int | None = None,
    ) -> GatewayKey:
        """See :meth:`GatewayClient.generate_key`."""
        return await self._run(self._c_generate_key(key_id, admin, can_override, expires_at, requests_per_minute))

    async def effective_config(self) -> dict[str, Any]:
        """See :meth:`GatewayClient.effective_config`."""
        return await self._run(self._c_get("/v1/config/effective"))

    async def validate_config(self, yaml_text: str) -> ConfigReport:
        """See :meth:`GatewayClient.validate_config`."""
        return await self._run(self._c_validate_config(yaml_text))

    async def config_analysis(self) -> tuple[ConfigFinding, ...]:
        """See :meth:`GatewayClient.config_analysis`."""
        return await self._run(self._c_analysis())

    async def live_policy(self) -> dict[str, Any]:
        """See :meth:`GatewayClient.live_policy`."""
        return await self._run(self._c_get("/v1/policy/live"))

    async def set_live_policy(
        self,
        *,
        entities: Mapping[str, Action] | None = None,
        custom_types: Sequence[CustomType | Mapping[str, Any]] | None = None,
        detectors: Mapping[str, bool] | None = None,
    ) -> dict[str, Any]:
        """See :meth:`GatewayClient.set_live_policy`."""
        return await self._run(self._c_set_live_policy(entities, custom_types, detectors))

    async def reset_live_policy(self) -> dict[str, Any]:
        """See :meth:`GatewayClient.reset_live_policy`."""
        return await self._run(self._c_reset_live_policy())

    async def preview_policy(
        self,
        text: str,
        /,
        *,
        entities: Mapping[str, Action] | None = None,
        custom_types: Sequence[CustomType | Mapping[str, Any]] | None = None,
        detectors: Mapping[str, bool] | None = None,
    ) -> PolicyPreview:
        """See :meth:`GatewayClient.preview_policy`."""
        return await self._run(self._c_preview_policy(text, entities, custom_types, detectors))

    async def selftest(self) -> SelfTestReport:
        """See :meth:`GatewayClient.selftest`."""
        return await self._run(self._c_selftest())

    async def selftest_suites(self, suites: Sequence[str] | None = None) -> dict[str, Any]:
        """See :meth:`GatewayClient.selftest_suites`."""
        return await self._run(self._c_selftest_suites(suites))

    async def presets(self) -> dict[str, Any]:
        """See :meth:`GatewayClient.presets`."""
        return await self._run(self._c_get("/v1/setup/presets"))

    async def diagnostics(self) -> dict[str, Any]:
        """See :meth:`GatewayClient.diagnostics`."""
        return await self._run(self._c_get("/v1/diagnostics"))

    async def attention(self) -> dict[str, Any]:
        """See :meth:`GatewayClient.attention`."""
        return await self._run(self._c_get("/v1/attention"))
