"""The SDK's exceptions. Their messages carry codes, types, counts and setting paths: never a value from a request.

HarpoError
├── ConfigurationError       the configuration is not valid, or a model it needs is missing
├── InvalidRequestError      a bad argument, or a gateway's 400 or 422 (also a ValueError)
├── BlockedError             the policy blocks the content: send nothing
├── DocumentError            a document was refused or could not be processed
└── GatewayError             a gateway answered with an error, or could not be reached
    ├── AuthenticationError        401: no gateway key, or an unknown or expired one
    ├── PermissionDeniedError      403: an admin key is needed, or the model or route is not allowed
    ├── NotFoundError              404
    ├── ConflictError              409
    ├── RequestTooLargeError       413
    ├── RateLimitError             429
    └── GatewayUnavailableError    502, 503, 504, a timeout, or no connection
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ._results import ConfigIssue, Reason, Risk


class HarpoError(Exception):
    """Base class of every exception the SDK raises. ``status`` and ``request_id`` are set when a gateway
    answered: its HTTP status, and the id it logged the request under (``x-harpo-request-id``)."""

    def __init__(self, message: str, *, status: int | None = None, request_id: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.request_id = request_id

    def __str__(self) -> str:
        context = [f"HTTP {self.status}"] if self.status is not None else []
        if self.request_id:
            context.append(f"request {self.request_id}")
        return f"{self.message} ({', '.join(context)})" if context else self.message


class ConfigurationError(HarpoError):
    """The configuration is not valid, or a language model it names is not installed. ``issues`` lists each
    problem with its setting path."""

    def __init__(self, message: str, *, issues: Sequence[ConfigIssue] = ()) -> None:
        super().__init__(message)
        self.issues = tuple(issues)


class InvalidRequestError(HarpoError, ValueError):
    """The request is not valid: an argument, or what a gateway refused with 400 or 422 (``details`` then holds
    the field paths it named)."""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        request_id: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message, status=status, request_id=request_id)
        self.details: Mapping[str, Any] = dict(details or {})


class BlockedError(HarpoError):
    """The policy blocks this content: nothing may be sent. ``reasons`` say why, with types and counts.

    ``overridable`` is true when every block is of a type the policy lets a permitted caller send as a placeholder
    (scan again with ``override=True``); ``override_permitted`` says whether this caller is one."""

    risk = Risk.RED

    def __init__(
        self,
        message: str,
        *,
        reasons: Sequence[Reason],
        blocked_types: Sequence[str] = (),
        overridable: bool = False,
        override_permitted: bool = False,
        status: int | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message, status=status, request_id=request_id)
        self.reasons = tuple(reasons)
        self.blocked_types = tuple(blocked_types)
        self.overridable = overridable
        self.override_permitted = override_permitted

    @property
    def codes(self) -> tuple[str, ...]:
        return tuple(r.code for r in self.reasons)


class DocumentError(HarpoError):
    """A document was refused or could not be processed. ``code`` is stable: unsupported_format, legacy_office,
    format_disabled, too_large, too_many_characters, encrypted, macros, uninspectable_pages, timeout, busy,
    residual_sensitive_data, ..."""

    def __init__(self, code: str, message: str, *, status: int | None = None, request_id: str | None = None) -> None:
        super().__init__(message or code, status=status, request_id=request_id)
        self.code = code


class GatewayError(HarpoError):
    """A gateway answered with an error, or could not be reached. ``type`` is the error type of its answer
    (authentication_error, permission_error, not_ready, ...); ``details`` holds the extra fields it sent."""

    def __init__(
        self,
        message: str,
        *,
        error_type: str = "api_error",
        status: int | None = None,
        request_id: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message, status=status, request_id=request_id)
        self.type = error_type
        self.details: Mapping[str, Any] = dict(details or {})


class AuthenticationError(GatewayError):
    """401: the gateway key is missing, unknown or expired."""


class PermissionDeniedError(GatewayError):
    """403: the key is not an admin key, or the model or route is not allowed by gateway policy."""


class NotFoundError(GatewayError):
    """404: no such route or resource (or a feature that is switched off, such as document redaction)."""


class ConflictError(GatewayError):
    """409: the change conflicts with the gateway's state (a key id in use, a live policy it cannot save)."""


class RequestTooLargeError(GatewayError):
    """413: over one of the gateway's request limits."""


class RateLimitError(GatewayError):
    """429: too many requests for this key. ``retry_after`` is in seconds, when the gateway said."""

    def __init__(self, message: str, *, retry_after: float | None = None, **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class GatewayUnavailableError(GatewayError):
    """502, 503, 504, a timeout, or no connection: the gateway, a detection layer it requires (``type``
    not_ready), or the provider behind it (``type`` upstream_error) is not available."""
