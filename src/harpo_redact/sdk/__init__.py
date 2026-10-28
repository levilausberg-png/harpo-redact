"""Harpo's Python SDK: the supported way to use Harpo from Python code.

Two entry points, each blocking or asyncio:

* :class:`Harpo` / :class:`AsyncHarpo`, the engine in your process: the gateway's own detection, policy, redaction,
  egress verification and document handling, with no server::

      from harpo_redact.sdk import Harpo

      with Harpo() as harpo:
          harpo.redact("Mail jane.doe@example.com")          # 'Mail [EMAIL_1]'

* :class:`GatewayClient` / :class:`AsyncGatewayClient`, a running gateway: scans, documents, requests to providers
  through it, and its control plane, behind its keys::

      from harpo_redact.sdk import GatewayClient

      with GatewayClient("http://127.0.0.1:8080", api_key="harpo_...") as gateway:
          gateway.scan("Mail jane.doe@example.com").text    # 'Mail [EMAIL_1]'

Everything in ``__all__`` is the public, stable API (semantic versioning applies from 2.5.0). The modules below it
whose names start with an underscore, and the rest of ``harpo_redact``, are internal. See docs/SDK.md.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ._client import AsyncGatewayClient, GatewayClient
from ._errors import (
    AuthenticationError,
    BlockedError,
    ConfigurationError,
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
    CustomTypeInfo,
    DocumentResult,
    EgressPreview,
    EngineStatus,
    EntityRule,
    Finding,
    GatewayKey,
    Health,
    InvariantCheck,
    KeyInfo,
    PolicyPreview,
    PolicyView,
    ProviderCheck,
    ProxyResponse,
    Readiness,
    Reason,
    ResponseScan,
    Risk,
    ScannedText,
    ScanResult,
    SelfTestReport,
    Trace,
    Verification,
)

if TYPE_CHECKING:
    from ..entities import EntityType
    from ._config import validate_config
    from ._engine import AsyncHarpo, Harpo, generate_key

# The engine pulls in the detection pipeline and its dependencies; a program that only talks to a gateway does
# not pay for that until it touches one of these names.
_LAZY = {
    "Harpo": "._engine",
    "AsyncHarpo": "._engine",
    "generate_key": "._engine",
    "validate_config": "._config",
    "EntityType": "..entities",
}


def __getattr__(name: str) -> Any:
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    value = getattr(importlib.import_module(module, __name__), name)
    globals()[name] = value
    return value


__all__ = [
    "AsyncGatewayClient",
    "AsyncHarpo",
    "AuthenticationError",
    "BlockedError",
    "ConfigFinding",
    "ConfigIssue",
    "ConfigReport",
    "ConfigurationError",
    "ConflictError",
    "CustomType",
    "CustomTypeInfo",
    "DocumentError",
    "DocumentResult",
    "EgressPreview",
    "EngineStatus",
    "EntityRule",
    "EntityType",
    "Finding",
    "GatewayClient",
    "GatewayError",
    "GatewayKey",
    "GatewayUnavailableError",
    "Harpo",
    "HarpoError",
    "Health",
    "InvalidRequestError",
    "InvariantCheck",
    "KeyInfo",
    "NotFoundError",
    "PermissionDeniedError",
    "PolicyPreview",
    "PolicyView",
    "ProviderCheck",
    "ProxyResponse",
    "RateLimitError",
    "Readiness",
    "Reason",
    "RequestTooLargeError",
    "ResponseScan",
    "Risk",
    "ScanResult",
    "ScannedText",
    "SelfTestReport",
    "Trace",
    "Verification",
    "generate_key",
    "validate_config",
]
