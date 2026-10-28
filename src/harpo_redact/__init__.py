"""Harpo: a self-hosted privacy firewall. Personal data and secrets become placeholders before a prompt reaches a
commercial LLM provider.

Named after Harpocrates, the Hellenistic god of silence and secrets, whose emblem, the rose, gave us *sub rosa*:
what is said under the rose stays there.

From Python, use the SDK (``harpo_redact.sdk``, docs/SDK.md); its entry points are also importable from here.
"""

from typing import TYPE_CHECKING, Any

__version__ = "2.5.0"

# Gateway keys start with this, so that Harpo (and any secret scanner) recognises one wherever it turns up.
KEY_PREFIX = "harpo_"

if TYPE_CHECKING:
    from .sdk import AsyncGatewayClient, AsyncHarpo, GatewayClient, Harpo

_SDK_ENTRY_POINTS = frozenset({"Harpo", "AsyncHarpo", "GatewayClient", "AsyncGatewayClient"})


def __getattr__(name: str) -> Any:
    # Imported on first use: the document worker process imports this package and must stay small.
    if name in _SDK_ENTRY_POINTS:
        from . import sdk

        return getattr(sdk, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["KEY_PREFIX", "AsyncGatewayClient", "AsyncHarpo", "GatewayClient", "Harpo", "__version__"]
