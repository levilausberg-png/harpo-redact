"""Risk verdicts: red stops a request, yellow forwards it with an advisory.

Messages are written on the server so every client shows the same wording.
They describe what was found, never the value itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .entities import EntityType


class Level(StrEnum):
    GREEN = "green"
    YELLOW = "yellow"
    RED = "red"


_RANK = {Level.GREEN: 0, Level.YELLOW: 1, Level.RED: 2}

LABELS: dict[EntityType, tuple[str, str]] = {
    EntityType.PRIVATE_KEY: ("private key", "private keys"),
    EntityType.SECRET: ("API key or password", "API keys or passwords"),
    EntityType.ENCODED_DATA: ("encoded blob with sensitive data", "encoded blobs with sensitive data"),
    EntityType.CREDIT_CARD: ("card number", "card numbers"),
    EntityType.IBAN: ("IBAN", "IBANs"),
    EntityType.US_SSN: ("US Social Security number", "US Social Security numbers"),
    EntityType.NL_BSN: ("Dutch BSN", "Dutch BSNs"),
    EntityType.UK_NINO: ("UK National Insurance number", "UK National Insurance numbers"),
    EntityType.NATIONAL_ID: ("national or tax ID", "national or tax IDs"),
    EntityType.ID_DOCUMENT: ("passport or licence number", "passport or licence numbers"),
    EntityType.ACCOUNT_ID: ("account or record number", "account or record numbers"),
    EntityType.CRYPTO_ADDRESS: ("crypto wallet address", "crypto wallet addresses"),
    EntityType.DEVICE_ID: ("device or vehicle ID", "device or vehicle IDs"),
    EntityType.ADDRESS: ("street address or postcode", "street addresses or postcodes"),
    EntityType.DATE: ("date", "dates"),
    EntityType.EMAIL: ("email address", "email addresses"),
    EntityType.PHONE: ("phone number", "phone numbers"),
    EntityType.IP_ADDRESS: ("IP address", "IP addresses"),
    EntityType.DATE_OF_BIRTH: ("date of birth", "dates of birth"),
    EntityType.PROTECTED_TERM: ("protected term", "protected terms"),
    EntityType.PERSON: ("name", "names"),
    EntityType.ORGANIZATION: ("organisation", "organisations"),
    EntityType.LOCATION: ("place", "places"),
    EntityType.QUASI_ID: ("indirect identifier", "indirect identifiers"),
}


def _names(etype: EntityType | str) -> tuple[str, str]:
    """A built-in type's words, or a custom type's own name ("EMPLOYEE_ID value")."""
    if etype in LABELS:
        return LABELS[EntityType(etype)]
    return f"{etype} value", f"{etype} values"


def label(etype: EntityType | str, count: int) -> str:
    singular, plural = _names(etype)
    return f"{count} {singular if count == 1 else plural}"


@dataclass(frozen=True, slots=True)
class Reason:
    code: str
    level: Level
    message: str
    entity_type: EntityType | str | None = None  # a built-in type, or a custom type's name
    count: int | None = None
    overridable: bool = False

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"code": self.code, "level": self.level.value, "message": self.message}
        if self.entity_type is not None:
            out["entity_type"] = str(self.entity_type)
        if self.count is not None:
            out["count"] = self.count
        if self.level is Level.RED:
            out["overridable"] = self.overridable
        return out


def overall(reasons: list[Reason]) -> Level:
    level = Level.GREEN
    for reason in reasons:
        if _RANK[reason.level] > _RANK[level]:
            level = reason.level
    return level


# --------------------------------------------------------------------------- red
def blocked_entity(etype: EntityType | str, count: int, overridable: bool) -> Reason:
    found = label(etype, count)
    if overridable:
        message = f"Found {found}. Remove it, or acknowledge to send with the value redacted."
    else:
        message = f"Found {found}. Remove it before sending; this block cannot be overridden."
    return Reason("blocked_entity", Level.RED, message, etype, count, overridable)


def unsupported_content(count: int) -> Reason:
    noun = "part" if count == 1 else "parts"
    return Reason(
        "unsupported_content",
        Level.RED,
        f"{count} image, audio or file {noun} can't be inspected, so the request is blocked. Send text only.",
        count=count,
    )


def slm_unavailable(status: str) -> Reason:
    return Reason(
        "slm_unavailable",
        Level.RED,
        f"The local indirect-identifier check failed ({status}) and policy requires it. Try again shortly.",
    )


def scan_budget(kind: str) -> Reason:
    return Reason(
        "scan_budget",
        Level.RED,
        f"The request needs more inspection than the gateway allows ({kind}), so it was not sent. "
        "Split it into smaller requests or raise the limit.",
    )


# --------------------------------------------------------------------------- yellow
def slm_degraded(status: str) -> Reason:
    return Reason(
        "slm_degraded",
        Level.YELLOW,
        f"The local indirect-identifier check was skipped ({status}). Only the deterministic layers ran.",
    )


def context_rot(ratio: float) -> Reason:
    return Reason(
        "context_rot",
        Level.YELLOW,
        f"{round(ratio * 100)}% of the outgoing words are placeholders. The model may lose the thread.",
    )


def collapsed(count: int) -> Reason:
    noun = "sentence mentions" if count == 1 else "sentences mention"
    return Reason(
        "collapsed_sentences",
        Level.YELLOW,
        f"{count} {noun} two different values that now read the same. Use relational mode or context repair.",
        count=count,
    )


def mixed_script(count: int) -> Reason:
    noun = "word mixes" if count == 1 else "words mix"
    return Reason(
        "mixed_script",
        Level.YELLOW,
        f"{count} {noun} Latin with Cyrillic or Greek letters, a common way to disguise text.",
        count=count,
    )


def hidden_characters(count: int) -> Reason:
    noun = "character was" if count == 1 else "characters were"
    return Reason(
        "hidden_characters",
        Level.YELLOW,
        f"{count} invisible formatting {noun} removed before scanning.",
        count=count,
    )


def keys_redacted(count: int) -> Reason:
    """Credentials are always redacted, never blocked: the request goes on, and this says what happened."""
    noun = "key or password was" if count == 1 else "keys or passwords were"
    return Reason(
        "keys_redacted",
        Level.YELLOW,
        f"{count} {noun} replaced with a placeholder before sending. Keys are always redacted.",
        EntityType.SECRET,
        count,
    )


def override_applied(types: list[EntityType | str]) -> Reason:
    names = ", ".join(_names(t)[1] for t in types)
    return Reason(
        "override_applied",
        Level.YELLOW,
        f"Block acknowledged for {names}. The values were still redacted.",
    )


def content_dropped(count: int) -> Reason:
    noun = "part was" if count == 1 else "parts were"
    return Reason(
        "content_dropped",
        Level.YELLOW,
        f"{count} image, audio or file {noun} removed because they can't be inspected.",
        count=count,
    )
