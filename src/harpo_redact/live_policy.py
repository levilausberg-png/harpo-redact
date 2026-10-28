"""Live policy: what the console can change without a restart.

The configuration file stays as written. Changes made on the console's Policy page (the action for each type,
custom types, and which detector families of the detection library run) are saved to ``policy.live_file`` and laid
over the configuration. Every gateway process watches that file, so a change reaches all workers within seconds and
survives a restart.

Keys are always redacted: the live policy cannot mention PRIVATE_KEY or SECRET, cannot switch off a credential
detector, and every other rule of the configuration (critical types are never allowed, custom names are unique) is
checked again on the combined result before anything is saved or applied.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import library
from .config import CustomType, Settings
from .entities import ALWAYS_REDACTED, CRITICAL_TYPES, EntityType
from .risk import LABELS

Action = Literal["redact", "block", "allow"]
WATCH_INTERVAL_S = 2.0
_HEADER = (
    "# Harpo live policy. Written by the console's Policy page and laid over the configuration file.\n"
    "# Keys are always redacted; nothing here can change that. Delete this file to go back to the configuration.\n"
)


class LivePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    entities: dict[EntityType, Action] = Field(default_factory=dict)
    custom_types: list[CustomType] | None = None  # None: keep the configuration's custom types
    detectors: dict[str, bool] = Field(default_factory=dict)  # detection library family id -> on or off
    updated_at: str | None = None
    updated_by: str | None = None  # the gateway key id that saved it

    @field_validator("entities", mode="after")
    @classmethod
    def _keys_stay_redacted(cls, value: dict[EntityType, Action]) -> dict[EntityType, Action]:
        for etype in value:
            if etype in ALWAYS_REDACTED:
                raise ValueError(f"{etype.value} is always redacted; it is not part of the live policy")
        return value

    @field_validator("detectors", mode="after")
    @classmethod
    def _switchable(cls, value: dict[str, bool]) -> dict[str, bool]:
        for family_id in value:
            family = library.BY_ID.get(family_id)
            if family is None:
                raise ValueError(f"{family_id} is not a detector family (see /v1/system: detection.library)")
            if family_id not in library.LIVE_IDS:
                why = family.locked or "it loads a model, so it is set in the configuration file and needs a restart"
                raise ValueError(f"{family.title} cannot be switched on the live policy: {why}")
        return value


@dataclass(frozen=True, slots=True)
class FileState:
    """What the file looked like when it was last read, to notice changes cheaply."""

    exists: bool
    mtime_ns: int = 0
    size: int = 0
    inode: int = 0


def file_state(path: str | None) -> FileState:
    if not path:
        return FileState(False)
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return FileState(False)
    return FileState(True, st.st_mtime_ns, st.st_size, st.st_ino)


def load(path: str) -> LivePolicy | None:
    """The live policy in ``path``, or None when there is no file. Raises ValueError when it is not valid."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"{path} is not valid YAML: {exc}") from None
    if not isinstance(data, dict):
        raise ValueError(f"{path} must hold a mapping")
    return LivePolicy.model_validate(data)


def apply(base: Settings, live: LivePolicy | None) -> Settings:
    """The configuration with the live policy laid over it, validated as a whole."""
    if live is None or (not live.entities and live.custom_types is None and not live.detectors):
        return base
    data = base.model_dump()
    entities = data["policy"]["entities"]
    for etype, action in live.entities.items():
        entities[etype] = {**entities.get(etype, {"overridable": False}), "action": action}
    if live.custom_types is not None:
        data["detection"]["custom_types"] = [c.model_dump() for c in live.custom_types]
    library.set_flags(data, live.detectors)
    merged = Settings.model_validate(data)
    # Notices describe the configuration file; the live policy cannot add any.
    merged.policy._ignored = list(base.policy._ignored)
    merged.detection.secrets._ignored = list(base.detection.secrets._ignored)
    merged.detection._ignored = list(base.detection._ignored)
    return merged


def to_yaml(live: LivePolicy) -> str:
    body = live.model_dump(mode="json", exclude_none=True)
    return _HEADER + yaml.safe_dump(body, sort_keys=False, allow_unicode=True)


def config_snippet(live: LivePolicy) -> str:
    """The same policy as lines for the configuration file, for a gateway that cannot save from the console."""
    body: dict[str, Any] = {}
    if live.entities:
        body["policy"] = {"entities": {t.value: {"action": a} for t, a in live.entities.items()}}
    detection: dict[str, Any] = {}
    for family_id, on in live.detectors.items():
        node = detection
        path = library.BY_ID[family_id].setting or ()
        for part in path[:-1]:
            node = node.setdefault(part, {})
        node[path[-1]] = on
    if live.custom_types is not None:
        detection["custom_types"] = [c.model_dump(mode="json") for c in live.custom_types]
    if detection:
        body["detection"] = detection
    if not body:
        return "# Nothing differs from the configuration file.\n"
    return yaml.safe_dump(body, sort_keys=False, allow_unicode=True)


def save(path: str, live: LivePolicy) -> FileState:
    """Write atomically (a temporary file, then a rename), readable by this user only.

    Returns the state of the file this call wrote, taken before the rename: if another worker's rename lands right
    after ours, the watcher sees a different file and loads it, instead of taking it for our own."""
    target = Path(path)
    fd, tmp = tempfile.mkstemp(prefix=".policy.", suffix=".tmp", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(to_yaml(live))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        st = os.stat(tmp)
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return FileState(True, st.st_mtime_ns, st.st_size, st.st_ino)


def remove(path: str) -> None:
    Path(path).unlink(missing_ok=True)


def writable(path: str | None) -> tuple[bool, str | None]:
    """Whether the console may save here, and if not, why."""
    if not path:
        return False, "policy.live_file is not set, so changes cannot be saved from the console."
    target = Path(path)
    folder = target.parent
    if not folder.is_dir():
        return False, f"The folder {folder} does not exist."
    if target.exists() and not os.access(target, os.W_OK):
        return False, f"{target} is read-only for the gateway."
    if not os.access(folder, os.W_OK | os.X_OK):
        return False, f"The folder {folder} is read-only for the gateway."
    return True, None


def stamp(live: LivePolicy, key_id: str) -> LivePolicy:
    now = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return live.model_copy(update={"updated_at": now, "updated_by": key_id})


def describe(base: Settings, effective: Settings, live: LivePolicy | None, path: str | None) -> dict[str, Any]:
    """The editor's view: every type with its action now and in the file, custom types, and where it is saved."""
    ok, reason = writable(path)
    types = []
    for etype in EntityType:
        now = effective.policy.entities[etype]
        configured = base.policy.entities[etype]
        if etype in ALWAYS_REDACTED:
            choices: list[str] = []
        elif etype in CRITICAL_TYPES:
            choices = ["redact", "block"]
        else:
            choices = ["redact", "block", "allow"]
        types.append(
            {
                "type": etype.value,
                "label": LABELS[etype][1],
                "action": now.action,
                "configured": configured.action,
                "changed": bool(live and etype in live.entities and live.entities[etype] != configured.action),
                "overridable": now.overridable,
                "choices": choices,
                "locked": etype in ALWAYS_REDACTED,
            }
        )
    custom_from = "live" if live is not None and live.custom_types is not None else "config"
    return {
        "editable": ok,
        "reason": reason,
        "file": path,
        "exists": bool(path and Path(path).is_file()),
        "updated_at": live.updated_at if live else None,
        "updated_by": live.updated_by if live else None,
        "always_redacted": sorted(t.value for t in ALWAYS_REDACTED),
        "types": types,
        "custom_types": [c.model_dump(mode="json") for c in effective.detection.custom_types],
        "custom_types_from": custom_from,
        "config_custom_types": [c.model_dump(mode="json") for c in base.detection.custom_types],
        "library": library.describe(effective, configured=base),
        "notices": effective.notices(),
    }
