"""Configuration for the local engine: the gateway's own loader and validation, nothing of its own."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

import yaml
from pydantic import ValidationError

from .. import live_policy
from ..config import Settings, load_settings
from ..presets import missing_ner_models
from ._errors import ConfigurationError
from ._results import ConfigIssue, ConfigReport

ConfigSource = Mapping[str, Any] | str | os.PathLike[str] | None
"""A configuration: ``None`` for the defaults, a mapping shaped like ``harpo.yaml``, or the path of a YAML file.
``HARPO_*`` environment variables apply on top, as they do for the gateway."""


def _issues(exc: ValidationError) -> list[ConfigIssue]:
    # Setting paths and pydantic's messages only: the offending input is not repeated.
    return [ConfigIssue(".".join(str(p) for p in e.get("loc", ())), str(e.get("msg", "invalid"))) for e in exc.errors()]


def _invalid(exc: ValidationError) -> ConfigurationError:
    issues = _issues(exc)
    shown = "; ".join(f"{i.path}: {i.message}" if i.path else i.message for i in issues[:5])
    more = f" (and {len(issues) - 5} more)" if len(issues) > 5 else ""
    return ConfigurationError(f"invalid configuration: {shown}{more}", issues=issues)


def load(source: ConfigSource) -> Settings:
    """The configuration as the gateway would read it."""
    try:
        if source is None:
            return Settings.model_validate({})
        if isinstance(source, Mapping):
            return Settings.model_validate(dict(source))
        if isinstance(source, str | os.PathLike):
            return load_settings(os.fspath(source))
    except ValidationError as exc:
        raise _invalid(exc) from None
    except FileNotFoundError as exc:
        raise ConfigurationError(str(exc), issues=[ConfigIssue("", str(exc))]) from None
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        problem = str(getattr(exc, "problem", "") or "not valid YAML")
        line = mark.line + 1 if mark is not None else None
        raise ConfigurationError(
            f"invalid configuration file: {problem}", issues=[ConfigIssue("", problem, line)]
        ) from None
    raise TypeError(f"config must be a mapping, a path or None, not {type(source).__name__}")


def from_environment() -> Settings:
    """What ``harpo serve`` reads: ``$HARPO_CONFIG``, else ./harpo.yaml or ./config/harpo.yaml, plus ``HARPO_*``."""
    try:
        return load_settings()
    except ValidationError as exc:
        raise _invalid(exc) from None
    except FileNotFoundError as exc:
        raise ConfigurationError(str(exc), issues=[ConfigIssue("", str(exc))]) from None


def with_live_policy(settings: Settings) -> tuple[Settings, bool]:
    """``policy.live_file`` laid over the configuration, as the gateway does when it starts; an invalid file stops
    the engine the way it stops the gateway. Returns the result and whether a live policy was applied."""
    path = settings.policy.live_file
    if not path:
        return settings, False
    try:
        live = live_policy.load(path)
        return live_policy.apply(settings, live), live is not None
    except ValidationError as exc:
        issues = _issues(exc)
        shown = "; ".join(f"{i.path}: {i.message}" for i in issues[:5])
        raise ConfigurationError(f"policy.live_file {path} is not valid: {shown}", issues=issues) from None
    except ValueError as exc:
        raise ConfigurationError(
            f"policy.live_file {path} is not valid: {exc}", issues=[ConfigIssue("", str(exc))]
        ) from None


def missing_models(settings: Settings) -> list[str]:
    ner = settings.detection.ner
    return missing_ner_models(ner.model, {str(k): v for k, v in ner.language_models.items()}, ner.enabled)


def validate_config(source: ConfigSource = None) -> ConfigReport:
    """Check a configuration the way ``harpo check-config`` does, without starting anything.

    ``valid`` says whether it loads (``errors`` say why not); ``problems`` are the reasons it must not serve
    production traffic (in production mode, which is the default); ``missing_models`` the language models it names
    that are not installed; ``notices`` the settings it asks for that are not honoured. ``ok`` combines them."""
    try:
        settings = load(source)
    except ConfigurationError as exc:
        return ConfigReport(False, exc.issues or (ConfigIssue("", exc.message),), (), (), ())
    problems = list(settings.production_problems())
    try:
        with_live_policy(settings)
    except ConfigurationError as exc:
        problems.append(exc.message)
    return ConfigReport(True, (), tuple(problems), tuple(settings.notices()), tuple(missing_models(settings)))
