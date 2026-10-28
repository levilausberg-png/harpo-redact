"""Configuration precedence and guards, and the command-line interface."""

from __future__ import annotations

import io
import json
import sys

import pytest
from pydantic import ValidationError

from harpo_redact.__main__ import main
from harpo_redact.config import EntityPolicy, Settings, load_settings
from harpo_redact.entities import EntityType

from .conftest import make_settings

PROD_YAML = """
environment: production
auth:
  enabled: true
  keys: [{id: ops, sha256: "%s"}]
upstreams:
  - {name: openai, style: openai, base_url: "https://api.openai.com/v1", api_key_env: OPENAI_API_KEY, models: ["gpt-*"]}
""" % ("a" * 64)


def test_yaml_then_environment_precedence(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "harpo.yaml"
    path.write_text("environment: development\nserver: {port: 9001}\n")
    monkeypatch.setenv("HARPO_CONFIG", str(path))
    assert load_settings().server.port == 9001
    monkeypatch.setenv("HARPO_SERVER__PORT", "9002")
    assert load_settings().server.port == 9002


def test_unknown_keys_are_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(environment="development", server={"prot": 1})  # type: ignore[arg-type]


def test_invalid_values_are_rejected() -> None:
    with pytest.raises(ValidationError, match="not a valid regular expression"):
        make_settings(detection={"registry": {"patterns": ["(unclosed"]}})
    with pytest.raises(ValidationError, match="must not contain credentials"):
        make_settings(
            upstreams=[{"name": "x", "style": "openai", "base_url": "https://u:p@api.example.com", "models": ["m"]}]
        )
    with pytest.raises(ValidationError, match="unknown phone regions"):
        make_settings(detection={"phone_regions": ["XX"]})


def test_keys_are_always_redacted_whatever_the_file_says() -> None:
    for key in ("PRIVATE_KEY", "SECRET"):
        settings = make_settings(policy={"entities": {key: {"action": "block", "overridable": True}}})
        assert settings.policy.entities[EntityType(key)] == EntityPolicy(action="redact", overridable=False)
        assert any(n.startswith(f"policy.entities.{key}.action: block") for n in settings.notices())
        with pytest.raises(ValidationError, match=f"{key} is always redacted"):
            make_settings(policy={"entities": {key: {"action": "allow"}}})
    switches = {
        "library": False,
        "disabled_rules": ["aws-access-token"],
        "natural_language": False,
        "seed_phrases": False,
    }
    secrets = make_settings(detection={"secrets": switches}).detection.secrets
    assert secrets.library and not secrets.disabled_rules and secrets.natural_language and secrets.seed_phrases
    assert len(make_settings(detection={"secrets": switches}).notices()) == 4
    assert make_settings().notices() == []


def test_production_guards(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "prod.yaml"
    path.write_text(PROD_YAML)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    settings = load_settings(str(path))
    assert any("OPENAI_API_KEY" in p for p in settings.production_problems())
    assert settings.production_problems({"OPENAI_API_KEY": "sk-x"}) == []
    insecure = load_settings(str(path), auth={"enabled": False})
    assert any("auth" in p for p in insecure.production_problems({"OPENAI_API_KEY": "sk-x"}))


def test_cli_hash_key(capsys) -> None:  # type: ignore[no-untyped-def]
    assert main(["hash-key", "--id", "team-a"]) == 0
    out = capsys.readouterr().out
    key = out.split("\n")[1].strip()
    assert key.startswith("harpo_") and "id: team-a" in out and "sha256: " in out


def test_cli_check_config_exit_codes(tmp_path, monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "prod.yaml"
    path.write_text(PROD_YAML)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert main(["check-config", "--config", str(path)]) == 2
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    assert main(["check-config", "--config", str(path)]) == 0
    bad = tmp_path / "bad.yaml"
    bad.write_text("server: {port: 'eighty'}\n")
    assert main(["check-config", "--config", str(bad)]) == 2
    assert "server.port" in capsys.readouterr().err


def test_cli_scan_exit_code(tmp_path, monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "dev.yaml"
    path.write_text(
        "environment: development\ndetection: {ner: {enabled: false}}\npolicy: {entities: {IBAN: {action: block}}}\n"
    )
    monkeypatch.setattr(sys, "stdin", io.StringIO("Mail jane@example.com"))
    assert main(["scan", "--config", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["redacted"] == "Mail [EMAIL_1]"
    monkeypatch.setattr(sys, "stdin", io.StringIO("key sk-proj-7Hq2LmV9xRt4KpZ8wNc3YbF6dJs1GaE5"))
    assert main(["scan", "--config", str(path)]) == 0  # keys are redacted, not blocked
    assert json.loads(capsys.readouterr().out)["redacted"] == "key [SECRET_1]"
    monkeypatch.setattr(sys, "stdin", io.StringIO("Refund to NL91ABNA0417164300"))
    assert main(["scan", "--config", str(path)]) == 1


def test_a_missing_language_model_is_named_with_how_to_install_it(tmp_path, monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    """spaCy models are not on PyPI: after `pip install harpo-redact` alone, serve, scan, redact-file and check-config
    say which model is missing and how to install it, instead of a traceback from spaCy."""
    import importlib.util

    real = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util, "find_spec", lambda name, *a: None if name == "en_core_web_sm" else real(name, *a)
    )
    path = tmp_path / "dev.yaml"
    path.write_text("environment: development\ndetection: {ner: {language_models: {de: not_a_model_xyz}}}\n")
    monkeypatch.setattr(sys, "stdin", io.StringIO("Call Priya Raman"))
    assert main(["scan", "--config", str(path)]) == 2
    err = capsys.readouterr().err
    assert "en_core_web_sm is not installed" in err and "#sha256=1932429db727" in err  # the pinned wheel, hash-checked
    assert "python -m spacy download not_a_model_xyz" in err and "Traceback" not in err
    # only the models the boot scripts and the image ship are said to come with them
    assert err.count("Docker image include it") == 1
    assert main(["serve", "--config", str(path)]) == 2
    assert main(["check-config", "--config", str(path)]) == 2
    assert "problem: the spaCy model en_core_web_sm" in capsys.readouterr().out
    path.write_text("environment: development\ndetection: {ner: {enabled: false}}\n")
    monkeypatch.setattr(sys, "stdin", io.StringIO("Mail jane@example.com"))
    assert main(["scan", "--config", str(path)]) == 0  # without NER nothing is asked for
