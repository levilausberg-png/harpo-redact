"""The name Harpo: the boot banner, gateway keys that announce themselves, and installs from before the rename."""

from __future__ import annotations

import io
import json
import secrets
from pathlib import Path

import pytest

from harpo_redact import KEY_PREFIX, banner
from harpo_redact.config import adopt_legacy_env, load_settings
from harpo_redact.launcher import adopt_legacy_state
from harpo_redact.pipeline import Pipeline

from .conftest import make_settings

FAST = {"detection": {"ner": {"enabled": False}}}
LINES = banner.standard_lines(8080, ["openai", "anthropic"], 226, True, False)


class Terminal(io.StringIO):
    def __init__(self, encoding: str = "utf-8") -> None:
        super().__init__()
        self._encoding = encoding

    @property
    def encoding(self) -> str:  # type: ignore[override]
        return self._encoding

    def isatty(self) -> bool:
        return True


def test_the_banner_shows_the_harp_and_what_this_gateway_does(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("HARPO_NO_BANNER", raising=False)
    monkeypatch.setenv("NO_COLOR", "1")
    term = Terminal()
    banner.show(LINES, term)
    out = term.getvalue()
    assert "HARPO-REDACT 2.5.0" in out and "✿" in out and "|\\_.-~~-._" in out and "\x1b[" not in out
    assert "Intercepting LLM traffic on port :8080" in out and "2 upstreams: openai, anthropic" in out
    assert "226 key rules, NER on, local model off" in out and "placeholders end with the request" in out


def test_the_banner_stays_out_of_logs_pipes_and_plain_terminals(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("HARPO_NO_BANNER", raising=False)
    piped = io.StringIO()
    banner.show(LINES, piped)
    assert piped.getvalue() == ""  # not a terminal: a log file or a container gets nothing
    ascii_term = Terminal("ascii")
    banner.show(LINES, ascii_term)
    out = ascii_term.getvalue()
    out.encode("ascii")  # a terminal that cannot show the rose gets ASCII, never a crash
    assert "@" in out and "HARPO-REDACT" in out
    monkeypatch.setenv("HARPO_NO_BANNER", "1")
    quiet = Terminal()
    banner.show(LINES, quiet)
    assert quiet.getvalue() == ""


def test_the_banner_is_coloured_on_a_colour_terminal(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    for name in ("NO_COLOR", "HARPO_NO_BANNER"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setattr(banner.sys, "platform", "linux")
    term = Terminal()
    banner.show(LINES, term)
    assert "\x1b[38;2;247;96;138m" in term.getvalue()  # the rose
    assert "\x1b[38;2;46;230;168m" in term.getvalue()  # jade strings and tags


def test_a_gateway_key_is_recognised_wherever_it_turns_up() -> None:
    """Gateway keys carry a prefix, so a key pasted into a prompt is redacted like any other key, also the two
    formats from before the rename. Documentation stubs stay as written."""
    pipeline = Pipeline(make_settings(**FAST))
    for prefix in (KEY_PREFIX, "pag_", "pk-"):
        key = prefix + secrets.token_urlsafe(32)
        assert pipeline.scan_sync([f"my gateway key is {key}, keep it"]).texts == [
            "my gateway key is [SECRET_1], keep it"
        ]
    for stub in ('api_key="harpo_..."', 'client = OpenAI(api_key="sk-...")', "OPENAI_API_KEY=sk-proj-...3Yb"):
        assert pipeline.scan_sync([stub]).texts == [stub]
    # an ellipsis after a whole value is punctuation, not a placeholder
    assert pipeline.scan_sync(["DB_PASSWORD=Tr0ub4dor... can you check?"]).texts == [
        "DB_PASSWORD=[SECRET_1] can you check?"
    ]


def test_new_gateway_keys_start_with_the_prefix(capsys) -> None:  # type: ignore[no-untyped-def]
    from harpo_redact.__main__ import main

    assert main(["hash-key", "--id", "ci"]) == 0
    out = capsys.readouterr().out
    key = next(line.strip() for line in out.splitlines() if line.strip().startswith(KEY_PREFIX))
    assert len(key) == len(KEY_PREFIX) + 43 and "Add this to harpo.yaml" in out


def test_variables_named_before_the_rename_still_work(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    env = {"PRIVATEAI_SERVER__PORT": "9123", "PRIVATEAI_LOGGING__LEVEL": "WARNING", "HARPO_LOGGING__LEVEL": "ERROR"}
    assert adopt_legacy_env(env) == ["PRIVATEAI_SERVER__PORT"]
    assert env["HARPO_SERVER__PORT"] == "9123" and env["HARPO_LOGGING__LEVEL"] == "ERROR"  # the new name wins
    monkeypatch.setenv("PRIVATEAI_SERVER__PORT", "9124")
    monkeypatch.setenv("HARPO_SERVER__PORT", "0")  # recorded, so the test leaves the environment as it found it
    monkeypatch.delenv("HARPO_SERVER__PORT")
    monkeypatch.delenv("HARPO_CONFIG", raising=False)
    monkeypatch.setenv("HARPO_ENVIRONMENT", "development")
    settings = load_settings()
    assert settings.server.port == 9124
    assert any("PRIVATEAI_SERVER__PORT (read as HARPO_SERVER__PORT; rename it)" in n for n in settings.notices())


def test_harpo_yaml_is_found_without_a_flag(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("HARPO_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "harpo.yaml").write_text("environment: development\nserver: {port: 9301}\n")
    assert load_settings().server.port == 9301
    (tmp_path / "harpo.yaml").write_text("environment: development\nserver: {port: 9302}\n")
    assert load_settings().server.port == 9302  # the working directory first


def test_an_install_from_before_the_rename_is_adopted(tmp_path) -> None:  # type: ignore[no-untyped-def]
    old = tmp_path / ".privateai"
    old.mkdir()
    (old / ".env").write_text("OPENAI_API_KEY=sk-test\n")
    (old / "gateway-key.txt").write_text("pk-abc\n")
    (old / "boot.json").write_text(json.dumps({"provider": "openai", "config": "config/gateway.yaml"}))
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "gateway.yaml").write_text("environment: development\n")
    notes = adopt_legacy_state(tmp_path)
    assert notes == ["moved .privateai/ to .harpo/", "renamed config/gateway.yaml to config/harpo.yaml"]
    new = tmp_path / ".harpo"
    assert (new / ".env").read_text() == "OPENAI_API_KEY=sk-test\n" and (new / "gateway-key.txt").exists()
    assert not old.exists() and (tmp_path / "config" / "harpo.yaml").exists()
    assert json.loads((new / "boot.json").read_text())["config"] == str(Path("config") / "harpo.yaml")
    assert adopt_legacy_state(tmp_path) == []  # once


@pytest.mark.parametrize("name", ["harpo", "harpo-redact"])
def test_both_commands_are_installed(name: str) -> None:
    from importlib.metadata import entry_points

    scripts = {ep.name: ep.value for ep in entry_points(group="console_scripts")}
    assert scripts.get(name) == "harpo_redact.__main__:main"


def test_the_version_flag(capsys) -> None:  # type: ignore[no-untyped-def]
    from harpo_redact.__main__ import main

    with pytest.raises(SystemExit):
        main(["--version"])
    assert capsys.readouterr().out.strip() == "harpo-redact 2.5.0"


def test_a_bare_harpo_explains_itself(capsys) -> None:  # type: ignore[no-untyped-def]
    from harpo_redact.__main__ import main

    assert main([]) == 0
    assert "self-hosted privacy firewall" in capsys.readouterr().out


def test_the_console_carries_the_mark(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(**FAST)
    page = client.get("/").text
    assert "<title>Harpo</title>" in page and "/console/apple-touch-icon.png" in page
    icon = client.get("/console/apple-touch-icon.png")
    assert icon.status_code == 200 and icon.headers["content-type"] == "image/png" and icon.content[:4] == b"\x89PNG"
    logo = client.get("/console/logo.svg").text
    assert "<title>Harpo</title>" in logo
