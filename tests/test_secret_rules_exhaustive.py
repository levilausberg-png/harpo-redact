"""Every credential rule proven with a verified sample (tools/gen_secret_samples.py)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from harpo_redact.detectors.secret_library import load_library

DATA = json.loads((Path(__file__).parent / "data" / "secret_samples.json").read_text())
LIB = load_library()
# The generator cannot reach the first two (their gitleaks patterns are scoped to file types). The Kubernetes rule is
# read by structure, every data entry of a Secret, so its sample is a manifest rather than text built from its regex.
# The generic rule only counts names with a credential word in them ("access_token", not "NYZlaccess"), which text
# built from its regex does not have.
HANDWRITTEN = {
    "generic-api-key": "access_token = 'dqr9wtawmywu9i7ie5zi8z36el72k3qz'",
    "freemius-secret-key": "$fs = array('secret_key' => 'sk_Ab3dE5gH7jK9mN2pQ4sT6vX8zA1cD');",
    "nuget-config-password": '<add key="ClearTextPassword" value="Tr0ub4dor&amp;3xQ" />',
    "kubernetes-secret-yaml": "apiVersion: v1\nkind: Secret\nmetadata:\n  name: db-credentials\ntype: Opaque\ndata:\n"
    "  password: SHVudGVyMmlzTXlQYXNzOQ==",
}
SAMPLES = {rule_id: v["text"] for rule_id, v in DATA["samples"].items()} | HANDWRITTEN


def test_every_rule_has_a_verified_sample() -> None:
    assert set(SAMPLES) == {r.id for r in LIB.rules}


@pytest.mark.parametrize("rule_id", sorted(SAMPLES))
def test_rule_fires_on_its_sample(rule_id: str) -> None:
    assert any(f"secret:{rule_id}" in s.sources for s in LIB.find(SAMPLES[rule_id]))


@pytest.mark.parametrize("rule_id", sorted(SAMPLES))
def test_rule_fires_inside_a_message(rule_id: str) -> None:
    text = f"Here is the config I'm stuck on:\n{SAMPLES[rule_id]}\nwhat's wrong with it?"
    assert any(f"secret:{rule_id}" in s.sources for s in LIB.find(text))


def test_every_secret_is_removed_end_to_end(make_pipeline) -> None:  # type: ignore[no-untyped-def]
    pipeline = make_pipeline(detection={"ner": {"enabled": False}})
    ids = sorted(SAMPLES)
    outcome = pipeline.scan_sync([SAMPLES[i] for i in ids])
    leaks = []
    for rule_id, redacted in zip(ids, outcome.texts, strict=True):
        text = SAMPLES[rule_id]
        for span in LIB.find(text):
            secret = text[span.start : span.end]
            if len(secret) >= 8 and secret in redacted:
                leaks.append((rule_id, secret[:16]))
    assert leaks == []


WRAPPERS = {
    "code fence": "```\n@@\n```",
    "blockquote": "> @@",
    "trailing comment": "@@  # TODO remove",
    "crlf": "line one\r\n@@\r\nline three",
    "indented": "        @@",
    "html": "<pre>@@</pre>",
    "parentheses": "(see @@)",
    "brackets": "[@@]",
    "braces": "{@@}",
    "list": "keys: @@, and more",
    "xml": "<value>@@</value>",
}


# 101 gitleaks rules accept a comma as the assignment operator ("discord, 123..."). A second, trailing comma
# ("keys: discord, 123..., and more") can then not be told from the operator, so a rule may miss in the "list"
# wrapper only if it is one of them. Derived from the patterns, so it does not depend on which sample a rule got.
COMMA_OPERATOR_RULES = {r.id for r in LIB.rules if re.search(r"\|,\)|\(,\||\|,\|", r.pattern.pattern)}


@pytest.mark.parametrize("wrapper", sorted(WRAPPERS))
def test_every_rule_survives_common_wrappers(wrapper: str) -> None:
    broken = {
        rule_id
        for rule_id, text in SAMPLES.items()
        if not any(f"secret:{rule_id}" in s.sources for s in LIB.find(WRAPPERS[wrapper].replace("@@", text)))
    }
    assert broken <= (COMMA_OPERATOR_RULES if wrapper == "list" else set())


def test_trailing_punctuation_of_a_password_is_redacted_too() -> None:
    for text, secret in (("DB_PASSWORD=Zomer(2024)!", "Zomer(2024)!"), ("my password is Summer2024!", "Summer2024!")):
        assert [text[s.start : s.end] for s in LIB.find(text)] == [secret]
    assert LIB.find("The password is wrong.") == []


def test_pin_needs_a_digit_but_password_accepts_a_word() -> None:
    assert LIB.find("A belaying pin is found too large to be easily inserted.") == []
    assert LIB.find("The pin was bent.") == []
    assert any("natural-language" in src for s in LIB.find("PIN is 4821") for src in s.sources)
    assert any("natural-language" in src for s in LIB.find("my password is sunshine") for src in s.sources)
    assert any("natural-language" in src for s in LIB.find("mon mot de passe est soleil") for src in s.sources)


@pytest.mark.parametrize(
    "text",
    [
        'password = "abc(def)ghi!x9Q"',
        "pwd: P@ss(w0rd)!2026",
        "my password is Tr0ub4dor&3 for the vpn",
        "wachtwoord: Zomer(2024)!",
        "passwort = K#9mP$xL2@vN",
        "the PIN is 7391",
        "secret_key = 'x7$kP(2mQ)v9'",
    ],
)
def test_passwords_with_symbols_are_found(text: str) -> None:
    assert any(span for span in LIB.find(text)), text


@pytest.mark.parametrize(
    "text",
    [
        "password = os.environ['DB_PASSWORD']",
        'password = getenv("DB_PASSWORD")',
        "api_key = process.env.API_KEY",
        "token = settings.GITHUB_TOKEN",
        "password=${DB_PASSWORD}",
    ],
)
def test_reading_a_secret_is_not_a_secret(text: str) -> None:
    assert LIB.find(text) == []


@pytest.mark.parametrize(
    "text",
    [
        'api_key = "YOUR_API_KEY"',
        'client = OpenAI(api_key="harpo_...")',
        'token = "sk-..."',
        "OPENAI_API_KEY=your-key-here",
        'password = "<password>"',
        'secret = "REPLACE_ME"',
        "export API_TOKEN=xxxxxxxxxxxx",
        "password: changeme",
        "the password: example",
    ],
)
def test_documentation_placeholders_are_not_credentials(text: str) -> None:
    assert LIB.find(text) == []


def test_aws_documentation_keys_are_still_redacted_by_the_pipeline(make_pipeline) -> None:  # type: ignore[no-untyped-def]
    """Strict: a key-shaped string is removed even when it is the well-known example from the AWS docs."""
    out = make_pipeline(detection={"ner": {"enabled": False}}).scan_sync(["Use AKIAIOSFODNN7EXAMPLE here."]).texts[0]
    assert "AKIAIOSFODNN7EXAMPLE" not in out
