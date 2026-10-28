"""The credential library: vendored gitleaks rules on RE2 plus prompt rules."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from harpo_redact.detectors.secret_library import bip39_checksum_ok, load_library, shannon_entropy

LIB = load_library()
ROOT = Path(__file__).resolve().parents[1]


def rules_hit(text: str) -> set[str]:
    return {source.split(":", 1)[1] for span in LIB.find(text) for source in span.sources}


def test_all_vendored_rules_load() -> None:
    assert len(LIB.rules) >= 220
    assert LIB.rule_count >= 225


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        ("export GITHUB_TOKEN=ghp_R8xvT2mQ9wLk4ZpN7yHc3BdF6sJa1EuG5oVi", "github-pat"),
        ("token glpat-Xk3mP9qL2wR7vN4tY8zB", "gitlab-pat"),
        ("SLACK=xoxb-2754312856-4823910374651-Hq7Lm2Xv9Rk3Np8Wz4Tc6Ybd", "slack-bot-token"),
        ("stripe key sk_live_4eC39HqLyjWDarjtT1zdp7dcXyZ51Abc", "stripe-access-token"),
        ("aws_access_key_id = AKIAQ7XLMN2RTV4PZWK6", "aws-access-token"),
        ("aws_secret_access_key=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", "aws-secret-access-key"),
        ("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", "sendgrid-api-token"),
        ("//registry.npmjs.org/:_authToken=npm_Z9xK3mP2qL7wR4vN8tY1zB6cD5fG0hJ2kL9m", "npm-access-token"),
        ("key=AIzaSyD7xK3mP9qL2wR7vN4tY8zB1cD5fG0hJ2k", "gcp-api-key"),
        ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "jwt"),
        ("docker login -p dckr_pat_Xk3mP9qL2wR7vN4tY8zB1cD5fG0", "docker-hub-pat"),
        ("curl -H 'Authorization: Basic YWRtaW46czNjcjN0UGFzcyE='", "basic-auth"),
        ("fyi my password is hunter2 for the staging box", "natural-language"),
        ("The PIN code is 4821, change it after first login.", "natural-language"),
        ("my password is sunshine", "natural-language"),
        ("het wachtwoord is Zomer2024!", "natural-language"),
    ],
)
def test_credentials_are_found(text: str, rule: str) -> None:
    assert rule in rules_hit(text)


@pytest.mark.parametrize(
    "text",
    [
        "The access token expires after 3600 seconds, so refresh it before calling the API.",
        "Our password policy requires 12 characters; the password is incorrect if it has no digit.",
        "The token is located in the request header, and the API key is stored in the vault.",
        "Key management: rotate keys every 90 days. Secret scanning runs in CI on every push.",
        "def get_token(): return os.environ['GITHUB_TOKEN']  # read token from env",
        "password=${DB_PASSWORD} and api_key=<your-key-here>",
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
        "The password is: ********",
    ],
)
def test_prose_and_placeholders_are_not_credentials(text: str) -> None:
    assert LIB.find(text) == []


def test_seed_phrase_with_valid_checksum() -> None:
    phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow"  # official BIP39 vector
    assert bip39_checksum_ok(phrase.split())
    assert "bip39-seed-phrase" in rules_hit(f"backup: {phrase}")
    # Twelve wordlist words with a bad checksum and no wallet context stay readable.
    assert "bip39-seed-phrase" not in rules_hit(
        "legal winner thank year wave sausage worth useful legal winner thank year"
    )


def test_repeated_words_are_not_a_seed_phrase() -> None:
    """Found while testing the SLM budget: "word word word ..." passed the short checksum by chance."""
    for text in ("word " * 400, "abandon " * 12, "abandon " * 11 + "about", "seed: " + "word " * 24):
        assert "bip39-seed-phrase" not in rules_hit(text), text[:30]


def test_entropy_helper() -> None:
    assert shannon_entropy("aaaa") == 0.0
    assert round(shannon_entropy("abcd"), 3) == 2.0


def test_no_false_positives_in_project_prose() -> None:
    """The README and this repository's docs are long technical English: zero hits expected, except the invented key
    of the README's before-and-after example, which must be found."""
    text = (ROOT / "README.md").read_text()
    example = "sk-proj-" + "Qz7vL2mX9pR4tW8kH3nB6yC1dF5gJ0aE"
    found = [(sorted(s.sources), text[s.start : s.end]) for s in LIB.find(text)]
    assert example in text and any(value == example for _, value in found)
    assert [hit for hit in found if hit[1] != example] == []


def test_linear_time_on_adversarial_input() -> None:
    hostile = "api_key=" + "a1" * 50_000 + " password is " + "x" * 50_000
    started = time.perf_counter()
    LIB.find(hostile)
    assert time.perf_counter() - started < 2.0
