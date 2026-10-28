"""INV-11: keys are always redacted.

API keys, tokens, passwords and private keys become placeholders and the request goes on. No configuration,
live policy, override or switch can block them, allow them, or stop them being looked for. The full credential
matrix (19 kinds through 31 carriers) is in test_redaction_matrix.py; this file pins the rule itself.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from pydantic import ValidationError

from harpo_redact import proxy
from harpo_redact.detectors.secret_library import load_library
from harpo_redact.entities import ALWAYS_REDACTED, EntityType
from harpo_redact.pipeline import Pipeline

from .conftest import AUTH, chat, make_settings
from .redaction_matrix import EC_KEY

FAST = {"detection": {"ner": {"enabled": False}}}
OPENAI_KEY = "sk-proj-7Hq2LmV9xRt4KpZ8wNc3YbF6dJs1GaE5"
AWS_KEY = "AKIAZ4X7Q2LMWN3RT5PJ"
NPM_TOKEN = "npm_aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"  # found by a gitleaks rule only
GITHUB_TOKEN = "ghp_R8xV2mQ9tL4wK7nB3cY6hJ1sD5fG0aZ2eU8i"
SEED = "legal winner thank year wave sausage worth useful legal winner thank yellow"
KEYS = [OPENAI_KEY, AWS_KEY, NPM_TOKEN, "my password is Tr0ub4dor&3x", f"recovery phrase: {SEED}", EC_KEY]


def forwarded(spy: Any) -> str:
    return spy.bodies[-1].decode("utf-8", "replace")


@pytest.mark.parametrize("text", KEYS, ids=["openai", "aws", "npm", "password", "seed", "pem"])
def test_every_kind_of_key_is_redacted_and_the_request_goes_on(gateway, text: str) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(**FAST)
    r = client.post("/v1/chat/completions", headers=AUTH, json=chat(f"use this: {text}"))
    assert r.status_code == 200 and r.headers["x-harpo-risk"] == "yellow"
    sent = forwarded(spy)
    assert "[SECRET_" in sent or "[PRIVATE_KEY_" in sent
    for piece in text.split():
        if len(piece) >= 12:
            assert piece not in sent


def test_the_anthropic_api_redacts_keys_too(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(**FAST)
    body = {"model": "claude-sonnet", "max_tokens": 64, "messages": [{"role": "user", "content": f"key {OPENAI_KEY}"}]}
    r = client.post("/v1/messages", headers=AUTH, json=body)
    assert r.status_code == 200 and OPENAI_KEY not in forwarded(spy) and "key [SECRET_1]" in forwarded(spy)


def test_the_reason_says_a_key_was_redacted(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(**FAST)
    out = client.post("/v1/scan", headers=AUTH, json={"text": f"deploy with {AWS_KEY}"}).json()
    codes = [r["code"] for r in out["reasons"]]
    assert "keys_redacted" in codes and out["risk"] == "yellow"


@pytest.mark.parametrize("key", ["SECRET", "PRIVATE_KEY"])
def test_no_policy_blocks_or_allows_a_key(gateway, key: str) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(policy={"entities": {key: {"action": "block", "overridable": False}}}, **FAST)
    text = OPENAI_KEY if key == "SECRET" else EC_KEY
    r = client.post("/v1/chat/completions", headers=AUTH, json=chat(f"use {text}"))
    assert r.status_code == 200 and f"[{key}_1]" in forwarded(spy)
    with pytest.raises(ValidationError, match="always redacted"):
        make_settings(policy={"entities": {key: {"action": "allow"}}})
    assert make_settings().policy.entities[EntityType(key)].action == "redact"


def test_no_switch_stops_keys_being_found(gateway) -> None:  # type: ignore[no-untyped-def]
    off = {"library": False, "disabled_rules": ["aws-access-token", "npm-access-token"], "natural_language": False,
           "seed_phrases": False}  # fmt: skip
    client, spy = gateway(detection={"ner": {"enabled": False}, "secrets": off})
    for text in (AWS_KEY, NPM_TOKEN, "my password is Tr0ub4dor&3x", f"recovery phrase: {SEED}"):
        r = client.post("/v1/chat/completions", headers=AUTH, json=chat(text))
        assert r.status_code == 200 and "[SECRET_1]" in forwarded(spy), text


def test_an_override_never_sends_a_key(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(**FAST)
    r = client.post("/v1/chat/completions", headers={**AUTH, "X-Harpo-Override": "true"}, json=chat(OPENAI_KEY))
    assert r.status_code == 200 and OPENAI_KEY not in forwarded(spy)


def test_the_live_policy_cannot_touch_keys() -> None:
    from harpo_redact.live_policy import LivePolicy

    for key in ALWAYS_REDACTED:
        with pytest.raises(ValidationError, match="always redacted"):
            LivePolicy.model_validate({"entities": {key.value: "block"}})


def test_a_key_the_scan_misses_is_still_stopped_at_egress(gateway, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(**FAST)
    real = proxy.Collector.apply
    monkeypatch.setattr(proxy.Collector, "apply", lambda self, red: real(self, list(self.texts)))  # sabotage
    r = client.post("/v1/chat/completions", headers=AUTH, json=chat(f"deploy {AWS_KEY}"))
    assert r.status_code == 403 and r.json()["error"]["harpo"]["reasons"][0]["code"] == "egress_verification"
    assert not spy.requests  # fail closed: a redaction bug blocks, it never leaks


def test_a_seed_phrase_placeholder_does_not_swallow_the_word_before_it() -> None:
    pipeline = Pipeline(make_settings(**FAST))
    out = pipeline.scan_sync([f"Please check the file. {SEED} was in the notes."])
    assert out.texts == ["Please check the file. [SECRET_1] was in the notes."]


def test_a_private_key_with_look_alike_letters_is_redacted_whole() -> None:
    pipeline = Pipeline(make_settings(**FAST))
    disguised = EC_KEY.replace("EC PRIVATE", "ЕС PRIVATE")  # Cyrillic Е and С
    out = pipeline.scan_sync([f"key: {disguised}"])
    assert out.texts == ["key: [PRIVATE_KEY_1]"]


def test_a_redacted_value_in_a_url_query_passes_egress_but_a_glued_password_does_not() -> None:
    pipeline = Pipeline(make_settings(**FAST))
    assert pipeline.residual_sync(["https://crm.example/search?api_key=[SECRET_1]&lang=en"]) == {}
    assert pipeline.residual_sync(["password: [PERSON_1]Hunter2isMyPass9"]).get("SECRET", 0) >= 1


def test_a_base64_wrapped_key_is_redacted_and_counted_as_a_key() -> None:
    pipeline = Pipeline(make_settings(**FAST))
    out = pipeline.scan_sync(["payload " + base64.b64encode(f"token={OPENAI_KEY}".encode()).decode()])
    assert not out.blocked and "[ENCODED_DATA_1]" in out.texts[0] and "keys_redacted" in [r.code for r in out.reasons]


def test_check_config_names_the_settings_that_no_longer_do_anything(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    from harpo_redact.__main__ import main

    path = tmp_path / "harpo.yaml"
    path.write_text(
        "environment: development\n"
        "policy: {entities: {SECRET: {action: block, overridable: true}, PRIVATE_KEY: {action: block}}}\n"
        "detection: {ner: {enabled: false}, secrets: {disabled_rules: [generic-api-key]}}\n"
    )
    assert main(["check-config", "--config", str(path)]) == 0
    out = capsys.readouterr().out
    assert "notice: policy.entities.SECRET.action: block" in out and "notice: policy.entities.PRIVATE_KEY.action" in out
    assert "notice: detection.secrets.disabled_rules: generic-api-key" in out


def test_the_whole_library_always_runs() -> None:
    switched_off = make_settings(detection={"ner": {"enabled": False}, "secrets": {"library": False}})
    assert Pipeline(switched_off).secret_rule_count == load_library().rule_count
    assert len(load_library().rules) == 221  # the gitleaks rules; the count adds five prompt rules


def test_extra_key_rules_are_checked_when_the_config_loads(tmp_path) -> None:  # type: ignore[no-untyped-def]
    good = tmp_path / "rules.toml"
    good.write_text("[[rules]]\nid = \"acme-token\"\nregex = '''acme_[A-Za-z0-9]{24}'''\nkeywords = [\"acme_\"]\n")
    pipeline = Pipeline(
        make_settings(detection={"ner": {"enabled": False}, "secrets": {"extra_rules_file": str(good)}})
    )
    out = pipeline.scan_sync(["token acme_" + "Q7x" * 8])
    assert out.texts == ["token [SECRET_1]"] and pipeline.secret_rule_count == load_library().rule_count + 1
    problems = {
        "missing.toml": "file not found",
        "dup.toml": ("[[rules]]\nid = \"aws-access-token\"\nregex = 'AKIA[0-9A-Z]{16}'\n", "already has this id"),
        "empty.toml": ("[[rules]]\nid = \"empty-match\"\nregex = 'x*'\n", "matches the empty string"),
        "lookaround.toml": ("[[rules]]\nid = \"look\"\nregex = '(?<=a)b'\n", "not valid RE2"),
        "nothing.toml": ("title = 'no rules'\n", r"has no \[\[rules\]\]"),
    }
    for name, spec in problems.items():
        path = tmp_path / name
        if isinstance(spec, tuple):
            path.write_text(spec[0])
            message = spec[1]
        else:
            message = spec
        with pytest.raises(ValidationError, match=message):
            make_settings(detection={"secrets": {"extra_rules_file": str(path)}})


def test_an_extra_rules_file_cannot_exempt_keys(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    """A gitleaks file's top-level [allowlist] would apply to every rule, built-in ones included. It is ignored, and
    check-config says so; a rule's own allowlist still works."""
    from harpo_redact.__main__ import main

    rules = tmp_path / "rules.toml"
    rules.write_text(
        "[allowlist]\nregexes = ['.*']\n\n[[rules]]\nid = 'acme-token'\nregex = 'acme_[A-Za-z0-9]{24}'\n"
        "keywords = ['acme_']\n[[rules.allowlists]]\nregexes = ['acme_0{24}']\n"
    )
    detection = {"ner": {"enabled": False}, "secrets": {"extra_rules_file": str(rules)}}
    pipeline = Pipeline(make_settings(detection=detection))
    for key in (NPM_TOKEN, "glpat-Xq7vL2mX9pR4tW8kQz7v", "acme_" + "Q7x" * 8):
        assert pipeline.scan_sync([f"token {key}"]).texts == ["token [SECRET_1]"], key
    assert pipeline.scan_sync(["token acme_" + "0" * 24]).texts == ["token acme_" + "0" * 24]
    config = tmp_path / "harpo.yaml"
    config.write_text(f"environment: development\ndetection: {{secrets: {{extra_rules_file: '{rules}'}}}}\n")
    assert main(["check-config", "--config", str(config)]) == 0
    assert "notice: detection.secrets.extra_rules_file: [allowlist]" in capsys.readouterr().out


def test_the_decoders_that_find_hidden_keys_stay_on() -> None:
    settings = make_settings(
        detection={"ner": {"enabled": False}, "encoded_max_depth": 0, "identifiers": {"decode_escapes": False}}
    )
    assert settings.detection.encoded_max_depth == 1 and settings.detection.identifiers.decode_escapes
    notices = " ".join(settings.notices())
    assert "detection.encoded_max_depth: 0" in notices and "detection.identifiers.decode_escapes: false" in notices
    pipeline = Pipeline(settings)
    wrapped = base64.b64encode(f"token={OPENAI_KEY}".encode()).decode()
    assert pipeline.scan_sync([f"payload {wrapped}"]).texts == ["payload [ENCODED_DATA_1]"]
    escaped = "token%3D" + OPENAI_KEY.replace("-", "%2D")
    assert pipeline.scan_sync([escaped]).texts == ["token%3D[SECRET_1]"]


def test_env_var_names_are_not_people(ner) -> None:  # type: ignore[no-untyped-def]
    found = ner.detect_many(["DATABASE_PASSWORD=Qz7vL2mX9pR4tW8k\nOPENAI_API_KEY=x\nRefund Anna de Vries today"])[0]
    assert [s.type for s in found] == [EntityType.PERSON] and json.dumps(
        [s.canonical for s in found]
    ) == '["anna de vries"]'


# Redacting instead of blocking means a key's span must be exact: these were too long (or, for the Redis URL,
# missing) when a coding agent sent a whole config file. Each case is what an agent reads every day.
CONFIG_FILES = {
    "env": (
        f"OPENAI_API_KEY={OPENAI_KEY}\nDATABASE_URL=postgres://app:Hunter2isMyPass9@db.internal:5432/app\n"
        "LOG_LEVEL=debug\nPORT=8443",
        "OPENAI_API_KEY=[SECRET_1]\nDATABASE_URL=postgres://app:[SECRET_2]@db.internal:5432/app\n"
        "LOG_LEVEL=debug\nPORT=8443",
    ),
    "redis without a user": (
        'REDIS_URL="redis://:Sup3rS3cretRedis@cache.internal:6379/0"\nFEATURE_FLAGS="a,b,c"',
        'REDIS_URL="redis://:[SECRET_1]@cache.internal:6379/0"\nFEATURE_FLAGS="a,b,c"',
    ),
    "json keeps its quotes": (
        f'{{\n  "api_key": "{OPENAI_KEY}",\n  "region": "eu-west-1",\n  "password": "Hunter2isMyPass9",\n  "retries": 3\n}}',
        '{\n  "api_key": "[SECRET_1]",\n  "region": "eu-west-1",\n  "password": "[SECRET_2]",\n  "retries": 3\n}',
    ),
    "shell prompt": (
        f"$ export OPENAI_API_KEY={OPENAI_KEY}\n$ npm run dev",
        "$ export OPENAI_API_KEY=[SECRET_1]\n$ npm run dev",
    ),
    "log lines": (
        f"12:00:01 INFO Authorization: Bearer {GITHUB_TOKEN}\n12:00:02 ERROR 401 Unauthorized",
        "12:00:01 INFO Authorization: Bearer [SECRET_1]\n12:00:02 ERROR 401 Unauthorized",
    ),
    "ini": (
        f"[default]\naws_access_key_id = {AWS_KEY}\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY\n"
        "region = eu-west-1",
        "[default]\naws_access_key_id = [SECRET_1]\naws_secret_access_key = [SECRET_2]\nregion = eu-west-1",
    ),
    "prose after": (
        f"My key is {OPENAI_KEY}\nCan you check why the request fails with 401?",
        "My key is [SECRET_1]\nCan you check why the request fails with 401?",
    ),
    "url query": (
        "GET https://crm.example/api/search?api_key=Qz7vL2mX9pR4tW8kQz7v&lang=en&page=2 HTTP/1.1",
        "GET https://crm.example/api/search?api_key=[SECRET_1]&lang=en&page=2 HTTP/1.1",
    ),
    "kubernetes secret": (  # every data entry is a secret; the gitleaks rule's group also took the YAML key
        "kind: Secret\ndata:\n  password: SHVudGVyMmlzTXlQYXNzOQ==\n  host: ZGIuaW50ZXJuYWw=\n---\nkind: ConfigMap\n"
        "data:\n  greeting: SGVsbG8gd29ybGQgYWdhaW4=",
        "kind: Secret\ndata:\n  password: [SECRET_1]\n  host: [SECRET_2]\n---\nkind: ConfigMap\n"
        "data:\n  greeting: SGVsbG8gd29ybGQgYWdhaW4=",
    ),
    "yaml parent after a key": (
        f"users:\n  - name: admin\n    token: {GITHUB_TOKEN}\ncontexts:\n  - name: prod",
        "users:\n  - name: admin\n    token: [SECRET_1]\ncontexts:\n  - name: prod",
    ),
    # Found by an independent review of 2.4.0: part of a password reached the provider in each of these.
    "password with an ampersand": (  # "&key=" inside a password is not a URL query field
        "DB_PASSWORD=Tr0ub4dor&key=3xZq!\nDB_USER=app",
        "DB_PASSWORD=[SECRET_1]\nDB_USER=app",
    ),
    "at sign in a URL password": (  # the password runs to the last "@" before the host
        "DATABASE_URL=postgres://app:P@ssw0rd!@db.internal:5432/app",
        "DATABASE_URL=postgres://app:[SECRET_1]@db.internal:5432/app",
    ),
    "quoted with blanks": (
        'SMTP_PASSWORD="Tr0ub4dor 3xZq 9Lmw"\nSMTP_PORT=587',
        'SMTP_PASSWORD="[SECRET_1]"\nSMTP_PORT=587',
    ),
    "escaped quote in json": (
        '{"user": "app", "password": "Tr0ub\\"4dor&3xZq"}',
        '{"user": "app", "password": "[SECRET_1]"}',
    ),
    "passphrase on a config line": (  # the rest of the line, without its comment
        "db:\n  password: correct horse battery staple  # rotated monthly\n  host: db.internal",
        "db:\n  password: [SECRET_1]  # rotated monthly\n  host: db.internal",
    ),
    "kubernetes secret as json": (  # kubectl get secret -o json, short values included
        '{"kind": "Secret", "metadata": {"name": "app"}, "data": {"aes": "bnp3cWw4c2RmYXNkZmFzZGZwdEU=", '
        '"pin": "czNjcjN0"}}',
        '{"kind": "Secret", "metadata": {"name": "app"}, "data": {"aes": "[SECRET_1]", "pin": "[SECRET_2]"}}',
    ),
    "kubernetes list": (  # kind is read per object: the ConfigMap in the same list keeps its values
        "kind: List\nitems:\n  - kind: ConfigMap\n    data:\n      APP_ENV: production\n  - kind: Secret\n"
        "    data:\n      DB_PASS: czNjcjN0\n    stringData:\n      password: hunter2",
        "kind: List\nitems:\n  - kind: ConfigMap\n    data:\n      APP_ENV: production\n  - kind: Secret\n"
        "    data:\n      DB_PASS: [SECRET_1]\n    stringData:\n      password: [SECRET_2]",
    ),
    # A key at the end of a line takes none of the lines after it.
    "heredoc": (
        f"cat > .env <<EOF\nOPENAI_API_KEY={OPENAI_KEY}\nEOF\nnpm start",
        "cat > .env <<EOF\nOPENAI_API_KEY=[SECRET_1]\nEOF\nnpm start",
    ),
    "git diff": (
        f"--- a/.env\n+++ b/.env\n@@ -1 +1,2 @@\n+OPENAI_API_KEY={OPENAI_KEY}\n+LOG_LEVEL=debug",
        "--- a/.env\n+++ b/.env\n@@ -1 +1,2 @@\n+OPENAI_API_KEY=[SECRET_1]\n+LOG_LEVEL=debug",
    ),
    "iso log": (
        f"2026-10-12T09:14:03Z INFO Authorization: Bearer {GITHUB_TOKEN}\n2026-10-12T09:14:04Z INFO retrying",
        "2026-10-12T09:14:03Z INFO Authorization: Bearer [SECRET_1]\n2026-10-12T09:14:04Z INFO retrying",
    ),
    "go log": (
        f"2026/10/12 09:14:03 token={GITHUB_TOKEN}\n2026/10/12 09:14:04 retrying",
        "2026/10/12 09:14:03 token=[SECRET_1]\n2026/10/12 09:14:04 retrying",
    ),
    "syslog": (
        f"Oct 12 09:14:03 web app: token={GITHUB_TOKEN}\nOct 12 09:14:04 web app: retrying",
        "Oct 12 09:14:03 web app: token=[SECRET_1]\nOct 12 09:14:04 web app: retrying",
    ),
    "netrc": (
        "machine api.heroku.com\n  login jane@corp.example\n  password 7f3c2a1b-9d8e-4f6a-b5c4-3e2d1f0a9b8c\n"
        "machine git.heroku.com",
        "machine api.heroku.com\n  login [EMAIL_1]\n  password [SECRET_1]\nmachine git.heroku.com",
    ),
    "shell loop": (
        f"for i in 1 2; do\n  export OPENAI_API_KEY={OPENAI_KEY}\ndone < hosts",
        "for i in 1 2; do\n  export OPENAI_API_KEY=[SECRET_1]\ndone < hosts",
    ),
    "tags, fences and links": (
        f"<env>\nOPENAI_API_KEY={OPENAI_KEY}\n</env>\n```\nOPENAI_API_KEY={OPENAI_KEY}\n```\nSee https://example.com/setup",
        "<env>\nOPENAI_API_KEY=[SECRET_1]\n</env>\n```\nOPENAI_API_KEY=[SECRET_1]\n```\nSee https://example.com/setup",
    ),
}


@pytest.mark.parametrize("name", list(CONFIG_FILES))
def test_a_key_takes_exactly_its_own_characters(name: str) -> None:
    text, expected = CONFIG_FILES[name]
    out = Pipeline(make_settings(**FAST)).scan_sync([text])
    assert out.texts == [expected] and not out.blocked


@pytest.mark.parametrize(
    ("text", "rest"),
    [
        (f"use this key: {OPENAI_KEY[:22]}\n{OPENAI_KEY[22:]} thanks", OPENAI_KEY[22:]),  # a cut key goes whole
        (f"my key: {OPENAI_KEY[:34]}\nfdjsgae thanks", "fdjsgae"),  # whatever its last characters are
        ("my password is Tr0ub4dor\n&3x okay", "&3x"),
        ("my password is Tr0ub4dor\n{3x}Zq okay", "Zq"),
        ("password: Tr0ub4dor\nab=Zq9!", "Zq9"),  # an assignment starts a new entry only after another one
        ("password=Tr0ub4dor&3x", "&3x"),  # an ampersand inside a password is not a query field
    ],
)
def test_a_key_cut_in_two_is_still_redacted_whole(text: str, rest: str) -> None:
    pipeline = Pipeline(make_settings(**FAST))
    out = pipeline.scan_sync([text]).texts[0]
    assert rest not in out and "[SECRET_1]" in out and pipeline.residual_sync([out]) == {}


@pytest.mark.parametrize("text", ["password: Tr0ub4dor\n- 3xZq", 'password: Tr0ub4dor\n"3xZq'])
def test_an_unquoted_value_ends_at_a_blank_or_a_quote_on_the_next_line_too(text: str) -> None:
    """The boundary is the value's own grammar, not the line break. Joined, "Tr0ub4dor- 3xZq" ends at the blank and
    'Tr0ub4dor"3xZq' at the quote, so the second line is a list item or a string, not the rest of the password."""
    pipeline = Pipeline(make_settings(**FAST))
    out = pipeline.scan_sync([text]).texts[0]
    assert out == "password: [SECRET_1]\n" + text.split("\n")[1] and pipeline.residual_sync([out]) == {}


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('PASSWORD="ask unit storm lake"', 'PASSWORD="[SECRET_1]"'),  # four random words are a passphrase
        ("password: correct horse battery staple", "password: [SECRET_1]"),
        ("password: will send it later", "password: will send it later"),  # a note under the label is not
        ("password: see the vault for details", "password: see the vault for details"),
        ('PASSWORD="will send it later"', 'PASSWORD="will send it later"'),
    ],
)
def test_a_passphrase_is_redacted_and_a_note_is_not(text: str, expected: str) -> None:
    assert Pipeline(make_settings(**FAST)).scan_sync([text]).texts == [expected]


def test_a_hostile_kubernetes_file_cannot_make_the_scan_slow() -> None:
    """Each "data:" line used to rescan every line after it: 490 indents and 150K blank lines took 22 s."""
    import time

    from harpo_redact.detectors.secret_library import _kubernetes_secret_values

    hostile = [
        "kind: Secret\n" + "".join("\t" * i + "data:\n" for i in range(490)) + "\n" * 150_000,
        "kind: Secret\n" + "".join(" " * (i % 400) + "data:\n" + " " * (i % 400) + "  k: v\n" for i in range(2400)),
        '{"kind":"Secret","data":' * 3000 + "1" + "}" * 3000,
    ]
    for text in hostile:
        spent = []
        for _ in range(2):  # CPU time, best of two: a busy machine must not look like a slow scan
            started = time.process_time()
            list(_kubernetes_secret_values(text))
            spent.append(time.process_time() - started)
        assert min(spent) < 1.0


def test_the_url_password_rule_and_the_email_rule_agree_on_what_a_url_is() -> None:
    """A scheme the URL rule does not accept (32 letters) leaves an e-mail address that the e-mail rule finds."""
    pipeline = Pipeline(make_settings(**FAST))
    assert pipeline.scan_sync(["x" * 32 + "://u:jane.doe@corp.example.com"]).texts == ["x" * 32 + "://u:[EMAIL_1]"]
    assert pipeline.scan_sync(["git+ssh://u:Tr0ub4dor3x@corp.example.com"]).texts == [
        "git+ssh://u:[SECRET_1]@corp.example.com"
    ]


@pytest.mark.parametrize("name", list(CONFIG_FILES))
def test_the_sanitized_file_passes_egress_verification(name: str) -> None:
    """Exact spans are not enough: egress verification rescans the sanitized body, and a placeholder at the end of a
    line must not be read as the start of a value that runs on into the next line."""
    pipeline = Pipeline(make_settings(**FAST))
    out = pipeline.scan_sync([CONFIG_FILES[name][0]]).texts[0]
    assert pipeline.residual_sync([out]) == {} and pipeline.residual_sync([json.dumps({"content": out})]) == {}


def test_an_agent_that_reads_a_dotenv_keeps_working(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(**FAST)
    text, expected = CONFIG_FILES["env"]
    read = {"type": "tool_use", "id": "toolu_01", "name": "read_file", "input": {"path": ".env"}}
    body = {
        "model": "claude-sonnet",
        "max_tokens": 64,
        "messages": [
            {"role": "user", "content": "The app won't start. Check the config."},
            {"role": "assistant", "content": [read]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_01", "content": text}]},
        ],
    }
    r = client.post("/v1/messages", headers=AUTH, json=body)
    assert r.status_code == 200 and r.headers["x-harpo-redactions"] == "2"
    assert json.loads(forwarded(spy))["messages"][2]["content"][0]["content"] == expected
