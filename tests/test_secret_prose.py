"""Credentials as people state them (detectors/statements.py and the provider rules): in other languages, in prose
that ends a token with a full stop, in forms that are not an assignment, and the near misses that must stay.

Every value here is invented, and token-shaped values are generated when the tests run, so no file in the
repository holds anything a secret scanner would stop.
"""

from __future__ import annotations

import base64
import random
import string
import time

import pytest

from harpo_redact.detectors.secret_library import looks_like_placeholder
from harpo_redact.detectors.statements import find_statements, name_words, random_looking, strength
from harpo_redact.entities import EntityType
from harpo_redact.pipeline import Pipeline

from .conftest import make_settings

PIPELINE = Pipeline(make_settings(detection={"ner": {"enabled": False}}))
_RNG = random.Random(20261014)
_ALNUM = string.ascii_letters + string.digits


def _token(n: int, alphabet: str = _ALNUM) -> str:
    return "".join(_RNG.choice(alphabet) for _ in range(n))


TOKEN = "Rk82mZq4TfW1vXc9Lp3s"
PASSWORD = "Gq7!pZ2xR"
NPM = "npm_" + _token(36)
HF = "hf_" + _token(34)
TELEGRAM_ID, TELEGRAM_SECRET = "7581930264", _token(35, _ALNUM + "_-")
DISCORD = "MTA4NTk2MzQ1Njc4OTAxMjM0." + _token(6) + "." + _token(33)
AZURE = _token(86, _ALNUM + "+/") + "=="
BASIC = base64.b64encode(b"svc_user:S3cr3tPass!").decode()
HEX_KEY = _token(32, "0123456789abcdef")
HEX_KEY_UPPER = _token(16, "0123456789ABCDEF")


def scan(text: str) -> tuple[str, set[EntityType]]:
    outcome = PIPELINE.scan_sync([text])
    return outcome.texts[0], {f.type for f in outcome.findings[0]}


@pytest.mark.parametrize(
    ("text", "value"),
    [
        # a credential-named identifier, in other languages
        (f"Das neue HF_TOKEN lautet {TOKEN}.", TOKEN),
        (f"Il DEPLOY_TOKEN di produzione è {TOKEN}.", TOKEN),
        (f"Nuestro SENTRY_AUTH_TOKEN nuevo es {TOKEN}.", TOKEN),
        (f"生产环境的 DEPLOY_TOKEN 是 {TOKEN}。", TOKEN),
        ("現在の db_password は Moonlitharbor です。", "Moonlitharbor"),
        # the word for password, and its "is"
        (f"A senha do servidor é {PASSWORD}.", PASSWORD),
        (f"Мой пароль: {PASSWORD}", PASSWORD),
        (f"パスワードは{PASSWORD}です。", PASSWORD),
        (f"数据库的密码是 {PASSWORD}。", PASSWORD),
        (f"비밀번호는 {PASSWORD}입니다", PASSWORD),
        (f"Das Passwort für den Server ist {PASSWORD}.", PASSWORD),
        (f"Hasło do bazy: {PASSWORD}", PASSWORD),
        (f"La sua password è {PASSWORD}, non condividerla.", PASSWORD),
        (f"the password for our wiki account is {PASSWORD}", PASSWORD),
        ("the wifi pw is meadow2024, ask before changing it", "meadow2024"),
        # forms that are not an assignment
        (f"set apiKey to {TOKEN}", TOKEN),
        (f"Then set the env var `STRIPE_KEY` to `{TOKEN}` in CI.", TOKEN),
        ("| password | Lantern-Orbit-42 |", "Lantern-Orbit-42"),
        (f"- **apiKey**: {TOKEN}", TOKEN),
        (f"**API Key:** {TOKEN}", TOKEN),
        (f"Please rotate DEPLOY_TOKEN ({TOKEN}) after the incident.", TOKEN),
        (f"An access key, such as {TOKEN}, goes in the header.", TOKEN),
        # code: a password-named field may hold any word
        ('{"db_password": "quietmeadow"}', "quietmeadow"),
        ("if ($password === 'quietmeadow') {", "quietmeadow"),
        ('client.setPassword("quietmeadow");', "quietmeadow"),
        (f"define('MAILGUN_API_KEY', '{TOKEN}');", TOKEN),
        ("<password>quietmeadow42</password>", "quietmeadow42"),
        ("CREATE USER app WITH PASSWORD 'quietmeadow42';", "quietmeadow42"),
        ("export DB_PASS=quietmeadow", "quietmeadow"),
        ("curl -d client_secret=quietmeadow https://auth.example.com/token", "quietmeadow"),
        (f"api_key: !secret {TOKEN}", TOKEN),
        (f'headers = {{"Authorization": "Basic {BASIC}"}}', BASIC),
        # provider tokens: at the end of a sentence, and as they are written in practice
        (f"The NPM_TOKEN is {NPM}.", NPM),
        (f"My token is {HF}.", HF),
        (f"TELEGRAM_BOT_TOKEN={TELEGRAM_ID}:{TELEGRAM_SECRET}", TELEGRAM_SECRET),
        (f"curl https://api.telegram.org/bot{TELEGRAM_ID}:{TELEGRAM_SECRET}/getMe", TELEGRAM_SECRET),
        (f"the bot logs in with {DISCORD} on start", DISCORD),
        (
            f"DefaultEndpointsProtocol=https;AccountName=store1;AccountKey={AZURE};EndpointSuffix=core.windows.net",
            AZURE,
        ),
        # command-line flags
        (f"python train.py --hub_token {TOKEN} --epochs 3", TOKEN),
        (f"deploy --api-key={TOKEN}", TOKEN),
        (f"mysql -u app --password={PASSWORD} shop", PASSWORD),
        # credentials with a type prefix, and PINs
        ("whsec_" + "Qm7Rt2ZpX9vLk4Nw8Bc3Hd6F", "whsec_" + "Qm7Rt2ZpX9vLk4Nw8Bc3Hd6F"),
        ("Your new PIN is 4821.", "4821"),
        # more ways of saying which value a credential has
        (f"Use the API key, which is {TOKEN}, in the header.", TOKEN),
        (f"the key is {TOKEN}. Keep it safe", TOKEN),
        (f"[reporting]\nKey = {HEX_KEY}\nRegion = eu-west\n", HEX_KEY),
        # the word for password straight before its value, and "include", "like", "of"
        ("She always types her password Lantern88# without looking", "Lantern88#"),
        ("log in as jdoe with password 4tealHorse4 today", "4tealHorse4"),
        ("- **password** Wq7$zTr2", "Wq7$zTr2"),
        ("Good passwords include Copper#Falcon7, for instance.", "Copper#Falcon7"),
        ("a password of Orchid@1990 was set for the kiosk", "Orchid@1990"),
        ("passwords like Maple!Stone42 are hard to guess", "Maple!Stone42"),
        (f"Key: {HEX_KEY_UPPER}", HEX_KEY_UPPER),
        (f"The password for the old reporting system is {PASSWORD}.", PASSWORD),
        (f"I have changed my password to {PASSWORD} today", PASSWORD),
        (f"Your password has been reset to {PASSWORD}", PASSWORD),
        # environment variables as a name and a value, Redis and Windows
        (f'{{"name": "PAYMENT_API_KEY", "value": "{TOKEN}"}}', TOKEN),
        (f"env:\n  - name: DB_PASSWORD\n    value: {PASSWORD}\n", PASSWORD),
        (f'1712000000.123456 [0 10.0.0.5:51234] "AUTH" "{PASSWORD}"', PASSWORD),
        (f"requirepass {PASSWORD}", PASSWORD),
        (f'"SET" "app:config:jwt_secret" "{TOKEN}" "EX" "0"', TOKEN),
        (f"net use Z: \\\\files01\\share /user:CORP\\p.devries {PASSWORD}", PASSWORD),
        (f"postgresql://app:1x#Q{PASSWORD}@db.internal:5432/app", f"1x#Q{PASSWORD}"),
        ("curl https://hooks.example.org/hooks/deploy/v1/" + TOKEN, TOKEN),
    ],
)
def test_a_stated_credential_does_not_leave(text: str, value: str) -> None:
    out, types = scan(text)
    assert value not in out, out
    assert types & {EntityType.SECRET, EntityType.PRIVATE_KEY}, types


def test_a_telegram_token_goes_whole() -> None:
    out, _ = scan(f"{TELEGRAM_ID}:{TELEGRAM_SECRET}")
    assert TELEGRAM_ID not in out and TELEGRAM_SECRET not in out


def test_a_pgp_private_key_block_is_a_private_key() -> None:
    body = "\n".join(_token(64, _ALNUM + "+/") for _ in range(6))
    block = f"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n{body}\n-----END PGP PRIVATE KEY BLOCK-----"
    out, types = scan(f"here it is:\n{block}\nthanks")
    assert EntityType.PRIVATE_KEY in types and body.splitlines()[2] not in out


@pytest.mark.parametrize(
    "text",
    [
        # prose about passwords, in other languages
        "Das Passwort ist falsch.",
        "Le mot de passe est incorrect, réessayez.",
        "パスワードは8文字以上です。",
        "密码错误，请重试。",
        "Пароль: не менее восьми символов",
        "the password should be at least 12 characters",
        "a password, such as one with symbols, is better",
        # names about a credential, not the credential
        "max_tokens: 4096",
        "token_type: bearer",
        "TOKEN_URL=https://auth.example.com/token",
        "PASSWORD_MIN_LENGTH=12",
        "secretName: my-db-secret",
        "secret: my-db-secret",
        'cache_key = "user:1234:profile"',
        "token: GITHUB_TOKEN",
        'password = request.form["password"]',
        "api_key: str = Field(...)",
        "| password | string | yes |",
        'getPassword("smtp")',
        "ERR_LIB_KEY_INVALID:204:invalid key",
        # words, not values
        "The secret sauce is v2-turbo.",
        "set the token to expire after one hour",
        "The token is base64-encoded.",
        "Last week's access_key is 530 days old.",
        "send the token to 10.0.0.1",
        # where a value comes from, and placeholders
        "api_key: !ENV ${API_KEY}",
        "api_key: $(vault kv get -field=api_key secret/app)",
        "export secret=change-me-please",
        'password = "dummytoken"',
        "export API_KEY=notarealkey",
        'vault_db_password: "fake_key_for_testing"',
        # hashes, versions, local defaults, paths
        "hashed_password: $2b$12$" + "a" * 7 + "Qm9vZ3VzSGFzaFZhbHVlRm9yVGVzdGluZzEy",
        "The current password version is 2.15.15",
        "postgres://app:dev@localhost:5432/test",
        "libapi_hash := " + "4f9a" * 16,
        '"spec/defines/key_spec.rb": "6ba8391d8fac22fb6d265cea56c7d823",',
        # flags that are not a value
        "git push --no-password --verbose",
        "the password policy for 2025 is stricter",
        "password SHA256 hashing is used throughout",
        "passwords are rotated every 90 days",
        "docker login --password-stdin < pw.txt",
        "cli --token-file /etc/app/token",
        # an object id with a type prefix, and keys that are not keys
        "customer cus_" + "J4nZ2xK9mQpL7rT1aB",
        "checkout session cs_test_" + "a1B2c3D4e5F6g7H8i9J0kLmN",
        "the key is to start early",
        "the cache key is 5f3a9b2c7d1e4f60a8b9",
        "Key = FBFBFBFBFBFBFBFBFBFBFBFBFBFBFBFB",
        "Key = 31415926535897932384626433832795",
        '"SET" "session:count" "42"',
        "net use Z: \\\\srv\\share /user:CORP\\bob *",
        "see /hooks/pre-commit/install-hooks-script",
    ],
)
def test_near_misses_stay(text: str) -> None:
    out, types = scan(text)
    assert EntityType.SECRET not in types, (text, out)


def test_a_bare_key_needs_a_value_shaped_like_one() -> None:
    assert list(find_statements(f"Key = {HEX_KEY}")) and list(find_statements(f"key: {HEX_KEY_UPPER}"))
    for text in ("cache key: 5f3a9b2c7d1e4f60", "primary key = 8e1f4c2b9d7a3e60", "the key is 5f3a9b2c7d1e4f60"):
        assert not list(find_statements(text)), text


def test_names_say_what_their_value_is() -> None:
    assert name_words("APIPassword") == ("api", "password")
    assert name_words("awsSecretKey") == ("aws", "secret", "key")
    assert name_words("DB_PASS2") == ("db", "pass")
    assert strength("DB_PASS") == "password" and strength("PASS") == "password" and strength("bypass") is None
    assert strength("PGPASSWORD") == "password"
    assert strength("client_secret") == "secret"
    assert strength("HF_TOKEN") == "token" and strength("x-api-key") == "token"
    assert strength("cache_key") is None and strength("api_version") is None and strength("max_tokens") is None
    assert strength("hashed_password") is None and strength("token_url") is None


def test_machine_made_values() -> None:
    assert random_looking(TOKEN)
    assert random_looking("2e455592-1a63-4557-a439-a23b2fad1799")
    assert random_looking("065AADD25710CEE9") and not random_looking("FBFBFBFBFBFBFBFB")
    for word in ("base64-encoded", "auth_service_gateway_68", "cluster.admin.staging.v1", "v2-turbo", "2024-05-01"):
        assert not random_looking(word), word


def test_placeholders_written_together() -> None:
    for value in ("dummytoken", "mysecret", "notarealkey", "change-me-please", "fake_key_for_testing"):
        assert looks_like_placeholder(value), value
    for value in ("hunter2", "Tr0ub4dor&3", "quietmeadow", "atom", "password1"):
        assert not looks_like_placeholder(value), value


def test_the_statement_rule_runs_in_linear_time() -> None:
    """Hostile input of four times the length takes about four times as long, never sixteen."""
    pieces = ["password ", "a_", "HF_TOKEN ist ", "| password ", "<password>", "密码是", "token ref=x token "]
    for piece in pieces:
        took = []
        for reps in (2_000, 8_000):
            started = time.perf_counter()
            list(find_statements(piece * reps))
            took.append(time.perf_counter() - started)
        assert took[1] < 8 * took[0] + 0.05, (piece, took)
