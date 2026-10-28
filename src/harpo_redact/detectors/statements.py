"""Layer 3c: credentials stated without a format of their own, in the ways people state them.

The gitleaks rules know token formats; the prompt rules in ``secret_library`` know English sentences ("my password
is ...", "api_key: ..."). These rules read the rest:

* a credential-named identifier and its value, however they are linked: ``HF_TOKEN=...``, ``"apiKey": "..."``,
  ``DB_PASS=...``, ``$password === '...'``, ``setPassword("...")``, ``define('DD_API_KEY', '...')``,
  ``<password>...</password>``, "the HF_TOKEN is ...", "rotate the API_KEY (...)", "Sein HF_TOKEN ist ...",
  "当前的 TELEGRAM_BOT_TOKEN 是 ...";
* the words for password, key and token in other languages, with their ways of saying "is": "Его пароль: ...",
  "パスワードは ... です", "他的密码是 ...", "A senha dele é ...", "La sua password è ...";
* "set X to Y", a table row ``| passwd | ... |``, a bold name ``**apiKey**: ...`` and SQL's
  ``PASSWORD '...'``.

A value must look like one. After a word ("is", "ist", "是") it must look generated, since prose follows those words
far more often than a secret does; a password-named field in code (a sign, a quoted literal) may hold any word.

All patterns run on RE2, in time linear in the text, and avoid case-folded Unicode letter classes, which RE2 could
only run without its DFA.
"""

from __future__ import annotations

import functools
import math
import re
from collections import Counter
from collections.abc import Iterator
from itertools import pairwise
from typing import Any

import re2

# --------------------------------------------------------------------------- what follows a name
_SIGN = r"===?|!==?|:=|=>|->|<-|=|:"
_SIGNS = frozenset({"===", "==", "!==", "!=", ":=", "=>", "->", "<-", "=", ":"})
# "is" in the languages people write prompts in, and the phrases that bring an example ("such as", "should be").
# Words between blanks only. "to", "on", "er" and "je" are left out: in English they lead anywhere but to a secret
# ("send the token to 10.0.0.1").
_COPULA = (
    r"(?i:is now|is still|is|was|ist|lautet|war|est|était|es|era|è|é|это|là|adalah|är|jest|este|είναι|such as"
    r"|e\.g\.|for example|for instance|should be|might be|could be|would be|must be|which is|which was|that is"
    r"|namely|i\.e\.)"
)
_CJK_LINK = r"(?:是|为|為|は|が|은|는|이|가)[ \t]{0,2}[:：]?"
_QUOTED = (
    r"\"([^\"\n]{1,256})\"|'([^'\n]{1,256})'|`([^`\n]{1,256})`|“([^”\n]{1,256})”|«([^»\n]{1,256})»"
    r"|「([^」\n]{1,256})」"
)
# Chinese, Japanese and Korean script, and their punctuation, end a value: "パスワードはXy9です" holds "Xy9".
_CJK = r"\x{3000}-\x{303F}\x{3040}-\x{30FF}\x{3400}-\x{4DBF}\x{4E00}-\x{9FFF}\x{AC00}-\x{D7AF}\x{FF00}-\x{FFEF}"
_BARE = r"([^\s\"'`“”‘’«»「」" + _CJK + r"]{3,256})"
# A YAML tag or anchor before a value ("!secret ...", "&key ..."); bold that closes after a colon ("**Key:** ...").
_BEFORE_VALUE = r"[ \t]{0,3}[*_]{0,3}[ \t]{0,3}(?:(?:!!?[A-Za-z]{1,20}|&[A-Za-z_][\w-]{0,20})[ \t]+)?"
_VALUE = r"(?:" + _QUOTED + r"|" + _BARE + r")"
_VALUE_GROUPS = 7  # six quoted forms and the bare one
# A few words between a name and its "is": "Das Passwort für den Dienst ist", "A senha dele é", "El DISCORD_TOKEN
# actual es". Any characters but blanks, digits and punctuation.
_WORD = r"[^\s\d.,;:!?()\[\]{}<>\"'`|=*#/\\]{1,20}"


def _filler(most: int) -> str:
    return r"((?:[ \t]+" + _WORD + r"){0," + str(most) + r"}?)"


def _link(fillers: int, *, comma: bool) -> str:
    """Two groups: the words between, then the link. A comma links a word of prose to its value ("the API key,
    Qz7v..., is"); after an identifier it is the next field of a list or an object."""
    return (
        _filler(fillers)
        + r"[*_`'\"]{0,3}[ \t]{0,3}("
        + _SIGN
        + r"|,?[ \t]"
        + _COPULA
        + r"[ \t]|[ \t][—–-][ \t]|"
        + (r",[ \t]|" if comma else "")
        + _CJK_LINK
        + r"|\()"
        + _BEFORE_VALUE
    )


def _options() -> Any:
    options = re2.Options()
    options.log_errors = False
    options.max_mem = 64 << 20
    return options


_OPTIONS = _options()
_STEMS = r"(?i:pass|pwd|pw|secret|token|key|cred|pat|auth)"
_IDENT = r"[A-Za-z0-9_.\-]{0,64}" + _STEMS + r"[A-Za-z0-9_.\-]{0,64}"

# --------------------------------------------------------------------------- credential-named identifiers
# Any identifier with a credential stem inside: the stem decides nothing yet, the words do (see strength()).
_IDENT_RE = re2.compile(
    r"(?:^|[^A-Za-z0-9_.\-])[*_]{0,3}[\"'`]?(" + _IDENT + r")[\"'`]?[*_]{0,3}" + _link(2, comma=False) + _VALUE,
    _OPTIONS,
)
# A name and its value handed over together, the first arguments of a call or a pair in brackets:
# define('DD_API_KEY', '...'), set_var("token", "..."), ("password", "..."). Not a JSON value followed by the next
# key: {"kind": "Secret", "metadata": ...}.
_PAIR_RE = re2.compile(r"[(\[,]\s{0,16}[\"'`](" + _IDENT + r")[\"'`][ \t]*,[ \t]*(?:" + _QUOTED + r")", _OPTIONS)
# A value wrapped in a call of one literal: Some("..."), SecretStr("..."), types.StringValue("..."), new X("...").
_WRAPPED_RE = re.compile(r"(?:new[ \t]+)?([A-Za-z_][\w.:]{0,64})\([ \t]*([\"'])([^\"'\n]{1,256})\2[ \t]*\)")
# <password>...</password>, <ApiKey>...</ApiKey>: the closing tag is checked after the match (RE2 has no
# back-references).
_XML_RE = re2.compile(
    r"<([A-Za-z][\w:.\-]{0,64})(?:[ \t][^<>\n]{0,200})?>[ \t]*([^<>\s]{3,256})[ \t]*</([A-Za-z][\w:.\-]{0,64})>",
    _OPTIONS,
)
# An environment variable written as a name and a value side by side: Kubernetes, ECS and Cloud Run list them as
# {"name": "DB_PASSWORD", "value": "..."} or "- name: DB_PASSWORD / value: ...".
_NAME_VALUE_RE = re2.compile(
    r"(?i:[\"']?name[\"']?)[ \t]*[:=][ \t]*[\"']?(" + _IDENT + r")[\"']?[ \t]*(?:,|\r?\n[ \t]*-?[ \t]*)[ \t]*"
    r"(?i:[\"']?value[\"']?)[ \t]*[:=][ \t]*" + _VALUE,
    _OPTIONS,
)
# Redis: a password given to AUTH or CONFIG SET requirepass, in a client, a config file or MONITOR output; and a key
# whose name says it holds a secret ("SET" "config:jwt_secret" "...").
_REDIS_AUTH_RE = re2.compile(
    r"(?i:\bAUTH)[\"']?[ \t]+(?:[\"'][^\"'\n]{1,64}[\"'][ \t]+)?[\"']([^\"'\n]{3,256})[\"']"
    r"|(?i:requirepass)[\"']?[ \t]+[\"']?([^\s\"']{3,256})",
    _OPTIONS,
)
_REDIS_SET_RE = re2.compile(
    r"(?i:\bSET)[\"']?[ \t]+[\"']([^\"'\s]{1,128})[\"'][ \t]+[\"']([^\"'\n]{3,512})[\"']", _OPTIONS
)
# Windows: "net use Z: \\server\share /user:DOMAIN\name PASSWORD".
_NET_USE_RE = re2.compile(r"(?i:\bnet[ \t]+use\b)[^\n]{0,200}?/user:[^\s\"]+[ \t]+([^\s\"/*][^\s\"<]{2,127})", _OPTIONS)
# SQL: CREATE ROLE app WITH LOGIN PASSWORD '...', CREATE USER x IDENTIFIED BY '...'.
# A command-line flag and its value: "--hf_token hf_...", "--api-key=...", "-password 'x'". The value is the next word,
# never another flag.
_FLAG_RE = re2.compile(r"(?:^|[\s(\"'`])--?(" + _IDENT + r")(=|[ \t]+)" + _VALUE, _OPTIONS)
_SQL_RE = re2.compile(r"(?i:\b(?:password|identified[ \t]+by)[ \t]+)'([^'\s]{3,128})'", _OPTIONS)

# --------------------------------------------------------------------------- the words for password, key, token
_PASSWORD_WORDS = (
    "password", "passphrase", "passcode", "passwords", "passphrases", "passcodes", "passwort", "kennwort",
    "wachtwoord", "mot de passe", "contraseña",
    "contrasena", "senha", "palavra-passe", "palavra passe", "parola d'ordine", "lösenord", "losenord",
    "adgangskode", "passord", "salasana", "jelszó", "jelszo", "hasło", "haslo", "heslo", "şifre", "sifre", "parolă",
    "пароль", "пароля", "паролем", "паролю", "пароле", "κωδικός", "κωδικό", "סיסמה", "סיסמא", "mật khẩu",
    "kata sandi", "kata laluan", "credentials", "credential", "pw",
)  # fmt: skip
_TOKEN_WORDS = (
    "api key", "api-key", "access key", "secret key", "private key", "access token", "auth token", "bearer token",
    "token", "secret", "clé api", "clé d'api", "clé secrète", "jeton", "clave api", "clave de api", "clave secreta",
    "chave de api", "chave api", "chave secreta", "chiave api", "chiave segreta", "api-schlüssel", "schlüssel",
    "zugangsdaten", "токен", "ключ api", "api-ключ", "секретный ключ", "секрет", "klucz api", "api anahtarı",
    "api-sleutel", "key", "api token", "license key", "licence key", "product key", "client secret", "app password",
)  # fmt: skip
# A bare "key" names many things ("the key is to start early", "the cache key is 5f3a..."): its value must look like a
# key someone was given. Capitals, small letters and digits do; after "=" or ":" ("Key = 8abd...") a long random hex
# string does too, unless the word before "key" says it is a kind of key that is not a secret.
_BARE_KEY_WORDS = frozenset({"key"})
_KEY_QUALIFIERS = frozenset(
    """cache object primary foreign sort partition row hash range lookup map dict dictionary registry idempotency
    dedup deduplication routing shard join group index composite natural surrogate unique candidate cluster
    clustering public pub music""".split()  # noqa: SIM905
)
_WORD_BEFORE_RE = re.compile(r"([A-Za-z0-9]+)[ \t_\-.]*$")
_HEX_KEY_RE = re.compile(r"[0-9a-fA-F]{16,128}")
# Written without blanks around them, so no boundary is asked for.
_CJK_PASSWORD_WORDS = ("パスワード", "暗証番号", "パスコード", "密码", "密碼", "口令", "비밀번호", "패스워드")
_CJK_TOKEN_WORDS = (
    "トークン", "APIキー", "アクセスキー", "シークレット", "アクセストークン", "令牌", "密钥", "密鑰", "秘钥",
    "访问令牌", "API密钥", "API 密钥", "凭证", "凭据", "토큰", "API 키", "액세스 키", "비밀 키",
)  # fmt: skip
_PASSWORD_SET = frozenset(w.casefold() for w in _PASSWORD_WORDS + _CJK_PASSWORD_WORDS)


def _alternation(words: tuple[str, ...]) -> str:
    return "|".join(re.escape(w).replace(r"\ ", "[ \t]") for w in sorted(words, key=len, reverse=True))


_NATURAL_RE = re2.compile(
    r"(?:^|[^A-Za-z0-9_])[*_]{0,3}(?i:("
    + _alternation(_PASSWORD_WORDS + _TOKEN_WORDS)
    + r"))[*_]{0,3}"
    + _link(6, comma=True)
    + _VALUE,
    _OPTIONS,
)
# "I changed my password to ...", "your password has been reset to ...": a credential and the value it was set to.
_WORDS = _alternation(_PASSWORD_WORDS + _TOKEN_WORDS)
_CHANGED_TO_RE = re2.compile(
    r"(?i:\b(?:changed?|changing|set|reset|updated?|updating)[ \t]+(?:[A-Za-z]+[ \t]+){0,3}?)(?i:(" + _WORDS + r"))"
    r"(?i:[ \t]+(?:to|into|as))[ \t]*:?[ \t]*" + _VALUE,
    _OPTIONS,
)
_WAS_CHANGED_TO_RE = re2.compile(
    r"(?:^|[^A-Za-z0-9_])(?i:(" + _WORDS + r"))(?i:(?:[ \t]+[A-Za-z]+){0,4}?[ \t]+(?:changed|set|reset|updated)"
    r"[ \t]+(?:to|into|as))[ \t]*:?[ \t]*" + _VALUE,
    _OPTIONS,
)
# "passwords like ...", "a password of ...", "good passwords include: ...": links that name an example or a value only
# straight after the credential's name. After a few words of prose ("your api key might look something like this:
# ...") they would shadow the sign that comes later.
_DIRECT_LINK = r"(?i:including|includes|include|like|of)"
_DIRECT_RE = re2.compile(
    r"(?:^|[^A-Za-z0-9_])[*_]{0,3}(?i:("
    + _alternation(_PASSWORD_WORDS + _TOKEN_WORDS)
    + r"))[*_]{0,3}()([ \t]+"
    + _DIRECT_LINK
    + r"[ \t]*:?[ \t])"
    + _BEFORE_VALUE
    + _VALUE,
    _OPTIONS,
)
# "his password River45!", "the password 7777qwerty7777", "**password** H9g$KpL4mZ!": the word for password and
# then the value, with nothing between. Only a value that mixes letters with digits or symbols counts there.
_ADJACENT_RE = re2.compile(
    r"(?:^|[^A-Za-z0-9_])[*_]{0,3}(?i:(" + _alternation(_PASSWORD_WORDS) + r"))[*_]{0,3}[ \t]+" + _BARE, _OPTIONS
)
_NATURAL_CJK_RE = re2.compile(
    r"(?i:(" + _alternation(_CJK_PASSWORD_WORDS + _CJK_TOKEN_WORDS) + r"))" + _link(0, comma=True) + _VALUE,
    _OPTIONS,
)

# --------------------------------------------------------------------------- "set X to Y", tables
_SET_TO_RE = re2.compile(
    r"(?i:\b(?:set|change|update|reset)[ \t]+(?:the[ \t]+|your[ \t]+|a[ \t]+|an[ \t]+|its[ \t]+)?"
    r"(?:(?:new[ \t]+)?(?:environment|env|config|configuration|shell|secret)[ \t]+(?:variable|var|value|setting)"
    r"[ \t]+)?)[\"'`]?([A-Za-z][A-Za-z0-9_.\-]{0,64}|(?i:password|passphrase|api[ \t]key|access[ \t]key|secret"
    r"[ \t]key|access[ \t]token|auth[ \t]token))[\"'`]?[ \t]+(?i:to|=)[ \t]+" + _VALUE,
    _OPTIONS,
)
_TABLE_ROW_RE = re2.compile(
    r"(?m)^[ \t]*\|?[ \t]*[*_`]{0,3}([A-Za-z][A-Za-z0-9_.\- ]{0,40}?)[*_`]{0,3}[ \t]*\|[ \t]*[`'\"]?"
    r"([^\s|`'\"]{3,128})[`'\"]?[ \t]*\|",
    _OPTIONS,
)

# --------------------------------------------------------------------------- what a name says
_PASSWORD_PARTS = frozenset("password passwd passphrase passcode pwd pw credential credentials creds".split())  # noqa: SIM905
_SECRET_PARTS = frozenset({"secret", "clientsecret", "apisecret"})
_TOKEN_PARTS = frozenset(
    "token apikey pat accesskey secretkey privatekey authtoken accesstoken auth".split()  # noqa: SIM905
)
_PASSWORD_ENDINGS = ("password", "passwd", "passphrase")
_TOKEN_ENDINGS = ("token", "apikey", "accesskey", "secretkey", "privatekey")
# A key that holds no secret: a cache key, a sort key, a primary key, a public key.
NOT_CREDENTIAL_KEY = frozenset(
    """cache sort partition primary foreign public pub publishable idempotency idempotent routing row lookup map dedup
    dedupe cursor page object item entry index shard group composite unique compound translation i18n label message
    msg list dict hash react kv file image host peer natural surrogate candidate join lock cluster bucket table column
    field json yaml hot short shortcut keyboard music sorting sharding header headers""".split()  # noqa: SIM905
)
# The last word of a name that is about a credential rather than the credential: an id, a hash, a URL, a length.
NOT_CREDENTIAL_LAST = frozenset(
    """id ids name names type types url uri urls endpoint path paths file files filename dir length len size count
    format hash hashed hashes sha sha1 sha256 sha512 md5 digest checksum crc fingerprint prefix suffix label hint
    version ver expiry expires expiration exp ttl timeout created updated policy scope scopes mode enabled disabled
    required regex pattern location ref arn field column input error message msg title description strength limit
    level log logs header headers env var variable source provider manager store service region algorithm alg salt
    reset rotation rotated owner holder generator validator validation min max hashers backend jti jwk kid uid guid
    uuid method methods signature sig""".split()  # noqa: SIM905
)
# A name that says its value is a hash of a credential, not the credential: "hashed_password", "password_digest".
HASH_WORDS = frozenset({"hash", "hashed", "digest", "salted"})
_CAMEL_SPLIT_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")
_GETTERS = frozenset(
    """get read fetch load lookup find retrieve has is check validate verify hash encode decode encrypt decrypt
    compare match contains delete remove clear rotate revoke generate gen print log mask redact prompt ask input
    getenv environ env field label placeholder""".split()  # noqa: SIM905
)


@functools.lru_cache(maxsize=4096)
def name_words(name: str) -> tuple[str, ...]:
    """The words of an identifier, lower-cased: "x-api-key", "APIPassword", "awsSecretKey", "DB_PASS2"."""
    words: list[str] = []
    for part in re.split(r"[_.\-\s/$@]+", name):
        words.extend(w.lower() for w in _CAMEL_SPLIT_RE.findall(part) if not w.isdigit())
    return tuple(words)


@functools.lru_cache(maxsize=4096)
def strength(name: str) -> str | None:
    """What a name says its value is: "password", "secret", "token" (a key or token), or None."""
    words = name_words(name)
    if not words or words[-1] in NOT_CREDENTIAL_LAST or not HASH_WORDS.isdisjoint(words):
        return None
    if any(w in _PASSWORD_PARTS or w.endswith(_PASSWORD_ENDINGS) for w in words):
        return "password"
    if words[-1] == "pass" and (len(words) > 1 or name.isupper()):
        return "password"  # DB_PASS, MAIL_PASS, PASS; not "bypass", not "pass: through"
    if any(w in _SECRET_PARTS or w.endswith("secret") for w in words):
        return "secret"
    if any(w in _TOKEN_PARTS or w.endswith(_TOKEN_ENDINGS) for w in words):
        return "token"
    for i, w in enumerate(words):
        if w == "key" and i > 0 and words[i - 1] not in NOT_CREDENTIAL_KEY:
            return "token"
    return None


# --------------------------------------------------------------------------- what a value must look like
_TRAILING = ".,;:!?)]}>"
_TYPE_WORDS = frozenset(
    """string str text varchar char bytes binary integer int number float double boolean bool object array list dict
    map json uuid date datetime timestamp email url enum any optional required hidden password passwd secret token
    mask masked encrypted hashed plaintext plain input field value type form none null nil undefined true false yes
    no on off enabled disabled empty blank unset unknown invalid incorrect wrong expired missing changed reset same
    redacted removed rotated revoked default example sample placeholder changeme todo tbd here below above stored
    saved needed see production staging development""".split()  # noqa: SIM905
)
# Hashes, ciphers and encodings named right after the word for password ("password SHA256 hashing").
_ALGORITHMS = frozenset(
    """md5 sha1 sha-1 sha224 sha256 sha-256 sha384 sha512 sha-512 sha3 aes128 aes-128 aes192 aes256 aes-256 pbkdf2
    argon2 argon2id scrypt bcrypt2 utf8 utf-8 utf16 utf-16 base32 base64 hex256 rsa2048 rsa4096 ntlmv2 ntlm2 2fa mfa2
    totp6""".split()  # noqa: SIM905
)
_URL_RE = re.compile(r"^(?:[a-z][a-z0-9+.\-]*://|www\.)", re.IGNORECASE)
_PATH_RE = re.compile(r"^(?:~|\.{1,2})?(?:/[\w.\-]+){2,}/?$|^(?:~|\.{1,2})?/[\w\-]+\.[A-Za-z0-9]{1,5}$|^[A-Za-z]:\\")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_NUMBER_RE = re.compile(r"^[+-]?\d{1,3}(?:[,.\s]\d{3})*(?:[.,]\d+)?%?$")
# Code, not a value: a call, an index, a member of a well-known object.
# A function in lower case or a dotted name: get_token(), hash(raw), request.form[...], os.getenv(...). A word with
# a capital and a bracket is as often a password ("Zomer(2024)!"); type annotations are named.
_CODE_RE = re.compile(
    r"^(?:[a-z_]\w*\s*[(\[]|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+\s*[(\[]|(?:self|this|cls|config|conf|cfg|settings|env|os"
    r"|process|args|opts|options|params|request|req|ctx|context|app|vault|secrets|credentials|creds|var|local|module"
    r"|data)\.[A-Za-z_]|(?:Optional|List|Dict|Union|Set|Tuple|Annotated|Literal|ClassVar|Final|SecretStr|SecretBytes"
    r"|Mapping|Sequence|Iterable)\[)"
)
# How a name is written: SCREAMING_SNAKE, snake_case, kebab-case or dotted lower case. A generated token mixes cases.
_IDENTIFIER_RE = re.compile(r"^(?:[A-Z][A-Z0-9_]*|[a-z][a-z0-9_.\-]*)$")
# Words joined into a name: "auth_service_gateway_68", "cluster.admin.staging.v1", "my-secret-name".
_WORDY_RE = re.compile(r"^[a-z]+(?:[_\-.](?:[a-z]{2,}|[a-z]{0,3}\d{1,4}))+$")
# Not a credential whatever its name: a password hash in modular crypt format ($2b$..., $argon2id$...), a version.
_HASH_FORMAT_RE = re.compile(r"^\$(?:2[abxy]?|argon2(?:id|i|d)|scrypt|pbkdf2(?:-sha\d+)?|[1567]|y|gy|sha1)\$")
_VERSION_RE = re.compile(r"^v?\d{1,4}(?:\.\d{1,4}){1,3}(?:[-+][0-9A-Za-z.]{1,20})?$")


def wordy(value: str) -> bool:
    """Words joined by separators, each in one case: "auth_service_gateway_68", "Content-Type", "X-Request-Id"."""
    parts = [p for p in re.split(r"[_\-.]", value) if p]
    if any(not (p.islower() or p.istitle() or p.isupper() or p.isdigit()) for p in parts):
        return False  # "mZq4-Tf8W": a generated value mixes cases inside a part
    return bool(_WORDY_RE.match(value.lower()))


# A constant or an environment variable named for the credential it holds ("REDIS_PASSWORD", "DB_PASS"): code that
# reads the secret, never the secret.
_CREDENTIAL_CONSTANT_RE = re.compile(
    r"(?:[A-Z][A-Z0-9]*_)+(?:PASSWORD|PASSWD|PASS|PWD|SECRET|TOKEN|KEY|APIKEY|CREDENTIALS?|AUTH)(?:_[A-Z0-9]+)*"
    r"|(?:PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|CREDENTIALS?)(?:_[A-Z0-9]+)+"
)


def credential_constant(value: str) -> bool:
    """ "REDIS_PASSWORD,", "API_TOKEN": the name of a constant that holds a credential."""
    return bool(_CREDENTIAL_CONSTANT_RE.fullmatch(value.rstrip(",;)")))


def never_a_credential(value: str) -> bool:
    """A password hash, a version number or a constant's name, under any name: "$2y$10$...", "2.15.15",
    "REDIS_PASSWORD"."""
    return bool(_HASH_FORMAT_RE.match(value) or _VERSION_RE.match(value)) or credential_constant(value)


def entropy(value: str) -> float:
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in Counter(value).values()) if n else 0.0


def _kind(c: str) -> int:
    return 0 if c.isdigit() else 1 if c.islower() else 2 if c.isupper() else 3


def generated(core: str) -> bool:
    """A digit, a symbol, or upper case after the first letter: "Tr0ub4dor", "velvet*5142", "kGFoicDG"."""
    inner = core.rstrip(_TRAILING)
    return (
        any(c.isdigit() for c in inner)
        or any(not c.isalnum() for c in inner)
        or (any(c.isupper() for c in inner[1:]) and any(c.islower() for c in inner))
    )


def random_looking(core: str, least: int = 12) -> bool:
    """A value a machine made: mixed character classes that change often. "base64-encoded", "v2-turbo" and
    "auth_service_gateway_68" are words."""
    if len(core) < least or wordy(core):
        return False
    classes = len({_kind(c) for c in core})
    if classes < 2 or entropy(core) < 3.0:
        return False
    if len(core) >= 16 and _HEX_KEY_RE.fullmatch(core) and (core.islower() or core.isupper()):
        return True  # hex in one case ("065AADD25710CEE9"): its letters and digits come in runs by chance
    changes = sum(_kind(a) != _kind(b) for a, b in pairwise(core)) / (len(core) - 1)
    return changes >= (0.22 if len(core) >= 20 else 0.3)


def looks_like_code(value: str) -> bool:
    """A call, an index or a member of a well-known object: request.form["password"], get_token(), self.secret."""
    return bool(_CODE_RE.match(value))


def names_credential(value: str) -> bool:
    """ "token: GITHUB_TOKEN" names where the token is; it is not one."""
    return bool(_IDENTIFIER_RE.match(value)) and strength(value) is not None


def acceptable(value: str, *, kind: str, link: str, quoted: bool, named: bool = False) -> bool:
    """Whether a value stated for a credential looks like one. ``kind`` is what the name says ("password", "secret"
    or "token"); ``link`` is "sign" (code, config, a table), "word" (prose: "is", "ist", "是") or "bracket";
    ``named`` is true when the name is an identifier (DB_PASSWORD), not a word of prose (password)."""
    from .secret_library import _NOT_A_VALUE, _TEMPLATE_RE, looks_like_placeholder
    from .secrets import CODE_REFERENCE_RE, is_encoded_text

    core = value if quoted else value.rstrip(_TRAILING)
    lowered = core.lower()
    if len(core) < 3 or any(c.isspace() for c in core):
        return False  # a passphrase with blanks is the English rules' to judge ("correct horse battery staple")
    if lowered in _TYPE_WORDS or lowered in _NOT_A_VALUE or looks_like_placeholder(core):
        return False
    if _TEMPLATE_RE.match(core) or CODE_REFERENCE_RE.match(core) or set(core) <= set("*xX.#-_•"):
        return False
    if _URL_RE.match(core) or _PATH_RE.match(core) or _EMAIL_RE.match(core) or _CODE_RE.match(core):
        return False
    if names_credential(core) or (core.startswith("[") and core.endswith("]") and core[1:-1].isupper()):
        return False  # where the value comes from, or a placeholder ([SECRET_1]) already
    if is_encoded_text(core) or never_a_credential(core):
        return False  # base64 of readable text (find_encoded judges what it says), a password hash, a version
    plain_name = named and len(core) >= 8 and core.isalpha()  # "db_password は Thunderginger", "client_secret=Abcdefgh"
    if kind == "password":
        if link == "sign":
            return len(core) >= 5 and (quoted or generated(core) or len(core) >= 6) and " " not in core.strip()
        # "Tiger_5211" is a password people make; "environment-specific" is a word of prose.
        words_only = wordy(core) and not any(c.isdigit() for c in core)
        return (len(core) >= 4 and generated(core) and not words_only) or plain_name
    least = 8 if link == "sign" else 12
    return random_looking(core, least) or (kind == "secret" and plain_name)


# --------------------------------------------------------------------------- the rules
def _value(m: Any, first: int) -> tuple[int, int, bool] | None:
    """(start, end, quoted) of the value whose groups start at ``first``."""
    for g in range(first, min(first + _VALUE_GROUPS, m.re.groups + 1)):
        start = m.start(g)
        if start >= 0:
            return start, m.end(g), g < first + _VALUE_GROUPS - 1
    return None


def _link_kind(link: str) -> str:
    link = link.strip()
    if link == "(":
        return "bracket"
    return "sign" if link in _SIGNS else "word"


def _bracketed(text: str, start: int, end: int, quoted: bool) -> int | None:
    """Where a bracketed value ends ("API_KEY (Qz7v...)"), or None when it is not one: a qualifier such as
    "password (base64): ..." or a value that never closes."""
    if quoted:
        close = end + 1  # past the closing quote
        while close < len(text) and text[close] in " \t":
            close += 1
        if close >= len(text) or text[close] != ")":
            return None
        value_end = end
    else:
        cut = text.find(")", start, end)
        if cut <= start:
            return None
        value_end = close = cut
    if text[close + 1 : close + 4].lstrip()[:1] in (":", "="):
        return None
    return value_end


def _emit(text: str, m: Any, kind: str, link: str, first: int, *, named: bool) -> Iterator[tuple[int, int, str]]:
    from .secrets import after_placeholder, in_query, query_value_end

    found = _value(m, first)
    if found is None:
        return
    start, end, quoted = found
    # "DB_PASSWORD=[SECRET_1]\nAPI_URL=...": a value redacted already, then the next line. Characters glued to a
    # placeholder are still a value ("[SECRET_1]Hunter2isMyPass"), and egress verification relies on both.
    glued = after_placeholder(text, start, end)
    if glued is None:
        return
    start = glued
    if not quoted and in_query(text, m.start(1)):
        end = query_value_end(text, start, end)  # "?api_key=Qz7v...&lang=en" keeps "&lang=en"
    if not quoted and link == "sign":
        wrapped = _WRAPPED_RE.match(text, start)
        if wrapped is not None and _GETTERS.isdisjoint(name_words(wrapped.group(1))):
            start, end, quoted = wrapped.start(3), wrapped.end(3), True  # password = Some("..."): the literal
    if quoted:
        while start < end and text[start] in " \t":
            start += 1  # ' zlwkfijq': blanks around a quoted value are not the value
        while end > start and text[end - 1] in " \t":
            end -= 1
    if link == "bracket":
        bracket_end = _bracketed(text, start, end, quoted)
        if bracket_end is None:
            return
        end = bracket_end
        if quoted and named:
            link = "sign"  # setPassword("..."), SecretStr("..."): a literal handed to a credential in code
    if not quoted:
        # A bare value keeps the punctuation after it, as the English rules do: a password may end in "!", and
        # swallowing a full stop costs nothing. A comma or semicolon after it is the sentence's.
        while end > start and text[end - 1] in ",;":
            end -= 1
    if acceptable(text[start:end], kind=kind, link=link, quoted=quoted, named=named):
        yield start, end, "statement"


def find_statements(text: str) -> Iterator[tuple[int, int, str]]:
    """(start, end, rule) of every credential stated in ``text`` that a format rule would not know."""
    lowered = text.lower()
    if any(stem in lowered for stem in ("pass", "pwd", "pw", "secret", "token", "key", "cred", "pat", "auth")):
        yield from _identifiers(text)
        yield from _pairs(text)
        yield from _set_to(text)
        yield from _table_rows(text)
        yield from _flags(text)
        yield from _name_values(text)
        yield from _redis(text)
        yield from _sql(text)
        if "<" in text:
            yield from _xml(text)
    yield from _natural(text)
    yield from _adjacent(text)
    yield from _near(text)
    yield from _changed_to(text)
    yield from _net_use(text)


def _scan(rx: Any, text: str, judge: Any) -> Iterator[tuple[int, int, str]]:
    """Every match ``judge`` accepts. RE2 finds matches that do not overlap, so a match turned down may hide one that
    starts inside it ("...fehler. Sein passwd ist ..." first matches "Authentifizierungsfehler"): the stretch after its
    name is searched again, in a window that holds any match starting there, so the work stays linear."""
    for m in rx.finditer(text):
        found = list(judge(text, m))
        if found:
            yield from found
        else:
            yield from _rescan(rx, text, m.end(1), m.end(), judge, 0)


_WINDOW = 1024  # longer than any match: a name, the words between, a link and a value


def _rescan(rx: Any, text: str, start: int, stop: int, judge: Any, depth: int) -> Iterator[tuple[int, int, str]]:
    if depth > 3 or start >= stop:
        return
    window = text[start : stop + _WINDOW]
    for m in rx.finditer(window):
        if m.start(1) >= stop - start:
            return  # the pass before finds this one
        found = list(judge(window, m))
        if not found:
            found = list(_rescan(rx, window, m.end(1), m.end(), judge, depth + 1))
        yield from ((a + start, b + start, rule) for a, b, rule in found)


def _identifiers(text: str) -> Iterator[tuple[int, int, str]]:
    yield from _scan(_IDENT_RE, text, _identifier)


def _identifier(text: str, m: Any) -> Iterator[tuple[int, int, str]]:
    name = m.group(1)
    kind = strength(name)
    if kind is None:
        return
    link = _link_kind(m.group(3))
    if m.group(2).strip() and link == "sign":
        return  # words between a name and a sign: "token for later = x" is not an assignment
    if link == "bracket" and any(w in _GETTERS for w in name_words(name)):
        return  # getPassword("smtp") names what to look up
    yield from _emit(text, m, kind, link, 4, named=True)


def _pairs(text: str) -> Iterator[tuple[int, int, str]]:
    for m in _PAIR_RE.finditer(text):
        kind = strength(m.group(1))
        if kind is not None:
            yield from _emit(text, m, kind, "sign", 2, named=True)


def _xml(text: str) -> Iterator[tuple[int, int, str]]:
    for m in _XML_RE.finditer(text):
        if m.group(1) != m.group(3):
            continue
        kind = strength(m.group(1).rsplit(":", 1)[-1])
        if kind is not None and acceptable(m.group(2), kind=kind, link="sign", quoted=True, named=True):
            yield m.start(2), m.end(2), "statement"


def _name_values(text: str) -> Iterator[tuple[int, int, str]]:
    if "alue" not in text and "ALUE" not in text:
        return
    for m in _NAME_VALUE_RE.finditer(text):
        kind = strength(m.group(1))
        if kind is not None:
            yield from _emit(text, m, kind, "sign", 2, named=True)


def _redis(text: str) -> Iterator[tuple[int, int, str]]:
    lowered = text.lower()
    if "auth" in lowered or "requirepass" in lowered:
        for m in _REDIS_AUTH_RE.finditer(text):
            g = 1 if m.start(1) >= 0 else 2
            if acceptable(m.group(g), kind="password", link="sign", quoted=g == 1, named=True):
                yield m.start(g), m.end(g), "statement"
    if "set" in lowered:
        for m in _REDIS_SET_RE.finditer(text):
            kind = strength(re.split(r"[:./]", m.group(1))[-1])
            if kind is not None and acceptable(m.group(2), kind=kind, link="sign", quoted=True, named=True):
                yield m.start(2), m.end(2), "statement"


def _net_use(text: str) -> Iterator[tuple[int, int, str]]:
    if "/user:" not in text.lower():
        return
    for m in _NET_USE_RE.finditer(text):
        if acceptable(m.group(1), kind="password", link="sign", quoted=False, named=True):
            yield m.start(1), m.end(1), "statement"


def _flags(text: str) -> Iterator[tuple[int, int, str]]:
    if "-" not in text:
        return
    for m in _FLAG_RE.finditer(text):
        kind = strength(m.group(1))
        found = _value(m, 3)
        if kind is None or found is None or text[found[0] : found[0] + 1] == "-":
            continue
        start, end, quoted = found
        if acceptable(text[start:end], kind=kind, link="sign", quoted=quoted, named=True):
            yield start, end, "statement"


def _sql(text: str) -> Iterator[tuple[int, int, str]]:
    for m in _SQL_RE.finditer(text):
        if acceptable(m.group(1), kind="password", link="sign", quoted=True, named=True):
            yield m.start(1), m.end(1), "statement"


def _natural(text: str) -> Iterator[tuple[int, int, str]]:
    for rx in (_NATURAL_RE, _NATURAL_CJK_RE, _DIRECT_RE):
        yield from _scan(rx, text, _natural_one)


def _natural_one(text: str, m: Any) -> Iterator[tuple[int, int, str]]:
    word = " ".join(m.group(1).casefold().split())
    kind = "password" if word in _PASSWORD_SET else "token"
    link = _link_kind(m.group(3))
    if m.group(2).strip() and m.group(3).strip() in _SIGNS - {":"}:
        return  # "token ref=...": the name before "=" is "ref"
    if word in _BARE_KEY_WORDS:
        found = _value(m, 4)
        value = text[found[0] : found[1]] if found else ""
        if not _a_key_value(text, m.start(1), value, signed=link == "sign"):
            return
    if link == "sign":
        link = "word"  # a word of prose, not an identifier: "Password: sunshine" is left to the English rules
    yield from _emit(text, m, kind, link, 4, named=False)


def _a_key_value(text: str, at: int, value: str, *, signed: bool) -> bool:
    """Whether the value after a bare "key" (at ``at``) looks like a key someone was given."""
    if any(c.isupper() for c in value) and any(c.islower() for c in value) and any(c.isdigit() for c in value):
        return True
    before = _WORD_BEFORE_RE.search(text, max(0, at - 32), at)
    if not signed or (before is not None and before.group(1).casefold() in _KEY_QUALIFIERS):
        return False
    core = value.strip("'\"`").rstrip(_TRAILING)
    return (
        _HEX_KEY_RE.fullmatch(core) is not None
        and any(c.isalpha() for c in core)
        and any(c.isdigit() for c in core)
        and entropy(core) >= 3.0
    )


def _adjacent(text: str) -> Iterator[tuple[int, int, str]]:
    from .opaque import opaque_capitals, random_letters
    from .secret_library import looks_like_placeholder
    from .secrets import after_placeholder

    for m in _ADJACENT_RE.finditer(text):
        glued = after_placeholder(text, m.start(2), m.end(2))
        if glued is None:
            continue  # "password [SECRET_1]\\nmachine ...": redacted already, then the next line
        start, end = glued, m.end(2)
        while end > start and text[end - 1] in ",;":
            end -= 1  # a comma or semicolon after the value is the sentence's (as in _emit)
        core = text[start:end].rstrip(_TRAILING)
        if text[m.start(1) - 1 : m.start(1)] == "-" or core.startswith("-"):
            continue  # "--no-password --verbose": flags
        letters = sum(c.isalpha() for c in core)
        # Letters alone are a word ("password reset"), unless no one writes them as one ("password DVSqTIIxXPUq").
        opaque = letters == len(core) and (random_letters(core, cued=True) or opaque_capitals(core, cued=True))
        if len(core) < 6 or letters == 0 or (letters == len(core) and not opaque) or core.lower() in _ALGORITHMS:
            continue
        if looks_like_placeholder(core) or never_a_credential(core):
            continue
        if any(rx.match(core) for rx in (_URL_RE, _PATH_RE, _EMAIL_RE, _CODE_RE)):
            continue
        if opaque or acceptable(core, kind="password", link="word", quoted=False):
            yield start, end, "statement"


# "Passwort möglicherweise 15/01/1990 und BfnMnQaGjPdc", "passwords, including SwiHUSxCiN3I and hYzsNGBVkghS": a value
# that no one writes as a word, a few words after a password word and in the same sentence, is that password.
_NEAR_RE = re2.compile(r"(?:^|[^A-Za-z0-9_])(?i:(" + _alternation(_PASSWORD_WORDS) + r"))(?:[^A-Za-z0-9_]|$)", _OPTIONS)
_NEAR_REACH = 80
_NEAR_TOKEN_RE = re.compile(r"(?<![\w\-./@#$%&+=\\])[A-Za-z0-9]{8,40}(?![\w\-/@\\+=])")
_SENTENCE_END_RE = re.compile(r"[.!?;](?:\s|$)|\n")


def _near(text: str) -> Iterator[tuple[int, int, str]]:
    from .opaque import opaque_capitals, random_letters

    for m in _NEAR_RE.finditer(text):
        start = m.end(1)
        stop = min(len(text), start + _NEAR_REACH)
        sentence = _SENTENCE_END_RE.search(text, start, stop)
        if sentence is not None:
            stop = sentence.start()
        for token in _NEAR_TOKEN_RE.finditer(text, start, min(len(text), stop + 41)):  # 41: past the longest token
            if token.end() > stop:
                break
            value = token.group()
            if random_letters(value, cued=True) or opaque_capitals(value, cued=True):
                yield token.start(), token.end(), "statement"


def _changed_to(text: str) -> Iterator[tuple[int, int, str]]:
    for rx in (_CHANGED_TO_RE, _WAS_CHANGED_TO_RE):
        for m in rx.finditer(text):
            word = " ".join(m.group(1).casefold().split())
            kind = "password" if word in _PASSWORD_SET else "token"
            yield from _emit(text, m, kind, "word", 2, named=False)


def _set_to(text: str) -> Iterator[tuple[int, int, str]]:
    for m in _SET_TO_RE.finditer(text):
        kind = strength(m.group(1))
        if kind is not None:
            yield from _emit(text, m, kind, "word", 2, named=True)


def _table_rows(text: str) -> Iterator[tuple[int, int, str]]:
    if "|" not in text:
        return
    for m in _TABLE_ROW_RE.finditer(text):
        kind = strength(m.group(1).strip().replace(" ", "_"))
        if _NUMBER_RE.match(m.group(2)):
            continue  # | generic_password | 3,342 |: a count in a table about passwords
        if kind is not None and acceptable(m.group(2), kind=kind, link="sign", quoted=False, named=True):
            yield m.start(2), m.end(2), "statement"
