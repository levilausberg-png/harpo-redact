"""Layers 3-5: credentials, encoded payloads and the protected-term registry."""

from __future__ import annotations

import base64
import binascii
import math
import re
from collections import Counter
from collections.abc import Callable, Iterator

from ..entities import CUSTOM_SOURCE, PLACEHOLDER_RE, Span, make_span
from ..entities import EntityType as E
from .patterns import URL_CREDENTIALS_RE
from .statements import credential_constant

# --------------------------------------------------------------------------- secrets
# Any label words ("EC", "RSA", "OPENSSH", or look-alike letters that normalisation leaves alone, like a Cyrillic
# "ЕС"): a key is redacted in place, so the whole block must be found, not just the line that names it. OpenPGP
# armours its secret keys as "PGP PRIVATE KEY BLOCK".
PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:[^\s-]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?"
    r"(?:-----END (?:[^\s-]+ )*PRIVATE KEY(?: BLOCK)?-----|\Z)"
)

_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?<![\w-])sk-(?:ant-|proj-|svcacct-|admin-)?[A-Za-z0-9][A-Za-z0-9_\-]{19,}"),
    re.compile(r"(?<!\w)[rsp]k_(?:live|test)_[A-Za-z0-9]{16,}"),
    # access key ids (AKIA, ASIA, ABIA, ACCA); a principal's unique id (AIDA, AROA, ...) names a user or a role and is
    # an account identifier (detectors/formats.py), not a key
    re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}(?![A-Z0-9])"),
    re.compile(r"(?<!\w)(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
    re.compile(r"(?<!\w)xox[abposr]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]+"),
    re.compile(r"(?<![\w-])AIza[0-9A-Za-z_\-]{35}(?![\w-])"),
    re.compile(r"(?<![\w-])eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
    # Harpo's own gateway keys (and the two formats before the rename): 32 random bytes, base64url
    re.compile(r"(?<![\w-])(?:harpo_|pag_|pk-)[A-Za-z0-9_\-]{43}(?![\w-])"),
)

ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?P<cue>password|passwd|pwd|passphrase|secret|client[_\-]?secret|api[_\-]?key|apikey"
    r"|access[_\-]?token|auth[_\-]?token)\b[\"']?\s*(?P<sep>[:=]|=>|\bis\b)\s*"
    # a quoted value runs to its closing quote (spaces and escaped quotes included); a bare one to a blank or quote
    r"(?:\"(?P<dq>(?:[^\"\\\n]|\\.){1,256})\"|'(?P<sq>[^'\n]{1,256})'|[\"']?(?P<value>[^\s\"',;]{6,}))"
)
BEARER_RE = re.compile(r"(?i)\bbearer\s+(?P<value>[A-Za-z0-9._~+/\-]{16,}=*)")
# The value of an AWS access key id setting, whatever its length: half of a key pair ("AWS_ACCESS_KEY_ID=AKIA...").
_AWS_KEY_ID_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])aws[_\-]?access[_\-]?key(?:[_\-]?id)?[\"']?[ \t]*(?:=|:|=>)[ \t]*[\"']?"
    r"(?P<v>(?-i:(?:AKIA|ASIA|ABIA|ACCA|A3T)[A-Z0-9]{8,36}))(?![A-Za-z0-9])"
)

# Reading a secret from somewhere is not the secret: os.environ["X"], getenv("X"), process.env.X
CODE_REFERENCE_RE = re.compile(
    r"^(?:os\.environ|os\.getenv|environ|getenv|process\.env|System\.getenv|std::getenv|ENV|Env|config|settings"
    r"|secrets|vault|keyring|Environment\.GetEnvironmentVariable)\b\s*[\[(.]"
)
# Where a value comes from rather than the value: ${DB_PASSWORD}, {{ secrets.X }}, <your-key>, $(vault kv get ...),
# a YAML tag (!ENV, !Ref, !vault), an Azure Key Vault reference, Ruby or ERB interpolation.
_TEMPLATE_VALUE_RE = re.compile(
    r"^(?:\$\{.*\}|\$[A-Za-z_]\w*|%[A-Za-z_]\w*%|\{\{.*\}\}|<.*>|%\(.*\)s|\*+|x+|\.+|\[[A-Z_]+(?:_\w+)?\]"
    r"|\$\(.*|!!?[A-Za-z]+(?:[.:][A-Za-z]+)*|@Microsoft\.KeyVault\(.*|#\{.*\}|%\{.*\}|<%.*)$"
)


def _looks_like_secret_value(value: str, *, strict: bool = False) -> bool:
    """Heuristic for assignment values: plain words ("required", "Paris") are not secrets.

    ``strict`` is used after the word "is", where prose is common: it demands a
    digit or a symbol rather than accepting unusual capitalisation alone.
    """
    if _TEMPLATE_VALUE_RE.match(value) or CODE_REFERENCE_RE.match(value) or credential_constant(value):
        return False
    stem = value.rstrip(".\u2026")
    if len(value) - len(stem) >= 1 and value.endswith(("...", "\u2026")) and (len(stem) <= 3 or stem[-1] in "_-"):
        return False  # documentation: api_key="harpo_...", "sk-..."; "Tr0ub4dor..." is a password and an ellipsis
    has_digit = any(c.isdigit() for c in value)
    has_symbol = any(not c.isalnum() for c in value.rstrip(".!?"))
    inner_upper = any(c.isupper() for c in value[1:]) and any(c.islower() for c in value)
    if strict:
        return has_digit or has_symbol
    return has_digit or has_symbol or inner_upper


def _entropy(value: str) -> float:
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in Counter(value).values()) if n else 0.0


def is_placeholder_token(token: str) -> bool:
    """``ghp_xxxxxxxx...``, ``sk-XXXXXXXX...``, ``AKIA0000000000000000``: a token's shape filled with one
    repeated character, as documentation writes it. A generated token is never this uniform."""
    return _entropy(token) < 2.5


def after_placeholder(text: str, start: int, end: int) -> int | None:
    """Where a credential's value really starts, when it starts with a placeholder.

    "api_key=[SECRET_1]&lang=en": the value was redacted already and "&lang=en" is the next field, so there is
    nothing to find (None). "password: [PERSON_1]Hunter2isMyPass": the characters glued to the placeholder are
    still checked as the value, so a placeholder cannot carry a password past the scan.
    """
    lead = PLACEHOLDER_RE.match(text[start:end])
    if lead is None:
        return start
    rest = start + lead.end()
    if rest >= end or not text[rest].isalnum():
        return None
    return rest


_QUERY_FIELD_RE = re.compile(r"&(?:amp;)?[A-Za-z_][\w.\-]{0,40}=")


def in_query(text: str, cue_start: int) -> bool:
    """Whether a credential's name is itself a URL query field: "?api_key=..." or "&token=..."."""
    return text[max(0, cue_start - 5) : cue_start].endswith(("?", "&", "&amp;"))


def query_value_end(text: str, start: int, end: int) -> int:
    """Where a value in a URL query ends: before the next field ("api_key=Qz7v...&lang=en" keeps "&lang=en"). Only
    for a credential that is a query field itself: "DB_PASSWORD=Tr0ub4dor&key=3xZq!" is one password."""
    m = _QUERY_FIELD_RE.search(text, start, min(len(text), end + 48))  # "&amp;lang=" may run past a value cut at ";"
    return m.start() if m is not None and m.start() < end else end


# A config line up to a password's value: YAML "password: ", INI "password = ", properties "db.password=". Not a shell
# line: "PGPASSWORD=x psql -h db" runs psql, with one word as the password.
_CONFIG_HEAD_RE = re.compile(
    r"(?m)^[ \t]{0,32}(?:\+[ \t]{0,4})?(?:-[ \t]{1,4})?(?:"
    r"[\"']?[A-Za-z_][\w.\-]{0,63}[\"']?(?:[ \t]{0,4}:[ \t]{1,8}|[ \t]{1,4}=[ \t]{0,8}|=[ \t]{1,8})"
    r"|[a-z][a-z0-9_\-]{0,40}(?:\.[a-z0-9_\-]{1,40}){1,8}=[ \t]{0,8})"
)
_COMMENT_AFTER_RE = re.compile(r"[ \t]{1,64}[#;]")
# Well-known default passwords. On a machine of one's own (localhost, a loopback address, or a one-word host such as
# a Compose service, "db" or "postgres") they document a local setup and give nothing away; with any other password,
# or on any other host, a connection URL's password is redacted.
DEFAULT_PASSWORDS = frozenset(
    """password pass passwd pwd secret changeme change_me change-me changeit example test testing dev development
    local postgres mysql mariadb redis mongo mongodb rabbitmq guest root admin user default demo sample
    dummy toor""".split()  # noqa: SIM905
)
_LOCAL_HOST_RE = re.compile(
    r"(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1\]|host\.docker\.internal|[A-Za-z][\w-]{0,62})"
    r"(?::\d{1,5})?(?=[/?#\s\"'`,;)]|\Z)"
)
PASSWORD_CUES = ("password", "passwd", "pwd", "passphrase")


def config_value_end(text: str, cue_start: int, start: int, end: int) -> int:
    """Where a password's unquoted value ends. On a config line it is the rest of the line without a comment, blanks
    included: "password: correct horse battery staple  # rotated". Anywhere else it is one word, and so it is when
    the rest looks like code or a list ("password = hash(raw)", "password: x, user: y")."""
    if end >= len(text) or text[end] not in " \t":
        return end
    line = text.rfind("\n", 0, cue_start) + 1
    if not _CONFIG_HEAD_RE.fullmatch(text, line, start):
        return end
    stop = text.find("\n", end)
    stop = len(text) if stop < 0 else stop
    rest = text[end:stop]
    comment = _COMMENT_AFTER_RE.search(rest)
    rest = (rest[: comment.start()] if comment else rest).rstrip()
    if not rest or len(rest) > 128 or ", " in rest or any(c in rest for c in '(){}[]=;`"\\'):
        return end
    return end + len(rest)


# Words of a sentence rather than of a passphrase: "will send it later" is a note, "correct horse battery staple"
# is not.
_SENTENCE_WORDS = frozenset(
    """a an the and or but for to of in on at by with from it is are was be will can see ask use not no this that your
    my our you we me here there later please""".split()  # noqa: SIM905
)


def quoted_value_is_secret(value: str, *, strict: bool = False) -> bool:
    """A quoted value under a credential's name. Without blanks it is judged like any value; with blanks it must
    look generated (a digit or a symbol) or be a passphrase: four or more lower-case words, at most one of them a
    word that sentences are made of."""
    if not any(c.isspace() for c in value):
        return len(value) >= 6 and _looks_like_secret_value(value, strict=strict)
    if len(value) < 8 or _TEMPLATE_VALUE_RE.match(value):
        return False
    words = value.split()
    if any(c.isdigit() for c in value) or any(not (c.isalnum() or c.isspace() or c in ".,!?'") for c in value):
        return True
    plain = len(words) >= 4 and all(w.isalpha() and w.islower() for w in words)
    return plain and sum(w in _SENTENCE_WORDS for w in words) <= 1


def find_secrets(text: str) -> Iterator[Span]:
    from .secret_library import looks_like_placeholder  # the library imports this module
    from .statements import looks_like_code, wordy

    for m in PEM_PRIVATE_KEY_RE.finditer(text):
        yield make_span(m.start(), m.end(), E.PRIVATE_KEY, "secret", "pem:" + m.group()[-48:])
    for pattern in _TOKEN_PATTERNS:
        for m in pattern.finditer(text):
            if not is_placeholder_token(m.group()):
                yield make_span(m.start(), m.end(), E.SECRET, "secret", m.group())
    for m in ASSIGNMENT_RE.finditer(text):
        group = "dq" if m.group("dq") is not None else "sq" if m.group("sq") is not None else "value"
        start = after_placeholder(text, m.start(group), m.end(group))
        if start is None:
            continue
        end = m.end(group)
        strict = m.group("sep").lower() == "is"
        if group == "value" and in_query(text, m.start()):
            end = query_value_end(text, start, end)
        elif group == "value" and not strict and m.group("cue").lower() in PASSWORD_CUES:
            wide = config_value_end(text, m.start(), start, end)
            if wide > end and quoted_value_is_secret(text[start:wide]):
                yield make_span(start, wide, E.SECRET, "secret", text[start:wide])
                continue
        value = text[start:end]
        if looks_like_placeholder(value) or looks_like_code(value):
            continue  # export secret=change-me-please, password: example_password, password = request.form[...]
        if m.group("cue").lower() not in PASSWORD_CUES and wordy(value):
            continue  # secret: my-db-secret names a secret; a key or token is not made of words
        if (
            quoted_value_is_secret(value, strict=strict)
            if group != "value"
            else (len(value) >= 6 and _looks_like_secret_value(value, strict=strict))
        ):
            yield make_span(start, end, E.SECRET, "secret", value)
    for m in _AWS_KEY_ID_ASSIGNMENT_RE.finditer(text):
        if not is_placeholder_token(m.group("v")):
            yield make_span(m.start("v"), m.end("v"), E.SECRET, "secret", m.group("v"))
    for m in BEARER_RE.finditer(text):
        yield make_span(m.start("value"), m.end("value"), E.SECRET, "secret", m.group("value"))
    for m in URL_CREDENTIALS_RE.finditer(text):
        if _TEMPLATE_VALUE_RE.match(m.group(1)) or CODE_REFERENCE_RE.match(m.group(1)):
            continue  # postgres://app:${POSTGRES_PASSWORD}@db names where the password comes from
        if m.group(1).lower() in DEFAULT_PASSWORDS and _LOCAL_HOST_RE.match(text, m.end()):
            continue  # postgres://app:dev@localhost:5432/test: a local setup's default, not a secret
        yield make_span(m.start(1), m.end(1), E.SECRET, "secret", m.group(1))


# --------------------------------------------------------------------------- encoded data
B64_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9+/=_\-])[A-Za-z0-9+/_\-]{8,}={0,2}(?![A-Za-z0-9+/=_\-])")
_B64_SHORT = 24  # below this a run must also look encoded: a digit, a symbol or mixed case
_HEX_RE = re.compile(r"[0-9a-fA-F]+")
# Hex-encoded text: a run of byte pairs ("6a616e65..."), optionally 0x-prefixed, or bytes apart by a space or
# colon as a hex dump prints them ("6a 61 6e 65 ...").
HEX_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Za-z])(?:0x)?((?:[0-9a-fA-F]{2}){6,})(?![0-9A-Za-z])"
    r"|(?<![0-9A-Za-z:])((?:[0-9a-fA-F]{2}[ :]){5,}[0-9a-fA-F]{2})(?![0-9A-Za-z:])"
)
_PREFIX = 64  # how far back on the same line a cue for an encoded value is looked for


def _printable(decoded: str, share: float) -> bool:
    return bool(decoded) and sum(c.isprintable() or c in "\n\r\t" for c in decoded) / len(decoded) >= share


def decode_base64_text(token: str) -> str | None:
    """The text a base64 (or base64url) run encodes, or None when it does not decode to readable text."""
    body = token.rstrip("=")
    if _HEX_RE.fullmatch(body) or body.isdigit():
        return None
    if body.isalpha() and (body.islower() or body.isupper() or body.istitle()):
        return None  # an ordinary word; base64 of digits is letters too, but in mixed case ("MTExMjIy")
    padded = body.replace("+", "-").replace("/", "_") + "=" * (-len(body) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
        decoded = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return decoded if _printable(decoded, 0.85) else None


def decode_hex_text(token: str) -> str | None:
    """The text a run of hex bytes encodes, or None. Hashes and keys decode to random bytes and are left alone."""
    try:
        decoded = bytes.fromhex(re.sub(r"[ :]", "", token)).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return decoded if _printable(decoded, 0.95) else None


def _looks_encoded(run: str) -> bool:
    """Long runs always qualify; a short one must also look encoded: a digit, a symbol or mixed case."""
    return len(run) >= _B64_SHORT or (
        any(c.isdigit() or c in "+/=_-" for c in run) or (run.lower() != run and run.upper() != run)
    )


def is_encoded_text(value: str) -> bool:
    """A whole value that is a base64 run of readable text: encoded content, to be judged by what it decodes to.

    Detectors that would take such a value as a credential or an ID leave it to ``find_encoded``, which decodes
    it and scans the text with the words before it ("password (base64): ..." still finds the password)."""
    return bool(B64_CANDIDATE_RE.fullmatch(value)) and _looks_encoded(value) and decode_base64_text(value) is not None


def _candidates(text: str) -> Iterator[tuple[int, int, str]]:
    for m in B64_CANDIDATE_RE.finditer(text):
        run = m.group()
        if not _looks_encoded(run):
            continue
        decoded = decode_base64_text(run)
        if decoded is not None:
            yield m.start(), m.end(), decoded
    for m in HEX_CANDIDATE_RE.finditer(text):
        group = 1 if m.group(1) is not None else 2
        decoded = decode_hex_text(m.group(group))
        if decoded is not None:
            yield m.start(), m.end(), decoded


def find_encoded(
    text: str,
    scan: Callable[[str], list[Span]],
    depth: int = 0,
    max_depth: int = 2,
) -> Iterator[Span]:
    """Decode base64 and hex runs and rescan them; a hit redacts the whole run.

    ``scan`` is the deterministic detector set (patterns, secrets, registry).
    Nested encodings are followed up to ``max_depth`` levels.
    """
    for start, end, decoded in _candidates(text):
        # The words before the run travel with it, so a cue outside ("BSN MTIzNDU2Nzg5") still counts.
        prefix = text[max(0, start - _PREFIX) : start].rsplit("\n", 1)[-1]
        hits = [s for s in scan(prefix + decoded) if s.end > len(prefix)]
        inner: set[E] = {s.type for s in hits}
        # Which custom types (and whether the registry) found something inside: their policy still applies.
        marks = {src for s in hits for src in s.sources if src.startswith(CUSTOM_SOURCE) or src == "registry"}
        if depth + 1 < max_depth:
            for nested in find_encoded(decoded, scan, depth + 1, max_depth):
                inner.add(nested.type)
                inner.update(nested.inner)
                marks.update(src for src in nested.sources if src.startswith(CUSTOM_SOURCE) or src == "registry")
        if inner:
            sources = frozenset({"encoded", *marks})
            yield Span(start, end, E.ENCODED_DATA, sources, text[start:end], 1.0, frozenset(inner))


# --------------------------------------------------------------------------- registry
_TERM_SEPARATORS_RE = re.compile(r"[\s_.\-]+")


def term_chunks(term: str) -> list[str]:
    """The parts of a term between separators. "x-ray" and "Project Bluefin" have two each; "- - -" has none.

    A term is matched as its parts with up to three separators between them. Splitting on every separator (not only
    on blanks) keeps the parts and the separators apart, so the pattern is unambiguous: linear time, whatever term
    an administrator enters."""
    return [c for c in _TERM_SEPARATORS_RE.split(term) if c]


def _term_pattern(term: str) -> str:
    return r"[\s_.\-]{0,3}".join(re.escape(chunk) for chunk in term_chunks(term))


class Registry:
    """Organisation-specific protected terms (exact) and patterns (regex)."""

    def __init__(self, terms: list[str], patterns: list[str]) -> None:
        cleaned = sorted({" ".join(t.split()) for t in terms if term_chunks(t)}, key=len, reverse=True)
        # Words of a term may be apart by any whitespace (a line break), or written as one identifier
        # ("project_bluefin", "Project-Bluefin", "ProjectBluefin").
        self._terms_re = (
            re.compile(r"(?<!\w)(?:" + "|".join(_term_pattern(t) for t in cleaned) + r")(?!\w)", re.IGNORECASE)
            if cleaned
            else None
        )
        self._patterns = [re.compile(p) for p in patterns]

    @property
    def empty(self) -> bool:
        return self._terms_re is None and not self._patterns

    def find(self, text: str) -> Iterator[Span]:
        if self._terms_re is not None:
            for m in self._terms_re.finditer(text):
                yield make_span(m.start(), m.end(), E.PROTECTED_TERM, "registry", m.group().casefold())
        for pattern in self._patterns:
            for m in pattern.finditer(text):
                if m.end() > m.start():
                    yield make_span(m.start(), m.end(), E.PROTECTED_TERM, "registry", m.group().casefold())
