"""Layer 3b: a credential library of 220+ rules, matched with RE2.

* The gitleaks rule set (MIT, vendored in ``data/gitleaks.toml``): provider
  tokens, cloud keys, webhooks and connection strings, each with gitleaks'
  keyword prefilter, entropy threshold and allowlists.
* Rules written for prompts rather than repositories: credentials stated in
  a sentence ("my password is hunter2"), HTTP Basic credentials, and BIP39
  wallet recovery phrases.

Matching uses RE2, which runs in time linear in the input. No prompt can make
a rule backtrack catastrophically, and the gitleaks patterns keep the exact
meaning they have in gitleaks.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
import tomllib
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any

import re2

from ..entities import PLACEHOLDER_RE, Span, make_span
from ..entities import EntityType as E
from .secrets import (
    CODE_REFERENCE_RE,
    after_placeholder,
    config_value_end,
    in_query,
    is_encoded_text,
    is_placeholder_token,
    query_value_end,
    quoted_value_is_secret,
)
from .statements import (
    HASH_WORDS,
    NOT_CREDENTIAL_KEY,
    NOT_CREDENTIAL_LAST,
    find_statements,
    looks_like_code,
    name_words,
    never_a_credential,
    wordy,
)

GITLEAKS_SOURCE = "github.com/gitleaks/gitleaks config/gitleaks.toml at commit b58d3f1"


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in Counter(value).values())


@dataclass(frozen=True, slots=True)
class _Allow:
    target: str  # "secret", "match" or "line"
    regexes: tuple[Any, ...]
    stopwords: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SecretRule:
    id: str
    pattern: Any  # a compiled re2 pattern
    keywords: tuple[str, ...]
    entropy: float | None
    secret_group: int | None
    allows: tuple[_Allow, ...]


def _as_list(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _compile_allow(entry: dict[str, Any]) -> _Allow | None:
    regexes = entry.get("regexes") or []
    stopwords = entry.get("stopwords") or []
    # Path and commit conditions describe repositories. Under AND they can
    # never hold for a prompt, so the whole entry is skipped.
    if (entry.get("paths") or entry.get("commits")) and str(entry.get("condition", "OR")).upper() == "AND":
        return None
    if not regexes and not stopwords:
        return None
    return _Allow(
        str(entry.get("regexTarget", "secret")),
        tuple(re2.compile(r) for r in regexes),
        tuple(s.lower() for s in stopwords),
    )


def parse_rules(raw: str, disabled: Iterable[str] = ()) -> tuple[list[SecretRule], list[_Allow]]:
    """Parse a gitleaks-format TOML document into compiled rules and global allowlists."""
    cfg = tomllib.loads(raw)
    skip = set(disabled)
    global_allows = [
        a for entry in _as_list(cfg.get("allowlist")) + _as_list(cfg.get("allowlists")) if (a := _compile_allow(entry))
    ]
    rules: list[SecretRule] = []
    for r in cfg.get("rules", []):
        if r["id"] in skip or "regex" not in r:
            continue
        allows = tuple(
            a for entry in _as_list(r.get("allowlist")) + _as_list(r.get("allowlists")) if (a := _compile_allow(entry))
        )
        rules.append(
            SecretRule(
                id=r["id"],
                pattern=re2.compile(r["regex"]),
                keywords=tuple(k.lower() for k in r.get("keywords", [])),
                entropy=r.get("entropy"),
                secret_group=r.get("secretGroup"),
                allows=allows,
            )
        )
    return rules, global_allows


# --------------------------------------------------------------------------- prompt rules
# Only password-like cues accept a plain word ("my password is sunshine"). A PIN or code
# must contain a digit: "a belaying pin is found too large" is Moby-Dick, not a PIN.
_STRONG_CUES = ("password", "passwd", "passphrase", "pwd", "wachtwoord", "passwort", "kennwort", "mot de passe")
# Cues whose value may be short: passwords, PINs and one-time codes. An API key, token or client secret is long, so
# "the staging access_key is 530" is not one.
_SHORT_VALUE_CUES = (
    *_STRONG_CUES, "pass", "pin", "security", "verification", "one", "otp", "2fa", "recovery", "backup", "contrase"
)  # fmt: skip
_KEY_MIN = 8
# RE2 has no lookbehind, so \b anchors the optional prefix: DB_PASSWORD, mysql.pwd and ADMIN-PASSWORD all
# count as the cue "password". Group 1 is the prefix, 2 the cue word, 3 the value.
_NL_CUES = (
    r"(pass(?:word|wd|phrase|code)|pwd|pin(?:[\s_-]?code)?|security[\s_-]?code|verification[\s_-]?code"
    r"|one[- ]time[\s_-]?code|otp|2fa[\s_-]?code|recovery[\s_-]?code|backup[\s_-]?code"
    r"|(?:api|access|secret|auth|private|client|signing|encryption)[\s_-]?(?:key|token|secret)"
    r"|wachtwoord|passwort|kennwort|mot\s+de\s+passe|contrase(?:ñ|n)a)"
)
_NL_CREDENTIAL_RE = re2.compile(
    r"(?i)\b((?:[A-Za-z0-9]+[_.\-])*)"
    + _NL_CUES
    + r"(?:\s+(?:for|of|to|on|van|voor)\s+[\w.@-]+){0,2}"
    # "password (base64): ...", and the closing quote of a key: "password": "..."
    + r"(?:\s?\([^()\n]{0,30}\))?[\"'`]?"
    + r"\s*(?:is\s+now|is\s+still|will\s+be|set\s+to|changed\s+to|reset\s+to|is|was|ist|est|=>|->|=|:)\s*"
    # a quoted value runs to its closing quote (groups 3 and 4); a bare one to a blank or a quote (group 5)
    + r"(?:\"((?:[^\"\\\n]|\\.){1,256})\"|'([^'\n]{1,256})'"
    + r"|[\"'`\x{201C}\x{2018}]?([^\s\"'`\x{201D}\x{2019}]{3,128}))"
)
# The cue and then the value with nothing in between ("AWS secret access key wJalr...", "password Tr0ub4dor&3x").
# Without a linking word or sign this is mostly prose ("password manager", "API key rotation"), so the value must
# look generated: eight or more characters from at least three of upper case, lower case, digits and symbols.
_NL_BARE_RE = re2.compile(
    r"(?i)\b((?:[A-Za-z0-9]+[_.\-])*)"
    + _NL_CUES
    + r"[ \t]{1,3}[\"'`\x{201C}\x{2018}]?([^\s\"'`\x{201D}\x{2019}]{8,128})"
)
# Between the cue and the value: a sign, not a word ("password: a b c" is a config line, "password is a" prose).
_LINKED_BY_SIGN_RE = re.compile(r"[\"'`]?[ \t]{0,8}[:=][ \t]{0,8}")
_NOT_A_VALUE = frozenset(
    """required incorrect invalid wrong correct expired missing empty blank set unset changed reset same
    different strong weak secure insecure long short too not the a an in on at for to from with without
    stored saved hidden shown encrypted hashed sensitive case-sensitive valid still now being been here
    there below above attached included provided needed necessary mandatory optional unknown known secret
    private public your my our their his her its this that these those what which when how why where who and
    or but if then else yes no none null nil true false undefined rotated revoked disabled enabled active
    inactive locked unlocked generated created updated deleted removed added sent received shared exposed
    leaked compromised safe unsafe fine ok okay good bad new old temporary permanent default random unique
    complex simple easy hard difficult available unavailable ready pending working broken identical similar
    something anything nothing everything it them him me you us redacted masked n/a na tbd todo unchanged
    configured printed logged displayed visible invisible obvious useless used reused unused only also
    always never usually probably definitely very really quite rather so such like just exactly either
    neither both all any some every each located kept written given managed handled checked verified
    accepted rejected denied requested listed noted mentioned described defined specified documented
    forgotten lost right left long-lived short-lived single multiple changeme example placeholder will see ask use
    check contact call send please later soon tbc via
    falsch richtig korrekt inkorrekt ungültig gültig abgelaufen erforderlich geändert zurückgesetzt sicher unsicher
    schwach stark leer gesperrt vergessen faux invalide obligatoire requis expiré modifié réinitialisé vide faible
    fort sécurisé bloqué oublié erróneo erronea incorrecta incorrecto obligatoria obligatorio inválida inválido
    caducada caducado vacía débil segura seguro bloqueada olvidada onjuist ongeldig verlopen verplicht gewijzigd leeg
    zwak sterk veilig geblokkeerd vergeten sbagliata errata scaduta obbligatoria vuota debole sicura bloccata
    dimenticata errada incorreta inválida expirada vazia fraca forte bloqueada esquecida""".split()  # noqa: SIM905
)
# Words that make up placeholders such as YOUR_API_KEY, replace-me or INSERT_TOKEN_HERE.
_PLACEHOLDER_WORDS = frozenset(
    [
        "your",
        "my",
        "the",
        "a",
        "an",
        "api",
        "key",
        "token",
        "secret",
        "password",
        "passwd",
        "pwd",
        "here",
        "insert",
        "enter",
        "replace",
        "me",
        "change",
        "changeme",
        "example",
        "sample",
        "test",
        "dummy",
        "fake",
        "placeholder",
        "redacted",
        "value",
        "string",
        "goes",
        "put",
        "add",
        "paste",
        "id",
        "client",
        "access",
        "auth",
        "private",
        "public",
        "todo",
        "tbd",
        "none",
        "null",
        "default",
        "xxx",
        "token_here",
        "real",
        "actual",
        "new",
        "old",
        "please",
        "now",
        "this",
        "foo",
        "bar",
        "baz",
        "qux",
        "demo",
        "mock",
        "stub",
        "temp",
        "tmp",
        "pass",
        "apikey",
        "accesskey",
        "secretkey",
        "not",
    ]
)
_SEPARATORS_RE = re.compile(r"[_\-. ]+")
# Placeholder words run together, "dummytoken", "mysecret", "notarealkey": one of them says it is not real.
_PLACEHOLDER_MARKERS = frozenset(
    "your my dummy fake example sample test placeholder changeme change replace insert mock demo foo todo not".split()  # noqa: SIM905
)
# Words that make a value of words a placeholder on their own: "fake_key_for_testing", "example-db-password".
_STRONG_MARKERS = frozenset({"dummy", "fake", "example", "sample", "placeholder", "changeme", "mock", "notreal"})
_GLUED_LIMIT = 40


def _glued_placeholder(value: str) -> bool:
    """Whether a run of lowercase letters is placeholder words written together, one of them a marker."""
    if not (3 < len(value) <= _GLUED_LIMIT and value.isalpha() and value.islower()):
        return False
    words = list(_PLACEHOLDER_WORDS)
    reach: list[tuple[bool, bool] | None] = [None] * (len(value) + 1)  # (reachable, a marker on the way)
    reach[0] = (True, False)
    for i in range(len(value)):
        here = reach[i]
        if here is None:
            continue
        for w in words:
            if value.startswith(w, i):
                marked = here[1] or w in _PLACEHOLDER_MARKERS
                prev = reach[i + len(w)]
                if prev is None or (marked and not prev[1]):
                    reach[i + len(w)] = (True, marked)
    end = reach[len(value)]
    return end is not None and end[1]


_DIGIT_GROUP_AFTER_RE = re.compile(r" \d{2,4}(?![\w.,:/\-])")
# The storage scheme in front of an LDAP or Dovecot password value: "{SSHA512}", "{CRYPT}", "{PBKDF2-SHA256}".
_SCHEME_PREFIX_RE = re.compile(r"\{[A-Z][A-Z0-9_\-]{1,23}\}")


def _not_a_secret(secret: str) -> bool:
    """Values no rule should report: "required", "${DB_PASSWORD}", "os.environ['KEY']", "your-api-key"."""
    core = secret.strip("\"'` ")
    return (
        core.lower() in _NOT_A_VALUE
        or looks_like_placeholder(core)
        or bool(_TEMPLATE_RE.match(core))
        or bool(CODE_REFERENCE_RE.match(core))
    )


def looks_like_placeholder(value: str) -> bool:
    """``harpo_...``, ``sk-...3Yb``, ``YOUR_API_KEY``, ``replace-me``, ``sk-xxxxxxxx``: documentation or a key shown
    masked, not a credential. Dots after a whole value are an ellipsis: ``Tr0ub4dor...`` is still a password."""
    stem = value.rstrip(".\u2026")
    if "..." in stem or "\u2026" in stem:
        return True
    if stem != value and value.endswith(("...", "\u2026")) and (len(stem) <= 3 or stem[-1] in "_-"):
        return True
    parts = [p for p in _SEPARATORS_RE.split(value.lower()) if p]
    if len(parts) > 1 and all(p in _PLACEHOLDER_WORDS or set(p) <= set("x*0") for p in parts):
        return True
    if len(parts) > 1 and all(p.isalpha() for p in parts) and not _STRONG_MARKERS.isdisjoint(parts):
        return True
    if _glued_placeholder(value.strip("\"'`")):
        return True
    return len(value) >= 6 and set(value.lower()) <= set("x*-_")  # xxxxxxxx, ********


# HTTP Basic credentials: base64 of "user:password" after "Basic", with or without the header's name in front
# (`Authorization: "Basic ..."` in code, "- Basic ..." in a YAML list). Only a value that decodes to readable
# "user:password" counts, which ordinary words after "basic" never do.
_BASIC_AUTH_RE = re2.compile(r"(?i)\bbasic\s+([A-Za-z0-9+/]{8,}={0,2})")
_SEED_CONTEXT_RE = re2.compile(
    r"(?i)\b(?:seed|mnemonic|recovery\s+phrase|secret\s+phrase|backup\s+phrase|wallet|metamask|ledger|trezor|bip-?39)\b"
)
# Plain-letter tokenising is linear in Python's engine and much cheaper per match than RE2's wrapper.
_FAST_WORD_RE = re.compile(r"[a-z]+")
_POS_WORD_RE = re.compile(r"[A-Za-z]+")
_SEPARATOR_RE = re.compile(r"^[\s,;.:\-()\d]*$")
_AWS_SECRET_RE = re2.compile(
    r"(?i)\b(?:aws)?_?secret_?(?:access)?_?key(?:_id)?[\"']?\s*(?:[:=]|=>)\s*[\"']?([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+=]|$)"
)
_DOCKER_PAT_RE = re2.compile(r"\b(dckr_pat_[A-Za-z0-9_-]{27})(?:[^A-Za-z0-9_-]|$)")
# Provider tokens as they are written in practice, where gitleaks' rules hold the documented format only: Hugging Face
# tokens with digits in them, Telegram bot tokens whose secret part does not start with "AA" (the whole token, bot
# id included), Discord bot tokens, Azure storage and Service Bus account keys. Each one's length is checked after
# the match, and so is the character after it, since RE2 has no look-ahead.
_PROVIDER_RULES: tuple[tuple[str, Any, int, str], ...] = (
    ("huggingface-token", re2.compile(r"\b((?:hf_|api_org_)[A-Za-z0-9]{30,})"), 1, "A-Za-z0-9_"),
    # in a Bot API URL the token follows "bot": https://api.telegram.org/bot<token>/getMe
    ("telegram-bot-token", re2.compile(r"(?:\bbot|\b)([0-9]{8,10}:[A-Za-z0-9_-]{35,})"), 1, "A-Za-z0-9_-"),
    (
        "discord-bot-token",
        re2.compile(r"\b([MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38})"),
        1,
        "A-Za-z0-9_.-",
    ),
    ("azure-account-key", re2.compile(r"(?i)\b(?:AccountKey|SharedAccessKey)=([A-Za-z0-9+/]{20,}={0,2})"), 1, ""),
)
_PROVIDER_SHAPES = {
    "huggingface-token": re.compile(r"(?:hf_|api_org_)[A-Za-z0-9]{34}"),
    "telegram-bot-token": re.compile(r"[0-9]{8,10}:[A-Za-z0-9_-]{35}"),
}
_TRAILING = ".,;:!?)]}>"
# Every entry under data: or stringData: of a Kubernetes Secret is a secret. gitleaks' kubernetes-secret-yaml rule
# reports the first base64 value of a manifest; redaction needs each of them, or the next entry is found as soon as
# the first is a placeholder and egress verification refuses the request. Both the YAML and the JSON form.
_K8S_KEY_RE = re.compile(
    r"^(-[ \t]{1,8})?([\"']?)([\w.\-]{1,253})\2[ \t]{0,8}:(?:[ \t]{1,8}([^\r\n]{0,16384})|[ \t]{0,8}(?=\r?\n|\Z))"
)
_K8S_SCALAR_RE = re.compile(r"([\"']?)([^\s\"'#][^\"'#]{0,16383}?)\1[ \t]{0,8}(?:#.{0,256})?")
_K8S_DATA_KEYS = ("data", "stringData")
# gitleaks rules read here by structure instead: kubernetes-secret-yaml matches any base64-looking value within 200
# characters of "kind: Secret", so in a List it also took a ConfigMap's "APP_ENV: production".
_READ_STRUCTURALLY = frozenset({"kubernetes-secret-yaml"})
_DELIMITER_CHARS = re.compile(r"[<>()\[\]{},&]")
# The end of a sentence: punctuation before a blank or the end of the text, and the punctuation of Chinese and
# Japanese, which never belongs to a token. A dot inside a token or a host name is not followed by a blank.
_SENTENCE_END_RE = re.compile(r"[.!?:;](?=\s|$)|[。、，；：！？）」』】〉》]")
_DELIMITER_VIEWS = tuple(
    str.maketrans(dict.fromkeys("<()[]{}&" + (">" if blank_gt else "") + ("," if blank_comma else ""), " "))
    for blank_gt, blank_comma in ((False, False), (False, True), (True, False), (True, True))
)  # "&" ends a value in a URL query ("?token=npm_...&lang=en")
# Where a value comes from rather than the value: ${DB_PASSWORD}, {{ secrets.X }}, <your-key>, $(vault kv get ...), a
# YAML tag (!ENV, !Ref, !vault), an Azure Key Vault reference, Ruby or ERB interpolation.
_TEMPLATE_RE = re.compile(
    r"^(?:\$\{.*\}?|\$[A-Za-z_]\w*|\{\{.*|<[^>]*>?|%\(.*\)s|\*+|x+|X+|\.+|\[[A-Z_]+(?:_\w+)?\]"
    r"|\$\(.*|!!?[A-Za-z]+(?:[.:][A-Za-z]+)*|@Microsoft\.KeyVault\(.*|#\{.*\}?|%\{.*\}?|<%.*)$"
)


@cache
def _bip39() -> dict[str, int]:
    words = resources.files("harpo_redact").joinpath("data/bip39-english.txt").read_text().split()
    if len(words) != 2048:
        raise RuntimeError("the BIP39 wordlist must hold 2048 words")
    return {w: i for i, w in enumerate(words)}


def bip39_checksum_ok(words: list[str]) -> bool:
    index = _bip39()
    n = len(words)
    if n not in (12, 15, 18, 21, 24) or any(w not in index for w in words):
        return False
    bits = "".join(format(index[w], "011b") for w in words)
    entropy_bits = n * 11 * 32 // 33
    entropy = int(bits[:entropy_bits], 2).to_bytes(entropy_bits // 8, "big")
    checksum = format(hashlib.sha256(entropy).digest()[0], "08b")[: len(bits) - entropy_bits]
    return bits[entropy_bits:] == checksum


def _longest_wordlist_run(text: str, index: dict[str, int]) -> int:
    best = run = 0
    for word in _FAST_WORD_RE.findall(text.lower()):
        run = run + 1 if word in index else 0
        best = max(best, run)
    return best


def _kubernetes_secret_values(text: str) -> Iterator[tuple[int, int]]:
    """The value of every entry under ``data:`` or ``stringData:`` of a Kubernetes Secret, in YAML or JSON. One pass
    over the lines (or characters): long or deeply nested input costs linear time."""
    if "ecret" not in text or "ata" not in text:
        return
    yield from _k8s_yaml(text)
    if '"data"' in text or '"stringData"' in text:
        yield from _k8s_json(text)


def _k8s_yaml(text: str) -> Iterator[tuple[int, int]]:
    # Pass 1: give every line the mapping it belongs to (an indentation stack; "- " starts a new one) and note the
    # mappings that say kind: Secret. Pass 2: the entries of their data blocks.
    lines: list[tuple[int, int, int, re.Match[str] | None, int]] = []  # (start, end, indent, key match, mapping)
    secret: set[int] = set()
    stack: list[tuple[int, int]] = []  # (indent, mapping id)
    pos, n, ids = 0, len(text), 0
    while pos <= n:
        nl = text.find("\n", pos)
        end = n if nl < 0 else nl
        stop = end - 1 if end > pos and text[end - 1] == "\r" else end
        body = text[pos:stop]
        stripped = body.lstrip(" \t")
        indent = len(body) - len(stripped)
        if stripped.startswith("---"):
            stack.clear()
        elif stripped and not stripped.startswith("#"):
            m = _K8S_KEY_RE.match(stripped)
            item = m is not None and m.group(1) is not None
            eff = indent + (len(m.group(1)) if item and m else 0)
            while stack and stack[-1][0] > eff:
                stack.pop()
            if item and stack and stack[-1][0] == eff:
                stack.pop()
            if not stack or stack[-1][0] < eff:
                ids += 1
                stack.append((eff, ids))
            mapping = stack[-1][1]
            if m is not None and m.group(3) == "kind" and (m.group(4) or "").strip().strip("\"'").lower() == "secret":
                secret.add(mapping)
            lines.append((pos + indent + (len(m.group(1)) if item and m else 0), stop, eff, m, mapping))
        if nl < 0:
            break
        pos = nl + 1
    i = 0
    while i < len(lines):
        _start, _stop, eff, m, mapping = lines[i]
        i += 1
        if m is None or mapping not in secret or m.group(3) not in _K8S_DATA_KEYS or (m.group(4) or "").strip():
            continue
        while i < len(lines) and lines[i][2] > eff:  # the block: every deeper line, consumed once
            es, estop, _e, em, _m = lines[i]
            i += 1
            if em is None or not em.group(4):
                continue
            vstart = es + em.start(4)
            sm = _K8S_SCALAR_RE.fullmatch(text, vstart, estop)
            if sm is not None and not sm.group(2).startswith(("|", ">", "{", "[")):
                yield sm.start(2), sm.end(2)


def _k8s_json(text: str) -> Iterator[tuple[int, int]]:
    """A single forward pass with an object stack: the string values of a "data" or "stringData" object, released
    when the object around it turns out to say "kind": "Secret"."""
    frames: list[_JsonFrame] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            if j >= n:
                return
            k = j + 1
            while k < n and text[k] in " \t\r\n":
                k += 1
            if frames:
                top = frames[-1]
                if k < n and text[k] == ":":
                    top.key = text[i + 1 : j]
                elif top.data:
                    top.values.append((i + 1, j))
                elif top.key == "kind" and text[i + 1 : j] == "Secret":
                    top.secret = True
            i = j + 1
            continue
        if c in "{[":
            parent = frames[-1] if frames else None
            data = c == "{" and parent is not None and parent.key in _K8S_DATA_KEYS and not parent.data
            frames.append(_JsonFrame(data=data))
        elif c in "}]" and frames:
            done = frames.pop()
            if done.data and frames:
                frames[-1].held.extend(done.values)
            elif done.secret:
                yield from done.held
        i += 1


@dataclass
class _JsonFrame:
    data: bool = False
    secret: bool = False
    key: str | None = None
    values: list[tuple[int, int]] = field(default_factory=list)
    held: list[tuple[int, int]] = field(default_factory=list)


def _seed_phrases(text: str) -> Iterator[tuple[int, int]]:
    index = _bip39()
    if _longest_wordlist_run(text, index) < 12:
        return  # cheap upper bound: most texts stop here
    words = [(m.start(), m.end(), m.group().lower()) for m in _POS_WORD_RE.finditer(text)]
    runs: list[list[tuple[int, int, str]]] = []
    current: list[tuple[int, int, str]] = []
    for word in words:
        if word[2] in index and (not current or _SEPARATOR_RE.match(text[current[-1][1] : word[0]])):
            current.append(word)
            continue
        if len(current) >= 12:
            runs.append(current)
        current = [word] if word[2] in index else []
    if len(current) >= 12:
        runs.append(current)
    if not runs:
        return
    has_context = _SEED_CONTEXT_RE.search(text) is not None
    for run in runs:
        tokens = [w[2] for w in run]
        # A real phrase is random words; "word word word ..." can pass the short checksum by chance.
        windows = sorted(
            (i, i + size)
            for size in (24, 21, 18, 15, 12)
            for i in range(0, len(tokens) - size + 1)
            if len(set(tokens[i : i + size])) >= 4 and bip39_checksum_ok(tokens[i : i + size])
        )
        if windows:
            # Only the words that make up a phrase. A wordlist word next to it ("check the file. legal winner ...")
            # is text, and keys are redacted in place, so the placeholder must not swallow it.
            start, end = windows[0]
            for a, b in windows[1:]:
                if a <= end:
                    end = max(end, b)
                    continue
                yield run[start][0], run[end - 1][1]
                start, end = a, b
            yield run[start][0], run[end - 1][1]
        elif has_context and len(set(tokens)) >= 4:
            yield run[0][0], run[-1][1]


# --------------------------------------------------------------------------- the library


_YAML_KEY_RE = re.compile(r"[A-Za-z_][\w.\-]{0,63}:(?:[ \t]*[|>][-+]?\s+|[ \t]+)")


def _unquoted(text: str, start: int, end: int) -> tuple[int, int]:
    """The value alone, when a rule's group takes more: the YAML key in front of it (kubernetes-secret-yaml's group
    is ``password: c2VjcmV0``) and the quotes around it (hashicorp-tf-password's is ``"..."``). Both are syntax:
    redacting them would leave ``[SECRET_1]`` where ``password: [SECRET_1]`` belongs, and break the YAML or JSON."""
    key = _YAML_KEY_RE.match(text, start, end)
    if key is not None and key.end() < end:
        start = key.end()
    while end - start > 2 and text[start] == text[end - 1] and text[start] in "\"'`":
        start, end = start + 1, end - 1
    return start, end


class SecretLibrary:
    def __init__(
        self,
        rules: list[SecretRule],
        global_allows: list[_Allow],
        *,
        natural_language: bool = True,
        seed_phrases: bool = True,
    ) -> None:
        self.rules = tuple(rules)
        self._global = tuple(global_allows)
        self._keywords = tuple(sorted({k for r in self.rules for k in r.keywords}))
        self._natural_language = natural_language
        self._seed_phrases = seed_phrases

    @property
    def rule_count(self) -> int:
        prompt_rules = 3 + len(_PROVIDER_RULES) + 2 * int(self._natural_language) + int(self._seed_phrases)
        return len(self.rules) + prompt_rules

    def may_hold_seed_phrase(self, text: str, min_words: int = 12) -> bool:
        """Cheap test: a run of at least ``min_words`` wordlist words."""
        return self._seed_phrases and _longest_wordlist_run(text, _bip39()) >= min_words

    def seed_phrase_spans(self, text: str) -> list[Span]:
        if not self._seed_phrases:
            return []
        return [
            make_span(start, end, E.SECRET, "secret:bip39-seed-phrase", text[start:end].lower(), 0.95)
            for start, end in _seed_phrases(text)
        ]

    @staticmethod
    def _allowed(allows: Iterable[_Allow], secret: str, match: str, line: str) -> bool:
        lowered = secret.lower()
        for allow in allows:
            target = match if allow.target == "match" else line if allow.target == "line" else secret
            if any(rx.search(target) for rx in allow.regexes):
                return True
            if any(word in lowered for word in allow.stopwords):
                return True
        return False

    def _line(self, text: str, start: int, end: int) -> str:
        left = text.rfind("\n", 0, start) + 1
        right = text.find("\n", end)
        return text[left : right if right != -1 else len(text)]

    def find(self, text: str) -> list[Span]:
        spans: list[Span] = []
        lowered = text.lower()
        present = {k for k in self._keywords if k in lowered}
        # gitleaks ends most tokens at a quote, whitespace or semicolon. In prompts a token is just as
        # often followed by "<" (HTML), ")" (Markdown) or "," (lists), so every rule also runs on a view
        # in which those delimiters are blanks. Same length, so offsets carry over unchanged.
        views = [text]
        if _DELIMITER_CHARS.search(text):
            for (
                table
            ) in _DELIMITER_VIEWS:  # ">" and "," are assignment operators in some rules, so some views keep them
                view = text.translate(table)
                if view not in views:
                    views.append(view)
        # In prose a token often ends a sentence ("The NPM_TOKEN is npm_..."), and gitleaks would not end it at a full
        # stop. One more view has every delimiter and the end of every sentence as a blank.
        ended = _SENTENCE_END_RE.sub(" ", text.translate(_DELIMITER_VIEWS[-1]))
        if ended not in views:
            views.append(ended)
        seen: set[tuple[int, int, str]] = set()
        for rule in self.rules:
            if rule.keywords and present.isdisjoint(rule.keywords):
                continue
            if rule.id in _READ_STRUCTURALLY:
                continue  # replaced by _kubernetes_secret_values, which knows which object a data block belongs to
            for body in views:
                for m in rule.pattern.finditer(body):
                    bounds = self._secret_bounds(rule, m)
                    if bounds is None:
                        continue
                    start, end = _unquoted(body, *bounds)
                    if (start, end, rule.id) in seen:
                        continue
                    secret = body[start:end]
                    if not secret.strip() or PLACEHOLDER_RE.fullmatch(secret) or _not_a_secret(secret):
                        continue
                    if rule.id.startswith("generic") and is_encoded_text(secret.strip("\"'`")):
                        continue  # base64 of readable text: find_encoded decodes it and judges what it says
                    if rule.id.startswith("generic") and not _credential_name(body, m.start(0), m.end(0)):
                        continue  # "hidapi_hash", "monkey_id", "api_version", "spec/key_spec.rb": not a credential
                    if rule.entropy is not None:
                        if shannon_entropy(secret) <= rule.entropy:
                            continue
                        if rule.id.startswith("generic") and not any(c.isdigit() for c in secret):
                            continue  # gitleaks' rule: generic secrets must contain a digit
                    line = self._line(body, m.start(), m.end())
                    if self._allowed(self._global, secret, m.group(0), line) or self._allowed(
                        rule.allows, secret, m.group(0), line
                    ):
                        continue
                    seen.add((start, end, rule.id))
                    spans.append(make_span(start, end, E.SECRET, f"secret:{rule.id}", text[start:end], 0.95))
        for span in self._prompt_rules(text):
            if "secret:statement" in span.sources and any(s.start <= span.start and span.end <= s.end for s in spans):
                continue  # a statement another rule found already
            spans.append(span)
        return spans

    @staticmethod
    def _secret_bounds(rule: SecretRule, m: Any) -> tuple[int, int] | None:
        groups = m.re.groups
        if rule.secret_group:
            if rule.secret_group > groups or m.start(rule.secret_group) < 0:
                return None
            return m.start(rule.secret_group), m.end(rule.secret_group)
        for g in range(1, groups + 1):
            if m.start(g) >= 0 and m.end(g) > m.start(g):
                return m.start(g), m.end(g)
        return m.start(0), m.end(0)

    def _prompt_rules(self, text: str) -> Iterator[Span]:
        if self._natural_language:
            for m in _NL_CREDENTIAL_RE.finditer(text):
                g = 3 if m.start(3) >= 0 else 4 if m.start(4) >= 0 else 5
                start, end = m.start(g), m.end(g)
                start = after_placeholder(text, start, end)
                if start is None:
                    continue
                cue = " ".join(m.group(2).lower().split())
                short_ok = cue.startswith(_SHORT_VALUE_CUES)
                if not HASH_WORDS.isdisjoint(name_words(m.group(1))):
                    continue  # "hashed_password: $2y$...": a hash of the password
                if g != 5:  # quoted: the whole value, blanks included, judged as a quoted value
                    value = text[start:end]
                    dull = looks_like_placeholder(value) or _TEMPLATE_RE.match(value) or is_encoded_text(value)
                    if (not short_ok and len(value) < _KEY_MIN) or never_a_credential(value):
                        continue
                    if quoted_value_is_secret(value) and value.lower() not in _NOT_A_VALUE and not dull:
                        yield make_span(start, end, E.SECRET, "secret:natural-language", value, 0.8)
                    continue
                if in_query(text, m.start()):
                    end = query_value_end(text, start, end)
                elif text[start:end].isdigit():
                    while (group := _DIGIT_GROUP_AFTER_RE.match(text, end)) is not None:
                        end = group.end()  # "Passcode: 739 481", "PIN 12 34": one code printed in groups
                elif cue.startswith(_STRONG_CUES) and _LINKED_BY_SIGN_RE.fullmatch(text, m.end(2), start):
                    wide = config_value_end(text, m.start(), start, end)
                    value = text[start:wide]
                    if wide > end and quoted_value_is_secret(value) and not looks_like_placeholder(value):
                        yield make_span(start, wide, E.SECRET, "secret:natural-language", value, 0.8)
                        continue
                value = text[start:end]
                # Trailing punctuation stays inside the span: a password may end in "!" or ")", and swallowing a
                # full stop costs nothing. Only the checks below look at the value without it.
                core = value.rstrip(_TRAILING)
                if len(core) < 3 or core.lower() in _NOT_A_VALUE or PLACEHOLDER_RE.fullmatch(core):
                    continue
                if (not short_ok and (len(core) < _KEY_MIN or wordy(core))) or never_a_credential(core):
                    continue  # "access_key is 530", "the token is queue.replica.staging.68", "$2y$10$...", "2.15.15"
                if looks_like_placeholder(value) or looks_like_placeholder(core):
                    continue
                if _TEMPLATE_RE.match(core) or CODE_REFERENCE_RE.match(core):
                    continue  # ${DB_PASSWORD}, $TOKEN, <your-key>, ****, os.environ["X"]
                if set(core) <= {"*", "x", "X", ".", "#", "-", "_"}:
                    continue  # already masked
                if is_encoded_text(core):
                    continue  # "password (base64): ...": find_encoded decodes it and checks what it says
                plain = core.isalpha() and (core.islower() or core.istitle())
                if plain and not cue.startswith(_STRONG_CUES):
                    continue  # "the token is located ..." is prose, "my password is sunshine" is not
                if looks_like_code(core):
                    continue  # password: request.form[...]
                yield make_span(start, end, E.SECRET, "secret:natural-language", value, 0.8)
            for m in _NL_BARE_RE.finditer(text):
                start, end = m.start(3), m.end(3)
                start = after_placeholder(text, start, end)
                if start is None:
                    continue
                if in_query(text, m.start()):
                    end = query_value_end(text, start, end)
                core = text[start:end].rstrip(_TRAILING)
                classes = (
                    any(c.isupper() for c in core)
                    + any(c.islower() for c in core)
                    + any(c.isdigit() for c in core)
                    + any(not c.isalnum() for c in core)
                )
                if len(core) < 8 or classes < 3 or _not_a_secret(core) or PLACEHOLDER_RE.fullmatch(core):
                    continue
                if is_encoded_text(core):
                    continue
                yield make_span(start, end, E.SECRET, "secret:natural-language", text[start:end], 0.8)
        for rx, rule_id in ((_AWS_SECRET_RE, "aws-secret-access-key"), (_DOCKER_PAT_RE, "docker-hub-pat")):
            for m in rx.finditer(text):
                if shannon_entropy(m.group(1)) > 3.5:
                    yield make_span(m.start(1), m.end(1), E.SECRET, f"secret:{rule_id}", m.group(1), 0.95)
        yield from _provider_tokens(text)
        if self._natural_language:
            for start, end, rule_id in find_statements(text):
                scheme = _SCHEME_PREFIX_RE.match(text, start, end)
                if scheme is not None and scheme.end() < end:
                    start = scheme.end()  # "{SSHA512}...": the scheme names how the value is stored; the rest is it
                yield make_span(start, end, E.SECRET, f"secret:{rule_id}", text[start:end], 0.8)
        for start, end in _kubernetes_secret_values(text):
            yield make_span(start, end, E.SECRET, "secret:kubernetes-secret-yaml", text[start:end], 0.95)
        for m in _BASIC_AUTH_RE.finditer(text):
            token = m.group(1)
            try:
                decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            if ":" in decoded and decoded.isprintable():
                yield make_span(m.start(1), m.end(1), E.SECRET, "secret:basic-auth", token, 0.95)
        if self._seed_phrases:
            for start, end in _seed_phrases(text):
                yield make_span(start, end, E.SECRET, "secret:bip39-seed-phrase", text[start:end].lower(), 0.95)


# gitleaks' generic rule takes any name with a credential word inside it ("hidapi_hash" holds "api", "monkey_id"
# holds "key"). A name only counts when one of its words is a credential word, and not when its last word says it
# is about one (an id, a hash, a version, a URL), it names a key that is no secret (a cache key), or it is part of a
# file path.
_GENERIC_WORDS = frozenset(
    """access auth api apikey credential credentials creds key passwd password pwd passphrase secret secrets token
    accesskey accesstoken authtoken secretkey privatekey clientsecret apisecret""".split()  # noqa: SIM905
)
_OPERATOR_RE = re.compile(r"[=:>,|?]")
_CODE_FILE_RE = re.compile(
    r"\.(?:rb|py|js|jsx|ts|tsx|go|java|kt|cs|php|json|ya?ml|toml|lock|md|txt|html?|css|sum|mod)$"
)


def _credential_name(text: str, start: int, end: int) -> bool:
    stop = _OPERATOR_RE.search(text, start, end)
    name = text[start : stop.start() if stop else end].strip(" \t*`'\"")
    if (start > 0 and text[start - 1] in "/\\") or "/" in name or _CODE_FILE_RE.search(name):
        return False
    words = name_words(name)
    if not words:
        return True
    if _GENERIC_WORDS.isdisjoint(words) or words[-1] in NOT_CREDENTIAL_LAST or not HASH_WORDS.isdisjoint(words):
        return False
    return not (words[-1] == "key" and len(words) > 1 and words[-2] in NOT_CREDENTIAL_KEY)


def _provider_tokens(text: str) -> Iterator[Span]:
    for rule_id, rx, group, token_chars in _PROVIDER_RULES:
        for m in rx.finditer(text):
            start, end = m.start(group), m.end(group)
            token = text[start:end]
            if token_chars and end < len(text) and re.match(f"[{token_chars}]", text[end]):
                continue  # part of something longer
            shape = _PROVIDER_SHAPES.get(rule_id)
            if shape is not None and not shape.fullmatch(token):
                continue
            body = token.split(":", 1)[-1] if rule_id == "telegram-bot-token" else token
            if shannon_entropy(body) < 3.5 or is_placeholder_token(body) or looks_like_placeholder(body):
                continue
            yield make_span(start, end, E.SECRET, f"secret:{rule_id}", token, 0.95)


@cache
def _vendored_rules() -> str:
    return resources.files("harpo_redact").joinpath("data/gitleaks.toml").read_text()


@cache
def builtin_rule_ids() -> frozenset[str]:
    """Ids of the vendored gitleaks rules."""
    return frozenset(r["id"] for r in tomllib.loads(_vendored_rules()).get("rules", []) if "id" in r)


def quiet_re2() -> Any:
    """RE2 options that report a bad pattern through the exception only, not on stderr."""
    options = re2.Options()
    options.log_errors = False
    return options


def re2_message(exc: Exception) -> str:
    text = exc.args[0] if exc.args else exc
    return text.decode("utf-8", "replace") if isinstance(text, bytes) else str(text)


_RULE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{1,79}")


def check_rules_file(path: str) -> int:
    """Check a file of extra key rules (gitleaks TOML) the way the scanner will load it.

    Returns the number of rules. Raises ValueError naming the first problem, so a typo stops the gateway at
    startup instead of leaving a rule silently unused.
    """
    file = Path(path)
    if not file.is_file():
        raise ValueError(f"file not found: {path}")
    try:
        raw = file.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"cannot read {path}: {exc}") from None
    try:
        cfg = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"{path} is not valid TOML: {exc}") from None
    rules = cfg.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError(f"{path} has no [[rules]] entries")
    builtin = builtin_rule_ids()
    seen: set[str] = set()
    options = quiet_re2()
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ValueError(f"rules[{i}] must be a table")
        rid = rule.get("id")
        if not isinstance(rid, str) or not _RULE_ID_RE.fullmatch(rid):
            raise ValueError(f"rules[{i}]: id must be 2-80 lowercase letters, digits, dots, dashes or underscores")
        if rid in builtin:
            raise ValueError(f"rule {rid}: a built-in rule already has this id; choose another")
        if rid in seen:
            raise ValueError(f"rule {rid}: the id is used twice")
        seen.add(rid)
        regex = rule.get("regex")
        if not isinstance(regex, str) or not regex:
            raise ValueError(f"rule {rid}: regex is required")
        try:
            compiled = re2.compile(regex, options)
        except re2.error as exc:
            raise ValueError(f"rule {rid}: regex is not valid RE2 ({re2_message(exc)})") from None
        if compiled.search("") is not None:
            raise ValueError(f"rule {rid}: regex matches the empty string")
        keywords = rule.get("keywords", [])
        if not isinstance(keywords, list) or not all(isinstance(k, str) and k for k in keywords):
            raise ValueError(f"rule {rid}: keywords must be a list of non-empty strings")
        entropy = rule.get("entropy")
        if entropy is not None and (not isinstance(entropy, int | float) or not 0 <= entropy <= 8):
            raise ValueError(f"rule {rid}: entropy must be a number from 0 to 8")
        group = rule.get("secretGroup")
        if group is not None and (not isinstance(group, int) or not 0 <= group <= compiled.groups):
            raise ValueError(f"rule {rid}: secretGroup must name one of the regex's {compiled.groups} groups")
        for entry in _as_list(rule.get("allowlist")) + _as_list(rule.get("allowlists")):
            for allow in entry.get("regexes") or []:
                try:
                    re2.compile(allow, options)
                except re2.error as exc:
                    raise ValueError(f"rule {rid}: allowlist regex is not valid RE2 ({re2_message(exc)})") from None
    return len(rules)


def load_library(
    *,
    gitleaks: bool = True,
    disabled: Iterable[str] = (),
    extra_rules_file: str | None = None,
    natural_language: bool = True,
    seed_phrases: bool = True,
) -> SecretLibrary:
    """The credential library. The gateway always loads it whole (keys are always redacted); the switches are
    for tests and tools that measure one part on its own."""
    rules: list[SecretRule] = []
    allows: list[_Allow] = []
    if gitleaks:
        rules, allows = parse_rules(_vendored_rules(), disabled)
    if extra_rules_file:
        # Its rules only: a top-level [allowlist] in the file would apply to every rule and could exempt keys the
        # built-in rules find (check-config names it). Each extra rule's own allowlist still applies.
        extra_rules, _ = parse_rules(Path(extra_rules_file).read_text(), disabled)
        rules.extend(extra_rules)
    return SecretLibrary(rules, allows, natural_language=natural_language, seed_phrases=seed_phrases)


def rules_file_global_allowlist(path: str) -> bool:
    """Whether a file of extra rules has a top-level [allowlist] (which the gateway does not apply)."""
    try:
        cfg = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return False
    return bool(cfg.get("allowlist") or cfg.get("allowlists"))
