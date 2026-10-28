"""Layer 2f: personal data in the machine formats that carry it, by the place each format gives it.

* Hardware addresses in a run: the iptables ``MAC=`` field holds two MAC addresses and the frame type in one chain
  ("MAC=ab:08:61:13:3f:53:6f:70:8a:9b:0c:1d:08:00"), and EUI-64 and InfiniBand identifiers are longer still.
* Machine-readable zones of passports and identity cards (ICAO 9303): the 44-, 36- and 30-character lines, which
  hold the holder's name, document number, nationality and dates.
* HL7 v2 messages: the patient, next of kin, guarantor, insured and clinician fields of PID, NK1, GT1, IN1, IN2,
  PV1, EVN, ORC and OBR segments, by their field numbers.
* AWS identities: the account in an ARN, IAM user and session names, and the unique IDs of users and roles
  (AIDA..., AROA...). Access keys are the gitleaks rules' (secret_library).
* User names where a format puts them: ``userName``, ``uid=`` in LDAP, ``SubjectUserName`` in Windows events,
  ``/home/<name>`` and ``C:\\Users\\<name>``, and the ``name@host:~$`` of a shell prompt. System accounts (root,
  ubuntu, www-data...) are left alone.
* Credentials with a type prefix that no vendor rule knows ("whsec_...", "sess_...", "sk_live_..."), Bitcoin private
  keys in wallet import format, and Bitcoin addresses written in bech32 whose checksum is off, after a word that
  names them ("bitcoin address", "pay to").
"""

from __future__ import annotations

import base64
import binascii
import math
import re
from collections import Counter
from collections.abc import Callable, Iterator

from ..entities import EntityType as E
from ..entities import Span, make_span

SOURCE = "format"

# --------------------------------------------------------------------------- hardware addresses
_MAC_CHAIN_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){6,}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])")

# --------------------------------------------------------------------------- machine-readable zones
_MRZ_LINE_RE = re.compile(r"(?<![A-Z0-9<])[A-Z0-9<]{30,44}(?![A-Z0-9<])")
# Line 2 of a passport (TD3): number, check digit, nationality, birth date, check, sex, expiry date, check, ...
_TD3_LINE2_RE = re.compile(r"[A-Z0-9<]{9}[0-9<][A-Z<]{3}\d{6}[0-9<][MFX<]\d{6}[0-9<][A-Z0-9<]{14}[0-9<]{2}")
# Line 2 of an identity card (TD1): birth date, check, sex, expiry date, check, nationality, ...
_TD1_LINE2_RE = re.compile(r"\d{6}[0-9<][MFX<]\d{6}[0-9<][A-Z<]{3}[A-Z0-9<]{11}[0-9<]")
_DOC_CODE_RE = re.compile(r"[PIACV][A-Z<][A-Z<]{3}")


def _mrz(line: str) -> bool:
    n = len(line)
    if n not in (30, 36, 44):
        return False
    if _TD3_LINE2_RE.fullmatch(line) or _TD1_LINE2_RE.fullmatch(line):
        return True
    # Line 1: a document code, the issuing state, then the name or the number padded with "<".
    return bool(_DOC_CODE_RE.match(line)) and line.count("<") >= 3


# --------------------------------------------------------------------------- HL7 v2
_HL7_SEGMENT_RE = re.compile(r"(?m)^(PID|NK1|GT1|IN1|IN2|PV1|EVN|ORC|OBR|PD1|MRG|ROL)\|")
# (segment, field) -> what the field holds. Field numbers as in HL7 v2.5; name fields are family^given^middle,
# clinician fields (XCN) are id^family^given^middle.
_HL7_FIELDS: dict[tuple[str, int], str] = {
    ("PID", 2): "id", ("PID", 3): "id", ("PID", 4): "id", ("PID", 5): "name", ("PID", 6): "name",
    ("PID", 7): "dob", ("PID", 9): "name", ("PID", 11): "address", ("PID", 13): "phone", ("PID", 14): "phone",
    ("PID", 18): "id", ("PID", 19): "ssn", ("PID", 20): "licence", ("PID", 21): "id",
    ("NK1", 2): "name", ("NK1", 4): "address", ("NK1", 5): "phone", ("NK1", 6): "phone", ("NK1", 30): "name",
    ("NK1", 31): "phone", ("NK1", 32): "address", ("NK1", 33): "id", ("NK1", 37): "ssn",
    ("GT1", 2): "id", ("GT1", 3): "name", ("GT1", 5): "address", ("GT1", 6): "phone", ("GT1", 7): "phone",
    ("GT1", 8): "dob", ("GT1", 12): "ssn",
    ("IN1", 16): "name", ("IN1", 18): "dob", ("IN1", 19): "address", ("IN1", 36): "id", ("IN1", 49): "id",
    ("IN2", 1): "id", ("IN2", 2): "ssn", ("IN2", 8): "id",
    ("PV1", 7): "clinician", ("PV1", 8): "clinician", ("PV1", 9): "clinician", ("PV1", 17): "clinician",
    ("PV1", 19): "id", ("PV1", 50): "id",
    ("EVN", 5): "clinician", ("ORC", 10): "clinician", ("ORC", 11): "clinician", ("ORC", 12): "clinician",
    ("OBR", 16): "clinician", ("OBR", 28): "clinician", ("PD1", 4): "clinician", ("ROL", 4): "clinician",
    ("MRG", 1): "id", ("MRG", 3): "id",
}  # fmt: skip
_HL7_NAME_SHAPE_RE = re.compile(
    r"[A-Z][A-Za-z'\-]{1,40}\^[A-Z][A-Za-z'\-]{1,40}(?:\^[A-Z][A-Za-z'\-]{0,40})?(?:\^[A-Za-z.]{0,10}){0,4}"
)
_HL7_TYPES = {"id": E.ACCOUNT_ID, "name": E.PERSON, "dob": E.DATE_OF_BIRTH, "address": E.ADDRESS, "phone": E.PHONE,
              "ssn": E.NATIONAL_ID, "licence": E.ID_DOCUMENT}  # fmt: skip


# What a field holds, read from the field itself: messages from real systems do not always put each value where the
# standard says. A street address with its parts ("913 Meadowline Terrace^^Helena^MT^59601^USA"), a phone number.
_HL7_ADDRESS_SHAPE_RE = re.compile(r"\d{1,6}[A-Za-z]?[ \t]+[A-Za-z][^|^~]{2,60}(?:\^[^|^~]{0,40}){2,8}")
_HL7_PHONE_SHAPE_RE = re.compile(r"(?:\+?1[ .\-]?)?\(?\d{3}\)?[ .\-]?\d{3}[ .\-]?\d{4}(?=\^|~|$)")
_HL7_DATE_SHAPE_RE = re.compile(r"(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])(?:\d{2,6})?")
_HL7_KIND_CHECK: dict[str, Callable[[str], bool]] = {
    "phone": lambda v: sum(c.isdigit() for c in v.split("^")[0]) >= 7 and not _HL7_DATE_SHAPE_RE.fullmatch(v),
    "dob": lambda v: sum(c.isdigit() for c in v.split("^")[0]) >= 6,
    "ssn": lambda v: sum(c.isdigit() for c in v) >= 9,
    "address": lambda v: any(c.isalpha() for c in v) and (any(c.isdigit() for c in v) or "^" in v),
    "licence": lambda v: any(c.isdigit() for c in v),
}


def _hl7_shape(field: str) -> str | None:
    value = field.split("~")[0]
    if _HL7_ADDRESS_SHAPE_RE.fullmatch(value.rstrip("^ ")):
        return "address"
    if _HL7_PHONE_SHAPE_RE.match(value):
        return "phone"
    return None


def _hl7(text: str) -> Iterator[Span]:
    for seg in _HL7_SEGMENT_RE.finditer(text):
        name = seg.group(1)
        line_end = text.find("\n", seg.start())
        line_end = len(text) if line_end == -1 else line_end
        line = text[seg.start() : line_end].rstrip("\r")
        offset = seg.start()
        cursor = 0
        for index, field in enumerate(line.split("|")):
            start = offset + cursor
            cursor += len(field) + 1
            if index == 0 or not field.strip(" ^~&"):
                continue
            kind = _HL7_FIELDS.get((name, index))
            shape = _hl7_shape(field)
            if kind in _HL7_KIND_CHECK and not _HL7_KIND_CHECK[kind](field):
                # not what the standard puts here: the field is read by its shape instead (a birth date one field
                # later than the standard has it)
                kind = "dob" if _HL7_DATE_SHAPE_RE.fullmatch(field.split("^")[0]) else None
            if kind is None and _HL7_NAME_SHAPE_RE.fullmatch(field):
                kind = "name"  # FAMILY^GIVEN^MIDDLE^^^MD in a field the table does not list
            if shape is not None and kind not in ("name", "clinician", "id"):
                kind = shape
            if kind is None:
                continue
            yield from _hl7_field(text, kind, start, field)


def _hl7_field(text: str, kind: str, start: int, field: str) -> Iterator[Span]:
    if kind in ("address", "phone", "dob", "ssn", "licence"):
        value = field.split("~")[0]
        if kind == "phone":
            value = value.split("^")[0] or value
        if kind == "dob":
            value = value.split("^")[0]
        stripped = value.rstrip("^ ")
        if stripped:
            yield make_span(start, start + len(stripped), _HL7_TYPES[kind], f"{SOURCE}:hl7", stripped.casefold(), 0.9)
        return
    cursor = start
    for repetition in field.split("~"):
        pos = cursor
        parts = [c for c in repetition.split("^") if c.strip()]
        if kind == "clinician" and len(parts) < 2 and " " not in repetition.strip():
            cursor += len(repetition) + 1
            continue  # a code ("MED", "CARD"), not a clinician: names have two parts or are written out
        for k, component in enumerate(repetition.split("^")):
            comp_start, pos = pos, pos + len(component) + 1
            value = component.strip()
            if not value or not any(c.isalnum() for c in value):
                continue
            if kind == "id" and k == 0:
                etype = E.ACCOUNT_ID
            elif kind == "name" and k <= 2:
                etype = E.PERSON
            elif kind == "clinician" and k == 0:
                etype = E.ACCOUNT_ID if any(c.isdigit() for c in value) else E.PERSON
            elif kind == "clinician" and 1 <= k <= 3:
                etype = E.PERSON
            else:
                continue
            lead = len(component) - len(component.lstrip())
            yield make_span(
                comp_start + lead, comp_start + lead + len(value), etype, f"{SOURCE}:hl7", value.casefold(), 0.9
            )
        cursor += len(repetition) + 1


# --------------------------------------------------------------------------- AWS identities
_ARN_RE = re.compile(
    r"arn:aws[a-z\-]{0,12}:[a-z0-9\-]{1,40}:[a-z0-9\-]{0,25}:(?P<acct>\d{12}):(?P<res>[A-Za-z0-9_+=,.@/:\-]{1,256})"
)
_PRINCIPAL_ID_RE = re.compile(
    r"(?<![A-Z0-9])(?:AIDA|AROA|AIPA|ANPA|ANVA|APKA|AGPA)[A-Z0-9]{12,28}(?::[A-Za-z0-9._@+=,\-]{2,64})?(?![A-Za-z0-9])"
)
_ARN_PERSON_PARTS = ("user", "mfa", "assumed-role", "federated-user")


def _aws(text: str) -> Iterator[Span]:
    if "arn:aws" in text:
        for m in _ARN_RE.finditer(text):
            yield make_span(m.start("acct"), m.end("acct"), E.ACCOUNT_ID, f"{SOURCE}:aws", m.group("acct"), 0.9)
            parts = m.group("res").split("/")
            if len(parts) >= 2 and parts[0] in ("role", "assumed-role"):
                # a role an organisation made ("stacknova-ec2-app-role"); the roles AWS makes for its own services
                # ("AWSServiceRoleForECS", ".../aws-service-role/...") name nothing of the customer's
                role = parts[1] if parts[0] == "assumed-role" else parts[-1]
                aws_made = "aws-service-role" in parts or role.startswith("AWSServiceRole")
                if role and not aws_made and _account_name_ok(role):
                    start = (
                        m.start("res") + len(parts[0]) + 1 if parts[0] == "assumed-role" else m.end("res") - len(role)
                    )
                    yield make_span(start, start + len(role), E.ACCOUNT_ID, f"{SOURCE}:aws", role.casefold(), 0.8)
            if len(parts) >= 2 and parts[0] in _ARN_PERSON_PARTS:
                last = parts[-1]
                if parts[0] == "assumed-role" and len(parts) < 3:
                    continue
                end = m.end("res")
                start = end - len(last)
                if last and _account_name_ok(last):
                    yield make_span(start, end, E.ACCOUNT_ID, f"{SOURCE}:aws", last.casefold(), 0.85)
    if not any(p in text for p in ("AIDA", "AROA", "AIPA", "ANPA", "ANVA", "APKA", "AGPA")):
        return
    for m in _PRINCIPAL_ID_RE.finditer(text):
        yield make_span(m.start(), m.end(), E.ACCOUNT_ID, f"{SOURCE}:aws", m.group(), 0.85)


# --------------------------------------------------------------------------- user names
_SYSTEM_ACCOUNTS = frozenset(
    """root admin administrator user users guest anonymous nobody system local service localservice networkservice
        ubuntu ec2-user centos debian fedora admin1 runner vagrant pi node www-data www apache nginx git jenkins
        docker app deploy travis circleci codespace vscode coder default public shared all postgres mysql redis
        daemon bin sys sync mail news ftp sshd test demo example sample string none null nil n/a na unknown required
        optional empty your yours my the here xxx changeme true false undefined username login me self current new
        edit search list""".split()  # noqa: SIM905
)  # fmt: skip
_USER_KEYS = (
    r"user[_\-. ]?name|login(?:[_\-. ]?name)?|logon[_\-. ]?name|sam[_\-. ]?account[_\-. ]?name|"
    r"user[_\-. ]?principal[_\-. ]?name|subject[_\-. ]?user[_\-. ]?name|target[_\-. ]?user[_\-. ]?name|"
    r"benutzername|nom d['’]utilisateur|nombre de usuario|nome utente|nome de usu[aá]rio|"
    r"gebruikersnaam|brugernavn|anv[aä]ndarnamn|k[aä]ytt[aä]j[aä]tunnus|nazwa u[zż]ytkownika|"
    r"u[zž]ivatelsk[eé] jm[eé]no|pou[zž][ií]vate[lľ]sk[eé] meno|uporabni[sš]ko ime|korisni[cč]ko ime|"
    r"felhaszn[aá]l[oó]n[eé]v|nume de utilizator|lietot[aā]jv[aā]rds|kasutajanimi|nama pengguna|"
    r"kullan[ıi]c[ıi] ad[ıi]|t[eê]n ng[ưu][ờo]i d[ùu]ng"
)
# The value of a user-name field. Code that assigns a variable ("username = request.form[...]") is not a value:
# a bare name after " = " is left alone, a quoted one or "key=value" without blanks (a log, a URL) is taken.
_USER_KEY_RE = re.compile(
    rf"(?i)(?<![A-Za-z0-9])(?:{_USER_KEYS})[\"'`]?(?P<link>[ \t]*(?::|=>|=|\"?>)[ \t]*)(?P<q>[\"'`]?)"
    r"(?:[A-Za-z0-9][A-Za-z0-9.\-]{0,31}\\{1,2})?(?P<v>[A-Za-z0-9][A-Za-z0-9._@+\-]{1,63})(?![A-Za-z0-9._@+\-]*[(\[])"
)
_LDAP_RE = re.compile(
    r"(?<![A-Za-z])(?:uid|sAMAccountName|userPrincipalName)(?P<link>[ \t]*[:=][ \t]*)(?P<q>)(?P<v>[^,\s;+\"<>]{2,64})"
)
_KEY_WORD_RE = re.compile(r"[^\W\d_]+")
_USER_KEY_FIRST = frozenset(
    """user username userid login loginname logon logonname sam samaccountname userprincipalname subject
        subjectusername target targetusername benutzername nom nombre nome gebruikersnaam brugernavn användarnamn
        käyttäjätunnus nazwa uživatelské používateľské uporabniško korisničko felhasználónév nume lietotājvārds
        kasutajanimi nama kullanıcı tên uid""".split()  # noqa: SIM905
)
_UID_NAME_RE = re.compile(r"\d+\((?P<name>[^()]{1,64})\)")
_CN_RE = re.compile(r"(?i)(?<![A-Za-z])cn=(?P<v>[^,=\n+\"]{3,64})")
# A person's user name as directories write it, first.last: group and service names ("backup-operators",
# "svc_ldap") are not people.
_USERNAME_SHAPE_RE = re.compile(r"[a-z]+\.[a-z]+(?:\.[a-z0-9]+)?")
# "/user:DOMAIN\\name" (net use, runas), and the user of a URL with credentials ("https://name:token@host").
_SLASH_USER_RE = re.compile(r"(?i)/user:(?:[A-Za-z0-9.\-]{1,32}\\{1,2})?(?P<v>[A-Za-z0-9][A-Za-z0-9._@\-]{1,63})")
_URL_USER_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]{1,30}://(?P<v>[A-Za-z0-9][A-Za-z0-9._%\-]{1,63}):[^\s/@]{1,256}@")
_HOME_RE = re.compile(
    r"(?:/home/|/Users/|/users/|[A-Za-z]:\\\\?Users\\\\?|[A-Za-z]:/Users/)(?P<v>[A-Za-z0-9._\-]{2,32})(?=[/\\\s\"'`:]|$)"
)
_PROMPT_RE = re.compile(
    r"(?m)(?:^|(?<=\s))(?P<v>[a-z_][a-z0-9._\-]{1,31})@(?P<host>[A-Za-z0-9][A-Za-z0-9.\-]{0,63}):[~/][^\n$#]{0,80}[$#]"
)
# A person's common name: capitalised words, initials and the particles between them ("Lotte de Boer").
_PERSON_CN_RE = re.compile(
    r"[A-Z][a-z]+(?:[ ](?:de|van|der|den|von|da|di|del|la|le|du|dos|das|ten|ter)|[ .\-][A-Z][a-z]*\.?)*[ ][A-Z][a-z]+"
)


# A machine's account, named for what it does: "deploy-bot", "github-actions-deploy", "svc_backup", "ci-runner".
_SERVICE_WORDS = frozenset(
    """bot bots robot deploy deployer deployment deploys ci cd cicd svc service services srv daemon jenkins github
    gitlab bitbucket actions runner runners terraform ansible puppet chef automation automated backup backups monitor
    monitoring nagios zabbix prometheus grafana datadog cron scheduler worker workers pipeline pipelines build builder
    release releases sync syncer noreply webhook webhooks integration integrations etl batch healthcheck
    probe""".split()  # noqa: SIM905
)


def _account_name_ok(value: str) -> bool:
    folded = value.casefold()
    if folded in _SYSTEM_ACCOUNTS or value.startswith("i-") or not any(c.isalpha() for c in value):
        return False
    parts = [p for p in re.split(r"[-_.@]", folded) if p]
    return not (len(parts) >= 2 and any(p in _SERVICE_WORDS for p in parts)) and folded not in _SERVICE_WORDS


_USER_WORDS = (
    "user",
    "login",
    "logon",
    "benutzer",
    "utilisateur",
    "usuario",
    "utente",
    "usuário",
    "gebruiker",
    "bruger",
    "användar",
    "käyttäjä",
    "użytkownik",
    "uživatel",
    "používate",
    "uporabni",
    "korisni",
    "felhaszn",
    "utilizator",
    "lietotāj",
    "kasutaja",
    "pengguna",
    "kullanıcı",
    "người dùng",
    "uid",
    "samaccountname",
)


def _user_names(text: str) -> Iterator[Span]:
    lowered = text.casefold()
    matches: list[re.Match[str]] = []
    if any(w in lowered for w in _USER_WORDS):
        for w in _KEY_WORD_RE.finditer(text):
            if w.group().casefold() in _USER_KEY_FIRST:
                for pattern in (_USER_KEY_RE, _LDAP_RE):
                    m = pattern.match(text, w.start())
                    if m is not None:
                        matches.append(m)
                        break
    for m in matches:
        if not m.group("q") and m.group("link").strip() == "=" and m.group("link") != "=":
            continue  # "username = request.form['u']": code
        value, start = m.group("v"), m.start("v")
        inner = _UID_NAME_RE.fullmatch(value)
        if inner is not None:
            value, start = inner.group("name"), start + inner.start("name")
        value = value.rstrip(".,;:)'\"")
        if _account_name_ok(value):
            yield make_span(start, start + len(value), E.ACCOUNT_ID, f"{SOURCE}:user", value.casefold(), 0.85)
    if "cn=" in lowered:
        for m in _CN_RE.finditer(text):
            value = m.group("v").strip()
            start = m.start("v")
            if _PERSON_CN_RE.fullmatch(value):
                yield make_span(start, start + len(value), E.PERSON, f"{SOURCE}:ldap", value.casefold(), 0.85)
            elif _USERNAME_SHAPE_RE.fullmatch(value) and _account_name_ok(value):
                yield make_span(start, start + len(value), E.ACCOUNT_ID, f"{SOURCE}:ldap", value.casefold(), 0.85)
    for pattern, cue in ((_SLASH_USER_RE, "/user:"), (_URL_USER_RE, "://")):
        if cue in lowered:
            for m in pattern.finditer(text):
                if _account_name_ok(m.group("v")):
                    yield make_span(
                        m.start("v"), m.end("v"), E.ACCOUNT_ID, f"{SOURCE}:user", m.group("v").casefold(), 0.85
                    )
    homes = "/home/" in text or "/Users/" in text or "/users/" in text or "Users\\" in text
    prompts = "@" in text and (":~" in text or ":/" in text)
    for pattern in (_HOME_RE,) * homes + (_PROMPT_RE,) * prompts:
        for m in pattern.finditer(text):
            value = m.group("v")
            if _account_name_ok(value):
                yield make_span(m.start("v"), m.end("v"), E.ACCOUNT_ID, f"{SOURCE}:user", value.casefold(), 0.85)
                if pattern is _PROMPT_RE and _account_name_ok(m.group("host")):
                    # the machine of a person's prompt ("nclark@macbook-pro:~$"): a device they use
                    host = m.group("host")
                    yield make_span(m.start("host"), m.end("host"), E.DEVICE_ID, f"{SOURCE}:host", host.casefold(), 0.8)
    if "AAAA" in text:
        for m in _SSH_PUBLIC_KEY_RE.finditer(text):
            if _ssh_key_ok(m.group("type"), m.group("v")):
                yield make_span(m.start("v"), m.end("v"), E.ACCOUNT_ID, f"{SOURCE}:ssh-key", m.group("v")[-24:], 0.85)


# An SSH public key identifies its holder ("ssh-ed25519 AAAAC3Nza... anna@laptop"). Its first bytes repeat its type
# ("\0\0\0\x0bssh-ed25519"), the way a check digit repeats a number, so a string that only looks like a key is left.
_SSH_PUBLIC_KEY_RE = re.compile(
    r"(?<![\w-])(?P<type>ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp(?:256|384|521)"
    r"|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)"
    r"[ \t]{1,4}(?P<v>AAAA[A-Za-z0-9+/]{40,4096}={0,3})(?![A-Za-z0-9+/=])"
)


def _ssh_key_ok(key_type: str, body: str) -> bool:
    need = -(-(4 + len(key_type)) // 3) * 4  # the base64 that holds the length and the type
    try:
        head = base64.b64decode(body[:need], validate=True)
    except (binascii.Error, ValueError):
        return False
    name = key_type.encode()
    return int.from_bytes(head[:4], "big") == len(name) and head[4 : 4 + len(name)] == name


# --------------------------------------------------------------------------- credentials and wallets
# Type prefixes of secrets: webhook signing secrets, Stripe-style secret and restricted keys, session, OAuth and
# reset tokens. Publishable keys (pk_) and object ids (cus_, pi_, cs_) are not secrets and are not listed.
_PREFIXED_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:(?:whsec|sk|rk|sess|session|oa2|oauth|refresh|reset|secret|priv|svc)_(?:(?:live|test|prod)_)?"
    # keys named for what they may do and where: "write_dev_...", "api_live_...", "read_prod_...", but not the object
    # ids of payment APIs ("cs_test_..." is a checkout session, "pi_live_..." a payment intent)
    r"|(?!(?:cs|pi|pm|ch|in|sub|src|seti|acct|evt|re|po|tr|txn|price|prod|plink|tok|cus|ii|il|ba|card|bank)_)"
    r"[a-z]{2,8}_(?:live|test|dev|prod|qa|stg|staging|sandbox)_)"
    r"(?P<v>[A-Za-z0-9]{20,128})(?![A-Za-z0-9])"
)
# The token in a webhook URL: "https://hooks.example.com/hooks/deploy/v1/l6ewAwj2lbtcP9qKMKzSrGCy".
_WEBHOOK_RE = re.compile(
    r"(?i)/(?:hooks?|webhooks?)/(?:[\w.\-]{1,40}/){0,4}(?P<v>[A-Za-z0-9_\-]{16,128})(?=[/?#\s\"'<>)]|$)"
)
_WIF_RE = re.compile(
    r"(?<![1-9A-HJ-NP-Za-km-z])(?:5[HJK][1-9A-HJ-NP-Za-km-z]{48,49}|[KL][1-9A-HJ-NP-Za-km-z]{49,51})(?![1-9A-HJ-NP-Za-km-z])"
)
_BECH32_SHAPE_RE = re.compile(r"(?<![a-z0-9])(?:bc|tb)1[02-9ac-hj-np-z]{39}(?:[02-9ac-hj-np-z]{20})?(?![a-z0-9])")
# A bech32 address whose checksum is off is still one after a word that names it ("bitcoin address bc1q..."); without
# such a word the validated layer decides (identifiers.find_crypto).
_WALLET_CUE_RE = re.compile(
    r"(?i)(?:bitcoin|btc|wallet|crypto|address|adresse|adres|dirección|indirizzo|endereço|pay|send|deposit|transfer)"
)


def _entropy(value: str) -> float:
    counts = Counter(value)
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def _mixed(value: str) -> bool:
    return any(c.islower() for c in value) and any(c.isupper() for c in value) and any(c.isdigit() for c in value)


def _keys(text: str) -> Iterator[Span]:
    if "_" in text:
        for m in _PREFIXED_RE.finditer(text):
            value = m.group("v")
            if _mixed(value) and _entropy(value) >= 3.5:
                yield make_span(m.start(), m.end(), E.SECRET, f"{SOURCE}:prefixed-key", m.group(), 0.85)
    if "hook" in text.lower():
        for m in _WEBHOOK_RE.finditer(text):
            value = m.group("v")
            if _mixed(value) and _entropy(value) >= 3.5:
                yield make_span(m.start("v"), m.end("v"), E.SECRET, f"{SOURCE}:webhook", value, 0.85)
    for m in _WIF_RE.finditer(text):
        value = m.group()
        if _mixed(value) and _entropy(value) >= 4.0:
            yield make_span(m.start(), m.end(), E.SECRET, f"{SOURCE}:wif", value, 0.85)


def _wallets(text: str) -> Iterator[Span]:
    if "bc1" in text or "tb1" in text:
        for m in _BECH32_SHAPE_RE.finditer(text):
            if _WALLET_CUE_RE.search(text, max(0, m.start() - 40), m.start()):
                yield make_span(m.start(), m.end(), E.CRYPTO_ADDRESS, f"{SOURCE}:bech32", m.group(), 0.8)


# --------------------------------------------------------------------------- identifiers in URLs and keys
# A query parameter that names a person, an account or a transaction, with a value that holds a digit:
# "?ref=ING-NL-9920047&txn=20250203-2340", "&customer_id=88213". Online identifiers (GDPR article 4).
_ID_PARAMS = frozenset(
    """uid userid user username account acct accountid accountno accountnumber customer customerid custid cust
    member memberid patient patientid mrn employee employeeid empid order orderid invoice invoiceid ref reference
    refno txn txnid transaction transactionid ticket ticketid case caseid booking bookingid reservation
    reservationid policy policyid policyno claim claimid subscriber subscriberid student studentid applicant
    applicantid""".split()  # noqa: SIM905
)
_QUERY_PARAM_RE = re.compile(r"[?&;](?P<key>[A-Za-z][A-Za-z_\-]{0,30})=(?P<v>[A-Za-z0-9][A-Za-z0-9._~%\-]{2,64})")
# A path or a store key under a word for people or accounts: "/users/4829", "/patients/88213/records",
# "user:4829", "customer:88213:cart". The join link of a meeting: "/j/84729301756".
_PERSON_PATH_RE = re.compile(
    r"(?:/(?:users?|customers?|members?|patients?|accounts?|employees?|profiles?|people|persons?|students?)/"
    r"|(?<![\w:])(?:user|customer|member|patient|account|employee|profile|student|uid)s?:(?:[a-z_]{1,20}:)?)"
    r"(?P<v>\d{2,12}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?![\w\-])"
)
_MEETING_RE = re.compile(r"/(?:j|w|meeting|meetings|join)/(?P<v>\d{9,12})(?=[/?#\s\"'\\<)]|$)")


def _url_ids(text: str) -> Iterator[Span]:
    if "=" in text and ("?" in text or "&" in text):
        for m in _QUERY_PARAM_RE.finditer(text):
            key = m.group("key").casefold().replace("_", "").replace("-", "")
            value = m.group("v")
            if key in _ID_PARAMS and any(c.isdigit() for c in value):
                yield make_span(m.start("v"), m.end("v"), E.ACCOUNT_ID, f"{SOURCE}:url-id", value, 0.8)
    if "/" in text or ":" in text:
        for pattern in (_PERSON_PATH_RE, _MEETING_RE):
            for m in pattern.finditer(text):
                yield make_span(m.start("v"), m.end("v"), E.ACCOUNT_ID, f"{SOURCE}:url-id", m.group("v"), 0.8)


def find_formats(text: str, personal: bool = True, crypto: bool = True) -> Iterator[Span]:
    """``personal``: the formats that carry personal data (identifiers.machine_formats); ``crypto``: wallet addresses
    (identifiers.crypto). Typed credentials always run: keys are always redacted."""
    yield from _keys(text)
    if crypto:
        yield from _wallets(text)
    if not personal:
        return
    if ":" in text:
        for m in _MAC_CHAIN_RE.finditer(text):
            yield make_span(m.start(), m.end(), E.DEVICE_ID, f"{SOURCE}:mac-chain", m.group().lower(), 0.9)
    if "<<" in text:
        for m in _MRZ_LINE_RE.finditer(text):
            if _mrz(m.group()):
                yield make_span(m.start(), m.end(), E.ID_DOCUMENT, f"{SOURCE}:mrz", m.group(), 0.9)
    if "|" in text:
        yield from _hl7(text)
    yield from _aws(text)
    yield from _user_names(text)
    yield from _url_ids(text)
