"""The redaction matrix: every protected value type, through 31 carriers, against the real proxy.

A carrier is a way a value can travel inside a request without looking like itself: quoting and markup, JSON (as
text, double-encoded, unicode-escaped, in tool-call arguments, in a tool schema, as an object key), XML, CSV,
YAML, URLs, percent and HTML escapes, base64, hex, invisible and look-alike characters, a line break inside the
value, spacing, and right-to-left override. Those 25 go through the OpenAI-style API; six more go through the
Anthropic-style API as content blocks: a system prompt, a tool_use input object, a tool_result, a text document,
an input-schema example and a name/value record.

Each case also carries a near miss: a look-alike that is not the protected value (a failed checksum, a missing
cue, a public key, a documentation placeholder). It must pass through unchanged, so hardening cannot buy recall by
redacting everything. Near misses are checked to be inert on their own terms, not by the gateway: a failed
checksum that is a valid phone number in the default phone regions (US, GB, NL, DE) is not a near miss, so those
were replaced by numbers that are neither (see the comments on the cases).

A failed checksum is a near miss only where nothing names it. After the word that says what it is ("SSN",
"card number", "IBAN"), the shape of a value is enough, checksum or not: a number one digit off still identifies
someone (detectors/cued.py). So those near misses travel under a field that names nothing (CHECKED_WITHOUT_CUE),
where the check decides, and test_redaction_matrix checks that under their own label they are protected.

The leak oracle shares no code with the gateway's detectors. It decodes what was forwarded every standard way
(JSON, escapes, percent, HTML, base64, hex, Unicode folding, reversal) and looks for the value, or any large piece
of it, in every decoded form. All values are synthetic; checksummed ones were generated to be valid.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import html
import json
import math
import re
import unicodedata
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

MODEL = "mock-provider"


@dataclass(frozen=True)
class Case:
    id: str
    value: str
    label: str  # how the value is introduced in prose: "BSN", "date of birth", "password ="
    key: str  # its field name in structured data: "bsn", "date_of_birth"
    expect: str = "redact"  # redact: forwarded with the value replaced; block: refused, nothing forwarded
    # Credentials are redacted like every other type: keys are always redacted, never blocked (INV-11).
    near_miss: str | None = None  # a look-alike that must pass through unchanged
    near_label: str | None = None  # the near miss's own label, when the cue itself is what differs
    near_key: str | None = None
    secret: str | None = None  # the part the oracle protects, when it is not the whole value


EC_KEY = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPfcbJv3aVnuaEgtlnFooX/i2MwqRRIlKlmIt3iX+O4qoAoGCCqGSM49
AwEHoUQDQgAEHqaE3y3Q8QUGoo+M0Z/Cupvfcuwqub3IMFRAtSowNgjLUEcykBhz
hAa8lVo2KptfeF1fP5ESycWhTU/csBIhHg==
-----END EC PRIVATE KEY-----"""
EC_PUBLIC = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHqaE3y3Q8QUGoo+M0Z/Cupvfcuwq
ub3IMFRAtSowNgjLUEcykBhzhAa8lVo2KptfeF1fP5ESycWhTU/csBIhHg==
-----END PUBLIC KEY-----"""
SEED = "decorate good butter tonight infant biology gate acid control knife select sleep"
SEED_BAD_CHECKSUM = "decorate good butter tonight infant biology gate acid control knife select select"
BEARER = "9f8c7e6d5b4a39281706f5e4d3c2b1a0Zx9Yw8Vu"
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3JfODQyMTciLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3OTE0MDAwMDB9."
    "kQ7vM2xR9pLw4nB8sE1tY6uC3aZ0dF5gH7jK2mN4oPq"
)

CASES: tuple[Case, ...] = (
    # ---------------------------------------------------------------- contact and payment
    Case("email", "maria.jansen@kpn-zakelijk.nl", "email", "email", near_miss="maria.jansen@kpn-zakelijk"),
    Case("phone_international", "+31 20 794 6095", "phone", "phone", near_miss="+31 20 794 609"),
    Case("phone_national", "020 794 6095", "phone", "phone"),
    Case("credit_card", "4103 9471 7534 1114", "card number", "card_number", near_miss="4103 9471 7534 1115"),
    Case("iban", "NL91ABNA0417164300", "IBAN", "iban", near_miss="NL92ABNA0417164300"),
    # ---------------------------------------------------------------- national identifiers
    Case("us_ssn", "159-74-4517", "SSN", "ssn", near_miss="000-74-4517"),
    Case("us_ssn_digits", "159744517", "SSN", "ssn", near_miss="000744517"),
    Case("nl_bsn", "298163871", "BSN", "bsn", near_miss="298163872"),
    Case("uk_nino", "JH 25 81 36 D", "National Insurance number", "national_insurance_number", near_miss="BG 25 81 36 D"),
    # 409 740 2359 fails the NHS check but is a valid US phone number; 109 740 2359 is neither.
    Case("gb_nhs", "409 740 2358", "NHS number", "nhs_number", near_miss="109 740 2359"),
    Case("ca_sin", "337 384 804", "social insurance number", "social_insurance_number", near_miss="337 384 805"),
    Case("fr_nir", "2 85 05 75 112 045 85", "numéro de sécurité sociale", "nir", near_miss="2 85 05 75 112 045 86"),
    Case("es_dni", "74913826C", "DNI", "dni", near_miss="74913826D"),
    Case("es_nie", "Y4719236H", "NIE", "nie", near_miss="Y4719236J"),
    Case("it_codice_fiscale", "RSSMRA85T10A562S", "codice fiscale", "codice_fiscale", near_miss="RSSMRA85T10A562T"),
    Case("be_national_number", "85.07.35-473.20", "rijksregisternummer", "rijksregisternummer",
         near_miss="85.07.35-473.21"),
    Case("de_tax_id", "38 273 301 463", "Steuer-ID", "steuer_id", near_miss="38 273 301 464"),
    Case("in_aadhaar", "2311 2587 8762", "Aadhaar", "aadhaar", near_miss="2311 2587 8763"),
    Case("in_pan", "AAPPL1234C", "PAN", "pan", near_miss="AAPZL1234C"),  # Z is no holder type
    Case("au_tfn", "816 567 024", "TFN", "tfn", near_miss="816 567 025"),
    # 156.458.460-78 fails the CPF check but is a US phone number (+1 564 584 6078); 256... is neither.
    Case("br_cpf", "156.458.460-79", "CPF", "cpf", near_miss="256.458.460-79"),
    Case("br_cpf_digits", "15645846079", "CPF", "cpf", near_miss="25645846079"),
    Case("mx_curp", "GOMA850314HDFRRN01", "CURP", "curp", near_miss="GOMA850314HDFRRN02"),
    Case("us_itin", "987-83-2413", "ITIN", "itin", near_miss="987-89-2413"),
    Case("us_ein", "91-3688987", "EIN", "ein", near_miss="17-3688987"),  # 17 is no EIN prefix; 07-... is a DE phone
    # A word after the cue is not the number; a code in capitals that no language writes would be (opaque.py).
    Case("passport", "X8R2K4L19", "passport number", "passport_number", near_miss="PENDING"),
    Case("bank_account", "7729341056", "account number", "account_number", near_miss="unassigned"),
    Case("routing_number", "093356334", "routing number", "routing_number", near_miss="193356334"),  # bad check digit
    # ---------------------------------------------------------------- crypto, network, devices
    Case("bitcoin_base58", "1BoatSLRHtKNngkdXEeobR76b53LETtpyT", "bitcoin address", "btc_address",
         near_miss="1BoatSLRHtKNngkdXEeobR76b53LETtpyU"),
    Case("bitcoin_bech32", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "bitcoin address", "btc_address",
         near_miss="bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdr"),
    Case("ethereum", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "ETH address", "eth_address",
         near_miss="0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe"),
    Case("ipv4", "81.204.36.12", "IP address", "ip_address", near_miss="81.204.36.312"),
    Case("ipv6", "2a02:a441:7c1e:4400:91f2:3e5b:cf04:1a7d", "IPv6 address", "ipv6_address"),
    Case("mac_address", "3c:22:fb:1a:9e:04", "MAC address", "mac_address", near_miss="3c:22:fb:1a:9e"),
    Case("imei", "35-987100-570061-3", "IMEI", "imei", near_miss="35-987100-570061-4"),
    Case("vin", "1HGCM82633A004352", "VIN", "vin", near_miss="1HGCM82633A00435"),
    # ---------------------------------------------------------------- dates, places, organisation terms
    Case("date_of_birth", "14 March 1985", "date of birth", "date_of_birth", near_miss="14 March 1985",
         near_label="invoice date", near_key="invoice_date"),
    # A street name alone is not an address in prose; under a "street" or "address" key it is a record's street,
    # so the near miss is a landmark.
    Case("street_nl", "Keizersgracht 123", "address", "street", near_miss="Keizersgracht", near_key="landmark"),
    Case("postcode_uk", "SW1A 1AA", "postcode", "postcode", near_miss="SW1A 1A"),
    Case("street_us", "1600 Pennsylvania Avenue", "address", "address", near_miss="Pennsylvania Avenue",
         near_key="landmark"),
    Case("protected_term", "Project Bluefin", "codename", "codename", near_miss="Project Bluefish"),
    # ---------------------------------------------------------------- credentials: blocked by default policy
    # Credential near misses are documentation placeholders under the same label. A truncated real-looking token
    # is not one: under a "token" label any long random value is a credential (gitleaks' generic rule).
    Case("aws_access_key", "AKIAZ4X7Q2LMWN3RT5PJ", "AWS access key", "aws_access_key_id", "redact",
         near_miss="YOUR_ACCESS_KEY_ID"),
    Case("aws_secret_key", "wJalrXUtnFEMIK7MDENGbPxRfiCYq8Lk3Hz5vT2n", "AWS secret access key",
         "aws_secret_access_key", "redact", near_miss="YOUR_SECRET_ACCESS_KEY"),
    Case("github_pat", "ghp_9xQ2LmT7vB4nK8sR1wE6yU3iO5pA0zCd7FgH", "GitHub token", "github_token", "redact",
         near_miss="ghp_" + "x" * 36),
    Case("github_fine_grained", "github_pat_11ABCDEFG0aBcDeFgHiJkL_mNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ0123",
         "GitHub token", "github_token", "redact"),
    Case("gitlab_pat", "glpat-xY7q2Lm9TvB4nK8sR1wE", "GitLab token", "gitlab_token", "redact"),
    Case("slack_bot", "xoxb-7281940356-5829174036182-aB3dE5fG7hJ9kL1mN3pQ5rS7", "Slack token", "slack_token", "redact"),
    Case("slack_webhook", "https://hooks.slack.com/services/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",
         "Slack webhook", "slack_webhook", "redact"),
    Case("stripe_live", "sk_live_51Hx9QmLp2Rt7Vw4Yz8Bc3Dn6", "Stripe key", "stripe_key", "redact"),
    Case("google_api_key", "AIzaSyD8xQ2LmT7vB4nK8sR1wE6yU3iO5pA0zCd", "Google API key", "google_api_key", "redact"),
    Case("openai_key", "sk-proj-7xQ2LmT9vB4nK8sR1wE6yU3iO5pA0zCdFgHjKlMnBvCxZ8T3BlbkFJq7W9e2R4t6Y8u0I1o3P5a7S9d",
         "OpenAI key", "openai_api_key", "redact"),
    Case("anthropic_key",
         "sk-ant-api03-" + "xQ2LmT9vB4nK8sR1wE6yU3iO5pA0zCdFgHjKlMnBvCxZ8q7W9e2R4t6Y8u0I1o3P5a7S9d2F4g6H8j0K2l4Z6x8C0v2B4n6M8q0W2e4R6t8Y0u2I4o6P8a0S2dAA",
         "Anthropic key", "anthropic_api_key", "redact"),
    Case("jwt", JWT, "session token", "session_token", "redact"),
    Case("password", "Tr0ub4dor&3x", "password", "password", "redact", near_miss="required"),
    Case("bearer_token", f"Bearer {BEARER}", "Authorization:", "authorization", "redact", secret=BEARER),
    Case("database_url", "postgres://app_admin:Wq3hT9mZx7Lp@db.internal:5432/billing", "database URL", "database_url",
         "redact", secret="Wq3hT9mZx7Lp", near_miss="postgres://db.internal:5432/billing"),
    Case("npm_token", "npm_aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5", "npm token", "npm_token", "redact"),
    Case("sendgrid_key", "SG.aB3dE5fG7hJ9kL1mN3pQ5r.S7tU9vW1xY3zA5bC7dE9fG1hJ3kL5mN7pQ9rS1tU3vW", "SendGrid key",
         "sendgrid_api_key", "redact"),
    # The near miss's label avoids wordlist words: "word list" plus twelve wordlist words is a run of fifteen, and
    # one of its twelve-word windows can pass the four-bit checksum by chance.
    Case("seed_phrase", SEED, "seed phrase", "seed_phrase", "redact", near_miss=SEED_BAD_CHECKSUM,
         near_label="dictation homework", near_key="dictation_homework"),
    Case("private_key", EC_KEY, "private key", "private_key", "redact", near_miss=EC_PUBLIC, near_label="public key",
         near_key="public_key"),
)  # fmt: skip


# --------------------------------------------------------------------------- carriers
def _user(text: str) -> dict[str, Any]:
    return {"model": MODEL, "messages": [{"role": "user", "content": text}]}


def _tool_call(arguments: str) -> dict[str, Any]:
    return {
        "model": MODEL,
        "messages": [
            {"role": "user", "content": "Look up the customer."},
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": "lookup", "arguments": arguments}}]},
            {"role": "tool", "tool_call_id": "call_1", "content": "Found one record."},
            {"role": "user", "content": "Continue."},
        ],
    }  # fmt: skip


def _xml(value: str) -> str:
    return html.escape(value, quote=True).replace("\n", "&#10;")


def _csv_cell(value: str) -> str:
    return f'"{value.replace(chr(34), chr(34) * 2)}"' if any(c in value for c in ',"\n') else value


def _yaml(key: str, value: str) -> str:
    if "\n" in value:
        body = "\n".join(f"    {line}" for line in value.split("\n"))
        return f"customer:\n  name: J. Smit\n  {key}: |\n{body}\n  status: open\n"
    return f"customer:\n  name: J. Smit\n  {key}: {json.dumps(value) if ': ' in value or value[:1] in '*&!%@' else value}\n  status: open\n"


def _fullwidth(value: str) -> str:
    return "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else ("　" if c == " " else c) for c in value)


_LOOKALIKE = str.maketrans(
    {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "y": "у", "x": "х", "i": "і", "s": "ѕ", "A": "А", "B": "В",
     "E": "Е", "K": "К", "M": "М", "H": "Н", "O": "О", "P": "Р", "C": "С", "T": "Т", "X": "Х"}
)  # fmt: skip


def _homoglyphs(value: str) -> str:
    """Cyrillic look-alike letters and mathematical bold digits (which NFKC folds back to ASCII)."""
    return "".join(chr(0x1D7EC + int(c)) if c.isdigit() else c for c in value.translate(_LOOKALIKE))


def _spaced(value: str) -> str:
    return "\n".join("   ".join(" ".join(word) for word in line.split(" ")) for line in value.split("\n"))


def _reversed_rtl(value: str) -> str:
    """Right-to-left override: the characters are stored reversed but displayed in the original order."""
    return "\n".join(f"\u202e{line[::-1]}\u202c" for line in value.split("\n"))


def _split(value: str) -> str:
    lines = value.split("\n")
    longest = max(range(len(lines)), key=lambda k: len(lines[k]))
    line = lines[longest]
    mid = len(line) // 2
    lines[longest] = f"{line[:mid]}\n{line[mid:]}"
    return "\n".join(lines)


def _b64url(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


Carrier = Callable[[str, str, str], dict[str, Any]]
CARRIERS: dict[str, Carrier] = {
    "sentence": lambda v, label, key: _user(f"Please update the customer file: {label} {v} before Friday."),
    "double_quotes": lambda v, label, key: _user(f'The {label} on file is "{v}".'),
    "single_quoted_kv": lambda v, label, key: _user(f"set {key}='{v}' on the profile"),
    "markdown_table": lambda v, label, key: _user(f"| field | value |\n|---|---|\n| {label} | {v} |"),
    "json_text": lambda v, label, key: _user(json.dumps({"customer": "on file", key: v})),
    "json_double_encoded": lambda v, label, key: _user(json.dumps({"payload": json.dumps({key: v})})),
    "json_unicode_escaped": lambda v, label, key: _user(
        '{"' + key + '": "' + "".join(f"\\u{ord(c):04x}" for c in v) + '"}'
    ),
    "xml_attribute": lambda v, label, key: _user(f'<record {key}="{_xml(v)}" status="open"/>'),
    "csv": lambda v, label, key: _user(f"name,{key},city\nJ. Smit,{_csv_cell(v)},Utrecht"),
    "yaml": lambda v, label, key: _user(_yaml(key, v)),
    "tool_arguments": lambda v, label, key: _tool_call(json.dumps({key: v})),
    "schema_default": lambda v, label, key: {
        "model": MODEL,
        "messages": [{"role": "user", "content": "Fill in the form."}],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "save_record",
                    "description": "Save a record.",
                    "parameters": {
                        "type": "object",
                        "properties": {key: {"type": "string", "default": v, "examples": [v]}},
                    },
                },
            }
        ],
    },
    "json_key": lambda v, label, key: _tool_call(json.dumps({f"{key}_index": {v: {"status": "verified"}}})),
    "url_query": lambda v, label, key: _user(
        f"Open https://crm.example.org/search?{key}={urllib.parse.quote(v, safe='')}&lang=en"
    ),
    "percent_all": lambda v, label, key: _user(f"{label}: " + "".join(f"%{b:02X}" for b in v.encode())),
    "html_entities": lambda v, label, key: _user(
        f"<tr><th>{label}</th><td>" + "".join(f"&#{ord(c)};" for c in v) + "</td></tr>"
    ),
    "base64": lambda v, label, key: _user(f"{label} (base64): {base64.b64encode(v.encode()).decode()}"),
    "base64_json": lambda v, label, key: _user(f"token payload: {_b64url(json.dumps({key: v}))}"),
    "hex": lambda v, label, key: _user(f"{label} (hex): {v.encode().hex()}"),
    "zero_width": lambda v, label, key: _user(f"{label}: " + "\u200b".join(v)),
    "fullwidth": lambda v, label, key: _user(f"{label}: {_fullwidth(v)}"),
    "homoglyphs": lambda v, label, key: _user(f"{label}: {_homoglyphs(v)}"),
    "line_split": lambda v, label, key: _user(f"{label}: {_split(v)} (copied from the form)"),
    "spaced": lambda v, label, key: _user(f"{label}: {_spaced(v)}"),
    "rtl_override": lambda v, label, key: _user(f"{label}: {_reversed_rtl(v)}"),
}
assert len(CARRIERS) == 25

# The same values through the Anthropic-style API (/v1/messages), in the shapes Claude Code and agent frameworks
# send: tool inputs are JSON objects there, not strings, and documents and system prompts are content blocks.
ANTHROPIC_MODEL = "claude-matrix"


def _anthropic(messages: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    return {"model": ANTHROPIC_MODEL, "max_tokens": 64, "messages": messages, **extra}


def _tool_use(tool_input: dict[str, Any]) -> dict[str, Any]:
    return _anthropic([
        {"role": "user", "content": "Look up the customer."},
        {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_1", "name": "lookup", "input": tool_input}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": "Found one record."}]},
    ])  # fmt: skip


ANTHROPIC_CARRIERS: dict[str, Carrier] = {
    "system_blocks": lambda v, label, key: _anthropic(
        [{"role": "user", "content": "Summarise the record."}],
        system=[{"type": "text", "text": f"Customer record. {label}: {v}"}],
    ),
    "tool_use_input": lambda v, label, key: _tool_use({key: v}),
    "tool_result_blocks": lambda v, label, key: _anthropic(
        [
            {"role": "user", "content": "Look up the customer."},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_1", "name": "lookup", "input": {}}]},
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "toolu_1",
                        "content": [{"type": "text", "text": f"{label}: {v}"}],
                    }
                ],
            },
        ]
    ),
    "document_text": lambda v, label, key: _anthropic(
        [
            {
                "role": "user",
                "content": [
                    {
                        "type": "document",
                        "source": {"type": "text", "media_type": "text/plain", "data": f"Record\n{label}: {v}\n"},
                    },
                    {"type": "text", "text": "Summarise the document."},
                ],
            },
        ]
    ),
    "input_schema_examples": lambda v, label, key: _anthropic(
        [{"role": "user", "content": "Fill in the form."}],
        tools=[
            {
                "name": "save_record",
                "description": "Save a record.",
                "input_schema": {"type": "object", "properties": {key: {"type": "string", "examples": [v]}}},
            }
        ],
    ),
    # A name/value record: the label is a sibling field, not the key.
    "name_value_records": lambda v, label, key: _tool_use(
        {"record": {"fields": [{"name": key, "value": v}, {"name": "status", "value": "open"}]}}
    ),
}
ALL_CARRIERS: dict[str, Carrier] = {**CARRIERS, **ANTHROPIC_CARRIERS}
NEAR_MISS_CARRIERS = ("sentence", "json_text", "tool_arguments", "base64", "tool_use_input", "name_value_records")


def endpoint_for(carrier: str) -> str:
    return "/v1/messages" if carrier in ANTHROPIC_CARRIERS else "/v1/chat/completions"


# Near misses that fail a check the word in front of them would override (see the module docstring).
CHECKED_WITHOUT_CUE = frozenset(
    {"phone_international", "credit_card", "iban", "us_ssn", "us_ssn_digits", "nl_bsn", "uk_nino", "ca_sin", "fr_nir",
     "es_dni", "es_nie", "it_codice_fiscale", "de_tax_id", "in_pan", "au_tfn", "br_cpf", "br_cpf_digits", "mx_curp",
     "us_itin", "us_ein", "routing_number", "bitcoin_bech32", "imei", "vin"}
)  # fmt: skip


def body_for(case: Case, carrier: str, *, near: bool = False, own_label: bool = False) -> dict[str, Any]:
    """The request for a case's value, or for its near miss (``near``). A near miss in CHECKED_WITHOUT_CUE travels
    under a field that names nothing, unless ``own_label``."""
    if near:
        assert case.near_miss is not None
        if case.id in CHECKED_WITHOUT_CUE and not own_label:
            return ALL_CARRIERS[carrier](case.near_miss, "reference", "reference")
        return ALL_CARRIERS[carrier](case.near_miss, case.near_label or case.label, case.near_key or case.key)
    return ALL_CARRIERS[carrier](case.value, case.label, case.key)


# --------------------------------------------------------------------------- the leak oracle
_FOLD = str.maketrans(
    "аеорсухіјѕһԁԛԝӏАВЕКМНОРСТХУІЈЅΑΒΕΖΗΙΚΜΝΟΡΤΥΧαοκνρτυχιεϲ",
    "aeopcyxijshdqwlABEKMHOPCTXYIJSABEZHIKMNOPTYXaoknptuxiec",
)
_B64_RUN = re.compile(r"[A-Za-z0-9+/_\-]{8,}={0,2}")
_HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{2}){5,}")
_ESC = re.compile(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})")
_QP = re.compile(r"=([0-9A-F]{2})")


def _clean(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = "".join(c for c in text if unicodedata.category(c) not in ("Cf", "Mn", "Me"))
    return text.translate(_FOLD)


def _strings(node: Any) -> list[str]:
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [s for k, v in node.items() for s in (*_strings(k), *_strings(v))]
    if isinstance(node, list):
        return [s for v in node for s in _strings(v)]
    return []


def _unescape(text: str) -> str:
    return _ESC.sub(lambda m: chr(int(m.group(1) or m.group(2), 16)), text)


def _decodings(text: str) -> list[str]:
    out = [
        html.unescape(text),
        urllib.parse.unquote(text),
        _unescape(text),
        _QP.sub(lambda m: chr(int(m.group(1), 16)), text),
    ]
    for run in _B64_RUN.findall(text):
        body = run.rstrip("=").replace("-", "+").replace("_", "/")
        with contextlib.suppress(binascii.Error, ValueError):
            out.append(base64.b64decode(body + "=" * (-len(body) % 4)).decode("utf-8", "ignore"))
    for run in _HEX_RUN.findall(text):
        out.append(bytes.fromhex(run).decode("utf-8", "ignore"))
    with contextlib.suppress(ValueError, RecursionError):
        out.extend(_strings(json.loads(text)))
    return out


def _views(text: str, depth: int = 4, cap: int = 400) -> set[str]:
    seen: set[str] = set()
    frontier = [text]
    for _ in range(depth):
        nxt: list[str] = []
        for item in frontier:
            for form in (item, _clean(item)):
                if form not in seen:
                    seen.add(form)
                    nxt.extend(_decodings(form))
        frontier = [x for x in dict.fromkeys(nxt) if x and x not in seen][:cap]
    seen.update(frontier)
    return seen


def core(text: str) -> str:
    return re.sub(r"[^0-9a-z]", "", _clean(text).casefold())


def leak(secret: str, texts: list[str]) -> str | None:
    """The first piece of `secret` (or all of it) found in any decoded form of `texts`, else None."""
    target = core(secret)
    size = min(len(target), min(max(8, math.ceil(len(target) * 0.6)), 24))
    pieces = {target[i : i + size] for i in range(len(target) - size + 1)}
    for text in texts:
        for view in _views(text):
            for candidate in (core(view), core(view[::-1])):
                hit = next((p for p in pieces if p in candidate), None)
                if hit is not None:
                    return f"{hit!r} survives in {view[:90]!r}"
    return None
