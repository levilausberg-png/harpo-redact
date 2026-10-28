"""The detection library: every detector Harpo has, grouped under what it protects, and how to switch it.

Each family names its umbrella (the kind of data it protects), the types it can produce, whether it is deterministic
or a model, and the setting that switches it. Families that cannot be switched off say why: credentials are always
redacted (INV-11), and the core validated patterns are controlled per type in the policy instead (an action of
"allow" for PHONE, say), which is the finer switch. The console's Detection page shows this list, /v1/system returns
it, ``harpo check-config`` prints it, and the live policy can switch the families marked ``live`` without a restart.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .config import Settings


@dataclass(frozen=True, slots=True)
class Family:
    id: str  # stable: the live policy and the API use it
    group: str
    title: str
    detail: str
    types: tuple[str, ...]
    setting: tuple[str, ...] | None = None  # path under Settings.detection; None: not switchable here
    method: str = "deterministic"  # or "model"
    locked: str | None = None  # why it is always on
    live: bool = True  # may the live policy switch it


ALWAYS_KEYS = "Credentials are always redacted (INV-11): this family cannot be switched off."
BY_TYPE = "A validated core pattern: to stop redacting one of its types, set that type's action to allow in the policy."

GROUPS = (
    "Credentials",
    "Contact and payment",
    "Identity numbers",
    "Region packs",
    "Forms, tables and fields",
    "Addresses and places",
    "Names",
    "Devices, networks and machine formats",
    "Crypto",
    "Hidden and encoded text",
    "Your own terms",
    "Local model",
)

# fmt: off
FAMILIES: tuple[Family, ...] = (
    # ------------------------------------------------------------------ credentials
    Family("secrets.library", "Credentials", "Credential library",
           "Gitleaks-derived rules and Harpo's own provider rules: API keys, tokens, private keys, connection strings, "
           "keys inside base64 and other encodings.", ("SECRET", "PRIVATE_KEY"), locked=ALWAYS_KEYS),
    Family("secrets.natural_language", "Credentials", "Credentials in prose",
           "\"My password is ...\", \"the token is ...\", \"Passwort: ...\": credential statements in 30+ languages, a "
           "password word next to its value or a few words before a value no one writes as a word (\"password "
           "DVSqTIIxXPUq\"), credentials in forms and config files.", ("SECRET",), locked=ALWAYS_KEYS),
    Family("secrets.seed_phrases", "Credentials", "Wallet recovery phrases",
           "BIP39 seed phrases, checked against the word list and their checksum.", ("SECRET",), locked=ALWAYS_KEYS),
    # ------------------------------------------------------------------ core validated patterns
    Family("core.email", "Contact and payment", "E-mail addresses",
           "Every address, obfuscated ones too (\"name [at] example [dot] com\"), also when Chinese, Japanese or "
           "Korean text runs straight into it.", ("EMAIL",), locked=BY_TYPE),
    Family("core.phone", "Contact and payment", "Phone numbers",
           "Validated by libphonenumber in the regions of detection.phone_regions, and in international form anywhere; "
           "dates are not phones.", ("PHONE",), locked=BY_TYPE),
    Family("core.cards", "Contact and payment", "Payment cards",
           "Card numbers with a network's prefix and length and a valid Luhn digit.", ("CREDIT_CARD",), locked=BY_TYPE),
    Family("core.iban", "Contact and payment", "IBANs", "Every country's IBAN, checked with mod 97.", ("IBAN",),
           locked=BY_TYPE),
    Family("core.national", "Identity numbers", "SSN, BSN and NINO",
           "US Social Security numbers (area rules), Dutch BSNs (eleven test) after their cue, UK National Insurance "
           "numbers.", ("US_SSN", "NL_BSN", "UK_NINO"), locked=BY_TYPE),
    Family("core.ip", "Devices, networks and machine formats", "IP addresses",
           "IPv4 and IPv6, but not loopback, unspecified and multicast addresses or a version in a product token "
           "(\"Chrome/120.0.0.0\"); also with tcpdump's port and inside wildcard DNS names.", ("IP_ADDRESS",),
           locked=BY_TYPE),
    Family("core.dob", "Names", "Dates of birth",
           "A date after a birth-date word in English, Dutch, German, French, Spanish, Italian, Portuguese and more, "
           "with month names in seven languages.", ("DATE_OF_BIRTH",), locked=BY_TYPE),
    # ------------------------------------------------------------------ identity numbers
    Family("identifiers.national_ids", "Identity numbers", "Checked national and tax IDs",
           "17 schemes in 14 countries, each checked: French NIR, Spanish DNI and NIE, Italian codice fiscale, Belgian "
           "national number, German Steuer-ID, Indian Aadhaar and PAN, Australian TFN, Brazilian CPF, Mexican CURP, "
           "US ITIN and EIN, NHS and SIN numbers (python-stdnum), and the Chinese resident identity and Korean "
           "resident registration numbers by the birth date inside them.", ("NATIONAL_ID",),
           ("identifiers", "national_ids")),
    Family("identifiers.cued_numbers", "Identity numbers", "Values named by a cue word",
           "Any value after a word that names it, in 30+ languages: phones, cards, national and tax numbers, passports "
           "and licences (a code in capitals alone too: \"license number CLYAFCWFNSIMY\"), account, record, policy, "
           "case, transaction and meeting numbers, bank codes, postcodes, PINs, vehicle and plate numbers, device IDs; "
           "digit groups printed with \" - \". Also card, phone and VIN shapes that need no cue.",
           ("PHONE", "CREDIT_CARD", "NATIONAL_ID", "ID_DOCUMENT", "ACCOUNT_ID", "ADDRESS", "SECRET", "DEVICE_ID"),
           ("identifiers", "cued_numbers")),
    Family("identifiers.opaque_codes", "Identity numbers", "Opaque codes",
           "Codes that no language writes, standing in a sentence without a cue word (glued to Chinese, Japanese or "
           "Korean text too): capitals such as \"FXJPIUZXKH\" or \"H5U8VOVWPQ\" (a licence, card or booking code) "
           "and letters in both cases such as \"BfnMnQaGjPdc\" (a password). Words, names, acronyms and the "
           "identifiers of code are told apart by the letter pairs they use and where their case changes; hashes, "
           "masks and test strings are left alone.",
           ("ACCOUNT_ID", "SECRET"), ("identifiers", "opaque_codes")),
    # ------------------------------------------------------------------ region packs
    Family("identifiers.regions.nl", "Region packs", "Netherlands",
           "Formats found without a cue: the btw-identificatienummer (both checksums) and the loonheffingennummer. "
           "Dutch cue words (KvK, AGB, BIG, A-nummer, V-nummer, kenteken, ...) are part of the cue words above.",
           ("NATIONAL_ID",), ("identifiers", "regions", "nl")),
    Family("identifiers.regions.us", "Region packs", "United States",
           "Masked SSNs and their last four (\"XXX-XX-4820\", \"SSN ending in 4820\"), ATIN, the printed Medicare MBI, "
           "USCIS receipt numbers, A-Numbers and I-94 numbers.", ("US_SSN", "NATIONAL_ID", "ACCOUNT_ID", "ID_DOCUMENT"),
           ("identifiers", "regions", "us")),
    Family("identifiers.regions.eu", "Region packs", "European Union",
           "VAT identification numbers of every member state with their check digits, the BIC after its cue, and EU "
           "Digital COVID Certificate identifiers.", ("NATIONAL_ID", "ACCOUNT_ID", "ID_DOCUMENT"),
           ("identifiers", "regions", "eu")),
    # ------------------------------------------------------------------ fields
    Family("identifiers.table_fields", "Forms, tables and fields", "Form and table fields",
           "Values under a CSV, Markdown or HTML column, in a two-column row, on a \"Label: value\" or \"Label   "
           "value\" line (after an item number too: \"49.c. Middle Name   ...\") or under a JSON key in text, checked "
           "against what the label names: names, addresses, towns, house numbers, numbers.",
           ("PERSON", "ADDRESS", "LOCATION", "PHONE", "NATIONAL_ID", "ACCOUNT_ID", "ID_DOCUMENT"),
           ("identifiers", "table_fields")),
    # ------------------------------------------------------------------ addresses
    Family("identifiers.addresses", "Addresses and places", "Addresses and places",
           "Street addresses in 30+ languages, postcodes with their town, PO boxes and military addresses, address "
           "labels and phrases (\"residing at\", \"wonende te\"); Chinese, Japanese and Korean addresses by their "
           "units: provinces, prefectures, road names (도로명주소), block numbers (3丁目4番5号, 8-30-16), postcodes.",
           ("ADDRESS", "LOCATION"), ("identifiers", "addresses")),
    # ------------------------------------------------------------------ names
    Family("ner.name_rules", "Names", "Name rules",
           "Names after greetings, titles, role labels and sign-offs, in signatures, above an address, before an "
           "identifier (\"Fleur Peters, BSN ...\"), written surname first, speakers of a chat transcript; Chinese, "
           "Japanese and Korean names by honorifics, titles and family names.", ("PERSON",), ("ner", "name_rules")),
    Family("ner.enabled", "Names", "Named-entity model",
           "spaCy models for people, organisations and places, by language.", ("PERSON", "ORGANIZATION", "LOCATION"),
           ("ner", "enabled"), method="model", live=False),
    Family("ner.propagate", "Names", "Every mention of a found name",
           "A name or place found once is redacted wherever else it occurs in the request.",
           ("PERSON", "ORGANIZATION", "LOCATION"), ("ner", "propagate")),
    Family("ner.precision_filter", "Names", "Model precision filter",
           "Drops what the model tags that cannot be a name: common words the text also writes in lower case, terms a "
           "document defines for itself (\"the Sponsor\") and abbreviations it spells out, field labels, table "
           "headers, document titles (\"Application to Register Permanent Residence\", \"NEW PATIENT INTAKE FORM\"), "
           "months, time zones, log levels, SQL and HTTP keywords, code names, acronyms, browser user agents, verbs "
           "that open an instruction (\"Mark all that apply\"). A full name lowered to slip past (\"emily bennett\") "
           "or written in leetspeak (\"El1f R4m4n\") is kept.",
           ("PERSON", "ORGANIZATION", "LOCATION"), ("ner", "precision_filter")),
    # ------------------------------------------------------------------ devices and machine formats
    Family("identifiers.devices", "Devices, networks and machine formats", "Devices",
           "MAC addresses, IMEI (Luhn and cue), vehicle identification numbers, serial numbers after their cue.",
           ("DEVICE_ID",), ("identifiers", "devices")),
    Family("identifiers.machine_formats", "Devices, networks and machine formats", "Machine formats",
           "Personal data where a format puts it: passport and ID-card machine-readable zones, HL7 fields (by position "
           "and by shape), AWS identities and the roles a customer made, user names in logs, paths and shell prompts "
           "with the prompt's machine, user and account ids in URL paths, parameters and store keys "
           "(\"/users/4829\", \"?ref=...\", \"user:4829\"), meeting links, MAC chains, SSH public keys (checked by the "
           "key type encoded in them). Service accounts (\"deploy-bot\") and built-in Windows accounts "
           "(\"S-1-5-18\") are not people. Typed credentials in these formats are always found.",
           ("ID_DOCUMENT", "PERSON", "ACCOUNT_ID", "DEVICE_ID", "DATE_OF_BIRTH", "ADDRESS", "PHONE"),
           ("identifiers", "machine_formats")),
    # ------------------------------------------------------------------ crypto
    Family("identifiers.crypto", "Crypto", "Crypto wallet addresses",
           "Bitcoin (base58check, bech32 and bech32m checksums) and Ethereum addresses.", ("CRYPTO_ADDRESS",),
           ("identifiers", "crypto")),
    # ------------------------------------------------------------------ hidden and encoded
    Family("identifiers.decode_escapes", "Hidden and encoded text", "Escaped text",
           "Percent, HTML, JSON and backslash escapes decoded in a shadow view (%40, &#64;, \\u0040).",
           ("EMAIL", "CREDIT_CARD", "SECRET"), ("identifiers", "decode_escapes"),
           locked="Always on: a key written with escapes is still a key (INV-11)."),
    Family("identifiers.spoken_emails", "Hidden and encoded text", "Spelled-out e-mail addresses",
           "\"name at example dot com\".", ("EMAIL",), ("identifiers", "spoken_emails")),
    Family("views", "Hidden and encoded text", "Shadow views",
           "Values split over lines, spelled out, spaced one by one, in leetspeak, reversed, written with look-alike "
           "letters or glued to Chinese, Japanese or Korean text are read again in a repaired view.", ("all",),
           locked="Always on: these views only repair "
           "characters, they add no new kind of finding."),
    Family("encoded", "Hidden and encoded text", "Encoded data",
           "base64, hex and other encodings decoded and scanned, detection.encoded_max_depth levels deep.", ("all",),
           locked="Always at least one level deep: a key inside base64 is still a key (INV-11). Deeper levels are set "
           "by detection.encoded_max_depth."),
    # ------------------------------------------------------------------ own terms
    Family("registry", "Your own terms", "Protected registry",
           "Your own terms and patterns, redacted as PROTECTED_TERM.", ("PROTECTED_TERM",),
           locked="Configured by its terms and patterns."),
    Family("custom_types", "Your own terms", "Custom types",
           "Named types of your own (EMPLOYEE_ID, PROJECT), each with its own action in the policy.", ("custom",),
           locked="Switched per type: set its action to allow."),
    # ------------------------------------------------------------------ local model
    Family("slm.enabled", "Local model", "Local language model",
           "An optional local model that can only add findings, each verified against the text.", ("all",),
           ("slm", "enabled"), method="model", live=False),
)
# fmt: on

BY_ID = {f.id: f for f in FAMILIES}
LIVE_IDS = frozenset(f.id for f in FAMILIES if f.setting is not None and f.locked is None and f.live)


def setting_of(settings: Settings, family: Family) -> Any:
    node: Any = settings.detection
    for part in family.setting or ():
        node = getattr(node, part)
    return node


def enabled(settings: Settings, family: Family) -> bool:
    if family.id == "encoded":
        return settings.detection.encoded_max_depth > 0
    if family.id == "registry":
        registry = settings.detection.registry
        return bool(registry.terms or registry.patterns)
    if family.id == "custom_types":
        return any(c.action != "allow" for c in settings.detection.custom_types)
    if family.setting is None:
        return True
    return bool(setting_of(settings, family))


def set_flags(data: dict[str, Any], flags: dict[str, bool]) -> None:
    """Write family switches into a Settings dump (``data`` is ``Settings.model_dump()``)."""
    for family_id, value in flags.items():
        family = BY_ID[family_id]
        node = data["detection"]
        path = family.setting or ()
        for part in path[:-1]:
            node = node[part]
        node[path[-1]] = bool(value)


def describe(settings: Settings, configured: Settings | None = None) -> dict[str, Any]:
    """Every family under its umbrella, on or off in ``settings``; with ``configured`` (the configuration file alone)
    also whether the file has it on, so the console can show what the live policy changed."""
    groups: dict[str, list[dict[str, Any]]] = {g: [] for g in GROUPS}
    for family in FAMILIES:
        row = {
            "id": family.id,
            "title": family.title,
            "detail": family.detail,
            "types": list(family.types),
            "method": family.method,
            "enabled": enabled(settings, family),
            "locked": family.locked,
            "live": family.id in LIVE_IDS,
            "setting": "detection." + ".".join(family.setting) if family.setting else None,
        }
        if configured is not None:
            row["configured"] = enabled(configured, family)
        groups[family.group].append(row)
    return {"groups": [{"name": name, "families": rows} for name, rows in groups.items() if rows]}


def summary_lines(settings: Settings) -> list[str]:
    """One line per umbrella for the command line: what is on and what is off."""
    lines = []
    for group in describe(settings)["groups"]:
        on = [f["title"] for f in group["families"] if f["enabled"]]
        off = [f["title"] for f in group["families"] if not f["enabled"]]
        text = ", ".join(on) if on else "nothing"
        if off:
            text += f" (off: {', '.join(off)})"
        lines.append(f"{group['name']}: {text}")
    return lines
