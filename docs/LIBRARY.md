# The detection library

Everything Harpo looks for, in one list: each detector **family** sits under the kind of data it protects (its
**umbrella**), says what it finds and which types it produces, and has one switch. The same list is shown on the
console's Detection page, switched on its Policy page, returned by `GET /v1/system` (`detection.library`), printed by
`harpo check-config`, and defined in `src/harpo_redact/library.py`.

Two kinds of switch work together:

- **A family switch decides what is looked for.** Switch the *Addresses and places* family off and street addresses
  are no longer searched for. Families overlap on purpose (defence in depth): a Dutch VAT number is found by the
  Netherlands pack and by the EU pack, a value under a "bsn" column by the table reader and by the cue words, so one
  family off does not always mean a value goes through.
- **A type's action decides what happens to what is found**: `redact` (a placeholder), `block` (the request stops) or
  `allow` (sent as written). To stop redacting a kind of value everywhere, set its type to `allow` in the policy; that
  is the switch for the core validated patterns (e-mail, phone, card, IBAN, SSN/BSN/NINO, IP, date of birth).

Credentials have no switch at all: keys are always redacted (INV-11), and the decoders that find keys hidden in
escapes and encodings always run.

## Umbrellas and families

The **Switch** column gives the setting under `detection` in the configuration file. **Live** families can also be
switched on the console's Policy page or with `PUT /v1/policy/live`, which reaches every worker within seconds without
a restart; families that load a model are switched in the configuration file and take effect on restart.

### Credentials

| Family | What it finds | Types | Switch |
| --- | --- | --- | --- |
| **Credential library** `secrets.library` | Gitleaks-derived rules and Harpo's own provider rules: API keys, tokens, private keys, connection strings, AWS key ids in their settings, keys inside base64 and other encodings | SECRET, PRIVATE_KEY | always on |
| **Credentials in prose** `secrets.natural_language` | "My password is ...", "the token is ...", "Passwort: ...": credential statements in 30+ languages, a password word next to its value or a few words before a value no one writes as a word ("password DVSqTIIxXPUq", "Passwort ... und BfnMnQaGjPdc"), credentials in forms and config files | SECRET | always on |
| **Wallet recovery phrases** `secrets.seed_phrases` | BIP39 seed phrases, checked against the word list and their checksum | SECRET | always on |

### Contact and payment

| Family | What it finds | Types | Switch |
| --- | --- | --- | --- |
| **E-mail addresses** `core.email` | Every address, obfuscated ones too ("name [at] example [dot] com"), also when Chinese, Japanese or Korean text runs straight into it | EMAIL | the type's action |
| **Phone numbers** `core.phone` | Validated by libphonenumber in the regions of `detection.phone_regions`, and in international form anywhere; dates are not phones | PHONE | the type's action |
| **Payment cards** `core.cards` | A network's prefix and length and a valid Luhn digit | CREDIT_CARD | the type's action |
| **IBANs** `core.iban` | Every country's IBAN, checked with mod 97 | IBAN | the type's action |

### Identity numbers

| Family | What it finds | Types | Switch |
| --- | --- | --- | --- |
| **SSN, BSN and NINO** `core.national` | US Social Security numbers (area rules), Dutch BSNs (eleven test) after their cue, UK National Insurance numbers | US_SSN, NL_BSN, UK_NINO | the type's action |
| **Checked national and tax IDs** `identifiers.national_ids` | 17 schemes in 14 countries, each checked: FR NIR, ES DNI and NIE, IT codice fiscale, BE national number, DE Steuer-ID, IN Aadhaar and PAN, AU TFN, BR CPF, MX CURP, US ITIN and EIN, NHS and SIN numbers, and the Chinese resident identity and Korean resident registration numbers by the birth date inside them | NATIONAL_ID | `identifiers.national_ids` · live |
| **Values named by a cue word** `identifiers.cued_numbers` | Any value after a word that names it, in 30+ languages: phones, cards, national and tax numbers, passports and licences (a code in capitals alone too: "license number CLYAFCWFNSIMY"), account, record, policy, case, transaction and meeting numbers, bank codes, postcodes, PINs, vehicle and plate numbers, device ids; digit groups printed with " - " | PHONE, CREDIT_CARD, NATIONAL_ID, ID_DOCUMENT, ACCOUNT_ID, ADDRESS, SECRET, DEVICE_ID | `identifiers.cued_numbers` · live |
| **Opaque codes** `identifiers.opaque_codes` | Codes that no language writes, standing in a sentence without a cue word (glued to Chinese, Japanese or Korean text too): capitals ("FXJPIUZXKH", "H5U8VOVWPQ": a licence, card or booking code) and letters in both cases ("BfnMnQaGjPdc": a password). Words, names, acronyms and the identifiers of code are told apart by the letter pairs they use and where their case changes; hashes, masks and test strings are left alone | ACCOUNT_ID, SECRET | `identifiers.opaque_codes` · live |

### Region packs

Formats a country or the EU writes its own way, found without a cue word. See [REGIONS.md](REGIONS.md) for the full
Dutch, US and EU inventory.

| Family | What it finds | Types | Switch |
| --- | --- | --- | --- |
| **Netherlands** `identifiers.regions.nl` | The btw-identificatienummer (both checksums) and the loonheffingennummer | NATIONAL_ID | `identifiers.regions.nl` · live |
| **United States** `identifiers.regions.us` | Masked SSNs and their last four ("XXX-XX-4820", "SSN ending in 4820"), ATIN, the printed Medicare MBI, USCIS receipt numbers, A-Numbers, I-94 numbers | US_SSN, NATIONAL_ID, ACCOUNT_ID, ID_DOCUMENT | `identifiers.regions.us` · live |
| **European Union** `identifiers.regions.eu` | VAT numbers of every member state with their check digits, the BIC after its cue (in capitals), EU Digital COVID Certificate ids | NATIONAL_ID, ACCOUNT_ID, ID_DOCUMENT | `identifiers.regions.eu` · live |

### Forms, tables and fields

| Family | What it finds | Types | Switch |
| --- | --- | --- | --- |
| **Form and table fields** `identifiers.table_fields` | Values under a CSV, Markdown or HTML column, in a two-column row, on a "Label: value" or "Label&nbsp;&nbsp;&nbsp;value" line, or under a JSON key in text, checked against what the label names: names, addresses, towns, house numbers, numbers | PERSON, ADDRESS, LOCATION, PHONE, NATIONAL_ID, ACCOUNT_ID, ID_DOCUMENT | `identifiers.table_fields` · live |

### Addresses and places

| Family | What it finds | Types | Switch |
| --- | --- | --- | --- |
| **Addresses and places** `identifiers.addresses` | Street addresses in 30+ languages, postcodes with their town, PO boxes and military addresses, address labels and phrases ("residing at", "wonende te"); Chinese, Japanese and Korean addresses by their units: provinces, prefectures, road names (도로명주소), block numbers (3丁目4番5号, 8-30-16), postcodes | ADDRESS, LOCATION | `identifiers.addresses` · live |

### Names

| Family | What it finds | Types | Switch |
| --- | --- | --- | --- |
| **Dates of birth** `core.dob` | A date after a birth-date word, with month names in seven languages | DATE_OF_BIRTH | the type's action |
| **Name rules** `ner.name_rules` | Names after greetings, titles, role labels and sign-offs, in signatures, above an address, before an identifier ("Fleur Peters, BSN ..."), written surname first, speakers of a chat transcript; Chinese, Japanese and Korean names by honorifics, titles and family names | PERSON | `ner.name_rules` · live |
| **Named-entity model** `ner.enabled` | spaCy models for people, organisations and places, by language | PERSON, ORGANIZATION, LOCATION | `ner.enabled` · restart |
| **Every mention of a found name** `ner.propagate` | A name or place found once is redacted wherever else it occurs in the request | PERSON, ORGANIZATION, LOCATION | `ner.propagate` · live |
| **Model precision filter** `ner.precision_filter` | Drops what the model tags that cannot be a name: common words the text also writes in lower case, terms a document defines for itself ("the Sponsor") and abbreviations it spells out, field labels, table headers, document titles ("Application to Register Permanent Residence", "NEW PATIENT INTAKE FORM"), months, time zones, log levels, SQL and HTTP keywords, code names, acronyms, browser user agents, verbs that open an instruction ("Mark all that apply"). A full name lowered to slip past ("emily bennett", "... notes. sanne bakker stond ...") or written in leetspeak ("El1f R4m4n") is kept | PERSON, ORGANIZATION, LOCATION | `ner.precision_filter` · live |

### Devices, networks and machine formats

| Family | What it finds | Types | Switch |
| --- | --- | --- | --- |
| **IP addresses** `core.ip` | IPv4 and IPv6, but loopback, unspecified and multicast addresses and versions in a product token ("Chrome/120.0.0.0"); also with tcpdump's port and inside wildcard DNS names | IP_ADDRESS | the type's action |
| **Devices** `identifiers.devices` | MAC addresses, IMEI (Luhn and cue), vehicle identification numbers, serial numbers after their cue | DEVICE_ID | `identifiers.devices` · live |
| **Machine formats** `identifiers.machine_formats` | Personal data where a format puts it: passport and ID-card machine-readable zones, HL7 fields (by position and by shape), AWS identities and the roles a customer made, user names in logs, paths and shell prompts with the prompt's machine, user and account ids in URL paths, parameters and store keys ("/users/4829", "?ref=...", "user:4829"), meeting links, MAC chains, SSH public keys (checked by the key type encoded in them). Service accounts ("deploy-bot") and built-in Windows accounts ("S-1-5-18") are not people | ID_DOCUMENT, PERSON, ACCOUNT_ID, DEVICE_ID, DATE_OF_BIRTH, ADDRESS, PHONE | `identifiers.machine_formats` · live |

### Crypto

| Family | What it finds | Types | Switch |
| --- | --- | --- | --- |
| **Crypto wallet addresses** `identifiers.crypto` | Bitcoin (base58check, bech32 and bech32m checksums) and Ethereum addresses | CRYPTO_ADDRESS | `identifiers.crypto` · live |

### Hidden and encoded text

| Family | What it finds | Types | Switch |
| --- | --- | --- | --- |
| **Escaped text** `identifiers.decode_escapes` | Percent, HTML, JSON and backslash escapes decoded in a shadow view (%40, &amp;#64;, @) | EMAIL, CREDIT_CARD, SECRET | always on |
| **Spelled-out e-mail addresses** `identifiers.spoken_emails` | "name at example dot com" | EMAIL | `identifiers.spoken_emails` · live |
| **Shadow views** `views` | Values split over lines, spelled out, spaced one by one, in leetspeak, reversed, written with look-alike letters or glued to Chinese, Japanese or Korean text, read again in a repaired view | all | always on |
| **Encoded data** `encoded` | base64, hex and other encodings decoded and scanned, `encoded_max_depth` levels deep (at least one) | all | always on |

### Your own terms

| Family | What it finds | Types | Switch |
| --- | --- | --- | --- |
| **Protected registry** `registry` | Your own terms and patterns, redacted as PROTECTED_TERM | PROTECTED_TERM | `registry.terms` and `registry.patterns` |
| **Custom types** `custom_types` | Named types of your own (EMPLOYEE_ID, PROJECT), each with its own action | custom | each type's action (`allow` switches it off) |

### Local model

| Family | What it finds | Types | Switch |
| --- | --- | --- | --- |
| **Local language model** `slm.enabled` | An optional local model that can only add findings, each verified against the text | all | `slm.enabled` · restart |

## Switching a family

In the configuration file (`config/harpo.example.yaml` lists every switch):

```yaml
detection:
  identifiers:
    addresses: false        # street addresses are no longer looked for
    regions:
      us: false             # the US pack is off; US cue words still work
  ner:
    propagate: false        # a found name is redacted only where the model saw it
```

Live, on the console's Policy page (*Detection library*), or with the API:

```bash
curl -X PUT http://localhost:8080/v1/policy/live \
  -H "Authorization: Bearer $HARPO_ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"detectors": {"identifiers.addresses": false}}'
```

The live policy is saved to `policy.live_file` and laid over the configuration file; `DELETE /v1/policy/live` goes
back to the file. A family that is not live (a credential, a model) is refused with the reason. The audit log records
which switches changed and who changed them. `POST /v1/policy/preview` with `{"text": ..., "policy": {"detectors":
{...}}}` shows what a switch would do to a sample before anything is saved.

`harpo check-config` prints the library as it stands, with the live policy when there is one:

```
ok: production configuration with 2 upstream(s)
detection library:
  Credentials: Credential library, Credentials in prose, Wallet recovery phrases
  Contact and payment: E-mail addresses, Phone numbers, Payment cards, IBANs
  ...
  Your own terms: nothing (off: Protected registry, Custom types)
```
