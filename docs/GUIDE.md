# Harpo: the complete guide

A self-hosted proxy that removes personal and confidential data from prompts before they reach an
LLM provider. Applications keep using the OpenAI or Anthropic SDKs; only the base URL changes.
Detected values are replaced with placeholders such as `[PERSON_1]` and are never restored: the
provider, its logs and its replies only ever contain placeholders.

## What it does

- **Two compatible endpoints.** `POST /v1/chat/completions` (OpenAI format, also used for Gemini's
  OpenAI-compatible API) and `POST /v1/messages` (Anthropic format), including streaming. Both also speak
  OpenRouter's dialect, with its provider routing enforced (see [OpenRouter](#openrouter)).
- **Layered detection.** Validated patterns (email, phone, card with Luhn and issuer prefix, IBAN, SSN,
  BSN, NINO, IP, date of birth), secrets and private keys, base64-wrapped data, a protected-terms
  registry, rule-based name cues, spaCy NER, and an optional local SLM (Ollama) for indirect identifiers.
- **A large credential library, always on.** The 221 gitleaks rules (MIT, vendored) run on RE2, which matches in
  linear time, so no prompt can trigger catastrophic backtracking. On top: passwords stated in a sentence
  ("my password is ..."), HTTP Basic credentials, AWS secret keys, Docker Hub tokens and BIP39 wallet
  recovery phrases (checksum verified). Keys are always redacted: the request goes on with `[SECRET_1]` where the key
  was. Add your own key formats with `detection.secrets.extra_rules_file`. The audit line records which rule fired,
  never the value.
- **More identifiers, validated or named.** 17 more national and tax ID schemes in 14 countries (python-stdnum check
  digits, and the birth date inside Chinese and Korean resident numbers; ambiguous formats need a cue word),
  MAC/IMEI/VIN, Bitcoin and Ethereum addresses, and dates (sent as-is unless policy redacts them). Any value named by the word in front of it (phone, card, national
  and tax numbers, identity documents, postcodes, accounts, bank codes, IBANs, vehicles, devices, PINs) in some thirty
  languages: after such a word the shape is enough, checksum or not, since a number one digit off still points to a
  person; without one, a value must pass its check. Street addresses and postcodes in their local grammar, names
  after greetings, honorifics and labels in other languages, and the machine formats that hold people (HL7, passport
  machine-readable zones, AWS identities, user names in paths and logs, SSH public keys). Chinese, Japanese and Korean
  addresses by their units (provinces, prefectures, 도로명주소 road names, 3丁目4番5号 block numbers) and names by
  honorifics and family names. Codes that no language writes ("FXJPIUZXKH", "BfnMnQaGjPdc") are told from words,
  names and code identifiers by their letter pairs and case. Escaped values (`%40`, `&#64;`, `\u0040`, "jane at
  example dot com") are decoded in a shadow copy and still caught.
- **Region packs for the Netherlands, the United States and the EU.** Formats a country writes its own way, found
  without a cue word and checked: the Dutch btw-identificatienummer and loonheffingennummer, masked US Social Security
  numbers and their last four, ATIN, the Medicare MBI, USCIS receipt numbers, A-Numbers and I-94 numbers, VAT numbers
  of every EU member state, the BIC and EU COVID certificate ids. [REGIONS.md](REGIONS.md) lists every Dutch, US and EU
  identifier and how it is found.
- **A detection library you can read and switch.** Every detector sits in a family under the kind of data it protects,
  with one switch each, in the configuration file or live on the console: see [Detection
  families](#detection-families) and [LIBRARY.md](LIBRARY.md).
- **Values in any shape.** A field name is a cue word: JSON leaves and keys carry the nearest meaningful key
  ("298163871" under `bsn`, a schema default under its property name), name/value records their sibling name, and
  table cells (CSV, TSV, Markdown, HTML) their column header or row label. A field name for a validated type picks
  the check, and the value must still pass it; a header the cue words know types its cells by shape, and a header
  for a person's name, an address or a place types a cell that holds one. Base64 and hex runs are decoded with the
  words before them; values are also read rejoined across line breaks (also inside a word), unspaced, in display
  order under a right-to-left override and with look-alike letters next to digits read as Latin.
  `tests/test_redaction_matrix.py` checks 60 value types in 31 shapes each.
- **Documents.** PDF, Word, Excel, PowerPoint and text files can be redacted through `POST /v1/documents/redact`,
  the `redact-file` command, or (opt-in) as attachments in chat requests. Files are parsed in an isolated worker
  process; what cannot be inspected is refused; the output is re-scanned before it is released.
- **Strict by default.** Unknown top-level request fields are rejected; tool descriptions and schemas,
  stop sequences and response schemas are scanned; location hints and `prompt_cache_key` are removed;
  Anthropic remote MCP servers are blocked; overrides need a key with `can_override: true`; provider
  responses are capped at 50 MB.
- **Three output styles.** Relational (`[PERSON_1]`, same value same number across the conversation),
  generic (`[PERSON]`), and generic with context repair (`[PERSON_A]`/`[PERSON_B]` inside a sentence).
- **Risk verdicts.** Green sends. Yellow sends with an advisory (a key was redacted, placeholder density,
  collapsed sentences, hidden characters, mixed scripts, overrides). Red blocks with a provider-shaped `403` that
  lists the reasons; a type your policy blocks can be sent redacted after an explicit override, by a key that may
  override. Keys never block: API keys, tokens, passwords and private keys are always redacted.
- **Your policy, live.** An action per type (redact, block or allow) and types of your own, changed on the console's
  Policy page and applied to the next request without a restart. See [Choose what matters](#choose-what-matters).
- **A console** at `/` that marks detected values while you type and shows exactly what would leave.
- **No content in logs.** Audit lines and metrics carry counts, codes and timings only.

## Quickstart (local demo, no provider account needed)

```bash
pip install -e ".[dev]"
pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl

harpo mock-upstream --port 9100 &                 # fake provider that echoes what it receives
HARPO_CONFIG=config/harpo.dev.yaml harpo serve
```

Open http://127.0.0.1:8080 and pick a sample, or call the API:

```bash
curl -s localhost:8080/v1/chat/completions -H 'content-type: application/json' \
  -d '{"model":"mock-provider","messages":[{"role":"user","content":"Email anna.jansen@corp.example about card 4111 1111 1111 1111"}]}'
```

## One command: the boot scripts

| | Start | Stop |
| --- | --- | --- |
| Windows | double-click `boot.cmd` (or `.\boot.cmd` in a terminal) | `stop.cmd` |
| macOS, Linux | `./boot.sh` | `./stop.sh` |

The first run takes a minute or a few, depending on your connection. It needs Python 3.12 or newer and creates
`.venv`. It installs the gateway and its hash-checked detection models, then asks where requests should go and for
that provider's key. The key is stored in `.harpo/.env`, readable only by you; a key already in your environment is
used as is. Next it finds your local model in Ollama (`phi3:latest` by default, or any other `phi3` tag), pins its
digest and loads it, starts the gateway, runs the self-test and opens the console with the gateway key on your
clipboard. Later runs take seconds. `stop` stops the gateway, unloads the model from memory and stops Ollama only if
`boot` started it.

`boot.cmd` starts PowerShell with `-ExecutionPolicy Bypass` for that one run, so it also works where scripts are
blocked, including Windows PowerShell 5.1. Without it: `powershell -NoProfile -ExecutionPolicy Bypass -File .\boot.ps1`.

| Option (Windows / macOS, Linux) | What it does |
| --- | --- |
| `-Provider openai` / `--provider openai` | First run: where requests go (openai, anthropic, openrouter, gemini, mistral, groq, deepseek, ollama). |
| `-SlmModel phi3:mini` / `--slm-model phi3:mini` | The local model (default `phi3:latest`). |
| `-NoSlm` / `--no-slm` | Run without the local model. |
| `-Strict` / `--strict` | Refuse requests while the local model is unavailable, instead of continuing without it. |
| `-Pull` / `--pull` | Download the local model if it is missing. |
| `-Reconfigure` / `--reconfigure` | Choose the provider again and write a new config and gateway key. |
| `-Port 8090` / `--port 8090`, `-NoBrowser` / `--no-browser` | Another port; do not open the browser. |

`harpo status` shows what is running. Logs are in `.harpo/gateway.log`. An Ollama on another machine: set
`HARPO_OLLAMA_URL`. An install from before the rename keeps working: the first boot moves `.privateai/` to `.harpo/`
and `config/gateway.yaml` to `config/harpo.yaml`, and `PRIVATEAI_*` variables are still read.

## Using it from an application

```python
from openai import OpenAI

client = OpenAI(base_url="https://ai-gateway.internal/v1", api_key="harpo_...")  # gateway key, not the provider key
client.chat.completions.create(model="gpt-4.1", messages=[{"role": "user", "content": "..."}])
```

```python
from anthropic import Anthropic

client = Anthropic(base_url="https://ai-gateway.internal", api_key="harpo_...")
```

Optional request headers: `X-Harpo-Mode: relational|generic`, `X-Harpo-Context-Repair: true`,
`X-Harpo-Override: true` (send overridable blocked values redacted). Response headers:
`X-Harpo-Risk`, `X-Harpo-Redactions`, `X-Harpo-Mode`, `X-Harpo-Request-Id`.

From Python code there is also the SDK ([SDK.md](SDK.md)): `harpo_redact.sdk.Harpo` runs the same engine in your
process, with no server (scan, redact with the proxy's block and egress checks, documents, policy), and
`GatewayClient` drives a running gateway (its scan, documents, provider requests and control plane) with a gateway
key.

## OpenRouter

`harpo init` (or `up --provider openrouter`) writes two upstreams with one key: the OpenAI-style API for
most clients and the Anthropic-style API that Claude Code uses (`ANTHROPIC_BASE_URL` pointing at the gateway).

```yaml
upstreams:
  - name: openrouter
    style: openai
    base_url: https://openrouter.ai/api/v1
    api_key_env: OPENROUTER_API_KEY
    models: ["anthropic/claude-sonnet-5.5", "openai/gpt-6.1-sol", "google/gemini-3.8-flash", "*"]
    openrouter:
      data_collection: deny     # only providers that do not store prompts; clients cannot loosen it
      zdr: false                # true: zero-data-retention endpoints only (strictest, fewer models)
      # only: [anthropic, google-vertex]   # optional: a client's provider.only is narrowed to these
      # ignore: [some-provider]            # optional: always added to a client's provider.ignore
      # model_choosing_plugins: block      # refuse routers even when models allows "*"
    # headers: {HTTP-Referer: "https://intranet.example", X-Title: "Support desk"}   # app attribution
  - name: openrouter-messages
    style: anthropic
    base_url: https://openrouter.ai/api
    api_key_env: OPENROUTER_API_KEY
    models: ["*"]
    openrouter: {data_collection: deny, zdr: false}
```

The dialect is recognised from the `openrouter.ai` host (`upstreams[].dialect` overrides it). On every request the
gateway sets the routing policy (a request may make it stricter, never looser), checks the `models` fallback list
and any model-choosing plugin (auto router, fusion and the other routers) against the upstream's `models`, removes
`session_id`, `trace` and plugin location hints, and scans the text that plugins carry. Signed `reasoning_details`
are forwarded unchanged and checked by egress verification. The Providers page shows each upstream's routing policy
and the key's remaining credit; the connection check reads limits and usage only.

## Choose what matters

Every type has an action. **Redact** replaces the value with a placeholder, **block** stops the request with a `403`
that says why, and **allow** sends the value as written. Everything is redacted by default except plain dates.

**Keys are always redacted.** API keys, tokens, passwords and private keys (`SECRET`, `PRIVATE_KEY`) become placeholders
and the request goes on, so a coding agent that reads a `.env` keeps working and the key it found never leaves. No setting
changes that. A configuration file that asks to block them still loads; the keys are redacted and `check-config` and the
console name the line that no longer does anything. `allow` is refused, the live policy cannot name them, the whole
credential library always runs (the older `library`, `disabled_rules`, `natural_language` and `seed_phrases` switches
are ignored), so do the decoders that find keys inside base64, hex and escapes, and an override never changes them. If a
scan ever missed one, egress verification would block the request rather than let it out. Encoded data that hides a
value can be redacted or blocked, never allowed. A type you set to block still blocks what it matches, a key included: a
custom type whose pattern matches a token, or `ENCODED_DATA` around one.

### On the console

The **Policy** page (admin keys) shows every type with its action: switch it, add your own types, type a sample into
**Try it** to see exactly what would leave with the draft, then **Apply now**. The change reaches new requests at
once. It is saved to `policy.live_file` and laid over the configuration file, which stays as written; every gateway
process watches that file, so all workers pick a change up within two seconds, and it survives restarts. **Back to the
configuration** deletes the file. Without `policy.live_file` (or when its folder is read-only) the page still lets you
try changes and gives you the lines to paste into the configuration.

`init` and `up` write `live_file: policy.live.yaml` (relative paths sit next to the configuration file). The Docker
Compose file keeps it on a `policy` volume through `HARPO_POLICY__LIVE_FILE`. The audit log records each change
with the key that made it and what changed: types and custom type names, never terms or patterns. Changing the policy
takes an admin key; with `auth.enabled: false` (development only) every caller is an admin, so keep such a gateway on
127.0.0.1.

### In the configuration file

```yaml
policy:
  live_file: policy.live.yaml
  entities:                       # types you do not list keep their defaults
    EMAIL: {action: redact}
    US_SSN: {action: block, overridable: true}
    ORGANIZATION: {action: allow}
detection:
  custom_types:
    - name: EMPLOYEE_ID           # placeholders: [EMPLOYEE_ID_1], [EMPLOYEE_ID_2], ...
      description: Staff numbers from HR
      patterns: ['\bEMP-\d{6}\b']    # RE2: linear time, no lookarounds or backreferences
    - name: PROJECT
      terms: [Project Bluefin, Falcon]  # whole words, any case; "project_bluefin" and "PROJECT-BLUEFIN" too
      action: block               # redact (default) | block | allow (switched off)
  secrets:
    extra_rules_file: config/our-keys.toml   # more key formats, gitleaks TOML; checked when the gateway starts
```

A custom type's name is 2 to 40 capital letters, digits or underscores. It cannot be a built-in type, and it cannot make
placeholders that read as another type's (`EMAIL_ID` would print `[EMAIL_ID]`, which is also how `EMAIL` labels a second
address in generic mode; `PRIVATE` could print `[PRIVATE_KEY]`). A term needs a letter or a digit; its parts (split at
blanks, `_`, `.` and `-`) match with up to three separators between them or none, so `x-ray` also finds `X RAY` and
`xray`. A custom type is decided by its own action: `PROTECTED_TERM: allow` does not switch it off. Its findings are
counted, audited and blocked under its own name, also inside base64 and across line breaks; spellings of one term share
one placeholder. Terms are compiled into a single prefix tree, so thousands of them cost about as much as a handful.

Extra key rules use the gitleaks format: `id`, `regex`, and optionally `keywords`, `entropy`, `secretGroup` and
`allowlists`. A rule that does not compile in RE2, matches the empty string, or reuses a built-in id stops startup with
the rule's id in the message. A rule's own `allowlists` apply to that rule only; a file-wide `[allowlist]` is ignored,
because it would also exempt values from the built-in rules, and `check-config` names it.

```toml
[[rules]]
id = "acme-internal-token"
description = "Acme service tokens"
regex = '''acme_[A-Za-z0-9]{24}'''
keywords = ["acme_"]
```

### Detection families

What is looked for is switched per family; what happens to what is found is switched per type (above). The families
sit under twelve umbrellas: Credentials; Contact and payment; Identity numbers; Region packs; Forms, tables and
fields; Addresses and places; Names; Devices, networks and machine formats; Crypto; Hidden and encoded text; Your own
terms; Local model. [LIBRARY.md](LIBRARY.md) describes each family, the types it produces and its switch. The
console's **Detection** page lists them, the **Policy** page switches them, `GET /v1/system` returns them under
`detection.library` and `harpo check-config` prints them.

```yaml
detection:
  identifiers:
    opaque_codes: false     # codes no language writes are no longer looked for
    regions:
      us: false             # the US pack is off; US cue words still work
  ner:
    precision_filter: true  # drop what the model tags that cannot be a name
```

Families overlap on purpose: a Dutch VAT number is found by the Netherlands pack and by the EU pack, a value under a
"bsn" column by the table reader and by the cue words, so switching one family off does not always let a value
through. Credentials, and the decoders that find keys in escapes and encodings, have no switch (INV-11). Families
that run a model (`ner.enabled`, `slm.enabled`) are switched in the configuration file and take effect on restart;
the others also switch live, with `{"detectors": {"identifiers.addresses": false}}` on `PUT /v1/policy/live`.

### API

| Endpoint | Purpose |
|---|---|
| `GET /v1/policy/live` | Each type's action now and in the configuration, custom types, family switches, where changes are saved (admin). |
| `PUT /v1/policy/live` | Save and apply `{"entities": {...}, "custom_types": [...], "detectors": {...}}`; `custom_types: null` keeps the configuration's (admin). |
| `DELETE /v1/policy/live` | Back to the configuration file alone (admin). |
| `POST /v1/policy/preview` | `{"text": "...", "policy": {...}}`: what would leave under a draft. Nothing is sent, saved or recorded (admin). |

## Documents: PDF, Word, Excel, PowerPoint and text files

```bash
# a file in, a redacted file out (the name goes in a header: a URL is logged by every proxy on the way)
curl -s localhost:8080/v1/documents/redact -H "authorization: Bearer $KEY" -H "x-harpo-filename: contract.docx" \
  --data-binary @contract.docx -o contract.redacted.docx -D -        # headers carry risk, redaction count, verified: true

curl -s "localhost:8080/v1/documents/redact?response=json" ... --data-binary @sheet.xlsx   # text, counts and the file as base64
harpo redact-file report.pdf            # writes report.redacted.pdf next to it; --text prints the redacted text
```

From Python: `Harpo().redact_document("report.pdf")` in-process, or `GatewayClient(...).redact_document(...)` against a
gateway ([SDK.md](SDK.md#documents)).

| Format | What happens |
| --- | --- |
| Word, PowerPoint, Excel | Edited in place at the XML level, paragraph by paragraph, so formatting survives and a name split across runs is one name. Headers, footers, footnotes, comments, tracked-change text, text boxes, field codes, speaker notes, alt text, hidden sheets, formulas, defined names and document properties are all covered. Spreadsheet cells are scanned with their column header ("Name: Priya Raman"), so bare names in a table are found. Author names, thumbnails and custom XML are removed. |
| PDF | Every page is rendered, the matching characters are painted black, and the pages are written into a new image-only PDF: no text layer, fonts, annotations, form fields or metadata carry over, so nothing sits under a black box. The redacted text comes back separately (`response=json`). |
| txt, md, csv, tsv, json, xml, html, yaml, .env, logs, source files | Edited in place: quoting, line endings, byte-order marks and every untouched byte stay as they were. |

What cannot be inspected is refused, not passed through: pictures, scanned pages, pages with no text layer, embedded objects, macros, pivot caches, external links, encrypted and legacy (`.doc` `.xls` `.ppt`) files. `documents.images: blank` replaces pictures with blank ones and blanks uninspectable PDF pages instead of refusing. A redacted file is only returned after it was re-opened and re-scanned with nothing found.

Files are parsed in a **separate worker process** that gets an empty environment (no provider keys), memory and CPU limits, no permission to write files and, where the system allows it, no network. It never imports the scanner. This is defence in depth, not a sandbox: run the container with a read-only filesystem and egress only to your providers.

`documents.in_chat: true` makes files attached to chat requests (OpenAI `file` parts, Anthropic `document` blocks) get extracted, scanned together with the rest of the request, and forwarded as text; anything that cannot be inspected fails the request. It is off by default, which keeps the old behaviour of blocking attachments.

## Production deployment

1. Create gateway keys: `harpo hash-key --id support-team`. Give the key (it starts with `harpo_`) to the team
   and put only the printed SHA-256 in the config. A gateway key pasted into a prompt is redacted like any key.
2. Copy `config/harpo.example.yaml` to `config/harpo.yaml` and set keys, upstreams, model
   patterns, `allowed_hosts`, policy, custom types and registry terms. For console policy changes, give the
   gateway a writable `policy.live_file` (the Compose file uses a `policy` volume).
3. Provide provider keys as environment variables named in `api_key_env`.
4. Validate: `harpo check-config` (it reads `harpo.yaml` in the working directory or `config/harpo.yaml`, or the
   file in `--config` or `HARPO_CONFIG`). In production mode the gateway refuses to start without auth keys, HTTPS
   upstreams, provider keys, or with DEBUG logging.
5. Run with Docker Compose (`docker compose up -d --build`) or any orchestrator. On an interactive terminal
   `harpo serve` prints a short banner; a container or a log file gets none (`HARPO_NO_BANNER=1` also turns it off).
   The image runs as a non-root user with a read-only root filesystem, no capabilities and core dumps disabled.
6. Terminate TLS at your ingress or set `server.tls_certfile`/`tls_keyfile`; enable `server.hsts`.
7. Optional SLM layer: `docker compose --profile slm-setup run --rm ollama-pull` once, then
   `docker compose --profile slm up -d` and set `detection.slm.enabled: true`. Ollama sits on an
   internal network without internet access.

**How the image is checked:** CI builds it and runs `tools/docker_smoke.py` against both Compose files on every push
and before every release: the shipped example passes `check-config`, the containers come up healthy as a non-root
user on a read-only root filesystem, requests in both API styles (streamed too) reach a fake provider with
placeholders only, a live policy change holds across a restart and a recreated container, the logs carry none of the
values sent, and the gateway stops cleanly. Run it yourself with `python tools/docker_smoke.py`; `--local` runs the
same cycle with plain processes where Docker is not available. The tests never call real provider APIs or a real
Ollama (they use mocks of the wire formats), so try your provider before production: the `provider-smoke` workflow
(Actions tab, with your keys as repository secrets) or `python tools/provider_smoke.py --start` with the keys in your
environment.

## Operations

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | Liveness. |
| `GET /readyz` | Readiness: NER loaded, SLM reachable when it is required, provider keys present. |
| `GET /metrics` | Prometheus: requests by decision and risk, redactions by type, blocks by reason, stage latency, upstream status, SLM outcomes. Restrict to your monitoring network. |
| `GET /v1/policy` | Effective policy for clients and the console: actions, custom type names (no terms or patterns), no registry or allow terms. |
| `GET/PUT/DELETE /v1/policy/live` | The live policy behind the console's Policy page (admin). See [Choose what matters](#choose-what-matters). |
| `POST /v1/scan` | Redact without forwarding. Used by the console and for batch jobs. |

Every route, with its authorization, fields, headers and errors: [API.md](API.md).

Logs are JSON lines on stdout. The audit logger (`harpo.audit`) writes one line per API request
with request id, key id, route, model, decision, risk, reason codes, counts per type and timings.

Key rotation: add the new hash next to the old one, roll it out to clients, then remove the old hash.

## Development

```bash
pytest                       # ~4,400 cases: the redaction matrix, every credential rule and ID scheme, fuzzing, documents
ruff check src tests bench tools && ruff format --check src tests bench tools
mypy                         # strict
bandit -r src -c pyproject.toml
pip-audit -r requirements.lock
python bench/bench_pipeline.py --runs 200
python bench/bench_documents.py --runs 5
python bench/eval_false_positives.py corpus/*.txt      # false positives on public-domain prose
python tools/gen_secret_samples.py                     # regenerate tests/data/secret_samples.json after updating gitleaks.toml
```

The credential library is tested rule by rule: `tools/gen_secret_samples.py` generates a matching token for each
gitleaks rule and keeps it only if the library flags it under that rule, so the fixture proves keywords, entropy
and allowlists, not just the regex. Identifier tests generate thousands of valid values from each scheme's own
check-digit algorithm and corrupt them one digit at a time. A Hypothesis fuzz test mixes seeded values into random
Unicode and requires that none survive and that redacting twice changes nothing.

See `docs/CHANGELOG.md` for what changed in each release, the bugs the tests found, and measured results.

## Guarantees, tests and measurements

- **Security invariants** (`docs/INVARIANTS.md`, set in context by [THREAT_MODEL.md](THREAT_MODEL.md)): eleven named
  properties, such as "no raw blocked value crosses the boundary", "probabilistic components cannot authorize egress"
  and "keys are always redacted", each with the mechanism that enforces it and tests named after it, including sabotage
  tests that prove the safety nets fire.
- **Adapters** (`src/harpo_redact/adapters.py`) declare every surface of a provider request: scanned,
  identifier, stripped, provider-signed or unsupported. A coverage walk checks every string, key and large number
  of each request against that declaration, and **egress verification** rescans the whole sanitized body before
  it leaves. `harpo_redact.conformance` is the black-box suite an adapter must pass: a canary in every slot,
  unknown fields in every object, wrong types everywhere.
- **LeakBench** (`bench/leakbench.py`, results in `docs/LEAKBENCH.md`): 1,280 labelled values under 18 attack
  transformations in five languages, plus look-alike traps. With the Docker image's language models: 25 escapes
  (98.0%), 0.18% of check phrases damaged; with all five: 29 escapes (97.7%), 0.14%. `tests/test_leakbench.py` fails
  the build on any regression.
- **External benchmarks** (`bench/external`, results in `docs/EXTERNAL_BENCHMARKS.md`): OpenPII, Nemotron-PII,
  RedactionBench (with its own R-Score) and ProwlBench, public datasets Harpo was not built against, each cut into a
  dev half that fixes are made on and a holdout half that is only counted. Every round is recorded next to the 2.4.0
  baseline, never over it.
- **RegionBench** (`bench/regionbench`): the Dutch, US and EU identifiers of `docs/REGIONS.md` in 2,480 documents from
  62 templates, split into dev and holdout templates, with look-alikes that must come through unchanged.
- **Redaction matrix** (`tests/test_redaction_matrix.py`): 60 value types through 31 carriers each (JSON, CSV,
  YAML, XML, tool arguments and schemas, escapes, base64, hex, look-alikes, line breaks, spacing, right-to-left
  override, and six Anthropic content-block shapes), through the real proxy; an independent oracle decodes all that
  left. 1,860 cases and 276 near misses that must pass unchanged. Bugs it found are pinned one by one in
  `tests/test_matrix_regressions.py`.
- **Budgets**: scan time, decoded bytes and detections per request; past a budget the request is blocked.

## Known limits

- NER uses one model per language. The Docker image and the example config load English, German and, for every
  other language and script, the multilingual `xx_ent_wiki_sm`; the Dutch, French and Spanish models are opt-in,
  for their licences. Each chunk of text goes to the model for its language. Without a model for it, non-English
  text is read by the English model by default (`other_languages: english`, recall first), which damages ordinary
  nouns: LeakBench measures 28% of check phrases damaged that way, against 0.18% with the image's models and 0.14%
  with the Dutch, German, French and Spanish ones. Text in another script (Cyrillic, Greek, CJK, Arabic) gets NER
  only from a configured `other` model.
  Lowercase names, nicknames and names in leetspeak are still missed: they are all of LeakBench's remaining
  escapes (25 of 1,280 with the Docker image's models); the SLM layer is the answer for them.
- Over-redaction happens: some products and events ("Tour de France") can be marked as names.
  Add public terms to `policy.allow_terms`.
- Phone numbers must be valid for a configured region; fictional ranges such as US 555 numbers
  are not redacted. A national-format number split over two lines is rejoined only after a phone word ("phone:",
  "tel", "mobile").
- Shadow views go one level deep: a value that is both spaced and reversed, or spaced inside base64, is not read.
  Encoded content is decoded two levels deep (`detection.encoded_max_depth`).
- Field names count as cue words for the types listed in `detectors/fields.py`; a key that is itself data (has
  digits) never becomes a label, and names in structured data still depend on NER.
- Images, audio and binary files cannot be inspected: they are blocked (default) or dropped. The same goes for
  pictures and scanned pages inside documents; there is no OCR.
- Documents: a redacted PDF is image-only (not searchable, larger than the original). Shape names in Office files
  are only scanned for emails and long numbers, not names. A national-format phone number directly after another
  number ("Qty 12 020 794 6095") can be missed; international format is robust. Spreadsheets are scanned cell by
  cell (about 0.5 ms per cell, so 3,000 cells take ~2 s) and are refused above `documents.max_segments`.
  Redacted Office files were checked to open and render in LibreOffice and to re-read in python-docx, openpyxl and
  python-pptx; they were not opened in Microsoft Office. The worker process limits memory, CPU, file writes and
  (where the system allows) the network; it is not a sandbox with a syscall filter.
- Redaction is one-way by design. Replies contain placeholders, never the original values.
- Short fragments give NER little context: a name in a tool description such as "CRM of Priya Raman"
  can be missed. Emails, phones and other validated values in those fields are always caught.
- Not detected yet: special-category data (health conditions, religion, ethnicity, orientation), URLs as
  identifiers, and combinations of harmless facts that identify someone together (quasi-identifier clusters)
  beyond what the optional SLM reports.
- Response scanning (`policy.response_scan`) uses the deterministic layers on non-streamed answers only;
  streamed answers are marked `x-harpo-response-scan: not_scanned_stream`.
- Rate limits are per gateway process. Signed thinking blocks are forwarded unchanged (egress verification still
  scans them); the provider wrote them.
- Scanning JSON schemas can rewrite enum values that contain personal data, which changes the tool
  contract the model sees. Rejecting unknown fields (at any depth) means new provider parameters fail, with the
  field path in the error, until the adapter declares them (or `policy.unknown_fields: pass` scans them as text).
- The NER cache keeps offsets and types (no text) for up to 15 minutes in process memory. Set
  `detection.ner.cache_entries: 0` to turn it off.
