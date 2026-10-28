# Changelog

## 2.5.0

- **A Python SDK** (`harpo_redact.sdk`, [SDK.md](SDK.md)), the supported way to use Harpo from Python code, next to the
  command line and the gateway. `Harpo` (and `AsyncHarpo`) runs the gateway's own pipeline in your process:
  `scan()` is `POST /v1/scan`, `redact()` adds the proxy's block check and egress verification, `redact_document()`
  is the document service of `harpo redact-file`, `with_policy()` lays a policy over the configuration as the
  console's Policy page does; plus `verify()`, `scan_response()`, `trace()`, `status()` and `validate_config()`.
  `GatewayClient` (and `AsyncGatewayClient`) drives a running gateway behind its keys: scans, documents, requests
  to providers through it, and its control plane. Typed, frozen results that never print text; one exception
  hierarchy whose messages never quote the input; `py.typed`. The SDK detects, decides and redacts nothing itself:
  its tests hold a local scan, `harpo scan` and `POST /v1/scan` to the same result for the same input, and the
  invariants (keys always redacted, egress verification, no reverse map, no content in logs or errors) through it.
  Detection, policy and redaction are unchanged, so every benchmark result below stands.
- **Packaging.** `pyproject.toml` is the package contract (`pip install .`, `pip install -e .`, `python -m build`):
  authors, keywords, classifiers, the type marker, and a build that needs setuptools alone; the hash-pinned lock files
  stay the source of reproducible environments. 2.5.0 is installed from its tag on GitHub
  (`pip install "harpo-redact @ git+https://github.com/levilausberg-png/harpo-redact@v2.5.0"`) or from a clone; it is
  not published on PyPI. The build lock and the test lock no longer pin the `wheel` package, which nothing uses any
  more. The 19 console screenshots in `docs/assets` that no page linked to are gone (8 MB); the ones the README shows
  stay.
- **Security contact.** Private vulnerability reports go through GitHub's private vulnerability reporting, with
  Security.Harpo@gmail.com as the fallback ([SECURITY.md](../SECURITY.md)).
- **External benchmarks.** `bench/external` scores Harpo on public datasets it was not built against: OpenPII,
  Nemotron-PII, RedactionBench and ProwlBench. Gretel PII masking is supported too, but was not run: its files could not
  be fetched. The protocol comes before the results: the build is frozen and run blind, the labels that count were fixed
  before any result was seen, and datasets with one split are cut into dev and holdout halves, so no fix is tuned on the
  numbers it is judged by. Every run is recorded next to the 2.4.0 baseline, never over it, in
  `docs/EXTERNAL_BENCHMARKS.md`.
- **Secrets as people write them** (first hardening round, from ProwlBench's dev half). On the holdout half, F1 rose
  from 0.828 to 0.931 (recall 0.743 to 0.916, precision 0.934 to 0.946) with the false-alarm rate on hard negatives
  unchanged; on all 24,603 cases it is 0.934, where the best reproducible tool on ProwlBench's leaderboard scores
  0.883 and gitleaks 0.573.
  - A new layer reads credentials stated in words (`detectors/statements.py`): a credential-named identifier and its
    value however they are linked (`HF_TOKEN=`, `"apiKey": "…"`, "the HF_TOKEN is …", "rotate the API_KEY (…)",
    `define('DD_API_KEY', '…')`, `<password>…</password>`, SQL's `PASSWORD '…'`, `Some("…")`), "is" in seventeen
    languages and the words for password, key and token in some twenty-five, Chinese, Japanese and Korean included;
    "set X to Y", table rows and bold names.
  - Provider tokens at the end of a sentence are found (gitleaks ends a token at a blank or a quote, not at a full
    stop); Telegram bot tokens whole and in Bot API URLs, Hugging Face tokens with digits, Discord bot tokens, Azure
    account keys, and PGP private key blocks. `Basic <base64>` counts without the header's name in front.
  - Fewer false alarms: commands, interpolations and YAML tags as values; placeholders written together
    (`dummytoken`, `notarealkey`); generic matches whose name only hides a credential word (`libapi_hash`) or is
    about one (`token_url`, `api_version`, `cache_key`); keys and tokens shorter than eight characters; password
    hashes and version numbers; well-known default passwords on a local host; code as a value; and adjectives after
    "password is" in German, French, Spanish, Dutch, Italian and Portuguese. NER no longer reads code as names.
  - LeakBench is unchanged in all four configurations; 80 new tests, in phrasings of our own.
- **Personal data as people write it, in any language** (second hardening round, from the dev halves of OpenPII,
  Nemotron-PII and RedactionBench). On their holdout halves, the values fully removed rose from 50.1% to 74.4% on
  OpenPII, from 79.3% to 94.6% on Nemotron-PII and from 80.4% to 83.7% on RedactionBench, with collateral within a
  few tenths of a point of where it was. ProwlBench's F1 rose a little (0.934 to 0.938) and LeakBench did not move.
  - A layer for values named by the word in front of them (`detectors/cued.py`): the words for phone, card,
    national and tax numbers, identity documents, postcodes, accounts, bank codes, IBANs, vehicles, devices and PINs
    in some thirty languages, folded, inflected and read out of field names. After such a word the shape is enough,
    so a number that fails its checksum or comes from a country without a validator is protected too; amounts,
    dates, times, IP addresses and versions are not taken. Without a cue, the validators decide as before.
  - Postal addresses in their local grammar (`detectors/addresses.py`); names after greetings, honorifics and labels
    in some twenty-five languages, and Chinese, Japanese and Korean names (`detectors/names.py`); table cells typed
    by their column header in any of those languages (`detectors/fields.py`); and the machine formats that hold people
    (`detectors/formats.py`): HL7, passport machine-readable zones, AWS identities, user names in paths, LDAP and
    Windows events.
  - PINs, CVVs and door codes are secrets; passwords stated without "is" ("his password River45!", "passwords such
    as …"), command-line flags, environment name/value pairs, Redis `AUTH`, `net use` and `Key = <hex>` are found.
  - **Behaviour change:** a failed checksum after the word that names it ("SSN 000-74-4517", "card number 4103 9471
    7534 1115") is redacted now: a number one digit off still points to a person. Under a field that names nothing,
    the check decides as before, and the redaction matrix carries its checksum near misses that way.
  - A custom type names a value that a cue word only suggests (`[EMPLOYEE_ID_1]`, not `[ACCOUNT_ID_1]`), and egress
    verification counts each value once instead of once per rule that found it.
  - 294 new tests, in phrasings of our own.
- **Precision, Asian scripts, and the Dutch, US and EU library** (third hardening round, from the dev halves of
  OpenPII and RedactionBench and from RegionBench's dev templates). On the holdout halves the values fully removed
  rose from 74.4% to 76.6% on OpenPII, with Japanese, Korean and Chinese doubling or close to it (28.7%, 39.8% and
  45.4% to 59.0%, 68.1% and 69.2% on all of OpenPII), and from 94.6% to 94.8% on Nemotron-PII, while collateral fell
  from 13.2% to 5.1% and from 4.1% to 2.3%. RedactionBench's R-Score rose from 0.311 to 0.460 (holdout half 0.308 to
  0.442) as its false positives fell by three quarters; on its holdout half the share of values fully removed fell
  from 83.7% to 81.3%, nearly all of it digit runs in log documents
  ([docs/EXTERNAL_BENCHMARKS.md](EXTERNAL_BENCHMARKS.md) has the details). ProwlBench's F1 rose to 0.941 (0.939 on the holdout half), and LeakBench has the same or fewer
  escapes in every configuration and fewer false positives in every one that runs a model.
  - **The detection library** (`library.py`, [docs/LIBRARY.md](LIBRARY.md)): every detector sits under the kind of data
    it protects (Credentials; Contact and payment; Identity numbers; Region packs; Forms, tables and fields;
    Addresses and places; Names; Devices, networks and machine formats; Crypto; Hidden and encoded text; Your own
    terms; Local model), with one switch each. The console's Policy page switches them live (`detectors` on
    `PUT /v1/policy/live`, saved and audited like the rest of the live policy), the Detection page lists them,
    `/v1/system` returns them and `harpo check-config` prints them. Credentials and the decoders that find keys stay
    on whatever is switched (INV-11). New settings: `identifiers.regions.{nl,us,eu}`, `identifiers.table_fields`,
    `identifiers.machine_formats`, `identifiers.opaque_codes`, `ner.precision_filter`.
  - **Region packs** for the Netherlands (btw-identificatienummer with both checksums, loonheffingennummer), the United
    States (masked SSNs and their last four, ATIN, the printed Medicare MBI, USCIS receipt numbers, A-Numbers, I-94)
    and the EU (VAT numbers of every member state, the BIC, EU COVID certificate ids), and cue words for the rest of
    each region's identifiers: [docs/REGIONS.md](REGIONS.md) lists what there is and how each is found.
    RegionBench (`bench/regionbench/`) measures it on Dutch, US and EU documents: on its holdout templates
    `hardening-3` removes 98.2% of the Dutch, 96.4% of the US and 96.7% of the EU values (`hardening-2`: 79.2%, 83.6%
    and 79.4%; 2.4.0: 70.0%, 71.3% and 48.3%) and damages 5.5% of the look-alikes that must stay (18.2%).
  - **The R-Score.** RedactionBench's document score (the paper's §3.3) is implemented in
    `bench/external/rscore.py` and reported for every round: false positives cost, and so does half a contextual
    entity. `hardening-3` scores 0.460 on all 200 documents (0.442 on the holdout half), against 0.311 for
    `hardening-2` and 0.272 for 2.4.0.
  - **Fewer false positives.** The NER model's tags pass a precision filter: words the text also writes in lower case,
    terms a document defines for itself ("the Sponsor") and abbreviations it spells out, field labels, table headers,
    acronyms, code names, user agents, document titles ("Application to Register Permanent Residence", "Verklaring
    van Geschiktheid", "NEW PATIENT INTAKE FORM") and verbs that open an instruction ("Mark all that apply") are not
    names; a name found once is spread to other mentions only if it could be one. What the filter keeps: a full name
    lowered to slip past, also where the multilingual model reads it badly (it opens a sentence in a text that opens
    the others with a capital: "... rapport. sanne bakker stond in de notities"), and a name in leetspeak ("El1f").
    Name rules no longer take the next label of a form, a config file's step names or a struct's fields. Dates are
    not phone numbers, a version in a product token is not an IP address, a well-known Windows account ("S-1-5-18")
    or a service account ("deploy-bot") is not a person, and the name of a constant ("REDIS_PASSWORD") or the scheme
    of a stored hash ("{SSHA512}") is not a password. AWS principal ids (AIDA..., AROA...) are account identifiers
    now, not keys.
  - **More found.** Chinese, Japanese and Korean addresses and names read by the structure the scripts give them
    (`detectors/cjk.py`): the Japanese prefectures (都, 道, 府, 県), municipality chain and block numbers (3丁目4番5号),
    Korean road-name addresses (a road ending in 로 or 길, then its number) and lot numbers, the Chinese
    administrative hierarchy (省, 市, 区, 县) and roads, and names led by a common family name, single or compound
    (김, 佐藤, 欧阳, 东方), after a title, an honorific or a verb that takes a person; values glued to the script
    without a blank (a spacing view), postcodes, Korean resident registration numbers, Chinese resident identity
    numbers, transcript speakers, and names in Latin letters before a family name. Everywhere: user and
    account ids in URL paths, parameters and store keys, meeting links, the machine in a shell prompt,
    customer IAM roles, HL7 fields read by their shape, "Label   value" forms, a code's lower-case prefix
    ("usr-..."), digit groups written with " - ", transaction, acquirer reference and meeting cues, AWS key ids in
    their settings, grouped passcodes, and full names written in lower case to slip past.
  - **Opaque codes** (`detectors/opaque.py`, a new family): values that no language writes, told from words, names,
    acronyms and the identifiers of code by the letter pairs they use and where their case changes. A code in
    capitals standing in a sentence ("bring your MKWBOOYWMV", or glued to Chinese, Japanese or Korean text:
    "请携带FXJPIUZXKH") is an identifier, random letters in both cases ("votre tqoCmDcgjGqo") a password; hashes,
    masks, test strings and quoted data are left alone. The same test lets a cue word name a code in capitals alone
    ("license number CLYAFCWFNSIMY") and finds a password a few words after the word for it ("Passwort ... und
    BfnMnQaGjPdc", "password DVSqTIIxXPUq"). Also new: driving licences that open with the surname's five letters
    ("MORGA 753116 SM9IJ"), SSH public keys checked by the key type encoded in them (a string that only looks like a
    key is left), and form lines after an item number ("49.c. Middle Name ...").
  - **Bounded caches.** Two caches of the table and field reader grew with every new field label the traffic
    brought; every label cache now holds at most 4,096 entries.
  - **Speed.** With the default configuration a scan takes 1% to 6% longer than after round 2 on the benchmark
    documents, and 0.7 ms longer on a short prompt (8.5 ms on average on LeakBench); the deterministic layers alone
    7% to 18% longer. The new rules skip text they cannot apply to (text in ASCII holds no Chinese, Japanese or
    Korean; a case-insensitive word list is tried only where one of its first letters stands), and the normaliser
    passes text with nothing to normalise straight through.
  - 186 new tests, in phrasings of our own.
- **Release.** Pillow 13.0.0, certifi 2026.10.19, opentelemetry-api 1.45.1 and setuptools 84.2.1: `pip-audit` flagged
  Pillow 12.3.0 (eight advisories), certifi 2026.7.22, opentelemetry-api 1.45.0 (CVE-2026-114603) and setuptools
  84.0.0 (GHSA-xmj3-9gf7-h52w); nothing else in `requirements.lock` moved. The build tools use the same setuptools,
  and the test tools filelock 4.2.4 (six advisories against 4.1.1). The sdist carries what builds the wheel and no
  longer a partial copy of the tests that could not run without the rest of the repository (`MANIFEST.in`).
  `tools/third_party.py` regenerates the dependency table of `THIRD_PARTY_NOTICES.md`, as the file says (it only
  printed a pointer to instructions that did not exist; `--check` compares). A first boot without a terminal and
  without the provider's key says the gateway will not start without it, which is what happens (it said requests
  would fail). The README and the brand guide count the 231 key rules the gateway loads (221 from gitleaks, 10 of
  Harpo's own), not 226. The version is 2.5.0: 2.4.0 names the baseline every benchmark round is measured against.
- **Documentation.** The README starts with what Harpo is and what it does to a request: a quickstart for pip, Linux and
  macOS, Windows and Docker, a before-and-after from a real run, the benchmark table with its holdout halves, the
  architecture, and the limitations next to the numbers. The boot scripts' options moved to the guide
  ([One command: the boot scripts](GUIDE.md#one-command-the-boot-scripts)), whose LeakBench figures now match
  [LEAKBENCH.md](LEAKBENCH.md) and whose known limits name the language models the image loads (English, German and the
  multilingual model; it said Dutch, French and Spanish too, which are opt-in). The screenshots in `docs/assets` are
  retaken from 2.5.0, with a new demo loop, architecture diagram and social preview. [RELEASING.md](RELEASING.md)
  replaces `docs/LAUNCH.md`: how a release is made, without the launch plan. [FAQ.md](FAQ.md) answers the questions
  people ask first. [API.md](API.md) is the HTTP API reference, route by route, and [THREAT_MODEL.md](THREAT_MODEL.md)
  sets out what Harpo protects, on which assumptions, and what it does not. The benchmark pages no longer count Gretel
  PII masking among the datasets measured; it has not been run. A missing language model that neither the boot scripts
  nor the image install (Dutch, French, Spanish) is no longer said to come with them. The Claude Code integration page
  (and its card in the console) no longer says that keys in the files it reads block the request: they are redacted and
  the request goes on (INV-11). The SOTA verification record (`bench/external/sota-verification`) writes the machine's
  scratch folder as `$S` in its commands and provenance files; no recorded value changed. The README's before-and-after
  example holds an invented key, which `.gitleaks.toml` allows by value, like the console's sample keys.

## 2.4.0

PrivateAI Gateway is now Harpo
- **The new name** is Harpo, after Harpocrates, the god of silence and secrets, whose rose gave us *sub rosa*: what
  passes through stays in the room. The old name was generic and close to an existing company's. The repository,
  package and image are `harpo-redact`; the command is `harpo` (`harpo-redact` works too). The story, the marks, the
  colours and the voice are in `docs/BRAND.md`.
- **What changed with it:** the configuration file is `harpo.yaml`, and `harpo serve` finds it in the working directory
  or in `config/` without `--config`; variables are `HARPO_*`; headers `X-Harpo-*`; error details `error.harpo`;
  metrics `harpo_*`; local state `.harpo/`; the module `harpo_redact`. An install from before keeps working:
  `PRIVATEAI_*` variables are still read (and `check-config` names each one to rename), and the first boot moves
  `.privateai/` to `.harpo/` and `config/gateway.yaml` to `config/harpo.yaml`.
- **Three parts, named:** Harpo-Shield (the proxy and egress verification), Harpo-Mask (detection, the key rules and
  the policy) and Harpo-Vault (what never leaves: provider keys, gateway keys stored as hashes, placeholders with no
  reverse map). The console is arranged the same way: Shield, Mask, Vault, and Proof for the guarantees, LeakBench and
  the system.
- **The mark** is a harp whose strings are a gate, with a heraldic rose at its crown, on Midnight Slate; jade marks
  what Harpo silenced or verified, rose what it held back. Six variants (tile, plain, shield, monolith, blueprint,
  and an avatar for profile pictures) come from one geometry: `python tools/make_marks.py docs/assets/brand`. The
  new palette keeps AA contrast: axe-core finds no serious or critical issue on any of the 16 console pages, dark,
  light or mobile. Every screenshot, the demo GIF and the social preview are new.
- **A boot banner:** `harpo serve`, `harpo demo` and the boot scripts show the harp, the port, the upstreams and what
  is protected, on interactive terminals only. `HARPO_NO_BANNER=1` turns it off and `NO_COLOR` keeps it plain.
- **Gateway keys start with `harpo_`,** so Harpo recognises one wherever it turns up, and so can any secret scanner.

Ready to ship
- **Evidence that cannot skip.** CI installs Chromium and LibreOffice and sets
  `HARPO_REQUIRE=browser,libreoffice,models`, so the console's browser tests, the LibreOffice rendering of redacted
  Office files and the language-model tests fail there when a tool is missing, instead of skipping. On your machine
  they still skip.
- **The Docker image has a smoke test.** `tools/docker_smoke.py` builds the image and runs both Compose files: the
  shipped example passes `check-config`, the demo answers, and the hardened production file with a fake provider comes
  up healthy as uid 10001 on a read-only root filesystem, sends requests in both API styles (streamed too) with
  placeholders only, keeps a live policy change across a restart and a recreated container, writes none of the values
  to its logs and stops cleanly. CI runs it on every push; `--local` runs the same cycle without Docker. Writing it
  turned up a bug: `docker compose up` failed for anyone without `HARPO_KEY` set, because the optional chat service
  required it and Compose resolves variables even in profiles it does not start.
- **A release waits for CI.** A `v*` tag runs the whole ci workflow (the tests and the Docker smoke test) and a
  preflight (the tag names the package version, the changelog has it, no placeholder is left in the repository)
  before anything is published, and each publishing job gets only the permissions it needs.
- **Pinned:** every GitHub Action to a commit on its current release (Node 24 throughout), the base image to its
  digest (`python:3.12-slim-bookworm`), Open WebUI to a release instead of `:main`. The test, build and model
  dependencies are hash-locked like the runtime ones (`requirements-dev.lock`, `requirements-build.lock`,
  `requirements-models.lock`), and Dependabot watches the Actions, the Dockerfile and the Compose files.
- **The README claims what the evidence shows:** Harpo removes the protected values it detects; it does not promise
  that no raw value ever leaves. A Known limitations section sits next to the numbers, and "Found a bypass?" says
  where to report one and what happens to it.
- **Real providers, checked from the browser.** `tools/provider_smoke.py` puts a request, streaming, a tool call and
  its result, a provider error and a cancelled stream through Harpo to your providers. `--start` runs its own
  gateway, and the `provider-smoke` workflow runs it from the Actions tab with keys kept as repository secrets.
- **A release can start from the Actions tab** (Run workflow, version 2.4.0) as well as from a pushed tag. The image
  it pushes is pulled back and put through the Docker smoke test before the GitHub release is created, and when it
  starts from the Actions tab the tag itself is only created at the end, on the commit that passed.
- **A secret scan in CI.** gitleaks over the release finds 771 secret-shaped strings, every one invented on purpose:
  LeakBench's corpus, one sample per credential rule, the test cases, the console's sample prompts and the
  self-test's canaries. `.gitleaks.toml` allows exactly those; the new `secrets` job fails on anything else in the
  tree or anywhere in the git history, and `.github/secret_scanning.yml` keeps GitHub's push protection off the two
  fixture folders.
- **A plain `pip install` explains itself.** spaCy models are not on PyPI, so after `pip install harpo-redact` alone,
  `serve`, `scan`, `redact-file` and `check-config` name the missing model and its one-line, hash-checked install
  instead of failing with a traceback from spaCy (found by installing the release from scratch on Python 3.12).
- `tools/set_repo.py` fills in the repository, licensor and security contact one at a time, and `--check` lists what
  is left (the release workflow refuses to publish until nothing is). The package metadata uses an SPDX licence
  expression, ships LICENSE and NOTICE inside the wheel and links the repository.

Keys are always redacted (INV-11)
- **API keys, tokens, passwords and private keys are redacted, not blocked.** The request goes on with `[SECRET_1]` or
  `[PRIVATE_KEY_1]` where the key was, with a yellow advisory (`keys_redacted`). A coding agent that reads a `.env`
  keeps working, and a key it finds still never leaves. Before, the whole request was refused unless a key with
  permission overrode it.
- **Nothing switches this off.** A configuration that sets `SECRET` or `PRIVATE_KEY` to `block` (as the 2.3.0 example
  did) still loads: keys are redacted, and `check-config`, the startup log and the console's configuration analysis
  name the line that no longer does anything. `allow` is refused. `detection.secrets.library`, `disabled_rules`,
  `natural_language` and `seed_phrases` are ignored the same way: the whole credential library always runs. Egress
  verification still blocks a key that a scan missed.
- **Redacting needs exact spans, and several were not exact** (a block used to hide this): a recovery phrase took
  the wordlist word before it ("check the *file*. legal winner ..."); a private key whose header used look-alike
  letters ("ЕС PRIVATE KEY") was only caught by its "private key:" cue, leaving the key itself; a redacted value
  followed by the next URL query field (`api_key=[SECRET_1]&lang=en`) was flagged again at egress; and environment
  variable names (`DATABASE_PASSWORD`) were tagged as people by NER. All four are fixed, and the redaction matrix
  now expects all 19 credential kinds in all 31 carriers to arrive redacted: 2,136 cases pass.
- **LeakBench** is unchanged for the default image, the multilingual and the deterministic configuration. With
  English NER reading every language (the `ner` row), the false-positive rate went from 40.3% to 47.6%: requests
  that hold a key used to be blocked and were not counted; now they go out with the key redacted, and what English
  NER does to the Dutch, German, French and Spanish phrases in them counts. No escapes changed.
- **A key takes exactly its own characters**, found by sending the config files a coding agent reads (`.env`, YAML,
  JSON, INI, Kubernetes manifests, shell history, logs, curl commands) through the proxy:
  - a key at the end of a line took every line after it, because a value cut by a line break is rejoined. Now the
    next line ends the key when it starts something new (an assignment after an assignment, a shell prompt, a
    timestamp, a list item, a closing tag or fence, prose); a key cut in two is still redacted whole. Egress
    verification reads a placeholder at the end of a line the same way, so it does not glue `KEY=[SECRET_1]` to the
    next line and refuse the file;
  - a connection URL's password took its host with it (`app:pw@db.internal` was also read as an email address);
  - rules that capture the quotes around a password, or the YAML key in front of it, redacted those too
    (`"password": [SECRET_1]`, no longer JSON);
  - only the first entry of a Kubernetes Secret's `data:` was redacted, so egress verification found the second and
    refused the request; every entry is a secret and is now redacted;
  - a key in a URL query took the fields after it (`api_key=...&lang=en`).

  `tests/test_keys_always_redacted.py` sends each file through the scan, egress verification and the proxy.
- **An independent review before release** found more places where part of a key could leave (2.3.0 blocked these
  requests, so the inexact spans did no harm there), two ways to slow the scan, and one fail-open. All are fixed and
  each is pinned by a test:
  - `DB_PASSWORD=Tr0ub4dor&key=3xZq!` was cut at `&key=`: only a credential that is itself a URL query field ends
    at the next field. `postgres://app:P@ssw0rd!@db` ended the password at its first `@`, now at the last one
    before the host. A quoted value stopped at a blank or an escaped quote (`"Tr0ub4dor 3xZq"`, `"Tr0ub\"4dor"`);
    it runs to its closing quote. A password with blanks on a config line kept only its first word
    (`password: correct horse battery staple`); it takes the rest of the line, without a comment, when that looks
    like a password: a digit or a symbol, or four or more words that do not read as a sentence (a note such as
    `password: will send it later` is left alone).
  - A key cut by a line break lost its second half when that half looked like the start of something new
    (`{3x}Zq`, `ab=Zq9!`, a token's last letters). An assignment now starts a new entry only after another one.
  - Kubernetes Secrets: `kubectl get secret -o json` was not covered, values under 10 characters were skipped, and
    `kind: Secret` was read per document, so a ConfigMap in the same `List` lost its values. Secrets are read by
    structure now, per object, in YAML and JSON, `data` and `stringData`.
  - A key at the end of a line still took the next one after a heredoc's `EOF`, in a git diff, before ISO-8601, Go
    and syslog timestamps, a URL, a closing tag or code fence, `done` or `fi`, and between `.netrc` entries.
  - **Denial of service:** a manifest with hundreds of nested `data:` lines was rescanned after each of them (22 s
    for one request, from any client); it is one pass now. A custom term made of separators (`- - - … z`)
    backtracked exponentially (12 s on a line of 60 dashes); a term's letters and digits are matched with at most
    three separators between them, in linear time, and a term needs a letter or a digit.
  - **Fail-open:** `PROTECTED_TERM: allow` switched off every custom type, even one set to block, in the scan and at
    egress. A custom type follows its own action only.
  - **INV-11:** a top-level `[allowlist]` in `extra_rules_file` applied to every rule, built-in ones included (npm
    and GitLab tokens went out raw); it is ignored, and `check-config` names it. `detection.encoded_max_depth: 0`
    and `decode_escapes: false` stopped keys inside base64 and escapes being found; both have a floor now, with a
    notice. The invariant's wording says what a policy can still do: a type set to block (a custom type whose
    pattern matches a token, `ENCODED_DATA` around one) still blocks.
  - The diagnostics bundle, meant for issue reports, held custom types' terms and patterns; it holds counts now.
  - Two workers saving the live policy at the same moment could leave one on its own policy indefinitely: it took
    the other's file for its own. A save records the file it wrote, before the rename.
  - An e-mail address in a URL with a 32-letter scheme was skipped by the e-mail rule but not taken by the URL rule;
    the two agree now. A custom type's name is also refused when one of its own placeholders could read as a
    built-in type: `PRIVATE` could print `[PRIVATE_KEY]` once its letter labels reach `KEY`, and `US` `[US_SSN]`.

Choose what matters, add your own
- **The console's Policy page is an editor.** Switch any type between redact, block and allow, try a sample against
  the draft, and apply it. Changes go to `policy.live_file`, are laid over the configuration file (which stays as
  written), reach every worker within two seconds through a file watch, and survive restarts. Admin keys only; the
  audit log names the key and what changed, never terms or patterns. Without a writable live file the page offers
  the YAML instead. API: `GET/PUT/DELETE /v1/policy/live`, `POST /v1/policy/preview`.
- **Custom types** (`detection.custom_types`): a name, exact terms and RE2 patterns, and an action. Placeholders
  carry the name (`[EMPLOYEE_ID_1]`); counts, reasons, metrics, the detector lab, documents, response scanning and
  egress verification use it; its action applies inside base64 and across line breaks. Names are checked so that no
  placeholder can read as another type's. Terms compile into one prefix tree (5,000 terms scan in milliseconds).
- **Extra key rules are documented and checked as configuration.** `detection.secrets.extra_rules_file` (gitleaks
  TOML) existed but was undocumented: a missing file or a pattern RE2 rejects stopped startup with a bare Python error,
  and a rule reusing a built-in id was loaded twice. Now `check-config` and startup name the rule and the problem:
  missing file, invalid TOML, a regex RE2 cannot compile, a regex that matches the empty string, a reused id.
- `init`, `up` and the demo set `policy.live_file`; the Compose file keeps it on a `policy` volume
  (`HARPO_POLICY__LIVE_FILE`). A relative `live_file` sits next to the configuration file.

Security fixes (these affect 2.3.0; upgrade)
- **Leak:** a gateway key pasted into a prompt without a label ("my key is pag_...") was not recognised and went out.
  Gateway keys, the `pag_` and `pk-` ones from before the rename included, are now redacted like any other key.
- **Leak:** a password followed by an ellipsis (`DB_PASSWORD=Tr0ub4dor...`) was taken for a documentation stub such
  as `sk-...` and sent. Only a stub (a prefix, then dots) counts as documentation now.
- **Leak:** an IBAN written directly after something shaped like the start of one ("Ref AB12 NL91 ABNA 0417 1643 00")
  was not detected and went out unredacted. Found by the fuzzer. Every place an IBAN can start is now tried.
- **Leak:** a password in a connection URL without a user name (`redis://:password@cache:6379/0`, the form Redis
  uses) was not detected.
- **Denial of service:** a long token followed by an "@" took quadratic time in the leetspeak-email view: 60,000
  characters took 8.5 s to scan, now 0.1 s. Found when the regex robustness test was extended to every module.
- **False block:** a template variable as a connection-URL password (`postgres://app:${POSTGRES_PASSWORD}@db`) was
  reported as a secret and the request was blocked.

OpenRouter
- Both of OpenRouter's APIs: OpenAI-style (`/api/v1/chat/completions`) and Anthropic-style (`/api/v1/messages`, the one
  Claude Code uses). `up --provider openrouter` and `init` configure both; `/api/v1/...` paths are accepted as aliases.
- Provider routing is enforced: prompt storage denied by default (`provider.data_collection: deny`), optional zero
  data retention (`openrouter.zdr`), `only` and `ignore` lists. A client can tighten routing, never loosen it.
- Fallback model lists and model-choosing plugins (auto router, fusion and the other routers) are checked against the
  upstream's allowed models; `session_id` and `trace` are removed; plugin text is scanned and `user_location`
  stripped; signed `reasoning_details` are forwarded unchanged and verified at egress.
- Bearer auth, static headers per upstream (`upstreams[].headers`, for app attribution; reserved headers refused),
  upstream model lists (cached), and a key check that shows credit limits and usage only.
- Newer Anthropic fields: `output_config` (its schema is scanned), `cache_control`, `speed`, `inference_geo`.
- Configuration analysis flags routing that allows prompt storage or lacks zero retention; the console shows each
  upstream's routing policy and OpenRouter credit, and the setup wizard asks for the routing choice.

Redaction hardening: the redaction matrix
- `tests/test_redaction_matrix.py` puts 60 protected value types (contact and payment data, 23 national and tax
  IDs, crypto, network and device identifiers, dates of birth, addresses, a protected term and 19 kinds of
  credential) through 31 carriers each, against the real proxy: quotes, Markdown, JSON as text, double-encoded and
  unicode-escaped, XML, CSV, YAML, tool-call arguments, schema defaults, object keys, URLs, percent and HTML escapes,
  base64, base64 JSON, hex, zero-width and full-width characters, look-alikes, line breaks inside the value,
  spacing, a right-to-left override, and six Anthropic shapes (system blocks, tool_use input objects, tool results,
  text documents, input-schema examples, name/value records). An oracle that shares no code with the detectors
  decodes everything that left and looks for any large piece of the value. 276 near misses (failed checksums,
  missing cues, public keys, documentation placeholders) must arrive unchanged.
- First run: 281 of 1,500 cases failed: 226 leaks, 41 false blocks, 14 values caught only by egress verification.
  Now all 1,860 cases and 276 near misses pass. What changed:
  - **Field names are cues.** A value is checked against the field it sits in (`detectors/fields.py`): JSON leaves
    and keys carry the nearest meaningful key ("298163871" under `bsn`, a schema `default` under its property),
    name/value records use their sibling name, and table cells their column header or row label (CSV, TSV,
    semicolons, Markdown, HTML). Words that change the meaning cancel the cue (`passport_expiry`, `password_hint`,
    `key_id`), and the value must still pass the type's own check.
  - **Cue words in every shape:** `nhs_number`, `socialInsuranceNumber`, `Steuer-ID`; quotes, markup, `|`,
    parentheticals ("(DD-MM-YYYY)", "(base64)") and short phrases ("passport number on file is ...") between cue
    and value.
  - **Encodings:** hex (contiguous and hex-dump), base64 runs from 8 characters, the cue window before an encoded
    value from 24 to 64 characters, JSON inside a JSON string. Base64 of readable text is judged by what it decodes
    to, so "token payload: <base64 JSON with an email>" is redacted, not blocked as an API key.
  - **Shadow views:** text under a right-to-left override read in display order; look-alike letters next to digits
    ("1АА", "арі03") read as Latin without touching Russian or Greek prose; spaced values with word gaps and
    punctuation; values broken inside a word ("14 Mar|ch 1985"); protected terms and seed phrases across any line
    break; national phone numbers across a break only after a phone word; a secret cut by a break redacted in full.
  - **Credentials:** a credential right after its cue word ("password Tr0ub4dor&3x") when it looks generated; HTML
    table cells; a token ending at `&` in a URL query; documentation placeholders (`ghp_xxxx...`,
    `YOUR_ACCESS_KEY_ID`) and stop words for every rule (the Terraform rule blocked `"password": "required"`).
  - **Keys with digits** ("bc1q...", "nl91abna...") are scanned with the request instead of being caught late by
    egress verification.
- Precision: a new suite of harmless structured data (package manifests, compose files, schemas, API responses,
  CSV, metrics tables, logs, code, `.env` templates; as text and as tool arguments) must pass unchanged. LeakBench is
  unchanged: no new escapes, the same false-positive rate. Typical prose scans about 10% slower; every hostile input
  tested scans in linear time.
- Every bug above is pinned by a minimal test in `tests/test_matrix_regressions.py`, including a source-hygiene test
  (no raw invisible or bidirectional characters in source, after bandit caught one in a docstring).

Also
- NER no longer tags snake_case field names ("date_of_birth", "customer_id", "created_at") as people, places or
  organisations; it was seen damaging CSV headers. The model never tagged snake_case usernames in those checks.
- The egress preview accepts the API styles `openai` and `anthropic` only (adapter names were accepted and refused).
- The detector lab shows the new views and a "Structured and disguised" sample.
- The playground says why a request that goes out was changed ("2 keys or passwords were replaced with a placeholder
  before sending"), along with the other advisories: hidden characters, mixed scripts, placeholder-heavy text.
- Long values in the console's key/value rows wrap under their label instead of being drawn over it (seen on
  Security guarantees at about 1,100 px wide).
- `ruff check src tests bench tools`, the CI lint step, passes again: data tables in `bench/` and `tools/` may use
  long lines, and the few real findings there are fixed.

Tests: 3,816 (2.3.0 had about 1,300), including the console's browser tests and the LibreOffice rendering tests: all
pass on Python 3.12 with the hash-pinned CI toolchain, one only when not run as root (it needs a folder the gateway
cannot write to). ruff, mypy (strict), bandit and pip-audit report nothing.

## 2.3.0

Security architecture
- Provider adapters declare every request surface; a coverage walk rejects (or, with `unknown_fields: pass`, scans)
  anything undeclared at any depth, including JSON keys. Fixed on the way: assistant `refusal` and `annotations`,
  OpenAI `extra_body` and custom-tool grammars, Anthropic `output_format` schemas and extra `metadata` fields were
  forwarded unscanned; extra fields on signed thinking blocks are refused.
- Egress verification: the sanitized body is rescanned before it leaves; a hit blocks (`egress_verification`).
- Adapter conformance suite (`privateai_gateway.conformance`). It found 48 server errors on wrong types in the
  Anthropic adapter (now 400s) and a fail-closed catch-all now turns any unexpected shape into a 400.
- Ten named security invariants with tests (`docs/INVARIANTS.md`), including sabotage tests. New: PDF redaction
  boxes are checked to be opaque in the encoded page before release.
- Provider redirects become 502s; nothing from a redirect reaches the client.

Detection
- Per-language NER (Dutch, German, French, Spanish models) with language detection per chunk; other scripts go only
  to a configured multilingual model. Code-shaped NER spans ("SKU-88213-XL") are dropped; all-caps names in normal
  text are read in title case.
- Shadow views for values split over lines, spelled out (five languages) or spaced one by one, and leetspeak
  emails; short base64 (12+ characters) with the cue before it; Cyrillic and Greek look-alikes folded inside
  mixed-script words.
- Seed-phrase false positive fixed: repeated words ("word word word ...") could pass the checksum by chance.
- SLM hardening: random per-request frame, exact schema, word-boundary spans, deterministic post-validation,
  input/answer/concurrency budgets, optional model digest pin; new failure states follow `on_failure`.

One-command start and stop
- `boot.cmd` / `boot.ps1` (Windows; the .cmd bypasses the execution policy for that run, also on PowerShell 5.1) and
  `boot.sh` (macOS, Linux) set everything up on the first run and start in seconds after; `stop.*` stop it again.
- `privateai-gateway up | down | status` do the work on every platform: hash-checked detection models, provider choice
  and key (owner-only `.privateai/.env`), the local model through Ollama (phi3:latest by default; started only if
  needed, digest pinned, loaded ahead of the first request), background start, readiness wait, self-test, the console
  with the gateway key on the clipboard. `down` stops only what `up` started and unloads the model.
- A `.gitignore`, so local state and keys are never committed.

Control plane: operations
- Detector lab (Configure > Detector lab, `POST /v1/lab/detect`): a sample through each detection stage separately,
  with the normalized view, shadow views (decoded escapes, joined lines, compacted runs, leetspeak) and decoded
  encoded values. Transient: nothing is stored, logged or counted.
- Self-test center (`POST /v1/selftest/suites`): gateway, detection, secrets, egress, adapters, security headers,
  configuration, documents, providers and local-model suites, each labelled local logic, live dependency or config.
- Attention center and posture timeline (`GET /v1/attention`): actionable conditions only, re-evaluated every 15 s;
  dismissed items stay hidden until their condition changes. In memory.
- Live event stream (`GET /v1/events`, server-sent events): Activity rows and Overview update as requests happen;
  pausing holds rows still and counts what arrives. Polling remains the fallback.
- Activity: saved views, sidebar favorites, column choice and density, CSV and JSON export, and a context menu
  (right-click, Shift+F10 or the Menu key). Observability and LeakBench export too. All metadata only.
- Ambient field and pointer light: a very slow background drift and a soft light on a few surfaces; off for touch,
  reduced motion and small screens, paused when the tab is hidden.
- A five-step product tour, offered once and remembered when finished or dismissed.

Control plane: investigation and assurance
- Live request path: the Overview topology animates real traffic between polls (blocked requests stop at Policy) and
  is still otherwise; its stages open their pages.
- Linked charts: one crosshair across a page's charts; clicking a point opens Activity filtered to that time slice
  (`#/activity?from=…&to=…`), keyboard-operable.
- Playground workspace: drag-resizable panes (arrow keys, double-click to reset) and Split / Focus input / Focus
  egress, remembered as UI preferences only.
- Configuration security analysis (`GET /v1/config/analysis`): required, recommended and informational findings, each
  with its setting, current and suggested value and invariant; one click opens the key in the YAML editor.
- Adapter surface explorer: every declared request field per adapter, with its handling and invariant.
- Document assurance receipts: content-free JSON with the released file's SHA-256 (tested to match the download).
- Diagnostic bundle (`GET /v1/diagnostics`): content-free, lists what it includes and excludes, previewed before download.
- Fixed: the setup wizard misread the self-test result and could show READY with a failed check.

Control plane polish
- Setup wizard (Configure > Setup): nine steps with secure defaults; the draft is validated by the gateway's own loader
  and checked against the running gateway (readiness, models, secret rules, live self-test, provider). The generated
  key exists only in page memory; nothing is saved or applied.
- Request trace: a content-free timing waterfall per request (normalization, identifiers and secrets, NER, SLM, policy,
  egress verification, provider, response scan), deep links (`#/activity/request/<id>`), `[`/`]` navigation and a JSON
  receipt. New recorded fields: `egress`, `egress_ms`, `response_scan`.
- Activity: URL-backed filters, removable filter chips, pause and resume for the live tail.
- Command palette 2.0 (fuzzy matching, recents, actions, providers, entity types, invariants), a `?` shortcut sheet,
  `G` + letter navigation, `J`/`K`, `/`, `⌘,`; breadcrumbs follow deep links.
- Motion tokens, View Transitions on the page area, reduced-motion, reduced-transparency and high-contrast modes;
  one whitelisted preference store (`privateai.ui.v1`).
- Accessibility: axe-core finds no serious or critical issues on all 15 pages (dark, light, mobile); text tokens raised
  to WCAG AA; dialogs trap and return focus; skip link; named scrollable regions.
- Status pages ping the local SLM fresh, so a stopped model is reported at once; `demo --slm URL` attaches one.
- Browser regression tests: no route scrolls sideways at 320-1920 px; palette; trace deep link; storage holds
  preferences only.

Control plane
- The console is rebuilt as a 14-page control plane in four groups: Operate (Overview, Playground, Documents,
  Activity), Connect (Integrations, Providers and adapters), Configure (Policy, Detection, Access, Configuration) and
  Assure (Observability, LeakBench, Security guarantees, System). Modular ES modules and token-based styles, no
  external requests, strict CSP unchanged.
- `POST /v1/egress/preview`: the exact sanitized request, computed by the proxy's own code path and not sent.
- `POST /v1/selftest`: canaries through the real sanitize path, reported per invariant; nothing is sent.
- Admin APIs: `/v1/system`, `/v1/providers` and connection checks, `/v1/keys` and key generation (shown once, never
  stored), `/v1/config/effective` (secrets reduced to counts) and `/v1/config/validate` (the real loader, with YAML
  line numbers; validates only).
- Verified responsive: no route scrolls sideways at 390 or 834 px wide; every page captured and inspected at 1920,
  1440, 1280, tablet and mobile, in dark and light.

Console, onboarding and integrations
- Redesigned console: live overview, side-by-side playground with streaming replies, documents, integrations,
  activity and policy views, command palette, light and dark themes, mobile layout. No external requests.
- `privateai-gateway demo` (gateway plus a fake provider, no accounts) and `privateai-gateway init` (provider presets,
  a gateway key, a config that passes the production guards).
- `GET /v1/models` (OpenAI and Anthropic formats), `POST /v1/messages/count_tokens`, `GET /v1/stats` (content-free,
  scoped per key; `admin` keys see all).
- 33 documented integrations; 9 verified end to end with the real client libraries (`tools/verify_integrations.sh`).
- The fake provider's Anthropic stream now has the `usage` fields SDKs need.
- CamelCase code words (`AccessDenied`, `PowerPoint`) are no longer tagged as organizations.

Licensing and distribution
- Licensed under Apache-2.0 (open source, with a patent grant); NOTICE file added. See LICENSING.md.
- The Docker image ships only MIT-licensed spaCy models (English, German, multilingual fallback); Dutch (CC BY-SA),
  French (LGPL-LR) and Spanish (GPL-3.0) are opt-in. LeakBench: the default set has the best recall (98.0%).
- Release workflow (multi-arch image on GHCR, SBOM, checksums), issue forms, Code of Conduct, Dependabot.

Operations
- Per-request budgets: `server.max_scan_ms`, `max_decoded_bytes`, `max_entities`.
- Optional response scanning (`policy.response_scan: report | redact`).
- Key expiry (`expires_at`) and per-key rate limits (`requests_per_minute`, 429 with Retry-After).
- LeakBench v1 and a regression gate; SBOM generator (`tools/make_sbom.py`); CI workflow; SECURITY.md and
  CONTRIBUTING.md; language models pinned by checksum in the Docker image.
- Test fixture fix: `make_pipeline` ignored the NER settings, so tests that turned NER off still ran it.

## 2.2.0: exhaustive library testing and document redaction

### 1. Library hardening

**How the libraries are tested now** (1,106 test cases in total, up from 178; most are parametrized):

| Area | Cases | What it proves |
| --- | --- | --- |
| Credential rules (`test_secret_rules_exhaustive.py`) | 479 | `tools/gen_secret_samples.py` generates a matching token for each gitleaks rule and keeps it only if the library flags it under that rule: 219 of 221 rules have a generated sample, 2 are hand-written. Each rule is tested bare, inside a message, in 11 wrappers (code fence, quote, comment, CRLF, indent, HTML, parentheses, brackets, braces, list, XML), and end to end (the secret is gone from the redacted text). |
| Identifiers (`test_identifiers_exhaustive.py`) | 161 | 40 generated valid values for each of 15 national-ID schemes in every format, lowercase variants, one-digit corruptions rejected, cue words required where formats collide; 9 card brands compact/spaced/dashed plus wrong-digit variants; 55+ IBAN examples in 4 spellings; every country's example phone number; 11 email forms in 8 wrappers; Bitcoin and Ethereum addresses; VIN, IMEI, MAC; routing numbers. |
| Robustness (`test_robustness.py`) | 213 | Every regex in the code base attacked with 32 hostile inputs (CPU-time bound); lone surrogates; 20 obfuscated forms (full-width and Arabic-Indic digits, zero-width characters, double URL-encoding, HTML entities, `\u0040`); 20 look-alikes (UUIDs, hashes, ISBNs, tracking numbers) that must not be flagged; 300,000 characters of public-domain prose; a Hypothesis fuzz test (400 examples x 11 seeded value types mixed into random Unicode: none may survive, and redacting twice changes nothing). |

**False positives**, `bench/eval_false_positives.py` on 11.7 million characters of public-domain English prose:
no secret, card, IBAN, phone or national-ID hits. The 11 high-risk hits are Project Gutenberg's own header text (3 real
email addresses, 3 real postal addresses) and a fictional character's date of birth in a novel (5).

**Bugs these tests found, now fixed:**

- Full-width and Arabic-Indic digits hid card numbers; all Unicode decimal digits are now folded to ASCII.
- Lone surrogate characters (JSON allows `"\ud800"`) could not be encoded; they are now replaced one for one.
- Double-encoded emails (`%2540`) were missed; escapes are decoded in two rounds.
- Lowercase NINO, DNI, NIE, PAN, CURP and codice fiscale values were missed.
- IBANs with dashes, Cisco-style dotted MAC addresses, EINs without a hyphen and emails with an IP-literal domain were missed.
- Documentation keys (`AKIAIOSFODNN7EXAMPLE`) and code references (`os.environ["X"]`, `getenv("X")`) were flagged as secrets.
- "A belaying pin is found too large" (Moby-Dick) was flagged as a PIN; a PIN cue now needs a digit.
- A reference code `INV-2026-000123` was read as a phone number.
- **Found by the fuzzer:** two card numbers separated by a stray digit group: the first swallowed the start of the second and the second **leaked**. Cards are now found by sliding a window over whole chains of digit groups.
- **Found by the fuzzer:** a phone number directly followed by a card or other digits was not detected at all (a **leak**). Strongly validated entities are now masked from the phone finder, and international numbers are matched as anchored windows.
- The sample generator was not reproducible (set iteration order), which made a pinned test fragile. It now fixes the hash seed; three runs under different seeds give the same file.

**Unexplained:** in the first run of the new suite, two tests failed once and have not failed since, in five reruns, 20 in-process repeats, five fuzz seeds, under CPU contention and under a 600 MB memory cap: a wrapper test for the credential rules and a wall-clock ReDoS timing check. The timing check now uses CPU time, best of two. The wrapper failure was not explained; the test stays.

**Known gap, documented:** 101 gitleaks rules accept a comma as the assignment operator, so a second, trailing comma
(`keys: datadog <key>, and more`) can make a rule miss. A national-format phone number directly after another number
(`Qty 12 020 794 6095`) can be missed; international format is robust.

### 2. Document redaction

PDF, Word, Excel, PowerPoint and text files, through `POST /v1/documents/redact`, `privateai-gateway redact-file`, and
(opt-in, `documents.in_chat`) as attachments in chat requests.

- **Office files** are edited in place at the XML level, paragraph by paragraph, so formatting survives and a name split
  across runs is one name. Covered: body, tables, headers, footers, footnotes, comments, tracked-change text, text boxes,
  field codes and hyperlink targets, speaker notes, alt text, hidden sheets, formulas, defined names, table columns,
  document properties. Spreadsheet cells are scanned with their column header as context. Authors, thumbnails and custom
  XML are removed. Pictures, embedded objects, macros, pivot caches, external links, encrypted and legacy files are
  refused (`documents.images: blank` replaces pictures with blank ones).
- **PDF** pages are rendered, the matching characters painted black, and the pages written into a new image-only PDF: no
  text layer, fonts, annotations, form fields or metadata carry over.
- **Verification:** a redacted file is re-opened and re-scanned; if anything detectable remains it is not released.
- **Isolation:** files are parsed in a separate worker process with an empty environment, memory and CPU caps, no
  permission to write files and, where the system allows it, no network. Overload is turned away (503) instead of queued
  without bound. This is defence in depth, not a syscall-filtered sandbox.

**Checked by:** python-docx, openpyxl, python-pptx and pdfium re-reading every output; a search of every decompressed part
for every seeded value; a pixel check that each sensitive value's original position is solid black in the redacted PDF
(including a rotated page); LibreOffice converting the redacted Word, Excel and PowerPoint files (they open and render, the
data is absent, the placeholders are visible); hostile files (zip bomb, path traversal, entity declarations, macros,
embedded objects, legacy and encrypted files, truncated PDFs); worker isolation (empty environment, no file writes,
address-space and CPU caps, a stuck worker is killed, a crashed worker is reported); a real server run with `curl`.
Not checked: Microsoft Office itself, a Docker build, real providers.

**Latency**, `bench/bench_documents.py`, cold (NER cache off), unique content, one machine:

| Document | p50 |
| --- | --- |
| Worker start | 37 ms |
| Word, 100 paragraphs (38 KB) | 0.65 s |
| Excel, 200 rows x 5 columns (1,006 cells) | 0.72 s |
| PowerPoint, 10 slides | 0.16 s |
| PDF, 5 pages | 0.49 s |
| PDF, 20 pages | 1.42 s |
| CSV, 1,000 rows x 3 columns (3,003 cells) | 1.78 s |
| Plain text, 100 KB | 1.29 s |

### 3. Pipeline latency

`bench/bench_pipeline.py --runs 200`, 4 KB prompt: deterministic layers p95 13.6 ms, with NER 72.5 ms, full proxy path
**95.1 ms** against the 100 ms target (82.1 ms before the detector changes in this release). It still clears the target,
with little headroom; p95 over 50 runs varies by roughly 10 ms from run to run. A 10-turn chat request: 31.5 ms without
the NER cache, 11.3 ms with it.

### 4. Dependencies

New runtime dependencies: `lxml 6.1.3`, `pypdfium2 5.6.0`, `Pillow 12.3.0` (all have arm64 wheels). `pip-audit` flagged
Pillow 12.1.1 (ten advisories) and lxml 6.0.2 (one) when these were first added; both were upgraded, the lock file was
regenerated (62 hashed pins) and `pip-audit` now reports no known vulnerabilities.

### 5. Other changes

- `POST /v1/documents/redact` takes the file name in a header (`X-PrivateAI-Filename`, percent-encoded), never in the
  URL, so proxies in front of the gateway cannot log it. File names are scanned like any other text.
- `/v1/policy` lists the document settings; new `documents.*` configuration section.
- Version 2.2.0.
