# FAQ

Short answers about Harpo 2.5.0. The details are in the [README](../README.md), the [guide](GUIDE.md) and the pages
linked below.

### What is Harpo?

An open-source, self-hosted privacy firewall for AI traffic. It is a gateway between your applications and LLM
providers: it detects secrets, credentials, personal data and sensitive identifiers in each request on your own
infrastructure, replaces them with placeholders such as `[PERSON_1]` or `[SECRET_1]`, and scans the exact outgoing
request again before it leaves. Apps keep their SDK and change one base URL; Python code can also call Harpo
directly, through its SDK. Apache-2.0; Python package `harpo-redact`, installed from its GitHub release tag (it is
not on PyPI).

### Can I use it from Python code, without running the gateway?

Yes. The SDK ([SDK.md](SDK.md)) runs the gateway's own engine in your process: `Harpo().scan(text)` for findings and
a verdict, `redact(text)` for the text as the gateway would let it leave (the same block check and egress
verification), `redact_document(path)` for files, `with_policy(...)` for your own types and actions. `GatewayClient`
drives a running gateway instead, behind its keys. It is the same implementation, not a second one: for the same
input, a local scan and the gateway's give the same result. Install it with
`pip install "harpo-redact @ git+https://github.com/levilausberg-png/harpo-redact@v2.5.0"` or from a clone
(`python -m pip install .`).

### Why not Microsoft Presidio?

Presidio is a widely used PII detection and anonymization toolkit: you call it from your code, or run its analyzer and
anonymizer services, and decide what to do with the result. Harpo is first a different shape: a gateway in the request
path (its Python SDK runs the same engine in your code, too). It speaks the OpenAI and Anthropic APIs, so existing apps
change a URL instead of code; it applies one policy to every app; it detects credentials (231 rules) as well as personal
data; it keeps the provider keys; and it re-scans the outgoing request and blocks it if a protected value is still
there. Harpo does not use Presidio, and we have not benchmarked the two against each other, so we make no accuracy
comparison. Presidio covers things Harpo does not, such as redacting text in images.

### Why not only regex?

Patterns find shapes, not meaning, and a pattern alone either misses or over-matches. Harpo validates what it can
(card numbers by Luhn and issuer, IBANs by mod-97, phone numbers with libphonenumber, 17 national ID schemes by their
checksums), uses context for values without a checkable format (the word that names a value, in some thirty languages;
a JSON key, a CSV header, a form label), runs NER for names, places and organisations, and decodes text before
matching (base64, hex, URL, HTML and JSON escapes, look-alike letters, zero-width characters, values split over lines
or spaced out). Credentials do use patterns: 231 rules, 221 of them from gitleaks, run on RE2 so no input can cause
catastrophic backtracking.

### Why not use a privacy LLM?

A language model is probabilistic: it can miss a value, and its output cannot prove that nothing sensitive is left.
Harpo keeps the decision deterministic. Models are sensors: spaCy NER always, and optionally a local model through
Ollama. They can add findings, never approve a request; policy and egress verification, which re-scans with the
deterministic layers, decide what leaves. A hosted "privacy model" would also mean sending the data out to have it
checked.

### Does any data leave my infrastructure?

Only the redacted request, to the provider you configured. Detection, policy, verification and logs run where you run
Harpo: your laptop, a server or your VPC. There is no Harpo cloud service and no telemetry; the console is served by
the gateway and makes no external requests, and the connection checks you start from it talk only to your providers.
The optional local model runs in your own Ollama. Setup downloads packages and models (pip, spaCy models from GitHub,
an Ollama model if you choose one); that is software coming in, not your data going out.

### Which providers work?

Presets for OpenAI, Anthropic, Google Gemini (through its OpenAI-compatible API), OpenRouter, Mistral, Groq, DeepSeek
and a local Ollama. Any other endpoint that speaks the OpenAI Chat Completions or Anthropic Messages API can be added as
an upstream, and requests are routed by model name. Harpo proxies `POST /v1/chat/completions` and `POST /v1/messages`
(streaming included), `/v1/messages/count_tokens` and `/v1/models` ([API.md](API.md)). Other APIs, such as OpenAI's
Responses API, embeddings, audio or files, are not proxied yet.

### Does OpenRouter work?

`harpo init --provider openrouter` writes two upstreams with one OpenRouter key: the OpenAI-style API for most clients
and the Anthropic-style API for Claude Code and the Anthropic SDKs. On every request the gateway sets OpenRouter's
provider routing: by default only providers that do not store prompts, optionally zero-data-retention endpoints only.
A client may make that stricter, never looser. Fallback model lists and model-choosing plugins are checked against the
models you allow, and session and trace ids are removed.

### Does Ollama work?

Yes, in two roles. As an upstream, a local Ollama is one more provider behind the same policy. As a sensor, Ollama
serves the optional local model (below). The boot scripts set that up when Ollama is installed, and `docker compose
--profile slm` runs Ollama on an internal network next to the gateway.

### What does deterministic-first mean?

That the detectors which decide are rules with checks, not models: validated formats, checksums, cue words and the
credential rules. Models come second, as sensors. The reason is that a guarantee has to be checkable: validated
detectors give the same answer for the same input, so a test can pin it and a regression shows up in CI. Models add
recall for names and context, but they never decide what leaves: egress verification uses the deterministic layers
only, and "probabilistic layers cannot authorize egress" is one of the eleven [invariants](INVARIANTS.md) the test
suite tries to break.

### Are reverse maps stored? Can I get the original values back in the reply?

No. Placeholders are numbered per request (the same value keeps the same number across the conversation in that
request), and there is no store and no resolver; the NER cache keeps offsets and types, no text, for up to 15 minutes
in memory and can be turned off (`detection.ner.cache_entries: 0`). Replies come back with placeholders. If your app
needs the real values in the final text, it fills them in from data it already holds. Nobody, the gateway included,
can turn a reply back into your data.

### What gets logged?

JSON lines on stdout. One audit line per API request: request id, key id, route, model, decision, risk, reason codes,
counts per type and timings. For a credential it records which rule fired, never the value. Prometheus metrics count
requests, redactions by type, blocks by reason and stage latency. Prompts, replies and detected values are never
logged or stored; the console's Activity page shows the same metadata. Production mode refuses debug logging.

### Does Harpo inspect responses?

Not by default. `policy.response_scan: report` runs the deterministic layers on non-streamed answers and reports what
it finds (`x-harpo-response-findings` and the audit line); `redact` also replaces it. Streamed answers are not scanned
and are marked `x-harpo-response-scan: not_scanned_stream`. Requests are always scanned, streamed or not.

### What does the optional local model (SLM) do?

It is an extra sensor, off by default: a small local model, or a specialised privacy model, served through Ollama's
API. It is designed to reduce residual false negatives for context-dependent or semantically ambiguous sensitive
content, the values the rules cannot see. Its findings are checked against the text and can only add redactions.
`on_failure: fail_closed` refuses requests while it is unavailable, `degrade` continues without it, and `model_digest`
pins the exact model. What it adds depends on the model you run, and it is not part of the published benchmark
numbers.

### Does it work with consumer ChatGPT, Claude or Gemini?

No. Consumer apps talk to their vendors directly and cannot be routed through a proxy. Use the console's playground,
or a self-hosted chat app (Open WebUI, LibreChat, LobeChat, AnythingLLM and others) pointed at Harpo, with the same
models through their APIs.

### Does it protect Cursor?

Only partly. Cursor can override the OpenAI base URL, but it calls custom endpoints from its own servers: your prompt
passes through Cursor's servers before it reaches the gateway, so Harpo cannot protect it from Cursor, and the gateway
has to be reachable from the internet over HTTPS. Continue, Cline and Claude Code connect from your machine.

### What are the current limitations?

The full list is in [Known limits](GUIDE.md#known-limits); the main ones:

- Names are the weak spot: all 25 LeakBench escapes are names (in leetspeak or lowercase), and egress
  verification cannot re-find a missed name. The optional local model is the layer for them.
- Ambiguous values trade precision for recall: identifiers without a checksum are protected after a word that names
  them; some products, events and organisations are over-redacted (2.3% to 5.1% collateral on the three
  personal-data benchmarks).
- No images, audio or OCR: images in chat are blocked by default, pictures and scanned pages in documents refused.
- Streamed replies are not scanned.
- Not detected yet: special-category data (health, religion, ethnicity, orientation) and combinations of harmless
  facts that identify someone together.
- An administrator can set most types to `allow`; keys and encoded data cannot be allowed.
- Rate limits are per gateway process.
- No independent security audit yet.

### How were the benchmarks run?

On public datasets Harpo was not built against: ProwlBench 2.0 (24,603 secret cases), Nemotron-PII (100,000
documents), OpenPII (10,000 documents) and RedactionBench (200 documents), 134,803 documents and cases in all. Each
started with a blind run of the previous release (2.4.0), recorded before anything was changed. Which labels count was
fixed before any result was seen. Fixes were made on the dev half of each dataset and judged on the holdout half; each
round is a frozen build identified by the sha256 of its installed package, run on data files identified by theirs, in
the default configuration. ProwlBench is scored by its own runner, unchanged. Results for 2.5.0: ProwlBench F1 0.941
(holdout half 0.939); Nemotron-PII 94.8% of values fully removed, 2.3% collateral; OpenPII 76.8%, 5.1%; RedactionBench
88.0%, 3.6%, R-Score 0.460. Each uses its benchmark's own metric; there is no combined score. The harness, every
result file and the full record, including what got worse, are in the repository ([bench/external](../bench/external),
[EXTERNAL_BENCHMARKS.md](EXTERNAL_BENCHMARKS.md)). The datasets are not in the repository: each is downloaded from its
publisher, under its own licence. Harpo has not been submitted to any leaderboard, and no rank is claimed on OpenPII
or Nemotron-PII, which rank models on a different metric. RegionBench and LeakBench are Harpo's own benchmarks: useful
for regressions, not independent evidence.

### Has Harpo been independently audited?

No. There has been no third-party security audit or penetration test. What exists: eleven named security invariants,
each with tests that try to break it; a conformance suite that puts a canary in every field of realistic requests for
each provider format; LeakBench and a redaction matrix (60 value types in 31 shapes) run in CI; a live self-test in the
console; dependency audits, secret scanning of the tree and the git history, hash-pinned dependencies, SHA-pinned CI
actions and an SBOM. What Harpo protects, on which assumptions, and what it does not:
[THREAT_MODEL.md](THREAT_MODEL.md). Vulnerabilities go to the private channel in [SECURITY.md](../SECURITY.md).

### What is the license?

Apache-2.0: use, modify, embed and redistribute it, commercially included, with an explicit patent grant. The name and
logo are not licensed (forks are welcome under their own name). Third-party components keep their licences
([THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)): the gitleaks rules are MIT; the Docker image and the boot
scripts ship only MIT-licensed spaCy models, and the optional Dutch (CC BY-SA 4.0), French (LGPL-LR) and Spanish
(GPL-3.0) models are opt-in.
