# Threat model

This page covers what Harpo 2.5.0 protects, against which threats, on which assumptions, and what it does not claim.
The guarantees themselves are in [INVARIANTS.md](INVARIANTS.md), each with the mechanism that enforces it and the
tests that check it.

## Security objective

**Unapproved sensitive information must not cross this boundary.**

The operator's policy approves a type by setting it to `allow`. Anything else the gateway detects is handled before
the request leaves:

- it is replaced by a placeholder, or the request is stopped;
- then the exact outgoing request is scanned once more.

In the invariants' words (INV-01): no raw blocked value crosses the boundary. Credentials are never approved. API
keys, tokens, passwords and private keys are always replaced (INV-11).

## Protected assets

| Asset | Protection |
| --- | --- |
| Request content: messages, system prompts, tool definitions, tool calls and tool results | Detected values are replaced before the request is forwarded. Content is not logged, and no error message quotes it. |
| Personal data and identifiers in that content | Detection, then the policy's action for each type: redact, block or allow. |
| Credentials pasted into prompts | Always redacted, whatever the policy says (INV-11). |
| Provider credentials | Read by the gateway from environment variables and added to forwarded requests. Clients never hold them, no API returns them (only whether one is set), and production refuses debug logging, which could print headers. |
| Gateway and admin keys | Stored only as SHA-256 and compared in constant time, with optional expiry and per-key rate limits. A gateway key pasted into a prompt is redacted like any other key. |
| Uploaded documents | Parsed in a separate worker process that cannot write files and has memory and CPU limits. Where the system allows, it also has no network. Every redacted file is re-opened and re-scanned before release (INV-09). Nothing is stored. |
| Configured sensitive terms: custom types, registry terms, allow terms | Every view reduces them to counts, except the admin-only policy editor (`GET /v1/policy/live`), which shows custom types' terms and patterns so they can be edited. They stay out of logs. |
| Security and audit metadata | Logs, audit lines, metrics and diagnostics carry codes, counts, key ids and timings, never content (INV-05). |

## Trust boundary

```text
application ──▶ Harpo ──▶ model provider
                  │
         policy, detection, redaction, egress verification
```

The application, and whoever holds a gateway key, are on the inside. The provider, and everything past it, is on the
outside. Harpo is the enforcement point between the two:

- what the provider receives is what Harpo forwarded, after its checks;
- what the application gets back is the provider's answer, with the placeholders still in it.

The Python SDK's local engine (`harpo_redact.sdk.Harpo`) moves the same checks into your own process. There the
boundary is your code: `redact()` refuses blocked content, and what leaves the process is up to you
([SDK.md](SDK.md#the-security-contract)).

## Assumptions

- The host or container Harpo runs on is not compromised, and neither is its operating-system isolation.
- Administrators act with legitimate authority. Admin keys and the console can change the policy, and the audit log
  records every change with the key that made it.
- The configuration is trusted: the configuration file, the environment variables and the live policy file. Whoever
  can write them decides the policy.
- The upstreams in the configuration are the providers the operator means to use. Harpo forwards to them, and to
  nothing else.
- Transport security is set up by the operator:
  - Harpo serves TLS itself when `server.tls_certfile` and `server.tls_keyfile` are set; otherwise a reverse proxy
    terminates it.
  - In production, upstreams must use HTTPS.
  - `server.allowed_hosts` should name the gateway's own hostnames.
- An optional local model (the SLM) sees the text it scans. It runs where the operator put it (the Compose file
  keeps it on an internal network with no internet access) and can only add findings.

## Threats Harpo addresses

| Threat | What stops it |
| --- | --- |
| Personal or sensitive values sent to a provider by accident | Detection on every surface the adapter declares, the policy, and placeholders. Egress verification blocks a request that still carries a detectable value. |
| Secrets and API keys in prompts, code, logs and configuration snippets | 231 credential rules (221 from gitleaks, run on RE2), always redacted (INV-11). |
| Encoded or disguised values | Decoding of base64, hex, URL, HTML and JSON escapes, two levels deep. Folding of look-alike letters and removal of zero-width characters. Rejoining of values split over lines or spaced out. |
| Parts of a request nobody inspects | Each adapter declares every field it understands, and a coverage walk checks every request against that declaration. Unknown fields are refused, or scanned as text by policy. Images, audio and unknown content parts are blocked or dropped with a marker. Remote MCP servers are blocked (INV-04, INV-07, INV-08, INV-10). |
| Getting around the policy | Overrides only let blocked types go on as placeholders, never as raw values (INV-06). NER and the SLM cannot approve anything (INV-03). A scan over its time, decoding or detection budget blocks the request instead of passing it. |
| Sensitive values in logs, metrics or error answers | Content-free records and errors that name types, counts and codes (INV-05). |
| Leaks through documents | Office and text files are edited in place; PDF pages are re-rendered as images with the values blacked out. Every file is verified before release, and pictures, scanned pages, macros and encrypted files are refused (INV-09, INV-10). |
| Unsafe outgoing requests | Only models the configuration allows. No redirects followed. Size limits on bodies, messages and provider answers. |
| A gap in detection between scan and send | Egress verification re-scans the whole outgoing body, values and keys, with the deterministic layers. A hit blocks the request (`egress_verification`). |
| Placeholders turned back into values | There is no reverse map. Placeholders are numbered per request, and nothing stores or resolves them (INV-02). |

## Defense layers

1. **Normalization and decoding.** Unicode folding and look-alike letters; decoded views of base64, hex and escapes.
2. **Deterministic detectors.** Validated formats and checksums: Luhn, IBAN mod-97, libphonenumber and 17 national ID
   schemes. Also the credential rules, the detection library's identifier families, and your own custom types.
3. **Contextual detectors.** A value named by a cue word in about thirty languages, a JSON key, a CSV header or a form
   label.
4. **NER**, bounded. spaCy models, one per language, in chunks. They can only add findings, and their cache keeps
   offsets and types, never text.
5. **Optional local SLM.** A sensor for what the rules miss. Its findings are checked deterministically, and the
   operator chooses whether its failure blocks requests (`fail_closed`).
6. **Policy.** An action per type, custom types and detector families, set in the configuration or live from the
   console. Credentials are fixed to redact.
7. **Redaction.** Placeholders per request, consistent across the messages of one request.
8. **Egress verification.** The deterministic layers re-scan everything about to leave.
9. **Invariant enforcement.** Eleven invariants, each with tests, plus a live self-test (`POST /v1/selftest`) that
   sends canaries through the real request path.

The probabilistic layers, NER and the SLM, raise recall but prove nothing. A name they miss is not re-found by egress
verification, which uses the deterministic layers only. [LEAKBENCH.md](LEAKBENCH.md) and
[EXTERNAL_BENCHMARKS.md](EXTERNAL_BENCHMARKS.md) measure how much they catch; neither claims a miss rate near zero.

## Out of scope and limitations

- **A compromised host.** Root on the gateway's machine or container sees everything the gateway sees.
- **A trusted administrator who weakens the policy on purpose.** `allow` means the value is sent as written.
  Credentials and encoded data cannot be allowed, and every change is audited, but an admin key can change the rest.
- **Values the detectors do not recognise:**
  - names in leetspeak or lowercase, and nicknames;
  - identifiers with no checksum and no cue word;
  - special-category data (health, religion, ethnicity, orientation);
  - combinations of harmless facts that identify someone together.

  The [benchmarks](EXTERNAL_BENCHMARKS.md) and the [known limits](GUIDE.md#known-limits) give the measured gaps.
- **Images, audio and OCR.** Harpo does not read them: images are blocked or dropped, and pictures and scanned pages
  in documents are refused or blanked.
- **Answers from the provider.**
  - Streamed answers are never scanned.
  - Response scanning is off by default, and when on, it covers non-streamed answers only.
  - Thinking blocks the provider signed are forwarded unchanged, though egress verification still scans them.
- **Data exposed before it reaches Harpo.** Harpo cannot protect what a client sends elsewhere first:
  - its own telemetry;
  - a vendor's servers in between, as with Cursor, which calls custom endpoints from its own infrastructure;
  - consumer apps such as ChatGPT, Claude and Gemini, which cannot be routed through any proxy.
- **The network, when transport security is not set up.** Plain HTTP between applications and the gateway, or
  between the gateway and a local model, can be read on the way.
- **The SDK's local engine** has no authentication, rate limits or audit of its own. Use the gateway where callers
  must be told apart.
- **Document parsing** is isolated by process limits, not by a syscall sandbox.
- **Rate limits** are per gateway process, not shared across replicas.
- **No independent security audit yet.**

## Related documents

- [INVARIANTS.md](INVARIANTS.md): the eleven properties, how each is enforced, and its tests.
- [SECURITY.md](../SECURITY.md): how to report a way past a protection, privately.
- [EXTERNAL_BENCHMARKS.md](EXTERNAL_BENCHMARKS.md) and [LEAKBENCH.md](LEAKBENCH.md): what detection catches and
  misses, measured.
- [GUIDE.md](GUIDE.md): [production deployment](GUIDE.md#production-deployment) and
  [known limits](GUIDE.md#known-limits).
- [API.md](API.md) and [SDK.md](SDK.md): the interfaces these checks sit behind.
