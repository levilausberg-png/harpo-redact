# Security invariants

These are the properties Harpo must keep, whatever else changes. Each one names the mechanism that
enforces it and the tests that check it. Every invariant has tests named `test_invNN_*` in
`tests/test_invariants.py`; `test_every_invariant_is_tested` fails if one is listed here without a test.

| ID | Invariant | Enforced by | Tested by |
| --- | --- | --- | --- |
| INV-01 | No raw blocked value crosses the boundary. | Detection and policy on every inspected surface; the coverage walk (nothing uninspected leaves); **egress verification**: the whole sanitized body, values and keys, is scanned again by the deterministic layers before it is sent, and a hit blocks the request. | `test_inv01_*`, the conformance suite (`tests/test_conformance.py`: a canary in every slot of realistic requests), the redaction matrix (`tests/test_redaction_matrix.py`: 60 value types through 31 carriers, checked by an independent leak oracle) |
| INV-02 | No reverse pseudonymization map persists beyond request scope. | Placeholders are numbered per request inside the pipeline; there is no reverse map, no store, no API that resolves a placeholder. The NER cache holds offsets and types under a per-process HMAC key, never text. | `test_inv02_*`: after requests, nothing reachable from the application holds the original values |
| INV-03 | Probabilistic components cannot independently authorize egress. | NER and the SLM can only *add* findings; SLM findings must pass deterministic verification; an SLM failure blocks or degrades by explicit policy; egress verification uses deterministic layers only. | `test_inv03_*`, `tests/test_slm_hardening.py` |
| INV-04 | Uninspectable content is never silently forwarded. | Images, audio, provider-side files, unknown content parts, remote MCP servers and unknown fields at any depth are blocked, or dropped with a visible marker when policy says so. | `test_inv04_*` |
| INV-05 | Sensitive prompt content never appears in telemetry. | Logs, audit lines and metrics carry codes, counts and key names only; exception messages are never logged; error responses do not echo request values. | `test_inv05_*` |
| INV-06 | Overrides never restore prohibited raw information. | An override lets a request that policy blocked continue with the values *redacted*; egress-verification blocks and budget blocks cannot be overridden; overriding is a per-key permission. Keys are never blocked in the first place (INV-11). | `test_inv06_*` |
| INV-07 | Every supported adapter enumerates all privacy-relevant surfaces it understands. | `adapters.py` declares each adapter's surfaces and identifier rules; the coverage walk enforces the declaration on every request. | `test_inv07_*`, `tests/test_conformance.py` |
| INV-08 | Unsupported provider fields fail according to explicit policy. | `policy.unknown_fields`: `reject` refuses the request naming the field path (never its value); `pass` scans the field as text. Never forwarded unchecked. | `test_inv08_*` |
| INV-09 | A sanitized document must survive reconstruction verification before release. | Office and text files are re-opened and re-scanned; PDF pages are decoded after encoding and every redaction box is checked to be opaque. A failure means the document is not released. | `test_inv09_*` |
| INV-10 | Unsupported images remain blocked rather than weakly inspected. | There is no OCR. Images in chat are blocked (or dropped); pictures and scanned pages in documents are refused, or replaced by blank ones on request. | `test_inv10_*` |
| INV-11 | Keys are always redacted. | API keys, tokens, passwords and private keys (`SECRET`, `PRIVATE_KEY`) become placeholders and the request goes on: these types never stop a request, and a key is never sent. Configuration validation fixes them to `redact`: a file that asks for `block` is reported and redacted anyway, `allow` is refused. The live policy cannot name them. The whole credential library always runs, and so do the decoders that find keys inside base64, hex and escapes, whatever the older switches say; a global allowlist in `extra_rules_file` is not applied. An override never changes them, and egress verification blocks a key the scan missed. A request can still be blocked by another type an administrator set to block, including a custom type whose pattern matches a key and `ENCODED_DATA` around one. | `test_inv11_*`, `tests/test_keys_always_redacted.py`, the credential rows of the redaction matrix |

**Through the SDK.** The Python SDK ([SDK.md](SDK.md)) is another way in, not another implementation: `Harpo.scan` is
the pipeline's scan, `Harpo.redact` adds the proxy's block check and egress verification, documents go through the
same service and its verification, and policies through the live policy's checks. `tests/test_sdk.py` holds it to
the canonical results for the same input and runs INV-01, INV-05, INV-06 and INV-11 through it; `GatewayClient`
goes through the gateway itself (`tests/test_sdk_client.py`).

## What the invariants do not claim

The threat model ([THREAT_MODEL.md](THREAT_MODEL.md)) sets these next to the assumptions Harpo makes and the threats
it does and does not address.

- They are about what crosses the gateway. Recall is not perfect: a name the detectors do not recognise is not
  redacted, and egress verification only re-checks with the deterministic layers (it cannot re-find a missed name).
  `bench/leakbench` measures recall.
- Content the provider produced and signed (thinking blocks) is forwarded unchanged; egress verification still scans it.
- The worker that parses documents is isolated by process limits, not by a syscall sandbox.
- The SDK's local engine runs in your process, with no authentication of its own: `scan()` returns a blocked result
  too, and what leaves your process is up to your code. `redact()` refuses blocked content.
