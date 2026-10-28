# Python SDK

Harpo is a gateway first: it sits between your applications and the model providers, and every request passes its
checks. The SDK gives Python code the same capabilities without leaving Python:

- **`Harpo` / `AsyncHarpo`**, the engine in your process. The gateway's own detection, policy, redaction, egress
  verification and document handling, with no server. For batch jobs, data pipelines, notebooks, and services that
  call a provider themselves.
- **`GatewayClient` / `AsyncGatewayClient`**, a running gateway from Python: its scans, documents, requests to providers
  through it, and its control plane (policy, keys, self-test, diagnostics), behind its gateway keys.

Both run the code the gateway runs. There is one implementation of every check; the SDK is an interface to it, and
its tests hold it to that: for the same input, a local scan, `harpo scan` and the gateway's `POST /v1/scan` give the
same result, down to every offset and placeholder.

```python
from harpo_redact.sdk import Harpo

with Harpo() as harpo:
    print(harpo.redact("Mail jane.doe@example.com about card 4111 1111 1111 1111"))
    # Mail [EMAIL_1] about card [CREDIT_CARD_1]
```

Runnable examples, each tested: [examples/python/sdk](../examples/python/sdk).

## Install

Harpo 2.5.0 is installed from its GitHub repository, not from PyPI. Python 3.12 or newer:

```bash
pip install "harpo-redact @ git+https://github.com/levilausberg-png/harpo-redact@v2.5.0"   # the release tag
```

or from a clone:

```bash
git clone https://github.com/levilausberg-png/harpo-redact
cd harpo-redact
python -m pip install .
```

For the exact dependency versions CI and the Docker image use, install the hash-pinned lock first:
`pip install --require-hashes --no-deps -r requirements.lock`, then `pip install --no-deps .`.

**Language models.** Names, places and organisations are found by spaCy models, which are not on PyPI, so pip does not
bring them. Without one, the engine refuses to start with a `ConfigurationError` that gives the one-line,
hash-checked install command; `pip install --require-hashes --no-deps -r requirements-models.lock` installs all six
(English, German and the multilingual model are MIT; Dutch, French and Spanish have other licences). To run without
NER, say so: `Harpo({"detection": {"ner": {"enabled": False}}})`.

## The engine

```python
from harpo_redact.sdk import Harpo

harpo = Harpo()                         # the default configuration
harpo = Harpo("config/harpo.yaml")      # a configuration file, as the gateway reads it
harpo = Harpo({"policy": {"entities": {"US_SSN": {"action": "block"}}}})   # a mapping shaped like harpo.yaml
harpo = Harpo.from_env()                # what `harpo serve` reads: $HARPO_CONFIG, ./harpo.yaml or ./config/harpo.yaml
```

`HARPO_*` environment variables apply on top of any of these, and `policy.live_file`, when set, is laid over the
configuration, exactly as the gateway does at startup. The models are loaded once per process and shared by every
engine. An engine is thread-safe; close it when you are done (`harpo.close()`, or use `with`).

### Scan

```python
result = harpo.scan("Customer Maria Jansen (maria.jansen@northwind.example) paid with 4111 1111 1111 1111.")

result.risk          # Risk.GREEN here; Risk.YELLOW goes on with an advisory, Risk.RED is blocked
result.blocked       # False: True means the policy says nothing may be sent
result.text          # 'Customer [PERSON_1] ([EMAIL_1]) paid with [CREDIT_CARD_1].'
result.findings      # (Finding(type='PERSON', start=9, end=21, placeholder='[PERSON_1]', sources=('ner', ...)), ...)
result.reasons       # why the risk is what it is, e.g. Reason(code='keys_redacted', level=Risk.YELLOW, ...)
result.counts        # {'PERSON': 1, 'EMAIL': 1, 'CREDIT_CARD': 1}
```

`scan()` is the gateway's `POST /v1/scan`. It always returns, also when the policy blocks: check `result.blocked`
before you use `result.text`. Findings carry offsets into the text you passed in, never the value itself.

Several texts are scanned together, so one value gets one placeholder across all of them, as the messages of one
request do:

```python
result = harpo.scan(["Maria Jansen wrote to us.", "Reply to Maria Jansen at maria.jansen@northwind.example."])
result.texts         # ('[PERSON_1] wrote to us.', 'Reply to [PERSON_1] at [EMAIL_1].')
result.items         # one ScannedText (text, findings) per input
```

Options, each with the gateway's rule:

| Option | Effect |
| --- | --- |
| `mode="generic"` | `[PERSON]` instead of `[PERSON_1]`; honoured when `policy.client_may_choose_mode` is true (the default), as `X-Harpo-Mode` is |
| `context_repair=True` | `[PERSON_A]`/`[PERSON_B]` inside a sentence in generic mode; the same rule |
| `override=True` | sends types the policy blocks with `overridable: true` as placeholders, unless `policy.override` is `never` (a caller in your process holds no gateway key, so the rule of a gateway without authentication applies) |
| `layers="fast"` | leaves out the optional local SLM |

### Redact

```python
safe = harpo.redact(text)               # the text as the gateway would let it leave
safe = harpo.redact([first, second])    # a list in, a list out
```

`redact()` is the proxy's checks for a request, on plain text: the scan; a block stops it with `BlockedError`; then,
with `policy.egress_verification: full` (the default), the redacted text is scanned again with the deterministic
layers, and anything still found stops it too. Use it when the result is going to leave your process.

```python
from harpo_redact.sdk import BlockedError, Harpo

with Harpo({"policy": {"entities": {"US_SSN": {"action": "block"}}}}) as guarded:   # the default redacts it
    try:
        guarded.redact("Her SSN is 536-90-4399")
    except BlockedError as blocked:
        blocked.reasons         # (Reason(code='blocked_entity', entity_type='US_SSN', count=1, ...),)
        blocked.blocked_types   # ('US_SSN',)
        blocked.overridable     # whether override=True would send it as a placeholder
```

### Documents

```python
result = harpo.redact_document("contract.docx")               # a path
result = harpo.redact_document(data, filename="notes.txt")    # or the bytes, with a name for text files
result.save("out/")          # writes contract.redacted.docx
result.verified              # the redacted file was opened again and scanned before release
result.text                  # the redacted document as readable text
```

PDF, Word, Excel, PowerPoint and text files (txt, md, csv, json, xml, html, yaml, logs, source), as `harpo
redact-file` and `POST /v1/documents/redact` handle them. The file is parsed in a separate worker process with its
own limits; Office and text files are edited in place, PDF pages are re-rendered with the values blacked out; what
cannot be inspected (pictures, scanned pages, macros, encrypted files) is refused rather than passed through.
`file=False` returns the text only. A blocked document raises `BlockedError`; one that cannot be processed raises
`DocumentError` with a stable `code` (`unsupported_format`, `legacy_office`, `too_large`, `encrypted`, `macros`, ...).

### Policy

```python
harpo.policy.entities["US_SSN"]     # EntityRule(action='redact', overridable=False)
harpo.policy.custom_types           # (CustomTypeInfo(name='EMPLOYEE_ID', ..., terms=0, patterns=1),)
harpo.policy.always_redacted        # ('PRIVATE_KEY', 'SECRET')
```

The view leaves the policy's own secrets out: a custom type's terms and patterns are counted, not listed.

`with_policy()` returns a new engine with a policy laid over this one's, the way the console's Policy page lays a live
policy over the configuration file, checked by the same rules:

```python
from harpo_redact.sdk import CustomType

strict = harpo.with_policy(
    entities={"US_SSN": "block", "ORGANIZATION": "allow"},       # redact, block or allow per type
    custom_types=[                                               # your own types (they replace this engine's)
        CustomType("EMPLOYEE_ID", patterns=(r"\bEMP-\d{6}\b",)),   # RE2 expressions, linear time
        CustomType("PROJECT", terms=("Project Bluefin",), action="block"),
    ],
    detectors={"identifiers.crypto": False},                     # detector families (docs/LIBRARY.md)
)
with strict:
    strict.redact("badge EMP-123456")                            # 'badge [EMPLOYEE_ID_1]'
```

Keys are always redacted: API keys, tokens, passwords and private keys cannot be set to block or allow, by a policy,
a switch, `allow_terms` or an override (INV-11), and `with_policy()` raises `ConfigurationError` for any attempt.
In the configuration file, the same policy is `policy.entities` and `detection.custom_types` (see
[`config/harpo.example.yaml`](../config/harpo.example.yaml)).

`validate_config(source)` checks a configuration the way `harpo check-config` does, without starting anything:

```python
from harpo_redact.sdk import validate_config

report = validate_config("config/harpo.yaml")
report.valid, report.errors       # does it load, and if not, each setting path with its message
report.problems                   # why it must not serve production traffic (production mode)
report.missing_models             # language models it names that are not installed, with the install command
report.ok                         # all of the above are clear
```

### More

| Call | What it does |
| --- | --- |
| `verify(text)` | The egress check alone: what the deterministic layers still find in text you are about to send (`Verification.clean`, `.counts`). |
| `scan_response(text)` | A provider's answer through the deterministic layers, with plain labels (`[EMAIL]`): what `policy.response_scan` does to answers on the gateway. |
| `trace(text)` | One sample through the detection stages, each stage's findings apart (the console's detector lab). The trace holds your text: keep it out of logs. |
| `status()` | The models, the local SLM and whether it answers, the credential rules, the custom types. |
| `detection_library()` | Every detector family under its umbrella, on or off. |
| `analyze()` | Hardening findings on the configuration, each with its setting. |
| `generate_key(id, ...)` | A new gateway key, as `harpo hash-key` makes it: the key once, and the `auth.keys` entry (its SHA-256) for the configuration. |

## A running gateway

```python
from harpo_redact.sdk import GatewayClient

with GatewayClient("https://harpo.internal", api_key="harpo_...") as gateway:
    gateway.scan("Mail jane.doe@example.com").text          # 'Mail [EMAIL_1]'
    answer = gateway.chat_completion({"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "..."}]})
    answer.body                                             # the provider's answer
    answer.risk, answer.redactions                          # the gateway's verdict on the request
```

`base_url` defaults to `$HARPO_URL` (else `http://127.0.0.1:8080`) and `api_key` to `$HARPO_KEY`. The key goes in
every request as `Authorization: Bearer`; the gateway decides what it may do, exactly as for any other client.

| Any gateway key | Admin key |
| --- | --- |
| `health()`, `ready()`, `policy()` | `system()`, `providers()`, `check_provider(name)` |
| `scan(...)`, `redact_document(...)` | `list_keys()`, `generate_key(id, ...)` |
| `chat_completion(body)`, `message(body)` | `effective_config()`, `validate_config(yaml)`, `config_analysis()` |
| `models(style)`, `preview_egress(style, body)` | `live_policy()`, `set_live_policy(...)`, `reset_live_policy()`, `preview_policy(text, ...)` |
| `trace(text)`, `stats()` | `selftest()`, `selftest_suites()`, `presets()`, `diagnostics()`, `attention()` |

Each call is one route of the HTTP API ([API.md](API.md)). `chat_completion()` and `message()` send a provider request
through the gateway (OpenAI and Anthropic style); the gateway sanitizes it, verifies it at egress and forwards it, or
raises `BlockedError` and sends nothing. They do not stream: for streaming, point the provider's own SDK at the gateway,
which streams through the same checks:

```python
from openai import OpenAI

client = OpenAI(base_url=gateway.openai_base_url, api_key="harpo_...")
```

`preview_egress()` shows exactly what the gateway would send for a request, without sending it. `set_live_policy()`
changes the policy on every worker without a restart; the change is audited with your key's id. `http_client=` takes
your own configured `httpx.Client` (proxies, client certificates, custom CAs).

## asyncio

`AsyncHarpo` and `AsyncGatewayClient` have the same calls, as coroutines:

```python
from harpo_redact.sdk import AsyncHarpo, AsyncGatewayClient

async with AsyncHarpo() as harpo:
    results = await asyncio.gather(*(harpo.scan(t) for t in tickets))

async with AsyncGatewayClient(api_key="harpo_...") as gateway:
    result = await gateway.scan("Mail jane.doe@example.com")
```

An `AsyncHarpo` loads its models in a worker thread when it starts (`async with`, `await harpo.start()`, or the first
call) and belongs to the event loop it started on. The blocking `Harpo` runs the same coroutines on an event loop of
its own, on a thread of its own: it can be called from any thread, and also from inside a running event loop (a
notebook, say), where it blocks like any other blocking call.

## Errors

| Exception | Raised when |
| --- | --- |
| `HarpoError` | The base class of all of them. `status` and `request_id` are set when a gateway answered. |
| `ConfigurationError` | The configuration is not valid (`issues`: setting paths and messages), or a model it names is not installed. |
| `InvalidRequestError` | A bad argument, or a gateway's 400 or 422. Also a `ValueError`. |
| `BlockedError` | The policy blocks the content: `reasons`, `blocked_types`, `overridable`, `override_permitted`. |
| `DocumentError` | A document was refused or could not be processed: `code`. |
| `GatewayError` | A gateway answered with an error (`type`: the error type of its answer), or could not be reached. |
| `AuthenticationError`, `PermissionDeniedError`, `NotFoundError`, `ConflictError`, `RequestTooLargeError`, `RateLimitError` (`retry_after`), `GatewayUnavailableError` | 401, 403, 404, 409, 413, 429, and 502/503/504 or no connection. |

No message quotes what you sent: they name types, counts, setting paths and codes. An unexpected error inside the
engine is raised as a `HarpoError` that keeps the error's type and withholds its message, which could quote the
input; the original exception is on `.original` if you need it.

## The security contract

The SDK is one more way into the same enforcement, so every invariant ([INVARIANTS.md](INVARIANTS.md)) holds through
it:

- **One implementation.** `scan()` is `Pipeline.scan`, the call behind `POST /v1/scan` and the proxy; `redact()` adds
  the proxy's block check and its egress verification (`Pipeline.residual`); `redact_document()` is
  `documents.service.redact_document`, as `harpo redact-file` and the documents endpoint; `with_policy()` is
  `live_policy.apply`, the console's. Nothing in the SDK detects, decides or redacts on its own.
- **Keys are always redacted** (INV-11), and an override never restores a value (INV-06): overrides only let an
  overridable *blocked* type go on as a placeholder, under the policy's `override` rule.
- **No reverse map.** Placeholders are numbered per call and nothing maps them back to values; the SDK adds no way to.
- **No content in logs, errors or `repr()`.** The SDK writes no logs of its own, and the engine logs what the gateway
  logs: codes, counts and timings. Results print types, counts and verdicts, never text (`repr(result)`); a
  generated key prints as `key=<hidden>`. The text is only handed over when you ask for it (`.text`, `.texts`,
  `.data`, `trace()`).
- **Fail closed.** A scan over one of its budgets (time, decoded data, detections) is blocked, never half-inspected;
  with the local SLM set to `fail_closed`, a scan it could not see is blocked; a document that cannot be inspected is
  refused.
- **What the engine does not do:** it has no authentication of its own (whoever can call it in your process is
  trusted like the operator), and it does not rate-limit or audit. Where callers must be told apart, held to a key's
  permissions and audited, run the gateway and use `GatewayClient`.

Between calls the engine keeps only what the gateway keeps: the loaded models, and NER's cache of offsets and types
for texts seen before, keyed by an HMAC with a per-process random key.

## What is public

- **Stable:** every name in `harpo_redact.sdk.__all__`, and `harpo_redact.Harpo`, `AsyncHarpo`, `GatewayClient`,
  `AsyncGatewayClient` and `__version__`. Their behaviour follows semantic versioning from 2.5.0: a breaking change
  comes with a major version and a changelog entry. Also stable: the `harpo` command, the HTTP API ([API.md](API.md))
  and the configuration file format.
- **Advanced:** `harpo_redact.conformance`, the black-box conformance runner for an adapter or a deployment (you supply
  `submit(body)`). Documented and kept working, but it may change in a minor version, with a changelog note.
- **Internal:** everything else: the modules of `harpo_redact.sdk` whose names start with `_`, and `harpo_redact.api`,
  `pipeline`, `proxy`, `adapters`, `config`, `detectors`, `documents`, `redactor`, `normalize`, `library`, ... They
  change without notice; build on `harpo_redact.sdk` instead. (`harpo_redact.config.Settings` is the model behind the
  configuration file: pass a mapping or a YAML file to the SDK, not the model.)

## Capabilities and where they are

| Capability | Implementation | CLI and HTTP | SDK |
| --- | --- | --- | --- |
| Configuration: load | `config.load_settings` | `--config`, `$HARPO_CONFIG`, `HARPO_*` | `Harpo(config)`, `Harpo.from_env()` |
| Configuration: validate | settings validation, production guards | `harpo check-config`, `POST /v1/config/validate` | `validate_config()`, `GatewayClient.validate_config()` |
| Configuration: analyze | `analysis.analyze` | `GET /v1/config/analysis` | `Harpo.analyze()`, `GatewayClient.config_analysis()` |
| Configuration: effective, redacted | the gateway's view | `GET /v1/config/effective` | `GatewayClient.effective_config()` |
| Scan: findings, risk, reasons | `Pipeline.scan` | `harpo scan`, `POST /v1/scan` | `scan()` (engine and client) |
| Redact for egress, with block and egress check | the proxy's sanitize checks | the proxy | `Harpo.redact()` |
| Egress verification | `Pipeline.residual` | the proxy; `POST /v1/egress/preview` | `Harpo.verify()`, `GatewayClient.preview_egress()` |
| Requests to providers | proxy and adapters | `POST /v1/chat/completions`, `/v1/messages` | `GatewayClient.chat_completion()`, `.message()`; provider SDKs via `openai_base_url` |
| Response scanning | `Pipeline.redact_deterministic` | `policy.response_scan` | `Harpo.scan_response()` |
| Documents | `documents.service.redact_document` | `harpo redact-file`, `POST /v1/documents/redact` | `redact_document()` (engine and client) |
| Policy: view | the configuration with the live policy | `GET /v1/policy` | `Harpo.policy`, `GatewayClient.policy()` |
| Policy: change (actions, custom types, detector families) | `live_policy.apply` | the console's Policy page, `PUT`/`DELETE /v1/policy/live` | `Harpo.with_policy()`, `GatewayClient.set_live_policy()` / `.reset_live_policy()` / `.live_policy()` |
| Policy: try a draft | `live_policy.apply` + `Pipeline` | `POST /v1/policy/preview` | `Harpo.with_policy().scan()`, `GatewayClient.preview_policy()` |
| Detection library | `library.describe` | `harpo check-config`, `GET /v1/system` | `Harpo.detection_library()` |
| Detection trace | `lab.lab_run` | `POST /v1/lab/detect` | `trace()` (engine and client) |
| Health and readiness | the gateway | `GET /healthz`, `/readyz` | `GatewayClient.health()`, `.ready()`; `Harpo.status()` |
| System, providers, activity, posture, diagnostics | the gateway | `GET /v1/system`, `/v1/providers`, `POST /v1/providers/{name}/check`, `GET /v1/stats`, `/v1/attention`, `/v1/diagnostics` | `GatewayClient.system()`, `.providers()`, `.check_provider()`, `.stats()`, `.attention()`, `.diagnostics()` |
| Gateway keys | `harpo_` + 32 random bytes, stored as SHA-256 | `harpo hash-key`, `GET /v1/keys`, `POST /v1/keys/generate` | `generate_key()`, `GatewayClient.list_keys()`, `.generate_key()` |
| Invariant self-test | canaries through the request path | `POST /v1/selftest`, `/v1/selftest/suites` | `GatewayClient.selftest()`, `.selftest_suites()` |
| Models and provider presets | the gateway's routes, `presets` | `GET /v1/models`, `harpo init`, `GET /v1/setup/presets` | `GatewayClient.models()`, `.presets()` |
| Run the gateway | uvicorn, the launcher | `harpo serve`, `demo`, `up`, `down`, `status`, the boot scripts, Docker | not in the SDK: run the command or the container |
| Metrics, the live event stream | Prometheus, server-sent events | `GET /metrics`, `GET /v1/events` | not wrapped: scrape `/metrics`; `GatewayClient.stats()` has the same counts |
