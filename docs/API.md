# HTTP API

The gateway's HTTP interface has two parts. The provider-compatible routes are the ones your applications already
speak. Harpo's own routes cover scanning, documents, policy and operations. Every route on this page is served by
`create_app` in `src/harpo_redact/api.py`, and no other route exists. There is no Swagger, ReDoc or OpenAPI page:
this file is the reference. From Python, `GatewayClient` in the SDK ([SDK.md](SDK.md)) wraps these routes, and
`Harpo` runs the same engine with no server.

**Stable** from 2.5.0, under semantic versioning:

- the routes, methods and authorization on this page;
- the request fields and response fields it names;
- the `X-Harpo-*` headers;
- the error shapes, their `type` values and `error.harpo.code`.

A minor version can add response fields, so ignore the ones you do not know.

**Not part of the API:**

- the wording of messages: match on `type` and codes;
- the nested contents of the display payloads `/v1/system`, `/v1/stats`, `/v1/diagnostics`, `/v1/attention` and
  `/v1/lab/detect` (their top-level fields are stable);
- the console's own files;
- the Python modules behind the routes.

## Conventions

- **Base URL.** The default is `http://127.0.0.1:8080` (`server.host`, `server.port`). The gateway speaks HTTPS when
  `server.tls_certfile` and `server.tls_keyfile` are set; otherwise put it behind your TLS-terminating proxy.
  - OpenAI SDKs take `<base>/v1`; Anthropic SDKs take `<base>`.
  - Clients built for OpenRouter can use `/api/v1/...` for the four provider routes. It is the same handler.
- **Bodies** are JSON objects (`content-type: application/json`). The exception is `POST /v1/documents/redact`,
  whose body is the file itself.
- **Limits.** Any of these over the limit gives `413 request_too_large`:
  - `server.max_body_bytes` (2,000,000 bytes) per request;
  - `server.max_messages` (256) messages or texts;
  - `server.max_total_chars` (200,000) characters of text;
  - documents: `documents.max_bytes` (20,000,000 bytes).
- **Every response carries:**
  - `X-Harpo-Request-Id`, which the audit log records for the request;
  - security headers: `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, a
    strict `Content-Security-Policy`, and `Cache-Control: no-store` unless the route sets its own;
  - HSTS, when `server.hsts` is on.

## Authentication

`/healthz`, `/readyz`, `/metrics` and the console's static files need no key. Every `/v1/` route needs a gateway key.

- **Sending the key.** Use `Authorization: Bearer <key>` or `x-api-key: <key>`. Both work on every route, so OpenAI
  and Anthropic SDKs work unchanged.
- **What a key is.** A gateway key is `harpo_` followed by 43 random characters. The configuration stores only its
  SHA-256 (`auth.keys`). Make one with `harpo hash-key`, `POST /v1/keys/generate` or the SDK's `generate_key()`.
- **Key settings:**
  - `admin` opens the control plane, the routes marked *admin* below;
  - `can_override` lets the key use `X-Harpo-Override` when `policy.override: listed_keys`;
  - `expires_at`;
  - `requests_per_minute`, counted per gateway process.
- **Refusals:**
  - a missing, unknown or expired key: `401 authentication_error`;
  - a key over its rate: `429 rate_limit_error`, with `Retry-After`;
  - a key without `admin` on an admin route: `403 permission_error`.
- **Without authentication.** With `auth.enabled: false` every caller is anonymous and treated as an admin. That is
  for development: a production configuration with it refuses to start.
- **Provider keys** never come from clients. The gateway reads them from the environment (`upstreams[].api_key_env`)
  and adds them to the request it forwards.

### Request headers

| Header | Routes | Effect |
| --- | --- | --- |
| `X-Harpo-Mode: relational` or `generic` | provider routes, documents | Placeholders numbered per value (`[PERSON_1]`) or plain (`[PERSON]`). Honoured when `policy.client_may_choose_mode` is true (the default), ignored otherwise. Any other value: 400. |
| `X-Harpo-Context-Repair: true` or `false` | provider routes, documents | In generic mode, tells two values of one type apart inside a sentence (`[PERSON_A]`, `[PERSON_B]`). The same rule as the mode. |
| `X-Harpo-Override: true` | provider routes, documents | A request whose only blocks are overridable types goes on with those values redacted. This works if `policy.override` lets this key: `listed_keys` means keys with `can_override`; `any_key` means any key; `never` means no key. It never sends a raw value, and blocks by egress verification or a budget cannot be overridden. |
| `X-Harpo-Filename` | documents | The file's name, percent-encoded. It travels in a header because proxies log URLs. |
| `X-Harpo-Response: file` or `json` | documents | What comes back (also `?response=`). With `json`, `?file=false` leaves the file out. |
| `anthropic-version`, `anthropic-beta` | Anthropic routes | Forwarded to the provider. |

### Response headers

| Header | Routes | Meaning |
| --- | --- | --- |
| `X-Harpo-Request-Id` | every response | The id of this request in the audit log. |
| `X-Harpo-Risk` | provider routes, documents | `green`, `yellow` (went on, with an advisory) or `red` (blocked). |
| `X-Harpo-Redactions`, `X-Harpo-Mode` | provider routes, documents | How many values were replaced, and the placeholder mode used. |
| `X-Harpo-Response-Scan` | provider routes, when `policy.response_scan` is on | `report`, `redact`, or `not_scanned_stream` for a streamed answer. |
| `X-Harpo-Response-Findings` | the same, non-streamed answers | How many values the deterministic layers found in the answer. |
| `X-Harpo-Document`, `X-Harpo-Segments`, `X-Harpo-Verified` | documents | The kind of file, the number of text segments, and whether the returned file was verified. |

From the provider, only these headers are passed on: `content-type`, `retry-after`, `request-id`, `x-request-id`,
`openai-processing-ms`, `openai-version`, `x-ratelimit-*` and `anthropic-ratelimit-*`.

## Errors

Every route answers errors in OpenAI's shape, except `/v1/messages` and `/v1/messages/count_tokens`, which use
Anthropic's. Provider SDKs therefore raise their usual exceptions. `error.harpo` holds Harpo's details when there are
any.

```json
{"error": {"message": "Request blocked by privacy policy. See error.harpo.reasons.", "type": "privacy_block",
           "param": null, "code": "privacy_block", "harpo": {"risk": "red", "blocked_types": ["US_SSN"], "...": "..."}}}
```

```json
{"type": "error", "error": {"type": "privacy_block",
                            "message": "Request blocked by privacy policy. See error.harpo.reasons.",
                            "harpo": {"risk": "red", "blocked_types": ["US_SSN"], "...": "..."}}}
```

| Status | `type` | When |
| --- | --- | --- |
| 400 | `invalid_request_error` | Not a JSON object; a field the adapter does not inspect (`policy.unknown_fields: reject` names its path, never its value); a request shape it does not support; a bad header value |
| 401 | `authentication_error` | Missing, unknown or expired gateway key |
| 403 | `permission_error` | An admin route with a key that is not admin |
| 403 | `privacy_block` | The policy blocks the content. `error.harpo` holds `risk`, `overridable`, `override_permitted`, `blocked_types` and `reasons` |
| 403 | `model_not_allowed`, `routing_policy` | No upstream allows this model, or a field or plugin the configuration does not allow; OpenRouter routing it does not allow |
| 404 | `not_found_error`, `not_found` | No such route or upstream; document redaction switched off |
| 409 | `conflict_error` | `POST /v1/keys/generate` with an id that exists |
| 409 | `live_policy_read_only` | The live policy cannot be saved. `error.harpo` holds the YAML to paste into the configuration instead |
| 413 | `request_too_large` | A size limit, above |
| 413, 415, 422, 500, 503, 504 | `document_error` | `error.harpo.code` says why, below |
| 422 | `invalid_request_error` | A live policy that is not valid. `error.harpo.errors` lists setting paths and messages |
| 429 | `rate_limit_error` | Over the key's `requests_per_minute`; see `Retry-After` |
| 502 | `upstream_error` | The provider could not be reached, timed out, redirected (redirects are never followed) or sent too much |
| 503 | `not_ready` | A required detection layer, the local SLM with `on_failure: fail_closed`, is unavailable |

`document_error` codes by status:

- 413: `too_large`, `too_many_characters`, `too_many_segments`, `too_many_pages`, `page_too_large`, `zip_bomb`.
- 415: `unsupported_format`, `legacy_office`, `format_disabled`.
- 422: a file Harpo refuses to inspect, for example `encrypted`, `macros`, `uninspectable_pages` or `corrupt`.
- 500: `residual_sensitive_data`, `verify_failed`. The redacted file still held detectable data or failed
  re-verification, so it was not released.
- 503: `busy`, `worker_crashed`, `worker_limit`.
- 504: `timeout`.

No error message quotes request content. Messages name types, counts, field paths and codes.

**Reasons.** `reasons` appear in scan results and in `error.harpo`. Each is `{code, level, message, entity_type,
count, overridable}`.

- Red codes block the request: `blocked_entity`, `unsupported_content`, `scan_budget`, `slm_unavailable`,
  `egress_verification` and `remote_tools`.
- Yellow codes let it go on with an advisory: `keys_redacted`, `override_applied`, `content_dropped`,
  `hidden_characters`, `mixed_script`, `collapsed_sentences`, `context_rot` and `slm_degraded`.

## Provider routes

| Method and path | Authorization | Purpose |
| --- | --- | --- |
| `POST /v1/chat/completions` | any key | OpenAI Chat Completions. Forwarded to the configured upstream of that style whose `models` match `model`: OpenAI, Gemini's OpenAI-compatible API, OpenRouter, Mistral, Groq, DeepSeek or Ollama. |
| `POST /v1/messages` | any key | Anthropic Messages, to an Anthropic-style upstream (Anthropic, or OpenRouter's Anthropic-compatible API). |
| `POST /v1/messages/count_tokens` | any key | Anthropic's token count. It applies the same scan and redaction as the message itself. |
| `GET /v1/models` | any key | The models a client may use. The list is OpenAI's shape, or Anthropic's when the request carries `anthropic-version`. Patterns such as `claude-*` are not listed. Upstreams with `list_models: upstream` (OpenRouter by default) add the provider's matching models. |

These are the only provider routes. The Responses API, legacy completions, embeddings, images, audio, files and batch
routes do not exist (404).

**What happens to a request, in order:**

1. The key is checked.
2. `model` must match an upstream's `models`; otherwise `403 model_not_allowed`.
3. Fields the adapter does not inspect are refused (400). With `policy.unknown_fields: pass` they are scanned as text
   instead.
4. Files attached to chat messages go through document redaction when `documents.in_chat` is on. Otherwise they
   count as content Harpo cannot read.
5. Every text surface the adapter declares is collected: messages, system prompts, tool definitions, tool calls and
   tool results.
   - Content Harpo cannot read (images, audio, unknown content parts) is blocked (`unsupported_content`), or dropped
     with a visible marker under `policy.unsupported_content: drop`.
   - Remote MCP servers are blocked unless `policy.remote_mcp: allow`.
6. One scan covers all of it. A type the policy blocks stops the request (`403 privacy_block`). Everything else found
   becomes a placeholder; API keys, tokens, passwords and private keys always do (INV-11).
7. **Egress verification.** The whole outgoing body, values and keys, is scanned again by the deterministic layers.
   Anything still found blocks the request (`privacy_block`, reason `egress_verification`).
8. The request is forwarded with the provider key. The answer comes back with the placeholders, since nothing maps
   them back to values.

**Streaming.** `"stream": true` works on both APIs. The request goes through every step above before anything is
sent. The provider's event stream is then relayed as it arrives, up to `upstream.max_response_bytes`.

**Responses.** A streamed answer is not scanned. When `policy.response_scan` is on, a non-streamed answer goes
through the deterministic layers:

- `report` counts what they find in `X-Harpo-Response-Findings`;
- `redact` also replaces those values with plain labels such as `[EMAIL]`.

`response_scan` is off by default.

## Harpo's routes

Each entry gives the authorization, the purpose, the request and response fields that matter, notes, and the SDK
equivalent.

### Scan: `POST /v1/scan`

- **Authorization:** any key.
- **Purpose:** redact text without forwarding it, for batch jobs, pipelines and the console.
- **Request:**
  - `text` or `texts`: exactly one of them;
  - `mode` and `context_repair`: honoured when `policy.client_may_choose_mode`;
  - `layers`: `full` (the default) or `fast` (without the local SLM);
  - `override`: under the key's override rule.
- **Response:**
  - `request_id`, `risk`, `overridable`, `reasons`, `mode`, `context_repair`, `layers`;
  - `results`: one per input, each `{redacted, entities: [{type, start, end, placeholder, sources}]}`;
  - `counts`, `redactions`, `rot_score`, `flags`, `slm`, `timings_ms`.
- **Notes:**
  - It answers 200 also when the policy blocks: check `risk` (`red`) before using `redacted`.
  - Several `texts` share placeholders, the way the messages of one request do.
  - Offsets index the text you sent. A finding never carries the value.
- **SDK:** `GatewayClient.scan()`, or `Harpo.scan()` in-process.

```bash
curl -s localhost:8080/v1/scan -H "authorization: Bearer $HARPO_KEY" -H "content-type: application/json" \
  -d '{"text": "Mail jane.doe@example.com about card 4111 1111 1111 1111"}'
```

```json
{
  "request_id": "5d08aca63e214ce7b3d05246fbca8c9b",
  "risk": "green",
  "reasons": [],
  "mode": "relational",
  "results": [
    {
      "redacted": "Mail [EMAIL_1] about card [CREDIT_CARD_1]",
      "entities": [
        {"type": "EMAIL", "start": 5, "end": 25, "placeholder": "[EMAIL_1]", "sources": ["pattern"]},
        {"type": "CREDIT_CARD", "start": 37, "end": 56, "placeholder": "[CREDIT_CARD_1]",
         "sources": ["cue:card", "cue:card-shape", "pattern"]}
      ]
    }
  ],
  "counts": {"EMAIL": 1, "CREDIT_CARD": 1},
  "redactions": 2
}
```

(Trimmed: the full answer also has `overridable`, `context_repair`, `layers`, `rot_score`, `flags`, `slm` and
`timings_ms`.)

### Documents: `POST /v1/documents/redact`

- **Authorization:** any key. It needs `documents.enabled` (on by default).
- **Purpose:** a file in, a redacted file out: PDF, Word, Excel, PowerPoint and text files.
- **Request:**
  - the body is the file;
  - `X-Harpo-Filename`;
  - optionally `Content-Type`, `X-Harpo-Response` and `?file=false`;
  - the mode and override headers.
- **Response:**
  - **By default, the redacted file**, as an attachment named `<name>.redacted.<ext>`, with `X-Harpo-Document`,
    `X-Harpo-Segments` and `X-Harpo-Verified`.
  - **With `json`:** `request_id`, `risk`, `kind`, `overridable`, `reasons`, `mode`, `counts`, `redactions`,
    `segments`, `info`, `text` (the redacted document as readable text), `verified` and `file`. `file` is
    `{filename, content_type, base64}`, or `null`.
- **Notes:**
  - Every file is re-opened and re-scanned before it is released (INV-09); `verified` reports it.
  - With `file=false` no file is made, so `verified` is false.
  - A blocked document gives `403 privacy_block`; a refused one gives `document_error` with its code.
- **SDK:** `GatewayClient.redact_document()`, or `Harpo.redact_document()`.

```bash
curl -s localhost:8080/v1/documents/redact -H "authorization: Bearer $HARPO_KEY" \
  -H "x-harpo-filename: contract.docx" --data-binary @contract.docx -o contract.redacted.docx
```

### Policy: `GET /v1/policy`

- **Authorization:** any key.
- **Purpose:** the policy requests are scanned with, as clients and the console see it.
- **Response:**
  - `version`, `default_mode`, `context_repair`, `client_may_choose_mode`;
  - `entities`: `{TYPE: {action, overridable}}`;
  - `always_redacted`: the credential types;
  - `custom_types`: name, description, action, and how many terms and patterns, never the terms themselves;
  - `live_policy`, `override_permitted`, `admin`;
  - `unknown_fields`, `unsupported_content`, `remote_mcp`, `egress_verification`, `response_scan`;
  - `upstreams`, `models`, `documents`, `limits`.
- **SDK:** `GatewayClient.policy()`, or `Harpo.policy`.

### Live policy (admin)

These routes change the policy on every worker without a restart. The change is saved to `policy.live_file`, and the
audit log records it with the key's id.

- `GET /v1/policy/live`: each type's action now and in the configuration, the custom types with their terms and
  patterns (this is the editor), the detector families, the file, and whether it is editable.
- `PUT /v1/policy/live` takes this body:

  ```json
  {"entities": {"US_SSN": "block"},
   "custom_types": [{"name": "EMPLOYEE_ID", "patterns": ["\\bEMP-\\d{6}\\b"]}],
   "detectors": {"identifiers.addresses": false}}
  ```

  `custom_types: null` keeps the configuration's. The same rules as the configuration file check it, and credential
  types cannot be named, because they are always redacted. Without a writable `live_file` it answers `409
  live_policy_read_only`.
- `DELETE /v1/policy/live`: back to the configuration file alone.
- `POST /v1/policy/preview`: `{"text": "...", "policy": {...}}`, where `text` is 1 to 20,000 characters and `policy`
  is optional. It answers `text`, `risk`, `blocked`, `findings`, `reasons` and `counts` under the draft. Nothing is
  sent, saved or recorded.
- **SDK:** `GatewayClient.live_policy()`, `.set_live_policy()`, `.reset_live_policy()` and `.preview_policy()`, or
  `Harpo.with_policy()`.

### Egress preview: `POST /v1/egress/preview`

- **Authorization:** any key.
- **Purpose:** exactly what the proxy would send for a provider request, without sending it. It runs the same code
  path as the proxy.
- **Request:** `{"style": "openai" | "anthropic", "body": {...}}`, where `body` is the provider request.
- **Response, when the request would go on:**
  - `decision: "would_forward"`;
  - `upstream`: `{name, url}`;
  - `auth`: the header and the environment variable the key comes from, never the key;
  - `body`: the sanitized request, byte for byte what would leave;
  - `risk`, `redactions`, `counts`, `mode`, `reasons`, `timings_ms`, `slm`, `egress_verification`.
- **Response, when the proxy would refuse:** `{decision, status, message, details}`, the error the proxy would
  answer.
- **SDK:** `GatewayClient.preview_egress()`.

```json
{"decision": "would_forward", "style": "openai",
 "upstream": {"name": "openai", "url": "https://api.openai.com/v1/chat/completions"},
 "body": {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Mail [EMAIL_1]"}]},
 "risk": "green", "redactions": 1, "counts": {"EMAIL": 1}, "egress_verification": "full"}
```

(Trimmed: the full answer also has `auth`, `mode`, `reasons`, `timings_ms` and `slm`.)

### Detection trace: `POST /v1/lab/detect`

- **Authorization:** any key.
- **Purpose:** one sample through the detection stages, each stage's findings apart. This is the console's detector
  lab.
- **Request:** `{"text": "..."}`, up to 20,000 characters.
- **Response:** `normalized`, `shadow_views`, `layers`, `slm`, `final`, `timings_ms`.
- **Notes:** the answer contains your text. Nothing is stored, logged or counted.
- **SDK:** `GatewayClient.trace()`, or `Harpo.trace()`.

### Configuration (admin)

- `GET /v1/config/effective` answers `config` and `yaml`: the configuration in force, live policy included. Key
  hashes are shortened, and registry lists, allow terms and custom terms and patterns are reduced to counts.
- `POST /v1/config/validate` takes `{"yaml": "..."}` (up to 512 kB). It answers:
  - `valid`;
  - `saved`, always false: nothing is saved or applied;
  - `errors`: `[{path, line, message}]`;
  - `problems`: the reasons a production configuration would refuse to start;
  - `diff`: against the running configuration.
- `GET /v1/config/analysis` answers `findings` and `counts`. Each finding is `{id, level, title, detail, setting,
  current, suggested, invariant}`, with `level` one of `required`, `recommended` or `info`.
- **SDK:** `GatewayClient.effective_config()`, `.validate_config()` and `.config_analysis()`, or `validate_config()`
  and `Harpo.analyze()`.

### Providers and presets (admin)

- `GET /v1/providers` answers `providers`. Each has `name`, `style`, `base_url`, `models`, `key_env`, `key_present`,
  `dialect`, `auth_scheme`, `timeout_s`, `max_connections`, `max_response_bytes` and `traffic`. No key values.
- `POST /v1/providers/{name}/check` is a connection test that sends no content: it lists the provider's models with
  the configured key (for OpenRouter it asks the key endpoint). It answers `name`, `reachable`, `status`,
  `latency_ms`, `auth` (`accepted`, `rejected`, `not confirmed` or `not needed`) and `error`.
- `GET /v1/setup/presets` answers `providers`: the presets `harpo init` and the setup wizard offer. Each has `id`,
  `style`, `base_url`, `key_env`, `models` and `companions`.
- **SDK:** `GatewayClient.providers()`, `.check_provider()` and `.presets()`.

### Keys (admin)

- `GET /v1/keys` answers `auth_enabled`, `override_policy` and `keys`. Each key has `id`, `fingerprint` (the first 8
  hex digits of its hash), `admin`, `can_override`, `expires_at`, `expired`, `requests_per_minute`, `requests` and
  `last_seen`.
- `POST /v1/keys/generate` takes `{"id": "ci-bot", "admin": false, "can_override": false, "expires_at": null,
  "requests_per_minute": 60}`. It answers `key` (shown once), `sha256`, `yaml` (the `auth.keys` entry) and
  `persisted: false`. Nothing is stored: add the entry to the configuration. An id that exists gives 409.
- **SDK:** `GatewayClient.list_keys()` and `.generate_key()`, or `generate_key()` with no gateway.

### Status, activity and self-test

| Method and path | Authorization | Response |
| --- | --- | --- |
| `GET /v1/system` | admin | `version`, `python`, `environment`, `uptime_s`, `workers`, `readiness`, `detection` (rules, the detection library, NER and SLM settings), `documents`, `upstreams` (no keys), `limits` |
| `GET /v1/stats?recent=60` | any key | Activity with no content: `totals`, `decisions`, `routes`, `by_type`, `by_reason`, `latency_ms`, `stages`, `upstreams`, `documents`, `recent`, `series`, `slm_states`, `response_findings`, `layers`. `scope` is `all` for admin keys and `key` for the others, who see their own requests only |
| `GET /v1/events` | any key | Server-sent events of the same records as they happen (`event: request`). Admin keys also get `event: posture` |
| `GET /v1/attention` | admin | `posture`, `evaluated_at`, `items` (conditions to act on: `id`, `severity`, `subsystem`, `title`, `detail`, `action`), `timeline` |
| `GET /v1/diagnostics` | admin | A bundle for issue reports, with no content. It lists what it `includes` and `excludes` |
| `POST /v1/selftest` | admin | Canaries through the live request path; nothing is sent or recorded. `results` (`[{id, status, detail}]` for INV-01, -04, -06, -07, -08, -09 with documents on, -10 and -11), `passed`, `ran_at` |
| `POST /v1/selftest/suites` | admin | `{"suites": [...]}`, optional. `suites` (`[{id, name, kind, status, tests, ms}]`, where `kind` is `local`, `config` or `live`: gateway, detection, secrets, egress, adapters, headers, configuration, documents, providers, slm), `passed`, `ran_at` |

SDK: `GatewayClient.system()`, `.stats()`, `.attention()`, `.diagnostics()`, `.selftest()`, `.selftest_suites()`;
`Harpo.status()` in-process.

### Operations, no key

| Method and path | Purpose |
| --- | --- |
| `GET /healthz` | Liveness: `{"status": "ok", "version": "2.5.0"}` |
| `GET /readyz` | Readiness: 200 `{"status": "ready", "checks": {...}}` or 503 `not_ready`. NER must be loaded, the SLM reachable when it is required, and the provider keys present (in production) |
| `GET /metrics` | Prometheus text when `server.metrics` is on (the default): `harpo_requests_total`, `harpo_redactions_total`, `harpo_blocks_total`, `harpo_stage_seconds`, `harpo_upstream_responses_total`, `harpo_slm_outcomes_total`. Counts and timings only; restrict it to your monitoring network |
| `GET /`, `GET /console/...` | The console when `server.console` is on: static files only. The console calls the API above with a gateway key |

SDK: `GatewayClient.health()` and `.ready()`.

## See also

- [GUIDE.md](GUIDE.md): configuration, production deployment and operations.
- [SDK.md](SDK.md): the same capabilities from Python.
- [integrations](integrations/README.md): each client and provider, set up.
- [INVARIANTS.md](INVARIANTS.md) and [THREAT_MODEL.md](THREAT_MODEL.md): what the gateway guarantees, and what it
  does not.
