# OpenRouter

*Providers* · configured per the vendor documentation

Hundreds of models behind one key, through both the OpenAI and the Anthropic API. The gateway enforces OpenRouter's privacy routing on every request: only providers that do not store prompts, optionally zero-data-retention endpoints only.

1. Start with `boot.cmd` (Windows) or `./boot.sh` and choose `openrouter`, or run `harpo init --provider openrouter`. Both configure the OpenAI-style API and the Anthropic-style API that Claude Code uses.
2. Point clients at the gateway as usual. OpenRouter-native clients and SDKs can use `http://localhost:8080/api/v1`.
3. Use OpenRouter's model names (`anthropic/claude-sonnet-5.5`). `GET /v1/models` lists the OpenRouter models your config allows.

**Config**

```yaml
upstreams:
  - name: openrouter
    style: openai
    base_url: https://openrouter.ai/api/v1
    api_key_env: OPENROUTER_API_KEY
    models: ["anthropic/*", "openai/*", "google/*"]
    openrouter:
      data_collection: deny   # enforced: only providers that do not store prompts
      zdr: true               # optional: zero-data-retention endpoints only
  - name: openrouter-messages # the Anthropic-style API (Claude Code)
    style: anthropic
    base_url: https://openrouter.ai/api
    api_key_env: OPENROUTER_API_KEY
    models: ["*"]
```

**Shell**

```bash
export OPENROUTER_API_KEY=sk-or-...
harpo serve --config config/harpo.yaml
```

**Python**

```python
from openai import OpenAI

client = OpenAI(base_url="http://localhost:8080/v1", api_key="$HARPO_KEY")
reply = client.chat.completions.create(
    model="anthropic/claude-sonnet-5.5",
    messages=[{"role": "user", "content": "Hello"}],
    extra_body={"provider": {"sort": "price"}},  # data_collection is set by the gateway
)
```

> **Note.** Clients can tighten routing (zdr, only, ignore) but never loosen it: a request asking for providers that store data is rewritten to `data_collection: deny`. Fallback lists (`models`, `fallbacks`) must name models this upstream allows; router plugins (auto-router, fusion) are accepted only when it allows any model.

> **Note.** The connection test on Providers & adapters uses OpenRouter's key endpoint and shows the key's remaining limit and spend: OpenRouter lists models to anyone, so a model listing proves nothing about the key.

> **Caution.** OpenRouter's web search and server tools run at OpenRouter, on the sanitized request. Generated images and other attachments are refused (`policy.unsupported_content`).

Vendor documentation: https://openrouter.ai/docs/api/reference

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
