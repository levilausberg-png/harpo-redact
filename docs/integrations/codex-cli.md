# OpenAI Codex CLI

*Coding agents* · configured per the vendor documentation

Add the gateway as a model provider in ~/.codex/config.toml, using the Chat Completions wire API.

**config.toml**

```toml
model = "gpt-4o-mini"
model_provider = "harpo"

[model_providers.harpo]
name = "Harpo"
base_url = "http://localhost:8080/v1"
env_key = "HARPO_API_KEY"
wire_api = "chat"
```

**Shell**

```bash
export HARPO_API_KEY=$HARPO_KEY
codex
```

> **Note.** The gateway proxies Chat Completions and Anthropic Messages; the OpenAI Responses API is on the roadmap, hence `wire_api = "chat"`.

Vendor documentation: https://github.com/openai/codex/blob/main/docs/config.md

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
