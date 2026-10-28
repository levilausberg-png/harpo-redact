# Claude Code

*Coding agents* · configured per the vendor documentation

Anthropic's coding agent reads ANTHROPIC_BASE_URL. Your code, logs and secrets are sanitized before they reach the model.

**Shell**

```bash
export ANTHROPIC_BASE_URL=http://localhost:8080
export ANTHROPIC_AUTH_TOKEN=$HARPO_KEY
claude
```

> **Note.** Through OpenRouter: configure the `openrouter-messages` upstream (the boot scripts do it), keep `ANTHROPIC_BASE_URL=http://localhost:8080`, and set `ANTHROPIC_DEFAULT_SONNET_MODEL` (and the Opus and Haiku variants) to OpenRouter model names such as `anthropic/claude-sonnet-5.5`.

> **Caution.** Claude Code adopts new API fields early. If a request is refused with `Not inspected by the gateway`, the error names the field path: set `policy.unknown_fields: pass` to scan such fields as text, and open an issue so the adapter can declare it.

> **Note.** Screenshots you paste are images: blocked by default (`policy.unsupported_content`). Keys and passwords in files it reads arrive as `[SECRET_1]`: they are always redacted, and the request goes on.

Vendor documentation: https://docs.claude.com/en/docs/claude-code/llm-gateway

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
