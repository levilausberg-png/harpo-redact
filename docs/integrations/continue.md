# Continue

*Coding agents* · configured per the vendor documentation

The open-source IDE assistant for VS Code and JetBrains. Set apiBase on any model.

**config.yaml**

```yaml
models:
  - name: gpt-4o-mini via Harpo
    provider: openai
    model: gpt-4o-mini
    apiBase: http://localhost:8080/v1
    apiKey: $HARPO_KEY
  - name: Claude via Harpo
    provider: anthropic
    model: claude-sonnet-5-5
    apiBase: http://localhost:8080/v1
    apiKey: $HARPO_KEY
```

Vendor documentation: https://docs.continue.dev/

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
