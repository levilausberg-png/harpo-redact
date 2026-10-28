# Zed

*Coding agents* · configured per the vendor documentation

Zed's assistant can use any OpenAI-compatible endpoint.

1. Paste the settings, then enter `$HARPO_KEY` as the OpenAI key in the Agent panel's settings.

**settings.json**

```json
{
  "language_models": {
    "openai": {
      "api_url": "http://localhost:8080/v1",
      "available_models": [{ "name": "gpt-4o-mini", "display_name": "gpt-4o-mini via Harpo", "max_tokens": 128000 }]
    }
  }
}
```

Vendor documentation: https://zed.dev/docs/ai/configuration

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
