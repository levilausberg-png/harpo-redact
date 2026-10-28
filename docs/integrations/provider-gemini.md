# Google Gemini

*Providers* · configured per the vendor documentation

Gemini through Google's OpenAI-compatible endpoint.

**Set up**

```bash
harpo init --provider gemini
export GEMINI_API_KEY=...
harpo serve --config config/harpo.yaml
```

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
