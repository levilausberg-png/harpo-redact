# Mistral, Groq, DeepSeek

*Providers* · configured per the vendor documentation

OpenAI-compatible providers with presets: --provider mistral, groq or deepseek.

**Set up**

```bash
harpo init --provider mistral
export MISTRAL_API_KEY=...
harpo serve --config config/harpo.yaml
```

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
