# OpenAI

*Providers* · configured per the vendor documentation

GPT models. Your OpenAI key stays on the gateway; apps only ever hold a gateway key.

**Set up**

```bash
harpo init --provider openai
export OPENAI_API_KEY=sk-...
harpo serve --config config/harpo.yaml
```

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
