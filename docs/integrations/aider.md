# Aider

*Coding agents* · configured per the vendor documentation

Pair programming in the terminal. Aider reads OPENAI_API_BASE.

**Shell**

```bash
export OPENAI_API_BASE=http://localhost:8080/v1
export OPENAI_API_KEY=$HARPO_KEY
aider --model openai/gpt-4o-mini
```

Vendor documentation: https://aider.chat/docs/llms/openai-compat.html

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
