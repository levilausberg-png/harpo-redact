# Anthropic

*Providers* · configured per the vendor documentation

Claude models, including for Claude Code.

**Set up**

```bash
harpo init --provider anthropic
export ANTHROPIC_API_KEY=sk-ant-...
harpo serve --config config/harpo.yaml
```

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
