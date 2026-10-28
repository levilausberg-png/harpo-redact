# Ollama (local models)

*Providers* · configured per the vendor documentation

Models on your own hardware. Useful for testing; local models do not need redaction to keep data in.

**Set up**

```bash
harpo init --provider ollama
harpo serve --config config/harpo.yaml
```

> **Note.** A local http upstream makes the config a development config: production requires https upstreams.

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
