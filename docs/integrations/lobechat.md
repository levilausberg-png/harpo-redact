# LobeChat

*Chat apps* · configured per the vendor documentation

A polished chat app with plugins. Set its OpenAI proxy URL to the gateway.

**Environment**

```bash
OPENAI_PROXY_URL=http://localhost:8080/v1
OPENAI_API_KEY=$HARPO_KEY
```

> **Note.** Running it in Docker? Inside a container `localhost` is the container itself: use `http://host.docker.internal:8080/v1` (Docker Desktop) or the gateway's service name, or use `docker compose --profile chat up`, which wires Open WebUI to the gateway for you.

Vendor documentation: https://lobehub.com/docs

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
