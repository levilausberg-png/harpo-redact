# Open WebUI

*Chat apps* · configured per the vendor documentation

A self-hosted, ChatGPT-style interface. Point its OpenAI connection at the gateway and every chat is sanitized first.

**Docker**

```bash
docker run -d --name open-webui -p 3000:8080 \
  -e OPENAI_API_BASE_URL=http://localhost:8080/v1 \
  -e OPENAI_API_KEY=$HARPO_KEY \
  -e ENABLE_OLLAMA_API=false \
  -v open-webui:/app/backend/data \
  ghcr.io/open-webui/open-webui:main
```

**Compose profile**

```bash
# from this repository: gateway + Open WebUI, already wired together
docker compose --profile chat up -d
open http://localhost:3000
```

> **Note.** Running it in Docker? Inside a container `localhost` is the container itself: use `http://host.docker.internal:8080/v1` (Docker Desktop) or the gateway's service name, or use `docker compose --profile chat up`, which wires Open WebUI to the gateway for you.

Vendor documentation: https://docs.openwebui.com/

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
