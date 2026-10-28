# LibreChat

*Chat apps* · configured per the vendor documentation

A multi-provider chat app. Add the gateway as a custom endpoint; models are listed from the gateway's /v1/models.

**librechat.yaml**

```yaml
endpoints:
  custom:
    - name: "Harpo"
      apiKey: "${HARPO_KEY}"
      baseURL: "http://localhost:8080/v1"
      models:
        default: ["gpt-4o-mini"]
        fetch: true
      titleConvo: true
      titleModel: "current_model"
```

> **Note.** Running it in Docker? Inside a container `localhost` is the container itself: use `http://host.docker.internal:8080/v1` (Docker Desktop) or the gateway's service name, or use `docker compose --profile chat up`, which wires Open WebUI to the gateway for you.

Vendor documentation: https://www.librechat.ai/docs/configuration/librechat_yaml

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
