# Dify, Flowise and other builders

*Automation* · configured per the vendor documentation

Add an OpenAI-API-compatible model provider with the gateway's base URL.

1. Add a model provider of type **OpenAI-API-compatible**.
2. Base URL `http://localhost:8080/v1`, API key `$HARPO_KEY`, model `gpt-4o-mini`.

> **Note.** Running it in Docker? Inside a container `localhost` is the container itself: use `http://host.docker.internal:8080/v1` (Docker Desktop) or the gateway's service name, or use `docker compose --profile chat up`, which wires Open WebUI to the gateway for you.

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
