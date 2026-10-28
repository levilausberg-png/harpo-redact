# n8n

*Automation* · configured per the vendor documentation

Workflow automation. The OpenAI credential has a Base URL field.

1. Credentials → New → **OpenAI**.
2. API key `$HARPO_KEY`, Base URL `http://localhost:8080/v1`.
3. Use the credential in the OpenAI Chat Model or AI Agent nodes.

> **Note.** Running it in Docker? Inside a container `localhost` is the container itself: use `http://host.docker.internal:8080/v1` (Docker Desktop) or the gateway's service name, or use `docker compose --profile chat up`, which wires Open WebUI to the gateway for you.

Vendor documentation: https://docs.n8n.io/integrations/builtin/credentials/openai/

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
