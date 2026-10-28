# curl and plain HTTP

*SDKs* · verified end to end against the gateway

Any language with an HTTP client: the request shape is OpenAI's or Anthropic's.

**OpenAI style**

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $HARPO_KEY" -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Email jane.doe@acme.com"}]}'
```

**Anthropic style**

```bash
curl http://localhost:8080/v1/messages \
  -H "x-api-key: $HARPO_KEY" -H "anthropic-version: 2023-06-01" -H "Content-Type: application/json" \
  -d '{"model": "claude-sonnet-5-5", "max_tokens": 256, "messages": [{"role": "user", "content": "Email jane.doe@acme.com"}]}'
```

**Scan only**

```bash
curl http://localhost:8080/v1/scan -H "Authorization: Bearer $HARPO_KEY" -H "Content-Type: application/json" \
  -d '{"text": "Email jane.doe@acme.com, card 4111 1111 1111 1111"}'
```

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway. Every route,
header and error is in [API.md](../API.md).
