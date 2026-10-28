# Anthropic SDK for TypeScript

*SDKs* · verified end to end against the gateway

The Anthropic client for JavaScript and TypeScript.

**TypeScript**

```ts
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic({ baseURL: "http://localhost:8080", apiKey: "$HARPO_KEY" });
const message = await client.messages.create({
  model: "claude-sonnet-5-5",
  max_tokens: 1024,
  messages: [{ role: "user", content: "Email jane.doe@acme.com about her refund" }],
});
console.log(message.content);
```

**Environment**

```bash
export ANTHROPIC_BASE_URL=http://localhost:8080
export ANTHROPIC_API_KEY=$HARPO_KEY
```

Vendor documentation: https://github.com/anthropics/anthropic-sdk-typescript

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
