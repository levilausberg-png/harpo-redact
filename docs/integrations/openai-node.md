# OpenAI SDK for Node

*SDKs* · verified end to end against the gateway

The same in JavaScript and TypeScript.

**TypeScript**

```ts
import OpenAI from "openai";

const client = new OpenAI({ baseURL: "http://localhost:8080/v1", apiKey: "$HARPO_KEY" });
const reply = await client.chat.completions.create({
  model: "gpt-4o-mini",
  messages: [{ role: "user", content: "Email jane.doe@acme.com about her refund" }],
});
console.log(reply.choices[0].message.content);
```

**Environment**

```bash
export OPENAI_BASE_URL=http://localhost:8080/v1
export OPENAI_API_KEY=$HARPO_KEY   # the gateway key; your provider key stays on the gateway
```

Vendor documentation: https://github.com/openai/openai-node

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
