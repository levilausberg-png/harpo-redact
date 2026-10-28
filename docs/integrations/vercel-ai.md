# Vercel AI SDK

*SDKs* · verified end to end against the gateway

Create a provider with the gateway's base URL. Use .chat(): the gateway proxies Chat Completions.

**TypeScript**

```ts
import { createOpenAI } from "@ai-sdk/openai";
import { generateText } from "ai";

const harpo = createOpenAI({ baseURL: "http://localhost:8080/v1", apiKey: "$HARPO_KEY" });
const { text } = await generateText({
  model: harpo.chat("gpt-4o-mini"),
  prompt: "Email jane.doe@acme.com about her refund",
});
console.log(text);
```

Vendor documentation: https://ai-sdk.dev/providers/ai-sdk-providers/openai

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
