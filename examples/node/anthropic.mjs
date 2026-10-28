// Anthropic SDK for TypeScript/JavaScript through Harpo.
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic({ baseURL: process.env.HARPO_URL ?? "http://127.0.0.1:8080", apiKey: process.env.HARPO_KEY ?? "demo" });
const message = await client.messages.create({
  model: process.env.HARPO_CLAUDE_MODEL ?? "demo-claude",
  max_tokens: 512,
  messages: [{ role: "user", content: "Refund Priya Raman, IBAN NL91ABNA0417164300" }],
});
console.log(message.content[0].text);
