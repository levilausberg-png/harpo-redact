// Vercel AI SDK through Harpo. Use .chat(): the gateway proxies Chat Completions.
import { createOpenAI } from "@ai-sdk/openai";
import { generateText, streamText } from "ai";

const harpo = createOpenAI({ baseURL: `${process.env.HARPO_URL ?? "http://127.0.0.1:8080"}/v1`, apiKey: process.env.HARPO_KEY ?? "demo" });
const model = harpo.chat(process.env.HARPO_MODEL ?? "demo-gpt");
const { text } = await generateText({ model, prompt: "Email jane.doe@acme.com about her refund" });
console.log(text);
const stream = streamText({ model, prompt: "Call +31 20 794 6095 tomorrow" });
let streamed = "";
for await (const part of stream.textStream) streamed += part;
console.log(streamed);
