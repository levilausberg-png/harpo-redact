// OpenAI SDK for Node through Harpo. `npm install`, then `node openai.mjs`.
import OpenAI from "openai";

const base = process.env.HARPO_URL ?? "http://127.0.0.1:8080";
const client = new OpenAI({ baseURL: `${base}/v1`, apiKey: process.env.HARPO_KEY ?? "demo" });
const reply = await client.chat.completions.create({
  model: process.env.HARPO_MODEL ?? "demo-gpt",
  messages: [{ role: "user", content: "Email jane.doe@acme.com about card 4111 1111 1111 1111" }],
});
console.log(reply.choices[0].message.content);
