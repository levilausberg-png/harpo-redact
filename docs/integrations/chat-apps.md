# ChatGPT, Claude and Gemini apps

*Chat apps* · configured per the vendor documentation

The consumer apps send what you type straight to their own servers and have no setting to change that, so no proxy, this one included, can sit in front of them. Use the same models privately through a chat app you control.

1. Open the built-in playground at `http://localhost:8080/#/playground` to chat with any configured model through the gateway.
2. Or run Open WebUI or LibreChat (below): a ChatGPT-style app where every message passes through the gateway.
3. Configure the provider once on the gateway (`harpo init --provider openai`, `anthropic`, `gemini` or `openrouter`).

> **Note.** A browser extension that checks what you paste into chatgpt.com or claude.ai against this gateway is on the roadmap. Until then, the apps above are the private route.

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
