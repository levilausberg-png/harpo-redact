# AnythingLLM

*Chat apps* · configured per the vendor documentation

Chat with your documents. Use the Generic OpenAI provider so both chats and the retrieved passages are sanitized.

1. Settings → AI Providers → LLM → **Generic OpenAI**.
2. Base URL: `http://localhost:8080/v1` · API key: `$HARPO_KEY` · Model: `gpt-4o-mini`.
3. Set the token context window to your model's.

Vendor documentation: https://docs.anythingllm.com/

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
