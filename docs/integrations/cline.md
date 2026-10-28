# Cline and Roo Code

*Coding agents* · configured per the vendor documentation

VS Code agents with an OpenAI Compatible provider.

1. API Provider: **OpenAI Compatible**.
2. Base URL `http://localhost:8080/v1`, API key `$HARPO_KEY`, Model ID `gpt-4o-mini`.
3. For Claude models through the Anthropic API, choose **Anthropic** and set the custom base URL to `http://localhost:8080`.

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
