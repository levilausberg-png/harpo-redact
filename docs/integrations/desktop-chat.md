# Jan, Chatbox, Msty, BoltAI

*Chat apps* · configured per the vendor documentation

Desktop chat apps with a custom OpenAI-compatible provider setting all work the same way.

1. Add a custom provider of type OpenAI-compatible.
2. Base URL `http://localhost:8080/v1`, API key `$HARPO_KEY`.
3. Add the model name, e.g. `gpt-4o-mini`.

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
