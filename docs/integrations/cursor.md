# Cursor

*Coding agents* · configured per the vendor documentation

Cursor can override the OpenAI base URL, but it calls custom endpoints from its own servers.

1. Settings → Models → OpenAI API key: `$HARPO_KEY`; enable **Override OpenAI Base URL**.
2. The URL must be reachable from the internet (HTTPS), not localhost.

> **Caution.** Cursor's servers handle your prompt before it reaches the gateway, so the gateway cannot protect it from Cursor. Prefer Continue, Cline or Claude Code, which connect from your machine.

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
