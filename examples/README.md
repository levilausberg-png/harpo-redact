# Examples

Runnable clients for the integrations marked *verified* in [docs/integrations](../docs/integrations/README.md).
Each one is unchanged code with one setting changed: the base URL.

```bash
harpo demo --no-browser        # gateway + a fake provider on http://127.0.0.1:8080
python examples/python/openai_sdk.py      # pip install openai
python examples/python/anthropic_sdk.py   # pip install anthropic
python examples/python/langchain_app.py   # pip install langchain-openai langchain-anthropic
python examples/python/openai_agents.py   # pip install openai-agents
cd examples/node && npm install && node openai.mjs && node anthropic.mjs && node vercel-ai.mjs
```

Against your own gateway: `export HARPO_URL=http://your-gateway:8080 HARPO_KEY=harpo_... HARPO_MODEL=gpt-4o-mini`.
`tools/verify_integrations.sh` runs them all and fails if any reply still contains the raw values.

## The Python SDK

Harpo's own engine and gateway client, from Python code ([docs/SDK.md](../docs/SDK.md)). The engine examples need no
gateway, only spaCy's English model (`harpo demo` prints its one-line install); every value in them is invented.

```bash
python examples/python/sdk/scan_text.py          # what Harpo finds, the verdict and the redacted text
python examples/python/sdk/redact_or_block.py    # redact(), or BlockedError when the policy blocks
python examples/python/sdk/custom_policy.py      # your own types and a stricter policy
python examples/python/sdk/redact_document.py    # a file in, a verified redacted file out
python examples/python/sdk/async_engine.py       # the engine in asyncio code
python examples/python/sdk/gateway_client.py     # a running gateway (harpo demo --no-browser first)
```

`tests/test_sdk_examples.py` runs every one of them and checks what they print.
