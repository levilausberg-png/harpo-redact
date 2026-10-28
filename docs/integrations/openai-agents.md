# OpenAI Agents SDK

*Frameworks* · verified end to end against the gateway

Give the SDK a client pointed at the gateway, use Chat Completions, and turn off tracing.

**Python**

```python
from openai import AsyncOpenAI
from agents import Agent, Runner, set_default_openai_api, set_default_openai_client, set_tracing_disabled

set_default_openai_client(AsyncOpenAI(base_url="http://localhost:8080/v1", api_key="$HARPO_KEY"))
set_default_openai_api("chat_completions")  # the gateway proxies Chat Completions
set_tracing_disabled(True)  # traces would go to OpenAI directly, unredacted

agent = Agent(name="Support", instructions="Be brief.", model="gpt-4o-mini")
print(Runner.run_sync(agent, "Email jane.doe@acme.com about her refund").final_output)
```

> **Caution.** Tracing uploads full traces to OpenAI outside the gateway. Keep it disabled, or send traces to a processor you host.

Vendor documentation: https://openai.github.io/openai-agents-python/

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
