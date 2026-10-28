"""OpenAI Agents SDK through Harpo: Chat Completions, tracing off (traces would bypass the gateway)."""
import os

from agents import Agent, Runner, set_default_openai_api, set_default_openai_client, set_tracing_disabled
from openai import AsyncOpenAI

set_default_openai_client(AsyncOpenAI(base_url=os.getenv("HARPO_URL", "http://127.0.0.1:8080") + "/v1", api_key=os.getenv("HARPO_KEY", "demo")))
set_default_openai_api("chat_completions")
set_tracing_disabled(True)
agent = Agent(name="Support", instructions="Be brief.", model=os.getenv("HARPO_MODEL", "demo-gpt"))
print(Runner.run_sync(agent, "Email jane.doe@acme.com about her refund").final_output)
