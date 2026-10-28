"""LangChain with both providers through Harpo."""
import os

from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI

base, key = os.getenv("HARPO_URL", "http://127.0.0.1:8080"), os.getenv("HARPO_KEY", "demo")
print(ChatOpenAI(base_url=f"{base}/v1", api_key=key, model=os.getenv("HARPO_MODEL", "demo-gpt")).invoke("Mail bob@corp.example").content)
print(ChatAnthropic(base_url=base, api_key=key, model=os.getenv("HARPO_CLAUDE_MODEL", "demo-claude")).invoke("Mail bob@corp.example").content)
