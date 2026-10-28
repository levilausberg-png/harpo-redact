"""Anthropic SDK through Harpo: messages, streaming and token counting."""
import os

from anthropic import Anthropic

client = Anthropic(base_url=os.getenv("HARPO_URL", "http://127.0.0.1:8080"), api_key=os.getenv("HARPO_KEY", "demo"))
model = os.getenv("HARPO_CLAUDE_MODEL", "demo-claude")
messages = [{"role": "user", "content": "Refund Priya Raman, IBAN NL91ABNA0417164300"}]
print(client.messages.create(model=model, max_tokens=512, messages=messages).content[0].text)
with client.messages.stream(model=model, max_tokens=512, messages=messages) as stream:
    print(stream.get_final_text())
print("input tokens:", client.messages.count_tokens(model=model, messages=messages).input_tokens)
