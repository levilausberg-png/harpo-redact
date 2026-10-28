"""OpenAI SDK through Harpo. Run `harpo demo` first (or set HARPO_URL / HARPO_KEY)."""
import os

from openai import OpenAI

client = OpenAI(base_url=os.getenv("HARPO_URL", "http://127.0.0.1:8080") + "/v1", api_key=os.getenv("HARPO_KEY", "demo"))
reply = client.chat.completions.create(
    model=os.getenv("HARPO_MODEL", "demo-gpt"),
    messages=[{"role": "user", "content": "Email jane.doe@acme.com about card 4111 1111 1111 1111"}],
)
print(reply.choices[0].message.content)
