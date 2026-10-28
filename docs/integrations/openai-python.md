# OpenAI SDK for Python

*SDKs* · verified end to end against the gateway

Set base_url, or set OPENAI_BASE_URL and change no code.

**Python**

```python
from openai import OpenAI

client = OpenAI(base_url="http://localhost:8080/v1", api_key="$HARPO_KEY")
reply = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Email jane.doe@acme.com about her refund"}],
)
print(reply.choices[0].message.content)
```

**Environment**

```bash
export OPENAI_BASE_URL=http://localhost:8080/v1
export OPENAI_API_KEY=$HARPO_KEY   # the gateway key; your provider key stays on the gateway
```

Vendor documentation: https://github.com/openai/openai-python

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
