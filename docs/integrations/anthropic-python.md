# Anthropic SDK for Python

*SDKs* · verified end to end against the gateway

Messages, streaming and token counting all go through the gateway.

**Python**

```python
from anthropic import Anthropic

client = Anthropic(base_url="http://localhost:8080", api_key="$HARPO_KEY")
message = client.messages.create(
    model="claude-sonnet-5-5",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Email jane.doe@acme.com about her refund"}],
)
print(message.content[0].text)
```

**Environment**

```bash
export ANTHROPIC_BASE_URL=http://localhost:8080
export ANTHROPIC_API_KEY=$HARPO_KEY
```

Vendor documentation: https://github.com/anthropics/anthropic-sdk-python

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
