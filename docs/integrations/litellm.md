# LiteLLM

*Frameworks* · configured per the vendor documentation

Call the gateway as an OpenAI-compatible endpoint, or chain it behind a LiteLLM proxy.

**Python**

```python
import litellm

reply = litellm.completion(
    model="openai/gpt-4o-mini",
    api_base="http://localhost:8080/v1",
    api_key="$HARPO_KEY",
    messages=[{"role": "user", "content": "Email jane.doe@acme.com"}],
)
```

Vendor documentation: https://docs.litellm.ai/

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
