# LlamaIndex

*Frameworks* · configured per the vendor documentation

OpenAILike accepts any model name served at a base URL.

**Python**

```python
from llama_index.llms.openai_like import OpenAILike

llm = OpenAILike(model="gpt-4o-mini", api_base="http://localhost:8080/v1", api_key="$HARPO_KEY", is_chat_model=True)
print(llm.complete("Email jane.doe@acme.com about her refund"))
```

Vendor documentation: https://docs.llamaindex.ai/

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
