# CrewAI

*Frameworks* · configured per the vendor documentation

CrewAI's LLM class takes a base URL for OpenAI-compatible endpoints.

**Python**

```python
from crewai import LLM

llm = LLM(model="openai/gpt-4o-mini", base_url="http://localhost:8080/v1", api_key="$HARPO_KEY")
```

Vendor documentation: https://docs.crewai.com/concepts/llms

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
