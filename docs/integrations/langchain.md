# LangChain

*Frameworks* · verified end to end against the gateway

ChatOpenAI and ChatAnthropic both take a base URL.

**Python**

```python
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI

gpt = ChatOpenAI(base_url="http://localhost:8080/v1", api_key="$HARPO_KEY", model="gpt-4o-mini")
claude = ChatAnthropic(base_url="http://localhost:8080", api_key="$HARPO_KEY", model="claude-sonnet-5-5")
print(gpt.invoke("Email jane.doe@acme.com about her refund").content)
```

Vendor documentation: https://python.langchain.com/

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
