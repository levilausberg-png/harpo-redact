"""Talk to a running gateway: its scan, a request through it to the provider, and its policy.

    harpo demo --no-browser                       # in another terminal: gateway + a fake provider
    python examples/python/sdk/gateway_client.py

Against your own gateway: HARPO_URL=https://harpo.internal HARPO_KEY=harpo_... python ...
"""

import os

from harpo_redact.sdk import BlockedError, GatewayClient

MODEL = os.getenv("HARPO_MODEL", "demo-gpt")

with GatewayClient() as gateway:  # $HARPO_URL (default http://127.0.0.1:8080) and $HARPO_KEY
    print("gateway", gateway.health().version, "| ready:", gateway.ready().ready)
    result = gateway.scan("Mail jane.doe@acme.example about card 4111 1111 1111 1111")  # invented
    print(result.risk.value, result.text)
    try:
        answer = gateway.chat_completion(
            {"model": MODEL, "messages": [{"role": "user", "content": "Call Jane Doe on +31 20 794 6095"}]}
        )
        print("provider saw only placeholders:", answer.body["choices"][0]["message"]["content"])
    except BlockedError as blocked:
        print("blocked by the gateway's policy:", blocked.codes)
    print("always redacted:", gateway.policy().always_redacted)
    # The same gateway serves the OpenAI and Anthropic SDKs: OpenAI(base_url=gateway.openai_base_url, ...)
