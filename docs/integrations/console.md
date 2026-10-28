# Built-in playground

*Chat apps* · verified end to end against the gateway

This console. See what a prompt turns into before it leaves, then send it to any configured model and read the reply.

1. Open `http://localhost:8080/#/playground`.
2. Type or pick a sample. The right pane is exactly what the provider receives.
3. Choose a model and press Send. Replies come back with placeholders: redaction is one-way.

`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.
