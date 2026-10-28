# Integrations

Every integration is one setting: the base URL. Pick yours; each page has copy-paste configuration.
The console (`/#/integrations`) shows the same catalog with your gateway's address and key filled in.

## Chat apps

| Integration | Status | |
| --- | --- | --- |
| [ChatGPT, Claude and Gemini apps](chat-apps.md) | see the note | The consumer apps send what you type straight to their own servers and have no setting to change that, so no proxy, this one included, can sit in front of them |
| [Built-in playground](console.md) | verified | This console |
| [Open WebUI](open-webui.md) | per vendor docs | A self-hosted, ChatGPT-style interface |
| [LibreChat](librechat.md) | per vendor docs | A multi-provider chat app |
| [LobeChat](lobechat.md) | per vendor docs | A polished chat app with plugins |
| [AnythingLLM](anythingllm.md) | per vendor docs | Chat with your documents |
| [Jan, Chatbox, Msty, BoltAI](desktop-chat.md) | per vendor docs | Desktop chat apps with a custom OpenAI-compatible provider setting all work the same way. |

## Coding agents

| Integration | Status | |
| --- | --- | --- |
| [Claude Code](claude-code.md) | per vendor docs | Anthropic's coding agent reads ANTHROPIC_BASE_URL |
| [OpenAI Codex CLI](codex-cli.md) | per vendor docs | Add the gateway as a model provider in ~/.codex/config.toml, using the Chat Completions wire API. |
| [Continue](continue.md) | per vendor docs | The open-source IDE assistant for VS Code and JetBrains |
| [Cline and Roo Code](cline.md) | per vendor docs | VS Code agents with an OpenAI Compatible provider. |
| [Aider](aider.md) | per vendor docs | Pair programming in the terminal |
| [Zed](zed.md) | per vendor docs | Zed's assistant can use any OpenAI-compatible endpoint. |
| [Cursor](cursor.md) | see the note | Cursor can override the OpenAI base URL, but it calls custom endpoints from its own servers. |

## SDKs

| Integration | Status | |
| --- | --- | --- |
| [OpenAI SDK for Python](openai-python.md) | verified | Set base_url, or set OPENAI_BASE_URL and change no code. |
| [OpenAI SDK for Node](openai-node.md) | verified | The same in JavaScript and TypeScript. |
| [Anthropic SDK for Python](anthropic-python.md) | verified | Messages, streaming and token counting all go through the gateway. |
| [Anthropic SDK for TypeScript](anthropic-ts.md) | verified | The Anthropic client for JavaScript and TypeScript. |
| [Vercel AI SDK](vercel-ai.md) | verified | Create a provider with the gateway's base URL |
| [curl and plain HTTP](http.md) | verified | Any language with an HTTP client: the request shape is OpenAI's or Anthropic's. |

## Frameworks

| Integration | Status | |
| --- | --- | --- |
| [LangChain](langchain.md) | verified | ChatOpenAI and ChatAnthropic both take a base URL. |
| [OpenAI Agents SDK](openai-agents.md) | verified | Give the SDK a client pointed at the gateway, use Chat Completions, and turn off tracing. |
| [LlamaIndex](llamaindex.md) | per vendor docs | OpenAILike accepts any model name served at a base URL. |
| [CrewAI](crewai.md) | per vendor docs | CrewAI's LLM class takes a base URL for OpenAI-compatible endpoints. |
| [LiteLLM](litellm.md) | per vendor docs | Call the gateway as an OpenAI-compatible endpoint, or chain it behind a LiteLLM proxy. |

## Automation

| Integration | Status | |
| --- | --- | --- |
| [n8n](n8n.md) | per vendor docs | Workflow automation |
| [Dify, Flowise and other builders](builders.md) | per vendor docs | Add an OpenAI-API-compatible model provider with the gateway's base URL. |

## Providers

| Integration | Status | |
| --- | --- | --- |
| [OpenRouter](provider-openrouter.md) | per vendor docs | Hundreds of models behind one key, through both the OpenAI and the Anthropic API |
| [OpenAI](provider-openai.md) | per vendor docs | GPT models |
| [Anthropic](provider-anthropic.md) | per vendor docs | Claude models, including for Claude Code. |
| [Google Gemini](provider-gemini.md) | per vendor docs | Gemini through Google's OpenAI-compatible endpoint. |
| [Mistral, Groq, DeepSeek](provider-mistral.md) | per vendor docs | OpenAI-compatible providers with presets: --provider mistral, groq or deepseek. |
| [Ollama (local models)](provider-ollama.md) | per vendor docs | Models on your own hardware |
