"""The integration catalog: one source for the console (console/integrations.json) and the docs (docs/integrations/).

    python tools/integrations.py        # regenerate both

Placeholders: {OPENAI_BASE} {ANTHROPIC_BASE} {KEY} {MODEL} {CLAUDE_MODEL}. "verified" means the snippet was run
against the gateway by tools/verify_integrations.sh (examples/); everything else follows the vendor's documentation.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATEGORIES = ["Chat apps", "Coding agents", "SDKs", "Frameworks", "Automation", "Providers"]
TONE = {"Chat apps": 0, "Coding agents": 2, "SDKs": 1, "Frameworks": 4, "Automation": 3, "Providers": 6}
DOCKER_NOTE = {
    "kind": "info",
    "text": "Running it in Docker? Inside a container `localhost` is the container itself: use `http://host.docker.internal:8080/v1` (Docker Desktop) or the gateway's service name, or use `docker compose --profile chat up`, which wires Open WebUI to the gateway for you.",
}


def item(
    id, name, category, mono, summary, *, steps=(), snippets=(), notes=(), docs=None, verified=False, caveat=False
):
    return {"id": id, "name": name, "category": category, "mono": mono, "tone": TONE[category], "summary": summary,
            "steps": list(steps), "snippets": [{"label": label, "lang": g, "code": c.strip("\n")} for label, g, c in snippets],
            "notes": list(notes), "docs": docs, "verified": verified, "caveat": caveat}  # fmt: skip


ENV_OPENAI = (
    "Environment",
    "bash",
    "export OPENAI_BASE_URL={OPENAI_BASE}\nexport OPENAI_API_KEY={KEY}   # the gateway key; your provider key stays on the gateway",
)
ENV_ANTHROPIC = ("Environment", "bash", "export ANTHROPIC_BASE_URL={ANTHROPIC_BASE}\nexport ANTHROPIC_API_KEY={KEY}")

ITEMS = [
    # ------------------------------------------------------------------ chat apps
    item(
        "chat-apps",
        "ChatGPT, Claude and Gemini apps",
        "Chat apps",
        "AI",
        "The consumer apps send what you type straight to their own servers and have no setting to change that, so no proxy, this one included, can sit in front of them. Use the same models privately through a chat app you control.",
        steps=[
            "Open the built-in playground at `{ANTHROPIC_BASE}/#/playground` to chat with any configured model through the gateway.",
            "Or run Open WebUI or LibreChat (below): a ChatGPT-style app where every message passes through the gateway.",
            "Configure the provider once on the gateway (`harpo init --provider openai`, `anthropic`, `gemini` or `openrouter`).",
        ],
        notes=[
            {
                "kind": "info",
                "text": "A browser extension that checks what you paste into chatgpt.com or claude.ai against this gateway is on the roadmap. Until then, the apps above are the private route.",
            }
        ],
        caveat=True,
    ),
    item(
        "console",
        "Built-in playground",
        "Chat apps",
        "PG",
        "This console. See what a prompt turns into before it leaves, then send it to any configured model and read the reply.",
        steps=[
            "Open `{ANTHROPIC_BASE}/#/playground`.",
            "Type or pick a sample. The right pane is exactly what the provider receives.",
            "Choose a model and press Send. Replies come back with placeholders: redaction is one-way.",
        ],
        verified=True,
    ),
    item(
        "open-webui",
        "Open WebUI",
        "Chat apps",
        "OW",
        "A self-hosted, ChatGPT-style interface. Point its OpenAI connection at the gateway and every chat is sanitized first.",
        snippets=[
            (
                "Docker",
                "bash",
                """
docker run -d --name open-webui -p 3000:8080 \\
  -e OPENAI_API_BASE_URL={OPENAI_BASE} \\
  -e OPENAI_API_KEY={KEY} \\
  -e ENABLE_OLLAMA_API=false \\
  -v open-webui:/app/backend/data \\
  ghcr.io/open-webui/open-webui:main""",
            ),
            (
                "Compose profile",
                "bash",
                "# from this repository: gateway + Open WebUI, already wired together\ndocker compose --profile chat up -d\nopen http://localhost:3000",
            ),
        ],
        notes=[DOCKER_NOTE],
        docs="https://docs.openwebui.com/",
    ),
    item(
        "librechat",
        "LibreChat",
        "Chat apps",
        "LC",
        "A multi-provider chat app. Add the gateway as a custom endpoint; models are listed from the gateway's /v1/models.",
        snippets=[
            (
                "librechat.yaml",
                "yaml",
                """
endpoints:
  custom:
    - name: "Harpo"
      apiKey: "${HARPO_KEY}"
      baseURL: "{OPENAI_BASE}"
      models:
        default: ["{MODEL}"]
        fetch: true
      titleConvo: true
      titleModel: "current_model\"""",
            )
        ],
        notes=[DOCKER_NOTE],
        docs="https://www.librechat.ai/docs/configuration/librechat_yaml",
    ),
    item(
        "lobechat",
        "LobeChat",
        "Chat apps",
        "LB",
        "A polished chat app with plugins. Set its OpenAI proxy URL to the gateway.",
        snippets=[("Environment", "bash", "OPENAI_PROXY_URL={OPENAI_BASE}\nOPENAI_API_KEY={KEY}")],
        notes=[DOCKER_NOTE],
        docs="https://lobehub.com/docs",
    ),
    item(
        "anythingllm",
        "AnythingLLM",
        "Chat apps",
        "AL",
        "Chat with your documents. Use the Generic OpenAI provider so both chats and the retrieved passages are sanitized.",
        steps=[
            "Settings → AI Providers → LLM → **Generic OpenAI**.",
            "Base URL: `{OPENAI_BASE}` · API key: `{KEY}` · Model: `{MODEL}`.",
            "Set the token context window to your model's.",
        ],
        docs="https://docs.anythingllm.com/",
    ),
    item(
        "desktop-chat",
        "Jan, Chatbox, Msty, BoltAI",
        "Chat apps",
        "DC",
        "Desktop chat apps with a custom OpenAI-compatible provider setting all work the same way.",
        steps=[
            "Add a custom provider of type OpenAI-compatible.",
            "Base URL `{OPENAI_BASE}`, API key `{KEY}`.",
            "Add the model name, e.g. `{MODEL}`.",
        ],
    ),
    # ------------------------------------------------------------------ coding agents
    item(
        "claude-code",
        "Claude Code",
        "Coding agents",
        "CC",
        "Anthropic's coding agent reads ANTHROPIC_BASE_URL. Your code, logs and secrets are sanitized before they reach the model.",
        snippets=[
            ("Shell", "bash", "export ANTHROPIC_BASE_URL={ANTHROPIC_BASE}\nexport ANTHROPIC_AUTH_TOKEN={KEY}\nclaude")
        ],
        notes=[
            {
                "kind": "info",
                "text": "Through OpenRouter: configure the `openrouter-messages` upstream (the boot scripts do "
                "it), keep `ANTHROPIC_BASE_URL={ANTHROPIC_BASE}`, and set `ANTHROPIC_DEFAULT_SONNET_MODEL` (and the Opus and "
                "Haiku variants) to OpenRouter model names such as `anthropic/claude-sonnet-5.5`.",
            },
            {
                "kind": "warn",
                "text": "Claude Code adopts new API fields early. If a request is refused with `Not inspected by the gateway`, the error names the field path: set `policy.unknown_fields: pass` to scan such fields as text, and open an issue so the adapter can declare it.",
            },
            {
                "kind": "info",
                "text": "Screenshots you paste are images: blocked by default (`policy.unsupported_content`). Keys and passwords in files it reads arrive as `[SECRET_1]`: they are always redacted, and the request goes on.",
            },
        ],
        docs="https://docs.claude.com/en/docs/claude-code/llm-gateway",
    ),
    item(
        "codex-cli",
        "OpenAI Codex CLI",
        "Coding agents",
        "CX",
        "Add the gateway as a model provider in ~/.codex/config.toml, using the Chat Completions wire API.",
        snippets=[
            (
                "config.toml",
                "toml",
                """
model = "{MODEL}"
model_provider = "harpo"

[model_providers.harpo]
name = "Harpo"
base_url = "{OPENAI_BASE}"
env_key = "HARPO_API_KEY"
wire_api = "chat\"""",
            ),
            ("Shell", "bash", "export HARPO_API_KEY={KEY}\ncodex"),
        ],
        notes=[
            {
                "kind": "info",
                "text": 'The gateway proxies Chat Completions and Anthropic Messages; the OpenAI Responses API is on the roadmap, hence `wire_api = "chat"`.',
            }
        ],
        docs="https://github.com/openai/codex/blob/main/docs/config.md",
    ),
    item(
        "continue",
        "Continue",
        "Coding agents",
        "CO",
        "The open-source IDE assistant for VS Code and JetBrains. Set apiBase on any model.",
        snippets=[
            (
                "config.yaml",
                "yaml",
                """
models:
  - name: {MODEL} via Harpo
    provider: openai
    model: {MODEL}
    apiBase: {OPENAI_BASE}
    apiKey: {KEY}
  - name: Claude via Harpo
    provider: anthropic
    model: {CLAUDE_MODEL}
    apiBase: {OPENAI_BASE}
    apiKey: {KEY}""",
            )
        ],
        docs="https://docs.continue.dev/",
    ),
    item(
        "cline",
        "Cline and Roo Code",
        "Coding agents",
        "CL",
        "VS Code agents with an OpenAI Compatible provider.",
        steps=[
            "API Provider: **OpenAI Compatible**.",
            "Base URL `{OPENAI_BASE}`, API key `{KEY}`, Model ID `{MODEL}`.",
            "For Claude models through the Anthropic API, choose **Anthropic** and set the custom base URL to `{ANTHROPIC_BASE}`.",
        ],
    ),
    item(
        "aider",
        "Aider",
        "Coding agents",
        "AD",
        "Pair programming in the terminal. Aider reads OPENAI_API_BASE.",
        snippets=[
            (
                "Shell",
                "bash",
                "export OPENAI_API_BASE={OPENAI_BASE}\nexport OPENAI_API_KEY={KEY}\naider --model openai/{MODEL}",
            )
        ],
        docs="https://aider.chat/docs/llms/openai-compat.html",
    ),
    item(
        "zed",
        "Zed",
        "Coding agents",
        "ZD",
        "Zed's assistant can use any OpenAI-compatible endpoint.",
        snippets=[
            (
                "settings.json",
                "json",
                """
{
  "language_models": {
    "openai": {
      "api_url": "{OPENAI_BASE}",
      "available_models": [{ "name": "{MODEL}", "display_name": "{MODEL} via Harpo", "max_tokens": 128000 }]
    }
  }
}""",
            )
        ],
        steps=["Paste the settings, then enter `{KEY}` as the OpenAI key in the Agent panel's settings."],
        docs="https://zed.dev/docs/ai/configuration",
    ),
    item(
        "cursor",
        "Cursor",
        "Coding agents",
        "CU",
        "Cursor can override the OpenAI base URL, but it calls custom endpoints from its own servers.",
        steps=[
            "Settings → Models → OpenAI API key: `{KEY}`; enable **Override OpenAI Base URL**.",
            "The URL must be reachable from the internet (HTTPS), not localhost.",
        ],
        notes=[
            {
                "kind": "warn",
                "text": "Cursor's servers handle your prompt before it reaches the gateway, so the gateway cannot protect it from Cursor. Prefer Continue, Cline or Claude Code, which connect from your machine.",
            }
        ],
        caveat=True,
    ),
    # ------------------------------------------------------------------ SDKs
    item(
        "openai-python",
        "OpenAI SDK for Python",
        "SDKs",
        "Py",
        "Set base_url, or set OPENAI_BASE_URL and change no code.",
        snippets=[
            (
                "Python",
                "python",
                """
from openai import OpenAI

client = OpenAI(base_url="{OPENAI_BASE}", api_key="{KEY}")
reply = client.chat.completions.create(
    model="{MODEL}",
    messages=[{"role": "user", "content": "Email jane.doe@acme.com about her refund"}],
)
print(reply.choices[0].message.content)""",
            ),
            ENV_OPENAI,
        ],
        verified=True,
        docs="https://github.com/openai/openai-python",
    ),
    item(
        "openai-node",
        "OpenAI SDK for Node",
        "SDKs",
        "JS",
        "The same in JavaScript and TypeScript.",
        snippets=[
            (
                "TypeScript",
                "ts",
                """
import OpenAI from "openai";

const client = new OpenAI({ baseURL: "{OPENAI_BASE}", apiKey: "{KEY}" });
const reply = await client.chat.completions.create({
  model: "{MODEL}",
  messages: [{ role: "user", content: "Email jane.doe@acme.com about her refund" }],
});
console.log(reply.choices[0].message.content);""",
            ),
            ENV_OPENAI,
        ],
        verified=True,
        docs="https://github.com/openai/openai-node",
    ),
    item(
        "anthropic-python",
        "Anthropic SDK for Python",
        "SDKs",
        "An",
        "Messages, streaming and token counting all go through the gateway.",
        snippets=[
            (
                "Python",
                "python",
                """
from anthropic import Anthropic

client = Anthropic(base_url="{ANTHROPIC_BASE}", api_key="{KEY}")
message = client.messages.create(
    model="{CLAUDE_MODEL}",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Email jane.doe@acme.com about her refund"}],
)
print(message.content[0].text)""",
            ),
            ENV_ANTHROPIC,
        ],
        verified=True,
        docs="https://github.com/anthropics/anthropic-sdk-python",
    ),
    item(
        "anthropic-ts",
        "Anthropic SDK for TypeScript",
        "SDKs",
        "TS",
        "The Anthropic client for JavaScript and TypeScript.",
        snippets=[
            (
                "TypeScript",
                "ts",
                """
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic({ baseURL: "{ANTHROPIC_BASE}", apiKey: "{KEY}" });
const message = await client.messages.create({
  model: "{CLAUDE_MODEL}",
  max_tokens: 1024,
  messages: [{ role: "user", content: "Email jane.doe@acme.com about her refund" }],
});
console.log(message.content);""",
            ),
            ENV_ANTHROPIC,
        ],
        verified=True,
        docs="https://github.com/anthropics/anthropic-sdk-typescript",
    ),
    item(
        "vercel-ai",
        "Vercel AI SDK",
        "SDKs",
        "AI",
        "Create a provider with the gateway's base URL. Use .chat(): the gateway proxies Chat Completions.",
        snippets=[
            (
                "TypeScript",
                "ts",
                """
import { createOpenAI } from "@ai-sdk/openai";
import { generateText } from "ai";

const harpo = createOpenAI({ baseURL: "{OPENAI_BASE}", apiKey: "{KEY}" });
const { text } = await generateText({
  model: harpo.chat("{MODEL}"),
  prompt: "Email jane.doe@acme.com about her refund",
});
console.log(text);""",
            )
        ],
        verified=True,
        docs="https://ai-sdk.dev/providers/ai-sdk-providers/openai",
    ),
    item(
        "http",
        "curl and plain HTTP",
        "SDKs",
        "{}",
        "Any language with an HTTP client: the request shape is OpenAI's or Anthropic's.",
        snippets=[
            (
                "OpenAI style",
                "bash",
                """
curl {OPENAI_BASE}/chat/completions \\
  -H "Authorization: Bearer {KEY}" -H "Content-Type: application/json" \\
  -d '{"model": "{MODEL}", "messages": [{"role": "user", "content": "Email jane.doe@acme.com"}]}'""",
            ),
            (
                "Anthropic style",
                "bash",
                """
curl {ANTHROPIC_BASE}/v1/messages \\
  -H "x-api-key: {KEY}" -H "anthropic-version: 2023-06-01" -H "Content-Type: application/json" \\
  -d '{"model": "{CLAUDE_MODEL}", "max_tokens": 256, "messages": [{"role": "user", "content": "Email jane.doe@acme.com"}]}'""",
            ),
            (
                "Scan only",
                "bash",
                """
curl {ANTHROPIC_BASE}/v1/scan -H "Authorization: Bearer {KEY}" -H "Content-Type: application/json" \\
  -d '{"text": "Email jane.doe@acme.com, card 4111 1111 1111 1111"}'""",
            ),
        ],
        verified=True,
    ),
    # ------------------------------------------------------------------ frameworks
    item(
        "langchain",
        "LangChain",
        "Frameworks",
        "LC",
        "ChatOpenAI and ChatAnthropic both take a base URL.",
        snippets=[
            (
                "Python",
                "python",
                """
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI

gpt = ChatOpenAI(base_url="{OPENAI_BASE}", api_key="{KEY}", model="{MODEL}")
claude = ChatAnthropic(base_url="{ANTHROPIC_BASE}", api_key="{KEY}", model="{CLAUDE_MODEL}")
print(gpt.invoke("Email jane.doe@acme.com about her refund").content)""",
            )
        ],
        verified=True,
        docs="https://python.langchain.com/",
    ),
    item(
        "openai-agents",
        "OpenAI Agents SDK",
        "Frameworks",
        "AG",
        "Give the SDK a client pointed at the gateway, use Chat Completions, and turn off tracing.",
        snippets=[
            (
                "Python",
                "python",
                """
from openai import AsyncOpenAI
from agents import Agent, Runner, set_default_openai_api, set_default_openai_client, set_tracing_disabled

set_default_openai_client(AsyncOpenAI(base_url="{OPENAI_BASE}", api_key="{KEY}"))
set_default_openai_api("chat_completions")  # the gateway proxies Chat Completions
set_tracing_disabled(True)  # traces would go to OpenAI directly, unredacted

agent = Agent(name="Support", instructions="Be brief.", model="{MODEL}")
print(Runner.run_sync(agent, "Email jane.doe@acme.com about her refund").final_output)""",
            )
        ],
        notes=[
            {
                "kind": "warn",
                "text": "Tracing uploads full traces to OpenAI outside the gateway. Keep it disabled, or send traces to a processor you host.",
            }
        ],
        verified=True,
        docs="https://openai.github.io/openai-agents-python/",
    ),
    item(
        "llamaindex",
        "LlamaIndex",
        "Frameworks",
        "LI",
        "OpenAILike accepts any model name served at a base URL.",
        snippets=[
            (
                "Python",
                "python",
                """
from llama_index.llms.openai_like import OpenAILike

llm = OpenAILike(model="{MODEL}", api_base="{OPENAI_BASE}", api_key="{KEY}", is_chat_model=True)
print(llm.complete("Email jane.doe@acme.com about her refund"))""",
            )
        ],
        docs="https://docs.llamaindex.ai/",
    ),
    item(
        "crewai",
        "CrewAI",
        "Frameworks",
        "CR",
        "CrewAI's LLM class takes a base URL for OpenAI-compatible endpoints.",
        snippets=[
            (
                "Python",
                "python",
                """
from crewai import LLM

llm = LLM(model="openai/{MODEL}", base_url="{OPENAI_BASE}", api_key="{KEY}")""",
            )
        ],
        docs="https://docs.crewai.com/concepts/llms",
    ),
    item(
        "litellm",
        "LiteLLM",
        "Frameworks",
        "LL",
        "Call the gateway as an OpenAI-compatible endpoint, or chain it behind a LiteLLM proxy.",
        snippets=[
            (
                "Python",
                "python",
                """
import litellm

reply = litellm.completion(
    model="openai/{MODEL}",
    api_base="{OPENAI_BASE}",
    api_key="{KEY}",
    messages=[{"role": "user", "content": "Email jane.doe@acme.com"}],
)""",
            )
        ],
        docs="https://docs.litellm.ai/",
    ),
    # ------------------------------------------------------------------ automation
    item(
        "n8n",
        "n8n",
        "Automation",
        "N8",
        "Workflow automation. The OpenAI credential has a Base URL field.",
        steps=[
            "Credentials → New → **OpenAI**.",
            "API key `{KEY}`, Base URL `{OPENAI_BASE}`.",
            "Use the credential in the OpenAI Chat Model or AI Agent nodes.",
        ],
        notes=[DOCKER_NOTE],
        docs="https://docs.n8n.io/integrations/builtin/credentials/openai/",
    ),
    item(
        "builders",
        "Dify, Flowise and other builders",
        "Automation",
        "DF",
        "Add an OpenAI-API-compatible model provider with the gateway's base URL.",
        steps=[
            "Add a model provider of type **OpenAI-API-compatible**.",
            "Base URL `{OPENAI_BASE}`, API key `{KEY}`, model `{MODEL}`.",
        ],
        notes=[DOCKER_NOTE],
    ),
    # ------------------------------------------------------------------ providers
    item(
        "provider-openrouter",
        "OpenRouter",
        "Providers",
        "OR",
        "Hundreds of models behind one key, through both the OpenAI and the Anthropic API. The gateway enforces OpenRouter's "
        "privacy routing on every request: only providers that do not store prompts, optionally zero-data-retention "
        "endpoints only.",
        steps=[
            "Start with `boot.cmd` (Windows) or `./boot.sh` and choose `openrouter`, or run "
            "`harpo init --provider openrouter`. Both configure the OpenAI-style API and the Anthropic-style "
            "API that Claude Code uses.",
            "Point clients at the gateway as usual. OpenRouter-native clients and SDKs can use `{ANTHROPIC_BASE}/api/v1`.",
            "Use OpenRouter's model names (`anthropic/claude-sonnet-5.5`). `GET /v1/models` lists the OpenRouter models "
            "your config allows.",
        ],
        snippets=[
            (
                "Config",
                "yaml",
                """
upstreams:
  - name: openrouter
    style: openai
    base_url: https://openrouter.ai/api/v1
    api_key_env: OPENROUTER_API_KEY
    models: ["anthropic/*", "openai/*", "google/*"]
    openrouter:
      data_collection: deny   # enforced: only providers that do not store prompts
      zdr: true               # optional: zero-data-retention endpoints only
  - name: openrouter-messages # the Anthropic-style API (Claude Code)
    style: anthropic
    base_url: https://openrouter.ai/api
    api_key_env: OPENROUTER_API_KEY
    models: ["*"]
""",
            ),
            ("Shell", "bash", "export OPENROUTER_API_KEY=sk-or-...\nharpo serve --config config/harpo.yaml"),
            (
                "Python",
                "python",
                """
from openai import OpenAI

client = OpenAI(base_url="{OPENAI_BASE}", api_key="{KEY}")
reply = client.chat.completions.create(
    model="anthropic/claude-sonnet-5.5",
    messages=[{"role": "user", "content": "Hello"}],
    extra_body={"provider": {"sort": "price"}},  # data_collection is set by the gateway
)
""",
            ),
        ],
        notes=[
            {
                "kind": "info",
                "text": "Clients can tighten routing (zdr, only, ignore) but never loosen it: a request asking "
                "for providers that store data is rewritten to `data_collection: deny`. Fallback lists (`models`, "
                "`fallbacks`) must name models this upstream allows; router plugins (auto-router, fusion) are accepted "
                "only when it allows any model.",
            },
            {
                "kind": "info",
                "text": "The connection test on Providers & adapters uses OpenRouter's key endpoint and shows "
                "the key's remaining limit and spend: OpenRouter lists models to anyone, so a model listing proves nothing "
                "about the key.",
            },
            {
                "kind": "warn",
                "text": "OpenRouter's web search and server tools run at OpenRouter, on the sanitized request. "
                "Generated images and other attachments are refused (`policy.unsupported_content`).",
            },
        ],
        docs="https://openrouter.ai/docs/api/reference",
    ),
    *[
        item(
            f"provider-{pid}",
            name,
            "Providers",
            mono,
            summary,
            snippets=[("Set up", "bash", f"harpo init --provider {pid}\n{env}harpo serve --config config/harpo.yaml")],
            notes=notes,
        )
        for pid, name, mono, summary, env, notes in [
            (
                "openai",
                "OpenAI",
                "OA",
                "GPT models. Your OpenAI key stays on the gateway; apps only ever hold a gateway key.",
                "export OPENAI_API_KEY=sk-...\n",
                [],
            ),
            (
                "anthropic",
                "Anthropic",
                "AN",
                "Claude models, including for Claude Code.",
                "export ANTHROPIC_API_KEY=sk-ant-...\n",
                [],
            ),
            (
                "gemini",
                "Google Gemini",
                "GE",
                "Gemini through Google's OpenAI-compatible endpoint.",
                "export GEMINI_API_KEY=...\n",
                [],
            ),
            (
                "mistral",
                "Mistral, Groq, DeepSeek",
                "MG",
                "OpenAI-compatible providers with presets: --provider mistral, groq or deepseek.",
                "export MISTRAL_API_KEY=...\n",
                [],
            ),
            (
                "ollama",
                "Ollama (local models)",
                "OL",
                "Models on your own hardware. Useful for testing; local models do not need redaction to keep data in.",
                "",
                [
                    {
                        "kind": "info",
                        "text": "A local http upstream makes the config a development config: production requires https upstreams.",
                    }
                ],
            ),
        ]
    ],
]


def render_md(x: dict) -> str:
    sub = {"{OPENAI_BASE}": "http://localhost:8080/v1", "{ANTHROPIC_BASE}": "http://localhost:8080", "{KEY}": "$HARPO_KEY",
           "{MODEL}": "gpt-4o-mini", "{CLAUDE_MODEL}": "claude-sonnet-5-5"}  # fmt: skip

    def fill(s: str) -> str:
        for k, v in sub.items():
            s = s.replace(k, v)
        return s

    out = [
        f"# {x['name']}",
        "",
        f"*{x['category']}* · {'verified end to end against the gateway' if x['verified'] else 'configured per the vendor documentation'}",
        "",
        fill(x["summary"]),
        "",
    ]
    if x["steps"]:
        out += [f"{i}. {fill(s)}" for i, s in enumerate(x["steps"], 1)] + [""]
    for sn in x["snippets"]:
        out += [f"**{sn['label']}**", "", f"```{sn['lang']}", fill(sn["code"]), "```", ""]
    for n in x["notes"]:
        out += [f"> {'**Note.** ' if n['kind'] == 'info' else '**Caution.** '}{fill(n['text'])}", ""]
    if x["docs"]:
        out += [f"Vendor documentation: {x['docs']}", ""]
    out += ["`$HARPO_KEY` is a gateway key (`harpo init` creates one). The provider key never leaves the gateway.", ""]
    return "\n".join(out)


def main() -> None:
    catalog = {"categories": CATEGORIES, "items": ITEMS}
    (ROOT / "src/harpo_redact/console/integrations.json").write_text(
        json.dumps(catalog, ensure_ascii=False, separators=(",", ":"))
    )
    docs = ROOT / "docs/integrations"
    docs.mkdir(parents=True, exist_ok=True)
    rows = [
        "# Integrations",
        "",
        "Every integration is one setting: the base URL. Pick yours; each page has copy-paste configuration.",
        "The console (`/#/integrations`) shows the same catalog with your gateway's address and key filled in.",
        "",
    ]
    for cat in CATEGORIES:
        rows += [f"## {cat}", "", "| Integration | Status | |", "| --- | --- | --- |"]
        for x in (i for i in ITEMS if i["category"] == cat):
            (docs / f"{x['id']}.md").write_text(render_md(x))
            status = "verified" if x["verified"] else ("see the note" if x["caveat"] else "per vendor docs")
            rows.append(f"| [{x['name']}]({x['id']}.md) | {status} | {re.sub(r'`', '', x['summary'].split('. ')[0])} |")
        rows.append("")
    (docs / "README.md").write_text("\n".join(rows))
    print(f"{len(ITEMS)} integrations; {sum(i['verified'] for i in ITEMS)} verified")


if __name__ == "__main__":
    main()
