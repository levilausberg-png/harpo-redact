"""Provider presets shared by `harpo init` and the console's setup wizard."""

from __future__ import annotations

# name: (style, base_url, api_key_env, models). Patterns route any matching model; literal names are listed in
# GET /v1/models for chat apps. Edit freely: this only seeds the config file.
PROVIDERS: dict[str, tuple[str, str, str | None, list[str]]] = {
    "openai": (
        "openai",
        "https://api.openai.com/v1",
        "OPENAI_API_KEY",
        ["gpt-5", "gpt-5-mini", "gpt-4.1", "gpt-4o-mini", "gpt-*", "o*"],
    ),
    "anthropic": (
        "anthropic",
        "https://api.anthropic.com",
        "ANTHROPIC_API_KEY",
        ["claude-sonnet-5-5", "claude-haiku-5-5", "claude-opus-5-5", "claude-fable-5-1", "claude-*"],
    ),
    "openrouter": (
        "openai",
        "https://openrouter.ai/api/v1",
        "OPENROUTER_API_KEY",
        ["anthropic/claude-sonnet-5.5", "openai/gpt-6.1-sol", "google/gemini-3.8-flash", "*"],
    ),
    "gemini": (
        "openai",
        "https://generativelanguage.googleapis.com/v1beta/openai",
        "GEMINI_API_KEY",
        ["gemini-3.8-flash", "gemini-*"],
    ),
    "mistral": (
        "openai",
        "https://api.mistral.ai/v1",
        "MISTRAL_API_KEY",
        ["mistral-large-latest", "mistral-small-latest", "*"],
    ),
    "groq": ("openai", "https://api.groq.com/openai/v1", "GROQ_API_KEY", ["llama-3.3-70b-versatile", "*"]),
    "deepseek": ("openai", "https://api.deepseek.com", "DEEPSEEK_API_KEY", ["deepseek-chat", "deepseek-reasoner"]),
    "ollama": ("openai", "http://localhost:11434/v1", None, ["llama3.2", "*"]),
}


# Extra upstreams a preset adds: OpenRouter also speaks the Anthropic Messages API (Claude Code, Anthropic SDKs).
# name: (style, base_url, api_key_env, models)
COMPANIONS: dict[str, list[tuple[str, str, str, str | None, list[str]]]] = {
    "openrouter": [("openrouter-messages", "anthropic", "https://openrouter.ai/api", "OPENROUTER_API_KEY", ["*"])],
}


# Optional per-language NER models (en is always used). `init` and `up` list the installed ones in the config.
LANGUAGE_MODELS = {"nl": "nl_core_news_sm", "de": "de_core_news_sm", "fr": "fr_core_news_sm", "es": "es_core_news_sm"}

# The MIT-licensed models the Docker image ships, pinned by hash. `up` installs the same files.
_SPACY = "https://github.com/explosion/spacy-models/releases/download"
MODEL_WHEELS = {
    "en_core_web_sm": (
        f"{_SPACY}/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl",
        "1932429db727d4bff3deed6b34cfc05df17794f4a52eeb26cf8928f7c1a0fb85",
    ),
    "de_core_news_sm": (
        f"{_SPACY}/de_core_news_sm-3.8.0/de_core_news_sm-3.8.0-py3-none-any.whl",
        "fec69fec52b1780f2d269d5af7582a5e28028738bd3190532459aeb473bfa3e7",
    ),
    "xx_ent_wiki_sm": (
        f"{_SPACY}/xx_ent_wiki_sm-3.8.0/xx_ent_wiki_sm-3.8.0-py3-none-any.whl",
        "6f3c4b853852ea9e9d2dc76cc950dddb10a7e4c42d813308caefe6c5e8be2f0a",
    ),
}


def installed_language_models() -> dict[str, str]:
    import importlib.util

    return {lang: name for lang, name in LANGUAGE_MODELS.items() if importlib.util.find_spec(name)}


def missing_ner_models(model: str, language_models: dict[str, str], enabled: bool = True) -> list[str]:
    """The spaCy models a configuration asks for that are not installed, each with how to install it.

    spaCy models are not on PyPI, so `pip install harpo-redact` brings none; the boot scripts and the Docker image do.
    A path instead of a package name is checked as a folder."""
    import importlib.util
    import os

    if not enabled:
        return []
    problems = []
    for name in dict.fromkeys([model, *language_models.values()]):
        if os.sep in name or "/" in name:
            if not os.path.isdir(name):
                problems.append(f"the spaCy model folder {name} does not exist")
            continue
        if importlib.util.find_spec(name) is not None:
            continue
        if name in MODEL_WHEELS:
            url, digest = MODEL_WHEELS[name]
            how = f'pip install "{url}#sha256={digest}" (./boot.sh and the Docker image include it)'
        else:
            how = f"python -m spacy download {name}"
        problems.append(
            f"the spaCy model {name} is not installed (detection.ner). Install it with: {how}"
            ", or set detection.ner.enabled: false to run without NER"
        )
    return problems
