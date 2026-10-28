"""Provider adapters: every surface of a request, declared and enforced.

An adapter turns a provider request into text the privacy engine can scan and says what it does with
every part of the request:

* ``scanned``      free text that is scanned and redacted
* ``identifier``   short machine names (model, role, tool name, enum values), checked against a strict
                   shape instead of scanned; an email or a sentence does not fit the shape
* ``stripped``     removed before forwarding (user ids, cache keys, the user's location)
* ``provider``     content the provider produced and signed (thinking blocks): forwarded as it was
* ``unsupported``  cannot be inspected (images, audio, provider-side files): blocked or dropped by policy

After an adapter has run, :func:`enforce_coverage` visits every string, every large number and every key
of the outgoing body. Anything the adapter did not account for is rejected (``policy.unknown_fields:
reject``) or scanned as text (``pass``); it is never forwarded unchecked (INV-07, INV-08). After redaction,
:func:`egress_strings` lists everything that is about to leave, for a final verification scan (INV-01).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any, Literal

from .proxy import (
    _INT_SCAN_MIN,
    _MAX_DEPTH,
    ANTHROPIC_FIELDS,
    OPENAI_FIELDS,
    OPENROUTER_ANTHROPIC_FIELDS,
    OPENROUTER_FIELDS,
    Collector,
    RequestShapeError,
    prepare_anthropic,
    prepare_anthropic_openrouter,
    prepare_openai,
    prepare_openrouter,
)

Handling = Literal["scanned", "identifier", "stripped", "provider", "unsupported"]

# Machine names: models, roles, tool names, enum values, ids, media types, domains. No spaces, no "@".
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9_.:/\-]{1,128}")
# Dict keys outside scanned JSON trees must look like field names.
KEY_RE = re.compile(r"[A-Za-z0-9_$][A-Za-z0-9_.\-:$]{0,79}")


class UncoveredField(ValueError):
    """A part of the request the adapter does not inspect. Carries paths (key names only), never values."""

    def __init__(self, problems: list[tuple[str, str]]) -> None:
        self.problems = problems
        shown = "; ".join(f"'{path}' {why}" for path, why in problems[:5])
        more = f" (and {len(problems) - 5} more)" if len(problems) > 5 else ""
        super().__init__(f"{shown}{more}")


@dataclass(frozen=True)
class Surface:
    path: str  # a JSON path pattern: "messages[].content[].text"
    handling: Handling
    note: str = ""


@dataclass(frozen=True)
class Adapter:
    name: str
    allowed_fields: frozenset[str]
    prepare: Callable[..., None]
    surfaces: tuple[Surface, ...]
    identifier_rules: tuple[str, ...]  # regexes over path patterns whose strings are shape-checked identifiers
    number_rules: tuple[str, ...] = ()  # paths where large integers are not identifiers (a seed)
    guarantees: str = ""
    _identifiers: re.Pattern[str] = field(init=False, repr=False, compare=False)
    _numbers: re.Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_identifiers", re.compile("|".join(f"(?:{r})" for r in self.identifier_rules)))
        object.__setattr__(self, "_numbers", re.compile("|".join(f"(?:{r})" for r in self.number_rules) or r"(?!)"))

    def is_identifier(self, path: str) -> bool:
        return bool(self._identifiers.fullmatch(path))

    def is_number(self, path: str) -> bool:
        return bool(self._numbers.fullmatch(path))

    def describe(self) -> dict[str, Any]:
        by: dict[str, list[str]] = {}
        for s in self.surfaces:
            by.setdefault(s.handling, []).append(s.path)
        return {"surfaces": by, "identifier_rules": len(self.identifier_rules), "guarantees": self.guarantees}


_GUARANTEE = (
    "Every string and key of the forwarded body is either scanned, a shape-checked identifier, stripped, "
    "provider-signed content forwarded unchanged, or the request is refused. A final deterministic scan of "
    "the whole outgoing body runs before it leaves."
)

OPENAI = Adapter(
    name="openai",
    allowed_fields=OPENAI_FIELDS,
    prepare=prepare_openai,
    surfaces=(
        Surface("messages[].content", "scanned"),
        Surface("messages[].content[].text", "scanned"),
        Surface("messages[].content[].refusal", "scanned"),
        Surface("messages[].refusal", "scanned"),
        Surface("messages[].annotations", "scanned", "url citations: titles and URLs"),
        Surface("messages[].tool_calls[].function.arguments", "scanned", "JSON parsed; keys and values"),
        Surface("messages[].tool_calls[].custom.input", "scanned"),
        Surface("messages[].function_call.arguments", "scanned"),
        Surface("messages[].name", "stripped", "for system, developer, user and assistant messages"),
        Surface("prediction.content", "scanned"),
        Surface("tools[].function.description", "scanned"),
        Surface("tools[].function.parameters", "scanned", "JSON schema; keys and values"),
        Surface("tools[].custom.description", "scanned"),
        Surface("tools[].custom.format.definition", "scanned", "grammar text"),
        Surface("functions[].description", "scanned"),
        Surface("functions[].parameters", "scanned"),
        Surface("response_format.json_schema.description", "scanned"),
        Surface("response_format.json_schema.schema", "scanned"),
        Surface("stop", "scanned"),
        Surface("extra_body", "scanned", "provider extensions, scanned as JSON"),
        Surface("user", "stripped"),
        Surface("safety_identifier", "stripped"),
        Surface("metadata", "stripped"),
        Surface("prompt_cache_key", "stripped"),
        Surface("web_search_options.user_location", "stripped"),
        Surface("messages[].content[] (image_url, input_audio, file_id)", "unsupported"),
        Surface("messages[].content[] (file with file_data)", "scanned", "documents.in_chat: extracted and scanned"),
    ),
    identifier_rules=(
        r"model",
        r"service_tier",
        r"reasoning_effort",
        r"verbosity",
        r"prompt_cache_retention",
        r"modalities\[\]",
        r"audio\.(voice|format)",
        r"tool_choice",
        r"tool_choice\.(type|mode|function\.name|custom\.name)",
        r"tool_choice\.allowed_tools\.(mode|tools\[\]\.(type|function\.name|custom\.name))",
        r"response_format\.(type|json_schema\.name)",
        r"tools\[\]\.(type|function\.name|custom\.name|custom\.format\.(type|syntax))",
        r"functions\[\]\.name",
        r"function_call(\.name)?",
        r"messages\[\]\.(role|tool_call_id|name|audio\.id)",
        r"messages\[\]\.tool_calls\[\]\.(id|type|function\.name|custom\.name)",
        r"messages\[\]\.function_call\.name",
        r"messages\[\]\.content\[\]\.type",
        r"prediction\.(type|content\[\]\.type)",
        r"web_search_options\.search_context_size",
    ),
    number_rules=(r"seed",),
    guarantees=_GUARANTEE,
)

_BLOCK = r"(?:system|messages\[\]\.content|(?:system|messages\[\]\.content)\[\]\.content)\[\]"
ANTHROPIC = Adapter(
    name="anthropic",
    allowed_fields=ANTHROPIC_FIELDS,
    prepare=prepare_anthropic,
    surfaces=(
        Surface("system", "scanned"),
        Surface("system[].text", "scanned"),
        Surface("messages[].content", "scanned"),
        Surface("messages[].content[].text", "scanned"),
        Surface("messages[].content[].citations[].(cited_text|document_title|title)", "scanned"),
        Surface("messages[].content[].input", "scanned", "tool_use input; keys and values"),
        Surface("messages[].content[].content", "scanned", "tool_result content"),
        Surface("messages[].content[].source.(data|content)", "scanned", "text documents"),
        Surface("messages[].content[].(title|context)", "scanned"),
        Surface("messages[].content[] (search_result).(source|title|content[].text)", "scanned"),
        Surface("messages[].content[] (thinking, redacted_thinking)", "provider", "signed by the provider"),
        Surface("tools[].description", "scanned"),
        Surface("tools[].input_schema", "scanned"),
        Surface("tools[].input_examples", "scanned"),
        Surface("output_format.schema", "scanned"),
        Surface("output_config.format.schema", "scanned"),
        Surface("stop_sequences[]", "scanned"),
        Surface("metadata", "stripped", "including user_id"),
        Surface("tools[].user_location", "stripped", "web search location"),
        Surface("mcp_servers", "unsupported", "blocked unless policy.remote_mcp: allow"),
        Surface("messages[].content[] (image, file and URL sources, container_upload)", "unsupported"),
    ),
    identifier_rules=(
        r"model",
        r"service_tier",
        r"container(\.id)?",
        r"thinking\.type",
        r"tool_choice\.(type|name)",
        r"tools\[\]\.(type|name|cache_control\.(type|ttl)|allowed_domains\[\]|blocked_domains\[\]|allowed_callers\[\])",
        r"output_format\.type",
        r"output_config\.(effort|format\.type)",
        r"cache_control\.(type|ttl)",
        r"speed",
        r"inference_geo",
        r"context_management\.edits\[\]\.(type|trigger\.type|keep\.type|clear_at_least\.type|exclude_tools\[\])",
        r"messages\[\]\.role",
        rf"{_BLOCK}\.(type|id|name|tool_use_id|cache_control\.(type|ttl)|source\.(type|media_type))",
        rf"{_BLOCK}\.citations\[\]\.type",
    ),
    guarantees=_GUARANTEE,
)

# --------------------------------------------------------------------------- OpenRouter
# OpenRouter speaks both APIs and adds routing, plugins and reasoning fields. The gateway enforces its routing
# policy on them (data_collection, zdr, only, ignore) and checks every model a request names.
_OPENROUTER_SURFACES = (
    Surface("provider.data_collection", "identifier", "enforced by gateway policy (deny by default)"),
    Surface("provider.zdr", "identifier", "enforced when the policy requires zero data retention"),
    Surface("provider.options", "scanned", "provider-specific options, scanned as data"),
    Surface("models[]", "identifier", "every fallback model must be allowed for this upstream"),
    Surface("fallbacks[].model", "identifier", "every fallback model must be allowed for this upstream"),
    Surface("plugins[].search_prompt", "scanned", "web search: the text the search engine receives"),
    Surface("plugins[].(include_domains|exclude_domains|allowed_domains|blocked_domains|rules)[]", "scanned"),
    Surface("plugins[].(allowed_models|excluded_models|analysis_models|models)[]", "scanned",
            "router plugins are allowed only when this upstream allows any model"),
    Surface("plugins[].x_search", "scanned"),
    Surface("plugins[].tools[].parameters", "scanned"),
    Surface("plugins[].user_location", "stripped", "the end user's location"),
    Surface("stop_server_tools_when", "scanned"),
    Surface("session_id", "stripped", "sticky-routing key"),
    Surface("trace", "stripped", "tracing metadata"),
)  # fmt: skip
_OPENROUTER_RULES = (
    r"models\[\]",
    r"fallbacks\[\]\.model",
    r"route",
    r"transforms\[\]",
    r"reasoning\.(effort|summary)",
    r"provider\.(order|only|ignore|quantizations)\[\]",
    r"provider\.(data_collection|sort|sort\.(by|partition))",
    r"provider\.max_price\.(prompt|completion|image|audio|request)",
    r"plugins\[\]\.(id|engine|mode|cost_tier|preset|price_source|algorithm|judge_model|model|pdf\.engine|tools\[\]\.type)",
    r"cache_control\.(type|ttl)",
    r"prompt_cache_options\.(mode|ttl)",
)
OPENROUTER = Adapter(
    name="openrouter",
    allowed_fields=OPENAI_FIELDS | OPENROUTER_FIELDS,
    prepare=prepare_openrouter,
    surfaces=(
        *OPENAI.surfaces,
        Surface("messages[].reasoning", "scanned", "reasoning text sent back in a conversation"),
        Surface("messages[].reasoning_details", "provider", "signed reasoning: unchanged, verified at egress"),
        Surface("messages[].images", "unsupported", "generated images cannot be inspected"),
        Surface("response_format.grammar", "scanned"),
        Surface("image_config", "scanned", "provider-specific image options, scanned as data"),
        *_OPENROUTER_SURFACES,
    ),
    identifier_rules=(
        *OPENAI.identifier_rules,
        *_OPENROUTER_RULES,
        r"messages\[\]\.content\[\]\.cache_control\.(type|ttl)",
        r"messages\[\]\.(model|configuration_update\.reasoning\.effort)",
    ),
    number_rules=OPENAI.number_rules,
    guarantees=_GUARANTEE,
)  # fmt: skip
OPENROUTER_ANTHROPIC = Adapter(
    name="openrouter_anthropic",
    allowed_fields=ANTHROPIC_FIELDS | OPENROUTER_ANTHROPIC_FIELDS,
    prepare=prepare_anthropic_openrouter,
    surfaces=(*ANTHROPIC.surfaces, Surface("user", "stripped", "an end-user identifier"), *_OPENROUTER_SURFACES),
    identifier_rules=(*ANTHROPIC.identifier_rules, *_OPENROUTER_RULES),
    number_rules=ANTHROPIC.number_rules,
    guarantees=_GUARANTEE,
)

ADAPTERS: dict[str, Adapter] = {a.name: a for a in (OPENAI, ANTHROPIC, OPENROUTER, OPENROUTER_ANTHROPIC)}


def adapter_for(style: str, dialect: str) -> Adapter:
    """The adapter for an upstream: its API style, and OpenRouter's extensions when it speaks that dialect."""
    if dialect == "openrouter":
        return OPENROUTER if style == "openai" else OPENROUTER_ANTHROPIC
    return ADAPTERS[style]


def _key_label(key: Any) -> str:
    return key if isinstance(key, str) and KEY_RE.fullmatch(key) else "?"


def enforce_coverage(body: dict[str, Any], collector: Collector, adapter: Adapter, mode: str) -> int:
    """Account for every string, large number and key of the body. Returns how many strings were added
    for scanning (``pass`` mode); raises :class:`UncoveredField` (``reject`` mode) or RequestShapeError."""
    problems: list[tuple[str, str]] = []
    added = 0

    def visit(node: Any, path: str, depth: int, in_tree: bool) -> None:
        nonlocal added
        if depth > _MAX_DEPTH:
            raise RequestShapeError("the request is nested too deeply to inspect")
        items = node.items() if isinstance(node, dict) else enumerate(node)
        tree = in_tree or id(node) in collector.tree_nodes
        for key, value in list(items):
            if isinstance(node, dict):
                child = f"{path}.{_key_label(key)}" if path else _key_label(key)
                if not tree and not (isinstance(key, str) and KEY_RE.fullmatch(key)):
                    if mode == "pass":
                        collector.add_json_tree(node)  # scans keys and values of this object
                        added += 1
                        tree = True
                    else:
                        problems.append((child, "has a key the gateway cannot inspect"))
            else:
                child = f"{path}[]"
            covered = (id(node), key) in collector.covered
            if isinstance(value, str):
                if covered:
                    continue
                if adapter.is_identifier(child):
                    if not IDENTIFIER_RE.fullmatch(value):
                        problems.append((child, "is not a valid identifier"))
                elif mode == "pass":
                    collector.add(node, key)
                    added += 1
                else:
                    problems.append((child, "is not inspected by this gateway"))
            elif isinstance(value, int) and not isinstance(value, bool) and abs(value) >= _INT_SCAN_MIN:
                if covered or adapter.is_number(child):
                    continue
                if mode == "pass":
                    collector.add_number(node, key)
                    added += 1
                else:
                    problems.append((child, "is a large number the gateway does not inspect"))
            elif isinstance(value, (dict, list)):
                visit(value, child, depth + 1, tree)

    visit(body, "", 0, False)
    if problems:
        raise UncoveredField(problems)
    return added


def egress_strings(body: Any, adapter: Adapter | None = None) -> Iterator[str]:
    """Every string value, every key and every large number that is about to leave the gateway.
    Numbers at paths the adapter declares numeric (a seed) are not identifiers and are skipped."""
    stack: list[tuple[Any, str, int]] = [(body, "", 0)]
    while stack:
        node, path, depth = stack.pop()
        if depth > _MAX_DEPTH:
            raise RequestShapeError("the request is nested too deeply to inspect")
        items = node.items() if isinstance(node, dict) else enumerate(node)
        for key, value in items:
            if isinstance(node, dict):
                child = f"{path}.{_key_label(key)}" if path else _key_label(key)
                if isinstance(key, str):
                    yield key
            else:
                child = f"{path}[]"
            if isinstance(value, str):
                yield value
            elif isinstance(value, int) and not isinstance(value, bool) and abs(value) >= _INT_SCAN_MIN:
                if adapter is None or not adapter.is_number(child):
                    yield str(value)
            elif isinstance(value, (dict, list)):
                stack.append((value, child, depth + 1))
