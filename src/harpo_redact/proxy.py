"""Request rewriting for the OpenAI- and Anthropic-compatible proxies.

Every text field of a request is collected into one list, scanned in one
pass (so relational indices agree across the whole conversation), and the
redacted strings are written back in place. Parts that cannot be inspected
(images, audio, binary files, unknown block types) are blocked by default or
dropped when ``policy.unsupported_content`` is ``drop``.

Error messages raised here never quote request content.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator
from typing import Any

REMOVED_MARKER = "[attachment removed by privacy gateway]"
_INT_SCAN_MIN = 10**6  # integers this large can be card, phone or ID numbers
_MAX_DEPTH = 64


class RequestShapeError(ValueError):
    """The request does not have a shape the gateway can inspect."""


class TooManyMessages(ValueError):
    pass


class FieldNotAllowed(ValueError):
    """A top-level request field outside the gateway's allowlist."""


class RemoteToolsBlocked(ValueError):
    """The request asks the provider to connect to remote MCP servers."""


class ModelNotAllowed(ValueError):
    """A model the request names (fallback lists, router plugins) is not allowed for this upstream."""


class RoutingPolicyError(ValueError):
    """The provider routing the request asks for leaves nothing the gateway's routing policy permits."""


# Top-level fields the gateway understands. Anything else could carry text the
# scanner never looks at, so it is rejected unless policy.unknown_fields is "pass".
OPENAI_FIELDS = frozenset(
    {
        "model", "messages", "audio", "frequency_penalty", "function_call", "functions", "logit_bias", "logprobs",
        "max_completion_tokens", "max_tokens", "metadata", "modalities", "n", "parallel_tool_calls", "prediction",
        "presence_penalty", "prompt_cache_key", "prompt_cache_retention", "reasoning_effort", "response_format",
        "safety_identifier", "seed", "service_tier", "stop", "store", "stream", "stream_options", "temperature",
        "tool_choice", "tools", "top_logprobs", "top_p", "user", "verbosity", "web_search_options", "extra_body",
    }
)  # fmt: skip
ANTHROPIC_FIELDS = frozenset(
    {
        "model", "messages", "max_tokens", "system", "metadata", "stop_sequences", "stream", "temperature",
        "top_p", "top_k", "tools", "tool_choice", "thinking", "service_tier", "mcp_servers", "container",
        "context_management", "output_format", "output_config", "cache_control", "speed", "inference_geo",
    }
)  # fmt: skip
# OpenRouter's extensions to both APIs (https://openrouter.ai/docs/api/reference): routing, plugins, sampling.
OPENROUTER_FIELDS = frozenset(
    {
        "models", "fallbacks", "route", "provider", "plugins", "transforms", "reasoning", "usage", "debug", "top_k",
        "top_a", "min_p", "repetition_penalty", "image_config", "stop_server_tools_when", "cache_control",
        "prompt_cache_options", "session_id", "trace", "structured_outputs",
    }
)  # fmt: skip
OPENROUTER_ANTHROPIC_FIELDS = frozenset(
    {"provider", "models", "fallbacks", "plugins", "route", "trace", "user", "session_id", "stop_server_tools_when"}
)
# Plugins that let OpenRouter choose (or combine) models: the model receiving the data cannot be checked.
MODEL_CHOOSING_PLUGINS = frozenset(
    {"auto-router", "auto-beta-router", "pareto-router", "switchyard-router", "jev-router", "fusion"}
)


def _scan_definition(container: dict[str, Any], collector: Collector, desc: str, schema: str) -> None:
    """Descriptions and JSON schemas of tools and response formats are prompt text too."""
    if isinstance(container.get(desc), str):
        collector.add(container, desc)
    tree = container.get(schema)
    if isinstance(tree, (dict, list)):
        collector.add_json_tree(tree)


def _scan_stop(body: dict[str, Any], key: str, collector: Collector) -> None:
    stop = body.get(key)
    if isinstance(stop, str):
        collector.add(body, key)
    elif isinstance(stop, list):
        for i, item in enumerate(stop):
            if isinstance(item, str):
                collector.add(stop, i)


Container = dict[str, Any] | list[Any]


def _children(node: Container) -> Iterator[tuple[Container, Any, Any]]:
    if isinstance(node, dict):
        for key, value in node.items():
            yield node, key, value
    else:
        for index, value in enumerate(node):
            yield node, index, value


# Keys that read like field names are not scanned; anything else in a JSON object can be data
# ({"Priya Raman": 120000} in a tool result) and is scanned like any other text. A key with a digit is always
# scanned: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" and "nl91abna0417164300" are lowercase too.
_PLAIN_KEY_RE = re.compile(r"[a-z_$@][a-z_.\-]*|[a-z]+(?:[A-Z][a-z]*)+")
# Keys that structure a value rather than name it. A value's label is the nearest key that is not one of these:
# the property name of a schema "default", the field of a {"value": ...} wrapper.
_STRUCTURAL_KEYS = frozenset(
    """default examples example enum const items properties value values data anyOf oneOf allOf not prefixItems
    additionalProperties patternProperties $defs definitions description title type format pattern input
    arguments parameters content text fields attributes record records payload body params args kwargs result
    results rows row item entry entries object list array input_schema schema""".split()  # noqa: SIM905
)  # fmt: skip
_LABEL_DEPTH = 3
# A key that can name its value: words of letters ("passport_number", "dateOfBirth", "Passport Number"). A key
# with digits may be data itself and never becomes part of a label.
_LABEL_KEY_RE = re.compile(r"[^\W\d_]+(?:[ _.\-]?[^\W\d_]+)*")


def _label(path: tuple[str, ...]) -> str | None:
    return ".".join(path[-_LABEL_DEPTH:]) if path else None


# Name/value records carry the label in a sibling: [{"name": "ssn", "value": "..."}], {"key": "...", "value": ...},
# {"field": "date_of_birth", "data": "..."} (form submissions, CRM properties, header lists).
_NAME_KEYS = ("name", "key", "field", "label", "property", "attribute", "header", "param", "parameter")
_VALUE_KEYS = frozenset({"value", "values", "data", "val", "content", "text"})


def _sibling_label(node: dict[Any, Any]) -> str | None:
    for key in _NAME_KEYS:
        name = node.get(key)
        if isinstance(name, str) and len(name) <= 64 and _LABEL_KEY_RE.fullmatch(name):
            return name
    return None


def _rename_key(container: dict[Any, Any], old: str, new: str) -> None:
    if new == old or old not in container:
        return
    target, n = new, 2
    while target in container:
        target, n = f"{new}#{n}", n + 1
    items = list(container.items())
    container.clear()
    for k, v in items:
        container[target if k == old else k] = v


class Collector:
    def __init__(self, drop_unsupported: bool) -> None:
        self.texts: list[str] = []
        # Per text, the field name it was found under (JSON leaves and keys), else None: pipeline.scan(labels=...).
        self.labels: list[str | None] = []
        self._setters: list[Callable[[str], None]] = []
        self._finalizers: list[Callable[[], None]] = []
        self.unsupported = 0
        self.dropped = 0
        self._drop = drop_unsupported
        # What the adapter accounted for, so a coverage walk can find what it did not (adapters.py).
        self.covered: set[tuple[int, Any]] = set()
        self.tree_nodes: set[int] = set()
        self._pins: list[Any] = []  # keeps containers alive so their ids stay unique
        self.notes: dict[str, Any] = {}  # content-free facts for the request record (enforced routing)

    @property
    def total_chars(self) -> int:
        return sum(len(t) for t in self.texts)

    def mark(self, container: Container, key: Any) -> None:
        self.covered.add((id(container), key))
        self._pins.append(container)

    def mark_tree(self, node: Any) -> None:
        """Account for a whole subtree without scanning it (unsupported or provider-signed content)."""
        if not isinstance(node, (dict, list)):
            return
        stack = [node]
        while stack:
            current = stack.pop()
            if len(self._pins) > 1_000_000:
                raise RequestShapeError("the request is too large to inspect")
            self.tree_nodes.add(id(current))
            self._pins.append(current)
            for container, key, value in _children(current):
                self.covered.add((id(container), key))
                if isinstance(value, (dict, list)):
                    stack.append(value)

    def add(self, container: Container, key: Any, label: str | None = None) -> None:
        value = container[key]
        self.texts.append(value)
        self.labels.append(label)
        self.mark(container, key)

        def setter(v: str, c: Any = container, k: Any = key) -> None:
            c[k] = v

        self._setters.append(setter)

    def add_number(self, container: Container, key: Any, label: str | None = None) -> None:
        original = container[key]
        self.texts.append(str(original))
        self.labels.append(label)
        self.mark(container, key)

        def setter(v: str, c: Any = container, k: Any = key, o: int = original) -> None:
            c[k] = o if v == str(o) else v

        self._setters.append(setter)

    def add_json_tree(self, node: Container) -> None:
        """Collect string leaves, large integers and data-like keys, in document order. Each is labelled with the
        nearest meaningful keys above it, so "298163871" under "bsn" is checked as a BSN."""
        self.tree_nodes.add(id(node))
        self._pins.append(node)
        stack: list[tuple[Iterator[tuple[Container, Any, Any]], tuple[str, ...]]] = [(_children(node), ())]
        while stack:
            if len(stack) > _MAX_DEPTH:
                raise RequestShapeError("a JSON value is nested too deeply to inspect")
            children, path = stack[-1]
            try:
                container, key, value = next(children)
            except StopIteration:
                stack.pop()
                continue
            child = path
            if isinstance(container, dict) and isinstance(key, str):
                if not _PLAIN_KEY_RE.fullmatch(key) and any(c.isalnum() for c in key):
                    self._add_key(container, key, _label(path))
                if key not in _STRUCTURAL_KEYS and len(key) <= 64 and _LABEL_KEY_RE.fullmatch(key):
                    child = (*path, key)
                elif key in _VALUE_KEYS and (sibling := _sibling_label(container)) is not None:
                    child = (*path, sibling)
            if isinstance(value, str):
                self.add(container, key, _label(child))
            elif isinstance(value, bool):
                continue
            elif isinstance(value, int) and abs(value) >= _INT_SCAN_MIN:
                self.add_number(container, key, _label(child))
            elif isinstance(value, (dict, list)):
                self.tree_nodes.add(id(value))
                self._pins.append(value)
                stack.append((_children(value), child))

    def _add_key(self, container: dict[Any, Any], key: str, label: str | None = None) -> None:
        """A key is renamed after all values were written, so value setters still find their entry."""
        self.texts.append(key)
        self.labels.append(label)
        pending = [key]

        def setter(v: str, p: list[str] = pending) -> None:
            p[0] = v

        def finalize(c: dict[Any, Any] = container, k: str = key, p: list[str] = pending) -> None:
            _rename_key(c, k, p[0])

        self._setters.append(setter)
        self._finalizers.append(finalize)

    def add_json_string(self, container: Container, key: Any) -> None:
        """Tool-call arguments arrive as a JSON string: scan its leaves, re-serialise if changed."""
        raw = container[key]
        self.mark(container, key)
        try:
            parsed = json.loads(raw)
        except (ValueError, RecursionError):
            self.add(container, key)
            return
        if not isinstance(parsed, (dict, list)):
            self.add(container, key)
            return
        first = len(self._setters)
        self.add_json_tree(parsed)
        dirty = [False]
        for i in range(first, len(self._setters)):
            inner = self._setters[i]

            def wrapped(v: str, inner: Callable[[str], None] = inner, before: str = self.texts[i]) -> None:
                if v != before:
                    dirty[0] = True
                inner(v)

            self._setters[i] = wrapped

        def finalize(c: Any = container, k: Any = key, obj: Container = parsed) -> None:
            if dirty[0]:
                c[k] = json.dumps(obj, ensure_ascii=False)

        self._finalizers.append(finalize)

    def unsupported_part(self, part: Any = None) -> bool:
        """Record a part that can't be inspected; return True if it should be kept (the request is then blocked)."""
        if self._drop:
            self.dropped += 1
            return False
        self.unsupported += 1
        self.mark_tree(part)
        return True

    def apply(self, redacted: list[str]) -> None:
        if len(redacted) != len(self._setters):
            raise RuntimeError("redacted text count does not match collected fields")
        for setter, value in zip(self._setters, redacted, strict=True):
            setter(value)
        for finalize in self._finalizers:
            finalize()


def _require_messages(body: dict[str, Any], max_messages: int) -> list[Any]:
    messages = body.get("messages")
    if not isinstance(messages, list) or not messages:
        raise RequestShapeError("messages must be a non-empty array")
    if len(messages) > max_messages:
        raise TooManyMessages(f"at most {max_messages} messages are allowed")
    return messages


# --------------------------------------------------------------------------- OpenAI
OPENAI_ROLES = frozenset({"system", "developer", "user", "assistant", "tool", "function"})
_PEOPLE_ROLES = frozenset({"system", "developer", "user", "assistant"})
_OPENAI_DROPPED_FIELDS = ("user", "safety_identifier", "metadata", "prompt_cache_key")


def _openai_parts(parts: list[Any], collector: Collector, where: str) -> list[Any]:
    kept: list[Any] = []
    removed = False
    for j, part in enumerate(parts):
        if not isinstance(part, dict):
            raise RequestShapeError(f"{where}[{j}] must be an object")
        ptype = part.get("type")
        if not isinstance(ptype, str):
            raise RequestShapeError(f"{where}[{j}].type must be a string")
        if ptype == "text" and isinstance(part.get("text"), str):
            collector.add(part, "text")
            kept.append(part)
        elif ptype == "refusal" and isinstance(part.get("refusal"), str):
            collector.add(part, "refusal")
            kept.append(part)
        elif collector.unsupported_part(part):
            kept.append(part)
        else:
            removed = True
    if removed:
        marker = {"type": "text", "text": REMOVED_MARKER}
        collector.mark_tree(marker)  # the gateway's own words: nothing to inspect
        kept.append(marker)
    return kept


def prepare_openai(
    body: dict[str, Any], collector: Collector, max_messages: int, *, remote_mcp: bool = False, upstream: Any = None
) -> None:
    messages = _require_messages(body, max_messages)
    for i, message in enumerate(messages):
        if not isinstance(message, dict):
            raise RequestShapeError(f"messages[{i}] must be an object")
        role = message.get("role")
        if not isinstance(role, str) or role not in OPENAI_ROLES:
            raise RequestShapeError(f"messages[{i}].role is not supported")
        if role in _PEOPLE_ROLES:
            message.pop("name", None)  # participant names identify people
        content = message.get("content")
        if isinstance(content, str):
            collector.add(message, "content")
        elif isinstance(content, list):
            message["content"] = _openai_parts(content, collector, f"messages[{i}].content")
        elif content is not None:
            raise RequestShapeError(f"messages[{i}].content must be a string, an array or null")
        tool_calls = message.get("tool_calls")
        if tool_calls is not None:
            if not isinstance(tool_calls, list):
                raise RequestShapeError(f"messages[{i}].tool_calls must be an array")
            for call in tool_calls:
                if not isinstance(call, dict):
                    raise RequestShapeError(f"messages[{i}].tool_calls entries must be objects")
                function = call.get("function")
                if isinstance(function, dict) and isinstance(function.get("arguments"), str):
                    collector.add_json_string(function, "arguments")
                custom = call.get("custom")
                if isinstance(custom, dict) and isinstance(custom.get("input"), str):
                    collector.add(custom, "input")
        function_call = message.get("function_call")
        if isinstance(function_call, dict) and isinstance(function_call.get("arguments"), str):
            collector.add_json_string(function_call, "arguments")
        if isinstance(message.get("refusal"), str):
            collector.add(message, "refusal")
        if isinstance(message.get("annotations"), list):  # url citations: titles and URLs
            collector.add_json_tree(message["annotations"])
    prediction = body.get("prediction")
    if isinstance(prediction, dict):
        predicted = prediction.get("content")
        if isinstance(predicted, str):
            collector.add(prediction, "content")
        elif isinstance(predicted, list):
            prediction["content"] = _openai_parts(predicted, collector, "prediction.content")
    tools = body.get("tools")
    if tools is not None:
        if not isinstance(tools, list):
            raise RequestShapeError("tools must be an array")
        for tool in tools:
            if not isinstance(tool, dict) or tool.get("type", "function") not in ("function", "custom"):
                raise RequestShapeError("tools entries must be function or custom tools")
            inner = tool.get(tool.get("type", "function"))
            if isinstance(inner, dict):
                _scan_definition(inner, collector, "description", "parameters")
                grammar = inner.get("format")
                if isinstance(grammar, dict) and isinstance(grammar.get("definition"), str):
                    collector.add(grammar, "definition")
    functions = body.get("functions")
    if isinstance(functions, list):
        for function in functions:
            if isinstance(function, dict):
                _scan_definition(function, collector, "description", "parameters")
    response_format = body.get("response_format")
    if isinstance(response_format, dict) and isinstance(response_format.get("json_schema"), dict):
        _scan_definition(response_format["json_schema"], collector, "description", "schema")
    _scan_stop(body, "stop", collector)
    extra = body.get("extra_body")
    if isinstance(extra, (dict, list)):  # provider extensions travel as data: scanned, keys included
        collector.add_json_tree(extra)
    elif isinstance(extra, str):
        collector.add(body, "extra_body")
    search = body.get("web_search_options")
    if isinstance(search, dict):
        search.pop("user_location", None)  # the user's city and country
    for field in _OPENAI_DROPPED_FIELDS:
        body.pop(field, None)
    if "store" in body:
        body["store"] = False


# --------------------------------------------------------------------------- Anthropic
ANTHROPIC_ROLES = frozenset({"user", "assistant"})
_UNTOUCHED_BLOCKS = frozenset({"thinking", "redacted_thinking"})  # signed by the provider
_SIGNED_BLOCK_KEYS = frozenset({"type", "thinking", "signature", "data", "cache_control"})


def _citations(block: dict[str, Any], collector: Collector) -> None:
    citations = block.get("citations")
    if not isinstance(citations, list):
        return
    for citation in citations:
        if isinstance(citation, dict):
            for key in ("cited_text", "document_title", "title"):
                if isinstance(citation.get(key), str):
                    collector.add(citation, key)


def _text_document(block: dict[str, Any], collector: Collector) -> bool:
    source = block.get("source")
    if not isinstance(source, dict):
        return False
    stype = source.get("type")
    if stype == "text" and isinstance(source.get("data"), str):
        collector.add(source, "data")
    elif stype == "content" and isinstance(source.get("content"), str):
        collector.add(source, "content")
    elif stype == "content" and isinstance(source.get("content"), list):
        inner = source["content"]
        if not all(isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str) for b in inner):
            return False
        for b in inner:
            collector.add(b, "text")
    else:
        return False
    for key in ("title", "context"):
        if isinstance(block.get(key), str):
            collector.add(block, key)
    return True


def _search_result(block: dict[str, Any], collector: Collector) -> bool:
    content = block.get("content")
    if not isinstance(content, list) or not all(
        isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str) for b in content
    ):
        return False
    for key in ("source", "title"):
        if isinstance(block.get(key), str):
            collector.add(block, key)
    for b in content:
        collector.add(b, "text")
    return True


def _anthropic_blocks(blocks: list[Any], collector: Collector, where: str) -> list[Any]:
    kept: list[Any] = []
    removed = False
    for j, block in enumerate(blocks):
        if not isinstance(block, dict):
            raise RequestShapeError(f"{where}[{j}] must be an object")
        btype = block.get("type")
        if not isinstance(btype, str):
            raise RequestShapeError(f"{where}[{j}].type must be a string")
        if btype == "text" and isinstance(block.get("text"), str):
            collector.add(block, "text")
            _citations(block, collector)
            kept.append(block)
        elif btype in _UNTOUCHED_BLOCKS:
            if not set(block) <= _SIGNED_BLOCK_KEYS:  # nothing may ride along on a signed block
                raise RequestShapeError(f"{where}[{j}] has fields a {btype} block does not have")
            collector.mark_tree(block)  # produced and signed by the provider: forwarded as it was
            kept.append(block)
        elif btype in ("tool_use", "server_tool_use"):
            tool_input = block.get("input")
            if isinstance(tool_input, (dict, list)):
                collector.add_json_tree(tool_input)
            elif isinstance(tool_input, str):
                collector.add(block, "input")
            kept.append(block)
        elif btype == "tool_result":
            content = block.get("content")
            if isinstance(content, str):
                collector.add(block, "content")
            elif isinstance(content, list):
                block["content"] = _anthropic_blocks(content, collector, f"{where}[{j}].content")
            kept.append(block)
        elif btype == "document" and _text_document(block, collector):  # noqa: SIM114
            kept.append(block)
        elif btype == "search_result" and _search_result(block, collector):  # noqa: SIM114
            kept.append(block)
        elif collector.unsupported_part(block):
            kept.append(block)
        else:
            removed = True
    if removed:
        marker = {"type": "text", "text": REMOVED_MARKER}
        collector.mark_tree(marker)  # the gateway's own words: nothing to inspect
        kept.append(marker)
    return kept


def prepare_anthropic(
    body: dict[str, Any], collector: Collector, max_messages: int, *, remote_mcp: bool = False, upstream: Any = None
) -> None:
    if body.get("mcp_servers") and not remote_mcp:
        raise RemoteToolsBlocked("mcp_servers")
    system = body.get("system")
    if isinstance(system, str):
        collector.add(body, "system")
    elif isinstance(system, list):
        body["system"] = _anthropic_blocks(system, collector, "system")
    elif system is not None:
        raise RequestShapeError("system must be a string or an array")
    messages = _require_messages(body, max_messages)
    for i, message in enumerate(messages):
        if not isinstance(message, dict):
            raise RequestShapeError(f"messages[{i}] must be an object")
        if not isinstance(message.get("role"), str) or message.get("role") not in ANTHROPIC_ROLES:
            raise RequestShapeError(f"messages[{i}].role is not supported")
        content = message.get("content")
        if isinstance(content, str):
            collector.add(message, "content")
        elif isinstance(content, list):
            message["content"] = _anthropic_blocks(content, collector, f"messages[{i}].content")
        else:
            raise RequestShapeError(f"messages[{i}].content must be a string or an array")
    tools = body.get("tools")
    if tools is not None:
        if not isinstance(tools, list):
            raise RequestShapeError("tools must be an array")
        for tool in tools:
            if not isinstance(tool, dict):
                raise RequestShapeError("tools entries must be objects")
            tool_type = str(tool.get("type") or "custom")
            if tool_type == "custom" or "input_schema" in tool:
                _scan_definition(tool, collector, "description", "input_schema")
                if isinstance(tool.get("input_examples"), list):
                    collector.add_json_tree(tool["input_examples"])
            if tool_type.startswith("web_search"):
                tool.pop("user_location", None)  # the user's city, region and timezone
    _scan_stop(body, "stop_sequences", collector)
    output_format = body.get("output_format")
    if isinstance(output_format, dict) and isinstance(output_format.get("schema"), (dict, list)):
        collector.add_json_tree(output_format["schema"])
    output_config = body.get("output_config")
    if isinstance(output_config, dict):  # output_config.format replaces output_format
        fmt = output_config.get("format")
        if isinstance(fmt, dict) and isinstance(fmt.get("schema"), (dict, list)):
            collector.add_json_tree(fmt["schema"])
    body.pop("metadata", None)  # user_id is its only documented field, and anything else in it is a side channel


# --------------------------------------------------------------------------- OpenRouter
def _scan_strings(values: Any, collector: Collector) -> None:
    if isinstance(values, list):
        for k, value in enumerate(values):
            if isinstance(value, str):
                collector.add(values, k)


def _openrouter_models(body: dict[str, Any]) -> list[str]:
    """Every model a request names besides `model`: the fallback list and fallback objects."""
    named: list[str] = []
    models = body.get("models")
    if models is not None:
        if not isinstance(models, list) or not all(isinstance(m, str) for m in models):
            raise RequestShapeError("models must be an array of model names")
        named.extend(models)
    fallbacks = body.get("fallbacks")
    if fallbacks is not None:
        if not isinstance(fallbacks, list):
            raise RequestShapeError("fallbacks must be an array")
        for entry in fallbacks:
            if not (isinstance(entry, dict) and isinstance(entry.get("model"), str)):
                raise RequestShapeError("fallbacks entries must be objects with a model")
            named.append(entry["model"])
    return named


def _openrouter_plugins(body: dict[str, Any], collector: Collector) -> list[str]:
    """Scan the free text plugins carry, strip the user's location; return the model-choosing plugins in use."""
    plugins = body.get("plugins")
    if plugins is None:
        return []
    if not isinstance(plugins, list):
        raise RequestShapeError("plugins must be an array")
    choosing: list[str] = []
    for j, plugin in enumerate(plugins):
        if not isinstance(plugin, dict) or not isinstance(plugin.get("id"), str):
            raise RequestShapeError(f"plugins[{j}] must be an object with an id")
        if isinstance(plugin.get("search_prompt"), str):  # web search: text the search engine receives
            collector.add(plugin, "search_prompt")
        for key in ("include_domains", "exclude_domains", "allowed_domains", "blocked_domains", "rules"):
            _scan_strings(plugin.get(key), collector)
        for key in ("allowed_models", "excluded_models", "analysis_models", "models"):
            _scan_strings(plugin.get(key), collector)
        if isinstance(plugin.get("x_search"), (dict, list)):
            collector.add_json_tree(plugin["x_search"])
        tools = plugin.get("tools")
        if isinstance(tools, list):
            for tool in tools:
                if isinstance(tool, dict) and isinstance(tool.get("parameters"), (dict, list)):
                    collector.add_json_tree(tool["parameters"])
        plugin.pop("user_location", None)  # the end user's city, region and timezone
        if plugin["id"] in MODEL_CHOOSING_PLUGINS and plugin.get("enabled", True) is not False:
            choosing.append(plugin["id"])
    return choosing


def _enforce_routing(body: dict[str, Any], upstream: Any) -> dict[str, Any]:
    """Apply the upstream's OpenRouter routing policy. Clients may tighten it, never loosen it."""
    cfg = upstream.openrouter
    provider = body.get("provider")
    if provider is None:
        provider = {}
    elif not isinstance(provider, dict):
        raise RequestShapeError("provider must be an object")
    applied: dict[str, Any] = {}
    if cfg.data_collection == "deny":
        provider["data_collection"] = "deny"
        applied["data_collection"] = "deny"
    elif isinstance(provider.get("data_collection"), str):
        applied["data_collection"] = provider["data_collection"]
    if cfg.zdr:
        provider["zdr"] = True
        applied["zdr"] = True
    elif provider.get("zdr") is True:
        applied["zdr"] = True
    if cfg.only:
        asked = provider.get("only")
        if asked is not None and not isinstance(asked, list):
            raise RequestShapeError("provider.only must be an array")
        allowed = [slug for slug in asked if slug in cfg.only] if asked else list(cfg.only)
        if not allowed:
            raise RoutingPolicyError("none of the providers in provider.only is permitted by gateway policy")
        provider["only"] = allowed
        applied["only"] = allowed
    if cfg.ignore:
        asked = provider.get("ignore") or []
        if not isinstance(asked, list):
            raise RequestShapeError("provider.ignore must be an array")
        provider["ignore"] = list(dict.fromkeys([*asked, *cfg.ignore]))
        applied["ignore"] = len(provider["ignore"])
    if provider:
        body["provider"] = provider
    return applied


def _prepare_openrouter_common(body: dict[str, Any], collector: Collector, upstream: Any) -> None:
    for name in _openrouter_models(body):
        if upstream is not None and not upstream.matches(name):
            raise ModelNotAllowed("a model in the request's fallback list is outside this upstream's models")
    choosing = _openrouter_plugins(body, collector)
    if (
        choosing
        and upstream is not None
        and (upstream.openrouter.model_choosing_plugins == "block" or not upstream.any_model)
    ):
        raise ModelNotAllowed(
            f"plugin '{choosing[0]}' lets the provider choose the model, which this upstream does not allow"
        )
    provider = body.get("provider")
    if isinstance(provider, dict) and isinstance(provider.get("options"), (dict, list)):
        collector.add_json_tree(provider["options"])  # provider-specific options: scanned as data
    for key in ("image_config", "stop_server_tools_when"):
        if isinstance(body.get(key), (dict, list)):
            collector.add_json_tree(body[key])
    for key in ("session_id", "trace"):  # sticky-routing keys and tracing metadata identify users and sessions
        body.pop(key, None)
    if upstream is not None:
        routing = _enforce_routing(body, upstream)
        if routing:
            collector.notes["routing"] = routing


def prepare_openrouter(
    body: dict[str, Any], collector: Collector, max_messages: int, *, remote_mcp: bool = False, upstream: Any = None
) -> None:
    """OpenRouter's OpenAI-compatible API: the OpenAI rules plus OpenRouter's fields."""
    prepare_openai(body, collector, max_messages, remote_mcp=remote_mcp)
    for message in body["messages"]:
        if isinstance(message.get("reasoning"), str):  # reasoning text sent back in a conversation
            collector.add(message, "reasoning")
        details = message.get("reasoning_details")
        if details is not None:
            if not isinstance(details, list):
                raise RequestShapeError("reasoning_details must be an array")
            collector.mark_tree(details)  # signed by the provider: forwarded unchanged, verified at egress
        images = message.get("images")
        if images is not None and not collector.unsupported_part(images):
            message.pop("images", None)  # generated images cannot be inspected
    response_format = body.get("response_format")
    if isinstance(response_format, dict) and isinstance(response_format.get("grammar"), str):
        collector.add(response_format, "grammar")
    _prepare_openrouter_common(body, collector, upstream)


def prepare_anthropic_openrouter(
    body: dict[str, Any], collector: Collector, max_messages: int, *, remote_mcp: bool = False, upstream: Any = None
) -> None:
    """OpenRouter's Anthropic-compatible API: the Anthropic rules plus OpenRouter's fields."""
    prepare_anthropic(body, collector, max_messages, remote_mcp=remote_mcp)
    body.pop("user", None)  # an end-user identifier
    _prepare_openrouter_common(body, collector, upstream)


# --------------------------------------------------------------------------- errors
def error_body(style: str, etype: str, message: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """An error in the provider's own shape, so SDK exceptions behave normally."""
    if style == "anthropic":
        error: dict[str, Any] = {"type": etype, "message": message}
        if extra:
            error["harpo"] = extra
        return {"type": "error", "error": error}
    error = {"message": message, "type": etype, "param": None, "code": etype}
    if extra:
        error["harpo"] = extra
    return {"error": error}
