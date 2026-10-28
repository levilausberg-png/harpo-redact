"""Adapter conformance: what a Harpo-compatible adapter has to prove, checked black-box.

You provide ``submit(body) -> Submission``: send ``body`` through a gateway that uses the adapter and report
the status the client got, what the client got back, and what reached the provider (``None`` if nothing did).
:func:`run` then works through realistic sample requests:

* **every string and every key**: a canary is put into each slot in turn
* **unknown fields**: an unknown key holding the canary is added to every object in turn
* **type confusion**: each value is replaced by other JSON types and by large numbers, in turn

The oracle is the same everywhere: the canary never reaches the provider or comes back to the client, and
no request causes a server error. Slots an adapter declares as provider-produced (signed thinking blocks) are
exempt from the leak check, because the provider wrote them. Samples must first pass unchanged.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

CANARY = "conformance.canary@leak-test.example"
_CANARY_RE = re.compile(re.escape(CANARY).replace(r"\.", r"[.\\]?"))  # also catches JSON-escaped forms
Path = tuple[Any, ...]


@dataclass(frozen=True)
class Submission:
    status: int
    forwarded: str | None
    response: str


@dataclass(frozen=True)
class Failure:
    check: str
    path: str
    detail: str


def pattern(path: Path) -> str:
    out = ""
    for step in path:
        out += "[]" if isinstance(step, int) else (f".{step}" if out else str(step))
    return out


def slots(node: Any, path: Path = ()) -> Iterator[tuple[Path, str]]:
    """(path, "value" or "key") for every string value and every key."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield (*path, key), "key"
            yield from slots(value, (*path, key))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from slots(value, (*path, i))
    elif isinstance(node, str):
        yield path, "value"


def objects(node: Any, path: Path = ()) -> Iterator[Path]:
    if isinstance(node, dict):
        yield path
        for key, value in node.items():
            yield from objects(value, (*path, key))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from objects(value, (*path, i))


def _parent(body: Any, path: Path) -> Any:
    for step in path[:-1]:
        body = body[step]
    return body


def put_value(sample: dict[str, Any], path: Path, value: Any) -> dict[str, Any]:
    body = copy.deepcopy(sample)
    _parent(body, path)[path[-1]] = value
    return body


def rename_key(sample: dict[str, Any], path: Path, new: str) -> dict[str, Any]:
    body = copy.deepcopy(sample)
    parent = _parent(body, path)
    items = list(parent.items())
    parent.clear()
    for k, v in items:
        parent[new if k == path[-1] else k] = v
    return body


def leaked(sub: Submission) -> bool:
    return bool(_CANARY_RE.search(sub.forwarded or "") or _CANARY_RE.search(sub.response))


def run(
    submit: Callable[[dict[str, Any]], Submission],
    samples: list[dict[str, Any]],
    *,
    exempt: Callable[[str], bool] = lambda _p: False,
    type_confusion: bool = True,
) -> list[Failure]:
    failures: list[Failure] = []

    def judge(check: str, path: Path, sub: Submission) -> None:
        where = pattern(path)
        if sub.status >= 500:
            failures.append(Failure(check, where, f"server error {sub.status}"))
        if leaked(sub) and not exempt(where):
            failures.append(Failure(check, where, f"canary reached the provider or the client (status {sub.status})"))

    for n, sample in enumerate(samples):
        baseline = submit(copy.deepcopy(sample))
        if baseline.status != 200 or baseline.forwarded is None:
            failures.append(
                Failure("baseline", f"sample {n}", f"the unmodified sample was not forwarded ({baseline.status})")
            )
            continue
        for path, kind in slots(sample):
            body = rename_key(sample, path, CANARY) if kind == "key" else put_value(sample, path, f"note {CANARY} end")
            judge(f"{kind}_canary", path, submit(body))
        for path in objects(sample):
            body = copy.deepcopy(sample)
            target = body
            for step in path:
                target = target[step]
            target["x_unknown_field"] = f"see {CANARY}"
            judge("unknown_field", (*path, "x_unknown_field"), submit(body))
        if type_confusion:
            for path, kind in slots(sample):
                if kind != "value":
                    continue
                for variant in (4111111111111111, [], {}, None, True, {"text": CANARY}, [CANARY]):
                    judge("type_confusion", path, submit(put_value(sample, path, variant)))
    return failures
