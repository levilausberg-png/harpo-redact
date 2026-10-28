"""Loaders for the external datasets: each yields documents with their gold spans, in one shape.

None of the data ships with Harpo; each loader reads the file as its publisher distributes it.
  openpii         ai4privacy/openpii-masking-micro-100k (or pii-masking-openpii-1.5m), data/validation.jsonl, CC BY 4.0
  nemotron        nvidia/Nemotron-PII, data/test-00000-of-00001.parquet, CC BY 4.0
  gretel          gretelai/gretel-pii-masking-en-v1, data/test-00000-of-00001.parquet, Apache-2.0
  redactionbench  RedactionBench/RedactionBench, data/test-00000-of-00001.parquet, CC BY 4.0
  prowlbench      github.com/Lercas/prowlbench, prowlbench.jsonl, PolyForm Noncommercial 1.0.0 (evaluation only)
"""

from __future__ import annotations

import ast
import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HALF_SALT = "harpo-external-v1"


def half_of(doc_id: str) -> str:
    """'dev' or 'holdout' for a file that is the only split at hand: RedactionBench and ProwlBench publish one, and
    for OpenPII and Nemotron-PII only the validation and test files were available here, not their training data.

    Failures are studied and fixed on the dev half alone; the holdout half is only ever counted, so its number after
    a fix says how the fix generalises. The halves come from a salted hash of the id, never from a result."""
    return "dev" if hashlib.sha256(f"{HALF_SALT}:{doc_id}".encode()).digest()[0] < 128 else "holdout"


@dataclass(slots=True)
class Gold:
    start: int
    end: int
    labels: tuple[str, ...]


@dataclass(slots=True)
class Doc:
    id: str
    text: str
    gold: list[Gold]
    meta: dict[str, str] = field(default_factory=dict)
    secret: bool | None = None  # ProwlBench: does the snippet hold a secret
    unlocated: int = 0  # gold values that could not be found in the text (datasets without offsets)


def _parquet_rows(path: Path) -> Iterator[dict[str, Any]]:
    import pyarrow.parquet as pq

    table = pq.read_table(path)
    yield from table.to_pylist()


def _as_list(value: Any) -> list[Any]:
    """Span lists arrive as lists, JSON strings or Python literals, depending on the export."""
    if value is None:
        return []
    if isinstance(value, str):
        try:
            return list(json.loads(value))
        except ValueError:
            return list(ast.literal_eval(value))
    return list(value)


def openpii(path: Path) -> Iterator[Doc]:
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            row = json.loads(line)
            text = row["source_text"]
            gold = [Gold(int(m["start"]), int(m["end"]), (str(m["label"]),)) for m in _as_list(row.get("privacy_mask"))]
            meta = {k: str(row.get(k, "")) for k in ("language", "region", "script")}
            meta["half"] = half_of(str(row.get("uid", "")))
            yield Doc(str(row.get("uid", "")), text, gold, meta)


def nemotron(path: Path) -> Iterator[Doc]:
    for row in _parquet_rows(path):
        text = row["text"]
        gold = [Gold(int(s["start"]), int(s["end"]), (str(s["label"]),)) for s in _as_list(row.get("spans"))]
        meta = {k: str(row.get(k, "")) for k in ("domain", "document_type", "document_format", "locale")}
        meta["half"] = half_of(str(row["uid"]))
        yield Doc(str(row["uid"]), text, gold, meta)


def gretel(path: Path) -> Iterator[Doc]:
    """Gretel gives each value and its types, not offsets: every occurrence of the value in the text is a span."""
    for row in _parquet_rows(path):
        text = row["text"]
        gold: list[Gold] = []
        unlocated = 0
        for entity in _as_list(row.get("entities")):
            value = str(entity.get("entity", ""))
            labels = tuple(str(t) for t in entity.get("types") or ())
            if not value.strip():
                continue
            start = text.find(value)
            if start < 0:
                unlocated += 1
                continue
            while start >= 0:
                gold.append(Gold(start, start + len(value), labels))
                start = text.find(value, start + len(value))
        meta = {k: str(row.get(k, "")) for k in ("domain", "document_type")}
        yield Doc(str(row["uid"]), text, gold, meta, unlocated=unlocated)


def redactionbench(path: Path) -> Iterator[Doc]:
    for i, row in enumerate(_parquet_rows(path)):
        text = row["raw_text"]
        gold = [Gold(int(s["start"]), int(s["end"]), (str(s["label"]),)) for s in _as_list(row.get("spans"))]
        meta = {"category": str(row.get("category", "")), "genre": str(row.get("genre", "")),
                "synthetic": str(bool(row.get("is_synthetic"))), "half": half_of(f"rb-{i:03d}")}  # fmt: skip
        yield Doc(f"rb-{i:03d}", text, gold, meta)


def prowlbench(path: Path) -> Iterator[Doc]:
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            row = json.loads(line)
            span = row.get("span")
            gold = [Gold(int(span[0]), int(span[1]), ("secret",))] if row["label"] and span else []
            meta = {k: str(row.get(k, "")) for k in ("tier", "lang", "source", "origin", "type")}
            meta["half"] = half_of(str(row["id"]))
            yield Doc(str(row["id"]), row["text"], gold, meta, secret=bool(row["label"]))


LOADERS = {
    "openpii": openpii,
    "nemotron": nemotron,
    "gretel": gretel,
    "redactionbench": redactionbench,
    "prowlbench": prowlbench,
}
