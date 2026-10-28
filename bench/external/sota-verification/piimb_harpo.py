"""Harpo on PIIMB (the PII Masking Benchmark, huggingface.co/datasets/piimb/pii-masking-benchmark).

PIIMB ranks models by masking F2: character-level and label-agnostic, gold and predicted spans merged per text
(overlapping or touching), pooled over every text of a task (micro), beta = 2. It runs every model on its
`sentences` subset. This adapter only translates: each text goes through the installed Harpo build in the
configuration the Docker image ships, and every redaction Harpo makes becomes a predicted span (Harpo's types are
not PIIMB's labels, and the masking metric ignores labels). A request Harpo blocks sends nothing, so it counts as
the whole text masked.

    # the official run: PIIMB's data file and PIIMB's own metrics module (src/piimb/metrics.py)
    <venv>/bin/python piimb_harpo.py official --piimb-repo DIR --tasks ai4privacy-en ai4privacy-multi nemotron-pii \
        --predictions OUT_DIR --out RESULT.json

    # an indication only, NOT PIIMB: the same metric re-implemented here, on our local files (other samples,
    # whole documents rather than PIIMB's sentences, OpenPII micro rather than OpenPII 1M)
    <venv>/bin/python piimb_harpo.py indicative --dataset nemotron --file FILE --predictions OUT_DIR --out RESULT.json

Predictions hold benchmark text offsets only; they are written outside the repository and recorded by sha256.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
import time
from collections.abc import Iterable, Iterator
from multiprocessing import get_context
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

_PIPE: Any = None


def _init() -> None:
    global _PIPE
    from harness import pipeline_for

    _PIPE = pipeline_for("default-image")
    _PIPE.warmup()


def _predict(item: tuple[int, str]) -> tuple[int, list[tuple[int, int, str]], bool]:
    """Harpo's redactions in one text, as (start, end, Harpo type); a blocked request masks the whole text."""
    index, text = item
    out = _PIPE.scan_sync([text])
    if out.blocked:
        return index, [(0, len(text), "BLOCKED")], True
    spans = [(f.start, f.end, str(f.type)) for f in out.findings[0] if f.start is not None and f.end is not None]
    return index, [(s, e, t) for s, e, t in spans if e > s], False


def predict_all(texts: list[str], workers: int) -> tuple[list[list[tuple[int, int, str]]], int]:
    preds: list[list[tuple[int, int, str]]] = [[] for _ in texts]
    blocked = 0
    with get_context("fork").Pool(workers, initializer=_init) as pool:
        for index, spans, was_blocked in pool.imap_unordered(_predict, enumerate(texts), chunksize=32):
            preds[index] = spans
            blocked += was_blocked
    return preds, blocked


# --------------------------------------------------------------------------- the metric, as PIIMB defines it
def merge(intervals: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for start, end in sorted(intervals):
        if out and start <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], end))
        else:
            out.append((start, end))
    return out


def intersection(a: list[tuple[int, int]], b: list[tuple[int, int]]) -> int:
    i = j = total = 0
    while i < len(a) and j < len(b):
        lo, hi = max(a[i][0], b[j][0]), min(a[i][1], b[j][1])
        total += max(0, hi - lo)
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return total


def masking_metrics(gold: list[list[tuple[int, int]]], pred: list[list[tuple[int, int]]],
                    lengths: list[int]) -> dict[str, float]:  # fmt: skip
    """Re-implementation of PIIMB's compute_masking_metrics from its published definition (used for the indication
    and as a cross-check of the official module)."""
    true = pred_chars = inter = text = 0
    for g, p, n in zip(gold, pred, lengths, strict=True):
        mg, mp = merge(g), merge(p)
        true += sum(e - s for s, e in mg)
        pred_chars += sum(e - s for s, e in mp)
        inter += intersection(mg, mp)
        text += n
    precision = inter / pred_chars if pred_chars else 0.0
    recall = inter / true if true else 0.0

    def fbeta(beta: float) -> float:
        b2 = beta * beta
        return (1 + b2) * precision * recall / (b2 * precision + recall) if precision + recall else 0.0

    fpr = (pred_chars - inter) / (text - true) if text - true > 0 else 0.0
    return {"precision": precision, "recall": recall, "f1": fbeta(1), "f2": fbeta(2), "fpr": fpr,
            "true_chars": true, "pred_chars": pred_chars, "intersection_chars": inter, "text_chars": text}  # fmt: skip


# --------------------------------------------------------------------------- the official run
def _official_metrics(repo: Path) -> Any:
    """PIIMB's own src/piimb/metrics.py, loaded from the checkout without installing the package."""
    sys.path.insert(0, str(repo / "src"))
    spec = importlib.util.spec_from_file_location("piimb_metrics", repo / "src" / "piimb" / "metrics.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_predictions(path: Path, rows: Iterator[dict[str, Any]]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            line = json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            fh.write(line)
            digest.update(line.encode())
    return digest.hexdigest()


def official(args: argparse.Namespace) -> dict[str, Any]:
    data = args.piimb_repo / "data" / "test_sentences.jsonl"
    rows = [json.loads(line) for line in data.open(encoding="utf-8") if line.strip()]
    metrics_module = _official_metrics(args.piimb_repo)
    entity_cls = getattr(metrics_module, "Entity", None)
    results: dict[str, Any] = {}
    for task in args.tasks:
        sub = [r for r in rows if r["task_name"] == task]
        if not sub:
            raise SystemExit(f"no rows for task {task} in {data}")
        texts = [r["text"] for r in sub]
        started = time.perf_counter()
        preds, blocked = predict_all(texts, args.workers)
        seconds = time.perf_counter() - started
        gold_spans = [[(e["start"], e["end"]) for e in r["entities"]] for r in sub]
        pred_spans = [[(s, e) for s, e, _ in p] for p in preds]
        lengths = [len(t) for t in texts]
        ours = masking_metrics(gold_spans, pred_spans, lengths)
        official_scores: dict[str, Any] | None = None
        if entity_cls is not None and hasattr(metrics_module, "compute_masking_metrics"):
            y_true = [[entity_cls(**e) for e in r["entities"]] for r in sub]
            y_pred = [[entity_cls(start=s, end=e, label=t) for s, e, t in p] for p in preds]
            m = metrics_module.compute_masking_metrics(y_true=y_true, y_pred=y_pred, text_lengths=lengths)
            official_scores = m.model_dump() if hasattr(m, "model_dump") else dict(vars(m))
        sha = _write_predictions(
            args.predictions / f"{task}.jsonl",
            ({"i": i, "spans": p} for i, p in enumerate(preds)),
        )
        results[task] = {
            "texts": len(sub),
            "gold_entities": sum(len(r["entities"]) for r in sub),
            "languages": sorted({r.get("language", "") for r in sub}),
            "blocked_texts": blocked,
            "seconds": round(seconds, 1),
            "official_masking_metrics": official_scores,
            "reimplemented_masking_metrics": ours,
            "predictions_sha256": sha,
        }
        f2 = official_scores["f2"] if official_scores else ours["f2"]
        print(f"{task}: {len(sub)} texts, F2 {f2:.4f}", flush=True)
    return {"subset": "sentences", "data_file": str(data.name),
            "data_sha256": hashlib.sha256(data.read_bytes()).hexdigest(), "tasks": results}  # fmt: skip


# --------------------------------------------------------------------------- the indication on local files
def indicative(args: argparse.Namespace) -> dict[str, Any]:
    from corpora import LOADERS

    docs = list(LOADERS[args.dataset](args.file))
    if args.limit:
        docs = docs[: args.limit]
    texts = [d.text for d in docs]
    preds, blocked = predict_all(texts, args.workers)
    gold = [[(g.start, g.end) for g in d.gold] for d in docs]
    pred = [[(s, e) for s, e, _ in p] for p in preds]
    metrics = masking_metrics(gold, pred, [len(t) for t in texts])
    sha = _write_predictions(
        args.predictions / f"{args.dataset}-indicative.jsonl",
        ({"id": d.id, "spans": p} for d, p in zip(docs, preds, strict=True)),
    )
    print(f"{args.dataset} (indicative, not PIIMB): {len(docs)} documents, F2 {metrics['f2']:.4f}", flush=True)
    return {"NOT_THE_NATIVE_SCORE": "PIIMB's metric re-implemented, on local files with other samples and whole "
            "documents; not comparable with the PIIMB leaderboard", "dataset": args.dataset,
            "file": args.file.name, "documents": len(docs), "blocked_texts": blocked, "masking_metrics": metrics,
            "predictions_sha256": sha}  # fmt: skip


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="mode", required=True)
    o = sub.add_parser("official")
    o.add_argument("--piimb-repo", type=Path, required=True)
    o.add_argument("--tasks", nargs="+", required=True)
    i = sub.add_parser("indicative")
    i.add_argument("--dataset", required=True)
    i.add_argument("--file", type=Path, required=True)
    i.add_argument("--limit", type=int)
    for p in (o, i):
        p.add_argument("--predictions", type=Path, required=True)
        p.add_argument("--out", type=Path, required=True)
        p.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()
    from harness import harpo_identity

    record = official(args) if args.mode == "official" else indicative(args)
    record["harpo"] = harpo_identity()
    record["configuration"] = "default-image (bench/external/harness.py pipeline_for)"
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
