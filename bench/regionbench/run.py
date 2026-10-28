"""RegionBench: how much of the Dutch, US and EU personal data in everyday documents Harpo removes.

  python bench/regionbench/run.py generate                     # corpus.jsonl from the templates (fixed seed)
  python bench/regionbench/run.py run [--config default-image] [--split dev|holdout] [--details FILE] [--save LABEL]

A value counts as removed when every letter and digit of it was inside a redaction, or the request was blocked; a
value partly covered still leaked the rest. A keep (a phrase with nothing personal in it, and the look-alikes: order
numbers, amounts, dates of events, versions, article numbers) counts as a false positive when any of it was
redacted. --save writes results-<LABEL>.json next to the corpus (the build it measured, such as "hardening-3"), which
bench/external/report.py puts in docs/EXTERNAL_BENCHMARKS.md; --details writes every miss with its context, for study
on the dev split only.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "external"))

import templates as T  # noqa: E402

CORPUS = HERE / "corpus.jsonl"
SEED = 20261019
PER_TEMPLATE = 40


def generate() -> int:
    records = []
    for tid in sorted(T.TEMPLATES):
        for i in range(PER_TEMPLATE):
            rng = random.Random(f"{SEED}:{tid}:{i}")
            record = T.build(tid, rng)
            record["id"] = f"{tid}#{i:02d}"
            records.append(record)
    CORPUS.write_text("".join(T.dump(r) + "\n" for r in records), encoding="utf-8")
    values = sum(len(r["values"]) for r in records)  # type: ignore[arg-type]
    keeps = sum(len(r["keeps"]) for r in records)  # type: ignore[arg-type]
    print(
        f"wrote {CORPUS.name}: {len(records)} documents, {values} values, {keeps} keeps, {len(T.TEMPLATES)} templates"
    )
    return 0


def _load(split: str | None) -> list[dict[str, Any]]:
    rows = [json.loads(line) for line in CORPUS.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [r for r in rows if split is None or r["split"] == split]


def score(doc: dict[str, Any], findings: list[tuple[int | None, int | None, str]], blocked: bool) -> dict[str, Any]:
    text = doc["text"]
    covered = bytearray(len(text))
    for start, end, _ in findings:
        if start is not None and end is not None:
            covered[max(0, start) : min(len(text), end)] = b"\x01" * (min(len(text), end) - max(0, start))
    values = []
    for v in doc["values"]:
        idx = [i for i in range(v["start"], v["end"]) if text[i].isalnum()]
        hit = sum(covered[i] for i in idx)
        status = "blocked" if blocked else "redacted" if hit == len(idx) else "partial" if hit else "leaked"
        values.append({"kind": v["kind"], "status": status, "start": v["start"], "end": v["end"]})
    keeps = []
    for k in doc["keeps"]:
        hit = sum(covered[i] for i in range(k["start"], k["end"]) if text[i].isalnum())
        keeps.append({"start": k["start"], "end": k["end"], "kept": hit == 0})
    return {"id": doc["id"], "template": doc["template"], "region": doc["region"], "split": doc["split"],
            "values": values, "keeps": keeps, "blocked": blocked}  # fmt: skip


def _rate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    count = Counter(r["status"] for r in rows)
    done = count["redacted"] + count["blocked"]
    return {"values": len(rows), "removed": done, "partial": count["partial"], "leaked": count["leaked"],
            "rate": round(done / len(rows), 4) if rows else None}  # fmt: skip


def aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    values = [
        v | {"region": r["region"], "split": r["split"], "template": r["template"]}
        for r in results
        for v in r["values"]
    ]
    keeps = [k | {"region": r["region"], "split": r["split"]} for r in results for k in r["keeps"]]
    out: dict[str, Any] = {"documents": len(results), "all": _rate(values)}
    for key in ("region", "split"):
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for v in values:
            groups[v[key]].append(v)
        out[f"by_{key}"] = {g: _rate(rows) for g, rows in sorted(groups.items())}
    cross: dict[str, list[dict[str, Any]]] = defaultdict(list)
    kinds: dict[str, list[dict[str, Any]]] = defaultdict(list)
    templates: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for v in values:
        cross[f"{v['region']} {v['split']}"].append(v)
        kinds[v["kind"]].append(v)
        templates[v["template"]].append(v)
    out["by_region_split"] = {g: _rate(rows) for g, rows in sorted(cross.items())}
    out["by_kind"] = {g: _rate(rows) for g, rows in sorted(kinds.items())}
    out["by_template"] = {g: _rate(rows) | {"split": rows[0]["split"]} for g, rows in sorted(templates.items())}
    lost = [k for k in keeps if not k["kept"]]
    out["keeps"] = {"keeps": len(keeps), "redacted": len(lost),
                    "false_positive_rate": round(len(lost) / len(keeps), 4) if keeps else None,
                    "by_region": {g: round(sum(not k["kept"] for k in keeps if k["region"] == g)
                                           / max(1, sum(k["region"] == g for k in keeps)), 4)
                                  for g in sorted({k["region"] for k in keeps})}}  # fmt: skip
    out["blocked_documents"] = sum(r["blocked"] for r in results)
    return out


def run(config: str, split: str | None, details: Path | None, save: str | None) -> int:
    from harness import harpo_identity, pipeline_for

    docs = _load(split)
    pipeline = pipeline_for(config)
    pipeline.warmup()
    results, misses = [], []
    started = time.perf_counter()
    for doc in docs:
        out = pipeline.scan_sync([doc["text"]])
        findings = [(f.start, f.end, str(f.type)) for f in out.findings[0]]
        result = score(doc, findings, out.blocked)
        results.append(result)
        if details is not None:
            text = doc["text"]
            misses.extend(
                {"id": doc["id"], "kind": v["kind"], "status": v["status"], "value": text[v["start"] : v["end"]],
                 "context": text[max(0, v["start"] - 60) : v["end"] + 40], "split": doc["split"]}
                for v in result["values"]
                if v["status"] in ("leaked", "partial")
            )  # fmt: skip
            for k, kk in zip(result["keeps"], doc["keeps"], strict=True):
                if not k["kept"]:
                    hits = [(text[s:e], t) for s, e, t in findings if s is not None and s < k["end"] and e > k["start"]]
                    misses.append(
                        {"id": doc["id"], "kind": "KEEP", "value": kk["surface"], "by": hits, "split": doc["split"]}
                    )
    seconds = time.perf_counter() - started
    metrics = aggregate(results)
    a = metrics["all"]
    print(f"regionbench {config}{' ' + split if split else ''}: {metrics['documents']} documents, {a['values']} values, "
          f"removed {a['rate']}, partly {a['partial']}, leaked {a['leaked']}; false positives "
          f"{metrics['keeps']['false_positive_rate']} ({metrics['keeps']['redacted']} of {metrics['keeps']['keeps']} keeps); {seconds:.0f} s")  # fmt: skip
    for g, r in metrics["by_region_split"].items():
        print(f"  {g:12} {r['rate']}  ({r['removed']}/{r['values']})")
    if details is not None:
        details.write_text("".join(json.dumps(m, ensure_ascii=False) + "\n" for m in misses), encoding="utf-8")
    if save:
        record = {"config": config, "split": split, "harpo": harpo_identity(), "seconds": round(seconds, 1),
                  "corpus_documents": len(docs), "metrics": metrics}  # fmt: skip
        (HERE / f"results-{save}.json").write_text(json.dumps(record, indent=1, ensure_ascii=False) + "\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("generate")
    r = sub.add_parser("run")
    r.add_argument("--config", default="default-image", choices=("default-image", "deterministic"))
    r.add_argument("--split", choices=("dev", "holdout"))
    r.add_argument("--details", type=Path)
    r.add_argument("--save", metavar="LABEL", help="write results-LABEL.json, LABEL naming the build measured")
    args = parser.parse_args(argv)
    if args.command == "generate":
        return generate()
    return run(args.config, args.split, args.details, args.save)


if __name__ == "__main__":
    sys.exit(main())
