"""Run Harpo, unchanged, over an external dataset and record the scores.

  python bench/external/run.py DATASET FILE --out bench/external/results/NAME [--config default-image] [--workers 2]
      [--limit N] [--details details.jsonl] [--gitleaks /path/to/gitleaks]

DATASET is openpii, nemotron, gretel, redactionbench or prowlbench (bench/external/corpora.py says which file each
takes). --details writes every document's result with the values that were not fully redacted and their context,
for error analysis: it holds dataset content, so keep it out of the repository. --gitleaks also scores gitleaks on
ProwlBench the way ProwlBench's own runner does, which checks this scorer against the published leaderboard.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from corpora import LOADERS, Doc  # noqa: E402
from harness import CONFIGS, aggregate, file_sha256, harpo_identity, prowl_metrics, run, summary_line  # noqa: E402

SLICES = {
    "openpii": ("language", "half"),
    "nemotron": ("domain", "document_format", "locale", "half"),
    "gretel": ("domain",),
    "redactionbench": ("category", "synthetic", "half"),
    "prowlbench": ("tier", "lang", "source", "origin", "type", "half"),
}
PROWL_EXT = {"code": ".py", "jira": ".md", "confluence": ".md", "log": ".log", "slack": ".txt"}  # as its runner


def gitleaks_flags(docs: list[Doc], binary: str) -> set[str]:
    """ProwlBench's gitleaks adapter: one file per case, the extension its source implies, `gitleaks dir`."""
    with tempfile.TemporaryDirectory(prefix="prowlbench-gitleaks-") as tmp:
        folder = Path(tmp) / "cases"
        folder.mkdir()
        for doc in docs:
            (folder / f"{doc.id}{PROWL_EXT.get(doc.meta.get('source', ''), '.txt')}").write_text(doc.text)
        report = Path(tmp) / "report.json"
        subprocess.run(
            [binary, "dir", str(folder), "-f", "json", "-r", str(report), "--log-level", "error"],
            capture_output=True,
            check=False,
        )
        findings = json.loads(report.read_text() or "[]")
    return {Path(f.get("File", "")).stem for f in findings if Path(f.get("File", "")).stem.startswith("pb-")}


def details(doc: Doc, result: dict[str, Any]) -> dict[str, Any]:
    """What was not fully redacted, with 40 characters of context on each side."""
    misses = []
    for span in result["spans"]:
        if span["status"] in ("leaked", "partial"):
            start, end = span["start"], span["end"]
            misses.append(span | {"value": doc.text[start:end], "context": doc.text[max(0, start - 40) : end + 40]})
    return {"id": doc.id, "meta": doc.meta, "types": result["types"], "blocked": result["blocked"], "misses": misses,
            "key_flag": result["key_flag"], "secret": doc.secret,
            "text": doc.text if doc.secret is not None and result["key_flag"] != doc.secret else None}  # fmt: skip


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dataset", choices=sorted(LOADERS))
    parser.add_argument("file", type=Path)
    parser.add_argument("--out", type=Path, required=True, help="folder for the results JSON")
    parser.add_argument("--config", choices=CONFIGS, default="default-image")
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--details", type=Path, help="per-document results with the missed values (keep private)")
    parser.add_argument("--gitleaks", help="prowlbench only: score this gitleaks binary too")
    parser.add_argument("--half", choices=("dev", "holdout"), help="score one half only (dev, while fixing)")
    args = parser.parse_args(argv)

    docs = list(LOADERS[args.dataset](args.file))
    # Nemotron-PII's test file holds each uid twice (a "us" and an "intl" document): give repeats their own id, so
    # every result and --details record is tied to its own text. Scores never depend on the id.
    seen: dict[str, int] = {}
    for doc in docs:
        seen[doc.id] = seen.get(doc.id, 0) + 1
        if seen[doc.id] > 1:
            doc.id = f"{doc.id}#{seen[doc.id]}"
    if args.half:
        docs = [d for d in docs if d.meta.get("half") == args.half]
        if not docs:
            parser.error(f"{args.dataset} has no halves")
    if args.limit:
        docs = docs[: args.limit]
    started = datetime.now(UTC)
    t0 = time.perf_counter()
    results = []
    for i, result in enumerate(run(docs, args.dataset, args.config, args.workers), 1):
        results.append(result)
        if i % 2000 == 0:
            print(f"  {i}/{len(docs)} documents, {time.perf_counter() - t0:.0f} s", flush=True)
    seconds = time.perf_counter() - t0
    results.sort(key=lambda r: r["id"])
    metrics = aggregate(results, args.dataset, SLICES[args.dataset])
    record: dict[str, Any] = {
        "dataset": args.dataset,
        "file": args.file.name,
        "file_sha256": file_sha256(args.file),
        "documents": len(docs),
        "limit": args.limit,
        "half": args.half,
        "config": args.config,
        "harpo": harpo_identity(),
        "scope_sha256": hashlib.sha256((HERE / "scope.py").read_bytes()).hexdigest(),
        "harness_sha256": hashlib.sha256(
            b"".join((HERE / n).read_bytes() for n in ("harness.py", "corpora.py", "rscore.py"))
        ).hexdigest(),
        "started": started.isoformat(timespec="seconds"),
        "seconds": round(seconds, 1),
        "metrics": metrics,
    }
    if args.dataset == "prowlbench":
        record["prowlbench"] = {"harpo": prowl_metrics(results)}
        for half in ("dev", "holdout"):
            if part := [r for r in results if r["meta"]["half"] == half]:
                record["prowlbench"][f"harpo {half} half"] = prowl_metrics(part)
        if args.gitleaks:
            version = subprocess.run([args.gitleaks, "version"], capture_output=True, text=True, check=False).stdout
            record["prowlbench"][f"gitleaks {version.strip()}"] = prowl_metrics(
                results, gitleaks_flags(docs, args.gitleaks)
            )
    args.out.mkdir(parents=True, exist_ok=True)
    name = (
        args.dataset
        + (f"-{args.config}" if args.config != "default-image" else "")
        + (f"-{args.half}" if args.half else "")
        + (f"-limit{args.limit}" if args.limit else "")
    )
    (args.out / f"{name}.json").write_text(json.dumps(record, indent=1, ensure_ascii=False) + "\n")
    if args.details:
        by_id = {d.id: d for d in docs}
        with args.details.open("w", encoding="utf-8") as fh:
            for result in results:
                fh.write(json.dumps(details(by_id[result["id"]], result), ensure_ascii=False) + "\n")
    print(summary_line(args.dataset, metrics) + f"; {seconds:.0f} s")
    if "prowlbench" in record:
        for tool, m in record["prowlbench"].items():
            print(
                f"  ProwlBench {tool}: precision {m['precision']} recall {m['recall']} F1 {m['f1']} accuracy {m['accuracy']}"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
