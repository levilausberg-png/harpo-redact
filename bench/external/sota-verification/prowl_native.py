"""ProwlBench through its own runner: Harpo added as one more tool, gitleaks 8.30.1 as the control.

    <venv>/bin/python bench/external/sota-verification/prowl_native.py \
        --prowl-repo CHECKOUT --work DIR --gitleaks BIN --out bench/external/sota-verification/prowl_result.json

The ProwlBench checkout is copied into WORK/benchmark (its runner writes the benchmark's files and its leaderboard
next to the data, so the checkout itself stays untouched) and its run_prowlbench.py is imported unchanged: its own
materialize(), prf() and main() write the snippets, score every tool and build the leaderboard. Two things come
from outside, and only these:

* a runner for Harpo: each file the runner materialised is scanned by the installed Harpo build in the configuration
  the Docker image ships (bench/external/harness.py pipeline_for("default-image")), and a snippet counts as flagged
  when Harpo redacts at least one SECRET or PRIVATE_KEY in it, the rule bench/external/harness.py uses;
* the path of the gitleaks binary, which run_prowlbench.py hard-codes as /tmp/gitleaks: a shim around its subprocess
  module rewrites that one path, nothing else.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import shutil
import subprocess
import sys
import types
from multiprocessing import get_context
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from corpora import half_of  # noqa: E402

KEY_TYPES = frozenset({"SECRET", "PRIVATE_KEY"})
_PIPE: Any = None


def _init() -> None:
    global _PIPE
    from harness import pipeline_for

    _PIPE = pipeline_for("default-image")
    _PIPE.warmup()


def _flag(path: str) -> tuple[str, bool]:
    text = Path(path).read_text()
    out = _PIPE.scan_sync([text])
    return path, any(str(f.type) in KEY_TYPES for f in out.findings[0])


def make_harpo_runner(workers: int) -> Any:
    def run_harpo(d: Path, cases: list[dict[str, Any]]) -> set[str]:
        paths = sorted(str(p) for p in Path(d).iterdir())
        with get_context("fork").Pool(workers, initializer=_init) as pool:
            flagged = [p for p, hit in pool.imap_unordered(_flag, paths, chunksize=32) if hit]
        return set(_RP._ids_from_paths(flagged))

    return run_harpo


_RP: Any = None


def main() -> int:
    global _RP
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--prowl-repo", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--gitleaks", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()

    published = json.loads((args.prowl_repo / "prowlbench_leaderboard.json").read_text())["tools"]
    bench = args.work / "benchmark"
    if bench.exists():
        shutil.rmtree(bench)
    shutil.copytree(args.prowl_repo, bench, ignore=shutil.ignore_patterns(".git"))
    os.chdir(args.work)
    sys.path.insert(0, str(bench))
    _RP = importlib.import_module("run_prowlbench")

    real_run = subprocess.run

    def run(cmd: list[str], *a: Any, **kw: Any) -> Any:
        if cmd and cmd[0] == "/tmp/gitleaks":
            cmd = [args.gitleaks, *cmd[1:]]
        return real_run(cmd, *a, **kw)

    shim = types.SimpleNamespace(run=run)
    _RP.subprocess = shim
    _RP.RUNNERS["harpo"] = make_harpo_runner(args.workers)

    sys.argv = ["run_prowlbench.py", "--tools", "harpo,gitleaks"]
    _RP.main()

    board = json.loads((bench / "prowlbench_leaderboard.json").read_text())
    detections = json.loads((bench / "prowlbench_detections.json").read_text())
    cases = _RP.load()
    harpo_ids = set(detections["harpo"])
    halves = {}
    for half in ("dev", "holdout"):
        sub = [c for c in cases if half_of(c["id"]) == half]
        p, r, f1, acc = _RP.prf(harpo_ids, sub)
        halves[half] = {"cases": len(sub), "precision": p, "recall": r, "f1": f1, "accuracy": acc}
    gitleaks_same = board["tools"]["gitleaks"] == published["gitleaks"]
    record = {
        "runner": "ProwlBench run_prowlbench.py, imported unchanged (main, materialize, prf)",
        "prowlbench_commit": subprocess.run(
            ["git", "-C", str(args.prowl_repo), "rev-parse", "HEAD"], capture_output=True, text=True
        ).stdout.strip(),
        "meta": board["_meta"],
        "harpo": board["tools"]["harpo"],
        "harpo_by_half": halves,
        "gitleaks": board["tools"]["gitleaks"],
        "gitleaks_published": published["gitleaks"],
        "gitleaks_reproduces_published_row_exactly": gitleaks_same,
        "adapter_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "detections_sha256": hashlib.sha256(json.dumps(detections, sort_keys=True).encode()).hexdigest(),
    }
    args.out.write_text(json.dumps(record, indent=1) + "\n")
    print(f"\nharpo: {json.dumps({k: board['tools']['harpo'][k] for k in ('precision', 'recall', 'f1', 'accuracy')})}")
    print(f"gitleaks reproduces the published row exactly: {gitleaks_same}")
    return 0 if gitleaks_same else 1


if __name__ == "__main__":
    sys.exit(main())
