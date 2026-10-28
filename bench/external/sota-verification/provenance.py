"""Provenance for the SOTA verification pass: which Harpo build ran, in which environment, on which data files and
with which scorers. Run with the interpreter of the frozen build:

    <venv>/bin/python bench/external/sota-verification/provenance.py --out environment/provenance.json \
        --file prowlbench=... --file openpii=... --file nemotron=... --prowl-repo DIR --gitleaks BIN \
        [--wheel WHL] [--archive ZIP] [--piimb-repo DIR] [--piimb-results DIR]

Nothing here changes Harpo; it only reads files and asks the installed package who it is.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.metadata
import json
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from harness import harpo_identity  # noqa: E402


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def git(repo: Path, *args: str) -> str | None:
    try:
        out = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout.strip() or None if out.returncode == 0 else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--file", action="append", default=[], help="NAME=PATH of a dataset file")
    parser.add_argument("--prowl-repo", type=Path)
    parser.add_argument("--gitleaks")
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--piimb-repo", type=Path)
    parser.add_argument("--piimb-results", type=Path)
    args = parser.parse_args()

    import harpo_redact

    installed = Path(harpo_redact.__file__).resolve().parent
    record: dict[str, Any] = {
        "checked_utc": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "harpo": harpo_identity(),
        "harpo_installed_at": str(installed),
        "harpo_installed_non_editable": "site-packages" in installed.parts,
        "source": {
            "git": "the source tree is not a git repository; it is identified by the package digest above and the "
            "release archive digest below",
        },
        "python": {
            "version": sys.version,
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "dependencies": {
            d.metadata["Name"]: d.version
            for d in sorted(importlib.metadata.distributions(), key=lambda d: (d.metadata["Name"] or "").lower())
        },
        "configuration": {
            "name": "default-image",
            "what": "the deterministic layers plus spaCy NER (en_core_web_sm, de_core_news_sm for German, "
            "xx_ent_wiki_sm for every other language), result cache off: bench/external/harness.py pipeline_for",
            "ner": {"cache_entries": 0, "language_models": {"de": "de_core_news_sm", "other": "xx_ent_wiki_sm"}},
        },
        "datasets": {},
    }
    if args.wheel:
        record["source"]["wheel"] = {"file": args.wheel.name, "sha256": sha256_file(args.wheel)}
    if args.archive:
        record["source"]["release_archive"] = {"file": args.archive.name, "sha256": sha256_file(args.archive)}
    for item in args.file:
        name, _, path = item.partition("=")
        p = Path(path)
        record["datasets"][name] = {"file": p.name, "bytes": p.stat().st_size, "sha256": sha256_file(p)}
    if args.prowl_repo:
        repo = args.prowl_repo
        record["prowlbench"] = {
            "repository": git(repo, "remote", "get-url", "origin"),
            "commit": git(repo, "rev-parse", "HEAD"),
            "upstream_heads": git(repo, "ls-remote", "origin"),
            "run_prowlbench.py_sha256": sha256_file(repo / "run_prowlbench.py"),
            "prowlbench.jsonl_sha256": sha256_file(repo / "prowlbench.jsonl"),
            "prowlbench_leaderboard.json_sha256": sha256_file(repo / "prowlbench_leaderboard.json"),
            "README.md_sha256": sha256_file(repo / "README.md"),
        }
    if args.gitleaks:
        version = subprocess.run([args.gitleaks, "version"], capture_output=True, text=True).stdout.strip()
        record["gitleaks"] = {"version": version, "sha256": sha256_file(Path(args.gitleaks))}
    for key, repo in (("piimb", args.piimb_repo), ("piimb_results", args.piimb_results)):
        if repo:
            files = sorted(p for p in repo.rglob("*") if p.is_file() and ".git" not in p.parts)
            record[key] = {"commit": git(repo, "rev-parse", "HEAD"),
                           "files": {str(p.relative_to(repo)): sha256_file(p) for p in files}}  # fmt: skip
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {args.out}: harpo {record['harpo']['package_sha256'][:16]}, "
          f"non-editable {record['harpo_installed_non_editable']}")  # fmt: skip
    return 0


if __name__ == "__main__":
    sys.exit(main())
