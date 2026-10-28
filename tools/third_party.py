"""Regenerate THIRD_PARTY_NOTICES.md's dependency table from installed package metadata.

    python tools/third_party.py           # rewrite the table; run it where requirements.lock is installed
    python tools/third_party.py --check   # exit 1 when the table and the installed packages disagree

One row per package in requirements.lock, with the licence its own metadata declares: the License field when it is
filled in, else the License-Expression, else the licence classifiers. The rest of the file is written by hand.
"""

from __future__ import annotations

import argparse
import re
import sys
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NOTICES = ROOT / "THIRD_PARTY_NOTICES.md"
HEADING = "## Python dependencies (requirements.lock)"


def locked() -> list[str]:
    lines = (ROOT / "requirements.lock").read_text(encoding="utf-8").splitlines()
    return sorted({m.group(1).lower() for line in lines if (m := re.match(r"^([A-Za-z0-9_.\-]+)==", line))})


def licence(name: str) -> str:
    meta = metadata.metadata(name)
    declared = (meta.get("License") or "").strip()
    if declared and "\n" not in declared and len(declared) <= 80:
        return declared
    if meta.get("License-Expression"):
        return str(meta["License-Expression"])
    classifiers = [c.split(" :: ")[-1] for c in meta.get_all("Classifier") or [] if c.startswith("License ::")]
    return ", ".join(classifiers) or "see the package"


def table() -> str:
    rows = [f"| {name} | {licence(name)} |" for name in locked()]
    return "\n".join([HEADING, "", "| Package | Licence |", "| --- | --- |", *rows]) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="only compare; exit 1 when the table is out of date")
    args = parser.parse_args(argv)
    text = NOTICES.read_text(encoding="utf-8")
    head, found, _ = text.partition(HEADING)
    if not found:
        print(f"{NOTICES.name} has no '{HEADING}' section", file=sys.stderr)
        return 1
    try:
        new = head + table()
    except metadata.PackageNotFoundError as missing:
        print(f"{missing} is in requirements.lock but not installed here: install the lock first", file=sys.stderr)
        return 1
    if args.check:
        print(f"{NOTICES.name} " + ("matches the installed packages" if new == text else "is out of date"))
        return 0 if new == text else 1
    NOTICES.write_text(new, encoding="utf-8")
    print(f"wrote {NOTICES.name}: {len(locked())} packages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
