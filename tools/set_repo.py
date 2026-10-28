"""Fill in the project's identity everywhere: repository, licensor and security contact.

python tools/set_repo.py --repo acme/harpo-redact --licensor "Acme B.V." --contact security@acme.example
python tools/set_repo.py --contact security@acme.example     # each option on its own, whenever it is decided
python tools/set_repo.py --check                              # lists what is still a placeholder; exit 1 if anything is

The release workflow runs --check and does not publish while a placeholder is left.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP = {".git", "node_modules", ".hypothesis", "__pycache__", "dist", "build", ".venv", ".mypy_cache", ".ruff_cache"}
SUFFIXES = {".md", ".yml", ".yaml", ".toml", ".py", ".txt", ".json", ".cff", ""}
PLACEHOLDERS = {"repo": "OWNER/harpo-redact", "licensor": "[LICENSOR NAME]", "contact": "[SECURITY CONTACT]"}


def project_files() -> Iterator[tuple[Path, str]]:
    for path in sorted(ROOT.rglob("*")):
        parts = set(path.relative_to(ROOT).parts)
        if not path.is_file() or SKIP & parts or any(p.endswith(".egg-info") for p in parts):
            continue
        if path.suffix not in SUFFIXES or path.name == "set_repo.py":
            continue
        try:
            yield path, path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", help="owner/name on GitHub")
    parser.add_argument("--licensor", help="who holds the copyright, as it should appear in NOTICE")
    parser.add_argument("--contact", help="where security and conduct reports go (an email address)")
    parser.add_argument("--check", action="store_true", help="only list what is still a placeholder")
    args = parser.parse_args(argv)
    pairs = {PLACEHOLDERS[name]: value for name in PLACEHOLDERS if (value := getattr(args, name))}
    if args.repo and args.repo.count("/") != 1:
        parser.error("--repo is owner/name")
    changed = 0
    left: dict[str, list[str]] = {}
    for path, text in project_files():
        new = text
        if not args.check:
            for old, value in pairs.items():
                new = new.replace(old, value)
            if new != text:
                path.write_text(new, encoding="utf-8")
                changed += 1
        for placeholder in PLACEHOLDERS.values():
            if placeholder in new:
                left.setdefault(placeholder, []).append(str(path.relative_to(ROOT)))
    if not args.check:
        print(f"updated {changed} files")
    for placeholder, paths in left.items():
        print(f"still a placeholder: {placeholder} in {', '.join(paths)}")
    if not left:
        print("no placeholders left")
    return 1 if args.check and left else 0


if __name__ == "__main__":
    sys.exit(main())
