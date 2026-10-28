"""Generate one verified sample per credential rule into tests/data/secret_samples.json.

    python tools/gen_secret_samples.py

Each gitleaks regex is turned into random matching strings (rstr). A string is
kept only when the library flags it under that exact rule id, so the fixture
proves the rule works end to end: keyword prefilter, RE2 match, secret group,
entropy threshold and allowlists. Rules where no attempt succeeds are listed
with the reason so a test can pin them. Re-run after updating gitleaks.toml.
"""

from __future__ import annotations

import json
import os
import random
import re
import sys
import tomllib
from pathlib import Path

import rstr

from harpo_redact.detectors.secret_library import _vendored_rules, load_library

rstr_xeger = sys.modules[rstr.Rstr.__module__]  # the module; rstr.xeger is a function

ATTEMPTS = 400
POSIX = {
    "[:alnum:]": "a-zA-Z0-9",
    "[:alpha:]": "a-zA-Z",
    "[:digit:]": "0-9",
    "[:upper:]": "A-Z",
    "[:lower:]": "a-z",
    "[:xdigit:]": "0-9A-Fa-f",
    "[:space:]": " \\t",
    "[:word:]": "\\w",
}


def for_python(rx: str) -> str:
    """RE2 syntax to something Python's sre_parse can generate from (RE2 still judges)."""
    head, tail = (rx[:4], rx[4:]) if rx.startswith("(?i)") else ("", rx)
    tail = tail.replace("(?i)", "")  # a mid-pattern flag only widens case, RE2 decides
    rx = head + tail
    rx = rx.replace("\\z", "\\Z")
    for k, v in POSIX.items():
        rx = rx.replace(k, v)
    return rx


def main() -> int:
    if os.environ.get("PYTHONHASHSEED") != "0":  # set iteration order must not change the samples
        os.execve(sys.executable, [sys.executable, *sys.argv], {**os.environ, "PYTHONHASHSEED": "0"})  # noqa: S606
    lib = load_library()
    raw = tomllib.loads(_vendored_rules())
    patterns = {r["id"]: r["regex"] for r in raw["rules"] if "regex" in r}
    rng = random.Random(20261002)  # noqa: S311  # test data, seeded so the fixture is reproducible
    rstr_xeger.STAR_PLUS_LIMIT = 400  # tokens such as Bedrock keys need up to 300 characters
    gen = rstr.Rstr(rng)
    # Unescaped dots in host names ("hooks.slack.com") should mostly come out as dots.
    gen._cases["any"] = lambda _: "." if rng.random() < 0.8 else rng.choice("abcdefghijklmnop")
    samples: dict[str, dict[str, str]] = {}
    missing: dict[str, str] = {}
    for rule in lib.rules:
        try:
            py = re.compile(for_python(patterns[rule.id]))
        except re.error as exc:
            missing[rule.id] = f"not generatable: {exc}"
            continue
        for _ in range(ATTEMPTS):
            try:
                text = gen.xeger(py)
            except Exception as exc:  # rstr raises on exotic opcodes
                missing[rule.id] = f"generator error: {type(exc).__name__}"
                break
            if not text.strip() or "\x00" in text:
                continue
            # Some rules only run when the provider is named nearby, as in gitleaks.
            contexts = [text] + [f"{kw} {text}" for kw in rule.keywords[:2]]
            found = None
            for candidate in contexts:
                hits = [s for s in lib.find(candidate) if f"secret:{rule.id}" in s.sources]
                if hits:
                    found = {"text": candidate, "secret": candidate[hits[0].start : hits[0].end]}
                    break
            if found:
                samples[rule.id] = found
                missing.pop(rule.id, None)
                break
        else:
            missing.setdefault(rule.id, "no generated string passed keywords, entropy and allowlists")
    out = Path(__file__).resolve().parents[1] / "tests" / "data" / "secret_samples.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"samples": samples, "missing": missing}, indent=1, sort_keys=True) + "\n")
    print(f"{len(samples)} of {len(lib.rules)} rules have a verified sample; {len(missing)} missing")
    for rule_id, reason in sorted(missing.items()):
        print(f"  {rule_id}: {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
