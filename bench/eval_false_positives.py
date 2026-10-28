"""False-positive rate of the deterministic layers on public-domain prose.

    python bench/eval_false_positives.py /path/to/gutenberg/*.txt

Every hit in prose this old is a false positive for the high-risk types (cards,
IDs, secrets, phones, emails...), so the counts are the false-positive counts.
"""

from __future__ import annotations

import sys
import time
from collections import Counter
from pathlib import Path

from harpo_redact.config import Settings
from harpo_redact.pipeline import Pipeline


def main(paths: list[str]) -> int:
    pipeline = Pipeline(Settings(environment="development", detection={"ner": {"enabled": False}}))
    total_chars, counts, examples = 0, Counter[str](), {}
    started = time.perf_counter()
    for path in paths:
        text = Path(path).read_text(encoding="latin-1")
        total_chars += len(text)
        chunks = [text[i : i + 8000] for i in range(0, len(text), 8000)]
        for i in range(0, len(chunks), 50):
            batch = chunks[i : i + 50]
            outcome = pipeline.scan_sync(batch)
            for chunk, findings in zip(batch, outcome.findings, strict=True):
                for f in findings:
                    counts[f.type.value] += 1
                    if f.start is not None and f.type.value not in examples:
                        examples[f.type.value] = (
                            Path(path).name,
                            chunk[max(0, f.start - 30) : f.end + 30].replace("\n", " "),
                        )
    elapsed = time.perf_counter() - started
    print(f"{total_chars / 1e6:.1f} M characters in {elapsed:.0f} s ({total_chars / 1e3 / elapsed:.0f} KB/s)")
    names = {"PERSON", "ORGANIZATION", "LOCATION"}  # characters and places in novels are real names
    print("High-risk types (every hit in 19th-century prose is a false positive unless it is Gutenberg's own header):")
    for etype, n in counts.most_common():
        if etype not in names:
            print(f"  {etype:16} {n:6}  {n / (total_chars / 1e6):7.2f} per M chars   e.g. {examples.get(etype)}")
    print("Name types (fictional characters; not counted as errors):", {k: v for k, v in counts.items() if k in names})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
