"""End-to-end time to redact a document: worker start, extraction, scan, edit, verification.

    python bench/bench_documents.py --runs 5 --json bench/results_documents.json

Cold numbers: the NER cache is off, the machine is whatever you run this on.
"""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import platform
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from harpo_redact.api import load_ner
from harpo_redact.config import Settings
from harpo_redact.documents.runner import WorkerRunner
from harpo_redact.documents.service import redact_document
from harpo_redact.pipeline import Pipeline


# Every piece of text is unique: identical text is scanned once, which would flatter the numbers.
def line(i: int) -> str:
    phone = f"+31 20 794 {6000 + i % 1000:04d}"
    return f"Please contact Priya Raman at priya.raman{i}@corp.example or {phone} about invoice {4400 + i}. "


def filler(i: int) -> str:
    return f"The quarterly review {i} covers delivery, staffing and the plan for release {i * 7 % 97}. "


def docx(paragraphs: int) -> bytes:
    import docx as d

    doc = d.Document()
    for i in range(paragraphs):
        doc.add_paragraph((line(i) if i % 10 == 0 else filler(i)) * 2)
    out = io.BytesIO()
    doc.save(out)
    return out.getvalue()


def xlsx(rows: int) -> bytes:
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws.append(["Name", "Email", "Phone", "City", "Notes"])
    for i in range(rows):
        ws.append(
            [
                f"Person Number{i}",
                f"user{i}@corp.example",
                f"+31 20 794 {6000 + i % 1000:04d}",
                "Amsterdam",
                "regular customer",
            ]
        )
    out = io.BytesIO()
    wb.save(out)
    return out.getvalue()


def pptx(slides: int) -> bytes:
    from pptx import Presentation

    prs = Presentation()
    for i in range(slides):
        slide = prs.slides.add_slide(prs.slide_layouts[1])
        slide.shapes.title.text = f"Review {i}"
        slide.placeholders[1].text = line(i) + filler(i)
    out = io.BytesIO()
    prs.save(out)
    return out.getvalue()


def pdf(pages: int) -> bytes:
    from reportlab.pdfgen import canvas

    out = io.BytesIO()
    c = canvas.Canvas(out)
    for page in range(pages):
        c.setFont("Helvetica", 11)
        for n in range(40):
            k = page * 40 + n
            c.drawString(50, 800 - n * 18, (line(k) if n % 8 == 0 else filler(k))[:95])
        c.showPage()
    c.save()
    return out.getvalue()


def csv(rows: int) -> bytes:
    lines = ["Name,Email,City"] + [f"Person Number{i},user{i}@corp.example,Amsterdam" for i in range(rows)]
    return ("\r\n".join(lines) + "\r\n").encode()


def text(n: int) -> bytes:
    return "".join(filler(i) if i % 40 else line(i) for i in range(n)).encode()


CASES = [
    ("docx, 100 paragraphs", "a.docx", lambda: docx(100)),
    ("xlsx, 200 rows x 5 columns", "a.xlsx", lambda: xlsx(200)),
    ("pptx, 10 slides", "a.pptx", lambda: pptx(10)),
    ("pdf, 5 pages", "a.pdf", lambda: pdf(5)),
    ("pdf, 20 pages", "a.pdf", lambda: pdf(20)),
    ("csv, 1000 rows x 3 columns", "a.csv", lambda: csv(1000)),
    ("plain text, 100 KB", "a.txt", lambda: text(1200)),
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--json")
    args = parser.parse_args()
    settings = Settings(environment="development", detection={"ner": {"cache_entries": 0}})
    pipeline = Pipeline(settings, ner=load_ner(settings.detection.ner))
    pipeline.warmup()
    runner = WorkerRunner(settings.documents)
    results: dict[str, object] = {
        "python": platform.python_version(),
        "machine": platform.platform(),
        "cpus": __import__("os").cpu_count(),
        "rows": [],
    }

    spawn = []
    for _ in range(args.runs + 1):
        t = time.perf_counter()
        asyncio.run(runner.selftest())
        spawn.append((time.perf_counter() - t) * 1000)
    base = statistics.median(spawn[1:])
    print(f"worker start + self-test: {base:.0f} ms (median)")
    results["worker_start_ms"] = round(base)
    print(f"{'document':32} {'KB':>7} {'p50 s':>7} {'max s':>7} {'segments':>9} {'redactions':>11}")
    for label, name, build in CASES:
        data = build()
        times, segments, redactions = [], 0, 0
        for i in range(args.runs + 1):
            t = time.perf_counter()
            out = asyncio.run(
                redact_document(
                    pipeline,
                    settings.documents,
                    runner,
                    data,
                    name,
                    None,
                    mode=None,
                    context_repair=None,
                    override=False,
                    want_file=True,
                )
            )
            if i:
                times.append(time.perf_counter() - t)
            segments, redactions = out.segments, out.scan.redactions
        row = {
            "document": label,
            "kb": round(len(data) / 1000, 1),
            "p50_s": round(statistics.median(times), 2),
            "max_s": round(max(times), 2),
            "segments": segments,
            "redactions": redactions,
        }
        results["rows"].append(row)  # type: ignore[union-attr]
        print(f"{label:32} {row['kb']:>7} {row['p50_s']:>7} {row['max_s']:>7} {segments:>9} {redactions:>11}")
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=1) + "\n")


if __name__ == "__main__":
    main()
