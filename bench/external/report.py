"""Write the recorded external-benchmark results into docs/EXTERNAL_BENCHMARKS.md.

  python bench/external/report.py [--check]

The doc names the result folders it shows in a marker line, <!-- results 2.4.0-baseline -->. Everything from there to
<!-- /results --> is generated from bench/external/results/<folder>/*.json, and the block between <!-- regionbench
<builds> --> and <!-- /regionbench --> from bench/regionbench/results-<build>.json, so no number in those tables is
typed by hand. --check exits 1 when the doc is out of date; the test suite checks the same.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DOC = ROOT / "docs" / "EXTERNAL_BENCHMARKS.md"
RESULTS = HERE / "results"
MARKER = re.compile(r"<!-- results (?P<runs>[\w.\- ]+) -->\n(?P<body>.*?)<!-- /results -->", re.DOTALL)
DATASETS = {
    "openpii": "OpenPII (ai4privacy)",
    "nemotron": "Nemotron-PII (NVIDIA)",
    "gretel": "Gretel PII masking",
    "redactionbench": "RedactionBench",
    "prowlbench": "ProwlBench",
}
SLICE_TITLES = {
    "language": "language",
    "domain": "domain",
    "document_format": "document format",
    "category": "category",
    "synthetic": "synthetic or real",
    "locale": "locale",
    "half": "half",
    "tier": "tier",
    "lang": "language",
    "source": "source",
    "origin": "origin",
}


def pct(value: float | None) -> str:
    return "–" if value is None else f"{100 * value:.1f}%"


def frac(value: float | None) -> str:
    return "–" if value is None else f"{value:.3f}"


def table(head: list[str], rows: list[list[str]]) -> list[str]:
    out = ["| " + " | ".join(head) + " |", "| " + " | ".join("---" for _ in head) + " |"]
    return out + ["| " + " | ".join(row) + " |" for row in rows]


def load(run: str) -> dict[str, dict[str, Any]]:
    folder = RESULTS / run
    if not folder.is_dir():
        raise SystemExit(f"no results folder {folder}")
    return {path.stem: json.loads(path.read_text()) for path in sorted(folder.glob("*.json"))}


def _recall_cells(r: dict[str, Any]) -> list[str]:
    return [f"{r['spans']:,}", pct(r["recall"]), pct(r["recall_any"]), f"{r['leaked']:,}", f"{r['partial']:,}"]


def _headline(runs: dict[str, dict[str, dict[str, Any]]]) -> list[str]:
    rows = []
    for key, title in DATASETS.items():
        found = False
        for run, records in runs.items():
            for rec in records.values():
                if rec["dataset"] != key:
                    continue
                found = True
                m = rec["metrics"]
                config = "" if rec["config"] == "default-image" else f" ({rec['config']})"
                rows.append(
                    [
                        f"{title}{config}",
                        run,
                        f"`{rec['file']}`",
                        f"{rec['documents']:,}",
                        *_recall_cells(m["in_scope"]),
                        pct(m["collateral"]["rate"]),
                        f"{m['latency_ms']['p50']} / {m['latency_ms']['p95']}",
                    ]
                )
        if not found:
            rows.append([title, "not run yet", "", "", "", "", "", "", "", "", ""])
    return table(
        ["Dataset", "Run", "File", "Documents", "Values in scope", "Fully removed", "Any part removed", "Leaked",
         "Partly removed", "Collateral", "p50 / p95 ms"],
        rows,
    )  # fmt: skip


def _identity(runs: dict[str, dict[str, dict[str, Any]]]) -> list[str]:
    rows = []
    for run, records in runs.items():
        for name, rec in records.items():
            h = rec["harpo"]
            models = ", ".join(f"{k} {v}" for k, v in h["models"].items() if v)
            rows.append(
                [run, name, h["version"], f"`{h['package_sha256'][:16]}`", f"`{rec['file_sha256'][:16]}`",
                 f"`{rec['scope_sha256'][:12]}`", f"`{rec['harness_sha256'][:12]}`", h["python"], models,
                 rec["started"][:10]]
            )  # fmt: skip
    return table(
        ["Run", "Result", "Harpo", "Package sha256", "Data file sha256", "Scope sha256", "Harness sha256", "Python",
         "Models", "Date"],
        rows,
    )  # fmt: skip


# ProwlBench's leaderboard: the rows a clean checkout reproduces, as its README at 53d6fc1 publishes them.
PROWL_PUBLISHED = (
    ("Prowl (shipped binary, cascade)", 0.951, 0.823, 0.883, 0.853),
    ("DeepPass2", 0.893, 0.567, 0.694, 0.663),
    ("gitleaks", 0.931, 0.413, 0.573, 0.585),
    ("detect-secrets", 0.848, 0.423, 0.564, 0.561),
    ("DeepSecrets", 0.921, 0.309, 0.462, 0.517),
    ("TruffleHog", 0.940, 0.303, 0.458, 0.518),
)


def _leaderboard(runs: dict[str, dict[str, dict[str, Any]]]) -> list[str]:
    """ProwlBench's published rows with Harpo's runs among them, by F1."""
    rows: list[tuple[float, list[str]]] = []
    for run, records in runs.items():
        for rec in records.values():
            if rec["dataset"] != "prowlbench" or "prowlbench" not in rec or rec.get("half") or rec.get("limit"):
                continue
            for key, label in (("harpo", "all cases"), ("harpo holdout half", "holdout half")):
                m = rec["prowlbench"].get(key)
                if m:
                    cells = [frac(m[k]) for k in ("precision", "recall", "f1", "accuracy")]
                    rows.append((m["f1"], [f"**Harpo, {run}, {label}**", *cells, "measured here"]))
    for name, *values in PROWL_PUBLISHED:
        rows.append((values[2], [name, *(frac(v) for v in values), "published"]))
    rows.sort(key=lambda r: -r[0])
    return table(["Tool", "Precision", "Recall", "F1", "Accuracy", "Source"], [r for _, r in rows])


# RedactionBench's leaderboard: Overall Mean R-Score as the paper (arXiv 2606.18782, its table of all 200 documents)
# reports it, with its scorer, which is not released yet. A selection: the five frontier and general models and
# the specialised PII models above 0.3.
RB_PUBLISHED = (
    ("claude-opus-4-6 (agentic, tool calls)", 0.71),
    ("gpt-5.4 (agentic, tool calls)", 0.66),
    ("Qwen3.5-397B-A17B", 0.59),
    ("openai/privacy-filter", 0.58),
    ("zai-org/GLM-5.1", 0.56),
    ("gretelai/gretel-gliner-bi-large-v1.0", 0.47),
    ("OpenMed-PII-SuperClinical-Large-434M-v1", 0.46),
    ("nvidia/gliner-PII", 0.42),
    ("jakobhuss/pii-extractor-gemma-3-270m-it", 0.40),
    ("iiiorg/piiranha-v1-detect-personal-information", 0.34),
    ("urchade/gliner_multi_pii-v1", 0.33),
)


def _r_score(runs: dict[str, dict[str, dict[str, Any]]]) -> list[str]:
    """RedactionBench's own metric for each run that has it, with the published rows."""
    rows: list[tuple[float, list[str]]] = []
    terms: list[list[str]] = []
    for run, records in runs.items():
        for rec in records.values():
            r = rec["metrics"].get("r_score") if rec["dataset"] == "redactionbench" else None
            if not r or rec.get("half") or rec.get("limit"):
                continue
            config = "" if rec["config"] == "default-image" else f" ({rec['config']})"
            halves = r["by_half"]
            rows.append(
                (r["mean"], [f"**Harpo, {run}{config}**", frac(r["mean"]), frac(r["p50"]), frac(r["p20"]),
                             frac(r["unstructured"]["mean"]), frac(halves["dev"]["mean"]),
                             frac(halves["holdout"]["mean"]), "measured here"])
            )  # fmt: skip
            t = r["terms"]
            terms.append(
                [f"{run}{config}", f"{t['mandatory_entities']:,}", f"{t['mandatory_coverage']:,.0f}",
                 f"{t['contextual_attempted']:,}", f"{t['contextual_penalty']:,.0f}", f"{t['false_runs']:,}",
                 f"{t['whole_gaps']:,}"]
            )  # fmt: skip
    if not rows:
        return []
    for name, mean in RB_PUBLISHED:
        rows.append((mean, [name, frac(mean), "", "", "", "", "", "published"]))
    rows.sort(key=lambda r: -r[0])
    out = table(["System", "Mean", "P50", "P20", "Unstructured mean", "Dev half", "Holdout half", "Source"],
                [r for _, r in rows])  # fmt: skip
    out += ["", "What the R-Score is made of, summed over the 200 documents:", ""]
    out += table(["Run", "Mandatory entities", "Covered (sum)", "Contextual attempted", "Contextual penalty",
                  "False-positive runs", "Whole gaps"], terms)  # fmt: skip
    return out


def _prowlbench(rec: dict[str, Any], run: str) -> list[str]:
    pb = rec["prowlbench"]
    out = [f"#### ProwlBench, {run}: its own metric (a snippet counts as detected when a secret is flagged in it)", ""]
    rows = []
    names = {"harpo": "Harpo, all cases", "harpo dev half": "Harpo, dev half",
             "harpo holdout half": "Harpo, holdout half"}  # fmt: skip
    for tool, m in pb.items():
        tiers = m["per_tier"]
        rows.append(
            [names.get(tool, f"{tool} (run here)"), frac(m["precision"]), frac(m["recall"]), frac(m["f1"]), frac(m["accuracy"])]
            + [frac(tiers.get(t, {}).get("recall")) for t in ("T1_structured", "T2_generic_context", "T3_freeform_multilingual")]
            + [frac(tiers.get("T4_hard_negative", {}).get("fp_rate"))]
        )  # fmt: skip
    out += table(["Tool", "Precision", "Recall", "F1", "Accuracy", "T1 recall", "T2 recall", "T3 recall", "T4 false-alarm rate"], rows)  # fmt: skip
    harpo = pb["harpo"]
    out += ["", "Recall by language and by source (Harpo, all cases):", ""]
    langs = harpo["per_language"]
    out += table(list(langs), [[f"{frac(v['recall'])} ({v['n']:,})" for v in langs.values()]])
    out += [""]
    sources = harpo["per_source"]
    out += table(list(sources), [[f"{frac(v['recall'])} ({v['n']:,})" for v in sources.values()]])
    neg = harpo.get("negatives", {})
    if neg:
        out += ["", "False alarms on the hard negatives, by whether the snippet assigns a value to a credential-named field:", ""]  # fmt: skip
        out += table(
            ["Negatives", "Cases", "False-alarm rate"],
            [[kind.replace("_", " "), f"{v['n']:,}", frac(v["fp_rate"])] for kind, v in neg.items()],
        )
    pos = {k: v for k, v in harpo["per_type"].items() if "recall" in v}
    negs = {k: v for k, v in harpo["per_type"].items() if "fp_rate" in v}
    out += ["", "<details><summary>Recall per secret type, false-alarm rate per negative type</summary>", ""]
    out += table(["Secret type", "Cases", "Recall"], [[k, f"{v['n']:,}", frac(v["recall"])] for k, v in pos.items()])
    out += [""]
    out += table(["Negative type", "Cases", "False-alarm rate"], [[k, f"{v['n']:,}", frac(v["fp_rate"])] for k, v in negs.items()])  # fmt: skip
    out += ["", "</details>"]
    return out


def _labels(rec: dict[str, Any], run: str, title: str) -> list[str]:
    m = rec["metrics"]
    out = [f"#### {title}, {run}: values removed, per label", ""]
    rows = [
        [f"`{label}`", r["scope"], *_recall_cells(r)]
        for label, r in m["per_label"].items()
    ]  # fmt: skip
    out += table(["Label", "Scope", "Values", "Fully removed", "Any part removed", "Leaked", "Partly removed"], rows)
    for line, key in (("Out of scope, all labels", "out_of_scope"), ("Unmapped labels", "unmapped")):
        r = m[key]
        if r["spans"]:
            out += [
                "",
                f"{line}: {r['spans']:,} values, {pct(r['recall'])} fully removed, {pct(r['recall_any'])} any part.",
            ]
    if m.get("unmapped_labels"):
        out += ["", "Unmapped: " + ", ".join(f"`{label}`" for label in m["unmapped_labels"]) + "."]
    if m.get("unlocated_values"):
        out += ["", f"{m['unlocated_values']:,} gold values could not be found in their text and are not scored."]
    if m.get("blocked_documents"):
        reasons = ", ".join(f"{k} {v}" for k, v in m["block_reasons"].items())
        out += ["", f"{m['blocked_documents']:,} documents were blocked whole ({reasons})."]
    if m.get("errors"):
        out += ["", "Errors: " + ", ".join(f"{k} {v}" for k, v in m["errors"].items()) + "."]
    return out


def _slices(rec: dict[str, Any], run: str, title: str) -> list[str]:
    m = rec["metrics"]
    out: list[str] = []
    for key, name in SLICE_TITLES.items():
        groups = m.get(f"by_{key}")
        if not groups:
            continue
        out += ["", f"{title}, {run}: in-scope values by {name}", ""]
        out += table([name.capitalize(), "Values", "Fully removed", "Any part removed", "Leaked", "Partly removed"],
                     [[g or "(none)", *_recall_cells(r)] for g, r in groups.items()])  # fmt: skip
    coll = m["collateral"]
    if coll["by_type"]:
        kinds = ", ".join(f"{k} {v:,}" for k, v in list(coll["by_type"].items())[:8])
        out += ["", f"Collateral: {coll['redacted_outside_gold']:,} of {coll['chars_outside_gold']:,} letters and digits "
                f"outside the gold values were redacted ({pct(coll['rate'])}); by type: {kinds}."]  # fmt: skip
    return out


def render(run_names: list[str]) -> str:
    runs = {run: load(run) for run in run_names}
    lines = ["### Summary", "", *_headline(runs)]
    lines += ["", "Run identity (the full digests are in the result files):", "", *_identity(runs)]
    board = _leaderboard(runs)
    if len(board) > 2 + len(PROWL_PUBLISHED):
        lines += [
            "",
            "ProwlBench's leaderboard with Harpo's runs (its published rows are those a clean checkout",
            "reproduces; Harpo has not been submitted):",
            "",
            *board,
        ]
    r_score = _r_score(runs)
    if r_score:
        lines += [
            "",
            "RedactionBench's own metric, the R-Score (bench/external/rscore.py, from the paper's definition; the",
            "authors' scorer is not released yet), with the published rows:",
            "",
            *r_score,
        ]
    for key, title in DATASETS.items():
        for run, records in runs.items():
            for rec in records.values():
                if rec["dataset"] != key:
                    continue
                config = "" if rec["config"] == "default-image" else f" ({rec['config']})"
                lines += [""]
                if key == "prowlbench" and "prowlbench" in rec:
                    lines += [*_prowlbench(rec, run + config), ""]
                lines += _labels(rec, run + config, title)
                lines += _slices(rec, run + config, title)
    return "\n".join(lines) + "\n"


REGION_RESULTS = ROOT / "bench" / "regionbench"
REGION_MARKER = re.compile(r"<!-- regionbench (?P<runs>[\w.\- ]+) -->\n(?P<body>.*?)<!-- /regionbench -->", re.DOTALL)
REGION_SPLITS = ("nl dev", "nl holdout", "us dev", "us holdout", "eu dev", "eu holdout")


def render_regionbench(run_names: list[str]) -> str:
    """RegionBench per build: values removed by region and template split, and the keeps it damaged."""
    rows, kinds = [], []
    for run in run_names:
        path = REGION_RESULTS / f"results-{run}.json"
        if not path.is_file():
            raise SystemExit(f"no RegionBench results {path}")
        rec = json.loads(path.read_text())
        m = rec["metrics"]
        cells = [pct(m["by_region_split"][g]["rate"]) for g in REGION_SPLITS]
        keeps = m["keeps"]
        rows.append([run, f"{m['all']['values']:,}", pct(m["all"]["rate"]), *cells,
                     f"{pct(keeps['false_positive_rate'])} ({keeps['redacted']:,} of {keeps['keeps']:,})"])  # fmt: skip
        kinds.append((run, m["by_kind"]))
    out = table(["Build", "Values", "Removed", *(g.replace(" ", ", ") for g in REGION_SPLITS), "Keeps damaged"], rows)
    last_run, last = kinds[-1]
    worst = sorted(last.items(), key=lambda kv: kv[1]["rate"] or 0)[:12]
    out += ["", f"The kinds of value {last_run} removes least often, over both splits:", ""]
    out += table(["Kind", "Values", "Removed", "Partly", "Leaked"],
                 [[k, f"{r['values']:,}", pct(r["rate"]), f"{r['partial']:,}", f"{r['leaked']:,}"] for k, r in worst])  # fmt: skip
    return "\n".join(out) + "\n"


def refresh(doc: str) -> str:
    match = MARKER.search(doc)
    if match is None:
        raise SystemExit("the doc has no <!-- results ... --> block")
    body = render(match["runs"].split())
    doc = doc[: match.start("body")] + body + doc[match.end("body") :]
    region = REGION_MARKER.search(doc)
    if region is not None:
        body = render_regionbench(region["runs"].split())
        doc = doc[: region.start("body")] + body + doc[region.end("body") :]
    return doc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 when the doc is out of date")
    args = parser.parse_args(argv)
    doc = DOC.read_text()
    new = refresh(doc)
    if args.check:
        print("up to date" if new == doc else "out of date: run python bench/external/report.py")
        return 0 if new == doc else 1
    DOC.write_text(new)
    print(f"wrote {DOC.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
