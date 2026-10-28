"""Run Harpo over a dataset and score only what it would have sent.

Every document goes through the same pipeline a request does (Pipeline.scan_sync). A gold span counts as protected
when every letter and digit in it was inside one of Harpo's redactions, or when the request was blocked; partly
covered spans are counted on their own, since part of the value still left. Redactions outside the gold spans are
reported as collateral, by Harpo type: the datasets do not annotate everything Harpo protects (organisations, say),
so it is an upper bound on over-redaction, not a precision.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import os
import platform
import re
import time
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from multiprocessing import get_context
from pathlib import Path
from typing import Any

import rscore
from corpora import Doc
from scope import REDACTIONBENCH_NEUTRAL, scope_of

KEY_TYPES = frozenset({"SECRET", "PRIVATE_KEY"})
CONFIGS = ("default-image", "deterministic")

# A credential-named field or statement holding six or more characters: "api_key = ...", "password: ...", "the
# secret is ...". ProwlBench's datasheet says hard negatives with a high-entropy value in a secret-named assignment
# were left out, since flagging those is defensible; this looser pattern remains in some, so false alarms on
# ProwlBench are also reported split by it.
CREDENTIAL_NAMED_RE = re.compile(
    r"(?i)(?:pass(?:word|wd)?|pwd|secret|api[_\- ]?key|access[_\- ]?key|private[_\- ]?key|token|credential"
    r"|auth(?:orization)?)[\w.\-]*[\"'`*]*\s*(?:=|:|=>|\bis\b)\s*[\"'`]?(?:bearer\s+|basic\s+)?"
    r"[A-Za-z0-9+/_\-$!@#%^&*.~]{6,}"
)


def pipeline_for(config: str) -> Any:
    """The configurations LeakBench measures: what the Docker image ships, and the deterministic layers alone."""
    from harpo_redact.api import load_ner
    from harpo_redact.config import Settings
    from harpo_redact.pipeline import Pipeline

    if config == "deterministic":
        return Pipeline(Settings(environment="development", detection={"ner": {"enabled": False}}))
    ner_cfg = {"cache_entries": 0, "language_models": {"de": "de_core_news_sm", "other": "xx_ent_wiki_sm"}}
    settings = Settings(environment="development", detection={"ner": ner_cfg})
    return Pipeline(settings, ner=load_ner(settings.detection.ner))


_PIPELINE: Any = None
_DATASET = ""


def _init(config: str, dataset: str) -> None:
    global _PIPELINE, _DATASET
    _PIPELINE = pipeline_for(config)
    _PIPELINE.warmup()
    _DATASET = dataset


def score(doc: Doc, findings: list[tuple[int | None, int | None, str]], blocked: bool, dataset: str) -> dict[str, Any]:
    """Per-document result: each gold span's status and coverage, and the collateral redactions by type."""
    text = doc.text
    n = len(text)
    covered = bytearray(n)
    unplaced = 0
    for start, end, _ in findings:
        if start is None or end is None:
            unplaced += 1
            continue
        covered[max(0, start) : min(n, end)] = b"\x01" * (min(n, end) - max(0, start))
    gold_mask = bytearray(n)
    spans = []
    for g in doc.gold:
        start, end = max(0, g.start), min(n, g.end)
        gold_mask[start:end] = b"\x01" * (end - start)
        idx = [i for i in range(start, end) if text[i].isalnum()]
        if not idx:
            continue
        hit = sum(covered[i] for i in idx)
        if blocked:
            status = "blocked"
        elif hit == len(idx):
            status = "redacted"
        elif hit:
            status = "partial"
        else:
            status = "leaked"
        spans.append(
            {
                "labels": list(g.labels),
                "scope": scope_of(dataset, list(g.labels)),
                "status": status,
                "coverage": round(hit / len(idx), 4),
                "start": start,
                "end": end,
            }
        )
    collateral: Counter[str] = Counter()
    for start, end, kind in findings:
        if start is None or end is None:
            continue
        for i in range(max(0, start), min(n, end)):
            if not gold_mask[i] and text[i].isalnum():
                collateral[kind] += 1
    outside = sum(1 for i in range(n) if not gold_mask[i] and text[i].isalnum())
    extra: dict[str, Any] = {}
    if dataset == "redactionbench":  # the benchmark's own metric, over what left: a blocked request sends nothing
        redacted = bytearray(b"\x01" * n) if blocked else covered
        extra["r_score"] = rscore.document_score(text, [(g.start, g.end, g.labels[0]) for g in doc.gold], redacted)
    return extra | {
        "id": doc.id,
        "meta": doc.meta,
        "spans": spans,
        "unlocated": doc.unlocated,
        "blocked": blocked,
        "types": sorted({kind for _, _, kind in findings}),
        "key_flag": any(kind in KEY_TYPES for _, _, kind in findings),
        "secret": doc.secret,
        "credential_named": bool(CREDENTIAL_NAMED_RE.search(text)) if doc.secret is False else None,
        "collateral": dict(collateral),
        "outside_chars": outside,
        "unplaced_findings": unplaced,
        "chars": n,
    }


def _scan(doc: Doc) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        out = _PIPELINE.scan_sync([doc.text])
    except Exception as exc:  # a crash would fail the request: nothing leaves, but it is a failure to report
        result = score(doc, [], True, _DATASET)
        result.update(error=type(exc).__name__, ms=(time.perf_counter() - started) * 1000)
        return result
    findings = [(f.start, f.end, str(f.type)) for f in out.findings[0]]
    result = score(doc, findings, out.blocked, _DATASET)
    result["ms"] = (time.perf_counter() - started) * 1000
    if out.blocked:
        result["reasons"] = sorted({r.code for r in out.reasons})
    return result


def run(docs: Iterable[Doc], dataset: str, config: str, workers: int) -> Iterator[dict[str, Any]]:
    """Results in completion order; each worker loads its own pipeline (spaCy models are per process). One worker
    runs in this process."""
    if workers <= 1:
        _init(config, dataset)
        yield from map(_scan, docs)
        return
    context = get_context("fork")
    with context.Pool(workers, initializer=_init, initargs=(config, dataset)) as pool:
        yield from pool.imap_unordered(_scan, docs, chunksize=16)


def _recall(rows: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(rows)
    count = Counter(r["status"] for r in rows)
    protected = count["redacted"] + count["blocked"]
    return {
        "spans": n,
        "redacted": count["redacted"],
        "blocked": count["blocked"],
        "partial": count["partial"],
        "leaked": count["leaked"],
        "recall": round(protected / n, 4) if n else None,  # every letter and digit of the value removed
        "recall_any": round((protected + count["partial"]) / n, 4) if n else None,  # at least part removed
    }


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(q * len(ordered)))], 2)


def aggregate(results: list[dict[str, Any]], dataset: str, slices: tuple[str, ...]) -> dict[str, Any]:
    spans = [s | {"meta": r["meta"]} for r in results for s in r["spans"]]
    by_label: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in spans:
        by_label["+".join(s["labels"])].append(s)
    out: dict[str, Any] = {
        "documents": len(results),
        "in_scope": _recall([s for s in spans if s["scope"] == "in"]),
        "all_labels": _recall([s for s in spans if dataset != "redactionbench" or s["scope"] == "in"]),
        "out_of_scope": _recall([s for s in spans if s["scope"] == "out"]),
        "unmapped": _recall([s for s in spans if s["scope"] == "unmapped"]),
        "unmapped_labels": sorted({lab for s in spans if s["scope"] == "unmapped" for lab in s["labels"]}),
        "per_label": {label: _recall(rows) | {"scope": rows[0]["scope"]} for label, rows in sorted(by_label.items())},
        "unlocated_values": sum(r["unlocated"] for r in results),
        "blocked_documents": sum(r["blocked"] for r in results),
        "block_reasons": dict(Counter(code for r in results for code in r.get("reasons", []))),
        "errors": dict(Counter(r["error"] for r in results if "error" in r)),
        "unplaced_findings": sum(r["unplaced_findings"] for r in results),
    }
    if dataset == "redactionbench":
        out["neutral_labels"] = sorted(REDACTIONBENCH_NEUTRAL)
        out["r_score"] = r_score_summary(results)
    for key in slices:
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for s in spans:
            if s["scope"] == "in":
                groups[s["meta"].get(key, "")].append(s)
        out[f"by_{key}"] = {value: _recall(rows) for value, rows in sorted(groups.items())}
    collateral: Counter[str] = Counter()
    for r in results:
        collateral.update(r["collateral"])
    outside = sum(r["outside_chars"] for r in results)
    out["collateral"] = {
        "chars_outside_gold": outside,
        "redacted_outside_gold": sum(collateral.values()),
        "rate": round(sum(collateral.values()) / outside, 4) if outside else None,
        "by_type": dict(collateral.most_common()),
    }
    ms = [r["ms"] for r in results]
    chars = sum(r["chars"] for r in results)
    out["latency_ms"] = {"p50": _percentile(ms, 0.5), "p95": _percentile(ms, 0.95), "p99": _percentile(ms, 0.99),
                         "max": round(max(ms), 2) if ms else 0, "mean_chars": round(chars / max(len(results), 1))}  # fmt: skip
    return out


# RedactionBench's unstructured categories, the paper's second leaderboard column; the rest are code, files, logs
# and terminal output.
UNSTRUCTURED = frozenset({"academic", "emails", "financial", "government", "legal", "medical", "operations"})


def r_score_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    """RedactionBench's R-Score over documents (rscore.py): mean, P50 and P20, overall and by slice, with the
    terms behind it summed so a change can be traced to what moved."""
    rows = [r for r in results if "r_score" in r]

    def scores(keep: Any) -> list[float]:
        return [r["r_score"]["score"] for r in rows if keep(r)]

    out = rscore.summarize(scores(lambda r: True))
    out["unstructured"] = rscore.summarize(scores(lambda r: r["meta"].get("category") in UNSTRUCTURED))
    by_category = {
        category: rscore.summarize(scores(lambda r, c=category: r["meta"].get("category") == c))
        for category in sorted({r["meta"].get("category", "") for r in rows})
    }
    out["by_category"] = by_category
    means = [v["mean"] for v in by_category.values() if v["mean"] is not None]
    out["macro_by_category"] = round(sum(means) / len(means), 4) if means else None
    for key in ("half", "synthetic"):
        out[f"by_{key}"] = {
            value: rscore.summarize(scores(lambda r, k=key, v=value: r["meta"].get(k) == v))
            for value in sorted({r["meta"].get(key, "") for r in rows})
        }
    out["terms"] = {
        "mandatory_entities": sum(r["r_score"]["mandatory_entities"] for r in rows),
        "mandatory_coverage": round(sum(r["r_score"]["num"] for r in rows if not r["r_score"]["all_contextual"]), 2),
        "contextual_attempted": sum(r["r_score"]["contextual_attempted"] for r in rows),
        "contextual_penalty": round(sum(r["r_score"]["contextual_penalty"] for r in rows), 2),
        "false_runs": sum(r["r_score"]["false_runs"] for r in rows),
        "whole_gaps": sum(r["r_score"]["whole_gaps"] for r in rows),
        "all_contextual_documents": sum(r["r_score"]["all_contextual"] for r in rows),
    }
    return out


def prowl_metrics(results: list[dict[str, Any]], flagged: set[str] | None = None) -> dict[str, Any]:
    """ProwlBench's own numbers, defined exactly as its run_prowlbench.py does: a case is detected when the tool
    flags at least one secret in it. For Harpo that is a SECRET or PRIVATE_KEY redaction."""
    det = flagged if flagged is not None else {r["id"] for r in results if r["key_flag"]}
    cases = [{"id": r["id"], "label": bool(r["secret"]), **r["meta"]} for r in results]
    tp = sum(c["id"] in det and c["label"] for c in cases)
    fp = sum(c["id"] in det and not c["label"] for c in cases)
    fn = sum(c["id"] not in det and c["label"] for c in cases)
    tn = sum(c["id"] not in det and not c["label"] for c in cases)
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 0.0
    out: dict[str, Any] = {
        "precision": round(p, 4),
        "recall": round(r, 4),
        "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0,
        "accuracy": round((tp + tn) / len(cases), 4) if cases else None,
        "per_tier": {},
        "per_language": {},
        "per_source": {},
    }
    for tier in sorted({c["tier"] for c in cases}):
        sub = [c for c in cases if c["tier"] == tier]
        if tier == "T4_hard_negative":
            out["per_tier"][tier] = {"fp_rate": round(sum(c["id"] in det for c in sub) / len(sub), 4), "n": len(sub)}
        else:
            npos = max(sum(c["label"] for c in sub), 1)
            out["per_tier"][tier] = {
                "recall": round(sum(c["id"] in det and c["label"] for c in sub) / npos, 4),
                "n": npos,
            }
    for key, name in (("lang", "per_language"), ("source", "per_source")):
        for value in sorted({c[key] for c in cases}):
            sub = [c for c in cases if c[key] == value and c["label"]]
            if sub:
                out[name][value] = {"recall": round(sum(c["id"] in det for c in sub) / len(sub), 4), "n": len(sub)}
    # Not ProwlBench's own breakdowns: false alarms split by CREDENTIAL_NAMED_RE, recall per secret type and
    # false-alarm rate per negative type.
    named = {r["id"]: r.get("credential_named") for r in results}
    out["negatives"] = {}
    for kind, want in (("credential_named", True), ("other", False)):
        sub = [c for c in cases if not c["label"] and named[c["id"]] is want]
        if sub:
            out["negatives"][kind] = {"fp_rate": round(sum(c["id"] in det for c in sub) / len(sub), 4), "n": len(sub)}
    out["per_type"] = {}
    for value in sorted({c["type"] for c in cases}):
        sub = [c for c in cases if c["type"] == value]
        rate = round(sum(c["id"] in det for c in sub) / len(sub), 4)
        out["per_type"][value] = {"recall" if sub[0]["label"] else "fp_rate": rate, "n": len(sub)}
    return out


def harpo_identity() -> dict[str, Any]:
    """Which Harpo ran: version, and a digest of every file of the installed package."""
    import harpo_redact

    root = Path(harpo_redact.__file__).parent
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts):
        digest.update(str(path.relative_to(root)).encode())
        digest.update(path.read_bytes())
    models = {}
    for name in ("en_core_web_sm", "de_core_news_sm", "xx_ent_wiki_sm", "spacy"):
        try:
            models[name] = importlib.metadata.version(name.replace("_", "-"))
        except importlib.metadata.PackageNotFoundError:
            models[name] = None
    return {
        "version": harpo_redact.__version__,
        "package_sha256": digest.hexdigest(),
        "python": platform.python_version(),
        "models": models,
        "cpus": os.cpu_count(),
    }


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def summary_line(dataset: str, agg: dict[str, Any]) -> str:
    inside = agg["in_scope"]
    r = agg.get("r_score")
    return (
        f"{dataset}: {agg['documents']} documents, {inside['spans']} in-scope values: recall {inside['recall']} "
        f"(any part {inside['recall_any']}), {inside['leaked']} leaked, {inside['partial']} partly; "
        f"collateral {agg['collateral']['rate']}; p95 {agg['latency_ms']['p95']} ms"
        + (f"; R-Score mean {r['mean']} P50 {r['p50']} P20 {r['p20']}" if r else "")
    )
