"""RedactionBench's R-Score (Brynjólfsson et al., arXiv 2606.18782, section 3.3), as this harness implements it.

The authors have not released their scorer yet (the dataset card says a reference implementation will follow), so
this is the paper's definition built from its text. Where the text leaves a choice open, the choice is written here,
and every number this file produces is labelled "as implemented here" in the docs.

The score of one document is a ratio of sums over its terms, R = sum(n) / sum(d):

- Spans come labelled mandatory or contextual. A contextual span with no letter or digit is glue (a blank, "/",
  ") ", "-"). A run of glue that touches a span of the same label on both sides joins them into one entity, so
  "Melissa Schettler" or "(559) 410-2874" is one entity and "03/08/2026" another (the paper's combinators). Glue is
  optional: it is never scored and redacting it is never an error. Spans that touch without glue stay separate
  entities, as the dataset card says.
- A mandatory entity gives (mean coverage of its parts, 1). Coverage is the share of a part's characters that were
  redacted; the mean over parts is the paper's component-wise mean, so a name in two parts is not worth two names.
- A contextual entity gives nothing unless it was attempted: any of its parts touched by a redaction. Touching one
  part selects the whole entity (the paper's grouping rule), and it then gives (0, 1 - mean coverage of its parts):
  redacting all of it or none of it is free, half of it costs half a point.
- In a document with no mandatory span at all, an attempted contextual entity gives (mean coverage, 1) instead, so
  such a document can still be scored above zero.
- A false positive is a run of redacted characters outside every labelled span. Each gives (0, 1), or (0, 2) when it
  is a whole gap of 3 or more characters between labelled spans (or a document edge). A run with no letter or digit
  (a blank, a bracket) is formatting and is not counted.
- A document with no terms at all (nothing mandatory, nothing attempted, nothing wrong) scores 1.0. A blocked
  request counts as every character redacted.

The dataset's score is the mean over documents, with the median (P50) and the 20th percentile (P20), as the paper
reports them, overall and by category.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Entity:
    label: str  # "mandatory" or "contextual"
    parts: list[tuple[int, int]] = field(default_factory=list)  # the scored spans
    glue: list[tuple[int, int]] = field(default_factory=list)  # connectors inside the entity, never scored


def _has_content(text: str, start: int, end: int) -> bool:
    return any(ch.isalnum() for ch in text[start:end])


def entities(text: str, spans: list[tuple[int, int, str]]) -> list[Entity]:
    """Group the labelled spans into entities: content spans joined by glue that has the same label on both sides.
    Glue that does not join two spans of one label is a contextual entity of its own."""
    ordered = sorted((max(0, s), min(len(text), e), label) for s, e, label in spans if e > s)

    def glue(k: int) -> bool:
        start, end, label = ordered[k]
        return label == "contextual" and not _has_content(text, start, end)

    out: list[Entity] = []
    current: Entity | None = None  # the entity the next glue run may extend
    i = 0
    while i < len(ordered):
        start, end, label = ordered[i]
        if not glue(i):
            current = Entity(label, [(start, end)])
            out.append(current)
            i += 1
            continue
        j = i  # the run of glue spans, each touching the next
        while j + 1 < len(ordered) and ordered[j + 1][0] == ordered[j][1] and glue(j + 1):
            j += 1
        after = j + 1
        if (
            current is not None
            and current.parts[-1][1] == start
            and after < len(ordered)
            and ordered[after][0] == ordered[j][1]
            and ordered[after][2] == current.label
            and not glue(after)
        ):
            current.glue.extend((s, e) for s, e, _ in ordered[i:after])
            current.parts.append((ordered[after][0], ordered[after][1]))
            i = after + 1
            continue
        out.extend(Entity("contextual", [(s, e)]) for s, e, _ in ordered[i:after])
        current = None
        i = after
    return out


def _coverage(redacted: bytearray, start: int, end: int) -> float:
    return sum(redacted[start:end]) / (end - start) if end > start else 0.0


def document_score(text: str, spans: list[tuple[int, int, str]], redacted: bytearray) -> dict[str, Any]:
    """R-Score of one document. `redacted` holds 1 for every character that was redacted."""
    groups = entities(text, spans)
    all_contextual = not any(g.label == "mandatory" for g in groups)
    num = den = 0.0
    mandatory = attempted = 0
    penalty = 0.0
    for g in groups:
        cover = [_coverage(redacted, s, e) for s, e in g.parts]
        mean = sum(cover) / len(cover)
        if g.label == "mandatory":
            mandatory += 1
            num += mean
            den += 1
        elif any(sum(redacted[s:e]) for s, e in g.parts):
            attempted += 1
            if all_contextual:
                num += mean
                den += 1
            else:
                den += 1 - mean
                penalty += 1 - mean
    labelled = bytearray(len(text))
    for s, e, _ in spans:
        labelled[max(0, s) : min(len(text), e)] = b"\x01" * (min(len(text), e) - max(0, s))
    false_runs = whole_gaps = 0
    i, n = 0, len(text)
    while i < n:
        if not redacted[i] or labelled[i]:
            i += 1
            continue
        j = i
        while j < n and redacted[j] and not labelled[j]:
            j += 1
        if _has_content(text, i, j):
            gap_start, gap_end = i, j
            while gap_start > 0 and not labelled[gap_start - 1]:
                gap_start -= 1
            while gap_end < n and not labelled[gap_end]:
                gap_end += 1
            whole = (gap_start, gap_end) == (i, j) and j - i >= 3
            false_runs += 1
            whole_gaps += whole
            den += 2 if whole else 1
        i = j
    score = num / den if den else 1.0
    return {
        "score": round(score, 6),
        "num": round(num, 6),
        "den": round(den, 6),
        "mandatory_entities": mandatory,
        "contextual_attempted": attempted,
        "contextual_penalty": round(penalty, 6),
        "false_runs": false_runs,
        "whole_gaps": whole_gaps,
        "all_contextual": all_contextual,
    }


def percentile(values: list[float], q: float) -> float | None:
    """The value at rank q of the sorted scores (lower nearest rank): P20 is the score 20% of documents fall below."""
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(q * len(ordered)))], 4)


def summarize(scores: list[float]) -> dict[str, Any]:
    if not scores:
        return {"documents": 0, "mean": None, "p50": None, "p20": None}
    return {
        "documents": len(scores),
        "mean": round(sum(scores) / len(scores), 4),
        "p50": percentile(scores, 0.5),
        "p20": percentile(scores, 0.2),
    }
