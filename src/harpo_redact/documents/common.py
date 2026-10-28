"""Types shared by the document engines. They run inside the worker process."""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Any

MAX_FRAME = 1 << 30  # a single message between gateway and worker, in bytes


class DocError(Exception):
    """A document the engines cannot or will not process. ``code`` is a stable reason."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.message = message or code


@dataclass(slots=True)
class Segment:
    """A piece of text to scan, with where it sits in the document."""

    text: str
    ctx: str = ""  # scanned together with the text, never edited: a column header
    group: str = ""  # reading-order heading, e.g. "page 2", "sheet Sales", "slide 3"
    row: int | None = None  # cells of one row are joined with tabs in the reading text

    def to_json(self) -> list[Any]:
        return [self.text, self.ctx, self.group, self.row]


@dataclass(frozen=True, slots=True)
class Limits:
    max_unpacked_bytes: int = 200_000_000
    max_part_bytes: int = 100_000_000
    max_parts: int = 5_000
    max_segments: int = 50_000
    max_chars: int = 1_000_000
    max_pages: int = 150
    images: str = "block"  # block | blank
    pdf_dpi: int = 150
    pdf_quality: int = 85
    pdf_max_pixels: int = 25_000_000
    pdf_pad: float = 0.12  # padding around a sensitive character box, as a fraction of its height

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Limits:
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in raw.items() if k in known})


def has_content(text: str) -> bool:
    return any(c.isalnum() for c in text)


def apply_ranges(text: str, ranges: list[list[Any]]) -> str:
    """Replace [start, end) ranges with their placeholder. Overlaps are absorbed."""
    out: list[str] = []
    pos = 0
    for start, end, placeholder in sorted(ranges, key=lambda r: (r[0], r[1])):
        start, end = max(0, int(start)), min(len(text), int(end))
        if start < pos:
            pos = max(pos, end)  # swallowed by the previous range
            continue
        out.append(text[pos:start])
        out.append(str(placeholder))
        pos = end
    out.append(text[pos:])
    return "".join(out)


def merge_ranges(groups: list[list[list[Any]]]) -> list[list[Any]]:
    """Union of range lists (a shared string used under several headers)."""
    flat = sorted((r for g in groups for r in g), key=lambda r: (r[0], -r[1]))
    merged: list[list[Any]] = []
    for start, end, placeholder in flat:
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end, placeholder])
    return merged


def edited_text(text: str, edit: dict[str, Any] | None) -> str:
    if not edit:
        return text
    if "t" in edit:
        return str(edit["t"])
    return apply_ranges(text, edit["r"])
