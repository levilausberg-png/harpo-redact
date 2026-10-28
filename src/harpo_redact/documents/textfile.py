"""Text-like files: .txt .md .csv .tsv .json .xml .html .yaml .log and similar.

Edits are applied to the raw text, so quoting, line endings and every untouched byte
stay exactly as they were. CSV and TSV cells are scanned with their column header as
context ("Name: Priya Raman"), which lets the name rules work on a bare cell.
"""

from __future__ import annotations

import codecs
from typing import Any

from .common import DocError, Limits, Segment, apply_ranges, has_content

_CHUNK = 8_000


def decode_text(data: bytes) -> tuple[str, str]:
    """(codec to write back with, text). Anything that is not clearly text is refused."""
    if data.startswith(codecs.BOM_UTF8):
        return "utf-8-sig", data.decode("utf-8-sig")
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        try:
            return "utf-16", data.decode("utf-16")
        except UnicodeDecodeError:
            raise DocError("unsupported_encoding", "the file is not valid UTF-16 text") from None
    if b"\x00" in data:
        raise DocError("binary_content", "the file contains binary data and is not a text file")
    try:
        return "utf-8", data.decode("utf-8")
    except UnicodeDecodeError:
        raise DocError("unsupported_encoding", "only UTF-8 and UTF-16 text is supported") from None


def _delimiter(text: str, name: str) -> str:
    if name.endswith(".tsv"):
        return "\t"
    first = text[:4000].split("\n", 1)[0]
    return max((",", ";", "\t", "|"), key=first.count) if first.strip() else ","


def csv_fields(text: str, delim: str) -> list[tuple[int, int, int, int]]:
    """(row, column, start, end) of every field's content, quotes excluded."""
    fields: list[tuple[int, int, int, int]] = []
    n, i, row, col = len(text), 0, 0, 0
    stops = (delim, "\n", "\r")
    while True:
        if i < n and text[i] == '"':
            j = i + 1
            while j < n:
                if text[j] == '"':
                    if j + 1 < n and text[j + 1] == '"':
                        j += 2
                        continue
                    break
                j += 1
            start, end, k = i + 1, min(j, n), j + 1
            while k < n and text[k] not in stops:
                k += 1
        else:
            k = i
            while k < n and text[k] not in stops:
                k += 1
            start, end = i, k
        fields.append((row, col, start, end))
        if k >= n:
            return fields
        if text[k] == delim:
            col, i = col + 1, k + 1
            continue
        if text[k] == "\r" and k + 1 < n and text[k + 1] == "\n":
            k += 1
        row, col, i = row + 1, 0, k + 1
        if i >= n:
            return fields


def chunks(text: str) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    pos, n = 0, len(text)
    while pos < n:
        end = min(n, pos + _CHUNK)
        if end < n:
            cut = max(text.rfind("\n", pos + _CHUNK // 2, end), text.rfind(" ", pos + _CHUNK // 2, end))
            if cut > pos:
                end = cut + 1
        out.append((pos, end))
        pos = end
    return out


class TextDocument:
    kind = "text"

    def __init__(self, data: bytes, name: str, limits: Limits) -> None:
        self.codec, self.text = decode_text(data)
        if len(self.text) > limits.max_chars:
            raise DocError("too_many_characters", f"the file has more than {limits.max_chars} characters")
        self.limits = limits
        self._segments: list[tuple[Segment, int]] = []  # (segment, offset of its text in self.text)
        lowered = name.lower()
        if lowered.endswith((".csv", ".tsv")):
            self._csv(lowered)
        else:
            self._plain()
        self.info: dict[str, Any] = {"kind": "text", "characters": len(self.text)}

    def _plain(self) -> None:
        for start, end in chunks(self.text):
            piece = self.text[start:end]
            if has_content(piece):
                self._segments.append((Segment(piece), start))

    def _csv(self, name: str) -> None:
        delim = _delimiter(self.text, name)
        cells = csv_fields(self.text, delim)
        if len(cells) > self.limits.max_segments:
            self._plain()  # too many cells to scan one by one: scan the file in chunks instead
            return
        header: dict[int, str] = {}
        for row, col, start, end in cells:
            value = self.text[start:end]
            if row == 0:
                header[col] = value.strip()
            if not has_content(value):
                continue
            label = header.get(col, "") if row > 0 else ""
            self._segments.append((Segment(value, ctx=f"{label}: " if label else "", row=row), start))

    def segments(self) -> list[Segment]:
        return [s for s, _ in self._segments]

    def apply(self, edits: dict[int, dict[str, Any]]) -> bytes:
        ranges: list[list[Any]] = []
        for index, edit in edits.items():
            segment, offset = self._segments[index]
            size = len(segment.text)
            if "t" in edit:
                ranges.append([offset, offset + size, str(edit["t"])])
            else:  # never trust offsets from outside the segment
                ranges.extend(
                    [offset + max(0, min(int(a), size)), offset + max(0, min(int(b), size)), p] for a, b, p in edit["r"]
                )
        return apply_ranges(self.text, ranges).encode(self.codec)

    def verify_strings(self, output: bytes) -> list[str]:
        reopened = TextDocument(output, "", self.limits)
        return [s.ctx + s.text for s in reopened.segments()]
