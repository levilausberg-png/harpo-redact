"""Document redaction: sniff the format, extract text in the worker, scan it with the gateway's
pipeline, send the edits back, and check the result before releasing it.

Fail closed: whatever cannot be inspected is refused (or blanked if policy says so), and a
redacted file is only returned after it was re-opened and re-scanned with nothing found.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any

from ..config import DocumentSettings, Mode
from ..pipeline import Pipeline, ScanOutcome
from .common import edited_text, has_content
from .runner import DocumentError, WorkerRunner

TEXT_EXTENSIONS = frozenset(
    [
        "txt",
        "md",
        "markdown",
        "rst",
        "csv",
        "tsv",
        "json",
        "jsonl",
        "ndjson",
        "xml",
        "html",
        "htm",
        "yaml",
        "yml",
        "toml",
        "ini",
        "cfg",
        "conf",
        "env",
        "properties",
        "log",
        "sql",
        "tex",
        "srt",
        "vtt",
        "py",
        "js",
        "ts",
        "jsx",
        "tsx",
        "java",
        "go",
        "rb",
        "php",
        "cs",
        "c",
        "h",
        "cpp",
        "hpp",
        "rs",
        "kt",
        "swift",
        "sh",
        "bash",
        "ps1",
        "tf",
        "gradle",
    ]
)
TEXT_TYPES = frozenset(
    {
        "application/json",
        "application/xml",
        "application/x-yaml",
        "application/yaml",
        "application/toml",
        "application/sql",
        "application/x-sh",
    }
)
STATUS = {
    "too_large": 413,
    "too_many_characters": 413,
    "too_many_segments": 413,
    "too_many_pages": 413,
    "zip_bomb": 413,
    "page_too_large": 413,
    "unsupported_format": 415,
    "legacy_office": 415,
    "format_disabled": 415,
    "timeout": 504,
    "busy": 503,
    "worker_crashed": 503,
    "worker_limit": 503,
    "internal_error": 500,
    "residual_sensitive_data": 500,
    "verify_failed": 500,
}


@dataclass
class DocumentOutcome:
    scan: ScanOutcome
    kind: str
    info: dict[str, Any]
    text: str
    filename: str
    segments: int
    data: bytes | None = None
    content_type: str | None = None
    extension: str = ""
    verified: bool = False
    notes: list[str] = field(default_factory=list)


def sniff(data: bytes, filename: str, content_type: str | None) -> str:
    if b"%PDF-" in data[:1024]:
        return "pdf"
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "ooxml"
    if data[:4] == b"\xd0\xcf\x11\xe0":
        raise DocumentError(
            "legacy_office", "legacy binary Office files (.doc .xls .ppt) are not supported: save as docx, xlsx or pptx"
        )
    ext = posixpath.splitext(filename.lower())[1].lstrip(".") or filename.lower().lstrip(".")
    kind = (content_type or "").split(";", 1)[0].strip().lower()
    if ext in TEXT_EXTENSIONS or kind.startswith("text/") or kind in TEXT_TYPES:
        return "text"
    raise DocumentError(
        "unsupported_format",
        "supported files are PDF, docx, xlsx, pptx and text formats such as txt, csv, json, md and html",
    )


def clean_filename(raw: str) -> str:
    name = posixpath.basename(raw.replace("\\", "/"))
    name = re.sub(r"[\x00-\x1f\x7f\"<>|?*]+", "", name).strip(". ")
    return name[:128]


def reading_text(
    segments: list[list[Any]],
    edits: dict[int, dict[str, Any]],
    *,
    labelled: bool = False,
    labels: dict[str, str] | None = None,
) -> str:
    """The document as readable text. ``labelled`` puts a column header in front of each table cell
    ("Name: Priya Raman | Email: ..."): used for chat, where the whole request is scanned afterwards."""
    cell_sep = " | " if labelled else "\t"
    parts: list[str] = []
    last_group: str | None = None
    last_row: int | None = None
    for i, (text, ctx, group, row) in enumerate(segments):
        if group == "template":
            continue
        piece = edited_text(text, edits.get(i)).replace("\r\n", "\n").replace("\r", "\n").strip("\n")
        if labelled and ctx:
            piece = ctx + piece
        if group != last_group:
            if parts:
                parts.append("\n\n")
            if group:
                parts.append(f"[{(labels or {}).get(group, group)}]\n")
            last_group, last_row = group, None
        elif parts:
            parts.append(cell_sep if row is not None and row == last_row else "\n")
        parts.append(piece)
        last_row = row
    return "".join(parts).strip()


def _limits(cfg: DocumentSettings) -> dict[str, Any]:
    return {
        "max_segments": cfg.max_segments,
        "max_chars": cfg.max_chars,
        "max_pages": cfg.max_pages,
        "images": cfg.images,
        "pdf_dpi": cfg.pdf_dpi,
        "max_part_bytes": min(cfg.max_bytes * 20, 500_000_000),
        "max_unpacked_bytes": min(cfg.max_bytes * 20, 500_000_000),
    }


async def redact_document(
    pipeline: Pipeline,
    cfg: DocumentSettings,
    runner: WorkerRunner,
    data: bytes,
    filename: str,
    content_type: str | None,
    *,
    mode: Mode | None,
    context_repair: bool | None,
    override: bool,
    want_file: bool,
) -> DocumentOutcome:
    if len(data) > cfg.max_bytes:
        raise DocumentError("too_large", f"the file is larger than {cfg.max_bytes} bytes")
    fmt = sniff(data, filename, content_type)
    try:
        async with asyncio.timeout(cfg.timeout_s):
            return await _run(
                pipeline, cfg, runner, data, filename, content_type, fmt, mode, context_repair, override, want_file
            )
    except TimeoutError:
        raise DocumentError("timeout", f"the document took longer than {cfg.timeout_s} seconds") from None


async def _run(
    pipeline: Pipeline,
    cfg: DocumentSettings,
    runner: WorkerRunner,
    data: bytes,
    filename: str,
    original_type: str | None,
    fmt: str,
    mode: Mode | None,
    context_repair: bool | None,
    override: bool,
    want_file: bool,
) -> DocumentOutcome:
    async with runner.session(fmt, filename, data) as session:
        opened = await session.open(_limits(cfg))
        kind = str(opened.info["kind"])
        if kind not in cfg.formats:
            raise DocumentError("format_disabled", f"{kind} documents are disabled by policy")
        segments = opened.segments
        texts: list[str] = []
        context_len: list[int] = []
        known: dict[tuple[int, str], int] = {}
        slot: list[int | None] = []
        for text, ctx, _group, _row in segments:
            if not has_content(text):
                slot.append(None)
                continue
            key = (len(ctx), ctx + text)
            index = known.get(key)
            if index is None:
                index = known[key] = len(texts)
                texts.append(ctx + text)
                context_len.append(len(ctx))
            slot.append(index)
        if sum(len(t) for t in texts) > cfg.max_chars:
            raise DocumentError("too_many_characters", f"the document has more than {cfg.max_chars} characters")
        stem = posixpath.splitext(filename)[0]
        name_slot = None
        if has_content(stem):  # a file name such as "Priya Raman CV.pdf" is personal data too
            name_slot = len(texts)
            texts.append(stem)
            context_len.append(0)
        outcome = await pipeline.scan(texts, mode=mode, context_repair=context_repair, layers="full", override=override)
        name = "document"
        if name_slot is not None and not outcome.findings[name_slot] and not outcome.blocked:
            name = clean_filename(stem) or "document"
        if outcome.blocked:
            return DocumentOutcome(outcome, kind, opened.info, "", name, len(segments))
        unique: list[dict[str, Any] | None] = []
        for u, found in enumerate(outcome.findings):
            ranges: list[list[Any]] = []
            unmapped = False
            for f in found:
                if f.start is None or f.end is None:
                    unmapped = True
                    continue
                start, end = f.start - context_len[u], f.end - context_len[u]
                if end > 0:
                    ranges.append([max(start, 0), end, f.placeholder])
            if unmapped:  # offsets could not be mapped back: replace the whole text rather than guess
                unique.append({"t": outcome.texts[u] if context_len[u] == 0 else "[REDACTED]"})
            else:
                unique.append({"r": ranges} if ranges else None)
        edits: dict[int, dict[str, Any]] = {}
        for i, which in enumerate(slot):
            chosen = unique[which] if which is not None else None
            if chosen is not None:
                edits[i] = chosen
        # A heading such as "sheet Priya payroll" reuses the decision made for the sheet's own name segment,
        # so the file and the readable text agree and nothing is scanned out of context.
        labels = {}
        for i, (text, _ctx, group, _row) in enumerate(segments):
            if group == "sheet names" and i in edits:
                labels[f"sheet {text}"] = f"sheet {edited_text(text, edits[i])}"
        result = DocumentOutcome(
            outcome, kind, opened.info, reading_text(segments, edits, labels=labels), name, len(segments)
        )
        if want_file:
            output, verify, content_type, extension = await session.apply(edits)
            leftover = await pipeline.residual(verify)
            if leftover:
                raise DocumentError(
                    "residual_sensitive_data",
                    "the redacted file still contains detectable data ("
                    + ", ".join(sorted(leftover))
                    + "), so it was not released",
                )
            if kind == "text":
                extension = posixpath.splitext(filename)[1].lstrip(".").lower() or "txt"
                content_type = (
                    original_type
                    if (original_type or "").lower().startswith(("text/", "application/"))
                    else "text/plain; charset=utf-8"
                )
            result.data, result.content_type, result.extension, result.verified = output, content_type, extension, True
        return result


# --------------------------------------------------------------------------- chat requests
def _decode_base64(raw: str) -> bytes:
    payload = raw.split(",", 1)[1] if raw.startswith("data:") and "," in raw else raw
    try:
        return base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError):
        raise DocumentError("bad_encoding", "an attached file is not valid base64") from None


def _file_parts(body: dict[str, Any], style: str) -> list[tuple[list[Any], int, str, str, bytes]]:
    """(content list, index, filename, mime type, data) of every inline file in a chat request."""
    found: list[tuple[list[Any], int, str, str, bytes]] = []

    def visit(content: Any) -> None:
        if not isinstance(content, list):
            return
        for j, part in enumerate(content):
            if not isinstance(part, dict):
                continue
            if style == "openai" and part.get("type") == "file" and isinstance(part.get("file"), dict):
                spec = part["file"]
                if isinstance(spec.get("file_data"), str):  # a file_id points at a provider-side file: not inspectable
                    raw = spec["file_data"]
                    mime = raw[5:].split(";", 1)[0] if raw.startswith("data:") else ""
                    found.append((content, j, str(spec.get("filename") or ""), mime, raw.encode()))
            elif style == "anthropic" and part.get("type") == "document" and isinstance(part.get("source"), dict):
                source = part["source"]
                if source.get("type") == "base64" and isinstance(source.get("data"), str):
                    found.append(
                        (
                            content,
                            j,
                            str(part.get("title") or ""),
                            str(source.get("media_type") or ""),
                            source["data"].encode(),
                        )
                    )
            elif part.get("type") == "tool_result":
                visit(part.get("content"))

    for message in body.get("messages") or []:
        if isinstance(message, dict):
            visit(message.get("content"))
    return found


async def convert_chat_documents(
    body: dict[str, Any], style: str, cfg: DocumentSettings, runner: WorkerRunner
) -> tuple[int, int]:
    """Replace inline files in a chat request by plain text parts holding their extracted text.

    The text is not redacted here: it joins the request's other text and is scanned with it, so one person is one
    placeholder across the message and the attachment. Returns (files converted, characters). A file that
    cannot be inspected fails the whole request: it is never forwarded as it was.
    """
    parts = _file_parts(body, style)
    total = 0
    for content, index, name, mime, raw in parts:
        encoded = raw.decode("ascii", "replace")
        if len(encoded) * 3 // 4 > cfg.max_bytes + 4:
            raise DocumentError("too_large", f"an attached file is larger than {cfg.max_bytes} bytes")
        data = _decode_base64(encoded)
        fmt = sniff(data, name, mime)
        try:
            async with asyncio.timeout(cfg.timeout_s), runner.session(fmt, name, data) as session:
                opened = await session.open(_limits(cfg))
        except TimeoutError:
            raise DocumentError("timeout", f"an attached file took longer than {cfg.timeout_s} seconds") from None
        kind = str(opened.info["kind"])
        if kind not in cfg.formats:
            raise DocumentError("format_disabled", f"{kind} documents are disabled by policy")
        text = reading_text(opened.segments, {}, labelled=True)
        total += len(text)
        if total > cfg.max_chars:
            raise DocumentError("too_many_characters", f"attached files have more than {cfg.max_chars} characters")
        content[index] = {"type": "text", "text": f"[Attached file: {name or 'file'}]\n{text}"}
    return len(parts), total
