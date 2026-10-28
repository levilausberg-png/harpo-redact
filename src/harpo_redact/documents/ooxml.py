"""Word, Excel and PowerPoint (.docx .xlsx .pptx), edited in place at the XML level.

* Paragraphs are scanned as a whole and edits are written back run by run, so
  formatting survives and a name split across runs is still one name.
* Spreadsheet cells are scanned with their column header as context.
* Everything that carries hidden data is dealt with explicitly: comments and
  tracked-change text are scanned, author names and metadata are blanked,
  thumbnails and custom XML are removed, and embedded objects, macros, external
  links and pivot caches are refused rather than passed through.
* Pictures cannot be inspected: they are refused (default) or replaced by blank images.

This module runs inside the worker process and uses nothing but lxml and the standard library
(plus Pillow for blank images).
"""

from __future__ import annotations

import io
import posixpath
import re
import zipfile
from typing import Any

from lxml import etree

from .common import DocError, Limits, Segment, apply_ranges, has_content, merge_ranges

NS = {
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
    "m": "http://schemas.openxmlformats.org/officeDocument/2006/math",
    "s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    "c": "http://schemas.openxmlformats.org/drawingml/2006/chart",
    "p": "http://schemas.openxmlformats.org/presentationml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "pr": "http://schemas.openxmlformats.org/package/2006/relationships",
    "ct": "http://schemas.openxmlformats.org/package/2006/content-types",
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "tc": "http://schemas.microsoft.com/office/spreadsheetml/2018/threadedcomments",
    "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
}
XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"


def q(prefix: str, local: str) -> str:
    return f"{{{NS[prefix]}}}{local}"


_MAIN_TYPES = {
    "wordprocessingml.document.main+xml": ("docx", "w", "document"),
    "wordprocessingml.template.main+xml": ("docx", "w", "document"),
    "spreadsheetml.sheet.main+xml": ("xlsx", "s", "workbook"),
    "spreadsheetml.template.main+xml": ("xlsx", "s", "workbook"),
    "presentationml.presentation.main+xml": ("pptx", "p", "presentation"),
    "presentationml.slideshow.main+xml": ("pptx", "p", "presentation"),
    "presentationml.template.main+xml": ("pptx", "p", "presentation"),
}
CONTENT_TYPES = {
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}
_RASTER = {"png": "PNG", "jpg": "JPEG", "jpeg": "JPEG", "gif": "GIF", "bmp": "BMP", "tif": "TIFF", "tiff": "TIFF"}
_FONTS = {"odttf", "ttf", "otf", "fntdata", "obfuscated"}
_REMOVE = re.compile(
    r"^(docProps/thumbnail\.\w+|docProps/custom\.xml|customXml/.*|.*printerSettings\d*\.bin|word/people\.xml)$"
)
_REJECT = (
    (re.compile(r"/embeddings/|/activeX/|/oleObject|/ctrlProps/"), "embedded_objects", "embedded objects"),
    (re.compile(r"/externalLinks/"), "external_links", "links to external workbooks"),
    (re.compile(r"(^|/)pivotCache/"), "pivot_cache", "pivot tables, which keep a copy of their source data"),
)


# --------------------------------------------------------------------------- package
class Package:
    def __init__(self, data: bytes, limits: Limits) -> None:
        self.limits = limits
        self.order: list[str] = []
        self.blobs: dict[str, bytes] = {}
        self.trees: dict[str, Any] = {}
        if data[:4] == b"\xd0\xcf\x11\xe0":
            raise DocError("legacy_office", "legacy binary or encrypted Office files are not supported")
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
            infos = archive.infolist()
        except zipfile.BadZipFile:
            raise DocError("corrupt", "the file is not a valid Office document") from None
        if len(infos) > limits.max_parts:
            raise DocError("zip_bomb", "the file has too many parts")
        total = 0
        for info in infos:
            name = info.filename
            if name.endswith("/"):
                continue
            if info.flag_bits & 0x1:
                raise DocError("encrypted", "the file is encrypted")
            if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise DocError("corrupt", "unsupported compression method")
            if name.startswith("/") or "\\" in name or "\x00" in name or ".." in name.split("/") or len(name) > 255:
                raise DocError("unsafe_path", "the file contains an unsafe part name")
            if name in self.blobs:
                raise DocError("corrupt", "the file contains duplicate parts")
            total += info.file_size
            if (
                info.file_size > limits.max_part_bytes
                or total > limits.max_unpacked_bytes
                or (info.file_size > 1_000_000 and info.compress_size and info.file_size / info.compress_size > 500)
            ):
                raise DocError("zip_bomb", "the file expands to an unreasonable size")
            try:
                with archive.open(info) as handle:
                    blob = handle.read(limits.max_part_bytes + 1)
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError, OSError):
                raise DocError("corrupt", "a part of the file cannot be read") from None
            if len(blob) > limits.max_part_bytes:
                raise DocError("zip_bomb", "the file expands to an unreasonable size")
            self.order.append(name)
            self.blobs[name] = blob
        if "[Content_Types].xml" not in self.blobs:
            raise DocError("not_office", "the file is a zip archive but not an Office document")

    @staticmethod
    def is_xml(name: str) -> bool:
        return name.endswith((".xml", ".rels", ".vml"))

    def xml(self, name: str) -> Any:
        tree = self.trees.get(name)
        if tree is None:
            blob = self.blobs[name]
            if b"<!DOCTYPE" in blob or b"<!ENTITY" in blob:
                raise DocError("unsupported_xml", "document type declarations are not allowed")
            parser = etree.XMLParser(
                resolve_entities=False, no_network=True, load_dtd=False, dtd_validation=False, huge_tree=False
            )
            try:
                tree = etree.fromstring(blob, parser)
            except etree.XMLSyntaxError:
                raise DocError("corrupt", "a part of the file is not valid XML") from None
            self.trees[name] = tree
        return tree

    def remove(self, name: str) -> None:
        if name not in self.blobs:
            return
        self.order.remove(name)
        del self.blobs[name]
        self.trees.pop(name, None)
        for rels in [n for n in self.order if n.endswith(".rels")]:
            source = rels_source(rels)
            tree = self.xml(rels)
            for rel in list(tree):
                if rel.get("TargetMode") != "External" and resolve(source, rel.get("Target", "")) == name:
                    tree.remove(rel)
        types = self.xml("[Content_Types].xml")
        for entry in list(types):
            if entry.tag == q("ct", "Override") and entry.get("PartName", "").lstrip("/") == name:
                types.remove(entry)

    def serialize(self) -> bytes:
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for name in ["[Content_Types].xml", *[n for n in self.order if n != "[Content_Types].xml"]]:
                tree = self.trees.get(name)
                blob = (
                    etree.tostring(tree, xml_declaration=True, encoding="UTF-8", standalone=True)
                    if tree is not None
                    else self.blobs[name]
                )
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))  # no timestamps
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o600 << 16
                archive.writestr(info, blob)
        return out.getvalue()


def rels_source(rels: str) -> str:
    folder, filename = posixpath.split(rels)
    stem = filename[: -len(".rels")]
    base = posixpath.dirname(folder)
    return posixpath.join(base, stem) if stem else ""


def resolve(source: str, target: str) -> str:
    if target.startswith("/"):
        return posixpath.normpath(target.lstrip("/"))
    return posixpath.normpath(posixpath.join(posixpath.dirname(source), target))


# --------------------------------------------------------------------------- text writers
class Writer:
    """One segment's text, spread over XML text elements. ``None`` pieces are separators."""

    def __init__(self, pieces: list[tuple[Any, str]]) -> None:
        self.pieces = pieces

    @property
    def text(self) -> str:
        return "".join(t for _, t in self.pieces)

    def apply(self, edit: dict[str, Any]) -> None:
        editable = [i for i, (el, _) in enumerate(self.pieces) if el is not None]
        if not editable:
            return
        if "t" in edit:
            for n, i in enumerate(editable):
                self._set(self.pieces[i][0], str(edit["t"]) if n == 0 else "")
            return
        spans, pos = [], 0
        for _, t in self.pieces:
            spans.append((pos, pos + len(t)))
            pos += len(t)
        keep = [[True] * len(t) for _, t in self.pieces]
        inserts: list[dict[int, str]] = [{} for _ in self.pieces]
        for start, end, placeholder in sorted(edit["r"], key=lambda r: (r[0], r[1])):
            anchor: tuple[int, int] | None = None
            for i in editable:
                a, b = spans[i]
                lo, hi = max(start, a), min(end, b)
                if lo < hi:
                    for k in range(lo - a, hi - a):
                        keep[i][k] = False
                    if anchor is None:
                        anchor = (i, lo - a)
            if anchor is None:  # the range covers only separators: place it before the next text
                nxt = next((i for i in editable if spans[i][1] > start), editable[-1])
                anchor = (nxt, max(0, min(start - spans[nxt][0], len(self.pieces[nxt][1]))))
            inserts[anchor[0]][anchor[1]] = inserts[anchor[0]].get(anchor[1], "") + str(placeholder)
        for i in editable:
            text = self.pieces[i][1]
            out: list[str] = []
            for k, ch in enumerate(text):
                out.append(inserts[i].get(k, ""))
                if keep[i][k]:
                    out.append(ch)
            out.append(inserts[i].get(len(text), ""))
            self._set(self.pieces[i][0], "".join(out))

    @staticmethod
    def _set(el: Any, text: str) -> None:
        el.text = text
        if el.tag in (q("w", "t"), q("w", "delText"), q("s", "t")) and text != text.strip():
            el.set(XML_SPACE, "preserve")


class AttrWriter:
    def __init__(self, el: Any, attr: str, text: str) -> None:
        self.el, self.attr, self.text = el, attr, text

    def apply(self, edit: dict[str, Any]) -> None:
        self.el.set(self.attr, str(edit["t"]) if "t" in edit else apply_ranges(self.text, edit["r"]))


class DropWriter:
    """Anything found in this element means the whole element goes (a formula, a defined name)."""

    def __init__(self, el: Any, also: list[Any] | None = None) -> None:
        self.el, self.also = el, also or []

    def apply(self, edit: dict[str, Any]) -> None:
        for el in [self.el, *self.also]:
            if el.getparent() is not None:
                el.getparent().remove(el)


class LinkWriter:
    def __init__(self, rel: Any) -> None:
        self.rel = rel

    def apply(self, edit: dict[str, Any]) -> None:
        self.rel.set("Target", "https://redacted.invalid/")


class NumericCellWriter:
    """A number that turned out to be an identifier becomes a text cell holding the placeholder."""

    def __init__(self, cell: Any, value: Any) -> None:
        self.cell, self.value = cell, value

    def apply(self, edit: dict[str, Any]) -> None:
        text = str(edit["t"]) if "t" in edit else apply_ranges(self.value.text or "", edit["r"])
        for child in list(self.cell):
            if child.tag in (q("s", "f"), q("s", "v"), q("s", "is")):
                self.cell.remove(child)
        self.cell.set("t", "inlineStr")
        holder = etree.Element(q("s", "is"))
        etree.SubElement(holder, q("s", "t")).text = text
        self.cell.insert(0, holder)


class SharedString:
    """A shared string used under several headers: the union of all edits is applied once."""

    def __init__(self, writer: Writer) -> None:
        self.writer, self.edits = writer, []  # type: Writer, list[dict[str, Any]]

    def add(self, edit: dict[str, Any]) -> None:
        self.edits.append(edit)

    def flush(self) -> None:
        if not self.edits:
            return
        full = next((e for e in self.edits if "t" in e), None)
        self.writer.apply(full or {"r": merge_ranges([e["r"] for e in self.edits])})


class SharedRef:
    def __init__(self, shared: SharedString) -> None:
        self.shared = shared

    def apply(self, edit: dict[str, Any]) -> None:
        self.shared.add(edit)


class SheetNameWriter:
    def __init__(self, sheet: Any, taken: set[str]) -> None:
        self.sheet, self.taken = sheet, taken

    def apply(self, edit: dict[str, Any]) -> None:  # brackets are illegal in sheet names: use a plain name
        n = 1
        while f"Redacted{n}" in self.taken:
            n += 1
        self.taken.add(f"Redacted{n}")
        self.sheet.set("name", f"Redacted{n}")


# --------------------------------------------------------------------------- paragraphs
_WORD_TEXT = frozenset({q("w", "t"), q("w", "delText"), q("m", "t")})
_WORD_SEP = {q("w", "tab"): " ", q("w", "br"): "\n", q("w", "cr"): "\n", q("w", "noBreakHyphen"): "-"}
_DRAW_TEXT = frozenset({q("a", "t")})
_DRAW_SEP = {q("a", "br"): "\n"}


def own_pieces(para: Any, text_tags: frozenset[str], sep: dict[str, str]) -> list[tuple[Any, str]]:
    """Text elements of one paragraph in order, not descending into nested paragraphs (text boxes)."""
    pieces: list[tuple[Any, str]] = []
    para_tag = para.tag
    stack = [iter(para)]
    while stack:
        for el in stack[-1]:
            tag = el.tag
            if not isinstance(tag, str) or tag == para_tag or tag == q("w", "instrText"):
                continue
            if tag in text_tags:
                pieces.append((el, el.text or ""))
            elif tag in sep:
                pieces.append((None, sep[tag]))
            else:
                stack.append(iter(el))
                break
        else:
            stack.pop()
    return pieces


_ATTR_ANY = frozenset({"descr", "alt", "string", "tooltip"})
_SINGLE_TEXT = (
    (q("p", "text"), "comments"),
    (q("tc", "text"), "comments"),
    (q("dc", "title"), "properties"),
    (q("dc", "subject"), "properties"),
    (q("dc", "description"), "properties"),
    (q("cp", "keywords"), "properties"),
    (q("cp", "category"), "properties"),
    (q("w", "instrText"), "fields"),
)
_SCRUB_ATTRS = {
    q("w", "author"): "Author",
    q("w", "initials"): "",
    "initials": "",
    "displayName": "Author",
    "userId": "",
    "providerId": "",
    "lastModifiedBy": "Author",
}
_SCRUB_TEXT = (
    q("dc", "creator"),
    q("cp", "lastModifiedBy"),
    q("ep", "Company"),
    q("ep", "Manager"),
    q("ep", "HyperlinkBase"),
    q("ep", "Template"),
)


# Attribute values that are structure, not text a person wrote: revision ids, colours, sizes, GUIDs, namespaces.
_STRUCTURAL = re.compile(r"^(?:[0-9A-Fa-f]+|-?\d+(?:\.\d+)?|\{?[0-9A-Fa-f-]{36}\}?|(?:urn|https?|file):\S*schemas\S*)$")


def _numeric(name: str) -> tuple[int, str]:
    m = re.search(r"(\d+)\.xml$", name)
    return (int(m.group(1)) if m else 0, name)


def _group(name: str) -> str:
    base = posixpath.basename(name)
    if re.match(r"(slideLayout|slideMaster|notesMaster|handoutMaster)\d*\.xml$", base):
        return "template"  # boilerplate: scrubbed in the file, left out of the readable text
    m = re.match(r"(slide|notesSlide|chart|drawing|header|footer|comments?|footnotes|endnotes)(\d*)", base)
    if base == "document.xml" or not m:
        return ""
    kind, number = m.groups()
    return {"slide": f"slide {number}", "notesSlide": f"notes {number}"}.get(kind, f"{kind} {number}".strip())


def _part_rank(name: str) -> tuple[int, int, str]:
    base = posixpath.basename(name)
    first = 0 if base in ("document.xml", "workbook.xml") else 1
    return (first, *_numeric(name))


def _col(ref: str) -> str:
    return re.sub(r"\d", "", ref)


def _row(ref: str) -> int:
    m = re.search(r"\d+", ref)
    return int(m.group()) if m else 0


# --------------------------------------------------------------------------- the document
class OoxmlDocument:
    def __init__(self, data: bytes, name: str, limits: Limits, *, verify: bool = False) -> None:
        self.limits = limits
        self.name = name
        self.pkg = Package(data, limits)
        self.kind = self._detect()
        self.info: dict[str, Any] = {"kind": self.kind}
        self._entries: list[tuple[Segment, Any]] = []
        self._shared: list[SharedString] = []
        self._images: list[str] = []
        self._check_parts(verify)
        self._collect()
        if len(self._entries) > limits.max_segments:
            raise DocError("too_many_segments", f"the document has more than {limits.max_segments} text pieces")
        if sum(len(s.text) for s, _ in self._entries) > limits.max_chars:
            raise DocError("too_many_characters", f"the document has more than {limits.max_chars} characters")
        self.info["images"] = len(self._images)

    # ---- structure
    def _detect(self) -> str:
        types = self.pkg.xml("[Content_Types].xml")
        found: tuple[str, str, str] | None = None
        for entry in types:
            content_type = entry.get("ContentType", "")
            if "macroEnabled" in content_type or "vbaProject" in content_type:
                raise DocError("macros", "macro-enabled documents are not supported")
            for suffix, value in _MAIN_TYPES.items():
                if content_type.endswith(suffix) and entry.tag == q("ct", "Override"):
                    found = value
                    main = entry.get("PartName", "").lstrip("/")
        if found is None:
            raise DocError("not_office", "the file is not a Word, Excel or PowerPoint document")
        kind, prefix, local = found
        root = self.pkg.xml(main)
        if root.tag != q(prefix, local):
            raise DocError("strict_ooxml", "this Office file format variant is not supported")
        return kind

    def _check_parts(self, verify: bool) -> None:
        for name in list(self.pkg.order):
            if _REMOVE.match(name):
                continue
            for pattern, code, what in _REJECT:
                if pattern.search(name):
                    raise DocError(code, f"the document contains {what}, which cannot be inspected")
            if Package.is_xml(name):
                continue
            ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
            if ext in _RASTER:
                self._images.append(name)
            elif ext in _FONTS:
                continue
            elif ext in ("emf", "wmf", "svg", "wdp", "jxr", "webp", "heic"):
                raise DocError(
                    "unsupported_image", f"the document contains a .{ext} picture, which cannot be inspected"
                )
            else:
                raise DocError("unsupported_part", "the document contains a part that cannot be inspected")
        if self._images and not verify and self.limits.images == "block":
            raise DocError(
                "images_present", f"the document contains {len(self._images)} picture(s) that cannot be inspected"
            )

    # ---- collecting text
    def _add(self, segment: Segment, writer: Any) -> None:
        self._entries.append((segment, writer))

    def _collect(self) -> None:
        names = sorted((n for n in self.pkg.order if Package.is_xml(n) and not n.endswith(".rels")), key=_part_rank)
        skip = {"[Content_Types].xml"}
        for name in names:
            if name in skip or _REMOVE.match(name):
                continue
            if self.kind == "xlsx" and (name == "xl/sharedStrings.xml" or name.startswith("xl/worksheets/sheet")):
                continue
            self._collect_part(name)
        for name in sorted((n for n in self.pkg.order if n.endswith(".rels")), key=_part_rank):
            for rel in self.pkg.xml(name):
                target = rel.get("Target", "")
                if rel.get("TargetMode") == "External" and target and has_content(target):
                    self._add(Segment(target, group="links"), LinkWriter(rel))
        if self.kind == "xlsx":
            self._collect_xlsx()

    def _collect_part(self, name: str) -> None:
        root = self.pkg.xml(name)
        group = _group(name)
        for para in root.iter(q("w", "p")):
            pieces = own_pieces(para, _WORD_TEXT, _WORD_SEP)
            writer = Writer(pieces)
            if has_content(writer.text):
                self._add(Segment(writer.text, group=group), writer)
        for para in root.iter(q("a", "p")):
            pieces = own_pieces(para, _DRAW_TEXT, _DRAW_SEP)
            writer = Writer(pieces)
            if has_content(writer.text):
                self._add(Segment(writer.text, group=group), writer)
        for tag, label in _SINGLE_TEXT:
            for el in root.iter(tag):
                if el.text and has_content(el.text):
                    self._add(Segment(el.text, group=label), Writer([(el, el.text)]))
        for el in root.iter(q("c", "v")):
            if el.text and any(c.isalpha() for c in el.text):
                self._add(Segment(el.text, group="charts"), Writer([(el, el.text)]))
        for el in root.iter():
            if not isinstance(el.tag, str):
                continue
            local = etree.QName(el).localname
            for attr in ("descr", "title", "name") if local in ("cNvPr", "docPr") else ():
                value = el.get(attr, "")
                # Shape names are mostly generated labels ("Header Placeholder 1"); only look at ones that
                # carry structured data. Alt text and titles are written by people and are always scanned.
                if has_content(value) and (attr != "name" or re.search(r"@|\d{6,}", value)):
                    self._add(Segment(value, group="shapes"), AttrWriter(el, attr, value))
            for attr in el.attrib:
                if etree.QName(attr).localname in _ATTR_ANY and has_content(el.get(attr, "")):
                    self._add(Segment(el.get(attr), group="shapes"), AttrWriter(el, attr, el.get(attr)))
            if el.tag == q("w", "fldSimple") and has_content(el.get(q("w", "instr"), "")):
                self._add(
                    Segment(el.get(q("w", "instr")), group="fields"),
                    AttrWriter(el, q("w", "instr"), el.get(q("w", "instr"))),
                )
            if el.tag in (q("w", "docVar"), q("w", "alias"), q("w", "tag")) and has_content(el.get(q("w", "val"), "")):
                self._add(
                    Segment(el.get(q("w", "val")), group="properties"),
                    AttrWriter(el, q("w", "val"), el.get(q("w", "val"))),
                )
        if self.kind == "xlsx" and name.startswith("xl/comments"):
            for comment in root.iter(q("s", "comment")):
                pieces = [(t, t.text or "") for t in comment.iter(q("s", "t"))]
                writer = Writer(pieces)
                if has_content(writer.text):
                    self._add(Segment(writer.text, group="comments"), writer)
        if self.kind == "xlsx" and name.startswith("xl/tables/"):
            for el in root.iter():
                if (
                    isinstance(el.tag, str)
                    and etree.QName(el).localname == "tableColumn"
                    and has_content(el.get("name", ""))
                ):
                    # must stay equal to the header cell, which is redacted the same way
                    self._add(Segment(el.get("name"), group="tables"), AttrWriter(el, "name", el.get("name")))

    # ---- spreadsheets
    def _collect_xlsx(self) -> None:
        workbook = self.pkg.xml("xl/workbook.xml")
        rels = {
            r.get("Id"): resolve("xl/workbook.xml", r.get("Target", ""))
            for r in self.pkg.xml("xl/_rels/workbook.xml.rels")
        }
        sheets = [(s.get("name", ""), rels.get(s.get(q("r", "id")), ""), s) for s in workbook.iter(q("s", "sheet"))]
        taken = {n for n, _, _ in sheets}
        for name, _, el in sheets:
            if has_content(name):
                self._add(Segment(name, group="sheet names"), SheetNameWriter(el, taken))
        for el in workbook.iter(q("s", "definedName")):
            if el.text and ('"' in el.text or "@" in el.text):
                self._add(Segment(el.text, group="names"), DropWriter(el))
        strings: list[Writer] = []
        if "xl/sharedStrings.xml" in self.pkg.blobs:
            for si in self.pkg.xml("xl/sharedStrings.xml").iter(q("s", "si")):
                for phonetic in list(si.iter(q("s", "rPh"))) + list(si.iter(q("s", "phoneticPr"))):
                    phonetic.getparent().remove(phonetic)
                strings.append(Writer([(t, t.text or "") for t in si.iter(q("s", "t"))]))
        shared = [SharedString(w) for w in strings]
        self._shared = shared
        used: set[int] = set()
        for sheet_name, part, _ in sheets:
            if part not in self.pkg.blobs:
                continue
            self._sheet(sheet_name, self.pkg.xml(part), strings, shared, used)
        for i, writer in enumerate(strings):
            if i not in used and has_content(writer.text):
                self._add(Segment(writer.text, group="unreferenced"), SharedRef(shared[i]))

    def _sheet(self, label: str, root: Any, strings: list[Writer], shared: list[SharedString], used: set[int]) -> None:
        cells = [c for c in root.iter(q("s", "c"))]
        header: dict[str, str] = {}
        first_row = min((_row(c.get("r", "")) for c in cells), default=0)
        top = [c for c in cells if _row(c.get("r", "")) == first_row]
        kinds = [c.get("t", "n") for c in top if c.find(q("s", "v")) is not None or c.find(q("s", "is")) is not None]
        if kinds and all(k in ("s", "inlineStr", "str") for k in kinds):
            for c in top:
                text = self._cell_text(c, strings)
                if text and has_content(text):
                    header[_col(c.get("r", ""))] = text.strip()
        group = f"sheet {label}"
        for c in cells:
            ref, kind = c.get("r", ""), c.get("t", "n")
            row = _row(ref)
            label_text = header.get(_col(ref), "") if row != first_row else ""
            ctx = f"{label_text}: " if label_text else ""
            value = c.find(q("s", "v"))
            formula = c.find(q("s", "f"))
            if formula is not None and formula.text and ('"' in formula.text or "@" in formula.text):
                twins = [
                    f
                    for f in root.iter(q("s", "f"))
                    if f is not formula and f.get("si") == formula.get("si") and formula.get("t") == "shared"
                ]
                self._add(Segment(formula.text, group=group), DropWriter(formula, twins))
            if kind == "s" and value is not None and (value.text or "").strip().isdigit():
                index = int(value.text.strip())
                if index < len(strings) and has_content(strings[index].text):
                    used.add(index)
                    self._add(Segment(strings[index].text, ctx=ctx, group=group, row=row), SharedRef(shared[index]))
            elif kind == "inlineStr":
                inline = c.find(q("s", "is"))
                if inline is not None:
                    writer = Writer([(t, t.text or "") for t in inline.iter(q("s", "t"))])
                    if has_content(writer.text):
                        self._add(Segment(writer.text, ctx=ctx, group=group, row=row), writer)
            elif kind == "str" and value is not None and value.text and has_content(value.text):
                self._add(Segment(value.text, ctx=ctx, group=group, row=row), Writer([(value, value.text)]))
            elif kind in ("n",) and value is not None and value.text and len(value.text.strip()) >= 7:
                self._add(Segment(value.text.strip(), ctx=ctx, group=group, row=row), NumericCellWriter(c, value))

    @staticmethod
    def _cell_text(cell: Any, strings: list[Writer]) -> str:
        kind, value = cell.get("t", "n"), cell.find(q("s", "v"))
        if kind == "s" and value is not None and (value.text or "").strip().isdigit():
            index = int(value.text.strip())
            return strings[index].text if index < len(strings) else ""
        if kind == "inlineStr" and cell.find(q("s", "is")) is not None:
            return "".join(t.text or "" for t in cell.find(q("s", "is")).iter(q("s", "t")))
        return (value.text or "") if kind == "str" and value is not None else ""

    # ---- the interface the worker uses
    def segments(self) -> list[Segment]:
        return [s for s, _ in self._entries]

    def apply(self, edits: dict[int, dict[str, Any]]) -> bytes:
        for index, edit in edits.items():
            segment, writer = self._entries[index]
            if "r" in edit:  # never trust offsets from outside the segment
                edit = {
                    "r": [
                        [max(0, min(int(a), len(segment.text))), max(0, min(int(b), len(segment.text))), p]
                        for a, b, p in edit["r"]
                    ]
                }
            writer.apply(edit)
        for shared in self._shared:
            shared.flush()
        self._scrub()
        for name in [n for n in self.pkg.order if _REMOVE.match(n)]:
            self.pkg.remove(name)
        if self._images:  # only reachable when pictures are blanked, not refused
            for name in self._images:
                self.pkg.blobs[name] = _blank_image(name)
        return self.pkg.serialize()

    def _scrub(self) -> None:
        for name in self.pkg.order:
            if not Package.is_xml(name) or name.endswith(".rels"):
                continue
            root = self.pkg.xml(name)
            for el in root.iter():
                if not isinstance(el.tag, str):
                    continue
                for attr, value in _SCRUB_ATTRS.items():
                    if attr in el.attrib:
                        el.set(attr, value)
                if etree.QName(el).localname in ("cmAuthor", "author") and "name" in el.attrib:
                    el.set("name", "Author")
                if el.tag in _SCRUB_TEXT:
                    el.text = ""
                if el.tag in (q("ep", "TitlesOfParts"), q("ep", "HeadingPairs")) or el.tag == q(
                    "w", "attachedTemplate"
                ):
                    el.getparent().remove(el)
            if name.startswith("xl/comments"):
                for author in root.iter(q("s", "author")):
                    author.text = "Author"
        for name in [n for n in self.pkg.order if n.endswith(".rels")]:
            for rel in self.pkg.xml(name):
                if rel.get("Type", "").endswith("/attachedTemplate"):
                    rel.getparent().remove(rel)
                elif rel.get("TargetMode") == "External" and rel.get("Target", "").lower().startswith("file:"):
                    rel.set("Target", "file:///redacted")

    def verify_strings(self, output: bytes) -> list[str]:
        again = OoxmlDocument(output, self.name, self.limits, verify=True)
        found = {s.ctx + s.text for s in again.segments()}
        for name in again.pkg.order:
            if not Package.is_xml(name):
                continue
            for el in again.pkg.xml(name).iter():
                if not isinstance(el.tag, str):
                    continue
                for value in (el.text, el.tail):  # text nodes: everything
                    if value and len(value.strip()) >= 3:
                        found.add(value.strip())
                for value in el.attrib.values():  # attributes: not identifiers, colours, numbers or namespaces
                    if len(value) >= 5 and not _STRUCTURAL.match(value.strip()):
                        found.add(value.strip())
        return sorted(found)


def _blank_image(name: str) -> bytes:
    from PIL import Image

    out = io.BytesIO()
    Image.new("RGB", (1, 1), (255, 255, 255)).save(out, _RASTER[name.rsplit(".", 1)[-1].lower()])
    return out.getvalue()
