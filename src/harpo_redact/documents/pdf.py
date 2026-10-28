"""PDF redaction by rasterising.

Every page is rendered, the characters that matched are painted over, and the pages are
written into a new image-only PDF. The original text, fonts, annotations, form fields,
attachments and metadata do not carry over, so nothing sits under a black box.

Pictures and pages with no text layer (scans, outlined text) cannot be inspected: they
are refused by default. With ``images: blank`` they are removed or blanked instead.
"""

from __future__ import annotations

import io
from typing import Any

from .common import DocError, Limits, Segment, has_content

MAX_OBJECTS = 200_000


def _utf16_index(text: str) -> list[int]:
    """PDFium indexes text in UTF-16 units; Python indexes code points."""
    out, pos = [], 0
    for ch in text:
        out.append(pos)
        pos += 2 if ord(ch) > 0xFFFF else 1
    return out


def _group(boxes: list[tuple[float, float, float, float]]) -> list[tuple[float, float, float, float]]:
    rects: list[tuple[float, float, float, float]] = []
    for left, bottom, right, top in boxes:
        height = top - bottom
        if rects:
            cl, cb, cr, ct = rects[-1]
            overlap = min(top, ct) - max(bottom, cb)
            if overlap > 0.5 * min(height, ct - cb) and cl - 3 * height <= left <= cr + 3 * height:
                rects[-1] = (min(cl, left), min(cb, bottom), max(cr, right), max(ct, top))
                continue
        rects.append((left, bottom, right, top))
    return rects


def _pdf_from_jpegs(pages: list[tuple[bytes, int, int, float, float]]) -> bytes:
    """A minimal PDF with one full-page JPEG per page and no metadata."""
    objects: dict[int, bytes] = {}
    kids: list[str] = []
    next_id = 3
    for jpeg, wpx, hpx, wpt, hpt in pages:
        page_id, content_id, image_id = next_id, next_id + 1, next_id + 2
        next_id += 3
        kids.append(f"{page_id} 0 R")
        content = f"q {wpt:.2f} 0 0 {hpt:.2f} 0 0 cm /Im0 Do Q".encode()
        objects[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {wpt:.2f} {hpt:.2f}] "
            f"/Resources << /XObject << /Im0 {image_id} 0 R >> >> /Contents {content_id} 0 R >>"
        ).encode()
        objects[content_id] = f"<< /Length {len(content)} >>\nstream\n".encode() + content + b"\nendstream"
        objects[image_id] = (
            (
                f"<< /Type /XObject /Subtype /Image /Width {wpx} /Height {hpx} /ColorSpace /DeviceRGB "
                f"/BitsPerComponent 8 /Filter /DCTDecode /Length {len(jpeg)} >>\nstream\n"
            ).encode()
            + jpeg
            + b"\nendstream"
        )
    objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objects[2] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(pages)} >>".encode()
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}
    for number in sorted(objects):
        offsets[number] = len(out)
        out += f"{number} 0 obj\n".encode() + objects[number] + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for number in sorted(objects):
        out += f"{offsets[number]:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


class PdfDocument:
    kind = "pdf"
    content_type = "application/pdf"
    extension = "pdf"

    def __init__(self, data: bytes, name: str, limits: Limits, *, verify: bool = False) -> None:
        import pypdfium2 as pdfium
        import pypdfium2.raw as raw

        self.limits = limits
        try:
            self.pdf = pdfium.PdfDocument(data)
        except pdfium.PdfiumError as exc:
            password = "password" in str(exc).lower()
            raise DocError(
                "encrypted" if password else "corrupt",
                "the PDF is encrypted" if password else "the file is not a valid PDF",
            ) from None
        count = len(self.pdf)
        if count == 0:
            raise DocError("corrupt", "the PDF has no pages")
        if count > limits.max_pages:
            raise DocError("too_many_pages", f"the PDF has more than {limits.max_pages} pages")
        self._segment_pages: list[int] = []
        self._segments: list[Segment] = []
        self._strip: dict[int, bool] = {}  # pages whose pictures are removed
        self._blank: set[int] = set()  # pages that cannot be inspected and are replaced by white pages
        picture_pages: list[int] = []
        nested_pages: list[int] = []
        uninspectable: list[int] = []
        annotations = 0
        total_chars = 0
        for i in range(count):
            page = self.pdf[i]
            textpage = page.get_textpage()
            chars = textpage.count_chars()
            text = textpage.get_text_range() if chars else ""
            total_chars += len(text)
            if total_chars > limits.max_chars:
                raise DocError("too_many_characters", f"the PDF has more than {limits.max_chars} characters")
            annotations += raw.FPDFPage_GetAnnotCount(page.raw)
            objects = top_images = nested_images = 0
            for obj in page.get_objects(max_depth=15):
                objects += 1
                if objects > MAX_OBJECTS:
                    raise DocError("too_complex", "a page is too complex to inspect")
                if obj.type == raw.FPDF_PAGEOBJ_IMAGE:
                    if obj.level == 0:
                        top_images += 1
                    else:
                        nested_images += 1
            if top_images or nested_images:
                picture_pages.append(i + 1)
            if nested_images:
                nested_pages.append(i + 1)
            if top_images:
                self._strip[i] = True
            if chars == 0 and objects > 0 and not (top_images or nested_images):
                uninspectable.append(i + 1)
                self._blank.add(i)
            if chars == 0 and (top_images or nested_images):
                self._blank.add(i)  # a scan: once its pictures are removed nothing is left
            if has_content(text):
                self._segment_pages.append(i)
                self._segments.append(Segment(text, group=f"page {i + 1}"))
        if not verify:
            if picture_pages and limits.images == "block":
                raise DocError(
                    "images_present",
                    f"the PDF contains pictures on page(s) {_pages(picture_pages)} that cannot be inspected",
                )
            if nested_pages:
                raise DocError(
                    "images_nested", f"pictures inside page content on page(s) {_pages(nested_pages)} cannot be removed"
                )
            if uninspectable and limits.images == "block":
                raise DocError("uninspectable_pages", f"page(s) {_pages(uninspectable)} have content but no text layer")
        self.info: dict[str, Any] = {
            "kind": "pdf",
            "pages": count,
            "images": len(picture_pages),
            "annotations": annotations,
            "blanked_pages": sorted(p + 1 for p in self._blank),
        }

    def segments(self) -> list[Segment]:
        return list(self._segments)

    def apply(self, edits: dict[int, dict[str, Any]]) -> bytes:
        import pypdfium2.raw as raw
        from PIL import ImageDraw

        per_page = {self._segment_pages[i]: edit for i, edit in edits.items()}
        rendered: list[tuple[bytes, int, int, float, float]] = []
        for i in range(len(self.pdf)):
            page = self.pdf[i]
            width, height = page.get_size()
            scale = self.limits.pdf_dpi / 72
            if width * scale * height * scale > self.limits.pdf_max_pixels:
                scale = (self.limits.pdf_max_pixels / (width * height)) ** 0.5
                if scale * 72 < 50:
                    raise DocError("page_too_large", "a page is too large to render")
            if self._strip.get(i):
                for obj in [o for o in page.get_objects(max_depth=0) if o.type == raw.FPDF_PAGEOBJ_IMAGE]:
                    page.remove_obj(obj)
                page.gen_content()
            bitmap = page.render(scale=scale, may_draw_forms=False, draw_annots=False)
            image = bitmap.to_pil().convert("RGB")
            draw = ImageDraw.Draw(image)
            boxes: list[tuple[float, float, float, float]] = []
            if i in self._blank:
                draw.rectangle((0, 0, image.width, image.height), fill=(255, 255, 255))
            elif i in per_page:
                edit = per_page[i]
                if "t" in edit:  # offsets unknown: black out the page
                    boxes = [(0, 0, image.width, image.height)]
                    draw.rectangle(boxes[0], fill=(0, 0, 0))
                else:
                    boxes = self._paint(page, bitmap, draw, edit["r"], scale)
            buffer = io.BytesIO()
            image.save(buffer, "JPEG", quality=self.limits.pdf_quality, optimize=True)
            _verify_opaque(buffer.getvalue(), boxes, i + 1)
            rendered.append((buffer.getvalue(), image.width, image.height, image.width / scale, image.height / scale))
        return _pdf_from_jpegs(rendered)

    def _paint(
        self, page: Any, bitmap: Any, draw: Any, ranges: list[list[Any]], scale: float
    ) -> list[tuple[float, float, float, float]]:
        painted: list[tuple[float, float, float, float]] = []
        textpage = page.get_textpage()
        text = textpage.get_text_range()
        units = _utf16_index(text)
        convert = bitmap.get_posconv(page)
        spans: list[tuple[int, int]] = []
        for start, end, _ in sorted(ranges, key=lambda r: (r[0], r[1])):
            start, end = max(0, int(start)), min(len(text), int(end))
            if spans and not text[spans[-1][1] : start].strip():  # only whitespace between: one box, no visible gap
                spans[-1] = (spans[-1][0], max(spans[-1][1], end))
            else:
                spans.append((start, end))
        for start, end in spans:
            boxes = []
            for k in range(start, end):
                if text[k].isspace():
                    continue  # a space has a sliver of a box that would split the run; the union covers the gap
                left, bottom, right, top = textpage.get_charbox(units[k])
                if right > left and top - bottom >= 0.5:
                    boxes.append((left, bottom, right, top))
            for left, bottom, right, top in _group(boxes):
                corners = [
                    convert.to_bitmap(x, y) for x, y in ((left, bottom), (right, bottom), (right, top), (left, top))
                ]
                xs, ys = [c[0] for c in corners], [c[1] for c in corners]
                pad = max(1.0, self.limits.pdf_pad * (top - bottom) * scale)
                box = (min(xs) - pad, min(ys) - pad, max(xs) + pad, max(ys) + pad)
                draw.rectangle(box, fill=(0, 0, 0))
                painted.append(box)
        return painted

    def verify_strings(self, output: bytes) -> list[str]:
        again = PdfDocument(output, "", self.limits, verify=True)
        if len(again.pdf) != len(self.pdf) or again.segments():
            raise DocError("verify_failed", "the redacted PDF still contains text")
        return []


def _verify_opaque(jpeg: bytes, boxes: list[tuple[float, float, float, float]], page: int) -> None:
    """INV-09 for PDFs: decode the page that will be released and check every redaction box is solid black."""
    if not boxes:
        return
    from PIL import Image

    image = Image.open(io.BytesIO(jpeg)).convert("L")
    for left, top, right, bottom in boxes:
        inner = (
            max(0, int(left) + 2),
            max(0, int(top) + 2),
            min(image.width, int(right) - 2),
            min(image.height, int(bottom) - 2),
        )
        if inner[2] <= inner[0] or inner[3] <= inner[1]:
            continue
        if max(image.crop(inner).tobytes()) > 96:
            raise DocError("verify_failed", f"a redaction on page {page} is not opaque, so the PDF was not released")


def _pages(numbers: list[int]) -> str:
    shown = ", ".join(str(n) for n in numbers[:10])
    return shown + (" ..." if len(numbers) > 10 else "")
