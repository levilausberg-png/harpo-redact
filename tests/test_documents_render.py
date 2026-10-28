"""Redacted Office files open and render in a real office suite (LibreOffice), with the data gone.

Skipped when LibreOffice is not installed. This shows the files are valid and render; it is evidence for
LibreOffice, not for Microsoft Office.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from . import doc_fixtures as fx
from .conftest import needs
from .test_documents import env, run  # noqa: F401  (the env fixture)

SOFFICE = shutil.which("soffice")


@pytest.fixture(autouse=True)
def _libreoffice() -> None:
    if SOFFICE is None:
        needs("libreoffice", "LibreOffice is not installed")


def render_text(path: Path, tmp: Path) -> str:
    import pypdfium2 as pdfium

    profile = tmp / "profile"
    subprocess.run(  # a fixed command on a file this test just wrote
        [str(SOFFICE), f"-env:UserInstallation=file://{profile}", "--headless", "--convert-to", "pdf", "--outdir", str(tmp), str(path)],
        check=True, capture_output=True, timeout=180,
    )  # fmt: skip
    pdf = pdfium.PdfDocument(str(tmp / (path.stem + ".pdf")))
    return "\n".join(pdf[i].get_textpage().get_text_range() for i in range(len(pdf)))


@pytest.mark.parametrize(
    ("builder", "name", "must_show"),
    [
        (fx.make_docx, "notes.docx", ["Formatting that must survive", "[PERSON_1]", "[EMAIL_1]"]),
        (fx.make_xlsx, "customers.xlsx", ["[PERSON_", "[EMAIL_", "nothing secret here"]),
        (
            fx.make_pptx,
            "deck.pptx",
            ["[PERSON_", "[EMAIL_", "[IBAN_1]"],
        ),  # the card is in the notes, which slides do not print
    ],
)
def test_redacted_office_files_open_and_render(env, tmp_path: Path, builder, name: str, must_show: list[str]) -> None:  # type: ignore[no-untyped-def]  # noqa: F811
    out = run(env(), builder(), name)
    assert out.data is not None
    path = tmp_path / name
    path.write_bytes(out.data)
    shown = render_text(path, tmp_path)
    for value in must_show:
        assert value in shown, f"{value!r} is not visible in the rendered {name}"
    for value in [*fx.CANARIES, "4111"]:
        assert value not in shown, f"{value!r} is visible in the rendered {name}"
