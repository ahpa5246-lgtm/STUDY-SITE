#!/usr/bin/env python3
"""Build a viewer-safe Arabic PDF from the XeLaTeX vector output."""
from pathlib import Path
from io import BytesIO
from shutil import copyfile
import fitz
from PIL import Image

root = Path(__file__).resolve().parent.parent
source = root / "hw_vector.pdf"
main = root / "حل واجبات المحاضرة الاولى.pdf"
selectable = root / "حل واجبات المحاضرة الاولى - نسخة نصية.pdf"
if not source.exists():
    raise SystemExit("XeLaTeX output was not found")
doc = fitz.open(source)
if len(doc) < 10:
    raise RuntimeError("Incomplete PDF: unexpected page count")
copyfile(source, selectable)
safe = fitz.open()
for page in doc:
    pix = page.get_pixmap(matrix=fitz.Matrix(2.85, 2.85), alpha=False, colorspace=fitz.csRGB)
    img = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
    buff = BytesIO()
    img.save(buff, format="JPEG", quality=91, subsampling=0, optimize=True)
    target = safe.new_page(width=page.rect.width, height=page.rect.height)
    target.insert_image(target.rect, stream=buff.getvalue())
safe.set_metadata({
    "title": "حل واجبات المحاضرة الاولى",
    "author": "Control Theory Study Notes",
    "subject": "Mesh analysis: homework 1-3, stable Arabic rendering",
})
safe.save(main, garbage=4, deflate=True, clean=True)
print("Updated", main, "pages", len(doc), "bytes", main.stat().st_size)
print("Editable/searchable backup", selectable)
