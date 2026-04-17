"""
pdfstudio.recursive
Follow embedded PDFs: when a decoded stream begins with `%PDF-`, parse
it as a child PDFFile. Attach it to the parent under `parent.children`
and recurse up to a bounded depth.

    expand_embedded_pdfs(pdf, max_depth=5) -> int  # number of new child PDFs
"""
from __future__ import annotations

import os
import tempfile
from typing import Optional

from .model import PDFFile, PDFObject


def expand_embedded_pdfs(pdf: PDFFile, *, max_depth: int = 5,
                         tmp_dir: Optional[str] = None) -> int:
    """Recursively parse every stream whose decoded bytes start with `%PDF-`."""
    from .parser import parse
    from .classify import classify

    count = 0

    if max_depth <= 0:
        return 0

    for obj in pdf.objects:
        if obj.stream is None:
            continue
        data = obj.stream.decoded_bytes
        if not data or not data.startswith(b'%PDF-'):
            continue

        # Write to a temp file so parser can mmap/seek cleanly.
        dirpath = tmp_dir or tempfile.mkdtemp(prefix='pdfstudio_child_')
        child_name = f'embedded_obj{obj.index}.pdf'
        child_path = os.path.join(dirpath, child_name)
        with open(child_path, 'wb') as fh:
            fh.write(data)

        try:
            child_pdf = parse(child_path)
            classify(child_pdf)
        except Exception as e:
            continue

        # Annotate the child with its provenance.
        child_pdf.path = child_path
        child_pdf.source_obj_index = obj.index
        child_pdf.source_parent_path = pdf.path

        pdf.children.append(child_pdf)
        count += 1

        # Mark the wrapper object so the renderer can surface it
        obj.labels.append(f'EmbeddedPDF -> child #{len(pdf.children)}')

        # Recurse
        count += expand_embedded_pdfs(child_pdf, max_depth=max_depth - 1, tmp_dir=dirpath)
    return count


def render_children(pdf: PDFFile, *, indent: int = 0) -> str:
    """Text rendering of the child-PDF tree."""
    if not pdf.children:
        return ''
    lines = []
    for i, child in enumerate(pdf.children):
        src = getattr(child, 'source_obj_index', '?')
        pad = '  ' * indent
        lines.append(f'{pad}└─ embedded #{i + 1}  (from obj {src})')
        lines.append(f'{pad}     path        : {child.path}')
        lines.append(f'{pad}     size        : {child.size:,} bytes')
        lines.append(f'{pad}     header      : {child.header}')
        lines.append(f'{pad}     revisions   : {len(child.revisions)}')
        lines.append(f'{pad}     objects     : {len(child.objects)}')
        lines.append(f'{pad}     flags       : {", ".join(c for _, c, _ in child.flags) or "—"}')
        sub = render_children(child, indent=indent + 1)
        if sub:
            lines.append(sub.rstrip())
    return '\n'.join(lines) + '\n'
