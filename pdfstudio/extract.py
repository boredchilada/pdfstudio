"""
pdfstudio.extract
Surgical extraction helpers — pdf-parser's -o / -d / -f equivalents.

    show_object(pdf, index, generation=0, filtered=False) -> str
    dump_stream(pdf, index, generation=0, decoded=False) -> bytes
"""
from __future__ import annotations

import hashlib
from typing import Optional

from .model import PDFFile, PDFObject


def _find(pdf: PDFFile, index: int, generation: int = 0, revision: Optional[int] = None) -> Optional[PDFObject]:
    candidates = [o for o in pdf.objects if o.index == index and o.generation == generation]
    if not candidates:
        return None
    if revision is not None:
        for o in candidates:
            if o.revision == revision:
                return o
        return None
    # Default: latest revision
    return max(candidates, key=lambda o: o.revision)


def show_object(pdf: PDFFile, index: int, generation: int = 0, revision: Optional[int] = None) -> str:
    o = _find(pdf, index, generation, revision)
    if o is None:
        return f'object {index} {generation} not found'

    lines = []
    lines.append(f'obj {o.index} {o.generation}')
    lines.append(f'  offset       : {o.offset:#x} ({o.offset})')
    lines.append(f'  length       : {o.raw_length} bytes')
    lines.append(f'  md5 (body)   : {o.md5}')
    lines.append(f'  revision     : v{o.revision}')
    lines.append(f'  kind         : {o.kind}')
    if o.labels:
        lines.append(f'  labels       : {"; ".join(o.labels)}')
    if o.stream is not None:
        s = o.stream
        lines.append(f'  stream       :')
        lines.append(f'    raw_offset   : {s.raw_offset:#x}')
        lines.append(f'    raw_length   : {s.raw_length}')
        lines.append(f'    declared_len : {s.declared_length}')
        lines.append(f'    filters      : {", ".join(s.filters) or "(none)"}')
        if s.raw_bytes is not None:
            lines.append(f'    raw_md5      : {hashlib.md5(s.raw_bytes).hexdigest()}')
            lines.append(f'    raw_sha256   : {hashlib.sha256(s.raw_bytes).hexdigest()}')
        if s.decoded_bytes is not None:
            lines.append(f'    decoded_len  : {len(s.decoded_bytes)}')
            lines.append(f'    decoded_md5  : {hashlib.md5(s.decoded_bytes).hexdigest()}')
            lines.append(f'    decoded_sha256: {hashlib.sha256(s.decoded_bytes).hexdigest()}')
        if s.decode_error:
            lines.append(f'    decode_error : {s.decode_error}')
    lines.append('')
    lines.append('--- body ---')
    lines.append(o.body.rstrip())
    return '\n'.join(lines) + '\n'


def dump_stream(pdf: PDFFile, index: int, generation: int = 0,
                decoded: bool = False, revision: Optional[int] = None) -> Optional[bytes]:
    o = _find(pdf, index, generation, revision)
    if o is None or o.stream is None:
        return None
    if decoded:
        return o.stream.decoded_bytes
    return o.stream.raw_bytes
