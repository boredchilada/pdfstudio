"""
pdfstudio.malformed
Extract bytes that live outside any parsed indirect object or recognised
structural token — i.e. the "malformed" or "unclaimed" regions of the
PDF. This is where attackers sometimes stash payloads that pdf-parser's
object iterator will not touch.

    extract_malformed(pdf) -> bytes
    extract_regions(pdf) -> list[tuple[int, int, bytes]]  # (start, end, data)
"""
from __future__ import annotations

from typing import List, Tuple

from .model import PDFFile


# Structural landmarks we treat as "claimed" even though they are not
# wrapped in indirect objects.
_STRUCT_TOKENS = [b'xref', b'trailer', b'%%EOF']


def _claimed_ranges(pdf: PDFFile, raw: bytes) -> List[Tuple[int, int]]:
    ranges: List[Tuple[int, int]] = []

    # PDF header line ends at the first newline after %PDF-
    if pdf.header:
        hdr_start = raw.find(pdf.header.encode('latin-1'))
        if hdr_start >= 0:
            nl = raw.find(b'\n', hdr_start)
            ranges.append((hdr_start, nl + 1 if nl >= 0 else hdr_start + len(pdf.header)))

    # Every parsed indirect object
    for obj in pdf.objects:
        if obj.offset >= 0 and obj.end_offset > obj.offset:
            ranges.append((obj.offset, obj.end_offset))

    # xref / trailer / %%EOF regions: best-effort — claim from the first xref before
    # a trailer to just past its %%EOF.
    for tr in pdf.trailers:
        # start at the preceding 'xref' keyword if present
        xref_start = raw.rfind(b'xref', 0, tr.offset)
        start = xref_start if xref_start >= 0 else tr.offset
        end = tr.eof_offset + len(b'%%EOF')
        ranges.append((start, end))

    # Merge overlapping
    ranges.sort()
    merged: List[Tuple[int, int]] = []
    for s, e in ranges:
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))
    return merged


def extract_regions(pdf: PDFFile) -> List[Tuple[int, int, bytes]]:
    """Return contiguous unclaimed byte ranges."""
    with open(pdf.path, 'rb') as fh:
        raw = fh.read()
    claimed = _claimed_ranges(pdf, raw)

    out: List[Tuple[int, int, bytes]] = []
    cursor = 0
    for s, e in claimed:
        if s > cursor:
            chunk = raw[cursor:s]
            if chunk.strip():  # ignore whitespace-only gaps
                out.append((cursor, s, chunk))
        cursor = max(cursor, e)
    if cursor < len(raw):
        chunk = raw[cursor:]
        if chunk.strip():
            out.append((cursor, len(raw), chunk))
    return out


def extract_malformed(pdf: PDFFile) -> bytes:
    """Concatenate every unclaimed region into one blob."""
    return b''.join(chunk for _, _, chunk in extract_regions(pdf))


def render_regions(regions: List[Tuple[int, int, bytes]]) -> str:
    if not regions:
        return '(no unclaimed bytes — the parser covered everything)\n'
    lines = ['Unclaimed regions (candidate malformed content):',
             f'{"START":>10}  {"END":>10}  {"LEN":>10}  PREVIEW (first 32 bytes, latin-1)']
    for s, e, chunk in regions:
        preview = chunk[:32].decode('latin-1', errors='replace').replace('\n', '\\n').replace('\r', '\\r')
        lines.append(f'{s:>10X}  {e:>10X}  {len(chunk):>10}  {preview!r}')
    return '\n'.join(lines) + '\n'
