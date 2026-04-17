"""
pdfstudio.pdfid_view
pdfid-style keyword + structural summary (plain-text).

    render_pdfid(pdf) -> str

Matches pdfid's layout closely: header line, counted keywords, entropy.
"""
from __future__ import annotations

import math
import os
import re

from .model import PDFFile


# The canonical pdfid keyword table (pdfid 0.2.8).
PDFID_KEYWORDS = [
    'obj', 'endobj', 'stream', 'endstream', 'xref', 'trailer', 'startxref',
    '/Page', '/Encrypt', '/ObjStm', '/JS', '/JavaScript', '/AA', '/OpenAction',
    '/AcroForm', '/JBIG2Decode', '/RichMedia', '/Launch', '/EmbeddedFile',
    '/XFA', '/Colors > 2^24',
]

# Extra keywords pdfstudio surfaces that pdfid does not by default.
EXTRA_KEYWORDS = [
    '/URI', '/Filespec', '/EmbeddedFiles', '/Names', '/Annot', '/Subtype/Link',
    '/S/URI', '/S/Launch', '/S/JavaScript', '/S/GoTo', '/S/GoToR',
    '/F(cmd.exe)',
]

# Broad name table, surfaced when --all-keywords is set.
ALL_EXTRA_KEYWORDS = [
    '/AcroForm', '/AdditionalActions', '/AP', '/Annotation',
    '/Bead', '/Border', '/Catalog', '/Dest', '/FDF', '/Field',
    '/Form', '/GoTo', '/GoToR', '/ImportData', '/Info',
    '/Kids', '/Lang', '/Metadata', '/Outlines',
    '/Pages', '/Parent', '/Pattern', '/ProcSet', '/Rect',
    '/Resources', '/Root', '/Sig', '/Signature', '/Subtype',
    '/Thread', '/Tile', '/Type', '/XObject',
    '/ASCII85Decode', '/ASCIIHexDecode', '/CCITTFaxDecode', '/DCTDecode',
    '/FlateDecode', '/JPXDecode', '/LZWDecode', '/RunLengthDecode',
    '/Crypt',
]

# Additional "extras" shown only with --extra-info (mirrors pdfid -e).
EXTRA_INFO_PATTERNS = [
    ('/CreationDate', r'/CreationDate\s*\(([^)]*)\)'),
    ('/ModDate',      r'/ModDate\s*\(([^)]*)\)'),
    ('/Producer',     r'/Producer\s*\(([^)]*)\)'),
    ('/Author',       r'/Author\s*\(([^)]*)\)'),
    ('/Creator',      r'/Creator\s*\(([^)]*)\)'),
    ('/Title',        r'/Title\s*\(([^)]*)\)'),
]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ln = len(data)
    return -sum((c / ln) * math.log2(c / ln) for c in freq if c)


def _count_occurrences(raw: bytes, keyword: str) -> int:
    """Count keyword in raw bytes. pdfid-style: no regex, literal substring."""
    return raw.count(keyword.encode('latin-1'))


def render_pdfid(pdf: PDFFile, *, nozero: bool = False,
                 extra_info: bool = False, all_keywords: bool = False) -> str:
    # Read raw bytes for byte-level entropy + counts.
    with open(pdf.path, 'rb') as fh:
        raw = fh.read()

    # Split into in-stream vs. out-of-stream bytes (approximate: use stream raw_bytes).
    in_stream = bytearray()
    for obj in pdf.objects:
        if obj.stream and obj.stream.raw_bytes:
            in_stream.extend(obj.stream.raw_bytes)
    # Very rough "out of stream" is everything minus stream bodies.
    # For true accuracy we would excise by exact offsets; pdfid also estimates.
    out_of_stream_len = len(raw) - len(in_stream)

    name = os.path.basename(pdf.path)
    lines = []
    lines.append(f'PDFiD 0.2.8-compatible  {name}')
    lines.append(f' PDF Header: {pdf.header or "(missing)"}')

    keyword_pool = list(PDFID_KEYWORDS)
    if all_keywords:
        keyword_pool = list(PDFID_KEYWORDS) + [k for k in ALL_EXTRA_KEYWORDS if k not in PDFID_KEYWORDS]
    maxname = max(len(k) for k in keyword_pool + EXTRA_KEYWORDS)

    for kw in keyword_pool:
        n = _count_occurrences(raw, kw)
        if nozero and n == 0:
            continue
        lines.append(f' {kw:<{maxname}}  {n:>7}')

    lines.append('')
    lines.append(' --- Extra keywords (pdfstudio) ---')
    any_extra = False
    for kw in EXTRA_KEYWORDS:
        n = _count_occurrences(raw, kw)
        if n == 0 and (nozero or True):
            # pdfstudio's extra list has always been zero-suppressed; keep it so.
            continue
        lines.append(f' {kw:<{maxname}}  {n:>7}')
        any_extra = True
    if not any_extra:
        lines.append(' (none)')

    # pdfid -e equivalent: Info-dict dates / producer / author / title / creator
    if extra_info:
        lines.append('')
        lines.append(' --- Info dictionary (--extra-info) ---')
        try:
            s = raw.decode('latin-1', errors='replace')
        except Exception:
            s = ''
        any_info = False
        for label, pat in EXTRA_INFO_PATTERNS:
            m = re.search(pat, s)
            if m:
                val = m.group(1)
                if len(val) > 80:
                    val = val[:77] + '...'
                lines.append(f' {label:<{maxname}}  {val}')
                any_info = True
        if not any_info:
            lines.append(' (no /Info metadata extracted)')

    lines.append('')
    lines.append(' --- Entropy ---')
    lines.append(f' Total entropy              : {_entropy(raw):.3f}  ({len(raw):,} bytes)')
    lines.append(f' Entropy inside streams     : {_entropy(bytes(in_stream)):.3f}  ({len(in_stream):,} bytes)')
    # Approximate outside-stream: we cannot cleanly excise without reparsing;
    # report the length as an indicator only.
    lines.append(f' Bytes not in stream bodies : {out_of_stream_len:,} bytes')

    lines.append('')
    lines.append(' --- Structural markers ---')
    lines.append(f' %%EOF count      : {len(pdf.eof_offsets)}')
    lines.append(f' startxref count  : {len(pdf.startxref_offsets)}')
    lines.append(f' trailer count    : {len(pdf.trailers)}')
    lines.append(f' revisions        : {len(pdf.revisions)}')

    return '\n'.join(lines) + '\n'
