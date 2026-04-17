"""
pdfstudio.parity
Features implemented to reach functional parity with Didier Stevens'
pdf-parser.py:

    search_key(pdf, key)      # -k KEY
    filter_by_type(pdf, type) # -t TYPE
    filter_elements(pdf, e)   # -e cxtsi
    stats(pdf)                # -a
    content_view(pdf)         # -c
    parse_object_list(spec)   # -o "12,15,20-25"
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Iterable

from .model import PDFFile, PDFObject


# ---------------------------------------------------------------------------
# -k KEY — enumerate every dict containing a given /KEY
# ---------------------------------------------------------------------------

def search_key(pdf: PDFFile, key: str) -> list[tuple[PDFObject, str]]:
    """Return (object, value_snippet) for every object whose body contains /key.

    key may include or omit the leading '/'. The value is extracted as
    everything after `/key` up to the next `/` or `>>`.
    """
    k = key if key.startswith('/') else '/' + key
    # Match /Key followed by its value. Alternatives cover:
    #   - array [...]
    #   - string (...)
    #   - hex <...>
    #   - dict <<...>>
    #   - name  /Name
    #   - indirect ref 'N G R'
    #   - integer / real / bool
    pat = re.compile(
        re.escape(k) + r'\b\s*('
        r'\[[^\]]*\]'
        r'|\([^)]*\)'
        r'|<<.*?>>'
        r'|<[^>]*>'
        r'|/[^\s/<>\[\]()]+'
        r'|\d+\s+\d+\s+R'
        r'|-?\d+(?:\.\d+)?'
        r'|true|false'
        r')',
        re.DOTALL,
    )
    out: list[tuple[PDFObject, str]] = []
    for obj in pdf.objects:
        m = pat.search(obj.body)
        if m:
            val = m.group(1).strip()
            # normalise whitespace
            val = re.sub(r'\s+', ' ', val)
            if len(val) > 120:
                val = val[:117] + '...'
            out.append((obj, val))
    return out


# ---------------------------------------------------------------------------
# -t TYPE — filter objects by /Type value
# ---------------------------------------------------------------------------

_RE_TYPE = re.compile(r'/Type\s*(/\w+)')


def filter_by_type(pdf: PDFFile, type_name: str) -> list[PDFObject]:
    """Return objects whose /Type matches type_name ('/Catalog', 'Catalog', ...)."""
    target = type_name if type_name.startswith('/') else '/' + type_name
    out = []
    for obj in pdf.objects:
        m = _RE_TYPE.search(obj.body)
        if m and m.group(1) == target:
            out.append(obj)
    return out


# ---------------------------------------------------------------------------
# -e ELEMENTS — element-class filter
# ---------------------------------------------------------------------------

# Stevens: c=comment  x=xref  t=trailer  s=startxref  i=indirect
# Our model keeps comments implicit and xref positions in eof/startxref_offsets.

def filter_elements(pdf: PDFFile, letters: str) -> dict[str, list]:
    """Return a dict with keys 'c'/'x'/'t'/'s'/'i' selected by `letters`."""
    letters = letters.lower()
    bag: dict[str, list] = {}
    if 'i' in letters:
        bag['indirect'] = list(pdf.objects)
    if 't' in letters:
        bag['trailer'] = list(pdf.trailers)
    if 's' in letters:
        bag['startxref'] = list(pdf.startxref_offsets)
    if 'x' in letters:
        # xref keyword positions are just before trailers in a classic PDF; we
        # don't parse comments or xref tables yet — surface raw offsets.
        bag['xref'] = list(range(len(pdf.trailers)))  # placeholder — per-trailer
    if 'c' in letters:
        bag['comment'] = []  # not tracked in the current model
    return bag


# ---------------------------------------------------------------------------
# -a STATS — summary counts
# ---------------------------------------------------------------------------

def stats(pdf: PDFFile) -> dict:
    kinds = Counter(o.kind for o in pdf.objects)
    types = Counter(
        (_RE_TYPE.search(o.body).group(1) if _RE_TYPE.search(o.body) else '(none)')
        for o in pdf.objects
    )
    filters = Counter()
    for o in pdf.objects:
        if o.stream:
            for f in o.stream.filters:
                filters[f] += 1

    return {
        'size': pdf.size,
        'header': pdf.header,
        'objects_total': len(pdf.objects),
        'streams': sum(1 for o in pdf.objects if o.stream is not None),
        'trailers': len(pdf.trailers),
        'revisions': len(pdf.revisions),
        'eof_markers': len(pdf.eof_offsets),
        'startxref_markers': len(pdf.startxref_offsets),
        'by_kind': dict(kinds),
        'by_pdf_type': dict(types),
        'by_filter': dict(filters),
    }


def render_stats(pdf: PDFFile) -> str:
    s = stats(pdf)
    lines = [
        'Stats',
        '─────',
        f'  size              : {s["size"]:,} bytes',
        f'  header            : {s["header"]}',
        f'  objects (total)   : {s["objects_total"]}',
        f'  streams           : {s["streams"]}',
        f'  trailers          : {s["trailers"]}',
        f'  revisions         : {s["revisions"]}',
        f'  %%EOF markers     : {s["eof_markers"]}',
        f'  startxref markers : {s["startxref_markers"]}',
        '',
        '  By kind:',
    ]
    for k, n in sorted(s['by_kind'].items(), key=lambda x: (-x[1], x[0])):
        lines.append(f'    {k:<28} {n:>5}')
    lines.append('')
    lines.append('  By /Type value:')
    for k, n in sorted(s['by_pdf_type'].items(), key=lambda x: (-x[1], x[0])):
        lines.append(f'    {k:<28} {n:>5}')
    lines.append('')
    lines.append('  By stream /Filter:')
    if s['by_filter']:
        for k, n in sorted(s['by_filter'].items(), key=lambda x: (-x[1], x[0])):
            lines.append(f'    {k:<28} {n:>5}')
    else:
        lines.append('    (no streams)')
    return '\n'.join(lines) + '\n'


# ---------------------------------------------------------------------------
# -c CONTENT — Stevens prints body only for non-stream or unfiltered objects
# ---------------------------------------------------------------------------

def content_view(pdf: PDFFile) -> str:
    lines = []
    for obj in sorted(pdf.objects, key=lambda o: (o.revision, o.index)):
        if obj.stream is None or not obj.stream.filters:
            lines.append(f'obj {obj.index} {obj.generation}   (v{obj.revision}, {obj.kind})')
            lines.append(obj.body.rstrip())
            lines.append('---')
    return '\n'.join(lines) + '\n'


# ---------------------------------------------------------------------------
# -o SPEC — multi-object selector ("12", "12,15", "20-25", combinations)
# ---------------------------------------------------------------------------

def parse_object_list(spec: str) -> list[int]:
    result: set[int] = set()
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            lo, hi = part.split('-', 1)
            result.update(range(int(lo), int(hi) + 1))
        else:
            result.add(int(part))
    return sorted(result)
