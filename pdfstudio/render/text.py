"""
pdfstudio.render.text
ASCII / Unicode box-drawing CLI output.

Default view layout:
    Header + top-line summary
    Revisions table
    Objects table
    Triggers walker output
    Flags panel
"""
from __future__ import annotations

import hashlib
import os
from collections import Counter
from typing import Iterable

from ..model import PDFFile
from ..walker import TriggerHit


RULER = '─'
BULLET = '•'
ARROW = '→'
BRANCH = '├─'
LAST = '└─'
PIPE = '│'


def _w(default: int = 120) -> int:
    try:
        return max(120, os.get_terminal_size().columns)
    except OSError:
        return default


def _title(text: str, width: int, char: str = '═') -> str:
    line = char * width
    return f'\n{line}\n{text}\n{char * width}'


def _sect(text: str, width: int) -> str:
    return f'\n{text}\n{"─" * min(len(text), width)}'


def _severity_glyph(sev: str) -> str:
    return {'HIGH': '★★★', 'MED': '★★ ', 'LOW': '★  ', 'INFO': '·  '}.get(sev, '   ')


def render(pdf: PDFFile, hits: list[TriggerHit], *, width: int | None = None) -> str:
    w = width if width is not None else _w()
    lines: list[str] = []

    # ---- Header / summary ---------------------------------------------------
    name = os.path.basename(pdf.path)
    lines.append(_title(f'PDFSTUDIO  {BULLET}  {name}  {BULLET}  {pdf.size:,} B  {BULLET}  {pdf.header or "(no header)"}', w))

    stream_count = sum(1 for o in pdf.objects if o.stream is not None)
    filter_counts: Counter[str] = Counter()
    for o in pdf.objects:
        if o.stream:
            for f in o.stream.filters:
                filter_counts[f] += 1
    filters_str = ', '.join(f'{k}×{v}' for k, v in filter_counts.most_common()) or '(none)'

    kinds: Counter[str] = Counter(o.kind for o in pdf.objects)
    annot_count = sum(v for k, v in kinds.items() if k.startswith('Annot'))
    action_count = sum(v for k, v in kinds.items() if k.startswith('Action'))

    try:
        with open(pdf.path, 'rb') as fh:
            raw = fh.read()
        md5  = hashlib.md5(raw).hexdigest()
        sha1 = hashlib.sha1(raw).hexdigest()
        sha2 = hashlib.sha256(raw).hexdigest()
    except OSError:
        md5 = sha1 = sha2 = '(n/a)'

    lines.append(f'{BULLET} Size                 {pdf.size:,} bytes')
    lines.append(f'{BULLET} MD5                  {md5}')
    lines.append(f'{BULLET} SHA-1                {sha1}')
    lines.append(f'{BULLET} SHA-256              {sha2}')
    lines.append(f'{BULLET} Header               {pdf.header or "(none)"}')
    lines.append(f'{BULLET} Revisions            {len(pdf.revisions)}' +
                 (f'  [incremental-update chain]' if len(pdf.revisions) > 1 else ''))
    lines.append(f'{BULLET} %%EOF markers        {len(pdf.eof_offsets)}  @ ' +
                 ', '.join(hex(x) for x in pdf.eof_offsets))
    lines.append(f'{BULLET} Objects              {len(pdf.objects)} total')
    lines.append(f'{BULLET} Streams              {stream_count}  (filters: {filters_str})')
    lines.append(f'{BULLET} Annotations          {annot_count}')
    lines.append(f'{BULLET} Actions              {action_count}')
    lines.append(f'{BULLET} Catalog /Root        ' + (f'obj {pdf.trailers[-1].root[0]}' if (pdf.trailers and pdf.trailers[-1].root) else '(missing)'))
    if pdf.parse_warnings:
        lines.append(f'{BULLET} Parse warnings       {len(pdf.parse_warnings)}')

    # ---- Revisions ----------------------------------------------------------
    if pdf.revisions:
        lines.append(_sect('Revisions', w))
        header = f'{"REV":<5}{"XREF@":>10}  {"SIZE":>6}  {"PREV":>10}  NEW / REWRITTEN OBJECTS'
        lines.append(header)
        for r in pdf.revisions:
            new_str = ','.join(str(i) for i in sorted(r.new_objects))
            rw_str  = ','.join(str(i) for i in sorted(r.rewritten_objects))
            parts = []
            if new_str:
                parts.append(f'NEW[{new_str}]')
            if rw_str:
                parts.append(f'REWRITE[{rw_str}]')
            detail = '  '.join(parts) or '(no per-index deltas)'
            prev = r.trailer.prev
            prev_s = str(prev) if prev is not None else '—'
            size_s = str(r.trailer.size) if r.trailer.size is not None else '—'
            lines.append(f'v{r.index:<4}{r.trailer.startxref:>10}  {size_s:>6}  {prev_s:>10}  {detail}')

    # ---- Objects ------------------------------------------------------------
    lines.append(_sect('Objects', w))
    lines.append(f'{"ID":>5}  {"REV":>3}  {"OFFSET":>8}  {"LEN":>7}  {"MD5":<12}  KIND                LABELS')
    # Column budget: a reasonable fixed-column table, labels truncated to
    # the remaining terminal width (no less than 30 chars).
    labels_budget = max(30, w - 70)
    for o in sorted(pdf.objects, key=lambda x: (x.revision, x.index)):
        labels = '; '.join(o.labels) if o.labels else ''
        if len(labels) > labels_budget:
            labels = labels[:labels_budget - 3] + '...'
        stream_tag = '[S]' if o.stream else ''
        lines.append(f'{o.index:>5}  v{o.revision:<2}  {o.offset:>8X}  {o.raw_length:>7}  '
                     f'{o.md5[:10]:<12}  {o.kind + " " + stream_tag:<20}{labels}')

    # ---- Triggers / walker --------------------------------------------------
    lines.append(_sect('Triggers (Catalog graph walk)', w))
    if not hits:
        lines.append('(no active triggers found)')
    else:
        for h in hits:
            glyph = _severity_glyph(h.severity)
            lines.append(f'{glyph}  {h.path}')
            if h.detail:
                snippet = h.detail.replace('\n', ' ').replace('\r', ' ')
                if len(snippet) > w - 6:
                    snippet = snippet[:w - 9] + '...'
                lines.append(f'      {PIPE}  {snippet}')

    # ---- Flags --------------------------------------------------------------
    if pdf.flags:
        lines.append(_sect('Flags', w))
        # Order: HIGH → MED → LOW → INFO
        order = {'HIGH': 0, 'MED': 1, 'LOW': 2, 'INFO': 3}
        for sev, code, msg in sorted(pdf.flags, key=lambda x: order.get(x[0], 99)):
            glyph = _severity_glyph(sev)
            lines.append(f'{glyph}  [{sev:<4}] {code:<24} {msg}')

    lines.append('')  # trailing newline
    return '\n'.join(lines)
