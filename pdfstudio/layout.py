"""
pdfstudio.layout
Vertical, PEstudio-style block diagram of the PDF file.

    render_layout(pdf) -> str

The diagram stacks the regions a PDF file is actually made of:

    ┌─ Header ──────────────────────┐ 0x00000000
    │ %PDF-1.3  (9 B)               │
    ╞═ Body — Revision 0 ═══════════╡ 0x00000009
    │   obj 1   dict      (Info)    │
    │   ...                         │
    │   obj 13  Catalog  [/Root]    │
    ├─ xref (v0) ───────────────────┤
    ├─ Trailer (v0) ────────────────┤
    ├─ %%EOF (v0) ──────────────────┤
    ╞═ Body — Revision 1 ═══════════╡  ← incremental update
    │   ★ obj 22  Action:JavaScript │
    │   ★ obj 23  Action:Launch     │
    ├─ xref (v1) ───────────────────┤
    ├─ Trailer (v1) ────────────────┤
    └─ %%EOF (v1) ──────────────────┘ 0x0000EC13
"""
from __future__ import annotations

from .model import PDFFile, PDFObject, Revision


WIDTH = 78  # total line width including borders
INNER = WIDTH - 4  # content width between '│ ' and ' │'


def _off(n: int) -> str:
    return f'0x{n:08X}'


def _sev(obj: PDFObject) -> str:
    """Return a star marker for 'interesting' objects."""
    k = obj.kind
    if k.startswith('Action:') or k == 'Filespec':
        return '★'
    if any(lbl.startswith('Decoded=Windows PE') or lbl.startswith('Decoded=ELF')
           or lbl.startswith('Decoded=OLE') for lbl in obj.labels):
        return '★'
    return ' '


def _line(text: str, *, border_l: str = '│', border_r: str = '│',
          pad: str = ' ') -> str:
    t = text
    if len(t) > INNER:
        t = t[:INNER - 1] + '…'
    return f'{border_l}{pad}{t:<{INNER}}{pad}{border_r}'


def _divider(label: str = '', *, top: bool = False, bottom: bool = False,
             double: bool = False, offset: str = '') -> str:
    """Horizontal divider. Use `double` for revision-start bars."""
    if top:
        l, r, fill = '┌', '┐', '─'
    elif bottom:
        l, r, fill = '└', '┘', '─'
    elif double:
        l, r, fill = '╞', '╡', '═'
    else:
        l, r, fill = '├', '┤', '─'
    label_chunk = f' {label} ' if label else ''
    rule = f'{l}{fill}{label_chunk}{fill * (WIDTH - 2 - len(label_chunk))}{r}'
    rule = rule[:WIDTH]
    if offset:
        rule = f'{rule}  {offset}'
    return rule


# ---------------------------------------------------------------------------

def _format_obj_line(o: PDFObject, *, star_col: int = 1) -> str:
    """One row per object, fits in INNER chars."""
    star = _sev(o)
    # e.g. "★ obj   23  v1  Action:Launch    F=cmd.exe"
    labels = '; '.join(o.labels) if o.labels else ''
    if o.stream and 'Filters=' not in labels:
        labels = ('stream; ' + labels).rstrip('; ')
    stem = f'{star} obj {o.index:>4}  v{o.revision}  {o.kind:<20}'
    remaining = INNER - len(stem)
    if remaining > 4 and labels:
        if len(labels) > remaining:
            labels = labels[:remaining - 1] + '…'
        return stem + labels
    return stem


def _format_trailer_line(tr) -> list[str]:
    """Break trailer dict into one-per-key lines, roughly."""
    parts = []
    if tr.root is not None:
        parts.append(f'/Root {tr.root[0]} {tr.root[1]} R')
    if tr.size is not None:
        parts.append(f'/Size {tr.size}')
    if tr.prev is not None:
        parts.append(f'/Prev {tr.prev}')
    if tr.info is not None:
        parts.append(f'/Info {tr.info[0]} {tr.info[1]} R')
    if tr.ids:
        parts.append(f'/ID [{", ".join(i[:12] + "…" for i in tr.ids)}]')
    if not parts:
        parts = ['(empty trailer dict)']
    return parts


def render_layout(pdf: PDFFile) -> str:
    if pdf.size <= 0:
        return '(empty file)\n'

    lines: list[str] = []

    # ---- Header band --------------------------------------------------------
    first_off = min((o.offset for o in pdf.objects), default=pdf.size)
    header_len = first_off
    lines.append(_divider('Header', top=True, offset=_off(0)))
    lines.append(_line(f'{pdf.header or "(unknown)"}   ({header_len} B)'))

    # ---- Per-revision bands -------------------------------------------------
    objects_by_rev: dict[int, list[PDFObject]] = {}
    for o in pdf.objects:
        objects_by_rev.setdefault(o.revision, []).append(o)
    for lst in objects_by_rev.values():
        lst.sort(key=lambda o: o.offset)

    revs: list[Revision] = list(pdf.revisions)

    for idx, r in enumerate(revs):
        body_start = first_off if idx == 0 else revs[idx - 1].trailer.eof_offset + 5
        body_end = r.xref_offset
        xref_start = r.xref_offset
        xref_end = r.trailer.offset
        trailer_start = r.trailer.offset
        trailer_end = r.trailer.eof_offset
        eof_start = r.trailer.eof_offset
        eof_end = r.trailer.eof_offset + 5

        # Revision header bar
        tag = f'Body — Revision {r.index}'
        if idx > 0:
            tag += '  (incremental update)'
        lines.append(_divider(tag, double=True, offset=_off(body_start)))

        # Summary sub-line
        new_ct = len(r.new_objects)
        rw_ct = len(r.rewritten_objects)
        size = body_end - body_start
        summary = f'{size:,} bytes   NEW={new_ct}   REWRITE={rw_ct}'
        lines.append(_line(summary))
        if r.new_objects:
            lines.append(_line(f'  NEW objs     : {", ".join(str(i) for i in sorted(r.new_objects))}'))
        if r.rewritten_objects:
            lines.append(_line(f'  REWRITE objs : {", ".join(str(i) for i in sorted(r.rewritten_objects))}'))
        lines.append(_line(''))

        # Objects belonging to this revision
        for o in objects_by_rev.get(r.index, []):
            lines.append(_line(_format_obj_line(o)))

        # xref section
        xref_len = max(0, xref_end - xref_start)
        lines.append(_divider(f'xref (v{r.index})  {xref_len} B', offset=_off(xref_start)))
        entries = len(r.resolved_objects) if hasattr(r, 'resolved_objects') else 0
        lines.append(_line(f'{entries} entries'))

        # Trailer section
        tr_len = max(0, trailer_end - trailer_start)
        lines.append(_divider(f'Trailer (v{r.index})  {tr_len} B', offset=_off(trailer_start)))
        for p in _format_trailer_line(r.trailer):
            lines.append(_line(f'  {p}'))

        # %%EOF marker
        is_last = (idx == len(revs) - 1)
        if is_last:
            lines.append(_divider(f'%%EOF (v{r.index})', offset=_off(eof_start)))
            lines.append(_line('%%EOF  (5 B)'))
            lines.append(_divider(bottom=True, offset=_off(min(pdf.size, eof_end))))
        else:
            lines.append(_divider(f'%%EOF (v{r.index})', offset=_off(eof_start)))
            lines.append(_line('%%EOF  (5 B)'))

    return '\n'.join(lines) + '\n'
