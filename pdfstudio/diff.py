"""
pdfstudio.diff
Two-PDF structural comparison.

Compares at three levels:
  - top-level metadata (size, version, revision count, %%EOF count)
  - per-object set (by index) — added, removed, body-unchanged, body-changed
  - per-trailer chain — /Prev, /Size, /Root correspondence
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .model import PDFFile


@dataclass
class DiffResult:
    same_header: bool
    left_size: int
    right_size: int
    left_revs: int
    right_revs: int
    left_eofs: int
    right_eofs: int

    objects_added: list[int]
    objects_removed: list[int]
    objects_body_unchanged: list[int]
    objects_body_changed: list[tuple[int, str, str]]   # (idx, left_md5, right_md5)

    trailer_rows: list[tuple[str, str, str]]            # (field, left, right)


def _best_obj(pdf: PDFFile, idx: int):
    return pdf.obj(idx)


def diff(left: PDFFile, right: PDFFile) -> DiffResult:
    l_idx = {o.index for o in left.objects}
    r_idx = {o.index for o in right.objects}

    added = sorted(r_idx - l_idx)
    removed = sorted(l_idx - r_idx)
    common = sorted(l_idx & r_idx)

    unchanged = []
    changed = []
    for idx in common:
        lo = _best_obj(left, idx)
        ro = _best_obj(right, idx)
        if lo and ro:
            if lo.md5 == ro.md5:
                unchanged.append(idx)
            else:
                changed.append((idx, lo.md5[:10], ro.md5[:10]))

    # Trailer comparison: align by revision index
    trailer_rows = []
    ln = max(len(left.trailers), len(right.trailers))
    for i in range(ln):
        lt = left.trailers[i] if i < len(left.trailers) else None
        rt = right.trailers[i] if i < len(right.trailers) else None
        def cell(v):
            return str(v) if v is not None else '—'
        trailer_rows.append((f'trailer[{i}] startxref', cell(lt.startxref if lt else None),
                              cell(rt.startxref if rt else None)))
        trailer_rows.append((f'trailer[{i}] /Size', cell(lt.size if lt else None),
                              cell(rt.size if rt else None)))
        trailer_rows.append((f'trailer[{i}] /Prev', cell(lt.prev if lt else None),
                              cell(rt.prev if rt else None)))
        trailer_rows.append((f'trailer[{i}] /Root', cell(lt.root if lt else None),
                              cell(rt.root if rt else None)))

    return DiffResult(
        same_header=(left.header == right.header),
        left_size=left.size, right_size=right.size,
        left_revs=len(left.revisions), right_revs=len(right.revisions),
        left_eofs=len(left.eof_offsets), right_eofs=len(right.eof_offsets),
        objects_added=added,
        objects_removed=removed,
        objects_body_unchanged=unchanged,
        objects_body_changed=changed,
        trailer_rows=trailer_rows,
    )


def render_diff(d: DiffResult, left_name: str, right_name: str) -> str:
    lines = []
    lines.append('═' * 80)
    lines.append(f'DIFF  {left_name}  ↔  {right_name}')
    lines.append('═' * 80)
    lines.append('')
    lines.append('Top-level')
    lines.append('─────────')
    lines.append(f'  size      : {d.left_size:>12,}  {d.right_size:>12,}  {"=" if d.left_size==d.right_size else "≠"}')
    lines.append(f'  revisions : {d.left_revs:>12}  {d.right_revs:>12}  {"=" if d.left_revs==d.right_revs else "≠"}')
    lines.append(f'  %%EOF     : {d.left_eofs:>12}  {d.right_eofs:>12}  {"=" if d.left_eofs==d.right_eofs else "≠"}')
    lines.append(f'  header    : {"same" if d.same_header else "different"}')

    lines.append('')
    lines.append('Objects')
    lines.append('───────')
    lines.append(f'  added   (only in right) : {len(d.objects_added):>4}' +
                 (f'  [{", ".join(str(x) for x in d.objects_added[:20])}{"..." if len(d.objects_added) > 20 else ""}]'
                  if d.objects_added else ''))
    lines.append(f'  removed (only in left)  : {len(d.objects_removed):>4}' +
                 (f'  [{", ".join(str(x) for x in d.objects_removed[:20])}{"..." if len(d.objects_removed) > 20 else ""}]'
                  if d.objects_removed else ''))
    lines.append(f'  unchanged body (md5)    : {len(d.objects_body_unchanged):>4}')
    lines.append(f'  changed body (md5)      : {len(d.objects_body_changed):>4}')
    for idx, lm, rm in d.objects_body_changed[:25]:
        lines.append(f'      obj {idx:<4}  {lm:>10}  →  {rm:<10}')
    if len(d.objects_body_changed) > 25:
        lines.append(f'      ... ({len(d.objects_body_changed) - 25} more)')

    lines.append('')
    lines.append('Trailers')
    lines.append('────────')
    for field, lv, rv in d.trailer_rows:
        mark = '=' if lv == rv else '≠'
        lines.append(f'  {field:<28}  {lv:>14}  {rv:>14}  {mark}')

    return '\n'.join(lines) + '\n'
