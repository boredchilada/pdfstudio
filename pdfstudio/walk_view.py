"""
pdfstudio.walk_view
Full-depth indented render of the Catalog reference graph.

Distinct from walker.py (which lists only the interesting trigger
anchors): this walks every object reachable from `/Root` and prints it
as a tree, deduplicating by (object index, path).

    render_walk(pdf, *, max_depth=12) -> str
"""
from __future__ import annotations

import re

from .model import PDFFile, PDFObject


RE_IREF = re.compile(r'(\d+)\s+(\d+)\s+R')


def _severity(kind: str) -> str:
    if kind in ('Action:Launch', 'Action:JavaScript'):
        return '★★★'
    if kind in ('Action:URI', 'Filespec', 'EmbeddedFile', 'Annot:Link'):
        return '★★ '
    if kind in ('Catalog', 'Pages', 'Page'):
        return '   '
    return '   '


def render_walk(pdf: PDFFile, *, max_depth: int = 12) -> str:
    if not pdf.trailers or not pdf.trailers[-1].root:
        return '(no Catalog /Root found in trailer)\n'
    root_idx = pdf.trailers[-1].root[0]

    lines: list[str] = []
    lines.append(f'Catalog walk — starting at obj {root_idx} (revision v{len(pdf.revisions) - 1})')
    lines.append('─' * 64)

    # Only walk latest revisions of objects.
    latest: dict[int, PDFObject] = {}
    for o in pdf.objects:
        cur = latest.get(o.index)
        if cur is None or o.revision >= cur.revision:
            latest[o.index] = o

    visited: set[int] = set()

    def _format_node(obj: PDFObject, key: str) -> str:
        sev = _severity(obj.kind)
        label = f'{sev} obj {obj.index:<4} [{obj.kind:<20}]'
        if obj.labels:
            first = obj.labels[0]
            if len(first) > 70:
                first = first[:67] + '...'
            label += f'  {first}'
        if key:
            label = f'{sev} {key:<14} → obj {obj.index:<4} [{obj.kind:<20}]'
            if obj.labels:
                first = obj.labels[0]
                if len(first) > 60:
                    first = first[:57] + '...'
                label += f'  {first}'
        return label

    def _walk(idx: int, key: str, depth: int, prefix: str, last: bool) -> None:
        if depth > max_depth:
            lines.append(prefix + '... (max depth)')
            return
        obj = latest.get(idx)
        if obj is None:
            lines.append(prefix + ('└─ ' if last else '├─ ') + f'{key} → obj {idx} (NOT FOUND)')
            return

        connector = '└─ ' if last else '├─ '
        line = _format_node(obj, key)
        lines.append(prefix + connector + line)

        if idx in visited:
            lines.append(prefix + ('   ' if last else '│  ') + '   (already walked; cycle suppressed)')
            return
        visited.add(idx)

        # Find keyed references (for structured display).
        # Pattern: "/Key  N G R" (the "key" is the preceding /Name).
        keyed_refs: list[tuple[str, int]] = []
        seen_positions: set[int] = set()
        for m in re.finditer(r'/(\w+)\s+(\d+)\s+(\d+)\s+R', obj.body):
            pos = m.start()
            if pos in seen_positions:
                continue
            seen_positions.add(pos)
            keyed_refs.append(('/' + m.group(1), int(m.group(2))))
        # Also surface bare refs inside arrays (e.g., /Kids [1 0 R 2 0 R])
        for m in re.finditer(r'\[([^\]]*)\]', obj.body):
            inner = m.group(1)
            for rm in RE_IREF.finditer(inner):
                ridx = int(rm.group(1))
                # Synthesize a key based on what precedes the bracket
                pre_start = max(0, m.start() - 25)
                pre_text = obj.body[pre_start:m.start()]
                array_key = re.search(r'/(\w+)\s*\[?\s*$', pre_text)
                label = '/' + array_key.group(1) + '[]' if array_key else '[]'
                key_tuple = (label, ridx)
                if key_tuple not in keyed_refs:
                    keyed_refs.append(key_tuple)

        for i, (k, child) in enumerate(keyed_refs):
            is_last = (i == len(keyed_refs) - 1)
            child_prefix = prefix + ('   ' if last else '│  ')
            _walk(child, k, depth + 1, child_prefix, is_last)

    # Root
    root_obj = latest.get(root_idx)
    if root_obj is None:
        lines.append(f'(obj {root_idx} not found)')
        return '\n'.join(lines) + '\n'

    lines.append(_format_node(root_obj, ''))
    visited.add(root_idx)
    # Walk children of root
    keyed = []
    for m in re.finditer(r'/(\w+)\s+(\d+)\s+(\d+)\s+R', root_obj.body):
        keyed.append(('/' + m.group(1), int(m.group(2))))
    for i, (k, child) in enumerate(keyed):
        is_last = (i == len(keyed) - 1)
        _walk(child, k, 1, '', is_last)

    return '\n'.join(lines) + '\n'
