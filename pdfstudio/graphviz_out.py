"""
pdfstudio.graphviz_out
Catalog/Page/Action graph exporters — Mermaid and Graphviz DOT.

Nodes   = objects (showing index + kind + key label)
Edges   = indirect references

These outputs let an analyst paste the graph into a Markdown doc (Mermaid)
or render it with `dot` (Graphviz).
"""
from __future__ import annotations

import re

from .model import PDFFile


_REF_RE = re.compile(r'(\d+)\s+(\d+)\s+R')


def _kind_style_mermaid(kind: str) -> str:
    """Return a Mermaid classDef suffix suitable for the given kind."""
    if kind.startswith('Action:Launch') or kind == 'Action:JavaScript':
        return 'danger'
    if kind.startswith('Action:'):
        return 'action'
    if kind.startswith('Annot'):
        return 'annot'
    if kind in ('Catalog',):
        return 'root'
    if kind in ('Page', 'Pages'):
        return 'page'
    if kind in ('Filespec', 'EmbeddedFile'):
        return 'embedded'
    if kind == 'Stream':
        return 'stream'
    return 'generic'


_MERMAID_CLASS_DEFS = """\
    classDef root     fill:#FFE082,stroke:#F57F17,color:#202020
    classDef page     fill:#BBDEFB,stroke:#1565C0,color:#202020
    classDef annot    fill:#FFCDD2,stroke:#B71C1C,color:#202020
    classDef action   fill:#FFAB91,stroke:#BF360C,color:#202020
    classDef danger   fill:#FF8A80,stroke:#B71C1C,color:#202020,stroke-width:2px
    classDef embedded fill:#E1BEE7,stroke:#4A148C,color:#202020
    classDef stream   fill:#E0E0E0,stroke:#424242,color:#202020
    classDef generic  fill:#F5F5F5,stroke:#9E9E9E,color:#202020
"""


def render_mermaid(pdf: PDFFile, *, only_interesting: bool = True) -> str:
    """Emit a Mermaid flowchart of the object reference graph.

    `only_interesting=True` reachable from Catalog through /OpenAction, /AA,
    /Names/EmbeddedFiles, and /Annots → /A, skipping pure layout / font nodes.
    Set False for the full object graph.
    """
    if not pdf.trailers or not pdf.trailers[-1].root:
        return 'flowchart TD\n    note["(no Catalog /Root found)"]\n'

    # Choose which objects to include
    latest: dict[int, object] = {}
    for o in pdf.objects:
        cur = latest.get(o.index)
        if cur is None or o.revision >= cur.revision:
            latest[o.index] = o
    objs_by_idx = latest

    included: set[int] = set()
    edges: list[tuple[int, int, str]] = []

    def add_edge(src: int, dst: int, label: str = '') -> None:
        if dst in objs_by_idx:
            edges.append((src, dst, label))
            included.add(src)
            included.add(dst)

    def walk_refs(obj) -> list[tuple[int, str]]:
        refs = []
        for m in _REF_RE.finditer(obj.body):
            refs.append((int(m.group(1)), ''))
        return refs

    if only_interesting:
        root_idx = pdf.trailers[-1].root[0]
        stack = [root_idx]
        visited = set()
        while stack:
            idx = stack.pop()
            if idx in visited:
                continue
            visited.add(idx)
            obj = objs_by_idx.get(idx)
            if obj is None:
                continue
            included.add(idx)
            for ref_idx, _ in walk_refs(obj):
                # keep edges only to objects that look interesting in this context
                target = objs_by_idx.get(ref_idx)
                if not target:
                    continue
                skip = target.kind in ('Font', 'Metadata') and obj.kind != 'Catalog'
                if skip:
                    continue
                add_edge(idx, ref_idx)
                stack.append(ref_idx)
    else:
        for idx, obj in objs_by_idx.items():
            included.add(idx)
            for ref_idx, _ in walk_refs(obj):
                if ref_idx in objs_by_idx:
                    add_edge(idx, ref_idx)

    # Build Mermaid text
    lines = ['flowchart TD']
    for idx in sorted(included):
        obj = objs_by_idx[idx]
        label_bits = [f'obj {idx}', obj.kind]
        if obj.labels:
            first_label = obj.labels[0]
            if len(first_label) > 40:
                first_label = first_label[:37] + '...'
            label_bits.append(first_label)
        label = '<br/>'.join(label_bits).replace('"', "'")
        lines.append(f'    N{idx}["{label}"]:::{_kind_style_mermaid(obj.kind)}')
    for src, dst, lab in edges:
        if lab:
            lines.append(f'    N{src} -->|{lab}| N{dst}')
        else:
            lines.append(f'    N{src} --> N{dst}')
    lines.append(_MERMAID_CLASS_DEFS)
    return '\n'.join(lines) + '\n'


def render_dot(pdf: PDFFile, *, only_interesting: bool = True) -> str:
    """Emit a Graphviz DOT description (same graph as Mermaid)."""
    if not pdf.trailers or not pdf.trailers[-1].root:
        return 'digraph G { note [label="(no /Root)"]; }\n'

    # Re-use Mermaid's traversal by calling it and re-formatting? cleaner: own traversal.
    latest: dict[int, object] = {}
    for o in pdf.objects:
        cur = latest.get(o.index)
        if cur is None or o.revision >= cur.revision:
            latest[o.index] = o
    objs_by_idx = latest

    included: set[int] = set()
    edges: list[tuple[int, int]] = []

    def walk_refs(obj) -> list[int]:
        return [int(m.group(1)) for m in _REF_RE.finditer(obj.body)]

    if only_interesting:
        root_idx = pdf.trailers[-1].root[0]
        stack = [root_idx]
        visited = set()
        while stack:
            idx = stack.pop()
            if idx in visited:
                continue
            visited.add(idx)
            obj = objs_by_idx.get(idx)
            if obj is None:
                continue
            included.add(idx)
            for ref_idx in walk_refs(obj):
                target = objs_by_idx.get(ref_idx)
                if not target:
                    continue
                if target.kind in ('Font', 'Metadata') and obj.kind != 'Catalog':
                    continue
                edges.append((idx, ref_idx))
                included.add(ref_idx)
                stack.append(ref_idx)
    else:
        for idx, obj in objs_by_idx.items():
            included.add(idx)
            for ref_idx in walk_refs(obj):
                if ref_idx in objs_by_idx:
                    edges.append((idx, ref_idx))

    color = {
        'Catalog': '#FFE082', 'Page': '#BBDEFB', 'Pages': '#BBDEFB',
        'Annot': '#FFCDD2', 'Action:URI': '#FFAB91',
        'Action:Launch': '#FF8A80', 'Action:JavaScript': '#FF8A80',
        'Filespec': '#E1BEE7', 'EmbeddedFile': '#E1BEE7',
        'Stream': '#E0E0E0',
    }

    lines = ['digraph G {', '    rankdir=TB;', '    node [shape=box, style=filled, fontname="Segoe UI"];']
    for idx in sorted(included):
        obj = objs_by_idx[idx]
        fill = color.get(obj.kind) or '#F5F5F5'
        for k, v in color.items():
            if obj.kind.startswith(k):
                fill = v
                break
        label_bits = [f'obj {idx}', obj.kind]
        if obj.labels:
            lb = obj.labels[0]
            if len(lb) > 44:
                lb = lb[:41] + '...'
            label_bits.append(lb)
        label = '\\n'.join(label_bits).replace('"', "'")
        lines.append(f'    N{idx} [label="{label}" fillcolor="{fill}"];')
    for src, dst in edges:
        lines.append(f'    N{src} -> N{dst};')
    lines.append('}')
    return '\n'.join(lines) + '\n'
