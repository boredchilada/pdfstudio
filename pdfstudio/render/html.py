"""
pdfstudio.render.html
Static single-file HTML report. No external assets, no JS required.

Layout mirrors the text renderer:
    - Top card: file identity + summary tiles
    - Byte map: horizontal strip coloured by revision
    - Revisions table
    - Objects table (sortable via <details>)
    - Triggers walker
    - Flags panel
"""
from __future__ import annotations

import html as _html
import os
from collections import Counter

from ..model import PDFFile
from ..walker import TriggerHit


_CSS = """
* { box-sizing: border-box; }
body { font-family: 'Segoe UI', Calibri, sans-serif; background: #111; color: #E0E0E0; margin: 0; padding: 24px; font-size: 14px; }
h1, h2, h3 { color: #3DD879; margin: 18px 0 6px 0; }
h1 { font-size: 22px; border-bottom: 1px solid #333; padding-bottom: 6px; }
h2 { font-size: 16px; }
code, pre, .mono { font-family: Consolas, 'Courier New', monospace; font-size: 12.5px; }
.card { background: #1A1A1A; border: 1px solid #2A2A2A; border-radius: 6px; padding: 14px 18px; margin-bottom: 16px; }
.tiles { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 10px; }
.tile { background: #202020; border: 1px solid #2A2A2A; border-radius: 4px; padding: 8px 12px; }
.tile .k { color: #888; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
.tile .v { color: #FFFFFF; font-size: 15px; font-family: Consolas, monospace; }

.bytemap { width: 100%; height: 36px; display: flex; border: 1px solid #333; border-radius: 3px; overflow: hidden; margin-top: 8px; }
.bytemap .band { position: relative; overflow: hidden; }
.bytemap .band span { position: absolute; bottom: 2px; left: 4px; color: rgba(255,255,255,0.85); font-size: 10px; font-family: Consolas; text-shadow: 0 1px 2px rgba(0,0,0,0.8); }

table { width: 100%; border-collapse: collapse; margin-top: 6px; }
th { background: #222; color: #3DD879; text-align: left; padding: 6px 10px; font-size: 12px; border-bottom: 1px solid #333; }
td { padding: 5px 10px; border-bottom: 1px solid #252525; font-family: Consolas, monospace; font-size: 12.5px; color: #D0D0D0; vertical-align: top; word-break: break-word; }
tr:nth-child(even) td { background: #181818; }

.kind-Catalog      { color: #FFD740; }
.kind-Page         { color: #82B1FF; }
.kind-Pages        { color: #82B1FF; }
.kind-Annot-Link   { color: #FF8A80; }
.kind-AnnotLink    { color: #FF8A80; }
.kind-Action-Launch, .kind-ActionLaunch { color: #FF5252; font-weight: bold; }
.kind-Action-JavaScript, .kind-ActionJavaScript { color: #FF5252; font-weight: bold; }
.kind-Action-URI, .kind-ActionURI { color: #FFAB40; }
.kind-Filespec     { color: #EA80FC; }
.kind-EmbeddedFile { color: #EA80FC; font-weight: bold; }
.kind-Stream       { color: #9E9E9E; }

.sev-HIGH { color: #FF5252; font-weight: bold; }
.sev-MED  { color: #FFB040; }
.sev-LOW  { color: #82B1FF; }
.sev-INFO { color: #888; }

.trigger { padding: 6px 10px; border-left: 3px solid #444; margin-bottom: 6px; background: #181818; }
.trigger.HIGH { border-left-color: #FF5252; }
.trigger.MED  { border-left-color: #FFB040; }
.trigger.LOW  { border-left-color: #82B1FF; }
.trigger .path { font-family: Consolas, monospace; color: #E0E0E0; }
.trigger .detail { color: #888; font-family: Consolas, monospace; font-size: 11.5px; margin-top: 2px; white-space: pre-wrap; }

.flags-list { list-style: none; padding: 0; margin: 0; }
.flags-list li { padding: 6px 10px; border-left: 3px solid #444; margin-bottom: 4px; background: #181818; }
.flags-list li.HIGH { border-left-color: #FF5252; }
.flags-list li.MED  { border-left-color: #FFB040; }
.flags-list li.LOW  { border-left-color: #82B1FF; }
.flags-list li.INFO { border-left-color: #666; }
.flags-list .code { color: #3DD879; font-family: Consolas, monospace; margin-right: 10px; }

footer { color: #555; font-size: 11px; margin-top: 32px; text-align: center; }
"""

REV_COLORS = ['#1E3A5F', '#5F3A1E', '#1E5F3A', '#5F1E3A', '#3A1E5F', '#5F5F1E']


def _safe_kind(kind: str) -> str:
    return 'kind-' + kind.replace(':', '-').replace(' ', '')


def _tile(key: str, value: str) -> str:
    return f'<div class="tile"><div class="k">{_html.escape(key)}</div><div class="v">{_html.escape(str(value))}</div></div>'


def _bytemap(pdf: PDFFile) -> str:
    if not pdf.revisions:
        return '<div class="bytemap"><div class="band" style="flex:1;background:#333;">' \
               f'<span>{pdf.size:,} B</span></div></div>'
    parts = []
    total = pdf.size or 1
    for r in pdf.revisions:
        lo, hi = r.byte_range
        span = max(1, hi - lo)
        frac = span / total
        color = REV_COLORS[r.index % len(REV_COLORS)]
        label = f'v{r.index}  {lo:#x}–{hi:#x}  {span:,} B'
        parts.append(
            f'<div class="band" style="flex:{frac}; background:{color};">'
            f'<span>{_html.escape(label)}</span></div>'
        )
    return '<div class="bytemap">' + ''.join(parts) + '</div>'


def render(pdf: PDFFile, hits: list[TriggerHit]) -> str:
    name = os.path.basename(pdf.path)

    # Summary stats
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

    tiles = ''.join([
        _tile('Size', f'{pdf.size:,} B'),
        _tile('Header', pdf.header or '(none)'),
        _tile('Revisions', str(len(pdf.revisions))),
        _tile('%%EOF', str(len(pdf.eof_offsets))),
        _tile('Objects', str(len(pdf.objects))),
        _tile('Streams', f'{stream_count} ({filters_str})'),
        _tile('Annotations', str(annot_count)),
        _tile('Actions', str(action_count)),
    ])

    # Revisions table
    if pdf.revisions:
        rev_rows = []
        for r in pdf.revisions:
            new_s = ', '.join(str(i) for i in sorted(r.new_objects)) or '—'
            rw_s  = ', '.join(str(i) for i in sorted(r.rewritten_objects)) or '—'
            prev_s = str(r.trailer.prev) if r.trailer.prev is not None else '—'
            rev_rows.append(
                f'<tr><td>v{r.index}</td><td>{r.trailer.startxref}</td>'
                f'<td>{r.trailer.size if r.trailer.size is not None else "—"}</td>'
                f'<td>{prev_s}</td><td>{_html.escape(new_s)}</td><td>{_html.escape(rw_s)}</td></tr>'
            )
        rev_table = (
            '<table><thead><tr><th>Rev</th><th>startxref</th><th>/Size</th>'
            '<th>/Prev</th><th>New objects</th><th>Rewritten objects</th></tr></thead>'
            '<tbody>' + ''.join(rev_rows) + '</tbody></table>'
        )
    else:
        rev_table = '<em>No trailers parsed.</em>'

    # Objects table
    obj_rows = []
    for o in sorted(pdf.objects, key=lambda x: (x.revision, x.index)):
        labels = '; '.join(o.labels) if o.labels else ''
        stream_tag = '[S]' if o.stream else ''
        obj_rows.append(
            f'<tr><td>{o.index}</td><td>v{o.revision}</td>'
            f'<td>{o.offset:#x}</td><td>{o.raw_length}</td>'
            f'<td>{o.md5[:10]}</td>'
            f'<td class="{_safe_kind(o.kind)}">{_html.escape(o.kind)} {stream_tag}</td>'
            f'<td>{_html.escape(labels)}</td></tr>'
        )
    obj_table = (
        '<table><thead><tr><th>ID</th><th>Rev</th><th>Offset</th><th>Len</th>'
        '<th>MD5</th><th>Kind</th><th>Labels</th></tr></thead>'
        '<tbody>' + ''.join(obj_rows) + '</tbody></table>'
    )

    # Triggers
    if hits:
        trig_blocks = []
        for h in hits:
            trig_blocks.append(
                f'<div class="trigger {h.severity}">'
                f'<div class="path">{_html.escape(h.path)}</div>'
                + (f'<div class="detail">{_html.escape(h.detail)}</div>' if h.detail else '')
                + '</div>'
            )
        trig_html = ''.join(trig_blocks)
    else:
        trig_html = '<em>No active triggers found.</em>'

    # Flags
    if pdf.flags:
        order = {'HIGH': 0, 'MED': 1, 'LOW': 2, 'INFO': 3}
        sorted_flags = sorted(pdf.flags, key=lambda x: order.get(x[0], 99))
        flag_items = ''.join(
            f'<li class="{sev}"><span class="sev-{sev}">[{sev}]</span> '
            f'<span class="code">{_html.escape(code)}</span>{_html.escape(msg)}</li>'
            for sev, code, msg in sorted_flags
        )
        flags_html = f'<ul class="flags-list">{flag_items}</ul>'
    else:
        flags_html = '<em>No flags raised.</em>'

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>pdfstudio — {_html.escape(name)}</title>
<style>{_CSS}</style>
</head>
<body>
<h1>pdfstudio &nbsp;•&nbsp; {_html.escape(name)}</h1>

<div class="card">
  <h2>Summary</h2>
  <div class="tiles">{tiles}</div>
  <h2 style="margin-top:18px;">Byte map (revisions)</h2>
  {_bytemap(pdf)}
</div>

<div class="card">
  <h2>Revisions</h2>
  {rev_table}
</div>

<div class="card">
  <h2>Objects</h2>
  {obj_table}
</div>

<div class="card">
  <h2>Triggers (Catalog graph walk)</h2>
  {trig_html}
</div>

<div class="card">
  <h2>Flags</h2>
  {flags_html}
</div>

<footer>pdfstudio 0.1.0 &nbsp;•&nbsp; static structure viewer &nbsp;•&nbsp; generated by a single-file CLI</footer>
</body>
</html>
'''
