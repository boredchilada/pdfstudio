"""
pdfstudio.rects_svg
Render each page's /MediaBox together with all its /Annot /Rect overlays
as a standalone SVG. Clickable link rectangles are highlighted in red,
labelled with the target URI or the action kind.

    render_svg(pdf) -> str
"""
from __future__ import annotations

import html
import re

from .model import PDFFile


RE_MEDIA = re.compile(r'/MediaBox\s*\[\s*(-?\d[\d\.\-\s]*)\]')
RE_ANN_INLINE = re.compile(r'/Annots\s*\[([^\]]+)\]', re.DOTALL)
RE_ANN_INDIRECT = re.compile(r'/Annots\s+(\d+)\s+(\d+)\s+R')
RE_INLINE_ARRAY = re.compile(r'\[([^\]]+)\]', re.DOTALL)
RE_IREF = re.compile(r'(\d+)\s+(\d+)\s+R')
RE_RECT = re.compile(r'/Rect\s*\[\s*(-?\d[\d\.\-\s]*)\]')
RE_A_REF = re.compile(r'/A\s+(\d+)\s+\d+\s+R')
RE_URI_INLINE = re.compile(r'/URI\s*\(([^)]*)\)')
RE_S = re.compile(r'/S\s*(/\w+)')


def _pages(pdf: PDFFile):
    return [o for o in pdf.objects if o.kind == 'Page']


def _parse_box(text: str) -> list[float]:
    parts = [float(x) for x in text.split()]
    return parts if len(parts) == 4 else []


def _annot_info(pdf: PDFFile, annot) -> dict:
    """Resolve a Link annotation's action: URI string or action kind."""
    info = {'rect': [], 'label': '', 'kind': annot.kind}
    mrect = RE_RECT.search(annot.body)
    if mrect:
        info['rect'] = _parse_box(mrect.group(1))

    # Inline URI
    mu = RE_URI_INLINE.search(annot.body)
    if mu:
        info['label'] = mu.group(1)
        info['kind'] = 'Annot:Link→URI'
        return info

    # Indirect /A action
    m = RE_A_REF.search(annot.body)
    if m:
        act = pdf.obj(int(m.group(1)))
        if act is not None:
            ms = RE_S.search(act.body)
            if ms:
                info['kind'] = 'Annot:Link→' + ms.group(1).lstrip('/')
            mua = RE_URI_INLINE.search(act.body)
            if mua:
                info['label'] = mua.group(1)
    return info


def render_svg(pdf: PDFFile, *, max_px_width: int = 800) -> str:
    pages = _pages(pdf)
    if not pages:
        return '<svg xmlns="http://www.w3.org/2000/svg" width="300" height="40">' \
               '<text x="10" y="25" font-family="Consolas" font-size="13">(no pages found)</text></svg>'

    # For each page, collect its rect + annotations
    blocks = []
    for page in pages:
        mb = RE_MEDIA.search(page.body)
        if not mb:
            continue
        box = _parse_box(mb.group(1))
        if not box:
            continue
        x0, y0, x1, y1 = box
        pw, ph = abs(x1 - x0), abs(y1 - y0)

        # Collect annotations — /Annots can be inline [N G R ...] or indirect N G R
        annot_body = None
        if (mi := RE_ANN_INLINE.search(page.body)):
            annot_body = mi.group(1)
        elif (md := RE_ANN_INDIRECT.search(page.body)):
            referent = pdf.obj(int(md.group(1)))
            if referent is not None:
                # If the referent is an array, use its contents; otherwise assume it IS one annot
                arr = RE_INLINE_ARRAY.search(referent.body)
                if arr:
                    annot_body = arr.group(1)
                else:
                    annot_body = f'{md.group(1)} {md.group(2)} R'

        annots = []
        if annot_body:
            for m in RE_IREF.finditer(annot_body):
                aobj = pdf.obj(int(m.group(1)))
                if aobj and aobj.kind.startswith('Annot'):
                    annots.append(_annot_info(pdf, aobj))

        blocks.append({
            'page_obj': page.index,
            'box': (x0, y0, x1, y1),
            'pw': pw, 'ph': ph,
            'annots': annots,
        })

    if not blocks:
        return '<svg xmlns="http://www.w3.org/2000/svg" width="300" height="40">' \
               '<text x="10" y="25">(no pages with /MediaBox)</text></svg>'

    # Scale pages to fit within max_px_width (keep individual page aspect)
    # Stack pages vertically.
    margin = 30
    label_h = 24
    svg_parts = []
    total_height = margin
    widest = max(b['pw'] for b in blocks)
    scale = (max_px_width - 2 * margin) / widest if widest else 1.0

    # Compute per-page dimensions
    for b in blocks:
        pw_px = b['pw'] * scale
        ph_px = b['ph'] * scale
        total_height += label_h + int(ph_px) + 20

    svg_parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{max_px_width}" '
        f'height="{int(total_height)}" font-family="Segoe UI, Calibri, sans-serif" '
        f'font-size="12">'
    )
    svg_parts.append(f'<rect x="0" y="0" width="{max_px_width}" height="{int(total_height)}" fill="#FAFAFA"/>')

    y_cursor = margin
    for b in blocks:
        pw_px = b['pw'] * scale
        ph_px = b['ph'] * scale
        px_x = (max_px_width - pw_px) / 2

        # Page label
        svg_parts.append(
            f'<text x="{px_x}" y="{y_cursor - 4}" fill="#202020" font-weight="bold">'
            f'Page — obj {b["page_obj"]} — MediaBox [{b["box"][0]:g} {b["box"][1]:g} {b["box"][2]:g} {b["box"][3]:g}] '
            f'({b["pw"]:.0f}×{b["ph"]:.0f} pt)</text>'
        )
        y_cursor += 6

        # Page border
        svg_parts.append(
            f'<rect x="{px_x}" y="{y_cursor}" width="{pw_px}" height="{ph_px}" '
            f'fill="#FFFFFF" stroke="#BDBDBD" stroke-width="1"/>'
        )

        # Annotation rects (PDF coords: origin bottom-left; SVG: top-left)
        x0, y0, x1, y1 = b['box']
        for a in b['annots']:
            rect = a['rect']
            if len(rect) != 4:
                continue
            rx0, ry0, rx1, ry1 = rect
            # Normalize so rx0<rx1 and ry0<ry1
            lx, ly = min(rx0, rx1), min(ry0, ry1)
            rw = abs(rx1 - rx0)
            rh = abs(ry1 - ry0)
            # Flip Y for SVG
            svg_x = px_x + (lx - x0) * scale
            svg_y = y_cursor + (y1 - (ly + rh)) * scale
            svg_w = rw * scale
            svg_h = rh * scale
            cov = (rw * rh) / (b['pw'] * b['ph']) if (b['pw'] and b['ph']) else 0

            # Colour logic: URI red, Launch dark red, GoTo blue, other orange
            kind = a['kind']
            if kind.endswith('Launch'):
                fill = 'rgba(255, 60, 60, 0.35)'; stroke = '#B71C1C'
            elif 'URI' in kind:
                fill = 'rgba(255, 82, 82, 0.25)'; stroke = '#D32F2F'
            elif kind.endswith('GoTo') or kind.endswith('GoToR'):
                fill = 'rgba(82, 121, 245, 0.22)'; stroke = '#1565C0'
            else:
                fill = 'rgba(255, 176, 64, 0.22)'; stroke = '#E65100'

            svg_parts.append(
                f'<rect x="{svg_x:.2f}" y="{svg_y:.2f}" '
                f'width="{svg_w:.2f}" height="{svg_h:.2f}" '
                f'fill="{fill}" stroke="{stroke}" stroke-width="1.4" stroke-dasharray="4,2"/>'
            )
            # Label inside the rect if it fits
            label = a['label'] or kind
            label_esc = html.escape(label[:80])
            cov_str = f' ({cov*100:.0f}% of page)'
            svg_parts.append(
                f'<text x="{svg_x + 6:.2f}" y="{svg_y + 14:.2f}" '
                f'fill="#202020" font-weight="bold">{label_esc}{cov_str}</text>'
            )

        y_cursor += ph_px + label_h

    svg_parts.append('</svg>')
    return '\n'.join(svg_parts) + '\n'
