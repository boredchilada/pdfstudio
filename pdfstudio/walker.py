"""
pdfstudio.walker
Traversal of the logical Catalog graph to identify active triggers and
their resolved targets.

Output: a list of TriggerHit records that the renderers consume.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .model import PDFFile, PDFObject


@dataclass
class TriggerHit:
    trigger: str                  # e.g. '/OpenAction'
    anchor_obj: int               # object where the trigger was found
    target_obj: Optional[int]     # what it points to (None if inline)
    path: str                     # human-readable chain (e.g. 'Catalog → OpenAction → obj 22 [Action:JavaScript]')
    detail: str = ''
    severity: str = 'MED'         # LOW / MED / HIGH


RE_IREF  = re.compile(r'(\d+)\s+(\d+)\s+R')
RE_OPENA = re.compile(r'/OpenAction\s*(<<[^>]+>>|\d+\s+\d+\s+R|\[[^\]]+\])', re.DOTALL)
RE_AA    = re.compile(r'/AA\s*<<\s*(.*?)\s*>>', re.DOTALL)
RE_AAKEY = re.compile(r'/(\w+)\s+(\d+)\s+\d+\s+R')
RE_ANNOTS= re.compile(r'/Annots\s*\[([^\]]+)\]', re.DOTALL)
RE_KIDS  = re.compile(r'/Kids\s*\[([^\]]+)\]', re.DOTALL)
RE_NAMES = re.compile(r'/Names\s+(\d+)\s+\d+\s+R')
RE_EFN   = re.compile(r'/EmbeddedFiles\s+(\d+)\s+\d+\s+R')
RE_A_REF = re.compile(r'/A\s+(\d+)\s+\d+\s+R')


def _resolve_ref(body: str) -> Optional[int]:
    """Return the first 'N G R' reference found in body, as integer index."""
    m = RE_IREF.search(body)
    return int(m.group(1)) if m else None


def walk(pdf: PDFFile) -> list[TriggerHit]:
    hits: list[TriggerHit] = []

    # Entry: Catalog via the latest trailer's /Root.
    if not pdf.trailers:
        return hits
    root = pdf.trailers[-1].root
    if not root:
        return hits
    catalog = pdf.obj(root[0], root[1])
    if catalog is None:
        return hits

    # /OpenAction on Catalog
    if (m := RE_OPENA.search(catalog.body)):
        val = m.group(1)
        tgt = _resolve_ref(val)
        if tgt is not None:
            tgt_obj = pdf.obj(tgt)
            kind = tgt_obj.kind if tgt_obj else '?'
            hits.append(TriggerHit(
                trigger='/OpenAction',
                anchor_obj=catalog.index,
                target_obj=tgt,
                path=f'Catalog (obj {catalog.index}) → /OpenAction → obj {tgt} [{kind}]',
                detail=(tgt_obj.body.strip()[:160] if tgt_obj else ''),
                severity='HIGH' if kind in ('Action:JavaScript', 'Action:Launch') else 'MED',
            ))
        elif val.startswith('<<'):
            hits.append(TriggerHit(
                trigger='/OpenAction',
                anchor_obj=catalog.index,
                target_obj=None,
                path=f'Catalog (obj {catalog.index}) → /OpenAction inline action',
                detail=val[:160],
                severity='MED',
            ))
        else:
            # destination array (e.g. [1 0 R /XYZ null null 0]) — view-only, not an action
            hits.append(TriggerHit(
                trigger='/OpenAction',
                anchor_obj=catalog.index,
                target_obj=None,
                path=f'Catalog (obj {catalog.index}) → /OpenAction destination (/XYZ view coord, not an action)',
                detail=val[:120],
                severity='LOW',
            ))

    # /Names /EmbeddedFiles from Catalog
    if (m := RE_NAMES.search(catalog.body)):
        names_obj = pdf.obj(int(m.group(1)))
        if names_obj and (mef := RE_EFN.search(names_obj.body)):
            efroot = pdf.obj(int(mef.group(1)))
            hits.append(TriggerHit(
                trigger='/Names/EmbeddedFiles',
                anchor_obj=catalog.index,
                target_obj=efroot.index if efroot else None,
                path=f'Catalog → /Names → obj {names_obj.index} → /EmbeddedFiles → obj {efroot.index if efroot else "?"}',
                detail='',
                severity='HIGH',
            ))

    # Walk page tree from /Pages
    pages_idx = None
    mp = re.search(r'/Pages\s+(\d+)\s+\d+\s+R', catalog.body)
    if mp:
        pages_idx = int(mp.group(1))
    if pages_idx is not None:
        stack = [pages_idx]
        visited: set[int] = set()
        while stack:
            idx = stack.pop()
            if idx in visited:
                continue
            visited.add(idx)
            node = pdf.obj(idx)
            if node is None:
                continue

            if node.kind == 'Pages':
                if (mk := RE_KIDS.search(node.body)):
                    for km in RE_IREF.finditer(mk.group(1)):
                        stack.append(int(km.group(1)))
            elif node.kind == 'Page':
                # /AA additional-actions on the page
                if (ma := RE_AA.search(node.body)):
                    for keym, tgt in RE_AAKEY.findall(ma.group(1)):
                        tgt_obj = pdf.obj(int(tgt))
                        kind = tgt_obj.kind if tgt_obj else '?'
                        hits.append(TriggerHit(
                            trigger=f'/AA /{keym}',
                            anchor_obj=node.index,
                            target_obj=int(tgt),
                            path=f'Page (obj {node.index}) → /AA /{keym} → obj {tgt} [{kind}]',
                            detail=(tgt_obj.body.strip()[:160] if tgt_obj else ''),
                            severity='HIGH' if kind in ('Action:JavaScript', 'Action:Launch') else 'MED',
                        ))
                # /Annots on the page
                if (mann := RE_ANNOTS.search(node.body)):
                    for am in RE_IREF.finditer(mann.group(1)):
                        aidx = int(am.group(1))
                        aobj = pdf.obj(aidx)
                        if not aobj:
                            continue
                        if aobj.kind.startswith('Annot'):
                            # Resolve /A action reference if present
                            act_ref = None
                            if (ar := RE_A_REF.search(aobj.body)):
                                act_ref = int(ar.group(1))
                            if act_ref is not None:
                                act = pdf.obj(act_ref)
                                akind = act.kind if act else '?'
                                hits.append(TriggerHit(
                                    trigger='/Annot /A',
                                    anchor_obj=aobj.index,
                                    target_obj=act_ref,
                                    path=f'Page → obj {aobj.index} [{aobj.kind}] → /A → obj {act_ref} [{akind}]',
                                    detail=(act.body.strip()[:160] if act else ''),
                                    severity='MED',
                                ))
                            else:
                                hits.append(TriggerHit(
                                    trigger='/Annot',
                                    anchor_obj=aobj.index,
                                    target_obj=None,
                                    path=f'Page → obj {aobj.index} [{aobj.kind}]',
                                    detail=aobj.body.strip()[:160],
                                    severity='LOW',
                                ))

    return hits
