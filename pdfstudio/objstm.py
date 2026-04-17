"""
pdfstudio.objstm
Expand /ObjStm (object stream) contents.

Adobe Systems (2008), §7.5.7:
  - /Type /ObjStm
  - /N    : number of compressed objects stored
  - /First: byte offset of the first object within the decoded stream data
  - The stream's decoded body begins with N pairs of integers:
        objNum1 offset1 objNum2 offset2 ... objNumN offsetN
    where offsetK is relative to /First (i.e. object K body starts at
    decoded[first + offsetK]).

This module returns synthetic PDFObject instances (generation = 0) for
each compressed child. They are added to PDFFile.objects with revision
inherited from the wrapper.
"""
from __future__ import annotations

import hashlib
import re
from typing import Optional

from .model import PDFFile, PDFObject


RE_N     = re.compile(r'/N\s+(\d+)')
RE_FIRST = re.compile(r'/First\s+(\d+)')
RE_INT   = re.compile(rb'\s*(\d+)\s+(\d+)')


def expand_objstm_all(pdf: PDFFile) -> int:
    """Expand every /ObjStm object in pdf. Returns count of new objects."""
    added_total = 0
    for wrapper in [o for o in pdf.objects if o.kind == 'ObjStm']:
        added_total += _expand_one(pdf, wrapper)
    return added_total


def _expand_one(pdf: PDFFile, wrapper: PDFObject) -> int:
    if wrapper.stream is None or wrapper.stream.decoded_bytes is None:
        return 0
    mN = RE_N.search(wrapper.body)
    mF = RE_FIRST.search(wrapper.body)
    if not mN or not mF:
        return 0
    n = int(mN.group(1))
    first = int(mF.group(1))

    data = wrapper.stream.decoded_bytes
    # Parse the N (objNum, offset) header pairs
    pairs: list[tuple[int, int]] = []
    cursor = 0
    for _ in range(n):
        # consume whitespace, then read two integers
        m = re.match(rb'\s*(\d+)\s+(\d+)', data[cursor:])
        if not m:
            return 0
        pairs.append((int(m.group(1)), int(m.group(2))))
        cursor += m.end()

    # For each pair, slice out the child body
    added = 0
    for k, (child_idx, child_off) in enumerate(pairs):
        start = first + child_off
        end = (first + pairs[k + 1][1]) if k + 1 < len(pairs) else len(data)
        child_body_bytes = data[start:end]
        child_body = child_body_bytes.decode('latin-1', errors='replace').strip()

        # Build a synthetic PDFObject. Offset is the wrapper's start so
        # analysts can always locate the source container.
        child = PDFObject(
            index=child_idx,
            generation=0,
            offset=wrapper.offset,  # wrapper offset — real body is inside wrapper's stream
            end_offset=wrapper.offset + wrapper.raw_length,
            body=child_body,
            raw_length=len(child_body_bytes),
        )
        child.md5 = hashlib.md5(child_body.encode('latin-1', errors='replace')).hexdigest()
        child.revision = wrapper.revision
        child.labels.append(f'ObjStm-child in obj {wrapper.index}')
        pdf.objects.append(child)
        added += 1
    return added
