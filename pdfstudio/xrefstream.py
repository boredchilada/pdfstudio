"""
pdfstudio.xrefstream
Parse /XRef cross-reference streams (PDF 1.5+).

Per Adobe Systems (2008), §7.5.8, an xref stream is an indirect object
whose dictionary declares:
    /Type   /XRef
    /W      [ type_width field1_width field2_width ]   — binary field widths
    /Size   total_entries
    /Index  [ first entry_count  (first entry_count)* ] (optional; default [0 Size])

The decoded stream body is a packed byte array of `Size` records
(type, field1, field2). Decoded entry kinds:
    type 0 : free entry               (field1 = next free, field2 = next gen)
    type 1 : normal in-use entry       (field1 = byte offset, field2 = generation)
    type 2 : compressed in-use entry   (field1 = ObjStm number, field2 = index in ObjStm)

This module exposes:
    parse_xref_streams(pdf) -> list[XRefRecord]
and appends a virtual Trailer per xref stream to pdf.trailers so the
revision reconstruction picks them up.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .model import PDFFile, PDFObject, Trailer


@dataclass
class XRefRecord:
    wrapper_obj: int
    entries: list[tuple[int, int, int, int]]   # (obj_number, type, field1, field2)
    size: Optional[int] = None


RE_W     = re.compile(r'/W\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s*\]')
RE_INDEX = re.compile(r'/Index\s*\[([^\]]+)\]', re.DOTALL)
RE_INT   = re.compile(r'\d+')
RE_SIZE  = re.compile(r'/Size\s+(\d+)')
RE_PREV  = re.compile(r'/Prev\s+(\d+)')
RE_ROOT  = re.compile(r'/Root\s+(\d+)\s+(\d+)\s+R')


def _read_int(data: bytes, off: int, width: int) -> int:
    if width == 0:
        return 0
    n = 0
    for i in range(width):
        n = (n << 8) | data[off + i]
    return n


def parse_xref_streams(pdf: PDFFile) -> list[XRefRecord]:
    """Parse every /XRef stream. Returns per-wrapper records.

    Also appends synthetic Trailer entries so revision reconstruction
    can treat xref-stream revisions just like classic-xref revisions.
    """
    results: list[XRefRecord] = []

    for obj in list(pdf.objects):
        if obj.kind != 'XRefStream' or obj.stream is None:
            continue
        data = obj.stream.decoded_bytes
        if data is None:
            continue

        mW = RE_W.search(obj.body)
        if not mW:
            continue
        w1, w2, w3 = (int(mW.group(i)) for i in (1, 2, 3))
        entry_size = w1 + w2 + w3
        if entry_size == 0:
            continue

        size_m = RE_SIZE.search(obj.body)
        total = int(size_m.group(1)) if size_m else None

        if (mI := RE_INDEX.search(obj.body)):
            nums = [int(x) for x in RE_INT.findall(mI.group(1))]
            index_pairs = list(zip(nums[0::2], nums[1::2]))
        else:
            index_pairs = [(0, total or (len(data) // entry_size))]

        entries: list[tuple[int, int, int, int]] = []
        cursor = 0
        for first, count in index_pairs:
            for k in range(count):
                if cursor + entry_size > len(data):
                    break
                t = _read_int(data, cursor, w1) if w1 else 1  # default type=1
                f1 = _read_int(data, cursor + w1, w2)
                f2 = _read_int(data, cursor + w1 + w2, w3)
                cursor += entry_size
                entries.append((first + k, t, f1, f2))

        results.append(XRefRecord(wrapper_obj=obj.index, entries=entries, size=total))

        # Build a synthetic Trailer from the xref-stream dict so the
        # revision reconstruction treats it as a proper revision boundary.
        eof_after = pdf.size
        for eof in sorted(pdf.eof_offsets):
            if eof > obj.offset:
                eof_after = eof
                break
        tr = Trailer(
            offset=obj.offset,
            body=obj.body,
            startxref=obj.offset,      # for xref streams the startxref points to the xref-stream obj itself
            eof_offset=eof_after,
            size=total,
        )
        if (pm := RE_PREV.search(obj.body)):
            tr.prev = int(pm.group(1))
        if (rm := RE_ROOT.search(obj.body)):
            tr.root = (int(rm.group(1)), int(rm.group(2)))
        # Only add if we don't already have a trailer at this startxref.
        if not any(t.startxref == tr.startxref for t in pdf.trailers):
            pdf.trailers.append(tr)

    return results


def compressed_object_map(records: list[XRefRecord]) -> dict[int, tuple[int, int]]:
    """Return {obj_number: (objstm_number, index_within_objstm)} for all
    type-2 entries across every xref stream."""
    out: dict[int, tuple[int, int]] = {}
    for rec in records:
        for obj_num, t, f1, f2 in rec.entries:
            if t == 2:
                out[obj_num] = (f1, f2)
    return out
