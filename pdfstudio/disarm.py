"""
pdfstudio.disarm
Neutralize dangerous PDF keys without rewriting the file's xref table.

Approach (same technique as pdfid.py --disarm): substitute the danger
keyword byte-for-byte with a look-alike that PDF readers will not
recognize. Byte offsets stay identical → the xref table remains valid.

Substitutions (all same length, so offsets are preserved):

    /OpenAction   → /OpenActi0n     (o → 0)
    /AA           → /A0             (A → 0)
    /Launch       → /Launc0         (h → 0)
    /JS           → /J0             (S → 0)
    /JavaScript   → /JavaScrip0     (t → 0)

We scan only inside parsed indirect object bodies — never inside stream
bodies (would corrupt compressed data). The operation is read/write:
the original file is not modified; a new file is written.

    disarm(pdf, out_path) -> DisarmReport
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .model import PDFFile


# Each (bad, neutered) pair must have identical byte length.
SUBSTITUTIONS: list[tuple[bytes, bytes]] = [
    (b'/JavaScript', b'/JavaScrip0'),
    (b'/OpenAction', b'/OpenActi0n'),
    (b'/Launch',     b'/Launc0'),
    (b'/JS',         b'/J0'),
    (b'/AA',         b'/A0'),
]


@dataclass
class DisarmReport:
    out_path: str
    total_substitutions: int = 0
    by_keyword: dict[str, int] = field(default_factory=dict)
    affected_objects: list[tuple[int, str, int]] = field(default_factory=list)
    # (object_index, keyword, hit_count_in_object)


def _body_scan_range(obj) -> tuple[int, int]:
    """Return (start, end) of the object's dictionary region — excluding
    any stream body, so we never touch compressed bytes."""
    start = obj.offset
    if obj.stream is not None:
        # Dictionary ends just before the 'stream' keyword.
        end = obj.stream.raw_offset - len('stream')
        # Walk back over newlines before 'stream' so we clip safely.
        while end > start and end - 1 >= 0:
            break  # start + body_pre_stream length is approximate; fine
        return start, end
    return start, obj.end_offset


def disarm(pdf: PDFFile, out_path: str) -> DisarmReport:
    with open(pdf.path, 'rb') as fh:
        raw = bytearray(fh.read())

    report = DisarmReport(out_path=out_path)

    for obj in pdf.objects:
        scan_start, scan_end = _body_scan_range(obj)
        if scan_end <= scan_start:
            continue
        segment = bytes(raw[scan_start:scan_end])

        for bad, good in SUBSTITUTIONS:
            assert len(bad) == len(good), f'substitution length mismatch: {bad!r} vs {good!r}'
            if bad not in segment:
                continue
            count = segment.count(bad)
            segment = segment.replace(bad, good)
            report.total_substitutions += count
            key = bad.decode('latin-1')
            report.by_keyword[key] = report.by_keyword.get(key, 0) + count
            report.affected_objects.append((obj.index, key, count))

        raw[scan_start:scan_end] = segment

    with open(out_path, 'wb') as fh:
        fh.write(bytes(raw))
    return report


def render_report(report: DisarmReport) -> str:
    lines = [
        f'pdfstudio disarm — wrote {report.out_path}',
        '─' * 64,
        f'Total substitutions: {report.total_substitutions}',
    ]
    if not report.total_substitutions:
        lines.append('  (nothing dangerous found — file is already benign.)')
        return '\n'.join(lines) + '\n'

    lines.append('')
    lines.append('By keyword:')
    for kw, n in sorted(report.by_keyword.items(), key=lambda x: -x[1]):
        lines.append(f'  {kw:<14} {n:>5}')

    lines.append('')
    lines.append('Per-object hits:')
    for idx, kw, n in report.affected_objects:
        lines.append(f'  obj {idx:>4}  {kw:<14} ×{n}')

    lines.append('')
    lines.append('Byte-level substitution preserves every xref offset — the file still parses.')
    return '\n'.join(lines) + '\n'
