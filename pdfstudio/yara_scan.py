"""
pdfstudio.yara_scan
Scan PDF file and decoded streams with YARA rules.

Requires the `yara-python` binding (optional). If yara is not installed,
the scan function raises RuntimeError and the CLI surfaces a friendly
"yara-python not installed" message.

    scan(pdf, rule_path, unfiltered=False, show_strings=False) -> list[Hit]
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .model import PDFFile


@dataclass
class Hit:
    target: str                # 'file' | 'obj N stream' | 'obj N stream(raw)'
    rule: str
    tags: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    strings: list[tuple[int, str, bytes]] = field(default_factory=list)


def _load_yara():
    try:
        import yara  # type: ignore
    except ImportError as e:
        raise RuntimeError(
            'yara-python not installed. `pip install yara-python` to enable --yara.'
        ) from e
    return yara


def scan(pdf: PDFFile, rule_path: str, *, unfiltered: bool = False,
         show_strings: bool = False) -> list[Hit]:
    import os
    yara = _load_yara()

    # Compile rules. Support a single file or a directory of .yar/.yara files.
    if os.path.isdir(rule_path):
        filepaths = {}
        for name in sorted(os.listdir(rule_path)):
            if name.lower().endswith(('.yar', '.yara')):
                filepaths[name] = os.path.join(rule_path, name)
        rules = yara.compile(filepaths=filepaths)
    else:
        rules = yara.compile(filepath=rule_path)

    hits: list[Hit] = []

    # --- File-level scan -----------------------------------------------------
    with open(pdf.path, 'rb') as fh:
        file_bytes = fh.read()
    for m in rules.match(data=file_bytes):
        hits.append(Hit(
            target='file',
            rule=m.rule,
            tags=list(m.tags),
            meta=dict(m.meta),
            strings=_strings_from_match(m) if show_strings else [],
        ))

    # --- Per-stream scan -----------------------------------------------------
    for obj in pdf.objects:
        if obj.stream is None:
            continue
        targets = []
        if unfiltered or obj.stream.decoded_bytes is None:
            # scan raw bytes
            if obj.stream.raw_bytes:
                targets.append((f'obj {obj.index} stream(raw)', obj.stream.raw_bytes))
        if obj.stream.decoded_bytes is not None:
            targets.append((f'obj {obj.index} stream(decoded)', obj.stream.decoded_bytes))

        for tag, data in targets:
            for m in rules.match(data=data):
                hits.append(Hit(
                    target=tag,
                    rule=m.rule,
                    tags=list(m.tags),
                    meta=dict(m.meta),
                    strings=_strings_from_match(m) if show_strings else [],
                ))
    return hits


def _strings_from_match(m) -> list[tuple[int, str, bytes]]:
    """yara-python match.strings is a list of StringMatch (v4) or tuples (v3)."""
    out = []
    raw = m.strings
    for entry in raw:
        # v4+: StringMatch with .identifier and .instances
        if hasattr(entry, 'instances'):
            for inst in entry.instances:
                out.append((int(inst.offset), str(entry.identifier), bytes(inst.matched_data)))
        elif isinstance(entry, tuple) and len(entry) == 3:
            off, ident, data = entry
            out.append((int(off), str(ident), bytes(data)))
    return out


def render_hits(hits: list[Hit], *, show_strings: bool = False) -> str:
    if not hits:
        return '(no YARA hits)\n'
    lines = []
    for h in hits:
        tagstr = f' [tags: {", ".join(h.tags)}]' if h.tags else ''
        lines.append(f'{h.target:<28}  rule={h.rule}{tagstr}')
        if h.meta:
            for k, v in h.meta.items():
                lines.append(f'    meta.{k} = {v}')
        if show_strings and h.strings:
            for off, ident, data in h.strings[:20]:
                disp = data[:60] + (b'...' if len(data) > 60 else b'')
                safe = disp.decode('latin-1', errors='replace')
                lines.append(f'    {ident:<20}  @ 0x{off:X}  {safe!r}')
    return '\n'.join(lines) + '\n'
