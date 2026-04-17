"""
pdfstudio.hexview
Minimal hex dumper for object bodies, raw streams, or decoded streams.

    hexdump(data, *, start_offset=0, width=16, max_bytes=None) -> str
"""
from __future__ import annotations


def hexdump(data: bytes, *, start_offset: int = 0, width: int = 16,
            max_bytes: int | None = None) -> str:
    if max_bytes is not None and len(data) > max_bytes:
        trailer = f'\n... ({len(data) - max_bytes} bytes not shown; use --hex-max 0 for full)\n'
        data = data[:max_bytes]
    else:
        trailer = ''

    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_parts = ' '.join(f'{b:02X}' for b in chunk)
        hex_parts = hex_parts.ljust(width * 3 - 1)
        ascii_parts = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{start_offset + i:08X}  {hex_parts}  |{ascii_parts}|')
    return '\n'.join(lines) + trailer
