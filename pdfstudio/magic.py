"""
pdfstudio.magic
Lightweight file-signature sniffer for decoded streams.

    sniff(data: bytes) -> Optional[str]
"""
from __future__ import annotations

from typing import Optional


# (magic bytes, min length, human label)
_SIGS: list[tuple[bytes, int, str]] = [
    (b'MZ', 2, 'Windows PE (DOS header)'),
    (b'\x7fELF', 4, 'ELF executable'),
    (b'\xCA\xFE\xBA\xBE', 4, 'Mach-O fat binary / Java class'),
    (b'\xFE\xED\xFA\xCE', 4, 'Mach-O 32-bit'),
    (b'\xFE\xED\xFA\xCF', 4, 'Mach-O 64-bit'),
    (b'PK\x03\x04', 4, 'ZIP archive / OOXML'),
    (b'PK\x05\x06', 4, 'ZIP (empty)'),
    (b'Rar!\x1A\x07', 6, 'RAR archive'),
    (b'\x1F\x8B', 2, 'gzip'),
    (b'7z\xBC\xAF\x27\x1C', 6, '7-Zip archive'),
    (b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', 8, 'OLE compound document (doc/xls/msi)'),
    (b'%PDF-', 5, 'PDF'),
    (b'\xFF\xD8\xFF', 3, 'JPEG'),
    (b'\x89PNG\r\n\x1A\n', 8, 'PNG'),
    (b'GIF87a', 6, 'GIF87a'),
    (b'GIF89a', 6, 'GIF89a'),
    (b'BM', 2, 'BMP'),
    (b'<?xml', 5, 'XML'),
    (b'<html', 5, 'HTML'),
    (b'<!DOCTYPE', 9, 'HTML / XML doctype'),
    (b'{', 1, 'JSON (maybe)'),
    (b'CWS', 3, 'Flash SWF (compressed)'),
    (b'FWS', 3, 'Flash SWF'),
]


def sniff(data: bytes) -> Optional[str]:
    if not data:
        return None
    # ISO 9660 has its magic at offset 0x8001 ('CD001')
    if len(data) >= 0x8006 and data[0x8001:0x8006] == b'CD001':
        return 'ISO 9660 filesystem image'
    head = data[:16]
    for sig, n, label in _SIGS:
        if head.startswith(sig) and len(data) >= n:
            return label
    # RTF
    if head.startswith(b'{\\rtf'):
        return 'RTF document'
    return None
