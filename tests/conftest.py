"""
Shared pytest fixtures.

We build tiny, hand-crafted PDFs at test time so the test suite doesn't
need to ship any real malware samples. Each builder returns raw bytes
that can be written to a tmp_path and then parsed like any real PDF.
"""
from __future__ import annotations

import zlib
from pathlib import Path
from typing import Callable

import pytest


# ---------------------------------------------------------------------------
# Low-level PDF bytes builders
# ---------------------------------------------------------------------------

def _xref_and_trailer(objects: list[bytes], root_idx: int,
                      prev: int | None = None) -> bytes:
    """Build a classic PDF body: header + N objects + xref + trailer + EOF.

    `objects[i]` is the already-serialized body of object number i+1
    (e.g. b'<</Type/Catalog/Pages 2 0 R>>').
    """
    header = b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n'
    out = bytearray(header)
    offsets = [0]  # offset 0 is the free-list head
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f'{i} 0 obj\n'.encode() + body + b'\nendobj\n'
    xref_start = len(out)
    n = len(objects) + 1
    out += f'xref\n0 {n}\n'.encode()
    out += b'0000000000 65535 f \n'
    for off in offsets[1:]:
        out += f'{off:010d} 00000 n \n'.encode()
    trailer = f'trailer\n<</Size {n}/Root {root_idx} 0 R'
    if prev is not None:
        trailer += f'/Prev {prev}'
    trailer += '>>\nstartxref\n' + str(xref_start) + '\n%%EOF\n'
    out += trailer.encode()
    return bytes(out), xref_start


# ---------------------------------------------------------------------------
# Concrete synthetic PDFs
# ---------------------------------------------------------------------------

def make_minimal_pdf() -> bytes:
    """The smallest valid PDF we can build: header + 3 objects + xref + trailer."""
    objs = [
        b'<</Type/Catalog/Pages 2 0 R>>',                            # 1
        b'<</Type/Pages/Count 1/Kids[3 0 R]>>',                      # 2
        b'<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>',        # 3
    ]
    body, _ = _xref_and_trailer(objs, root_idx=1)
    return body


def make_pdf_with_launch_action() -> bytes:
    """Single-revision PDF with a /Launch action invoking cmd.exe."""
    objs = [
        b'<</Type/Catalog/Pages 2 0 R/OpenAction 4 0 R>>',           # 1
        b'<</Type/Pages/Count 1/Kids[3 0 R]>>',                      # 2
        b'<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>',        # 3
        b'<</S/Launch/Type/Action/Win<</F(cmd.exe)/D(c:\\\\windows'
        b'\\\\system32)/P(/Q /C echo hi)>>>>',                       # 4
    ]
    body, _ = _xref_and_trailer(objs, root_idx=1)
    return body


def make_pdf_with_openaction_js() -> bytes:
    """PDF where /OpenAction points to a /JavaScript action."""
    objs = [
        b'<</Type/Catalog/Pages 2 0 R/OpenAction 4 0 R>>',           # 1
        b'<</Type/Pages/Count 1/Kids[3 0 R]>>',                      # 2
        b'<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>',        # 3
        b'<</S/JavaScript/JS(app.alert("hi"))/Type/Action>>',        # 4
    ]
    body, _ = _xref_and_trailer(objs, root_idx=1)
    return body


def make_pdf_with_uri_to_exe(url: str = 'http://evil.example/payload.exe') -> bytes:
    """Annot:Link whose /A points to an Action:URI with a .exe URL."""
    objs = [
        b'<</Type/Catalog/Pages 2 0 R>>',                            # 1
        b'<</Type/Pages/Count 1/Kids[3 0 R]>>',                      # 2
        b'<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]'
        b'/Annots[4 0 R]>>',                                         # 3
        b'<</Type/Annot/Subtype/Link/Rect[50 50 400 100]/A 5 0 R>>', # 4
        f'<</Type/Action/S/URI/URI({url})>>'.encode(),               # 5
    ]
    body, _ = _xref_and_trailer(objs, root_idx=1)
    return body


def make_pdf_with_embedded_pe() -> bytes:
    """PDF whose stream, after Flate decoding, starts with an MZ header."""
    payload = b'MZ' + b'\x90' * 62 + b'PE\x00\x00' + b'\x00' * 32
    compressed = zlib.compress(payload)
    stream_obj = (
        f'<</Length {len(compressed)}/Filter/FlateDecode>>'.encode()
        + b'\nstream\n' + compressed + b'\nendstream'
    )
    objs = [
        b'<</Type/Catalog/Pages 2 0 R>>',                            # 1
        b'<</Type/Pages/Count 1/Kids[3 0 R]>>',                      # 2
        b'<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>',        # 3
        stream_obj,                                                  # 4
    ]
    body, _ = _xref_and_trailer(objs, root_idx=1)
    return body


def make_incremental_update_pdf() -> bytes:
    """v0 clean PDF, then a v1 incremental update adding an Action:Launch."""
    base = make_minimal_pdf()

    # Append a new object 4 (Launch action) and patch the catalog to reference it.
    append_start = len(base)
    add_obj4_offset = append_start
    obj4 = (b'4 0 obj\n<</S/Launch/Type/Action/Win<</F(cmd.exe)>>>>\n'
            b'endobj\n')
    obj1_new_offset = append_start + len(obj4)
    obj1 = (b'1 0 obj\n<</Type/Catalog/Pages 2 0 R/OpenAction 4 0 R>>\n'
            b'endobj\n')

    new_xref_start = append_start + len(obj4) + len(obj1)

    # The original v0 xref starts where the first `xref` token lives in base.
    # Recompute by scanning once.
    v0_xref = base.rfind(b'xref\n')

    update = obj4 + obj1
    xref_block = (
        b'xref\n'
        b'0 1\n0000000000 65535 f \n'
        b'1 1\n' + f'{obj1_new_offset:010d} 00000 n \n'.encode() +
        b'4 1\n' + f'{add_obj4_offset:010d} 00000 n \n'.encode()
    )
    trailer = (
        f'trailer\n<</Size 5/Root 1 0 R/Prev {v0_xref}>>\n'
        f'startxref\n{new_xref_start}\n%%EOF\n'
    ).encode()
    return base + update + xref_block + trailer


def make_non_pdf(magic: bytes = b'MZ\x90\x00') -> bytes:
    """Not a PDF at all — a Windows PE-ish header (or anything we pass)."""
    return magic + b'\x00' * 512


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def minimal_pdf(tmp_path: Path) -> Path:
    p = tmp_path / 'minimal.pdf'
    p.write_bytes(make_minimal_pdf())
    return p


@pytest.fixture
def launch_pdf(tmp_path: Path) -> Path:
    p = tmp_path / 'launch.pdf'
    p.write_bytes(make_pdf_with_launch_action())
    return p


@pytest.fixture
def openaction_js_pdf(tmp_path: Path) -> Path:
    p = tmp_path / 'openaction_js.pdf'
    p.write_bytes(make_pdf_with_openaction_js())
    return p


@pytest.fixture
def uri_to_exe_pdf(tmp_path: Path) -> Path:
    p = tmp_path / 'uri_to_exe.pdf'
    p.write_bytes(make_pdf_with_uri_to_exe())
    return p


@pytest.fixture
def embedded_pe_pdf(tmp_path: Path) -> Path:
    p = tmp_path / 'embedded_pe.pdf'
    p.write_bytes(make_pdf_with_embedded_pe())
    return p


@pytest.fixture
def incremental_pdf(tmp_path: Path) -> Path:
    p = tmp_path / 'incremental.pdf'
    p.write_bytes(make_incremental_update_pdf())
    return p


@pytest.fixture
def non_pdf(tmp_path: Path) -> Path:
    p = tmp_path / 'not_a_pdf.pdf'
    p.write_bytes(make_non_pdf())
    return p


@pytest.fixture
def make_pdf(tmp_path: Path) -> Callable[[bytes, str], Path]:
    """Factory — write arbitrary raw bytes to a tmp .pdf path."""
    counter = [0]

    def _make(content: bytes, name: str | None = None) -> Path:
        counter[0] += 1
        p = tmp_path / (name or f'synth_{counter[0]}.pdf')
        p.write_bytes(content)
        return p

    return _make
