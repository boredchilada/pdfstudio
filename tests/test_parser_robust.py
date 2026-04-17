"""
Parser-robustness tests. These verify that pdfstudio DOESN'T CRASH on
adversarial or malformed input. The goal isn't that output is correct on
broken files — it's that we produce a PDFFile with a warning rather than
raising.
"""
from __future__ import annotations

import pytest

from pdfstudio.parser import parse
from pdfstudio.classify import classify
from pdfstudio.flags import run_all
from pdfstudio.walker import walk


# ---------------------------------------------------------------------------
# Empty / tiny / magic-only inputs
# ---------------------------------------------------------------------------

def test_empty_file_does_not_crash(make_pdf):
    p = make_pdf(b'')
    pdf = parse(str(p))
    classify(pdf)
    run_all(pdf)
    assert pdf.header == ''
    assert pdf.objects == []


def test_one_byte_file(make_pdf):
    p = make_pdf(b'%')
    pdf = parse(str(p))
    classify(pdf)
    run_all(pdf)
    assert pdf.header == ''


def test_header_only(make_pdf):
    p = make_pdf(b'%PDF-1.4\n')
    pdf = parse(str(p))
    classify(pdf)
    run_all(pdf)
    assert pdf.header == '%PDF-1.4'
    assert pdf.objects == []


def test_header_with_no_trailer(make_pdf):
    p = make_pdf(b'%PDF-1.4\n1 0 obj\n<</Type/Catalog>>\nendobj\n')
    pdf = parse(str(p))
    classify(pdf)
    # Parser should find the object even without trailer
    assert len(pdf.objects) == 1


def test_truncated_mid_object(make_pdf):
    p = make_pdf(b'%PDF-1.4\n1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\n'
                 b'2 0 obj\n<</Type/Pages/Count 1/Kids[3 0 R')  # cut off
    pdf = parse(str(p))
    classify(pdf)
    run_all(pdf)
    # Should not crash; either picks up the partial or skips it.


def test_truncated_mid_stream(make_pdf):
    p = make_pdf(b'%PDF-1.4\n1 0 obj\n<</Length 99>>\nstream\nABCDE')
    pdf = parse(str(p))
    classify(pdf)
    run_all(pdf)


def test_only_eof_marker(make_pdf):
    p = make_pdf(b'%%EOF\n')
    pdf = parse(str(p))
    classify(pdf)
    run_all(pdf)


# ---------------------------------------------------------------------------
# Garbage structural bytes
# ---------------------------------------------------------------------------

def test_null_bytes_only(make_pdf):
    p = make_pdf(b'\x00' * 1024)
    pdf = parse(str(p))
    classify(pdf)
    run_all(pdf)


def test_random_binary(make_pdf):
    """Pseudo-random bytes shouldn't parse-crash."""
    import random
    rng = random.Random(12345)
    data = bytes(rng.randrange(256) for _ in range(4096))
    p = make_pdf(data)
    pdf = parse(str(p))
    classify(pdf)
    run_all(pdf)


def test_duplicate_objects(make_pdf):
    data = (b'%PDF-1.4\n'
            b'1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n'
            b'1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n'
            b'2 0 obj\n<</Type/Pages/Count 0>>\nendobj\n'
            b'%%EOF\n')
    p = make_pdf(data)
    pdf = parse(str(p))
    classify(pdf)
    run_all(pdf)
    # Should handle the duplicate without crashing
    assert len(pdf.objects) >= 1


# ---------------------------------------------------------------------------
# Malformed numbers
# ---------------------------------------------------------------------------

def test_huge_length_declared(make_pdf):
    """Declared stream /Length bigger than file — shouldn't OOM or crash."""
    p = make_pdf(b'%PDF-1.4\n1 0 obj\n<</Length 999999999>>\nstream\n'
                 b'ABC\nendstream\nendobj\n%%EOF')
    pdf = parse(str(p))
    classify(pdf)
    run_all(pdf)


def test_negative_length(make_pdf):
    p = make_pdf(b'%PDF-1.4\n1 0 obj\n<</Length -5>>\nstream\nABC\n'
                 b'endstream\nendobj\n%%EOF')
    pdf = parse(str(p))
    classify(pdf)
    run_all(pdf)


# ---------------------------------------------------------------------------
# Circular references
# ---------------------------------------------------------------------------

def test_circular_parent_kids(make_pdf):
    """Pages <-> Page cycling shouldn't cause infinite walk."""
    data = (b'%PDF-1.4\n'
            b'1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n'
            b'2 0 obj\n<</Type/Pages/Count 1/Kids[3 0 R]/Parent 3 0 R>>\nendobj\n'
            b'3 0 obj\n<</Type/Page/Parent 2 0 R/Kids[2 0 R]/MediaBox[0 0 1 1]>>\nendobj\n'
            b'xref\n0 4\n0000000000 65535 f \n'
            b'0000000009 00000 n \n0000000057 00000 n \n0000000115 00000 n \n'
            b'trailer\n<</Size 4/Root 1 0 R>>\nstartxref\n170\n%%EOF\n')
    p = make_pdf(data)
    pdf = parse(str(p))
    classify(pdf)
    run_all(pdf)
    # Should complete in finite time
    hits = walk(pdf)
    # Just assert no exception and we got some result
    assert isinstance(hits, list)


# ---------------------------------------------------------------------------
# Broken filter
# ---------------------------------------------------------------------------

def test_bad_flate_stream(make_pdf):
    """Stream declares /Filter/FlateDecode but body isn't zlib-compressed."""
    data = (b'%PDF-1.4\n1 0 obj\n<</Length 5/Filter/FlateDecode>>\n'
            b'stream\nHELLO\nendstream\nendobj\n%%EOF')
    p = make_pdf(data)
    pdf = parse(str(p))
    classify(pdf)
    run_all(pdf)
    streams = [o for o in pdf.objects if o.stream is not None]
    if streams:
        # decoded_bytes should be None and decode_error populated
        assert streams[0].stream.decode_error is not None


def test_bad_ascii85_stream(make_pdf):
    data = (b'%PDF-1.4\n1 0 obj\n<</Length 5/Filter/ASCII85Decode>>\n'
            b'stream\n!!@@#~>\nendstream\nendobj\n%%EOF')
    p = make_pdf(data)
    pdf = parse(str(p))
    classify(pdf)
    run_all(pdf)


# ---------------------------------------------------------------------------
# Flag engine on nothing
# ---------------------------------------------------------------------------

def test_flags_on_empty_pdf(make_pdf):
    """Flag engine must not error on a file that produces zero objects."""
    p = make_pdf(b'')
    pdf = parse(str(p))
    classify(pdf)
    run_all(pdf)
    # NOT_A_PDF should fire; no other crash
    codes = [c for _s, c, _m in pdf.flags]
    assert 'NOT_A_PDF' in codes


def test_walker_handles_missing_root(make_pdf):
    """Trailer says /Root X 0 R but obj X doesn't exist."""
    data = (b'%PDF-1.4\n'
            b'1 0 obj\n<</Type/Pages/Count 0>>\nendobj\n'
            b'xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n'
            b'trailer\n<</Size 2/Root 99 0 R>>\nstartxref\n50\n%%EOF\n')
    p = make_pdf(data)
    pdf = parse(str(p))
    classify(pdf)
    hits = walk(pdf)
    assert isinstance(hits, list)  # no crash
