"""Parser sanity tests — does parse() produce the structures we expect?"""
from __future__ import annotations

from pdfstudio.parser import parse
from pdfstudio.classify import classify


def test_minimal_parses(minimal_pdf):
    pdf = parse(str(minimal_pdf))
    classify(pdf)
    assert pdf.header == '%PDF-1.4'
    assert len(pdf.objects) == 3
    assert len(pdf.revisions) == 1
    assert len(pdf.trailers) == 1
    assert pdf.trailers[0].root == (1, 0)


def test_minimal_catalog_found(minimal_pdf):
    pdf = parse(str(minimal_pdf))
    classify(pdf)
    cats = [o for o in pdf.objects if o.kind == 'Catalog']
    pages = [o for o in pdf.objects if o.kind == 'Pages']
    page = [o for o in pdf.objects if o.kind == 'Page']
    assert len(cats) == 1 and cats[0].index == 1
    assert len(pages) == 1 and pages[0].index == 2
    assert len(page) == 1 and page[0].index == 3


def test_launch_action_classified(launch_pdf):
    pdf = parse(str(launch_pdf))
    classify(pdf)
    actions = [o for o in pdf.objects if o.kind.startswith('Action:')]
    assert len(actions) == 1
    assert actions[0].kind == 'Action:Launch'


def test_stream_filter_detected(embedded_pe_pdf):
    pdf = parse(str(embedded_pe_pdf))
    classify(pdf)
    streams = [o for o in pdf.objects if o.stream is not None]
    assert len(streams) == 1
    assert streams[0].stream.filters == ['/FlateDecode']


def test_stream_flate_decoded(embedded_pe_pdf):
    pdf = parse(str(embedded_pe_pdf))
    classify(pdf)
    s = next(o for o in pdf.objects if o.stream is not None)
    assert s.stream.decoded_bytes is not None
    assert s.stream.decoded_bytes.startswith(b'MZ')


def test_incremental_update_detected(incremental_pdf):
    pdf = parse(str(incremental_pdf))
    classify(pdf)
    assert len(pdf.revisions) == 2
    assert len(pdf.eof_offsets) == 2
    v1 = pdf.revisions[1]
    assert v1.trailer.prev is not None
    assert 4 in v1.new_objects
    assert 1 in v1.rewritten_objects


def test_incremental_uses_latest_revision(incremental_pdf):
    pdf = parse(str(incremental_pdf))
    classify(pdf)
    # obj(1) should resolve to the latest Catalog revision, which references obj 4.
    latest_cat = pdf.obj(1)
    assert latest_cat is not None
    assert latest_cat.revision == 1
    assert '/OpenAction 4 0 R' in latest_cat.body


def test_non_pdf_parses_with_empty_header(non_pdf):
    """Parser shouldn't crash on non-PDF input; just produces an empty result."""
    pdf = parse(str(non_pdf))
    classify(pdf)
    assert pdf.header == ''
    assert pdf.objects == []
    assert pdf.revisions == []
    # Emits a warning so the caller knows why
    assert any('PDF-' in w for w in pdf.parse_warnings)


def test_uri_action_classified(uri_to_exe_pdf):
    pdf = parse(str(uri_to_exe_pdf))
    classify(pdf)
    uri_actions = [o for o in pdf.objects if o.kind == 'Action:URI']
    assert len(uri_actions) == 1
    assert 'payload.exe' in uri_actions[0].body
