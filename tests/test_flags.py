"""
Flag-rule unit tests. Each test builds a minimal synthetic PDF carrying
exactly the trigger for one rule and asserts that rule (and no unrelated
verdict rule) fires.
"""
from __future__ import annotations

from pdfstudio.parser import parse
from pdfstudio.classify import classify
from pdfstudio.flags import run_all


def _codes(pdf) -> set[str]:
    return {c for _s, c, _m in pdf.flags}


def _sevs(pdf, code: str) -> list[str]:
    return [s for s, c, _m in pdf.flags if c == code]


# ---------------------------------------------------------------------------
# Verdict rules (HIGH)
# ---------------------------------------------------------------------------

def test_not_a_pdf_fires(non_pdf):
    pdf = parse(str(non_pdf))
    classify(pdf); run_all(pdf)
    assert 'NOT_A_PDF' in _codes(pdf)
    assert _sevs(pdf, 'NOT_A_PDF') == ['HIGH']


def test_launch_cmd_fires(launch_pdf):
    pdf = parse(str(launch_pdf))
    classify(pdf); run_all(pdf)
    assert 'LAUNCH_CMD' in _codes(pdf)


def test_embedded_pe_fires(embedded_pe_pdf):
    pdf = parse(str(embedded_pe_pdf))
    classify(pdf); run_all(pdf)
    assert 'EMBEDDED_PE' in _codes(pdf)


def test_openaction_js_fires(openaction_js_pdf):
    pdf = parse(str(openaction_js_pdf))
    classify(pdf); run_all(pdf)
    assert 'OPENACTION_JS' in _codes(pdf)


def test_uri_to_executable_fires(uri_to_exe_pdf):
    pdf = parse(str(uri_to_exe_pdf))
    classify(pdf); run_all(pdf)
    assert 'URI_TO_EXECUTABLE' in _codes(pdf)


def test_multirev_weaponization_fires(incremental_pdf):
    pdf = parse(str(incremental_pdf))
    classify(pdf); run_all(pdf)
    codes = _codes(pdf)
    assert 'MULTI_REV' in codes
    assert 'MULTI_REV_WEAPONIZATION' in codes


# ---------------------------------------------------------------------------
# URL rules (MED)
# ---------------------------------------------------------------------------

def test_url_shortener(make_pdf):
    from tests.conftest import make_pdf_with_uri_to_exe
    data = make_pdf_with_uri_to_exe(url='https://tinyurl.com/abcdef')
    p = make_pdf(data)
    pdf = parse(str(p))
    classify(pdf); run_all(pdf)
    assert 'URL_SHORTENER' in _codes(pdf)


def test_dynamic_dns(make_pdf):
    from tests.conftest import make_pdf_with_uri_to_exe
    data = make_pdf_with_uri_to_exe(url='http://badc2.duckdns.org/beacon')
    p = make_pdf(data)
    pdf = parse(str(p))
    classify(pdf); run_all(pdf)
    assert 'DYNAMIC_DNS' in _codes(pdf)


def test_raw_ip_uri(make_pdf):
    from tests.conftest import make_pdf_with_uri_to_exe
    data = make_pdf_with_uri_to_exe(url='http://10.0.0.5/beacon')
    p = make_pdf(data)
    pdf = parse(str(p))
    classify(pdf); run_all(pdf)
    assert 'RAW_IP_URI' in _codes(pdf)


def test_abused_file_host(make_pdf):
    from tests.conftest import make_pdf_with_uri_to_exe
    data = make_pdf_with_uri_to_exe(url='https://pixeldrain.com/api/file/abc')
    p = make_pdf(data)
    pdf = parse(str(p))
    classify(pdf); run_all(pdf)
    assert 'ABUSED_FILE_HOST' in _codes(pdf)


def test_canarytoken(make_pdf):
    from tests.conftest import make_pdf_with_uri_to_exe
    data = make_pdf_with_uri_to_exe(url='http://canarytokens.com/traffic/xyz/post.jsp')
    p = make_pdf(data)
    pdf = parse(str(p))
    classify(pdf); run_all(pdf)
    assert 'CANARYTOKEN' in _codes(pdf)


def test_uri_octal_encoded(make_pdf):
    # https://tinyurl.com/x → octal-escape the scheme delimiters
    encoded = r'https\072\057\057tinyurl\056com\057abc'
    from tests.conftest import make_pdf_with_uri_to_exe
    data = make_pdf_with_uri_to_exe(url=encoded)
    p = make_pdf(data)
    pdf = parse(str(p))
    classify(pdf); run_all(pdf)
    codes = _codes(pdf)
    assert 'URI_OCTAL_ENCODED' in codes
    # After decoding, URL_SHORTENER should ALSO fire
    assert 'URL_SHORTENER' in codes


# ---------------------------------------------------------------------------
# Identifier rules (INFO)
# ---------------------------------------------------------------------------

def test_has_acroform(make_pdf):
    data = (b'%PDF-1.4\n'
            b'1 0 obj\n<</Type/Catalog/Pages 2 0 R/AcroForm<</Fields[]>>>>\n'
            b'endobj\n'
            b'2 0 obj\n<</Type/Pages/Count 0>>\nendobj\n'
            b'xref\n0 3\n0000000000 65535 f \n'
            b'0000000009 00000 n \n0000000080 00000 n \n'
            b'trailer\n<</Size 3/Root 1 0 R>>\nstartxref\n130\n%%EOF\n')
    p = make_pdf(data)
    pdf = parse(str(p))
    classify(pdf); run_all(pdf)
    assert 'HAS_ACROFORM' in _codes(pdf)


def test_has_openaction(launch_pdf):
    pdf = parse(str(launch_pdf))
    classify(pdf); run_all(pdf)
    assert 'HAS_OPENACTION' in _codes(pdf)


def test_uncommon_tld(make_pdf):
    from tests.conftest import make_pdf_with_uri_to_exe
    data = make_pdf_with_uri_to_exe(url='http://badsite.xyz/lure')
    p = make_pdf(data)
    pdf = parse(str(p))
    classify(pdf); run_all(pdf)
    assert 'UNCOMMON_TLD' in _codes(pdf)


def test_external_hosts_excludes_noise(make_pdf):
    """URIs to only noise hosts (w3.org, adobe.com) shouldn't surface EXTERNAL_HOSTS."""
    from tests.conftest import make_pdf_with_uri_to_exe
    data = make_pdf_with_uri_to_exe(url='http://www.w3.org/1999/02/22-rdf-syntax-ns')
    p = make_pdf(data)
    pdf = parse(str(p))
    classify(pdf); run_all(pdf)
    assert 'EXTERNAL_HOSTS' not in _codes(pdf)


# ---------------------------------------------------------------------------
# Negative: clean PDF should produce no verdict flags
# ---------------------------------------------------------------------------

def test_minimal_pdf_no_verdicts(minimal_pdf):
    """A clean minimal PDF should produce zero HIGH/MED flags."""
    pdf = parse(str(minimal_pdf))
    classify(pdf); run_all(pdf)
    high_med = [c for s, c, _m in pdf.flags if s in ('HIGH', 'MED')]
    assert high_med == []
