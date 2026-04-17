"""Tests for automation.py — summary line, exit codes, bundle writer."""
from __future__ import annotations

import json
from pathlib import Path

from pdfstudio.parser import parse
from pdfstudio.classify import classify
from pdfstudio.walker import walk
from pdfstudio.flags import run_all
from pdfstudio.automation import (
    compute_exit_code, max_severity, summary_line,
    write_bundle, to_sarif, to_stix,
    EXIT_OK, EXIT_MED, EXIT_HIGH,
)


def _prep(path: Path):
    pdf = parse(str(path))
    classify(pdf)
    hits = walk(pdf)
    run_all(pdf)
    return pdf, hits


def test_exit_code_clean(minimal_pdf):
    pdf, _ = _prep(minimal_pdf)
    assert compute_exit_code(pdf) == EXIT_OK


def test_exit_code_high_on_launch(launch_pdf):
    pdf, _ = _prep(launch_pdf)
    assert compute_exit_code(pdf) == EXIT_HIGH


def test_max_severity_high_on_embedded_pe(embedded_pe_pdf):
    pdf, _ = _prep(embedded_pe_pdf)
    assert max_severity(pdf) == 'HIGH'


def test_summary_line_format(launch_pdf):
    pdf, _ = _prep(launch_pdf)
    line = summary_line(pdf)
    assert line.startswith('PDFSTUDIO')
    assert 'severity=HIGH' in line
    assert 'md5=' in line
    assert 'sha256=' in line


def test_bundle_writes_all_files(launch_pdf, tmp_path):
    pdf, hits = _prep(launch_pdf)
    out = tmp_path / 'bundle'
    paths = write_bundle(pdf, hits, str(out))
    for p in (paths.json_path, paths.html_path, paths.summary_path,
              paths.flags_csv_path, paths.iocs_csv_path,
              paths.sarif_path, paths.stix_path, paths.deep_dump_path):
        assert Path(p).exists(), f'missing {p}'


def test_bundle_json_schema(launch_pdf, tmp_path):
    pdf, hits = _prep(launch_pdf)
    out = tmp_path / 'bundle'
    paths = write_bundle(pdf, hits, str(out))
    data = json.loads(Path(paths.json_path).read_text(encoding='utf-8'))
    assert data['schema'] == 'pdfstudio-report/1'
    assert data['max_severity'] == 'HIGH'
    assert len(data['objects']) >= 4


def test_sarif_is_valid_structure(launch_pdf):
    pdf, _ = _prep(launch_pdf)
    doc = to_sarif(pdf)
    assert doc['version'] == '2.1.0'
    assert 'runs' in doc and len(doc['runs']) == 1
    rules = doc['runs'][0]['tool']['driver']['rules']
    # One rule per distinct code present in the PDF's flags
    codes_in_flags = {c for _s, c, _m in pdf.flags}
    codes_in_rules = {r['id'] for r in rules}
    assert codes_in_flags == codes_in_rules
    assert doc['runs'][0]['tool']['driver']['informationUri'].startswith('http')


def test_stix_bundle_has_file_observable(launch_pdf):
    pdf, _ = _prep(launch_pdf)
    doc = to_stix(pdf)
    assert doc['type'] == 'bundle'
    file_objs = [o for o in doc['objects'] if o.get('type') == 'file']
    assert len(file_objs) == 1
    assert 'MD5' in file_objs[0]['hashes']
    assert 'SHA-256' in file_objs[0]['hashes']
