"""
pdfstudio.automation
Automation-friendly utilities: exit-code policy, stable summary lines,
report-bundle writer, and standard-format exports (SARIF 2.1, STIX 2.1,
CSV).

Intended for orchestrators such as BigFix, SCCM, Tanium, Ansible, or CI
pipelines. All functions are side-effect-free except the writers, which
are explicit about the paths they touch.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from .model import PDFFile


# ---------------------------------------------------------------------------
# Exit-code policy
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {'HIGH': 3, 'MED': 2, 'LOW': 1, 'INFO': 0}

# Return codes — chosen so downstream tooling can check >= N
EXIT_OK        = 0    # parsed cleanly, no MED or HIGH flags
EXIT_LOW       = 5    # LOW flag(s) only
EXIT_MED       = 10   # at least one MED flag
EXIT_HIGH      = 20   # at least one HIGH flag
EXIT_BAD_ARGS  = 2    # argparse error
EXIT_PARSE_FAIL = 3   # could not parse (e.g. not a PDF, encrypted without key)


def max_severity(pdf: PDFFile) -> str:
    """Return the highest severity present in pdf.flags (or 'NONE')."""
    worst = 'NONE'
    for sev, _code, _msg in pdf.flags:
        if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(worst, -1):
            worst = sev
    return worst


def compute_exit_code(pdf: PDFFile, threshold: Optional[str] = None) -> int:
    """Map pdf triage severity → exit code.

    If `threshold` is provided ('HIGH', 'MED', 'LOW'), any severity at or
    above it produces EXIT_HIGH; below it produces EXIT_OK. This lets
    orchestrators get a binary clean/not-clean verdict aligned with their
    policy.
    """
    worst = max_severity(pdf)
    if threshold:
        return EXIT_HIGH if SEVERITY_ORDER.get(worst, 0) >= SEVERITY_ORDER.get(threshold, 99) else EXIT_OK
    if worst == 'HIGH':
        return EXIT_HIGH
    if worst == 'MED':
        return EXIT_MED
    if worst == 'LOW':
        return EXIT_LOW
    return EXIT_OK


# ---------------------------------------------------------------------------
# Summary line — stable, grep-friendly
# ---------------------------------------------------------------------------

def _file_hashes(path: str) -> tuple[str, str]:
    try:
        with open(path, 'rb') as fh:
            raw = fh.read()
        return hashlib.md5(raw).hexdigest(), hashlib.sha256(raw).hexdigest()
    except OSError:
        return '(n/a)', '(n/a)'


def summary_line(pdf: PDFFile) -> str:
    """One-line summary: space-separated key=value, stable field order.

    Example:
        PDFSTUDIO v=0.1 file=X.pdf size=60435 md5=... sha256=... header=%PDF-1.3 \
            revs=2 objs=25 streams=4 urls=0 severity=HIGH \
            flags=LAUNCH_CMD,LAUNCH_NEWLINE_PAD,EMBEDDED_PE,OPENACTION_JS
    """
    from . import __version__
    md5, sha256 = _file_hashes(pdf.path)
    flag_codes = ','.join(sorted({c for _s, c, _m in pdf.flags})) or 'NONE'
    urls = 0
    for obj in pdf.objects:
        urls += obj.body.count('/URI ')
    parts = [
        'PDFSTUDIO',
        f'v={__version__}',
        f'file={os.path.basename(pdf.path)}',
        f'size={pdf.size}',
        f'md5={md5}',
        f'sha256={sha256}',
        f'header={pdf.header or "?"}',
        f'revs={len(pdf.revisions)}',
        f'objs={len(pdf.objects)}',
        f'streams={sum(1 for o in pdf.objects if o.stream)}',
        f'urls={urls}',
        f'severity={max_severity(pdf)}',
        f'flags={flag_codes}',
    ]
    return ' '.join(parts)


# ---------------------------------------------------------------------------
# Report-bundle writer
# ---------------------------------------------------------------------------

@dataclass
class BundlePaths:
    directory: str
    json_path: str
    html_path: str
    summary_path: str
    flags_csv_path: str
    iocs_csv_path: str
    sarif_path: str
    stix_path: str
    deep_dump_path: str


def render_deep_dump(pdf, hits) -> str:
    """Single-file Markdown catch-all view of a parsed PDF.

    Sections:
        1. Structural report (text, fenced)
        2. pdfid keyword table
        3. Catalog walk
        4. Stats + trailer summary
        5. Mermaid graph (fenced for md viewers)
        6. IOCs (urls / domains / stream hashes)
        7. Bodies of objects referenced by HIGH/MED flags
        8. Malformed regions
        9. Hex windows (header + xref/trailer tail)
    """
    import re as _re
    from .render import text as render_text
    from .pdfid_view import render_pdfid
    from .walk_view import render_walk
    from .parity import render_stats
    from .graphviz_out import render_mermaid
    from .malformed import extract_regions, render_regions
    from .hexview import hexdump
    from .hunt import extract_iocs
    from .layout import render_layout

    md5, sha256 = _file_hashes(pdf.path)
    out: list[str] = []

    # --- Front matter ---------------------------------------------------------
    out.append(f'# pdfstudio deep dump — `{os.path.basename(pdf.path)}`\n\n')
    out.append('| | |\n|---|---|\n')
    out.append(f'| File | `{os.path.basename(pdf.path)}` |\n')
    out.append(f'| Size | {pdf.size:,} bytes |\n')
    out.append(f'| MD5 | `{md5}` |\n')
    out.append(f'| SHA-256 | `{sha256}` |\n')
    out.append(f'| Header | `{pdf.header or "?"}` |\n')
    out.append(f'| Revisions | {len(pdf.revisions)} |\n')
    out.append(f'| Max severity | **{max_severity(pdf)}** |\n')
    out.append(f'| Generated | {time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())} (UTC) |\n\n')

    def _fenced(title: str, body: str, lang: str = '') -> None:
        out.append(f'## {title}\n\n```{lang}\n{body.rstrip()}\n```\n\n')

    # 1. Structural report -----------------------------------------------------
    try:
        _fenced('1. Structural report', render_text.render(pdf, hits, width=200))
    except Exception as e:
        out.append(f'## 1. Structural report\n\n_failed: {e}_\n\n')

    # 1b. File-layout block diagram -------------------------------------------
    try:
        _fenced('1b. File layout (block diagram)', render_layout(pdf))
    except Exception as e:
        out.append(f'## 1b. File layout\n\n_failed: {e}_\n\n')

    # 2. pdfid keyword table ---------------------------------------------------
    try:
        _fenced('2. pdfid keyword table', render_pdfid(pdf, nozero=False, extra_info=True, all_keywords=True))
    except Exception as e:
        out.append(f'## 2. pdfid keyword table\n\n_failed: {e}_\n\n')

    # 3. Catalog walk ----------------------------------------------------------
    try:
        _fenced('3. Catalog walk', render_walk(pdf))
    except Exception as e:
        out.append(f'## 3. Catalog walk\n\n_failed: {e}_\n\n')

    # 4. Stats + trailer summary ----------------------------------------------
    out.append('## 4. Stats\n\n')
    try:
        out.append(f'```\n{render_stats(pdf).rstrip()}\n```\n\n')
    except Exception as e:
        out.append(f'_stats failed: {e}_\n\n')
    # Trailers as a compact table
    if pdf.trailers:
        out.append('### Trailers\n\n')
        out.append('| # | offset | startxref | size | prev | root |\n')
        out.append('|---|---|---|---|---|---|\n')
        for i, t in enumerate(pdf.trailers):
            out.append(f'| {i} | `{t.offset:#x}` | `{t.startxref}` | `{t.size}` | '
                       f'`{t.prev}` | `{t.root}` |\n')
        out.append('\n')
    if pdf.startxref_offsets:
        out.append('### startxref markers\n\n')
        out.append(', '.join(f'`{o:#x}`' for o in pdf.startxref_offsets) + '\n\n')

    # 5. Mermaid graph ---------------------------------------------------------
    out.append('## 5. Catalog graph (mermaid)\n\n')
    try:
        out.append(f'```mermaid\n{render_mermaid(pdf).rstrip()}\n```\n\n')
    except Exception as e:
        out.append(f'_failed: {e}_\n\n')

    # 6. IOCs ------------------------------------------------------------------
    out.append('## 6. IOCs\n\n')
    try:
        iocs = extract_iocs(pdf)
        if not (iocs.urls or iocs.domains or iocs.stream_sha256):
            out.append('_no URLs, domains, or stream hashes extracted_\n\n')
        else:
            if iocs.urls:
                out.append('**URLs**\n\n')
                for u in iocs.urls:
                    out.append(f'- `{u}`\n')
                out.append('\n')
            if iocs.domains:
                out.append('**Domains**\n\n')
                for d in iocs.domains:
                    out.append(f'- `{d}`\n')
                out.append('\n')
            if iocs.stream_sha256:
                out.append('**Stream SHA-256**\n\n')
                out.append('| obj | size | sha256 |\n|---|---|---|\n')
                for idx, sha, size in iocs.stream_sha256:
                    out.append(f'| {idx} | {size} | `{sha}` |\n')
                out.append('\n')
    except Exception as e:
        out.append(f'_failed: {e}_\n\n')

    # 7. Flagged-object bodies -------------------------------------------------
    out.append('## 7. Flagged object bodies\n\n')
    try:
        refs_re = _re.compile(r'\bobj\s+(\d+)\b', _re.I)
        # Group flag codes by obj index so we show each body once.
        per_obj: dict[int, tuple[str, list[str]]] = {}  # idx -> (worst_sev, [codes])
        for sev, code, msg in pdf.flags:
            if sev not in ('HIGH', 'MED'):
                continue
            for m in refs_re.finditer(msg):
                idx = int(m.group(1))
                cur_sev, codes = per_obj.get(idx, ('', []))
                if code not in codes:
                    codes.append(code)
                if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(cur_sev, -1):
                    cur_sev = sev
                per_obj[idx] = (cur_sev, codes)
        if not per_obj:
            out.append('_no HIGH/MED flags reference specific objects_\n\n')
        else:
            by_idx = [(o.index, o.revision, o) for o in pdf.objects]
            for idx in sorted(per_obj):
                sev, codes = per_obj[idx]
                candidates = [o for (i, _r, o) in by_idx if i == idx]
                if not candidates:
                    out.append(f'### obj {idx} — flags: {", ".join(f"`{c}`" for c in codes)}\n\n_object not found_\n\n')
                    continue
                obj = max(candidates, key=lambda o: o.revision)
                body = obj.body.strip()
                if len(body) > 2000:
                    body = body[:2000] + '\n... (truncated at 2 KB)'
                out.append(f'### obj {idx} v{obj.revision} [{obj.kind}] — {sev} — '
                           f'flags: {", ".join(f"`{c}`" for c in codes)}\n\n')
                out.append(f'```\n{body}\n```\n\n')
    except Exception as e:
        out.append(f'_failed: {e}_\n\n')

    # 8. Malformed regions -----------------------------------------------------
    try:
        _fenced('8. Malformed / unclaimed regions', render_regions(extract_regions(pdf)))
    except Exception as e:
        out.append(f'## 8. Malformed regions\n\n_failed: {e}_\n\n')

    # 9. Hex windows -----------------------------------------------------------
    out.append('## 9. Hex windows\n\n')
    try:
        with open(pdf.path, 'rb') as fh:
            raw = fh.read()
        head = raw[:256]
        out.append('### Header (bytes 0–255)\n\n')
        out.append(f'```\n{hexdump(head).rstrip()}\n```\n\n')
        # Tail window around last startxref / trailer
        if pdf.startxref_offsets:
            anchor = max(pdf.startxref_offsets)
            start = max(0, anchor - 128)
            end = min(len(raw), anchor + 128)
            out.append(f'### Tail (bytes {start}–{end-1}, around last startxref @ `{anchor:#x}`)\n\n')
            out.append(f'```\n{hexdump(raw[start:end], start_offset=start).rstrip()}\n```\n\n')
        else:
            out.append('### Tail\n\n_no startxref found_\n\n')
    except Exception as e:
        out.append(f'_hex preview failed: {e}_\n\n')

    return ''.join(out)


def write_bundle(pdf, hits, out_dir: str) -> BundlePaths:
    """Write a per-file report bundle. Orchestrators upload the whole dir.

    Contents:
        report.json        — full JSON (from CLI --json)
        report.html        — standalone HTML view
        summary.txt        — one-line summary + triage paragraph
        flags.csv          — one row per flag
        iocs.csv           — one row per IOC (url / hash / domain / ip)
        report.sarif       — SARIF 2.1
        report.stix.json   — STIX 2.1 indicator bundle
    """
    from .render import html as render_html
    from .hunt import extract_iocs

    Path(out_dir).mkdir(parents=True, exist_ok=True)
    p = BundlePaths(
        directory=out_dir,
        json_path=os.path.join(out_dir, 'report.json'),
        html_path=os.path.join(out_dir, 'report.html'),
        summary_path=os.path.join(out_dir, 'summary.txt'),
        flags_csv_path=os.path.join(out_dir, 'flags.csv'),
        iocs_csv_path=os.path.join(out_dir, 'iocs.csv'),
        sarif_path=os.path.join(out_dir, 'report.sarif'),
        stix_path=os.path.join(out_dir, 'report.stix.json'),
        deep_dump_path=os.path.join(out_dir, 'deep_dump.md'),
    )

    # --- HTML ---
    Path(p.html_path).write_text(render_html.render(pdf, hits), encoding='utf-8')

    # --- JSON ---
    json_obj = _to_json(pdf, hits)
    Path(p.json_path).write_text(json.dumps(json_obj, indent=2, default=str), encoding='utf-8')

    # --- Summary ---
    Path(p.summary_path).write_text(
        summary_line(pdf) + '\n\n' + _triage_paragraph(pdf) + '\n', encoding='utf-8'
    )

    def _safe(v):
        """Make strings CSV-safe: strip NUL, newlines, control chars."""
        s = str(v).replace('\x00', '').replace('\r', ' ').replace('\n', ' ')
        return ''.join(ch for ch in s if ch >= ' ' or ch == '\t')

    # --- Flags CSV ---
    with open(p.flags_csv_path, 'w', encoding='utf-8', newline='') as fh:
        w = csv.writer(fh, quoting=csv.QUOTE_ALL)
        w.writerow(['severity', 'code', 'message'])
        for sev, code, msg in pdf.flags:
            w.writerow([_safe(sev), _safe(code), _safe(msg)])

    # --- IOCs CSV ---
    iocs = extract_iocs(pdf)
    with open(p.iocs_csv_path, 'w', encoding='utf-8', newline='') as fh:
        w = csv.writer(fh, quoting=csv.QUOTE_ALL)
        w.writerow(['kind', 'value', 'context'])
        for u in iocs.urls:
            w.writerow(['url', _safe(u), ''])
        for d in iocs.domains:
            w.writerow(['domain', _safe(d), ''])
        for idx, sha, size in iocs.stream_sha256:
            w.writerow(['stream_sha256', _safe(sha), f'obj={idx} size={size}'])

    # --- SARIF ---
    Path(p.sarif_path).write_text(json.dumps(to_sarif(pdf), indent=2), encoding='utf-8')

    # --- STIX ---
    Path(p.stix_path).write_text(json.dumps(to_stix(pdf), indent=2), encoding='utf-8')

    # --- Deep dump (single-file catch-all view) ---
    try:
        Path(p.deep_dump_path).write_text(render_deep_dump(pdf, hits), encoding='utf-8')
    except Exception as e:
        Path(p.deep_dump_path).write_text(f'(deep dump failed: {e})\n', encoding='utf-8')

    return p


def _triage_paragraph(pdf: PDFFile) -> str:
    sev = max_severity(pdf)
    verdict = {
        'HIGH': 'This PDF exhibits high-severity indicators and should be treated as malicious pending dynamic validation.',
        'MED':  'This PDF exhibits medium-severity indicators; review the click targets and downstream chain before opening.',
        'LOW':  'Low-severity findings only; structurally unusual but no active execution paths.',
        'NONE': 'No flags raised. Structure appears benign under the current rule set.',
    }.get(sev, 'No flags raised.')

    flag_sum = '; '.join(f'{s}:{c}' for s, c, _ in pdf.flags) or '(none)'
    return (
        f'Verdict: {verdict}\n'
        f'Flags: {flag_sum}\n'
        f'Revisions: {len(pdf.revisions)}.  Objects: {len(pdf.objects)}.  '
        f'Streams: {sum(1 for o in pdf.objects if o.stream)}.  Size: {pdf.size:,} bytes.'
    )


def _to_json(pdf, hits) -> dict:
    """JSON-serializable dump (kept local to avoid circular import)."""
    return {
        'schema': 'pdfstudio-report/1',
        'path': pdf.path,
        'size': pdf.size,
        'header': pdf.header,
        'revisions': [
            {
                'index': r.index,
                'startxref': r.trailer.startxref,
                'size': r.trailer.size,
                'prev': r.trailer.prev,
                'root': list(r.trailer.root) if r.trailer.root else None,
                'byte_range': list(r.byte_range),
                'new_objects': sorted(r.new_objects),
                'rewritten_objects': sorted(r.rewritten_objects),
            }
            for r in pdf.revisions
        ],
        'objects': [
            {
                'index': o.index, 'generation': o.generation,
                'offset': o.offset, 'length': o.raw_length,
                'md5': o.md5, 'kind': o.kind, 'revision': o.revision,
                'labels': o.labels,
                'has_stream': o.stream is not None,
                'stream_filters': o.stream.filters if o.stream else [],
                'stream_declared_length': o.stream.declared_length if o.stream else None,
                'stream_decode_error': o.stream.decode_error if o.stream else None,
            }
            for o in sorted(pdf.objects, key=lambda x: (x.revision, x.index))
        ],
        'triggers': [
            {
                'trigger': h.trigger, 'anchor_obj': h.anchor_obj,
                'target_obj': h.target_obj, 'path': h.path,
                'detail': h.detail, 'severity': h.severity,
            }
            for h in hits
        ],
        'flags': [{'severity': s, 'code': c, 'message': m} for s, c, m in pdf.flags],
        'max_severity': max_severity(pdf),
    }


# ---------------------------------------------------------------------------
# SARIF 2.1 (Static Analysis Results Interchange Format)
# ---------------------------------------------------------------------------

def to_sarif(pdf: PDFFile) -> dict:
    """Convert pdfstudio flags to a SARIF 2.1 log."""
    from . import __version__

    severity_to_level = {'HIGH': 'error', 'MED': 'warning', 'LOW': 'note', 'INFO': 'note'}

    rule_ids = sorted({c for _s, c, _m in pdf.flags})
    rules = [{
        'id': code,
        'name': code,
        'shortDescription': {'text': code},
        'fullDescription': {'text': next((m for s, c, m in pdf.flags if c == code), code)},
        'defaultConfiguration': {
            'level': severity_to_level.get(
                next((s for s, c, _m in pdf.flags if c == code), 'INFO'),
                'note',
            ),
        },
    } for code in rule_ids]

    results = []
    for sev, code, msg in pdf.flags:
        results.append({
            'ruleId': code,
            'level': severity_to_level.get(sev, 'note'),
            'message': {'text': msg},
            'locations': [{
                'physicalLocation': {
                    'artifactLocation': {'uri': os.path.basename(pdf.path)},
                }
            }],
        })

    return {
        'version': '2.1.0',
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'pdfstudio',
                    'version': __version__,
                    'informationUri': 'https://github.com/boredchilada/pdfstudio',
                    'rules': rules,
                }
            },
            'results': results,
        }],
    }


# ---------------------------------------------------------------------------
# STIX 2.1 indicator bundle
# ---------------------------------------------------------------------------

def to_stix(pdf: PDFFile) -> dict:
    """Convert IOCs + the PDF's file identity to a STIX 2.1 bundle."""
    from .hunt import extract_iocs
    import uuid

    def sdo(type_: str, **fields) -> dict:
        return {
            'type': type_,
            'spec_version': '2.1',
            'id': f'{type_}--{uuid.uuid4()}',
            'created': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'modified': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            **fields,
        }

    md5, sha256 = _file_hashes(pdf.path)

    objects = []

    # File observable for the PDF itself
    objects.append({
        'type': 'file',
        'spec_version': '2.1',
        'id': f'file--{uuid.uuid4()}',
        'hashes': {'MD5': md5, 'SHA-256': sha256},
        'name': os.path.basename(pdf.path),
        'size': pdf.size,
    })

    iocs = extract_iocs(pdf)
    for u in iocs.urls:
        objects.append(sdo(
            'indicator',
            pattern=f"[url:value = '{u}']",
            pattern_type='stix',
            valid_from=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            labels=['pdf-click-target'],
        ))
    for d in iocs.domains:
        objects.append(sdo(
            'indicator',
            pattern=f"[domain-name:value = '{d}']",
            pattern_type='stix',
            valid_from=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            labels=['pdf-domain'],
        ))
    for idx, sha, size in iocs.stream_sha256:
        objects.append(sdo(
            'indicator',
            pattern=f"[file:hashes.'SHA-256' = '{sha}']",
            pattern_type='stix',
            valid_from=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            labels=['pdf-embedded-stream'],
            description=f'Embedded stream SHA-256 from obj {idx} ({size} B decoded)',
        ))

    # Flags as STIX notes attached to the file
    for sev, code, msg in pdf.flags:
        objects.append(sdo(
            'note',
            abstract=f'{sev}: {code}',
            content=msg,
            authors=['pdfstudio'],
            object_refs=[objects[0]['id']],
        ))

    return {
        'type': 'bundle',
        'id': f'bundle--{uuid.uuid4()}',
        'objects': objects,
    }


# ---------------------------------------------------------------------------
# Batch mode
# ---------------------------------------------------------------------------

def _worker_scan(path: str, out_root: str) -> dict:
    """One-file worker: parse, classify, walk, flag, write bundle. Return a row dict."""
    from .parser import parse
    from .classify import classify
    from .walker import walk
    from .flags import run_all as run_flags

    row = {'path': path, 'status': 'ok', 'error': ''}
    try:
        pdf = parse(path)
        classify(pdf)
        hits = walk(pdf)
        run_flags(pdf)
    except Exception as e:
        row['status'] = 'parse_error'
        row['error'] = str(e)
        return row

    md5, sha256 = _file_hashes(path)
    row['md5'] = md5
    row['sha256'] = sha256
    row['size'] = pdf.size
    row['severity'] = max_severity(pdf)
    row['flag_codes'] = ','.join(sorted({c for _s, c, _m in pdf.flags}))

    # Bundle directory per file: <out_root>/<sha256>/
    bundle_dir = os.path.join(out_root, sha256 if sha256 != '(n/a)' else md5)
    write_bundle(pdf, hits, bundle_dir)
    row['bundle_dir'] = bundle_dir
    return row


def run_batch(paths: Iterable[str], out_root: str, *, jobs: int = 1) -> list[dict]:
    """Process many PDFs in parallel. Returns one row dict per input."""
    paths = list(paths)
    if jobs <= 1:
        return [_worker_scan(p, out_root) for p in paths]

    from concurrent.futures import ProcessPoolExecutor, as_completed
    rows: list[dict] = []
    with ProcessPoolExecutor(max_workers=jobs) as ex:
        futures = {ex.submit(_worker_scan, p, out_root): p for p in paths}
        for fut in as_completed(futures):
            try:
                rows.append(fut.result())
            except Exception as e:
                rows.append({'path': futures[fut], 'status': 'worker_error', 'error': str(e)})
    return rows


def write_batch_index(rows: list[dict], out_root: str) -> tuple[str, str]:
    """Write index.csv + index.json summarising a batch run."""
    csv_path = os.path.join(out_root, 'index.csv')
    json_path = os.path.join(out_root, 'index.json')
    fields = ['path', 'status', 'md5', 'sha256', 'size', 'severity', 'flag_codes', 'bundle_dir', 'error']
    with open(csv_path, 'w', encoding='utf-8', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction='ignore')
        w.writeheader()
        w.writerows(rows)
    with open(json_path, 'w', encoding='utf-8') as fh:
        json.dump({'rows': rows}, fh, indent=2, default=str)
    return csv_path, json_path
