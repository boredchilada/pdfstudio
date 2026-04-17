#!/usr/bin/env python3
"""
pdfstudio — static structure browser for PDF files.

Stevens-style single-file entry point. All heavy lifting lives in the
sibling `pdfstudio` package. Stdlib only.

Common usage (default view):
    pdfstudio.py file.pdf                     # structure + triggers + flags
    pdfstudio.py file.pdf --html out.html     # standalone HTML report
    pdfstudio.py file.pdf --json              # JSON dump to stdout

pdfid parity:
    pdfstudio.py file.pdf --pdfid             # pdfid-style keyword summary

pdf-parser parity (surgical):
    pdfstudio.py file.pdf -o 21               # show one object
    pdfstudio.py file.pdf -o 21 -d raw.bin    # dump raw stream of obj 21
    pdfstudio.py file.pdf -o 21 -D decoded.bin # dump filter-decoded stream
    pdfstudio.py file.pdf -s "/Launch"        # search for keyword
    pdfstudio.py file.pdf -s "MZ" --in-streams
    pdfstudio.py file.pdf -r 21               # objects referencing obj 21

Graph output (beyond Stevens):
    pdfstudio.py file.pdf --mermaid           # Catalog graph as Mermaid
    pdfstudio.py file.pdf --dot graph.dot     # Catalog graph as Graphviz DOT

Tuning:
    --full-graph   include all objects in Mermaid/DOT (not just reachable)
    --revision N   target specific revision for -o / -d / -D (default: latest)
    --no-decode    skip stream decoding (faster; disables MZ/entropy checks)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Windows consoles default to cp1252 which can't render the Unicode box /
# arrow glyphs pdfstudio emits. Reconfigure stdio to UTF-8 on Windows only.
if os.name == 'nt':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

from . import __version__
from .parser import parse
from .classify import classify
from .walker import walk
from .flags import run_all as run_flags
from .render import text as render_text
from .render import html as render_html
from .extract import show_object, dump_stream
from .search import search_keyword, find_referrers
from .pdfid_view import render_pdfid
from .graphviz_out import render_mermaid, render_dot
from .rects_svg import render_svg as render_rects_svg
from .hexview import hexdump
from .diff import diff as pdf_diff, render_diff
from .objstm import expand_objstm_all
from .parity import (
    search_key, filter_by_type, filter_elements, render_stats,
    content_view, parse_object_list,
)
from .walk_view import render_walk
from .xrefstream import parse_xref_streams
from .malformed import extract_malformed, extract_regions, render_regions
from .shell import PDFShell
from . import hunt as hunt_mod
from .disarm import disarm as disarm_pdf, render_report as render_disarm_report
from .recursive import expand_embedded_pdfs, render_children
from .tui import run_tui
from .automation import (
    summary_line, compute_exit_code, write_bundle, to_sarif, to_stix,
    run_batch, write_batch_index,
    EXIT_OK, EXIT_BAD_ARGS, EXIT_PARSE_FAIL,
)


def _to_json(pdf, hits) -> dict:
    return {
        'path': pdf.path,
        'size': pdf.size,
        'header': pdf.header,
        'eof_offsets': pdf.eof_offsets,
        'startxref_offsets': pdf.startxref_offsets,
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
                'eof_offset': r.trailer.eof_offset,
            }
            for r in pdf.revisions
        ],
        'objects': [
            {
                'index': o.index,
                'generation': o.generation,
                'offset': o.offset,
                'length': o.raw_length,
                'md5': o.md5,
                'kind': o.kind,
                'revision': o.revision,
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
        'flags': [
            {'severity': s, 'code': c, 'message': m} for s, c, m in pdf.flags
        ],
        'parse_warnings': pdf.parse_warnings,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog='pdfstudio',
        description='Static structure browser for PDF files — PE Studio-style for PDFs.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument('file', help='Path to the PDF file to analyze.')

    # Top-level view modes (mutually exclusive with each other where it matters)
    ap.add_argument('--html', metavar='OUT', help='Write a standalone HTML report to OUT.')
    ap.add_argument('--json', action='store_true', help='Emit JSON to stdout instead of text.')
    ap.add_argument('--pdfid', action='store_true', help='Emit a pdfid-style keyword summary.')
    ap.add_argument('--nozero', action='store_true',
                    help='With --pdfid: suppress keywords whose count is zero (pdfid -n).')
    ap.add_argument('--extra-info', action='store_true',
                    help='With --pdfid: show /CreationDate /ModDate /Producer ... (pdfid -e).')
    ap.add_argument('--all-keywords', action='store_true',
                    help='With --pdfid: show an expanded PDF keyword table (pdfid -a).')
    ap.add_argument('--recursedir', action='store_true',
                    help='When the positional argument is a directory, recurse into subdirectories.')
    ap.add_argument('--mermaid', action='store_true', help='Emit a Mermaid flowchart of the Catalog graph.')
    ap.add_argument('--dot', metavar='OUT', help='Write a Graphviz DOT file to OUT.')
    ap.add_argument('--full-graph', action='store_true',
                    help='For --mermaid / --dot, include all objects (not just Catalog-reachable).')

    # pdf-parser-style surgical ops
    ap.add_argument('-o', '--object', metavar='SPEC',
                    help='Show (or operate on) object(s). Accepts "12", "12,15" or "20-25".')
    ap.add_argument('-g', '--generation', type=int, default=0, metavar='G',
                    help='Generation number for --object (default: 0).')
    ap.add_argument('--revision', type=int, metavar='V',
                    help='Revision for --object (default: latest revision).')
    ap.add_argument('-d', '--dump-raw', metavar='OUT',
                    help='Dump raw (undecoded) stream bytes of --object to OUT.')
    ap.add_argument('-D', '--dump-decoded', metavar='OUT',
                    help='Dump filter-decoded stream bytes of --object to OUT.')
    ap.add_argument('-s', '--search', metavar='KEYWORD',
                    help='Search object bodies for KEYWORD (case-insensitive by default).')
    ap.add_argument('--case', action='store_true', help='Case-sensitive --search.')
    ap.add_argument('--in-streams', action='store_true',
                    help='--search also scans decoded stream contents.')
    ap.add_argument('--unfiltered', action='store_true',
                    help='--search also scans raw (pre-filter) stream bytes.')
    ap.add_argument('--regex', action='store_true',
                    help='Treat --search KEYWORD as a regex.')
    ap.add_argument('-r', '--refs', type=int, metavar='N',
                    help='List every object that references object N.')

    # pdf-parser: -k KEY, -t TYPE, -e ELEMENTS, -a, -c, -O, -y
    ap.add_argument('-k', '--key', metavar='/KEY',
                    help='Find every dict with the given /KEY; print its value.')
    ap.add_argument('-t', '--type', metavar='TYPE',
                    help='Filter objects by /Type value (e.g. /Page, Catalog).')
    ap.add_argument('-e', '--elements', metavar='LETTERS',
                    help='Filter output by element class (c=comment x=xref t=trailer s=startxref i=indirect).')
    ap.add_argument('-a', '--stats', action='store_true',
                    help='Display object/type/filter statistics for the PDF.')
    ap.add_argument('-c', '--content', action='store_true',
                    help='Print body of every object without a filtered stream.')
    ap.add_argument('-O', '--objstm', action='store_true',
                    help='Expand /ObjStm compressed children into the object list.')
    ap.add_argument('-v', '--verbose', action='store_true',
                    help='Print parse warnings (malformed elements).')
    ap.add_argument('-y', '--yara', metavar='RULES',
                    help='YARA rule file or directory; scans file + decoded streams.')
    ap.add_argument('--yarastrings', action='store_true',
                    help='Print matching YARA strings with offsets.')

    # Walker view + malformed extract + interactive shell
    ap.add_argument('--walk', action='store_true',
                    help='Print a full tree walk of the Catalog-reachable object graph.')
    ap.add_argument('-x', '--extract-malformed', metavar='OUT',
                    help='Write unclaimed (malformed/overlay) bytes to OUT.')
    ap.add_argument('--show-malformed', action='store_true',
                    help='Show a summary table of unclaimed byte regions.')
    ap.add_argument('--shell', action='store_true',
                    help='Enter the interactive REPL on the parsed PDF.')
    ap.add_argument('--tui', action='store_true',
                    help='Enter the curses TUI (arrow-key navigation, live object browser).')
    ap.add_argument('--disarm', metavar='OUT.pdf',
                    help='Write a neutralized copy of the PDF to OUT.pdf '
                         '(byte-substitutes /OpenAction, /AA, /Launch, /JS, /JavaScript).')
    ap.add_argument('-R', '--recursive', action='store_true',
                    help='Recursively parse embedded PDFs found inside /EmbeddedFile streams.')
    ap.add_argument('--recursive-depth', type=int, default=5, metavar='N',
                    help='Max recursion depth for --recursive (default: 5).')

    # Threat-hunting / network enrichment (opt-in; default-off)
    ap.add_argument('--hunt', action='store_true',
                    help='Run forensic enrichment: extract URLs/hashes, DNS+HEAD+URLhaus.')
    ap.add_argument('--hunt-offline', action='store_true',
                    help='Like --hunt but no network — just extract and list IOCs.')
    ap.add_argument('--hunt-vt', action='store_true',
                    help='With --hunt: also query VirusTotal (needs VT_API_KEY env var).')
    ap.add_argument('--hunt-mb', action='store_true',
                    help='With --hunt: also query MalwareBazaar (needs MB_API_KEY env var).')
    ap.add_argument('--hunt-nodns', action='store_true',
                    help='With --hunt: skip DNS lookups.')
    ap.add_argument('--hunt-nohead', action='store_true',
                    help='With --hunt: skip HTTP HEAD requests.')

    # Visual / comparative views
    ap.add_argument('--rects', metavar='OUT.svg',
                    help='Write an SVG overlay of every page\'s MediaBox + annotation Rects.')
    ap.add_argument('--hex', action='store_true',
                    help='With --object N: show a hex dump of the body (and decoded stream).')
    ap.add_argument('--hex-max', type=int, default=512,
                    help='With --hex: max bytes to dump per section (0 = unlimited; default 512).')
    ap.add_argument('--diff', metavar='OTHER.pdf',
                    help='Compare this PDF against OTHER.pdf (structural diff).')

    # Automation / orchestration
    ap.add_argument('--summary-line', action='store_true',
                    help='Print a single stable key=value one-liner to stdout and exit.')
    ap.add_argument('--report', metavar='DIR',
                    help='Write a per-file report bundle (json/html/csv/sarif/stix/summary) to DIR.')
    ap.add_argument('--sarif', metavar='OUT.sarif',
                    help='Write a SARIF 2.1 file with every flag as a result.')
    ap.add_argument('--stix', metavar='OUT.json',
                    help='Write a STIX 2.1 bundle of observables + indicators + notes.')
    ap.add_argument('--csv', metavar='OUT.csv',
                    help='Write a flat CSV of all flags (severity,code,message).')
    ap.add_argument('--batch', metavar='FILE',
                    help='Process every path in FILE (one per line; use "-" for stdin). '
                         'Writes a bundle per file into --report DIR; pass --report as required.')
    ap.add_argument('--jobs', type=int, default=1, metavar='N',
                    help='Parallel workers for --batch (default: 1).')
    ap.add_argument('--exit-on-severity', metavar='LEVEL',
                    help='Exit code = HIGH if any flag severity >= LEVEL (HIGH/MED/LOW); else OK.')
    ap.add_argument('--strict-exit', action='store_true',
                    help='Use the severity-based exit code policy '
                         '(HIGH=20, MED=10, LOW=5, OK=0, parse_fail=3).')

    ap.add_argument('--no-decode', action='store_true',
                    help='Skip stream decoding (faster; MZ/entropy checks disabled).')
    ap.add_argument('--version', action='version', version=f'pdfstudio {__version__}')
    args = ap.parse_args(argv)

    # --- Batch mode (takes a @file or `-` of input paths) ------------------
    if args.batch:
        if not args.report:
            print('pdfstudio: --batch requires --report DIR', file=sys.stderr)
            return EXIT_BAD_ARGS
        if args.batch == '-':
            paths = [ln.strip() for ln in sys.stdin if ln.strip()]
        else:
            paths = [ln.strip() for ln in Path(args.batch).read_text(encoding='utf-8').splitlines()
                     if ln.strip() and not ln.startswith('#')]
        print(f'pdfstudio: batch scanning {len(paths)} file(s) with {args.jobs} worker(s)...',
              file=sys.stderr)
        rows = run_batch(paths, args.report, jobs=args.jobs)
        csv_p, json_p = write_batch_index(rows, args.report)
        print(f'pdfstudio: wrote batch index {csv_p}', file=sys.stderr)
        # Exit code = worst severity observed in the batch
        worst = 'NONE'
        from pdfstudio.automation import SEVERITY_ORDER as _SO
        for r in rows:
            if r.get('severity') and _SO.get(r['severity'], 0) > _SO.get(worst, -1):
                worst = r['severity']
        from pdfstudio.automation import compute_exit_code as _ec  # noqa
        # Fake a PDFFile-like for exit code via dict access
        class _X:
            pass
        _x = _X()
        _x.flags = [(worst, 'batch', 'batch worst severity')] if worst != 'NONE' else []
        return compute_exit_code(_x, threshold=args.exit_on_severity) if args.strict_exit else EXIT_OK

    path = Path(args.file)

    # --- Directory-scan mode ------------------------------------------------
    # If the positional arg is a directory, enumerate PDFs inside.
    #  - With --report DIR → run full batch (parallel, per-file bundles).
    #  - Else → one-line triage (or --pdfid summary) per PDF.
    if path.is_dir():
        pattern = '**/*.pdf' if args.recursedir else '*.pdf'
        files = [str(p) for p in sorted(path.glob(pattern))]
        # Also match upper-case extensions (common on Windows samples)
        pattern_upper = '**/*.PDF' if args.recursedir else '*.PDF'
        files.extend(str(p) for p in sorted(path.glob(pattern_upper))
                     if str(p) not in files)
        if not files:
            print(f'pdfstudio: no .pdf files under {path} '
                  f'{"(recursive)" if args.recursedir else "(top level — use --recursedir to recurse)"}',
                  file=sys.stderr)
            return 1

        # ---- Batch path: user asked for a report bundle ----
        if args.report:
            print(f'pdfstudio: scanning {path} → {len(files)} PDF(s) with {args.jobs} worker(s)...',
                  file=sys.stderr)
            rows = run_batch(files, args.report, jobs=args.jobs)
            csv_p, _json_p = write_batch_index(rows, args.report)
            print(f'pdfstudio: wrote batch index {csv_p}', file=sys.stderr)
            worst = 'NONE'
            from pdfstudio.automation import SEVERITY_ORDER as _SO
            for r in rows:
                if r.get('severity') and _SO.get(r['severity'], 0) > _SO.get(worst, -1):
                    worst = r['severity']
            class _Tmp: ...
            _t = _Tmp()
            _t.flags = [(worst, 'batch', '')] if worst != 'NONE' else []
            # Print one-liner summary of the batch to stdout
            print(f'pdfstudio: batch_worst_severity={worst} files={len(files)} '
                  f'report_dir={args.report}')
            if args.strict_exit or args.exit_on_severity:
                return compute_exit_code(_t, threshold=args.exit_on_severity)
            return EXIT_OK

        # ---- Light-weight per-file triage (no bundle writes) ----
        worst = 'NONE'
        from pdfstudio.automation import SEVERITY_ORDER as _SO, max_severity as _msev
        for f in files:
            try:
                sub_pdf = parse(f, decode_streams=not args.no_decode)
                classify(sub_pdf)
                run_flags(sub_pdf)
            except Exception as e:
                print(f'{f} : parse error — {e}', file=sys.stderr)
                continue
            sev = _msev(sub_pdf)
            if _SO.get(sev, 0) > _SO.get(worst, -1):
                worst = sev
            if args.pdfid:
                print(f'=== {f} ===')
                sys.stdout.write(render_pdfid(
                    sub_pdf,
                    nozero=args.nozero,
                    extra_info=args.extra_info,
                    all_keywords=args.all_keywords,
                ))
                print()
            elif args.summary_line:
                print(summary_line(sub_pdf))
            else:
                flag_codes = [c for s, c, _ in sub_pdf.flags if s in ('HIGH', 'MED')]
                print(f'{f:<72}  {sub_pdf.size:>10,} B  '
                      f'sev={sev:<5} '
                      f'revs={len(sub_pdf.revisions)}  '
                      f'objs={len(sub_pdf.objects)}  '
                      f'flags={",".join(flag_codes) if flag_codes else "—"}')
        if args.strict_exit or args.exit_on_severity:
            class _Tmp: ...
            _t = _Tmp()
            _t.flags = [(worst, 'dir', '')] if worst != 'NONE' else []
            return compute_exit_code(_t, threshold=args.exit_on_severity)
        return EXIT_OK

    if not path.is_file():
        print(f'pdfstudio: error: {path} is not a file or directory', file=sys.stderr)
        return 2

    # --- pipeline -----------------------------------------------------------
    try:
        pdf = parse(str(path), decode_streams=not args.no_decode)
    except Exception as e:
        print(f'pdfstudio: parse failed — {e}', file=sys.stderr)
        return EXIT_PARSE_FAIL
    classify(pdf)

    # Parse any /XRef cross-reference streams (modern PDFs).
    xref_records = parse_xref_streams(pdf)
    if xref_records:
        # xref streams may introduce new trailer entries; recompute revisions
        # via the parser's revision reconstruction by calling parse's logic
        # (simplest: re-sort trailers and rebuild revisions from them).
        pdf.trailers.sort(key=lambda t: t.startxref)
        # parser already populated pdf.revisions from classic trailers; we only
        # want to surface the presence of xref streams. The flag engine will tag
        # XREF_STREAM so analysts know the revision table may be incomplete.

    if args.objstm:
        added = expand_objstm_all(pdf)
        if added:
            classify(pdf)  # re-classify so synthetic children get a kind
            print(f'pdfstudio: expanded {added} /ObjStm child object(s)', file=sys.stderr)
    if args.recursive:
        added_children = expand_embedded_pdfs(pdf, max_depth=args.recursive_depth)
        if added_children:
            print(f'pdfstudio: parsed {added_children} embedded PDF(s)', file=sys.stderr)
    hits = walk(pdf)
    run_flags(pdf)

    # Parse -o SPEC once; used by many branches below.
    selected_objects: list[int] = []
    if args.object:
        try:
            selected_objects = parse_object_list(args.object)
        except ValueError:
            print(f'pdfstudio: invalid -o / --object spec: {args.object!r}', file=sys.stderr)
            return 2

    # --- dispatch -----------------------------------------------------------
    did_output = False

    # Automation: one-line summary (emit first so orchestrators can grep it)
    if args.summary_line:
        print(summary_line(pdf))
        did_output = True

    # Automation: per-file report bundle
    if args.report:
        bundle = write_bundle(pdf, hits, args.report)
        print(f'pdfstudio: wrote bundle -> {bundle.directory}', file=sys.stderr)
        did_output = True

    # Automation: individual SARIF / STIX / CSV exports
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(to_sarif(pdf), indent=2), encoding='utf-8')
        print(f'pdfstudio: wrote SARIF  -> {args.sarif}', file=sys.stderr)
        did_output = True
    if args.stix:
        Path(args.stix).write_text(json.dumps(to_stix(pdf), indent=2), encoding='utf-8')
        print(f'pdfstudio: wrote STIX   -> {args.stix}', file=sys.stderr)
        did_output = True
    if args.csv:
        import csv as _csv
        with open(args.csv, 'w', encoding='utf-8', newline='') as fh:
            w = _csv.writer(fh)
            w.writerow(['severity', 'code', 'message'])
            for sev, code, msg in pdf.flags:
                w.writerow([sev, code, msg])
        print(f'pdfstudio: wrote CSV    -> {args.csv}', file=sys.stderr)
        did_output = True

    if args.json:
        json.dump(_to_json(pdf, hits), sys.stdout, indent=2, default=str)
        sys.stdout.write('\n')
        did_output = True

    if args.html:
        Path(args.html).write_text(render_html.render(pdf, hits), encoding='utf-8')
        print(f'Wrote HTML report: {args.html}', file=sys.stderr)
        did_output = True

    if args.pdfid:
        sys.stdout.write(render_pdfid(
            pdf,
            nozero=args.nozero,
            extra_info=args.extra_info,
            all_keywords=args.all_keywords,
        ))
        did_output = True

    if args.mermaid:
        sys.stdout.write(render_mermaid(pdf, only_interesting=not args.full_graph))
        did_output = True

    if args.dot:
        Path(args.dot).write_text(render_dot(pdf, only_interesting=not args.full_graph),
                                  encoding='utf-8')
        print(f'Wrote Graphviz DOT: {args.dot}', file=sys.stderr)
        did_output = True

    if args.rects:
        Path(args.rects).write_text(render_rects_svg(pdf), encoding='utf-8')
        print(f'Wrote annotation SVG: {args.rects}', file=sys.stderr)
        did_output = True

    if args.walk:
        sys.stdout.write(render_walk(pdf))
        did_output = True

    if args.extract_malformed:
        data = extract_malformed(pdf)
        Path(args.extract_malformed).write_bytes(data)
        print(f'Wrote {len(data)} byte(s) of unclaimed content to {args.extract_malformed}',
              file=sys.stderr)
        did_output = True

    if args.show_malformed:
        sys.stdout.write(render_regions(extract_regions(pdf)))
        did_output = True

    if args.hunt or args.hunt_offline:
        is_online = args.hunt and not args.hunt_offline
        hunt_mod.run_hunt(
            pdf,
            mode='all',
            with_dns=is_online and not args.hunt_nodns,
            with_head=is_online and not args.hunt_nohead,
            with_urlhaus=is_online,
            with_vt=is_online and args.hunt_vt,
            with_mb=is_online and args.hunt_mb,
            stdout=sys.stdout,
        )
        did_output = True

    if args.disarm:
        report = disarm_pdf(pdf, args.disarm)
        sys.stdout.write(render_disarm_report(report))
        did_output = True

    if args.recursive and hasattr(pdf, 'children') and pdf.children:
        sys.stdout.write('\nEmbedded PDFs:\n')
        sys.stdout.write(render_children(pdf))
        did_output = True

    if args.tui:
        return run_tui(pdf)

    if args.shell:
        shell = PDFShell(pdf, hunt_enabled=(args.hunt or args.hunt_offline), hunt_module=hunt_mod)
        try:
            shell.cmdloop()
        except KeyboardInterrupt:
            print()
        did_output = True

    if args.diff:
        other_path = Path(args.diff)
        if not other_path.is_file():
            print(f'pdfstudio: --diff target {other_path} not found', file=sys.stderr)
            return 2
        other = parse(str(other_path), decode_streams=not args.no_decode)
        classify(other)
        result = pdf_diff(pdf, other)
        sys.stdout.write(render_diff(result,
                                     left_name=Path(args.file).name,
                                     right_name=other_path.name))
        did_output = True

    # -o / -d / -D — object display and extraction
    if args.dump_raw or args.dump_decoded:
        if not selected_objects:
            print('pdfstudio: --dump-raw / --dump-decoded require -o / --object', file=sys.stderr)
            return 2
        if len(selected_objects) > 1 and (args.dump_raw or args.dump_decoded):
            print('pdfstudio: dump flags accept only one object at a time', file=sys.stderr)
            return 2
        idx = selected_objects[0]
        if args.dump_raw:
            data = dump_stream(pdf, idx, args.generation, decoded=False, revision=args.revision)
            if data is None:
                print(f'pdfstudio: obj {idx} has no stream (or not found)', file=sys.stderr)
                return 1
            Path(args.dump_raw).write_bytes(data)
            print(f'Wrote {len(data)} raw bytes to {args.dump_raw}', file=sys.stderr)
            did_output = True
        if args.dump_decoded:
            data = dump_stream(pdf, idx, args.generation, decoded=True, revision=args.revision)
            if data is None:
                print(f'pdfstudio: obj {idx} has no decoded stream (or decode failed)',
                      file=sys.stderr)
                return 1
            Path(args.dump_decoded).write_bytes(data)
            print(f'Wrote {len(data)} decoded bytes to {args.dump_decoded}', file=sys.stderr)
            did_output = True
    elif selected_objects:
        # Display one or more objects
        max_b = None if args.hex_max == 0 else args.hex_max
        for idx in selected_objects:
            sys.stdout.write(show_object(pdf, idx, args.generation, args.revision))
            if args.hex:
                target = None
                for o in pdf.objects:
                    if o.index == idx and o.generation == args.generation:
                        if args.revision is None or o.revision == args.revision:
                            target = o
                            break
                if target is not None:
                    sys.stdout.write('\n--- body hex ---\n')
                    sys.stdout.write(hexdump(target.body.encode('latin-1'),
                                             start_offset=target.offset, max_bytes=max_b))
                    if target.stream is not None:
                        if target.stream.raw_bytes:
                            sys.stdout.write('\n--- stream raw hex ---\n')
                            sys.stdout.write(hexdump(target.stream.raw_bytes,
                                                     start_offset=target.stream.raw_offset,
                                                     max_bytes=max_b))
                        if target.stream.decoded_bytes is not None:
                            sys.stdout.write('\n--- stream decoded hex ---\n')
                            sys.stdout.write(hexdump(target.stream.decoded_bytes,
                                                     start_offset=0, max_bytes=max_b))
            sys.stdout.write('\n')
        did_output = True

    if args.search:
        matches = search_keyword(pdf, args.search,
                                 case=args.case,
                                 in_streams=args.in_streams,
                                 regex=args.regex,
                                 unfiltered=args.unfiltered)
        if not matches:
            print(f'(no matches for {args.search!r})')
        else:
            for m in matches:
                print(f'obj {m.obj.index:>4} [{m.obj.kind:<20}] ({m.where:<6}) {m.snippet}')
        did_output = True

    if args.key:
        results = search_key(pdf, args.key)
        if not results:
            print(f'(no object contains key {args.key})')
        else:
            for obj, val in results:
                print(f'obj {obj.index:>4} [{obj.kind:<24}]  {args.key} = {val}')
        did_output = True

    if args.type:
        results = filter_by_type(pdf, args.type)
        if not results:
            print(f'(no object has /Type matching {args.type})')
        else:
            for obj in results:
                lbl = '; '.join(obj.labels) if obj.labels else ''
                print(f'obj {obj.index:>4}  v{obj.revision}  {obj.kind:<24} {lbl}')
        did_output = True

    if args.elements:
        bag = filter_elements(pdf, args.elements)
        for k, items in bag.items():
            print(f'=== {k} ({len(items)}) ===')
            if k == 'indirect':
                for o in items:
                    print(f'  obj {o.index:>4} v{o.revision} [{o.kind}]')
            elif k == 'trailer':
                for t in items:
                    print(f'  trailer @ {t.offset:#x}  startxref={t.startxref}  size={t.size}  prev={t.prev}  root={t.root}')
            elif k == 'startxref':
                for off in items:
                    print(f'  startxref @ {off:#x}')
            elif k == 'xref':
                for i in items:
                    print(f'  xref #{i}')
            elif k == 'comment':
                print('  (comment tracking not implemented in this version)')
        did_output = True

    if args.stats:
        sys.stdout.write(render_stats(pdf))
        did_output = True

    if args.content:
        sys.stdout.write(content_view(pdf))
        did_output = True

    if args.verbose and pdf.parse_warnings:
        print('--- parse warnings ---')
        for w in pdf.parse_warnings:
            print('  ' + w)
        did_output = did_output or True

    if args.yara:
        try:
            from pdfstudio.yara_scan import scan as yara_scan, render_hits
            yhits = yara_scan(pdf, args.yara, unfiltered=args.unfiltered,
                              show_strings=args.yarastrings)
            sys.stdout.write(render_hits(yhits, show_strings=args.yarastrings))
        except RuntimeError as e:
            print(f'pdfstudio: {e}', file=sys.stderr)
            return 1
        did_output = True

    if args.refs is not None:
        refs = find_referrers(pdf, args.refs)
        if not refs:
            print(f'(no objects reference {args.refs} 0 R)')
        else:
            print(f'{len(refs)} object(s) reference {args.refs} 0 R:')
            for o in refs:
                print(f'  obj {o.index:>4} [{o.kind}]')
        did_output = True

    if not did_output:
        # Default: text structure view
        sys.stdout.write(render_text.render(pdf, hits))

    if args.strict_exit or args.exit_on_severity:
        return compute_exit_code(pdf, threshold=args.exit_on_severity)
    return EXIT_OK


if __name__ == '__main__':
    raise SystemExit(main())
