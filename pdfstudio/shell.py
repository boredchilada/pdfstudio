"""
pdfstudio.shell
Interactive REPL for a parsed PDF. Parses once, then answers queries
without re-reading the file.

Commands:
    help / ?                 show help
    info                     summary (counts, hashes, revisions)
    objects                  list all objects
    obj N [--hex]            show object N (optionally with hex dump)
    body N                   print raw body of object N
    stream N [raw|dec]       print stream (decoded by default)
    triggers                 re-run walker
    walk                     catalog-tree walk
    flags                    show flag engine output
    search KW                search bodies for KW
    key /KEY                 show every dict's value of /KEY
    refs N                   who references obj N?
    type TYPE                objects whose /Type = TYPE
    revisions                per-revision NEW/REWRITTEN
    stats                    statistics
    dump N path              dump obj N raw stream to path
    ddump N path             dump obj N decoded stream to path
    hunt [url|hash|all]      forensic enrichment (requires --hunt at CLI time)
    quit / exit / q          leave
"""
from __future__ import annotations

import cmd
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Optional

from .model import PDFFile
from .walker import walk
from .extract import show_object, dump_stream
from .search import search_keyword, find_referrers
from .parity import search_key, filter_by_type, render_stats
from .walk_view import render_walk
from .hexview import hexdump


class PDFShell(cmd.Cmd):
    prompt = 'pdfstudio> '
    intro = (
        'pdfstudio interactive shell — parsed in-memory. Type `help` or `?` for commands, '
        '`quit` to leave.\n'
    )

    def __init__(self, pdf: PDFFile, *, hunt_enabled: bool = False,
                 hunt_module=None):
        super().__init__()
        self.pdf = pdf
        self.hunt_enabled = hunt_enabled
        self.hunt = hunt_module

    # ---------------- helpers ----------------

    def _find_obj(self, idx: int):
        candidates = [o for o in self.pdf.objects if o.index == idx]
        if not candidates:
            return None
        return max(candidates, key=lambda o: o.revision)

    def _parse_int(self, s: str) -> Optional[int]:
        try:
            return int(s)
        except (TypeError, ValueError):
            return None

    # ---------------- commands ----------------

    def do_info(self, arg):
        """Summary counts + header + hashes."""
        import hashlib
        with open(self.pdf.path, 'rb') as fh:
            raw = fh.read()
        md5 = hashlib.md5(raw).hexdigest()
        sha256 = hashlib.sha256(raw).hexdigest()
        print(f'  path       : {self.pdf.path}')
        print(f'  size       : {self.pdf.size:,} bytes')
        print(f'  md5        : {md5}')
        print(f'  sha-256    : {sha256}')
        print(f'  header     : {self.pdf.header}')
        print(f'  revisions  : {len(self.pdf.revisions)}')
        print(f'  objects    : {len(self.pdf.objects)}')
        print(f'  eof_count  : {len(self.pdf.eof_offsets)}')

    def do_objects(self, arg):
        """List every object."""
        for o in sorted(self.pdf.objects, key=lambda x: (x.revision, x.index)):
            stream_tag = ' [S]' if o.stream else ''
            lbls = '; '.join(o.labels[:2])
            print(f'  obj {o.index:>4}  v{o.revision}  {o.kind:<22}{stream_tag} {lbls}')

    def do_obj(self, arg):
        """obj N [--hex]   — show object N, optionally with hex dump."""
        parts = shlex.split(arg)
        if not parts:
            print('usage: obj N [--hex]')
            return
        idx = self._parse_int(parts[0])
        if idx is None:
            print('usage: obj N [--hex]')
            return
        print(show_object(self.pdf, idx))
        if '--hex' in parts[1:]:
            target = self._find_obj(idx)
            if target:
                print('\n--- body hex ---')
                print(hexdump(target.body.encode('latin-1'),
                              start_offset=target.offset, max_bytes=256))
                if target.stream and target.stream.decoded_bytes:
                    print('\n--- decoded stream hex ---')
                    print(hexdump(target.stream.decoded_bytes, start_offset=0, max_bytes=256))

    def do_body(self, arg):
        """body N   — print object body only."""
        idx = self._parse_int(arg.strip())
        if idx is None:
            print('usage: body N')
            return
        obj = self._find_obj(idx)
        if not obj:
            print(f'obj {idx} not found')
            return
        print(obj.body.rstrip())

    def do_stream(self, arg):
        """stream N [raw|dec]   — print stream body (decoded default)."""
        parts = shlex.split(arg)
        if not parts:
            print('usage: stream N [raw|dec]')
            return
        idx = self._parse_int(parts[0])
        if idx is None:
            print('usage: stream N [raw|dec]')
            return
        mode = parts[1] if len(parts) > 1 else 'dec'
        obj = self._find_obj(idx)
        if not obj or not obj.stream:
            print(f'obj {idx} has no stream')
            return
        data = obj.stream.decoded_bytes if mode == 'dec' else obj.stream.raw_bytes
        if data is None:
            print(f'(stream bytes unavailable, mode={mode})')
            return
        print(hexdump(data, start_offset=0, max_bytes=512))

    def do_triggers(self, arg):
        """Re-run the trigger walker."""
        for h in walk(self.pdf):
            print(f'  [{h.severity}] {h.path}')

    def do_walk(self, arg):
        """Render the Catalog-reachable object graph."""
        print(render_walk(self.pdf))

    def do_flags(self, arg):
        """Show flag-engine output."""
        for sev, code, msg in self.pdf.flags:
            print(f'  [{sev}] {code:<24} {msg}')

    def do_search(self, arg):
        """search KEYWORD [streams]   — keyword search; append 'streams' to include decoded stream bytes."""
        parts = shlex.split(arg)
        if not parts:
            print('usage: search KEYWORD [streams]')
            return
        kw = parts[0]
        in_streams = 'streams' in parts[1:]
        matches = search_keyword(self.pdf, kw, in_streams=in_streams)
        if not matches:
            print('(no matches)')
            return
        for m in matches:
            print(f'  obj {m.obj.index:>4} [{m.obj.kind:<20}] ({m.where}) {m.snippet}')

    def do_key(self, arg):
        """key /KEY   — every dict with that key + its value."""
        k = arg.strip()
        if not k:
            print('usage: key /KEY')
            return
        for obj, val in search_key(self.pdf, k):
            print(f'  obj {obj.index:>4} [{obj.kind}]  {k} = {val}')

    def do_refs(self, arg):
        """refs N   — objects referencing obj N."""
        idx = self._parse_int(arg.strip())
        if idx is None:
            print('usage: refs N')
            return
        refs = find_referrers(self.pdf, idx)
        if not refs:
            print(f'(no object references {idx} 0 R)')
            return
        for o in refs:
            print(f'  obj {o.index:>4} [{o.kind}]')

    def do_type(self, arg):
        """type TYPE   — objects whose /Type matches."""
        tname = arg.strip()
        if not tname:
            print('usage: type /Catalog | type Page | ...')
            return
        for o in filter_by_type(self.pdf, tname):
            print(f'  obj {o.index:>4} v{o.revision}  {o.kind}')

    def do_revisions(self, arg):
        """Per-revision NEW/REWRITTEN summary."""
        for r in self.pdf.revisions:
            print(f'  v{r.index}  startxref={r.trailer.startxref}  '
                  f'/Size={r.trailer.size}  /Prev={r.trailer.prev}  '
                  f'NEW={sorted(r.new_objects)}  REWRITE={sorted(r.rewritten_objects)}')

    def do_stats(self, arg):
        """Render stats view."""
        print(render_stats(self.pdf))

    def do_dump(self, arg):
        """dump N path   — write raw stream bytes of obj N to path."""
        parts = shlex.split(arg)
        if len(parts) != 2:
            print('usage: dump N path')
            return
        idx = self._parse_int(parts[0])
        if idx is None:
            print('usage: dump N path')
            return
        data = dump_stream(self.pdf, idx, decoded=False)
        if data is None:
            print(f'(no stream on obj {idx})')
            return
        Path(parts[1]).write_bytes(data)
        print(f'  wrote {len(data)} bytes to {parts[1]}')

    def do_ddump(self, arg):
        """ddump N path   — write filter-decoded stream bytes of obj N to path."""
        parts = shlex.split(arg)
        if len(parts) != 2:
            print('usage: ddump N path')
            return
        idx = self._parse_int(parts[0])
        if idx is None:
            print('usage: ddump N path')
            return
        data = dump_stream(self.pdf, idx, decoded=True)
        if data is None:
            print(f'(no decoded stream on obj {idx})')
            return
        Path(parts[1]).write_bytes(data)
        print(f'  wrote {len(data)} bytes to {parts[1]}')

    def do_hunt(self, arg):
        """hunt [url|hash|all]   — forensic enrichment (DNS/HEAD/URLhaus/...)."""
        if not self.hunt_enabled or self.hunt is None:
            print('hunt disabled — start the shell with --hunt at the CLI.')
            return
        mode = arg.strip() or 'all'
        self.hunt.run_hunt(self.pdf, mode=mode, stdout=sys.stdout)

    def do_quit(self, arg):
        """Leave the shell."""
        return True
    do_exit = do_quit
    do_q = do_quit
    do_EOF = do_quit  # Ctrl-D

    def emptyline(self):
        pass
