"""
pdfstudio.tui
Curses TUI for navigating a parsed PDF.

Layout:
    ┌─ Objects ─────────┐ ┌─ Detail ─────────────────────────────────┐
    │  obj 1   dict     │ │ header, metadata, body, stream preview   │
    │  obj 2   Page     │ │                                          │
    │ >obj 13  Catalog  │ │                                          │
    │ ...               │ │                                          │
    └───────────────────┘ └──────────────────────────────────────────┘
    ┌─ Status ─────────────────────────────────────────────────────────┐

Keys:
    Up/Down / j/k       move selection
    Enter / →           follow first indirect reference in selected body
    Backspace / ←       back to previous selection
    /                   search (substring, over bodies)
    n                   next search hit
    t                   jump to Triggers view
    f                   jump to Flags view
    w                   jump to Walk view (full tree)
    g                   go to object (prompt for N)
    x                   extract (dump decoded stream to ./obj_N.bin)
    ?                   help
    q                   quit

Falls back with a helpful message if curses is unavailable (on Windows,
install `windows-curses`: `pip install windows-curses`).
"""
from __future__ import annotations

import sys
import os
from typing import Optional

from .model import PDFFile, PDFObject
from .walker import walk
from .walk_view import render_walk


def run_tui(pdf: PDFFile) -> int:
    try:
        import curses
    except ImportError:
        sys.stderr.write(
            'pdfstudio tui: the `curses` module is unavailable on this Python.\n'
            'On Windows run: pip install windows-curses\n'
        )
        return 1

    return curses.wrapper(_main_loop, pdf)


def _main_loop(stdscr, pdf: PDFFile) -> int:
    import curses

    curses.curs_set(0)
    curses.use_default_colors()
    curses.start_color()
    # Colour pairs
    curses.init_pair(1, curses.COLOR_YELLOW, -1)   # catalog/root
    curses.init_pair(2, curses.COLOR_BLUE, -1)     # pages
    curses.init_pair(3, curses.COLOR_RED, -1)      # action:launch/JS, high-severity
    curses.init_pair(4, curses.COLOR_MAGENTA, -1)  # filespec/embedded
    curses.init_pair(5, curses.COLOR_GREEN, -1)    # stream
    curses.init_pair(6, curses.COLOR_CYAN, -1)     # annot:link / URI
    curses.init_pair(7, curses.COLOR_WHITE, curses.COLOR_BLUE)  # highlight
    curses.init_pair(8, curses.COLOR_BLACK, curses.COLOR_YELLOW)  # status bar
    curses.init_pair(9, curses.COLOR_BLACK, curses.COLOR_RED)  # error status

    # Ordered object list (latest revision only)
    latest: dict[int, PDFObject] = {}
    for o in pdf.objects:
        cur = latest.get(o.index)
        if cur is None or o.revision >= cur.revision:
            latest[o.index] = o
    objs = sorted(latest.values(), key=lambda o: o.index)

    # Special synthetic "views" appended after objects
    triggers = walk(pdf)

    state = {
        'selected': 0,
        'top': 0,
        'detail_mode': 'object',  # object | triggers | flags | walk | help
        'search': '',
        'search_hits': [],
        'history': [],
        'status': 'q quit  ↑/↓ nav  ⏎ follow  / search  t triggers  f flags  w walk  g goto  x dump  ? help',
        'status_tag': 'info',
    }

    _KIND_COLOR = {
        'Catalog': 1, 'Pages': 2, 'Page': 2,
        'Action:Launch': 3, 'Action:JavaScript': 3, 'Action:URI': 6,
        'Filespec': 4, 'EmbeddedFile': 4,
        'Stream': 5, 'Annot:Link': 6,
    }

    def kind_attr(kind: str):
        for prefix, pair in _KIND_COLOR.items():
            if kind.startswith(prefix):
                return curses.color_pair(pair)
        return curses.A_NORMAL

    def draw():
        stdscr.erase()
        max_y, max_x = stdscr.getmaxyx()
        list_width = max(28, max_x // 3)
        detail_x = list_width + 1

        # ── header ──
        title = f' pdfstudio tui — {os.path.basename(pdf.path)} ({pdf.size:,} B, {len(pdf.objects)} obj, {len(pdf.revisions)} rev) '
        stdscr.addnstr(0, 0, title + ' ' * max(0, max_x - len(title)), max_x,
                       curses.color_pair(8) | curses.A_BOLD)

        # ── object list panel ──
        top = state['top']
        sel = state['selected']
        visible_rows = max_y - 3
        if sel < top:
            top = sel
        if sel >= top + visible_rows:
            top = sel - visible_rows + 1
        state['top'] = top

        for i in range(visible_rows):
            idx = top + i
            if idx >= len(objs):
                break
            o = objs[idx]
            marker = '>' if idx == sel else ' '
            label = f'{marker} obj {o.index:>4} v{o.revision} {o.kind[:14]:<14}'
            attr = kind_attr(o.kind)
            if idx == sel:
                attr = curses.color_pair(7) | curses.A_BOLD
            stdscr.addnstr(1 + i, 0, label.ljust(list_width - 1), list_width - 1, attr)
            stdscr.addch(1 + i, list_width - 1, curses.ACS_VLINE)

        # ── detail panel ──
        if state['detail_mode'] == 'object' and objs:
            o = objs[sel]
            _draw_object_detail(stdscr, o, detail_x, max_x - detail_x, max_y - 2, pdf)
        elif state['detail_mode'] == 'triggers':
            _draw_list(stdscr, ['Triggers (active chains)', ''] +
                       [f'[{h.severity}] {h.path}' + (f'\n   {h.detail[:60]}' if h.detail else '')
                        for h in triggers],
                       detail_x, max_x - detail_x, max_y - 2)
        elif state['detail_mode'] == 'flags':
            lines = ['Flags', '']
            for sev, code, msg in pdf.flags:
                lines.append(f'[{sev}] {code:<26} {msg}')
            _draw_list(stdscr, lines, detail_x, max_x - detail_x, max_y - 2)
        elif state['detail_mode'] == 'walk':
            lines = render_walk(pdf).splitlines()
            _draw_list(stdscr, lines, detail_x, max_x - detail_x, max_y - 2)
        elif state['detail_mode'] == 'help':
            _draw_list(stdscr, __doc__.splitlines(), detail_x, max_x - detail_x, max_y - 2)

        # ── status ──
        status_attr = curses.color_pair(9) if state['status_tag'] == 'error' else curses.color_pair(8)
        stdscr.addnstr(max_y - 1, 0, (' ' + state['status']).ljust(max_x), max_x, status_attr)

        stdscr.refresh()

    def prompt(msg: str) -> str:
        curses.echo()
        max_y, max_x = stdscr.getmaxyx()
        stdscr.addnstr(max_y - 1, 0, (' ' + msg + ' ').ljust(max_x), max_x,
                       curses.color_pair(8))
        stdscr.refresh()
        s = stdscr.getstr(max_y - 1, len(' ' + msg + ' ') + 1, 80).decode('latin-1', errors='replace')
        curses.noecho()
        return s.strip()

    def set_status(msg: str, tag: str = 'info'):
        state['status'] = msg
        state['status_tag'] = tag

    # Main event loop
    while True:
        draw()
        try:
            k = stdscr.get_wch()
        except KeyboardInterrupt:
            return 0

        # Navigation
        if k in ('q', 'Q'):
            return 0
        elif k in ('?',):
            state['detail_mode'] = 'help'
            set_status('help shown — any key to return')
        elif k in ('t',):
            state['detail_mode'] = 'triggers'
            set_status('triggers')
        elif k in ('f',):
            state['detail_mode'] = 'flags'
            set_status('flags')
        elif k in ('w',):
            state['detail_mode'] = 'walk'
            set_status('full Catalog walk')
        elif k in ('o',):
            state['detail_mode'] = 'object'
            set_status('objects')
        elif k in ('j',) or k == curses.KEY_DOWN:
            state['selected'] = min(len(objs) - 1, state['selected'] + 1)
            state['detail_mode'] = 'object'
        elif k in ('k',) or k == curses.KEY_UP:
            state['selected'] = max(0, state['selected'] - 1)
            state['detail_mode'] = 'object'
        elif k in ('g',):
            ans = prompt('go to obj N:')
            try:
                target = int(ans)
            except ValueError:
                set_status('not a number', 'error')
                continue
            for i, o in enumerate(objs):
                if o.index == target:
                    state['selected'] = i
                    state['history'].append(state['selected'])
                    state['detail_mode'] = 'object'
                    set_status(f'jumped to obj {target}')
                    break
            else:
                set_status(f'obj {target} not found', 'error')
        elif k in ('\n', '\r', curses.KEY_RIGHT):
            # follow first indirect ref in selected object
            if not objs:
                continue
            import re
            body = objs[state['selected']].body
            m = re.search(r'(\d+)\s+(\d+)\s+R', body)
            if not m:
                set_status('no outgoing reference to follow', 'error')
                continue
            target = int(m.group(1))
            for i, o in enumerate(objs):
                if o.index == target:
                    state['history'].append(state['selected'])
                    state['selected'] = i
                    state['detail_mode'] = 'object'
                    set_status(f'→ obj {target}')
                    break
        elif k == curses.KEY_LEFT or k == '\x08' or k == curses.KEY_BACKSPACE:
            if state['history']:
                state['selected'] = state['history'].pop()
                set_status('← back')
        elif k in ('/',):
            term = prompt('search:')
            if not term:
                continue
            state['search'] = term
            state['search_hits'] = [
                i for i, o in enumerate(objs)
                if term.lower() in o.body.lower()
                or any(term.lower() in l.lower() for l in o.labels)
            ]
            if state['search_hits']:
                state['selected'] = state['search_hits'][0]
                state['detail_mode'] = 'object'
                set_status(f'{len(state["search_hits"])} match(es) — press n for next')
            else:
                set_status(f'no matches for {term!r}', 'error')
        elif k in ('n',):
            if not state['search_hits']:
                continue
            cur = state['selected']
            for idx in state['search_hits']:
                if idx > cur:
                    state['selected'] = idx
                    break
            else:
                state['selected'] = state['search_hits'][0]
            set_status(f'match #{state["search_hits"].index(state["selected"]) + 1} / {len(state["search_hits"])}')
        elif k in ('x',):
            # dump decoded stream of selected object
            if not objs:
                continue
            o = objs[state['selected']]
            if not o.stream or not o.stream.decoded_bytes:
                set_status('selected object has no decoded stream', 'error')
                continue
            out_path = f'obj_{o.index}.bin'
            with open(out_path, 'wb') as fh:
                fh.write(o.stream.decoded_bytes)
            set_status(f'wrote {len(o.stream.decoded_bytes):,} bytes to {out_path}')


def _draw_object_detail(stdscr, obj: PDFObject, x: int, w: int, h: int, pdf: PDFFile) -> None:
    import curses

    lines = []
    lines.append(f'obj {obj.index} {obj.generation}')
    lines.append(f'  offset   : {obj.offset:#x}')
    lines.append(f'  length   : {obj.raw_length}')
    lines.append(f'  md5      : {obj.md5}')
    lines.append(f'  rev      : v{obj.revision}')
    lines.append(f'  kind     : {obj.kind}')
    if obj.labels:
        for lbl in obj.labels:
            lines.append(f'  label    : {lbl}')
    if obj.stream:
        lines.append('  stream   :')
        lines.append(f'    filters       : {", ".join(obj.stream.filters) or "(none)"}')
        lines.append(f'    declared_len  : {obj.stream.declared_length}')
        lines.append(f'    raw_offset    : {obj.stream.raw_offset:#x}')
        if obj.stream.decoded_bytes is not None:
            lines.append(f'    decoded_len   : {len(obj.stream.decoded_bytes):,}')
        if obj.stream.decode_error:
            lines.append(f'    decode_error  : {obj.stream.decode_error}')

    lines.append('')
    lines.append('--- body ---')
    for ln in obj.body.splitlines():
        lines.append(ln)

    if obj.stream and obj.stream.decoded_bytes is not None:
        lines.append('')
        lines.append('--- decoded stream (first 320 bytes, latin-1) ---')
        preview = obj.stream.decoded_bytes[:320]
        decoded = preview.decode('latin-1', errors='replace').replace('\r', '\\r')
        for ln in decoded.splitlines():
            lines.append(ln)

    _draw_list(stdscr, lines, x, w, h)


def _draw_list(stdscr, lines: list[str], x: int, w: int, h: int) -> None:
    for i, ln in enumerate(lines[:h - 1]):
        safe = ln[:w - 2].replace('\t', '    ')
        try:
            stdscr.addnstr(1 + i, x, safe, w - 2)
        except Exception:
            pass
