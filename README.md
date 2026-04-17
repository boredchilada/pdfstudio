# pdfstudio

**PEstudio-style static structure browser for PDF files.**

Stevens-parity CLI with Catalog-graph walker, 30+ detection rules,
HTML/JSON/SARIF/STIX reports, block-diagram file layout, recursive
embedded-PDF follower, shell REPL, curses TUI, and write-mode disarmer.

### Prior art (a.k.a. people who did the hard part already)

Two tools did 80% of this job before pdfstudio existed. If you're new
to PDF analysis, go read them first — this README can wait.

- **[Didier Stevens](https://blog.didierstevens.com/)** basically
  invented the discipline of static PDF malware analysis. His
  [pdf-tools page](https://blog.didierstevens.com/programs/pdf-tools/)
  hosts `pdfid.py` and `pdf-parser.py`, which have been the correct
  answer to "how do I look inside a malicious PDF" since roughly
  forever. Relevant reading:
  - [Anatomy of Malicious PDF Documents](https://www.scribd.com/document/20604734/Anatomy-of-Malicious-PDF-Documents) (2008)
  - [The entire /pdf/ blog category](https://blog.didierstevens.com/category/pdf/)
    — fifteen+ years of "here's how that one weird trick works"

  pdfstudio's `--pdfid` output, the `-o` / `-s` / `-k` / `-r` /
  `-e` / `-a` / `--search` / `--no-decode` switches, and the whole
  "one keyword per line" display style exist so analysts with muscle
  memory can pretend they're still using pdf-parser. We are not
  replacing his tools; we are shamelessly remixing them.

- **[PEstudio](https://www.winitor.com/)** (Marc Ochsenmeier) is the
  tool every Windows malware analyst reaches for when they get a PE,
  because it puts the interesting bits in front of you before the
  coffee kicks in. The vertical block-diagram layout, the
  "surface indicators, don't detonate" posture, and the
  "one screen instead of ten CLI invocations" ethos all come from
  years of going "I wish this existed for PDFs." Now it does.
  Thank you, Marc.

If you want to argue that pdfstudio is a love letter written in too
much Python, we won't stop you.

Stdlib-only Python 3.10+. Optional `yara-python` for YARA scanning;
`windows-curses` for the TUI on Windows.

---

## TL;DR — if you read one thing, read this

Point pdfstudio at a PDF (or a folder) and ask for a report bundle:

```bash
pdfstudio suspicious.pdf --report out/
```

Open [`out/<sha256>/deep_dump.md`](#what-the-deep-dump-contains) in your
markdown viewer of choice. It's a single, self-contained **all-in-one
analyst view** with everything the tool found:

1. **Structural report** — header, revisions, object table, triggers,
   flags with severity glyphs
2. **File layout block diagram** — PEstudio-style vertical stack of
   `Header / Body(v0) / xref / Trailer / %%EOF` with byte offsets
3. **pdfid keyword table** — pdfid-parity keyword counts, entropy,
   info-dict, structural markers
4. **Catalog walk** — indented tree of how `/Root → /Pages → /Page → …`
   resolves, with action triggers starred
5. **Stats** — object counts by kind, `/Type`, stream filter
6. **Mermaid graph** — paste into any mermaid-aware viewer and see the
   Catalog graph rendered visually
7. **IOCs** — URLs, domains, per-stream SHA-256s
8. **Flagged object bodies** — raw PDF syntax of every object that a
   HIGH/MED rule called out, grouped by object
9. **Malformed regions** — any bytes the parser couldn't claim
10. **Hex windows** — first bytes (header) + tail around the last
    `startxref` (xref/trailer/EOF)

Scan bundles also contain `report.html`, `report.json`,
`report.sarif` (SARIF 2.1), `report.stix.json` (STIX 2.1),
`flags.csv`, `iocs.csv`, `summary.txt`. Point BigFix / SCCM / Tanium /
CI at the bundle directory.

### What the deep dump contains (sample)

```
## 1b. File layout (block diagram)

┌─ Header ────────────────────────────────────────────────────────  0x00000000
│ %PDF-1.3   (22 B)                                              │
╞═ Body — Revision 0 ═════════════════════════════════════════════  0x00000016
│ 14,400 bytes   NEW=17   REWRITE=0                              │
│   obj    2  v0  Page                MediaBox=[0 0 612 792]     │
│   obj   13  v0  Catalog                                        │
│   obj   14  v0  Stream              Filters=/FlateDecode       │
├─ xref (v0)  370 B ──────────────────────────────────────────────  0x00003856
├─ Trailer (v0)  142 B ───────────────────────────────────────────  0x000039C8
│   /Root 13 0 R   /Size 18                                      │
├─ %%EOF (v0) ────────────────────────────────────────────────────  0x00003A56
╞═ Body — Revision 1  (incremental update) ══════════════════════   0x00003A5B
│ 45,231 bytes   NEW=6   REWRITE=2                               │
│ ★ obj   20  v1  Filespec            F=form.pdf                 │
│ ★ obj   21  v1  Stream              Decoded=Windows PE         │
│ ★ obj   22  v1  Action:JavaScript                              │
│ ★ obj   23  v1  Action:Launch       F=cmd.exe                  │
├─ xref (v1)  183 B ──────────────────────────────────────────────  0x0000EB0A
├─ Trailer (v1)  75 B ────────────────────────────────────────────  0x0000EBC1
│   /Root 13 0 R   /Size 24   /Prev 14422                        │
├─ %%EOF (v1) ────────────────────────────────────────────────────  0x0000EC0C
└─────────────────────────────────────────────────────────────────  0x0000EC11

## 7. Flagged object bodies

### obj 23 v1 [Action:Launch] — HIGH — flags: `LAUNCH_CMD`, `LAUNCH_NEWLINE_PAD`
```
<</S/Launch/Type/Action/Win<</F(cmd.exe)/D(c:\windows\system32)/P(/Q /C %HOMEDRIVE%&cd %HOMEPATH%&…
```
```

---

> ⚠️ **Security note**
> pdfstudio parses untrusted, actively malicious binary input. Run it in
> a sandboxed analysis VM — not on a primary workstation. The tool is
> static-only (no scripts are executed from the PDF), but the file itself
> may still trigger your endpoint-protection or be accidentally
> double-clicked if left in the wrong folder.

## Install

### From source (recommended during triage work)

```bash
git clone https://github.com/boredchilada/pdfstudio.git
cd pdfstudio
pip install -e .
pdfstudio --version
```

### Run without installing

```bash
python pdfstudio.py file.pdf       # script shim, imports the package
python -m pdfstudio file.pdf       # equivalent, once on PYTHONPATH
```

### Optional extras

```bash
pip install -e .[tui]     # windows-curses for the TUI on Windows
pip install -e .[yara]    # yara-python for --yara-rules
pip install -e .[dev]     # pytest + coverage for contributors
```

### External tools

- **7z** is required by `tools/mb_fetch.py` to unpack MalwareBazaar's
  AES-encrypted archives. Install via chocolatey (`choco install 7zip`)
  or Homebrew (`brew install p7zip`).

## Known limitations

pdfstudio aims to be a fast triage tool, not a complete PDF interpreter.
These are the known gaps:

- **Encrypted PDFs**: `/Encrypt` is detected and flagged, but object
  bodies are not decrypted. Most structural rules will not fire on
  encrypted files.
- **/ObjStm object streams**: wrapper objects are detected and partially
  expanded, but not every packed child is resolved through xref-stream
  type-2 entries.
- **/XFA (XML Forms Architecture)**: presence is detected and surfaced
  as an identifier flag; XFA XML bodies are not parsed.
- **Very large files (>100 MB)**: the parser holds the whole file in
  memory.
- **Adversarial inputs**: the parser is regex-driven and has been
  hardened for common malformations, but is not fuzzing-proof. If you
  find a crash, please open an issue with the triggering sample hash.

## Cheatsheet

```
# Default structure view (triggers + flags + revisions + objects table)
python pdfstudio.py file.pdf

# Same analysis, rendered as a standalone HTML file
python pdfstudio.py file.pdf --html report.html

# Machine-readable JSON for downstream tooling
python pdfstudio.py file.pdf --json

# pdfid-compatible keyword + entropy summary
python pdfstudio.py file.pdf --pdfid
python pdfstudio.py file.pdf --pdfid --nozero           # suppress zero counts  (pdfid -n)
python pdfstudio.py file.pdf --pdfid --extra-info       # /CreationDate, /Producer etc. (pdfid -e)
python pdfstudio.py file.pdf --pdfid --all-keywords     # expanded keyword table        (pdfid -a)

# Directory scan (pdfid -s / --recursedir)
python pdfstudio.py samples/                            # one-line summary per PDF in dir
python pdfstudio.py samples/ --recursedir               # recurse into subdirectories
python pdfstudio.py samples/ --recursedir --pdfid --nozero  # per-file pdfid summary

# Surgical object operations
python pdfstudio.py file.pdf -o 23                 # show object 23
python pdfstudio.py file.pdf -o 23 --revision 0    # show v0 copy
python pdfstudio.py file.pdf -o 21 -d raw.bin      # dump raw stream
python pdfstudio.py file.pdf -o 21 -D decoded.bin  # dump filter-decoded stream

# Search
python pdfstudio.py file.pdf -s "/Launch"                 # object-body search
python pdfstudio.py file.pdf -s "MZ" --in-streams         # search decoded streams too

# Reference lookup
python pdfstudio.py file.pdf -r 21                 # who references object 21?

# Graph export
python pdfstudio.py file.pdf --mermaid             # Mermaid flowchart
python pdfstudio.py file.pdf --mermaid --full-graph  # include all objects
python pdfstudio.py file.pdf --dot graph.dot       # Graphviz DOT file
# then: dot -Tsvg graph.dot -o graph.svg

# Visual: annotation rectangle overlay as SVG
python pdfstudio.py file.pdf --rects overlay.svg   # page + clickable rects

# Hex view
python pdfstudio.py file.pdf -o 23 --hex           # object body + stream in hex
python pdfstudio.py file.pdf -o 23 --hex --hex-max 0  # full dump (no truncation)

# Two-PDF structural diff
python pdfstudio.py left.pdf --diff right.pdf

# Full Catalog-graph tree walk (indented, cycle-suppressed, severity stars)
python pdfstudio.py file.pdf --walk

# Malformed / unclaimed bytes (anything not in an indirect object or structural token)
python pdfstudio.py file.pdf --show-malformed
python pdfstudio.py file.pdf -x unclaimed.bin

# Interactive REPL — parse once, then navigate
python pdfstudio.py file.pdf --shell
# (in the shell:)
#   info
#   triggers
#   obj 21 --hex
#   stream 21 dec
#   key /URI
#   refs 21
#   walk
#   hunt url          (if --hunt was supplied)
#   quit

# Threat-hunting enrichment
python pdfstudio.py file.pdf --hunt-offline       # extract IOCs, no network
python pdfstudio.py file.pdf --hunt               # + DNS resolve + HTTP HEAD + URLhaus anonymous
python pdfstudio.py file.pdf --hunt --hunt-vt     # also VirusTotal (needs VT_API_KEY env var)
python pdfstudio.py file.pdf --hunt --hunt-mb     # also MalwareBazaar (needs MB_API_KEY env var)

# Curses TUI (arrow-key navigation, live object browser)
python pdfstudio.py file.pdf --tui
# On Windows install the curses backend once:  pip install windows-curses

# Recursive — follow embedded PDFs in /EmbeddedFile streams
python pdfstudio.py file.pdf -R
python pdfstudio.py file.pdf -R --recursive-depth 10

# Write a disarmed copy (byte-substitutes /OpenAction, /AA, /Launch, /JS, /JavaScript)
python pdfstudio.py file.pdf --disarm safe_copy.pdf

# AUTOMATION — one-line summary, exit code policy, report bundle, batch
python pdfstudio.py file.pdf --summary-line                 # grep-friendly one-liner
python pdfstudio.py file.pdf --strict-exit                  # exit 0/5/10/20 by severity
python pdfstudio.py file.pdf --exit-on-severity HIGH        # exit 20 iff any HIGH flag
python pdfstudio.py file.pdf --report out/s1/               # 7-file bundle
python pdfstudio.py file.pdf --sarif out.sarif              # SARIF 2.1
python pdfstudio.py file.pdf --stix out.stix.json           # STIX 2.1
python pdfstudio.py file.pdf --csv out.flags.csv            # flat CSV

# Batch scan of many PDFs in parallel (BigFix/SCCM/Tanium-friendly)
ls samples/*.pdf | python pdfstudio.py ignored --batch - --report batch_out/ --jobs 8 --strict-exit
python pdfstudio.py ignored --batch files.txt --report batch_out/ --jobs 8 --strict-exit

# Point at a folder — pdfstudio auto-discovers .pdf files
python pdfstudio.py samples/                                       # one-line triage
python pdfstudio.py samples/ --recursedir                          # recurse subdirectories
python pdfstudio.py samples/ --strict-exit                         # exit reflects worst severity
python pdfstudio.py samples/ --report out/ --jobs 8 --strict-exit  # full parallel batch + bundles
python pdfstudio.py samples/ --recursedir --report out/ --jobs 8   # recursive + parallel + bundles
```

## Automation / orchestration guide

`pdfstudio` is designed to be driven by ops tooling (BigFix, SCCM,
Tanium, Intune, Ansible, GitHub Actions, GitLab CI, etc.) and to
produce outputs those tools ingest directly.

### Exit codes (`--strict-exit`)

| code | meaning                              |
|-----:|--------------------------------------|
|   0  | parsed OK, no MED/HIGH flags         |
|   5  | LOW flag(s) only                     |
|  10  | at least one MED flag                |
|  20  | at least one HIGH flag (malicious)   |
|   2  | argument / usage error               |
|   3  | parse failure (not a PDF, encrypted) |

`--exit-on-severity HIGH|MED|LOW` gives a binary verdict aligned with a
policy: any flag ≥ LEVEL → exit 20, else exit 0.

### One-line summary (`--summary-line`)

Emitted on stdout in `KEY=VALUE` form, stable field order:

```
PDFSTUDIO v=0.1.0 file=X.pdf size=60435 md5=... sha256=... \
  header=%PDF-1.3 revs=2 objs=25 streams=4 urls=0 \
  severity=HIGH flags=EMBEDDED_PE,LAUNCH_CMD,LAUNCH_NEWLINE_PAD,...
```

Grep-friendly, splunk-friendly, and the first line of stdout so simple
capture-then-regex works.

### Report bundle (`--report DIR`)

Writes seven files per input PDF that any orchestrator can upload back:

| file                | purpose                                   |
|--------------------|-------------------------------------------|
| `summary.txt`       | summary line + 3-line triage paragraph    |
| `report.json`       | full machine-readable model               |
| `report.html`       | standalone HTML viewer (styled)           |
| `report.sarif`      | SARIF 2.1 — drop into GitHub/Azure/etc.   |
| `report.stix.json`  | STIX 2.1 bundle — drop into MISP/TIPs     |
| `flags.csv`         | flat CSV of flags                         |
| `iocs.csv`          | flat CSV of URLs / domains / stream hashes|

### Batch mode (`--batch FILE --report DIR --jobs N`)

Processes every path in FILE (or stdin with `-`), one bundle per input
(keyed by SHA-256), and writes `index.csv` + `index.json` summarising
the whole run. Uses `concurrent.futures.ProcessPoolExecutor` for
parallelism. Example BigFix-style action:

```bash
python pdfstudio.py _ --batch /tmp/todo.txt --report /tmp/out --jobs 8 --strict-exit
# /tmp/out/index.csv, /tmp/out/<sha256>/report.{json,html,sarif,...}
```

### BigFix / SCCM / Ansible snippet

```bash
# single-host action
python pdfstudio.py "$SUSPICIOUS" --report "$UPLOAD_DIR" --strict-exit
rc=$?
case $rc in
  0)  echo "clean" ;;
  5)  echo "low" ;;
  10) echo "suspicious" ;;
  20) echo "malicious — escalate" ;;
  *)  echo "error rc=$rc" ;;
esac
```

### Networking / security posture

- Network is OFF by default. `--hunt` is the only flag that opens a
  socket; it is not used by any other path. Safe to run on air-gapped
  endpoints.
- Stdlib-only by default; the optional extras are `yara-python` (for
  `-y`) and `windows-curses` (for `--tui` on Windows).
- Read-only by default. The only write-mode is `--disarm` (explicit
  output path; never modifies input). All other exporters write only to
  paths the user named.
- Deterministic output — reports do not carry run timestamps in the
  JSON payload (STIX/SARIF timestamps are spec-mandated).

## Disarm

`--disarm OUT.pdf` writes a neutralized copy of the input by replacing
five danger keywords with same-length look-alikes that PDF readers will
not parse as actions:

    /OpenAction  → /OpenActi0n
    /AA          → /A0
    /Launch      → /Launc0
    /JS          → /J0
    /JavaScript  → /JavaScrip0

Because every substitution preserves its byte length, the xref table
stays valid and the file still parses as a PDF — it just no longer
auto-executes anything. Identical technique to pdfid's `--disarm`. The
disarm pass only scans inside object dictionary regions, never inside
stream bodies, so compressed payloads are untouched.

## Recursive walker

`-R` / `--recursive` expands every stream whose decoded bytes start with
`%PDF-` into a parsed child PDF. Children get their own classify/walk/
flag pass, attached to the parent under `parent.children`. Runs to a
bounded depth (`--recursive-depth N`, default 5) so cycles and deeply
nested content can't exhaust resources. Useful for PDFs whose payload
is another PDF (a common polyglot / embedded-attachment pattern).

## TUI

`--tui` starts a full-screen curses interface with two panes — object
list on the left, detail on the right — and a status bar at the bottom.

    Up/Down or j/k      move selection
    Enter or →          follow first indirect reference
    Backspace or ←      step back
    /                   search
    n                   next search hit
    t / f / w / o       triggers / flags / walk / objects view
    g                   go to object by number
    x                   dump decoded stream of selected object
    ? / q               help / quit

Parses once, then all navigation is instant. On Windows: `pip install
windows-curses` once. On Linux/macOS: works out of the box.

## Threat-hunting mode (`--hunt`)

Default-off network enrichment. Extracts every URL (from `/URI` actions
and free-form URL patterns in bodies + decoded streams), every domain
derived from those URLs, and every decoded-stream SHA-256. Then runs
any combination of:

- **DNS resolve** — every host → A records
- **HTTP HEAD** — status, content-type, content-length, location, final URL after redirects
- **URLhaus** (abuse.ch, anonymous POST) — per URL: query_status, threat, tags
- **VirusTotal** (opt-in via `VT_API_KEY`) — per URL: last_analysis_stats
- **MalwareBazaar** (opt-in via `MB_API_KEY`) — per stream SHA-256: signature

Runs only when `--hunt` is supplied. Use `--hunt-offline` to extract
IOCs without any network calls. No payload bodies are downloaded.

## Interactive shell

`--shell` drops into a `cmd.Cmd` REPL after parsing. All commands use
the already-parsed in-memory model. Available commands:

    info  objects  obj N [--hex]  body N  stream N [raw|dec]
    triggers  walk  flags  search KW [streams]  key /KEY  refs N
    type TYPE  revisions  stats  dump N path  ddump N path
    hunt [url|hash|all]  quit

## Stream magic sniffer

Every decoded stream is automatically sniffed for common file signatures
(MZ, ELF, Mach-O, PE, PK/ZIP, 7z, gzip, OLE compound, PDF, JPEG, PNG, GIF,
BMP, RTF, Flash SWF, ISO 9660 at offset 0x8001, XML/HTML). The hit is
surfaced as a `Decoded=<type>` label on the object and also triggers the
`EMBEDDED_PE`, `EMBEDDED_ZIP`, or `EMBEDDED_ELF` flag when applicable.
Extend the signature table in `pdfstudio/magic.py`.

## Package layout

```
tools/pdfstudio/
├── pdfstudio.py                   # CLI entry point
├── pdfstudio/                     # library
│   ├── __init__.py
│   ├── model.py                   # dataclasses: PDFFile, Revision, PDFObject, Stream, Trailer
│   ├── parser.py                  # find %PDF, xref, trailers, objects, streams
│   │                              # + FlateDecode, ASCIIHex, ASCII85, LZW, RunLength decoders
│   ├── classify.py                # assign a high-level 'kind' to each object
│   ├── walker.py                  # Catalog → OpenAction / AA / Names / Annots traversal
│   ├── flags.py                   # suspicious-indicator rule engine
│   ├── extract.py                 # -o object view, -d / -D stream dump
│   ├── search.py                  # -s keyword search, -r referrer lookup
│   ├── pdfid_view.py              # pdfid-style keyword + entropy summary
│   ├── graphviz_out.py            # Mermaid + Graphviz DOT graph exporters
│   ├── rects_svg.py               # page + annotation rectangle SVG overlay
│   ├── hexview.py                 # hex dumper
│   ├── diff.py                    # two-PDF structural diff
│   ├── magic.py                   # file-signature sniffer for decoded streams
│   ├── objstm.py                  # /ObjStm content expansion
│   ├── xrefstream.py              # /XRef cross-reference stream parser
│   ├── parity.py                  # -k, -t, -e, -a, -c, multi-object spec
│   ├── walk_view.py               # --walk full tree rendering
│   ├── malformed.py               # -x / --show-malformed extraction
│   ├── shell.py                   # --shell interactive REPL
│   ├── tui.py                     # --tui curses interface
│   ├── hunt.py                    # --hunt forensic enrichment
│   ├── disarm.py                  # --disarm byte-substitution writer
│   ├── recursive.py               # -R embedded PDF walker
│   ├── automation.py              # exit codes, summary line, report bundle, SARIF/STIX/CSV, batch
│   ├── yara_scan.py               # -y YARA scanning
│   ├── pdfid_view.py              # --pdfid keyword summary
│   └── render/
│       ├── __init__.py
│       ├── text.py                # default CLI text renderer
│       └── html.py                # standalone HTML renderer
└── README.md
```

Every module is small (~100–250 lines). Add a new view by creating
`pdfstudio/render/<name>.py` and wiring it into `pdfstudio.py`.

## pdfid.py option → pdfstudio option

Authoritative mapping against Didier Stevens' `pdfid.py --help`:

| pdfid flag           | pdfstudio equivalent                    |
|----------------------|-----------------------------------------|
| (no flag)            | `--pdfid`                               |
| `-s` scan directory  | pass a directory as the positional arg  |
| `-a` all names       | `--pdfid --all-keywords`                |
| `-e` extra (dates…)  | `--pdfid --extra-info`                  |
| `-f` force (no %PDF) | always permissive — parser doesn't require header to proceed |
| `-n` nozero          | `--nozero`                              |
| `-o FILE` log file   | redirect stdout (`> file.txt`)          |
| `--recursedir`       | `--recursedir`                          |
| `-d` disarm          | *not supported — read-only tool*        |
| `-p` plugins         | *not supported — use `--flags` engine + `--yara` instead* |
| `-c` csv             | *not supported — use `--json`*          |
| `-l` literal names   | *not applicable — no wildcard expansion in pdfstudio*     |

## pdf-parser.py option → pdfstudio option

Authoritative mapping against Didier Stevens' `pdf-parser.py --help`:

| pdf-parser flag            | pdfstudio equivalent                  |
|---------------------------|---------------------------------------|
| `-s SEARCH`               | `-s SEARCH` (plus `--regex`, `--case`) |
| `--searchstream=X`        | `-s X --in-streams`                   |
| `--unfiltered`            | `--unfiltered` (combined with `-s`)    |
| `--casesensitive`         | `--case`                              |
| `--regex`                 | `--regex`                             |
| `-f` (apply filters)      | `-D OUT` (filtered dump) / default decode |
| `-w` (raw data)           | `-d OUT` (raw dump)                   |
| `-o OBJECT`               | `-o SPEC` (accepts `12`, `12,15`, `20-25`) |
| `-r REFERENCE`            | `-r N`                                |
| `-e cxtsi`                | `-e cxtsi`                            |
| `-a` (stats)              | `-a`                                  |
| `-t TYPE`                 | `-t TYPE`                             |
| `-O` (parse /ObjStm)      | `-O`                                  |
| `-H` (hash of objects)    | auto-included in `-o` output + default view (file-level) |
| `-c` (content)            | `-c`                                  |
| `-v` (verbose / malformed) | `-v`                                 |
| `-k KEY`                  | `-k KEY`                              |
| `-y YARA`                 | `-y RULES`                            |
| `--yarastrings`           | `--yarastrings`                       |
| `-d OUT` (dump stream)    | `-d OUT` (raw) / `-D OUT` (decoded)   |
| `-x FILE` (extract malformed) | `-x OUT` (bytes) / `--show-malformed` (table) |
| `-g` generate Python      | (not planned — out of scope)          |
| `--overridingfilters`     | (not yet — planned)                   |

## What pdfstudio adds on top of pdf-parser

- `--html` — styled standalone HTML report
- `--json` — machine-readable dump
- `--pdfid` — pdfid-compatible keyword summary
- `--mermaid` / `--dot` — Catalog reference graph
- `--rects out.svg` — per-page annotation rectangle overlay
- `--diff other.pdf` — two-PDF structural diff
- `--hex` — per-object hex dump (body + raw stream + decoded stream)
- Named suspicious-flag engine (`EMBEDDED_PE`, `LAUNCH_CMD`, `LAUNCH_NEWLINE_PAD`, `OPENACTION_JS`, `FULL_PAGE_LINK`, `MULTI_REV_WEAPONIZATION`, `STREAM_HIGH_ENTROPY`, `OBJSTM_PRESENT`, `XREF_STREAM`, `ENCRYPTED`, `EMBEDDED_ZIP`, `EMBEDDED_ELF`)
- Catalog-graph walker resolving `/OpenAction` / `/AA` / `/Names /EmbeddedFiles` / `/Annots → /A` chains
- Per-revision new-vs-rewritten object reconstruction via `/Prev` chain
- Automatic file-signature sniffer (22+ signatures) surfaced as `Decoded=<type>` labels

## What it covers vs. pdfid / pdf-parser

| Capability                                    | pdfid | pdf-parser | pdfstudio |
|-----------------------------------------------|:-----:|:----------:|:---------:|
| Keyword counts                                |  ✔    |     —      |   ✔ (`--pdfid`) |
| Entropy (in/out stream)                       |  ✔    |     —      |   ✔ (`--pdfid`) |
| Object tree parsing                           |  —    |     ✔      |   ✔ |
| Object body display (`-o N`)                  |  —    |     ✔      |   ✔ |
| Stream dump (`-d` / `-D`)                     |  —    |     ✔      |   ✔ |
| FlateDecode / ASCIIHex / ASCII85 decoders     |  —    |     ✔      |   ✔ |
| LZW / RunLength decoders                      |  —    |     ✔      |   ✔ |
| Keyword search (`-s`)                         |  —    |     ✔      |   ✔ |
| Referrer lookup (`-r`)                        |  —    |     ✔      |   ✔ |
| Catalog-graph walker (trigger resolution)     |  —    |     —      |   ✔ |
| Per-revision new-vs-rewritten reconstruction  |  —    |   partial  |   ✔ |
| Named suspicious-flag engine                  |  —    |     —      |   ✔ |
| HTML report                                   |  —    |     —      |   ✔ |
| JSON output                                   |  —    |     —      |   ✔ |
| Mermaid / Graphviz export                     |  —    |     —      |   ✔ |
| Annotation-rectangle SVG overlay              |  —    |     —      |   ✔ (`--rects`) |
| Hex view (`--hex`)                            |  —    |  (via `-a`)|   ✔ |
| Two-PDF structural diff                       |  —    |     —      |   ✔ (`--diff`) |
| Magic sniffer (PE/ZIP/ISO/…)                  |  —    |     —      |   ✔ (auto) |
| `/ObjStm` detection (flag only)               |  —    |     ✔      |   ✔ (detect; expansion planned) |
| Object-stream content expansion               |  —    |     ✔      |   — (planned) |
| Encrypted PDF support                         |  —    |     ✔      |   — (planned) |
| YARA rule integration                         |  —    |     ✔      |   — (planned) |

## Scope and non-goals

- **Static only.** No JavaScript execution, no shellcode emulation.
- **No byte-level tampering.** Read-only. For PDF repair or forgery use
  other tools (e.g. `qpdf`).
- **Best-effort parser.** Regex-based; handles well-formed and malformed
  PDFs that Adobe Reader would still accept. Won't parse encrypted,
  cross-reference-stream, or heavily malformed linearized PDFs reliably
  yet.

## Extending it

- **Add a new flag rule**: drop a function into `pdfstudio/flags.py` and
  append it to `ALL_RULES`. It receives the parsed `PDFFile` and returns
  a list of `(severity, code, message)` tuples.
- **Add a new view**: create `pdfstudio/render/<name>.py` exposing
  `render(pdf, hits) -> str` and import + wire in `pdfstudio.py`.
- **Add a new classifier**: extend the dictionaries at the top of
  `classify.py`.

## License

Single-file internal tool, no license file yet. Treat as public domain
pending explicit licensing.
