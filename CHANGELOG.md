# Changelog

All notable changes to pdfstudio are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-04-17

Initial public release.

### Core parsing

- Regex-driven structural parser: header, indirect objects, streams,
  xref tables, trailers, incremental-update chains via `/Prev`.
- Filter decoders: `/FlateDecode`, `/ASCIIHexDecode`, `/ASCII85Decode`,
  `/LZWDecode`, `/RunLengthDecode`.
- Revision reconstruction — new / rewritten objects per revision.
- Catalog graph walker with cycle suppression.
- `/ObjStm` wrapper detection and partial expansion.
- `/XRef` cross-reference stream parsing.

### Detection

30+ flag rules grouped by intent:

- **Verdict rules (HIGH / MED)** — `NOT_A_PDF`, `LAUNCH_CMD`,
  `LAUNCH_NEWLINE_PAD`, `LAUNCH_SHELL_META`, `EMBEDDED_PE`,
  `EMBEDDED_ELF`, `EMBEDDED_ZIP`, `OPENACTION_JS`, `AA_JAVASCRIPT`,
  `JS_EXPORT_DATA_OBJECT`, `MULTI_REV_WEAPONIZATION`,
  `FILESPEC_EXT_MISMATCH`, `URI_TO_EXECUTABLE`.
- **URL rules (MED)** — `URL_SHORTENER`, `DYNAMIC_DNS`,
  `ABUSED_FILE_HOST`, `RAW_IP_URI`, `CANARYTOKEN`,
  `URI_OCTAL_ENCODED`, `URI_SWAP_ACROSS_REVISIONS`,
  `BASE64_IN_URI`, `URI_ON_WIDGET`, `INVISIBLE_WIDGET`,
  `LARGE_WIDGET`.
- **Structural (MED / LOW / INFO)** — `MULTI_REV`, `FULL_PAGE_LINK`,
  `ENCRYPTED`, `STREAM_HIGH_ENTROPY`, `OBJSTM_PRESENT`,
  `XREF_STREAM`.
- **Identifier rules (INFO)** — `HAS_ACROFORM`, `HAS_XFA`,
  `HAS_SUBMITFORM`, `HAS_OPENACTION`, `HAS_AA`, `EXTERNAL_HOSTS`,
  `UNCOMMON_TLD`, `HYPHENATED_HOST`, `TYPOSQUAT_DOMAIN`.

### Output

- Default text report with structural summary, objects table, trigger
  walk, flags with star-severity glyphs.
- Standalone HTML report (`--html`).
- JSON (`--json`), SARIF 2.1, STIX 2.1, CSV.
- Deep-dump Markdown (`deep_dump.md` inside `--report` bundles):
  structural report, pdfid keyword table, catalog walk, stats,
  mermaid graph, IOCs, flagged-object bodies, malformed regions,
  hex windows.
- File-layout block diagram — PEstudio-style vertical stack of header
  / body-per-revision / xref / trailer / %%EOF sections with offsets.
- Mermaid flowchart (`--mermaid`) and Graphviz DOT (`--dot`).
- SVG annotation overlay (`--rects`).
- Hexdump (`--hex`) and per-object dump (`-d` raw, `-D` decoded).

### pdfid / pdf-parser parity

- `--pdfid`, `--nozero`, `--extra-info`, `--all-keywords`.
- `-o`, `-g`, `-s`, `--case`, `--in-streams`, `--unfiltered`,
  `--regex`, `-r`, `-k`, `-t`, `-e`, `-a`, `-c`, `-O`, `-v`, `-y`,
  `-x`, `--no-decode`.
- `--search` regex / keyword, `-r` referrers, `-k` key-value lookup.

### Interactive

- `--shell` — cmd.Cmd REPL with `info`, `objects`, `obj`, `body`,
  `stream`, `triggers`, `walk`, `flags`, `search`, `key`, `refs`,
  `type`, `revisions`, `stats`, `dump`, `ddump`, `hunt`, `quit`.
- `--tui` — curses 2-pane TUI with arrow-key navigation, search,
  dump, walk, flags, goto-obj.

### Forensic / threat-hunting

- `--hunt` — URL / domain / hash extraction.
- `--hunt-vt` — VirusTotal enrichment (opt-in via `VT_API_KEY`).
- `--hunt-mb` — MalwareBazaar lookup (opt-in via `MB_API_KEY`).
- `--disarm OUT.pdf` — byte-level same-length substitution to
  neutralize `/OpenAction`, `/AA`, `/Launch`, `/JS`, `/JavaScript`.
- `-R` recursive embedded-PDF follower.
- YARA scanning via `yara-python` (optional extra).

### Enterprise automation

- Exit codes: `0` clean / `5` LOW / `10` MED / `20` HIGH /
  `3` parse-fail / `2` bad-args.
- `--summary-line` — stable grep-friendly one-liner.
- `--report DIR` — per-file bundle (8 files: json, html, summary.txt,
  flags.csv, iocs.csv, report.sarif, report.stix.json, deep_dump.md).
- `--batch FILE` — list of paths from stdin / file.
- Directory targeting: pointing at a folder auto-discovers
  `*.pdf` and `*.PDF`, with `--recursedir` for subdirectories.
- `--jobs N` — parallel workers via `ProcessPoolExecutor`.
- `--strict-exit` — worst-severity of any scanned file drives exit
  code. `--exit-on-severity` for custom thresholds.
- Batch index — `index.csv` + `index.json` at the report root.

### Tests

- 51 pytest tests covering parser, robustness (truncated / circular
  / garbage input), all flag rules on synthetic PDFs, automation
  (summary line, exit codes, bundle writer, SARIF / STIX shape).
- Test fixtures build synthetic PDFs at test time — no malware
  samples are committed.

### Packaging

- `pip install -e .` installs the `pdfstudio` console entry point.
- `python -m pdfstudio` works via `__main__.py`.
- `python pdfstudio.py` still works from a source clone.
- MIT license.
- Optional extras: `[tui]` (windows-curses), `[yara]` (yara-python),
  `[dev]` (pytest + coverage).
