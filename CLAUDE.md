# CLAUDE.md

Project-specific guidance for Claude Code / Claude Agent SDK sessions
working on this repo.

## What this project is

**pdfstudio** — a stdlib-only Python CLI that performs static structural
analysis of PDF files, with an emphasis on malware triage. Think
"PEstudio for PDFs." Stevens-parity for pdfid + pdf-parser, plus a
flag engine, interactive shell / TUI, and enterprise automation output
(SARIF / STIX / CSV / bundled reports).

## Hard rules

- **Never commit PDFs to this repo.** The `.gitignore` excludes `*.pdf`,
  `malware_samples/`, `evidence/`, `out/`. If a test needs a PDF, build
  it synthetically in `tests/conftest.py` — every flag rule in
  `test_flags.py` does exactly this. There are zero binary samples
  shipped with the project and that must stay true.
- **Never commit API keys, auth tokens, or sample hashes tied to live
  incidents.** The MalwareBazaar fetcher (`tools/mb_fetch.py`, not in
  the repo) reads `MB_API_KEY` from the environment. VT / MB hunters
  same pattern.
- **Never introduce a third-party runtime dependency without
  discussion.** pdfstudio deliberately ships stdlib-only for the core.
  Optional extras (`yara-python`, `windows-curses`) are declared in
  `pyproject.toml` under `[project.optional-dependencies]` and gated
  at import time.
- **Don't break the `python pdfstudio.py file.pdf` in-place workflow.**
  That shim must keep working without `pip install`.
- **Don't add heuristic rules at HIGH severity.** Verdict rules
  (HIGH/MED) should fire only on deterministic, byte-level, or
  spec-level evidence. Heuristic / fuzzy rules belong at INFO. This is
  a hard-won convention — the user pushed back when TYPOSQUAT_DOMAIN
  was HIGH; it now lives at INFO.

## Project layout

```
pdfstudio/
├── pdfstudio.py              # script shim; imports pdfstudio.cli.main
├── pdfstudio/                # the package
│   ├── __init__.py           # __version__
│   ├── __main__.py           # enables `python -m pdfstudio`
│   ├── cli.py                # argparse, dispatch, the CLI's main()
│   ├── model.py              # PDFFile, Revision, PDFObject, Stream, Trailer
│   ├── parser.py             # regex-driven structural parse
│   ├── classify.py           # per-object kind + labels
│   ├── walker.py             # Catalog graph walk, TriggerHit records
│   ├── flags.py              # all detection rules (ALL_RULES list)
│   ├── layout.py             # vertical block-diagram file layout
│   ├── automation.py         # exit codes, summary_line, write_bundle,
│   │                         # run_batch, SARIF/STIX/CSV writers,
│   │                         # render_deep_dump
│   ├── render/               # text + html report rendering
│   ├── parity.py             # pdf-parser stats, key/type filters
│   ├── pdfid_view.py         # pdfid-style keyword table
│   ├── objstm.py             # /ObjStm expansion
│   ├── xrefstream.py         # /XRef compressed xref tables
│   ├── malformed.py          # unclaimed-region extraction
│   ├── extract.py            # show / dump individual objects
│   ├── search.py             # keyword search, referrer lookup
│   ├── hexview.py            # hexdump helper
│   ├── diff.py               # two-PDF structural diff
│   ├── graphviz_out.py       # mermaid + DOT rendering
│   ├── rects_svg.py          # SVG annotation overlay
│   ├── shell.py              # cmd.Cmd interactive REPL
│   ├── tui.py                # curses TUI
│   ├── disarm.py             # byte-level same-length substitution
│   ├── recursive.py          # follow embedded %PDF- streams
│   ├── hunt.py               # URL/domain/hash enrichment
│   ├── yara_scan.py          # yara-python wrapper (optional)
│   ├── magic.py              # file-magic signatures for streams
│   └── walk_view.py          # full catalog-walk rendering
└── tests/
    ├── conftest.py           # synthetic PDF builders + fixtures
    ├── test_parser.py        # parser sanity
    ├── test_parser_robust.py # adversarial input, no-crash guarantees
    ├── test_flags.py         # every flag rule on synthetic inputs
    └── test_automation.py    # bundle writer, exit codes, SARIF/STIX
```

## Common commands

```bash
# Install in editable mode
pip install -e .[dev]

# Run the full test suite
pytest tests/ -q

# Run one test module
pytest tests/test_flags.py -q

# Run pdfstudio in-place (no install needed)
python pdfstudio.py path/to/file.pdf

# Installed console entry point
pdfstudio path/to/file.pdf

# Batch triage a folder with full report bundles
pdfstudio malware_samples/ --report out/ --jobs 4 --strict-exit

# Build wheel + sdist
python -m build
```

## Coding conventions

- **Python 3.10+.** Use `list[str]` / `dict[str, int]` / `|` union types.
- **Dataclasses for structured data** (`model.py`). Don't monkey-patch
  attributes at runtime.
- **Regexes live near the rules that use them**, not in a shared globals
  file. flags.py has its own set; parser.py has its own set.
- **Every flag rule returns `list[tuple[str, str, str]]`** — tuples of
  `(severity, code, message)`. `severity` is `'HIGH'` / `'MED'` /
  `'LOW'` / `'INFO'`. `code` is an uppercase underscore identifier
  shown in `flags.csv` and SARIF `ruleId`.
- **Rule function names use `check_<thing>` prefix.** Add them to
  `ALL_RULES` at the bottom of `flags.py`.
- **No comments on what code does.** Only comment on *why* — a subtle
  invariant, a known edge case, a workaround for a specific bug. Don't
  narrate the code.
- **No emojis in code or reports** unless explicitly requested.
- **Windows considerations:** the CLI reconfigures stdio to UTF-8 in
  `cli.py` only when `os.name == 'nt'`. Don't remove that. When
  bash-emitting shell commands inside the repo, remember paths with
  spaces need quoting.

## Adding a new flag rule — the checklist

1. Write the rule as `check_<name>(pdf: PDFFile) -> list[tuple[...]]`
   in `flags.py`.
2. Decide severity deterministically:
   - HIGH → byte-level evidence of a malicious pattern (LAUNCH_CMD,
     EMBEDDED_PE, NOT_A_PDF)
   - MED → strong pattern but not definitive (SHORTENER, DDNS,
     RAW_IP_URI)
   - LOW → unusual but not inherently bad
   - INFO → identifier / factual surface ("HAS_X")
3. Append to `ALL_RULES`.
4. Add a unit test in `tests/test_flags.py` using a synthetic PDF
   from `conftest.py`. The test should assert the rule fires on a
   positive example AND that clean PDFs don't accidentally trigger it.
5. Mention the rule in `CHANGELOG.md` under the current `[Unreleased]`
   section.
6. Run `pytest tests/ -q` — must be green before committing.

## Adding a new output format

The bundle writer is in `automation.py::write_bundle`. Paths are in the
`BundlePaths` dataclass. To add a new artifact:

1. Add a field to `BundlePaths`.
2. Populate the path in `write_bundle`.
3. Write the file at the bottom of `write_bundle`.
4. Add a case in `test_automation.py::test_bundle_writes_all_files`.

## Release checklist

Before cutting a release tag:

1. `pytest tests/ -q` — 100% green.
2. `python -m build` — wheel and sdist build without warnings.
3. Update `pdfstudio/__init__.py::__version__` and
   `pyproject.toml::version`.
4. Move the `[Unreleased]` section of `CHANGELOG.md` under a new
   version heading with today's date.
5. Commit, tag `vX.Y.Z`, push, push tag.

## What's deliberately NOT in scope

- XFA XML body parsing
- Full /ObjStm child-object resolution through xref-stream type-2
  entries
- Encrypted PDF object decryption
- Rendering PDF content (layout, text extraction)
- Dynamic sandboxing / detonation

If a user asks for one of the above, push back with an explanation of
why it's out of scope for a static triage tool, not try to implement
half of it.
