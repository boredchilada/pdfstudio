#!/usr/bin/env python3
"""pdfstudio — script launcher.

This file exists so the tool can be run in-place from a clone without
installing: `python tools/pdfstudio/pdfstudio.py file.pdf`.

All behavior lives in `pdfstudio.cli.main`. After `pip install .`, the
console entry point `pdfstudio` runs the same function.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure the sibling package is importable when running the script directly
# out of a source tree.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from pdfstudio.cli import main

if __name__ == '__main__':
    sys.exit(main())
