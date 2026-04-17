"""
pdfstudio.search
Keyword search (pdf-parser -s) and referrer lookup (pdf-parser -r).

    search_keyword(pdf, keyword, case=False, in_streams=False) -> list[Match]
    find_referrers(pdf, index, generation=0) -> list[PDFObject]
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .model import PDFFile, PDFObject


@dataclass
class Match:
    obj: PDFObject
    where: str          # 'body' or 'stream'
    snippet: str        # short context line


def search_keyword(pdf: PDFFile, keyword: str, *,
                   case: bool = False, in_streams: bool = False,
                   regex: bool = False, unfiltered: bool = False) -> list[Match]:
    """Search object bodies (and optionally streams) for keyword.

    regex=True: treat `keyword` as a regex.
    unfiltered=True: also scan the raw (pre-filter) stream bytes.
    """
    flags = 0 if case else re.IGNORECASE
    pattern = re.compile(keyword if regex else re.escape(keyword), flags)

    out: list[Match] = []
    for obj in pdf.objects:
        for m in pattern.finditer(obj.body):
            lo = max(0, m.start() - 30)
            hi = min(len(obj.body), m.end() + 40)
            snippet = obj.body[lo:hi].replace('\n', ' ').replace('\r', ' ')
            out.append(Match(obj=obj, where='body', snippet=snippet))
            break  # one hit per object
        if in_streams and obj.stream:
            # decoded stream
            if obj.stream.decoded_bytes is not None:
                try:
                    txt = obj.stream.decoded_bytes.decode('latin-1', errors='replace')
                    m = pattern.search(txt)
                    if m:
                        lo = max(0, m.start() - 30)
                        hi = min(len(txt), m.end() + 40)
                        snippet = txt[lo:hi].replace('\n', ' ').replace('\r', ' ')
                        out.append(Match(obj=obj, where='stream', snippet=snippet))
                except Exception:
                    pass
            # optionally raw (pre-filter) stream
            if unfiltered and obj.stream.raw_bytes:
                try:
                    txt = obj.stream.raw_bytes.decode('latin-1', errors='replace')
                    m = pattern.search(txt)
                    if m:
                        lo = max(0, m.start() - 30)
                        hi = min(len(txt), m.end() + 40)
                        snippet = txt[lo:hi].replace('\n', ' ').replace('\r', ' ')
                        out.append(Match(obj=obj, where='stream(raw)', snippet=snippet))
                except Exception:
                    pass
    return out


# --- Referrer lookup --------------------------------------------------------

_REF_TMPL = r'\b{idx}\s+{gen}\s+R\b'


def find_referrers(pdf: PDFFile, index: int, generation: int = 0) -> list[PDFObject]:
    """Return every object whose body contains 'index gen R'."""
    pat = re.compile(_REF_TMPL.format(idx=index, gen=generation))
    return [o for o in pdf.objects if pat.search(o.body)]
