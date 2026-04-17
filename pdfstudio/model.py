"""
pdfstudio.model
Data classes for parsed PDF artefacts.

All offsets are byte offsets into the raw file. All strings are latin-1
(the 8-bit transport alphabet of PDF structural tokens).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Stream:
    """A PDF stream: binary blob preceded by its dictionary."""
    raw_offset: int               # byte offset of the first byte after 'stream\n'
    raw_length: int               # length of the raw (possibly compressed) body
    filters: list[str] = field(default_factory=list)   # e.g. ['/FlateDecode']
    declared_length: Optional[int] = None
    raw_bytes: Optional[bytes] = None
    decoded_bytes: Optional[bytes] = None
    decode_error: Optional[str] = None


@dataclass
class PDFObject:
    """A single indirect object: `N G obj ... endobj`."""
    index: int                    # object number
    generation: int               # generation number
    offset: int                   # byte offset of the 'N G obj' token
    end_offset: int               # byte offset just past 'endobj'
    body: str                     # dictionary / value portion (pre-stream)
    stream: Optional[Stream] = None
    md5: str = ""
    raw_length: int = 0           # offset-to-offset span
    # Populated later by classify.py / walker.py
    kind: str = "unknown"         # Catalog/Page/Pages/Annot/Action/Filespec/Stream/...
    labels: list[str] = field(default_factory=list)
    # Populated by revision reconstruction
    revision: int = 0             # which revision (0 = original) this copy lives in


@dataclass
class Trailer:
    """One trailer dictionary (one per revision)."""
    offset: int                   # offset of the 'trailer' keyword
    body: str                     # raw dict body, `<< ... >>`
    startxref: int                # integer value after `startxref`
    eof_offset: int               # byte offset of the following %%EOF
    size: Optional[int] = None    # /Size
    prev: Optional[int] = None    # /Prev (byte offset of previous xref)
    root: Optional[tuple[int, int]] = None  # /Root as (index, gen)
    info: Optional[tuple[int, int]] = None  # /Info
    ids: list[str] = field(default_factory=list)  # /ID (hex fragments)


@dataclass
class Revision:
    """One logical revision of the PDF."""
    index: int                    # 0 = original, 1 = first incremental update, ...
    trailer: Trailer
    xref_offset: int              # where the revision's xref lives
    byte_range: tuple[int, int]   # covered byte range in the file
    # Per-object status relative to prior revisions:
    new_objects: list[int] = field(default_factory=list)
    rewritten_objects: list[int] = field(default_factory=list)
    # All objects whose xref entry is written by this revision:
    resolved_objects: dict[int, int] = field(default_factory=dict)  # index -> obj offset


@dataclass
class PDFFile:
    """Top-level parsed result."""
    path: str
    size: int
    header: str                   # e.g. '%PDF-1.4'
    objects: list[PDFObject] = field(default_factory=list)
    trailers: list[Trailer] = field(default_factory=list)
    revisions: list[Revision] = field(default_factory=list)
    # Top-level statistics:
    eof_offsets: list[int] = field(default_factory=list)
    startxref_offsets: list[int] = field(default_factory=list)
    parse_warnings: list[str] = field(default_factory=list)
    # Populated by flags.py:
    flags: list[tuple[str, str, str]] = field(default_factory=list)
    # (severity: HIGH/MED/LOW, code: short tag, message: human explanation)

    # Populated by recursive.py when a stream decodes to another %PDF-.
    # Each child is itself a fully parsed PDFFile.
    children: list['PDFFile'] = field(default_factory=list)
    # Provenance — only set on children produced by recursive expansion.
    source_obj_index: Optional[int] = None
    source_parent_path: Optional[str] = None

    def obj(self, index: int, generation: int = 0) -> Optional[PDFObject]:
        """Return the latest (highest-revision) copy of an object."""
        best = None
        for o in self.objects:
            if o.index == index and o.generation == generation:
                if best is None or o.revision >= best.revision:
                    best = o
        return best
