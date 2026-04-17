"""
pdfstudio.classify
Annotate PDFObject instances with a high-level `kind` (Catalog, Page, Annot,
Action, Filespec, Stream, ...) and surface lightweight per-object labels.

Keeps all keyword lookups in one place so they are easy to extend.
"""
from __future__ import annotations

import re

from .magic import sniff
from .model import PDFFile, PDFObject


# Mapping from /Type value to canonical kind label
TYPE_MAP = {
    '/Catalog':   'Catalog',
    '/Pages':     'Pages',
    '/Page':      'Page',
    '/Annot':     'Annot',
    '/Action':    'Action',
    '/Filespec':  'Filespec',
    '/EmbeddedFile': 'EmbeddedFile',
    '/Metadata':  'Metadata',
    '/Font':      'Font',
    '/XObject':   'XObject',
    '/Outlines':  'Outlines',
    '/Sig':       'Sig',
    '/ObjStm':    'ObjStm',
    '/XRef':      'XRefStream',
}

# Well-known action subtypes (/S /URI etc.)
ACTION_MAP = {
    '/URI':       'Action:URI',
    '/Launch':    'Action:Launch',
    '/JavaScript':'Action:JavaScript',
    '/JS':        'Action:JavaScript',
    '/GoTo':      'Action:GoTo',
    '/GoToR':     'Action:GoToRemote',
    '/Named':     'Action:Named',
    '/SubmitForm':'Action:SubmitForm',
    '/ImportData':'Action:ImportData',
}

ANNOT_SUBTYPE_MAP = {
    '/Link':       'Annot:Link',
    '/Widget':     'Annot:Widget',
    '/FileAttachment': 'Annot:FileAttachment',
    '/Text':       'Annot:Text',
    '/Popup':      'Annot:Popup',
}


RE_TYPE = re.compile(r'/Type\s*(/\w+)')
RE_S    = re.compile(r'/S\s*(/\w+)')
RE_SUBT = re.compile(r'/Subtype\s*(/\w+)')
RE_URI  = re.compile(r'/URI\s*\(([^)]*)\)')
RE_F_L  = re.compile(r'/F\s*\(([^)]+)\)')          # /F (cmd.exe) inline filename
RE_RECT = re.compile(r'/Rect\s*\[\s*(-?\d[\d\.\-\s]*)\]')
RE_MEDI = re.compile(r'/MediaBox\s*\[\s*(-?\d[\d\.\-\s]*)\]')


def classify(pdf: PDFFile) -> None:
    """Mutates pdf.objects in-place, setting kind and labels."""
    for obj in pdf.objects:
        body = obj.body

        # Stream-only objects (e.g. content streams) never declare /Type.
        if obj.stream is not None and not RE_TYPE.search(body):
            obj.kind = 'Stream'
            if obj.stream.filters:
                obj.labels.append('Filters=' + ','.join(obj.stream.filters))
            continue

        # /Type lookup
        mt = RE_TYPE.search(body)
        type_name = mt.group(1) if mt else None

        if type_name == '/Annot':
            # refine by /Subtype
            ms = RE_SUBT.search(body)
            sub = ms.group(1) if ms else None
            obj.kind = ANNOT_SUBTYPE_MAP.get(sub, 'Annot')
            if (mr := RE_RECT.search(body)):
                coords = [x for x in re.split(r'\s+', mr.group(1).strip()) if x]
                obj.labels.append('Rect=[' + ' '.join(coords) + ']')
        elif type_name == '/Action':
            ms = RE_S.search(body)
            sub = ms.group(1) if ms else None
            obj.kind = ACTION_MAP.get(sub, 'Action')
        elif type_name in TYPE_MAP:
            obj.kind = TYPE_MAP[type_name]
        else:
            # no /Type but we may still recognize the thing from its keys
            if RE_S.search(body):
                s = RE_S.search(body).group(1)
                if s in ACTION_MAP:
                    obj.kind = ACTION_MAP[s]
            elif '/Kids' in body and '/Count' in body:
                obj.kind = 'Pages'
            elif '/MediaBox' in body and '/Parent' in body:
                obj.kind = 'Page'
            elif '/Filespec' in body or ('/EF' in body and '/F' in body):
                obj.kind = 'Filespec'
            elif '/EmbeddedFiles' in body:
                obj.kind = 'Names'
            elif obj.stream is not None:
                obj.kind = 'Stream'
            else:
                obj.kind = 'dict' if '<<' in body else 'value'

        # Inline-URI label (common on Link annotations and URI actions)
        if (mu := RE_URI.search(body)):
            obj.labels.append(f'URI={mu.group(1)}')

        # /F inline filename (used by /Launch actions and /Filespec)
        if (mf := RE_F_L.search(body)):
            obj.labels.append(f'F={mf.group(1)}')

        # MediaBox on pages
        if (mm := RE_MEDI.search(body)):
            obj.labels.append('MediaBox=[' + ' '.join(mm.group(1).split()) + ']')

    # Second pass: magic sniff on every decoded stream (not short-circuited).
    for obj in pdf.objects:
        if obj.stream is not None and obj.stream.decoded_bytes:
            tag = sniff(obj.stream.decoded_bytes)
            if tag:
                obj.labels.append(f'Decoded={tag}')
