"""
pdfstudio.parser
Low-level PDF parsing: find structural landmarks, extract objects and
streams, reconstruct revisions from the /Prev trailer chain.

Scope (MVP):
  - Unencrypted PDFs.
  - Classic `xref` tables. Cross-reference *streams* (/ObjStm / /XRef) are
    detected but not fully expanded; their enclosing objects are still parsed.
  - Stream length read from /Length in the stream's own dictionary.
"""
from __future__ import annotations

import hashlib
import re
import zlib
from typing import Optional

from .model import PDFFile, PDFObject, Revision, Stream, Trailer


# ---------------------------------------------------------------------------
# Regex library — all operate on the raw bytes of the file, decoded as latin-1.
# ---------------------------------------------------------------------------

RE_HEADER     = re.compile(r'%PDF-(\d+\.\d+)')
RE_EOF        = re.compile(r'%%EOF')
RE_STARTXREF  = re.compile(r'startxref\s+(\d+)\s+%%EOF', re.DOTALL)
RE_TRAILER    = re.compile(r'trailer\s*(<<.*?>>)\s*startxref\s+(\d+)\s+%%EOF', re.DOTALL)
RE_OBJECT     = re.compile(r'(\d+)\s+(\d+)\s+obj\b(.*?)\bendobj', re.DOTALL)
RE_STREAM     = re.compile(r'stream[\r\n]+(.*?)[\r\n]*endstream', re.DOTALL)
RE_FILTER     = re.compile(r'/Filter\s*(?:\[([^\]]+)\]|(/\w+))')
RE_LENGTH_DIRECT   = re.compile(r'/Length\s+(\d+)(?=[\s/>])')
RE_LENGTH_INDIRECT = re.compile(r'/Length\s+(\d+)\s+(\d+)\s+R\b')
RE_PREV       = re.compile(r'/Prev\s+(\d+)')
RE_SIZE       = re.compile(r'/Size\s+(\d+)')
RE_ROOT       = re.compile(r'/Root\s+(\d+)\s+(\d+)\s+R')
RE_INFO       = re.compile(r'/Info\s+(\d+)\s+(\d+)\s+R')
RE_ID         = re.compile(r'/ID\s*\[\s*<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>\s*\]')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _all_offsets(pattern: re.Pattern, text: str) -> list[int]:
    return [m.start() for m in pattern.finditer(text)]


def _parse_filters(body: str) -> list[str]:
    """Return ['/FlateDecode', '/ASCII85Decode', ...] for the given dict body."""
    m = RE_FILTER.search(body)
    if not m:
        return []
    if m.group(1):  # array form
        parts = re.findall(r'/\w+', m.group(1))
    else:
        parts = [m.group(2)]
    return parts


def _lzw_decode(data: bytes) -> bytes:
    """Adaptive LZW decoder for /LZWDecode streams (Adobe Systems, 2008, §7.4.4)."""
    out = bytearray()
    code_size = 9
    max_code = 1 << code_size
    dict_size = 258
    dictionary: dict[int, bytes] = {i: bytes([i]) for i in range(256)}
    # 256 = clear table, 257 = EOD
    bit_buf = 0
    bit_count = 0
    prev_entry: Optional[bytes] = None
    i = 0
    while i < len(data):
        while bit_count < code_size and i < len(data):
            bit_buf = (bit_buf << 8) | data[i]
            bit_count += 8
            i += 1
        if bit_count < code_size:
            break
        shift = bit_count - code_size
        code = (bit_buf >> shift) & ((1 << code_size) - 1)
        bit_buf &= (1 << shift) - 1
        bit_count = shift

        if code == 257:  # EOD
            break
        if code == 256:  # clear
            code_size = 9
            max_code = 1 << code_size
            dict_size = 258
            dictionary = {i: bytes([i]) for i in range(256)}
            prev_entry = None
            continue

        if code in dictionary:
            entry = dictionary[code]
        elif code == dict_size and prev_entry is not None:
            entry = prev_entry + prev_entry[:1]
        else:
            raise ValueError(f'LZW: invalid code {code} at dict_size {dict_size}')

        out.extend(entry)

        if prev_entry is not None:
            dictionary[dict_size] = prev_entry + entry[:1]
            dict_size += 1
            if dict_size == (1 << code_size) - 1 and code_size < 12:
                code_size += 1
                max_code = 1 << code_size
        prev_entry = entry
    return bytes(out)


def _runlength_decode(data: bytes) -> bytes:
    """Adobe RunLengthDecode filter (Adobe Systems, 2008, §7.4.5)."""
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        i += 1
        if b == 128:
            break
        if b < 128:
            # Next b+1 bytes are literal
            n = b + 1
            out.extend(data[i:i + n])
            i += n
        else:
            # Next byte is repeated (257 - b) times
            if i >= len(data):
                break
            n = 257 - b
            out.extend(bytes([data[i]]) * n)
            i += 1
    return bytes(out)


def _decode_stream(raw: bytes, filters: list[str]) -> tuple[Optional[bytes], Optional[str]]:
    """Decode a stream through its filter pipeline. Returns (decoded, error)."""
    data = raw
    for f in filters:
        if f in ('/FlateDecode', '/Fl'):
            try:
                data = zlib.decompress(data)
            except zlib.error as e:
                return None, f'FlateDecode: {e}'
        elif f in ('/ASCIIHexDecode', '/AHx'):
            try:
                cleaned = bytes(c for c in data if chr(c) not in ' \t\r\n').rstrip(b'>')
                data = bytes.fromhex(cleaned.decode('ascii'))
            except Exception as e:
                return None, f'ASCIIHexDecode: {e}'
        elif f in ('/ASCII85Decode', '/A85'):
            try:
                import base64
                trimmed = data.split(b'~>')[0].lstrip(b'<~')
                data = base64.a85decode(trimmed, adobe=False)
            except Exception as e:
                return None, f'ASCII85Decode: {e}'
        elif f in ('/LZWDecode', '/LZW'):
            try:
                data = _lzw_decode(data)
            except Exception as e:
                return None, f'LZWDecode: {e}'
        elif f in ('/RunLengthDecode', '/RL'):
            try:
                data = _runlength_decode(data)
            except Exception as e:
                return None, f'RunLengthDecode: {e}'
        elif f in ('/DCTDecode', '/DCT',        # JPEG
                   '/CCITTFaxDecode', '/CCF',    # TIFF CCITT
                   '/JBIG2Decode',
                   '/JPXDecode',                 # JPEG 2000
                   '/Crypt'):
            # Passthrough: we keep the raw bytes; callers can recognize the codec.
            return data, f'filter {f} not decoded (passthrough)'
        else:
            return None, f'unsupported filter: {f}'
    return data, None


# ---------------------------------------------------------------------------
# Main parse entry point
# ---------------------------------------------------------------------------

def parse(path: str, *, decode_streams: bool = True) -> PDFFile:
    with open(path, 'rb') as fh:
        raw = fh.read()
    text = raw.decode('latin-1')

    pdf = PDFFile(path=path, size=len(raw), header='')

    # Header
    m = RE_HEADER.search(text[:1024])
    if m:
        pdf.header = m.group(0)
    else:
        pdf.parse_warnings.append('no %PDF- header within first 1 KiB')

    # EOF offsets
    pdf.eof_offsets = _all_offsets(RE_EOF, text)
    pdf.startxref_offsets = [m.start() for m in re.finditer(r'startxref\b', text)]

    # Trailers
    for m in RE_TRAILER.finditer(text):
        dict_body, xref_s = m.group(1), m.group(2)
        eof_off = text.find('%%EOF', m.end() - 6)
        tr = Trailer(
            offset=text.rfind('trailer', 0, m.end()),
            body=dict_body,
            startxref=int(xref_s),
            eof_offset=eof_off,
        )
        if (sm := RE_SIZE.search(dict_body)):
            tr.size = int(sm.group(1))
        if (pm := RE_PREV.search(dict_body)):
            tr.prev = int(pm.group(1))
        if (rm := RE_ROOT.search(dict_body)):
            tr.root = (int(rm.group(1)), int(rm.group(2)))
        if (im := RE_INFO.search(dict_body)):
            tr.info = (int(im.group(1)), int(im.group(2)))
        if (idm := RE_ID.search(dict_body)):
            tr.ids = [idm.group(1), idm.group(2)]
        pdf.trailers.append(tr)

    # Revisions (ordered by startxref following the /Prev chain upwards)
    if pdf.trailers:
        ordered = sorted(pdf.trailers, key=lambda t: t.startxref)
        prev_end = 0
        for i, tr in enumerate(ordered):
            rev = Revision(
                index=i,
                trailer=tr,
                xref_offset=tr.startxref,
                byte_range=(prev_end, tr.eof_offset + 5),
            )
            pdf.revisions.append(rev)
            prev_end = tr.eof_offset + 5

    # ---- Objects (first pass: locate and capture bodies) ------------------
    pending_streams: list[tuple[PDFObject, int, str, int]] = []
    # (obj, body_start_in_text, body, stream_keyword_pos_in_text)

    for m in RE_OBJECT.finditer(text):
        idx, gen, body = int(m.group(1)), int(m.group(2)), m.group(3)
        offset = m.start()
        end_offset = m.end()
        body_start = m.start(3)

        obj = PDFObject(
            index=idx, generation=gen,
            offset=offset, end_offset=end_offset,
            body=body,
            raw_length=end_offset - offset,
        )
        obj.md5 = hashlib.md5(body.encode('latin-1')).hexdigest()

        # Stream inside body?
        sm = RE_STREAM.search(body)
        if sm:
            stream_kw_pos = body_start + body.find('stream', 0, sm.end())
            pending_streams.append((obj, body_start, body, stream_kw_pos))

        # Tag object to the revision whose byte-range contains its offset.
        for rev in pdf.revisions:
            lo, hi = rev.byte_range
            if lo <= offset < hi:
                obj.revision = rev.index
                break

        pdf.objects.append(obj)

    # ---- Second pass: resolve /Length (direct + indirect) and decode ------
    def _length_for(body_pre_stream: str) -> tuple[Optional[int], Optional[tuple[int, int]]]:
        """Returns (direct_length, (indirect_ref_index, gen)) — exactly one is None."""
        # Indirect /Length N G R takes precedence (more specific)
        im = RE_LENGTH_INDIRECT.search(body_pre_stream)
        if im:
            return None, (int(im.group(1)), int(im.group(2)))
        dm = RE_LENGTH_DIRECT.search(body_pre_stream)
        if dm:
            return int(dm.group(1)), None
        return None, None

    def _resolve_indirect_int(ref_idx: int, ref_gen: int) -> Optional[int]:
        """Return the integer value of the referenced object (for /Length indirects)."""
        for obj in pdf.objects:
            if obj.index == ref_idx and obj.generation == ref_gen:
                m = re.search(r'\b(\d+)\b', obj.body)
                if m:
                    return int(m.group(1))
        return None

    for obj, _body_start, body, stream_kw_pos in pending_streams:
        # /Length is in the dictionary before the 'stream' keyword
        pre_stream_body = body.split('stream', 1)[0]
        direct, indirect = _length_for(pre_stream_body)
        declared_length = direct
        if declared_length is None and indirect is not None:
            declared_length = _resolve_indirect_int(*indirect)

        # Absolute byte position of first stream data byte
        start = stream_kw_pos + len('stream')
        while start < len(raw) and raw[start] in (0x0D, 0x0A):
            start += 1

        # Stream body length: prefer declared; otherwise scan for 'endstream'
        if declared_length is not None:
            raw_len = declared_length
        else:
            end_scan = raw.find(b'endstream', start)
            raw_len = (end_scan - start) if end_scan > 0 else 0
            # Trim trailing CR/LF before 'endstream'
            while raw_len > 0 and raw[start + raw_len - 1] in (0x0D, 0x0A):
                raw_len -= 1

        raw_bytes = raw[start:start + raw_len] if raw_len > 0 else b''
        filters = _parse_filters(pre_stream_body)
        st = Stream(
            raw_offset=start,
            raw_length=raw_len,
            filters=filters,
            declared_length=declared_length,
            raw_bytes=raw_bytes,
        )
        if decode_streams and filters and raw_bytes:
            dec, err = _decode_stream(raw_bytes, filters)
            st.decoded_bytes = dec
            st.decode_error = err
        obj.stream = st

    # Per-revision new vs. rewritten object tracking (by index number).
    seen_indices: set[int] = set()
    for rev in pdf.revisions:
        in_rev = [o for o in pdf.objects if o.revision == rev.index]
        for o in in_rev:
            rev.resolved_objects[o.index] = o.offset
            if o.index in seen_indices:
                rev.rewritten_objects.append(o.index)
            else:
                rev.new_objects.append(o.index)
                seen_indices.add(o.index)

    return pdf
