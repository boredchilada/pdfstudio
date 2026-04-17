"""
pdfstudio.flags
Lightweight pattern-based suspicious-indicator engine.

Each rule inspects a parsed PDFFile and may append zero or more flags:
    (severity, code, message)

Severity: HIGH / MED / LOW / INFO
"""
from __future__ import annotations

import math
import re

from .model import PDFFile


# ----- helpers ---------------------------------------------------------------

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ln = len(data)
    return -sum((c / ln) * math.log2(c / ln) for c in freq if c)


def _has_keyword(pdf: PDFFile, keyword: str) -> bool:
    return any(keyword in o.body for o in pdf.objects)


def _objects_of_kind(pdf: PDFFile, kind: str) -> list:
    return [o for o in pdf.objects if o.kind == kind]


# ----- rules -----------------------------------------------------------------

def check_multirev_weaponization(pdf: PDFFile) -> list[tuple[str, str, str]]:
    out = []
    if len(pdf.revisions) >= 2:
        out.append(('MED', 'MULTI_REV',
                    f'Incremental-update chain ({len(pdf.revisions)} revisions). '
                    'Each revision can add / rewrite objects after the canonical %%EOF.'))
        # Any revision that adds a /Launch, /JS or /EmbeddedFiles?
        for rev in pdf.revisions[1:]:
            reasons = []
            for idx in rev.new_objects + rev.rewritten_objects:
                obj = pdf.obj(idx)
                if not obj:
                    continue
                if obj.kind == 'Action:Launch':
                    reasons.append(f'adds /Launch (obj {idx})')
                elif obj.kind == 'Action:JavaScript':
                    reasons.append(f'adds /JavaScript (obj {idx})')
                elif obj.kind == 'Filespec':
                    reasons.append(f'adds /Filespec (obj {idx})')
            if reasons:
                out.append(('HIGH', 'MULTI_REV_WEAPONIZATION',
                            f'Revision v{rev.index}: ' + '; '.join(reasons)))
    return out


def check_launch_cmd(pdf: PDFFile) -> list[tuple[str, str, str]]:
    out = []
    for a in _objects_of_kind(pdf, 'Action:Launch'):
        body = a.body
        if re.search(r'/F\s*\(\s*cmd\.exe', body, re.I):
            out.append(('HIGH', 'LAUNCH_CMD',
                        f'obj {a.index} is a /Launch action invoking cmd.exe'))
        else:
            out.append(('HIGH', 'LAUNCH',
                        f'obj {a.index} is a /Launch action'))
    return out


def check_newline_padding(pdf: PDFFile) -> list[tuple[str, str, str]]:
    out = []
    for a in _objects_of_kind(pdf, 'Action:Launch'):
        # look for 5+ consecutive \n escapes in a /P or command parameter
        if re.search(r'(?:\\n\s*){5,}', a.body) or re.search(r'(?:\n){5,}', a.body):
            out.append(('HIGH', 'LAUNCH_NEWLINE_PAD',
                        f'obj {a.index} /Launch has run of newline characters '
                        '(visual bypass of confirmation dialog).'))
    return out


def check_embedded_executable(pdf: PDFFile) -> list[tuple[str, str, str]]:
    out = []
    for o in pdf.objects:
        if o.stream and o.stream.decoded_bytes:
            head = o.stream.decoded_bytes[:2]
            if head == b'MZ':
                out.append(('HIGH', 'EMBEDDED_PE',
                            f'obj {o.index} decoded stream starts with MZ (Windows PE).'))
            elif head == b'PK':
                out.append(('MED', 'EMBEDDED_ZIP',
                            f'obj {o.index} decoded stream starts with PK (ZIP / OOXML).'))
            elif head == b'\x7fE':  # 0x7F 'E' from 0x7FELF
                out.append(('HIGH', 'EMBEDDED_ELF',
                            f'obj {o.index} decoded stream starts with ELF magic.'))
    return out


def check_openaction_javascript(pdf: PDFFile) -> list[tuple[str, str, str]]:
    out = []
    if _has_keyword(pdf, '/OpenAction') and (_has_keyword(pdf, '/JavaScript') or _has_keyword(pdf, '/JS')):
        out.append(('HIGH', 'OPENACTION_JS',
                    '/OpenAction co-occurs with /JavaScript — auto-execute pattern.'))
    return out


def check_full_page_link(pdf: PDFFile) -> list[tuple[str, str, str]]:
    out = []
    # Find all Page MediaBoxes
    page_boxes = []
    for p in _objects_of_kind(pdf, 'Page'):
        m = re.search(r'/MediaBox\s*\[\s*(-?\d[\d\.\-\s]*)\]', p.body)
        if m:
            try:
                parts = [float(x) for x in m.group(1).split()]
                if len(parts) == 4:
                    page_boxes.append(parts)
            except ValueError:
                pass

    if not page_boxes:
        return out

    # Use first page as reference
    x0, y0, x1, y1 = page_boxes[0]
    page_w, page_h = abs(x1 - x0), abs(y1 - y0)

    for a in _objects_of_kind(pdf, 'Annot:Link'):
        m = re.search(r'/Rect\s*\[\s*(-?\d[\d\.\-\s]*)\]', a.body)
        if not m:
            continue
        try:
            parts = [float(x) for x in m.group(1).split()]
            if len(parts) != 4:
                continue
            rw = abs(parts[2] - parts[0])
            rh = abs(parts[3] - parts[1])
            cov = (rw * rh) / (page_w * page_h) if page_w and page_h else 0
            if cov >= 0.70:
                out.append(('MED', 'FULL_PAGE_LINK',
                            f'obj {a.index} /Link /Rect covers {cov*100:.0f}% of page area.'))
        except ValueError:
            pass
    return out


def check_high_entropy_streams(pdf: PDFFile) -> list[tuple[str, str, str]]:
    out = []
    for o in pdf.objects:
        if o.stream and o.stream.decoded_bytes:
            e = _entropy(o.stream.decoded_bytes)
            if e >= 7.5 and len(o.stream.decoded_bytes) >= 1024:
                out.append(('INFO', 'STREAM_HIGH_ENTROPY',
                            f'obj {o.index} decoded stream entropy {e:.2f} '
                            f'({len(o.stream.decoded_bytes)} B) — likely compressed or encrypted payload.'))
    return out


def check_objstm_present(pdf: PDFFile) -> list[tuple[str, str, str]]:
    out = []
    ostms = [o for o in pdf.objects if o.kind == 'ObjStm']
    if ostms:
        out.append(('INFO', 'OBJSTM_PRESENT',
                    f'{len(ostms)} /ObjStm object stream(s) present '
                    '(nested objects not expanded in this version).'))
    return out


def check_xref_stream(pdf: PDFFile) -> list[tuple[str, str, str]]:
    out = []
    xrs = [o for o in pdf.objects if o.kind == 'XRefStream']
    if xrs:
        out.append(('INFO', 'XREF_STREAM',
                    f'{len(xrs)} cross-reference stream(s) present — classic xref table may not cover every object.'))
    return out


def check_encryption(pdf: PDFFile) -> list[tuple[str, str, str]]:
    out = []
    if any('/Encrypt' in t.body for t in pdf.trailers):
        out.append(('MED', 'ENCRYPTED',
                    'PDF declares /Encrypt in its trailer — objects may not be parseable without the decryption key.'))
    return out


# ---------------------------------------------------------------------------
# URL-oriented rules — operate on URIs extracted from /URI actions and
# /A<<... /URI (...)>> dict values. Everything is surfaced as (obj, url).
# ---------------------------------------------------------------------------

_RE_URI = re.compile(r'/URI\s*\(\s*([^)]*)\)')


def _iter_uris(pdf: PDFFile):
    """Yield (obj, url) for every URI appearing in an object body.

    Octal escapes (\\072 = ':', \\057 = '/', etc.) are decoded so that
    downstream rules can match the real host/path.
    """
    for o in pdf.objects:
        for m in _RE_URI.finditer(o.body):
            url = m.group(1).strip()
            if _RE_OCTAL.search(url):
                url = _octal_decode(url)
            if url:
                yield o, url


_SHORTENER_HOSTS = {
    'tinyurl.com', 'bit.ly', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'cutt.ly', 'rb.gy', 'shorturl.at', 'tiny.cc', 'lnkd.in',
    'buff.ly', 'rebrand.ly', 'bl.ink', 's.id', 'v.gd', 'shorturl.com',
    'adf.ly', 'short.io', 'tr.im', 'qr.net', 'bitly.com',
    'surl.li', 'cutt.it', 'gg.gg', 'n9.cl', 'short.gy', 'tiny.one',
    'rotf.lol', 'clck.ru', 'u.to', 'x.gd', '2tu.us', 'tiny.url',
}

_CANARYTOKEN_HOSTS = {
    'canarytokens.com', 'canarytokens.net', 'canarytokens.org',
    'canary.tools', 'thinkst.com',
}

# Common brand / account-related words used in phishing lures.
# Typosquat detection compares domain labels against these with fuzzy match.
_BRAND_WORDS = {
    # account & auth
    'account', 'accounts', 'login', 'signin', 'verify', 'verification',
    'secure', 'security', 'password', 'authenticate', 'authentication',
    # platform / service
    'manager', 'management', 'solutions', 'service', 'services', 'support',
    'portal', 'online', 'update', 'center', 'help',
    # financial
    'bank', 'banking', 'payment', 'payments', 'invoice', 'billing', 'refund',
    'paypal', 'western', 'union', 'transfer',
    # big brand names
    'microsoft', 'office', 'office365', 'outlook', 'teams', 'sharepoint',
    'apple', 'icloud', 'itunes', 'google', 'gmail', 'amazon', 'aws',
    'docusign', 'dropbox', 'adobe', 'acrobat', 'onedrive', 'onelogin',
    'linkedin', 'facebook', 'instagram', 'netflix', 'wetransfer',
    'dhl', 'fedex', 'ups', 'usps',
    # document
    'document', 'documents', 'invoice', 'form', 'file', 'files', 'scan',
    'delivery',
}

_ABUSED_FILE_HOSTS = {
    'pixeldrain.com', 'anonfiles.com', 'mega.nz', 'mega.co.nz',
    'transfer.sh', 'gofile.io', 'file.io', 'catbox.moe', 'litter.catbox.moe',
    'mediafire.com', 'sendspace.com', 'ufile.io', 'dropmefiles.com',
    'kastr.me', 'tmpfiles.org', 'filebin.net', 'we.tl', 'wetransfer.com',
    'workupload.com', 'easyupload.io', 'zippyshare.com',
}

# Match PDF octal escapes like \072 (a colon). Three octal digits.
_RE_OCTAL = re.compile(r'\\[0-3][0-7]{2}')
_RE_IPV4 = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
_RE_IPV6 = re.compile(r'^\[?[0-9a-fA-F:]+\]?$')


def _octal_decode(s: str) -> str:
    """Decode PDF-style octal escapes \\nnn to their character."""
    return _RE_OCTAL.sub(lambda m: chr(int(m.group(0)[1:], 8)), s)

_DDNS_SUFFIXES = (
    '.duckdns.org', '.no-ip.com', '.no-ip.org', '.no-ip.biz', '.no-ip.info',
    '.ddns.net', '.dyndns.org', '.dyndns.biz', '.dyndns.tv', '.dynu.net',
    '.hopto.org', '.zapto.org', '.serveftp.com', '.servebeer.com',
    '.sytes.net', '.myftp.org', '.myftp.biz', '.myq-see.com',
    '.redirectme.net', '.changeip.net',
)

_EXEC_EXTS = (
    '.exe', '.scr', '.bat', '.cmd', '.ps1', '.hta', '.vbs', '.vbe',
    '.js', '.jse', '.wsf', '.wsh', '.msi', '.dll', '.jar',
    '.zip', '.rar', '.7z', '.iso', '.img', '.lnk', '.chm',
)


def _host_of(url: str) -> str:
    """Return the lowercased host portion of a URL (best-effort, no deps)."""
    u = url.strip().lower()
    # strip scheme
    if '://' in u:
        u = u.split('://', 1)[1]
    # strip path/query
    for sep in ('/', '?', '#'):
        if sep in u:
            u = u.split(sep, 1)[0]
    # strip userinfo and port
    if '@' in u:
        u = u.split('@', 1)[1]
    if ':' in u:
        u = u.split(':', 1)[0]
    return u


def check_url_shortener(pdf: PDFFile) -> list[tuple[str, str, str]]:
    out = []
    for o, url in _iter_uris(pdf):
        host = _host_of(url)
        if host in _SHORTENER_HOSTS:
            out.append(('MED', 'URL_SHORTENER',
                        f'obj {o.index} URI uses a URL-shortener host ({host}): {url}'))
    return out


def check_dynamic_dns(pdf: PDFFile) -> list[tuple[str, str, str]]:
    out = []
    for o, url in _iter_uris(pdf):
        host = _host_of(url)
        for sfx in _DDNS_SUFFIXES:
            if host.endswith(sfx):
                out.append(('MED', 'DYNAMIC_DNS',
                            f'obj {o.index} URI points at a dynamic-DNS host ({host}): {url}'))
                break
    return out


def check_uri_to_executable(pdf: PDFFile) -> list[tuple[str, str, str]]:
    out = []
    for o, url in _iter_uris(pdf):
        # Check path extension only — ignore query/fragment.
        path = url.split('?', 1)[0].split('#', 1)[0].lower().rstrip('/')
        for ext in _EXEC_EXTS:
            if path.endswith(ext):
                out.append(('HIGH', 'URI_TO_EXECUTABLE',
                            f'obj {o.index} URI directly links to a {ext} download: {url}'))
                break
    return out


def check_uri_swap_across_revisions(pdf: PDFFile) -> list[tuple[str, str, str]]:
    """Same object index rewritten across revisions carrying different URIs."""
    out = []
    if len(pdf.revisions) < 2:
        return out
    by_idx_rev: dict[tuple[int, int], set[str]] = {}
    for o in pdf.objects:
        for m in _RE_URI.finditer(o.body):
            url = m.group(1).strip()
            if url:
                by_idx_rev.setdefault((o.index, o.revision), set()).add(url)

    # Also follow /A indirect references: if an Annot rewritten across
    # revisions points to different Action:URI targets, that's the same
    # pattern. Collect per-index-across-revisions URL sets using the
    # current-revision resolver.
    per_idx_urls: dict[int, set[tuple[int, str]]] = {}
    for (idx, rev), urls in by_idx_rev.items():
        for u in urls:
            per_idx_urls.setdefault(idx, set()).add((rev, u))

    for idx, pairs in per_idx_urls.items():
        urls_only = {u for _r, u in pairs}
        revs_only = {r for r, _u in pairs}
        if len(urls_only) >= 2 and len(revs_only) >= 2:
            out.append(('MED', 'URI_SWAP_ACROSS_REVISIONS',
                        f'obj {idx} rewrites its /URI across {len(revs_only)} revisions '
                        f'({len(urls_only)} distinct URLs): ' +
                        ' → '.join(u for _r, u in sorted(pairs))))
    return out


def check_js_export_data_object(pdf: PDFFile) -> list[tuple[str, str, str]]:
    out = []
    pat = re.compile(r'exportDataObject\s*\(', re.I)
    for o in _objects_of_kind(pdf, 'Action:JavaScript'):
        if pat.search(o.body):
            # nLaunch:1 is the explicit open-after-export flag; flag either way
            # but annotate if seen.
            m = re.search(r'nLaunch\s*:\s*(\d+)', o.body)
            detail = f' (nLaunch={m.group(1)})' if m else ''
            out.append(('HIGH', 'JS_EXPORT_DATA_OBJECT',
                        f'obj {o.index} JavaScript calls exportDataObject(){detail} — '
                        'Acrobat API to write an embedded file to disk (CVE-2010-1240 class).'))
    return out


def check_launch_shell_meta(pdf: PDFFile) -> list[tuple[str, str, str]]:
    """Heuristic: /Launch action whose parameters contain shell meta or env vars.

    Catches variants not picked up by LAUNCH_CMD (which requires F=cmd.exe).
    """
    out = []
    # Interesting markers in /P or /F values
    markers = [
        (re.compile(r'/P\s*\(\s*[^)]*%[A-Z_]+%', re.I),          'env-var expansion in /P'),
        (re.compile(r'/P\s*\(\s*[^)]*\bcmd\s*/[cCkK]\b', re.I),  'cmd /c or /k in /P'),
        (re.compile(r'/P\s*\(\s*[^)]*\bpowershell', re.I),        'powershell in /P'),
        (re.compile(r'/P\s*\(\s*[^)]*\bstart\s+', re.I),           'start command in /P'),
        (re.compile(r'/P\s*\(\s*[^)]*[&|][^)]', re.I),             'shell-chaining (& or |) in /P'),
    ]
    for a in _objects_of_kind(pdf, 'Action:Launch'):
        hits_local = []
        for pat, why in markers:
            if pat.search(a.body):
                hits_local.append(why)
        if hits_local:
            out.append(('HIGH', 'LAUNCH_SHELL_META',
                        f'obj {a.index} /Launch contains shell-script indicators: ' +
                        '; '.join(hits_local)))
    return out


def check_filespec_ext_mismatch(pdf: PDFFile) -> list[tuple[str, str, str]]:
    """/Filespec F=name.ext whose referenced /EF stream decodes to a different magic."""
    out = []
    # Magic → representative extensions that the file name SHOULD match.
    ext_for_magic = {
        'Windows PE (DOS header + PE signature)': {'.exe', '.scr', '.dll', '.sys', '.cpl', '.ocx'},
        'ELF executable': {'.elf', '.so', ''},   # often no ext
        'OLE compound document': {'.doc', '.xls', '.ppt', '.msi'},
        'ZIP archive / OOXML container': {'.zip', '.docx', '.xlsx', '.pptx', '.jar', '.apk'},
        'JPEG image': {'.jpg', '.jpeg'},
        'PNG image': {'.png'},
        'PDF': {'.pdf'},
    }

    for fs in _objects_of_kind(pdf, 'Filespec'):
        # Find claimed filename
        mname = re.search(r'/(?:UF|F)\s*\(([^)]+)\)', fs.body)
        if not mname:
            continue
        name = mname.group(1).strip().lower()
        # Extract .ext (last)
        ext = ''
        if '.' in name:
            ext = '.' + name.rsplit('.', 1)[1]

        # Find /EF stream reference
        mef = re.search(r'/EF\s*<<\s*/F\s+(\d+)\s+(\d+)\s+R', fs.body)
        if not mef:
            continue
        ef_idx = int(mef.group(1))
        stream_obj = pdf.obj(ef_idx)
        if not stream_obj or not stream_obj.stream:
            continue
        # Find a Decoded= label (set by classify.py's magic sniff)
        magic_label = None
        for lbl in stream_obj.labels:
            if lbl.startswith('Decoded='):
                magic_label = lbl[len('Decoded='):]
                break
        if not magic_label:
            continue

        # Compare
        matched = False
        for mgx_prefix, allowed in ext_for_magic.items():
            if magic_label.startswith(mgx_prefix.split(' ')[0]):
                if ext in allowed:
                    matched = True
                break

        if not matched:
            out.append(('HIGH', 'FILESPEC_EXT_MISMATCH',
                        f'Filespec obj {fs.index} claims name "{name}" but /EF '
                        f'stream obj {ef_idx} decodes as: {magic_label}'))
    return out


def check_uri_octal_encoded(pdf: PDFFile) -> list[tuple[str, str, str]]:
    """/URI value uses PDF octal escapes to hide characters like ':' '/' '.'"""
    out = []
    for o in pdf.objects:
        for m in _RE_URI.finditer(o.body):
            raw = m.group(1)
            # Only interesting when the escape hides URL-structural chars
            escapes = _RE_OCTAL.findall(raw)
            if len(escapes) >= 3:
                decoded = _octal_decode(raw)
                out.append(('MED', 'URI_OCTAL_ENCODED',
                            f'obj {o.index} /URI uses octal escapes ({len(escapes)}) '
                            f'to hide the URL; decoded: {decoded}'))
    return out


def check_abused_file_host(pdf: PDFFile) -> list[tuple[str, str, str]]:
    out = []
    for o, url in _iter_uris(pdf):
        host = _host_of(url)
        if host in _ABUSED_FILE_HOSTS:
            out.append(('MED', 'ABUSED_FILE_HOST',
                        f'obj {o.index} URI points at a commonly-abused file-sharing '
                        f'host ({host}): {url}'))
    return out


def check_raw_ip_uri(pdf: PDFFile) -> list[tuple[str, str, str]]:
    """URI whose host is a raw IPv4/IPv6 literal — no domain name."""
    out = []
    for o, url in _iter_uris(pdf):
        host = _host_of(url)
        if _RE_IPV4.match(host):
            out.append(('MED', 'RAW_IP_URI',
                        f'obj {o.index} URI uses a raw IPv4 host ({host}): {url}'))
        elif ':' in host and _RE_IPV6.match(host) and host != 'localhost':
            # crude IPv6 test — any colon-bearing host that isn't a known scheme hint
            out.append(('MED', 'RAW_IP_URI',
                        f'obj {o.index} URI uses a raw IPv6 host ({host}): {url}'))
    return out


def check_uri_on_widget(pdf: PDFFile) -> list[tuple[str, str, str]]:
    """Annot:Widget (form field) carrying a /URI — unusual, often used to
    disguise a clickable trigger as a form input."""
    out = []
    for o in pdf.objects:
        if o.kind != 'Annot:Widget':
            continue
        if '/URI' in o.body:
            m = _RE_URI.search(o.body)
            url = m.group(1).strip() if m else '(unparsed)'
            if _RE_OCTAL.search(url):
                url = _octal_decode(url)
            out.append(('MED', 'URI_ON_WIDGET',
                        f'obj {o.index} is an Annot:Widget (form field) carrying a '
                        f'/URI action: {url}'))
    return out


def check_invisible_widget(pdf: PDFFile) -> list[tuple[str, str, str]]:
    """Annot:Widget whose /Rect is collapsed to zero area — intentionally hidden."""
    out = []
    for o in pdf.objects:
        if o.kind != 'Annot:Widget':
            continue
        m = re.search(r'/Rect\s*\[\s*(-?\d[\d\.\-\s]*)\]', o.body)
        if not m:
            continue
        try:
            parts = [float(x) for x in m.group(1).split()]
            if len(parts) == 4:
                w = abs(parts[2] - parts[0])
                h = abs(parts[3] - parts[1])
                if w < 0.5 and h < 0.5:
                    out.append(('MED', 'INVISIBLE_WIDGET',
                                f'obj {o.index} Annot:Widget has zero-area /Rect '
                                f'[{" ".join(str(p) for p in parts)}] — invisible trigger.'))
        except ValueError:
            pass
    return out


def check_large_widget(pdf: PDFFile) -> list[tuple[str, str, str]]:
    """Annot:Widget whose body is unexpectedly large (usually a few hundred
    bytes). A multi-KB widget typically carries XFA, JavaScript, or embedded
    payloads."""
    out = []
    for o in pdf.objects:
        if o.kind != 'Annot:Widget':
            continue
        if o.raw_length >= 10_000:
            out.append(('MED', 'LARGE_WIDGET',
                        f'obj {o.index} Annot:Widget body is {o.raw_length:,} B — '
                        'oversized widgets often contain XFA scripts or inline payloads.'))
    return out


def check_canarytoken(pdf: PDFFile) -> list[tuple[str, str, str]]:
    """URI pointing at a CanaryToken host — a deliberate tracking beacon.
    Often seen in honeypot PDFs, red-team sample drops, or IR deceptions.
    Not inherently malicious, but strong context signal.
    """
    out = []
    for o, url in _iter_uris(pdf):
        host = _host_of(url)
        if host in _CANARYTOKEN_HOSTS or host.endswith('.canarytokens.org') \
                or host.endswith('.canary.tools'):
            out.append(('MED', 'CANARYTOKEN',
                        f'obj {o.index} URI is a CanaryToken beacon ({host}): {url}'))
    return out


def check_typosquat_domain(pdf: PDFFile) -> list[tuple[str, str, str]]:
    """Domain whose labels look like misspellings of common brand words.

    Heuristic: split the host on '-' and '.', then for each label >=4 chars
    fuzzy-match against a brand-word list. If two or more labels are close
    (ratio >= 0.78) but not exact matches to a brand word, flag.
    """
    from difflib import SequenceMatcher
    out = []
    seen_hosts: set[str] = set()
    for o, url in _iter_uris(pdf):
        host = _host_of(url)
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)
        # Strip trailing TLD (keep the interesting label portion)
        # Then split on '-' and '.'
        parts = re.split(r'[-.]', host)
        parts = [p for p in parts if len(p) >= 4]
        if len(parts) < 2:
            continue
        matches: list[tuple[str, str, float]] = []  # (label, brand, ratio)
        for label in parts:
            if label in _BRAND_WORDS:
                continue  # exact match isn't a typo
            best_brand = None
            best_ratio = 0.0
            for brand in _BRAND_WORDS:
                # skip trivially different lengths
                if abs(len(brand) - len(label)) > 3:
                    continue
                r = SequenceMatcher(None, label, brand).ratio()
                if r > best_ratio:
                    best_brand, best_ratio = brand, r
            if best_brand and best_ratio >= 0.78 and label != best_brand:
                matches.append((label, best_brand, best_ratio))

        if len(matches) >= 2:
            detail = ', '.join(f'"{lbl}"≈"{brand}" ({r*100:.0f}%)'
                               for lbl, brand, r in matches[:5])
            out.append(('INFO', 'TYPOSQUAT_DOMAIN',
                        f'obj {o.index} URI host "{host}" contains multiple '
                        f'brand-word misspellings: {detail}'))
    return out


def check_base64_in_uri(pdf: PDFFile) -> list[tuple[str, str, str]]:
    """URI whose query/path carries a long base64-looking blob.
    Catches tracker redirects (wix.com/so/?w=<base64>), opaque one-click
    landers, and encoded C2 tokens. Base64-decodes the blob and reports
    the first human-readable bytes when possible.
    """
    import base64 as _b64
    out = []
    b64_token = re.compile(r'[A-Za-z0-9_\-/+=]{40,}')
    for o, url in _iter_uris(pdf):
        # Search the part after the domain
        tail = url
        if '://' in tail:
            tail = tail.split('://', 1)[1]
        if '/' in tail:
            tail = tail.split('/', 1)[1]  # drop host
        for m in b64_token.finditer(tail):
            blob = m.group(0)
            # Avoid obvious non-b64 cases (very high digit fraction = hash/id)
            alpha = sum(1 for c in blob if c.isalpha())
            if alpha < len(blob) * 0.4:
                continue
            # Try decoding (padding-tolerant, urlsafe first)
            decoded: bytes | None = None
            padded = blob + '=' * (-len(blob) % 4)
            try:
                decoded = _b64.urlsafe_b64decode(padded)
            except Exception:
                try:
                    decoded = _b64.b64decode(padded, validate=False)
                except Exception:
                    decoded = None
            if not decoded or len(decoded) < 6:
                continue
            # Must contain mostly printable ASCII to count as "successful"
            printable = sum(1 for b in decoded if 0x20 <= b < 0x7f or b in (0x0a, 0x0d, 0x09))
            if printable < len(decoded) * 0.8:
                continue
            preview = decoded[:80].decode('latin-1', 'replace').replace('\n', ' ')
            out.append(('MED', 'BASE64_IN_URI',
                        f'obj {o.index} URI contains a base64-encoded blob '
                        f'({len(blob)} chars) decoding to: "{preview}"'))
            break  # one flag per URI is enough
    return out


# ---------------------------------------------------------------------------
# INFO-level identifier rules — "what kind of PDF is this?" Not verdicts,
# just facts worth surfacing so the analyst can decide.
# ---------------------------------------------------------------------------

# Noise hosts never worth calling out as "external contact".
_NOISE_HOSTS = {
    'www.w3.org', 'w3.org',
    'ns.adobe.com', 'www.adobe.com', 'adobe.com',
    'www.aiim.org', 'aiim.org',
    'purl.org', 'www.purl.org',
    'www.microsoft.com', 'microsoft.com', 'crl.microsoft.com',
    'www.iec.ch', 'iec.ch',
    'www.apache.org', 'apache.org',
    'scripts.sil.org', 'www.sil.org',
    'www.ascendercorp.com', 'ascendercorp.com',
    'dejavu.sourceforge.net', 'sourceforge.net',
    'en.wikipedia.org', 'wikipedia.org',
    'lucasfonts.com',
}

# Common "reasonable" TLDs. Everything else triggers UNCOMMON_TLD.
_COMMON_TLDS = {
    'com', 'net', 'org', 'gov', 'edu', 'mil', 'int',
    'io', 'co', 'uk', 'de', 'fr', 'ca', 'au', 'us', 'eu',
    'ch', 'nl', 'se', 'no', 'fi', 'dk', 'be', 'ie', 'es', 'it', 'pt',
    'jp', 'kr',
}


def _ident_external_hosts(pdf: PDFFile) -> set[str]:
    hosts: set[str] = set()
    for _o, url in _iter_uris(pdf):
        h = _host_of(url)
        if h and h not in _NOISE_HOSTS:
            hosts.add(h)
    return hosts


def check_ident_acroform(pdf: PDFFile) -> list[tuple[str, str, str]]:
    for t in pdf.trailers + []:
        pass  # noop, just to keep symmetry
    if _has_keyword(pdf, '/AcroForm'):
        widgets = sum(1 for o in pdf.objects if o.kind == 'Annot:Widget')
        extra = f' ({widgets} Widget field{"s" if widgets != 1 else ""})' if widgets else ''
        return [('INFO', 'HAS_ACROFORM',
                 f'PDF declares /AcroForm — interactive form present{extra}.')]
    return []


def check_ident_xfa(pdf: PDFFile) -> list[tuple[str, str, str]]:
    if _has_keyword(pdf, '/XFA'):
        return [('INFO', 'HAS_XFA',
                 'PDF declares /XFA (XML Forms Architecture) — dynamic forms '
                 'that can embed JavaScript and have a historical exploit record.')]
    return []


def check_ident_submitform(pdf: PDFFile) -> list[tuple[str, str, str]]:
    out = []
    for o in pdf.objects:
        if '/SubmitForm' in o.body or '/S/SubmitForm' in o.body or '/S /SubmitForm' in o.body:
            m = re.search(r'/F\s*\(\s*([^)]+)\)', o.body)
            target = m.group(1).strip() if m else '(target not parsed)'
            out.append(('INFO', 'HAS_SUBMITFORM',
                        f'obj {o.index} /SubmitForm action — sends form data to: {target}'))
    return out


def check_ident_openaction(pdf: PDFFile) -> list[tuple[str, str, str]]:
    # Skip if the heavier OPENACTION_JS already fires (avoid duplicate noise).
    if _has_keyword(pdf, '/OpenAction'):
        return [('INFO', 'HAS_OPENACTION',
                 '/OpenAction present — a target runs automatically when the '
                 'document opens. Inspect the linked object.')]
    return []


def check_ident_aa(pdf: PDFFile) -> list[tuple[str, str, str]]:
    if _has_keyword(pdf, '/AA'):
        return [('INFO', 'HAS_AA',
                 '/AA (Additional Actions) present — triggers on page/widget '
                 'events (open, close, focus, mouse). Walk the linked action(s).')]
    return []


def check_ident_external_hosts(pdf: PDFFile) -> list[tuple[str, str, str]]:
    hosts = _ident_external_hosts(pdf)
    if not hosts:
        return []
    # Cap the listed hosts so the message doesn't blow up.
    shown = sorted(hosts)[:8]
    more = f' (+{len(hosts) - 8} more)' if len(hosts) > 8 else ''
    return [('INFO', 'EXTERNAL_HOSTS',
             f'PDF URIs contact {len(hosts)} non-boilerplate host(s): '
             + ', '.join(shown) + more)]


def check_ident_uncommon_tld(pdf: PDFFile) -> list[tuple[str, str, str]]:
    out = []
    seen: set[str] = set()
    for o, url in _iter_uris(pdf):
        host = _host_of(url)
        if not host or host in _NOISE_HOSTS:
            continue
        tld = host.rsplit('.', 1)[-1]
        if tld and tld not in _COMMON_TLDS and host not in seen:
            seen.add(host)
            out.append(('INFO', 'UNCOMMON_TLD',
                        f'obj {o.index} URI host "{host}" uses uncommon TLD ".{tld}".'))
    return out


def check_ident_hyphenated_host(pdf: PDFFile) -> list[tuple[str, str, str]]:
    out = []
    seen: set[str] = set()
    for o, url in _iter_uris(pdf):
        host = _host_of(url)
        if not host or host in _NOISE_HOSTS or host in seen:
            continue
        if host.count('-') >= 3:
            seen.add(host)
            out.append(('INFO', 'HYPHENATED_HOST',
                        f'obj {o.index} URI host "{host}" contains '
                        f'{host.count("-")} hyphens — common phishing pattern.'))
    return out


def check_not_a_pdf(pdf: PDFFile) -> list[tuple[str, str, str]]:
    """File doesn't have a %PDF- header. Sniff the first bytes to report what
    it actually is — catches EXE/ZIP/OLE/HTML files distributed with a .pdf
    filename (classic phishing lure or broken/renamed sample).
    """
    out = []
    needs_flag = (not pdf.header) or (not pdf.header.startswith('%PDF-'))
    if not needs_flag:
        return out

    magic_desc = 'unknown'
    try:
        with open(pdf.path, 'rb') as fh:
            head = fh.read(16)
        if head[:2] == b'MZ':
            magic_desc = 'Windows PE executable (MZ header)'
        elif head[:4] == b'\x7fELF':
            magic_desc = 'ELF executable'
        elif head[:4] == b'\xd0\xcf\x11\xe0':
            magic_desc = 'OLE compound document (Office 97-2003)'
        elif head[:2] == b'PK':
            magic_desc = 'ZIP / OOXML container'
        elif head[:4] == b'%!PS':
            magic_desc = 'PostScript'
        elif head[:5] == b'{\\rtf':
            magic_desc = 'RTF document'
        elif head[:5].lower() in (b'<html', b'<!doc'):
            magic_desc = 'HTML document'
        elif head[:6] == b'Rar!\x1a\x07':
            magic_desc = 'RAR archive'
        elif head[:4] == b'7z\xbc\xaf':
            magic_desc = '7-Zip archive'
        else:
            magic_desc = f'unknown (first bytes: {head[:8].hex()})'
    except OSError as e:
        magic_desc = f'could not read: {e}'

    out.append(('HIGH', 'NOT_A_PDF',
                f'File does not begin with %PDF- header. Detected magic: {magic_desc}. '
                'This is not a parseable PDF; downstream structural rules cannot apply.'))
    return out


def check_aa_javascript(pdf: PDFFile) -> list[tuple[str, str, str]]:
    """Any /AA (Additional Actions) dict that triggers /JavaScript.

    Complements OPENACTION_JS: actions can fire on page open, form focus,
    annotation mouse-over, and many other events beyond /OpenAction.
    """
    out = []
    pat = re.compile(r'/AA\s*<<[^>]*(?:/JS|/JavaScript)\b', re.I)
    for o in pdf.objects:
        if pat.search(o.body):
            out.append(('HIGH', 'AA_JAVASCRIPT',
                        f'obj {o.index} has an /AA (Additional Actions) dictionary '
                        'invoking JavaScript — fires on a triggering event without '
                        'needing /OpenAction.'))
    return out


ALL_RULES = [
    check_multirev_weaponization,
    check_launch_cmd,
    check_newline_padding,
    check_embedded_executable,
    check_openaction_javascript,
    check_full_page_link,
    check_high_entropy_streams,
    check_objstm_present,
    check_xref_stream,
    check_encryption,
    check_url_shortener,
    check_dynamic_dns,
    check_uri_to_executable,
    check_uri_swap_across_revisions,
    check_js_export_data_object,
    check_launch_shell_meta,
    check_filespec_ext_mismatch,
    check_uri_octal_encoded,
    check_abused_file_host,
    check_raw_ip_uri,
    check_uri_on_widget,
    check_invisible_widget,
    check_large_widget,
    check_aa_javascript,
    check_canarytoken,
    check_typosquat_domain,
    check_base64_in_uri,
    check_not_a_pdf,
    # INFO-level identifiers (surface facts, not verdicts)
    check_ident_acroform,
    check_ident_xfa,
    check_ident_submitform,
    check_ident_openaction,
    check_ident_aa,
    check_ident_external_hosts,
    check_ident_uncommon_tld,
    check_ident_hyphenated_host,
]


def run_all(pdf: PDFFile) -> None:
    pdf.flags.clear()
    for rule in ALL_RULES:
        try:
            pdf.flags.extend(rule(pdf))
        except Exception as e:
            pdf.flags.append(('INFO', 'RULE_ERROR', f'{rule.__name__}: {e}'))
