"""
pdfstudio.hunt
Forensic / threat-hunting enrichment of PDF IOCs.

Extracts URLs from `/URI` actions, domains from them, and hashes of
every embedded / decoded stream. Then — on explicit opt-in — resolves
DNS, performs HTTP HEAD, and queries URLhaus, VirusTotal, and
MalwareBazaar where API keys are provided via environment variables:

    VT_API_KEY   — VirusTotal v3 API key
    MB_API_KEY   — MalwareBazaar Auth-Key
    URLHAUS_KEY  — abuse.ch Auth-Key (optional; anonymous POST works)

Network is OFF by default. Nothing here runs unless `enable_*` flags
are passed to `run_hunt`.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

from .model import PDFFile


DEFAULT_TIMEOUT = 10
USER_AGENT = 'pdfstudio/0.1 (+research; no payload download)'


# ---------------------------------------------------------------------------
# IOC extraction (offline)
# ---------------------------------------------------------------------------

RE_URI_INLINE = re.compile(r'/URI\s*\(([^)]*)\)')
RE_URL_FREEFORM = re.compile(r'https?://[^\s\'"<>)\]\}]+')


@dataclass
class IOCBundle:
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    stream_sha256: list[tuple[int, str, int]] = field(default_factory=list)
    # (obj_index, sha256, decoded_length)


def extract_iocs(pdf: PDFFile) -> IOCBundle:
    bundle = IOCBundle()
    seen_urls: set[str] = set()

    for obj in pdf.objects:
        for m in RE_URI_INLINE.finditer(obj.body):
            u = m.group(1).strip()
            if u and u not in seen_urls:
                bundle.urls.append(u)
                seen_urls.add(u)
        for m in RE_URL_FREEFORM.finditer(obj.body):
            u = m.group(0).rstrip('.,;')
            if u not in seen_urls:
                bundle.urls.append(u)
                seen_urls.add(u)

    # Also scan decoded streams for free-form URLs
    for obj in pdf.objects:
        if obj.stream and obj.stream.decoded_bytes:
            try:
                text = obj.stream.decoded_bytes.decode('latin-1', errors='replace')
            except Exception:
                continue
            for m in RE_URL_FREEFORM.finditer(text):
                u = m.group(0).rstrip('.,;')
                if u not in seen_urls:
                    bundle.urls.append(u)
                    seen_urls.add(u)

    # Derive domains from URLs
    seen_domains: set[str] = set()
    for url in bundle.urls:
        try:
            host = urllib.parse.urlparse(url).hostname
            if host and host not in seen_domains:
                bundle.domains.append(host)
                seen_domains.add(host)
        except Exception:
            pass

    # Stream sha256 fingerprints (decoded)
    for obj in pdf.objects:
        if obj.stream and obj.stream.decoded_bytes:
            h = hashlib.sha256(obj.stream.decoded_bytes).hexdigest()
            bundle.stream_sha256.append((obj.index, h, len(obj.stream.decoded_bytes)))
    return bundle


# ---------------------------------------------------------------------------
# Network enrichment (opt-in only)
# ---------------------------------------------------------------------------

def _http(method: str, url: str, *, headers: Optional[dict] = None,
          data: Optional[bytes] = None, timeout: int = DEFAULT_TIMEOUT) -> dict:
    headers = headers or {}
    headers.setdefault('User-Agent', USER_AGENT)
    req = urllib.request.Request(url, method=method, headers=headers, data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(1024 * 1024)  # cap 1 MiB defensively
            return {
                'status': resp.status,
                'headers': {k.lower(): v for k, v in resp.getheaders()},
                'body': body,
                'final_url': resp.geturl(),
            }
    except Exception as e:
        return {'error': str(e)}


def resolve_dns(host: str) -> list[str]:
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
    except Exception as e:
        return [f'(dns error: {e})']


def http_head(url: str) -> dict:
    r = _http('HEAD', url)
    if 'error' in r:
        # Some servers reject HEAD; fall back to GET with range 0-1023
        r = _http('GET', url, headers={'Range': 'bytes=0-1023'})
    return r


def query_urlhaus(url: str) -> dict:
    """Anonymous POST. Optional Auth-Key via URLHAUS_KEY env var."""
    data = urllib.parse.urlencode({'url': url}).encode('ascii')
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    if (key := os.environ.get('URLHAUS_KEY')):
        headers['Auth-Key'] = key
    r = _http('POST', 'https://urlhaus-api.abuse.ch/v1/url/', headers=headers, data=data)
    if 'error' in r:
        return r
    try:
        return json.loads(r['body'].decode('utf-8', errors='replace'))
    except Exception as e:
        return {'parse_error': str(e), 'raw_head': r['body'][:200]}


def query_vt_url(url: str) -> dict:
    key = os.environ.get('VT_API_KEY')
    if not key:
        return {'skipped': 'VT_API_KEY not set'}
    # Encode URL → base64 id per VT API v3
    import base64
    vid = base64.urlsafe_b64encode(url.encode('utf-8')).rstrip(b'=').decode('ascii')
    r = _http('GET', f'https://www.virustotal.com/api/v3/urls/{vid}',
              headers={'x-apikey': key})
    if 'error' in r:
        return r
    try:
        return json.loads(r['body'].decode('utf-8', errors='replace'))
    except Exception as e:
        return {'parse_error': str(e)}


def query_mb_hash(sha256: str) -> dict:
    key = os.environ.get('MB_API_KEY')
    if not key:
        return {'skipped': 'MB_API_KEY not set'}
    data = urllib.parse.urlencode({'query': 'get_info', 'hash': sha256}).encode('ascii')
    headers = {'Content-Type': 'application/x-www-form-urlencoded',
               'Auth-Key': key}
    r = _http('POST', 'https://mb-api.abuse.ch/api/v1/', headers=headers, data=data)
    if 'error' in r:
        return r
    try:
        return json.loads(r['body'].decode('utf-8', errors='replace'))
    except Exception as e:
        return {'parse_error': str(e)}


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run_hunt(pdf: PDFFile, *, mode: str = 'all',
             with_dns: bool = True,
             with_head: bool = True,
             with_urlhaus: bool = True,
             with_vt: bool = False,
             with_mb: bool = False,
             stdout=sys.stdout) -> None:
    bundle = extract_iocs(pdf)

    out = stdout.write

    def h(line: str = ''):
        out(line + '\n')

    h('─' * 72)
    h(f'pdfstudio hunt — {os.path.basename(pdf.path)}')
    h('─' * 72)

    if mode in ('all', 'url'):
        h('')
        h(f'URLs extracted: {len(bundle.urls)}')
        for u in bundle.urls:
            h(f'  • {u}')

        h('')
        h(f'Domains: {len(bundle.domains)}')
        for d in bundle.domains:
            parts = [f'  • {d}']
            if with_dns:
                ips = resolve_dns(d)
                parts.append(f'-> {", ".join(ips)}')
            h(' '.join(parts))

        if with_head:
            h('')
            h('HTTP HEAD results (truncated):')
            for u in bundle.urls:
                r = http_head(u)
                if 'error' in r:
                    h(f'  ✗ {u}  -> {r["error"]}')
                    continue
                ct = r['headers'].get('content-type', '?')
                cl = r['headers'].get('content-length', '?')
                loc = r['headers'].get('location', '')
                line = f'  ✓ {u}  HTTP {r["status"]}  {ct}  len={cl}'
                if loc:
                    line += f'  -> {loc}'
                if r['final_url'] != u:
                    line += f'  (final={r["final_url"]})'
                h(line)

        if with_urlhaus:
            h('')
            h('URLhaus (abuse.ch) lookup:')
            for u in bundle.urls:
                r = query_urlhaus(u)
                q = r.get('query_status', 'unknown')
                threat = r.get('threat', '')
                tags = ','.join(r.get('tags') or [])
                h(f'  • {u}  status={q}  threat={threat}  tags={tags}')

        if with_vt:
            h('')
            h('VirusTotal URL lookup (VT_API_KEY):')
            for u in bundle.urls:
                r = query_vt_url(u)
                if 'skipped' in r:
                    h(f'  (skipped — {r["skipped"]})')
                    break
                if 'error' in r:
                    h(f'  ✗ {u}  -> {r["error"]}')
                    continue
                attrs = (r.get('data') or {}).get('attributes') or {}
                stats = attrs.get('last_analysis_stats', {})
                h(f'  • {u}  malicious={stats.get("malicious")}  suspicious={stats.get("suspicious")}  harmless={stats.get("harmless")}')

    if mode in ('all', 'hash'):
        h('')
        h(f'Embedded stream SHA-256 ({len(bundle.stream_sha256)}):')
        for idx, sha, n in bundle.stream_sha256:
            h(f'  obj {idx:<4}  {n:>10,} B  {sha}')

        if with_mb:
            h('')
            h('MalwareBazaar hash lookup (MB_API_KEY):')
            for idx, sha, _ in bundle.stream_sha256:
                r = query_mb_hash(sha)
                if 'skipped' in r:
                    h(f'  (skipped — {r["skipped"]})')
                    break
                if 'error' in r:
                    h(f'  ✗ obj {idx}  -> {r["error"]}')
                    continue
                q = r.get('query_status', 'unknown')
                sig = ((r.get('data') or [{}])[0] or {}).get('signature') if r.get('data') else ''
                h(f'  obj {idx:<4}  {sha}  status={q}  signature={sig or "—"}')

    h('─' * 72)
