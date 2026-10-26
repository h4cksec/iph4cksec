"""Origin discovery: passive hosts -> candidate IPs -> active multi-signal verification."""
from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import urllib3

from . import dnsx, sources
from .fingerprint import (
    Fingerprint, cert_info, compare, default_page, favicon_hash, fingerprint_url,
    http_probe, parse_html, shingles, tls_meta, tokens_of,
)
from .util import log, run_parallel
from .wordlist import load_wordlist, permutations

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CLOUDFLARE_V4 = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
CLOUDFLARE_V6 = [
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]
CF_NETS = [ipaddress.ip_network(n) for n in CLOUDFLARE_V4 + CLOUDFLARE_V6]

HTTP_PORTS = [(80, "http"), (443, "https")]
DEEP_PORTS = [(8080, "http"), (8443, "https"), (8000, "http"),
              (8888, "http"), (3000, "http"), (5000, "http"), (9000, "http")]
SERVICE_PORTS = [21, 22, 25, 3306, 5432, 6379, 9200, 11211, 27017]


@dataclass
class Candidate:
    ip: str
    host: str = ""
    source: str = ""
    score: int = 0
    evidence: list[str] = field(default_factory=list)
    status: int = 0
    server: str = ""
    title: str = ""
    favicon: int | None = None
    cert_names: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    tls: dict[str, Any] = field(default_factory=dict)
    fp: dict[str, Any] = field(default_factory=dict)
    cdn: bool = False
    provider: str = ""
    body_sha: str = ""
    aliases: list[str] = field(default_factory=list)

    def row(self) -> dict[str, Any]:
        return {
            "ip": self.ip, "score": self.score, "host": self.host,
            "source": self.source, "status": self.status, "server": self.server,
            "title": self.title, "favicon": self.favicon,
            "ports": ",".join(str(p) for p in self.ports),
            "cert_names": ",".join(self.cert_names[:8]),
            "evidence": "; ".join(self.evidence),
            "tls_version": self.tls.get("version", ""),
            "tls_issuer": self.tls.get("issuer", ""),
            "provider": self.provider,
            "aliases": ",".join(self.aliases),
        }


PROVIDER_SIGNS = [
    ("cloudflare", ("cf-ray", "cf-cache-status", "cf-mitigated")),
    ("vercel", ("x-vercel-id", "x-vercel-cache")),
    ("cloudfront", ("x-amz-cf-id", "x-amz-cf-pop")),
    ("fastly", ("x-fastly-request-id",)),
    ("akamai", ("x-akamai-transformed", "x-akamai-request-id")),
    ("imperva", ("x-iinfo",)),
    ("sucuri", ("x-sucuri-id",)),
    ("netlify", ("x-nf-request-id",)),
    ("bunny", ("x-bunnycdn",)),
    ("azure", ("x-azure-ref", "x-msedge-ref")),
]


def detect_provider(headers: dict[str, str], server: str = "") -> str:
    low = {k.lower(): v.lower() for k, v in headers.items()}
    for provider, keys in PROVIDER_SIGNS:
        if any(k in low for k in keys):
            return provider
    srv = (server or low.get("server", "")).lower()
    for provider in ("cloudflare", "vercel", "cloudfront", "fastly", "akamai",
                     "netlify", "sucuri", "bunnycdn", "gws", "github.com"):
        if provider in srv:
            return "google" if provider == "gws" else provider.replace(".com", "")
    if "amazons3" in srv:
        return "aws-s3"
    return ""


def is_cdn(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in CF_NETS)


def _cookie_names(headers: dict[str, str]) -> set[str]:
    raw = headers.get("set-cookie", "")
    names: set[str] = set()
    for part in raw.split(","):
        first = part.strip().split("=", 1)[0].strip()
        if first and " " not in first:
            names.add(first)
    return names


def fp_from_probe(ip: str, port: int, scheme: str, host_header: str,
                  status: int, headers: dict[str, str], data: bytes,
                  timeout: float, with_favicon: bool = True) -> Fingerprint:
    fp = Fingerprint(url=f"{scheme}://{host_header}/", final_url=f"{scheme}://{host_header}/")
    fp.status = status
    fp.server = headers.get("server", "")
    fp.ctype = headers.get("content-type", "").split(";")[0].strip().lower()
    fp.powered = headers.get("x-powered-by", "")
    fp.headers = headers
    fp.cf_headers = any(k in headers for k in ("cf-ray", "cf-cache-status", "cf-mitigated")) \
        or "cloudflare" in fp.server.lower()
    fp.cookie_names = _cookie_names(headers)
    html = (data or b"")[:500_000].decode("utf-8", "ignore")
    parsed = parse_html(html)
    fp.title = parsed["title"]
    fp.text_tokens = tokens_of(parsed["text"])
    fp.text_sig = set(fp.text_tokens)
    fp.shingle_sig = shingles(fp.text_tokens, 3)
    fp.body_len = len(html)
    fp.body_sha = hashlib.sha256(html.encode("utf-8", "ignore")).hexdigest()
    fp.meta_generator = parsed["generator"]
    fp.asset_hashes = parsed["assets"]
    fp.default_page = default_page(fp.title, html, fp.server)
    fp.cert_sha, fp.cert_names = cert_info(ip, port, sni=host_header, timeout=timeout)
    if with_favicon:
        fp.favicon = favicon_hash(f"{scheme}://{host_header}/", timeout=timeout,
                                  connect=(ip, port, scheme, host_header), html=html)
    return fp


def probe_host(ip: str, host_header: str, port: int, scheme: str,
               timeout: float = 7.0) -> tuple[int, dict[str, str], bytes] | None:
    return http_probe(ip, port, scheme, host_header, "/", timeout, sni=host_header)


def service_banner(ip: str, port: int, timeout: float = 4.0) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in (80, 8080, 8000, 8888, 3000, 5000, 9000):
                sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            elif port == 443:
                return ""
            data = sock.recv(512)
            text = data.decode("utf-8", "ignore")
            first = text.splitlines()[0] if text else ""
            return first[:160]
    except (OSError, ssl.SSLError, ValueError):
        return ""


def gather_candidates(
    domain: str,
    passive_hosts: dict[str, set[str]],
    deep: bool = True,
    brute: bool = False,
    wordlist_path: str | None = None,
    workers: int = 40,
) -> tuple[dict[str, set[str]], dict[str, set[str]], dict[str, Any]]:
    """Return (ip -> hostnames, ip -> sources, stats)."""
    ip_hosts: dict[str, set[str]] = {}
    ip_sources: dict[str, set[str]] = {}
    stats: dict[str, Any] = {"passive_hosts": len(passive_hosts), "resolved": 0,
                             "brute_hosts": 0, "axfr_hosts": 0, "spf_ips": 0}

    def link(ip: str, host: str, src: str) -> None:
        ip_hosts.setdefault(ip, set()).add(host)
        ip_sources.setdefault(ip, set()).add(src)

    for host, ips in passive_hosts.items():
        for ip in ips:
            link(ip, host, "passive")

    hosts = sorted(passive_hosts)[:600]
    resolved = dnsx.resolve_many(hosts, workers=workers)
    for host, ips in resolved.items():
        for ip in ips:
            link(ip, host, "dns")
    stats["resolved"] = len(resolved)

    for mx in dnsx.resolve(domain, "MX"):
        for ip in dnsx.resolve(mx, "A"):
            link(ip, mx, "mx")

    spf = dnsx.spf_data(domain)
    for ip in spf["ips"]:
        link(ip, domain, "spf")
    stats["spf_ips"] = len(spf["ips"])

    axfr_hosts = dnsx.axfr(domain) if deep else []
    stats["axfr_hosts"] = len(axfr_hosts)
    for host in axfr_hosts:
        for ip in dnsx.resolve(host, "A"):
            link(ip, host, "axfr")

    brute_names: list[str] = []
    if brute:
        words = load_wordlist(wordlist_path)
        brute_names = [f"{w}.{domain}" for w in words]
        brute_names += permutations(sorted(passive_hosts), domain)
        brute_names = sorted(set(brute_names))[:4000]
        bres = dnsx.resolve_many(brute_names, workers=workers)
        for host, ips in bres.items():
            if ips:
                stats["brute_hosts"] += 1
                for ip in ips:
                    link(ip, host, "brute")

    if deep:
        hist_hosts = sorted(passive_hosts)[:60]
        hist = run_parallel(lambda h: (h, sources.src_mnemonic_host(h)), hist_hosts, 10)
        for pair in hist.values():
            if not pair:
                continue
            host, found = pair
            for h, ips in (found or {}).items():
                for ip in ips:
                    link(ip, h, "pdns-history")

    if deep:
        rev_targets = [ip for ip in list(ip_hosts)[:80] if not is_cdn(ip)]
        rev = run_parallel(lambda ip: (ip, sources.reverse_ip(ip)), rev_targets, 12)
        for pair in rev.values():
            if not pair:
                continue
            ip, hostnames = pair
            for host in hostnames:
                if host == domain or host.endswith("." + domain):
                    link(ip, host, "reverse-ip")
    return ip_hosts, ip_sources, stats


def _host_priority(hosts: set[str], domain: str) -> list[str]:
    def key(h: str) -> tuple[int, int]:
        is_sub = 0 if h.endswith("." + domain) else 1
        return (is_sub, len(h))
    return sorted(hosts, key=key)


def _cert_covers(names: list[str], domain: str) -> bool:
    for n in names:
        n = n.lower().lstrip("*.")
        if n == domain or n.endswith("." + domain):
            return True
    return False


def verify_candidate(
    ip: str,
    domain: str,
    hosts: set[str],
    srcs: set[str],
    base: Fingerprint,
    timeout: float = 7.0,
    deep: bool = True,
    challenge: bool = False,
) -> Candidate | None:
    cand = Candidate(ip=ip, host="", source=",".join(sorted(srcs)))
    cand.cdn = is_cdn(ip)
    best: tuple[int, Fingerprint, str, int, str] | None = None
    tried: set[tuple[str, int, str]] = set()
    for host_header in _host_priority(hosts, domain)[:6] + [domain]:
        for port, scheme in HTTP_PORTS + (DEEP_PORTS if deep else []):
            key = (host_header, port, scheme)
            if key in tried:
                continue
            tried.add(key)
            pr = probe_host(ip, host_header, port, scheme, timeout)
            if pr is None:
                continue
            status, headers, data = pr
            if "cloudflare" in headers.get("server", "").lower() or "cf-ray" in headers:
                continue
            fp = fp_from_probe(ip, port, scheme, host_header, status, headers, data,
                               timeout, with_favicon=True)
            if challenge:
                score, evidence = 0, []
                if _cert_covers(fp.cert_names, domain):
                    score += 45; evidence.append("cert-covers-domain")
                if not fp.cf_headers:
                    score += 10; evidence.append("direct-response")
                if fp.status in (200, 201, 204, 301, 302, 401, 403):
                    score += 10; evidence.append(f"status={fp.status}")
                if fp.title:
                    score += 5; evidence.append(f"title={fp.title[:40]!r}")
                if host_header == domain:
                    score += 5; evidence.append("apex-host")
                if srcs & {"spf", "mx", "axfr"}:
                    score += 12; evidence.append("mail-or-dns-record")
                if fp.default_page:
                    score -= 25; evidence.append("default-page")
                score = max(0, min(100, score))
            else:
                score, evidence = compare(base, fp, domain)
            if best is None or score > best[0]:
                best = (score, fp, host_header, port, scheme)
    if best is None:
        return None
    score, fp, host_header, port, scheme = best
    cand.host = host_header
    cand.score = score
    cand.evidence = evidence
    cand.status = fp.status
    cand.server = fp.server
    cand.title = fp.title
    cand.favicon = fp.favicon
    cand.cert_names = fp.cert_names
    cand.fp = fp.summary()
    cand.provider = detect_provider(fp.headers, fp.server)
    cand.body_sha = fp.body_sha
    cand.ports = [port]
    if cand.provider:
        cand.evidence.append(f"via={cand.provider}")

    if deep:
        for sport in SERVICE_PORTS:
            banner = service_banner(ip, sport, timeout=3.0)
            if banner:
                cand.services[sport] = banner
                cand.ports.append(sport)
        tls = {}
        for p, s in ((443, "https"), (8443, "https")):
            if p == port or p in cand.ports:
                tls = tls_meta(ip, p, sni=host_header, timeout=timeout)
                if tls:
                    break
        cand.tls = tls
        if tls.get("names") and not cand.cert_names:
            cand.cert_names = tls["names"]

    if "spf" in srcs:
        cand.score = min(100, cand.score + 12); cand.evidence.append("spf-ip")
    if "mx" in srcs:
        cand.score = min(100, cand.score + 8); cand.evidence.append("mx-ip")
    if "axfr" in srcs:
        cand.score = min(100, cand.score + 18); cand.evidence.append("axfr-ip")
    if cand.host and cand.host != domain:
        cand.evidence.append(f"host={cand.host}")
    return cand


def final_verify(cand: Candidate, domain: str, base: Fingerprint,
                 timeout: float = 8.0) -> dict[str, Any]:
    """Second pass over the winner: DNS, HTTP, cert, body, SPF, rDNS."""
    ip = cand.ip
    a_records = dnsx.resolve(domain, "A") + dnsx.resolve(domain, "AAAA")
    dns_match = ip in a_records
    port = 443 if 443 in cand.ports else (80 if 80 in cand.ports else 443)
    scheme = "https" if port == 443 else "http"
    pr = http_probe(ip, port, scheme, domain, "/", timeout, sni=domain)
    status, headers, data = pr if pr else (0, {}, b"")
    html = (data or b"")[:500_000].decode("utf-8", "ignore")
    body_sha = hashlib.sha256(html.encode("utf-8", "ignore")).hexdigest()
    cert_sha, cert_names = cert_info(ip, port, sni=domain, timeout=timeout)
    cert_ok = _cert_covers(cert_names, domain)
    spf_ips = dnsx.spf_data(domain).get("ips", [])
    spf_ok = ip in spf_ips
    rdns = dnsx.reverse_dns(ip)

    sim = 0.0
    evidence: list[str] = []
    if base.status and status:
        fp = fp_from_probe(ip, port, scheme, domain, status, headers, data,
                           timeout, with_favicon=False)
        sim, evidence = compare(base, fp, domain)

    http_ok = status in (200, 201, 204, 301, 302, 401, 403)
    if dns_match and cert_ok and http_ok and (sim >= 60 or body_sha == base.body_sha
                                              or (base.status in (403, 503) and base.cf_headers)):
        verdict = "IP ORIGEN CONFIRMADA"
    elif cert_ok and dns_match:
        verdict = "IP ORIGEN PROBABLE"
    elif cert_ok:
        verdict = "CANDIDATO CON CERTIFICADO DEL DOMINIO"
    else:
        verdict = "NO CONFIRMADA"

    return {
        "ip": ip, "dns_match": dns_match, "dns_records": a_records,
        "http_status": status, "http_server": headers.get("server", ""),
        "cert_ok": cert_ok, "cert_names": cert_names, "cert_sha256": cert_sha,
        "body_sha256": body_sha, "body_match": body_sha == base.body_sha,
        "similarity": sim, "evidence": evidence,
        "spf_match": spf_ok, "reverse_dns": rdns, "verdict": verdict,
    }


def discover(
    domain: str,
    passive_hosts: dict[str, set[str]],
    deep: bool = True,
    brute: bool = False,
    wordlist_path: str | None = None,
    timeout: float = 7.0,
    workers: int = 20,
) -> dict[str, Any]:
    log(f"fingerprinting baseline {domain}", "info")
    base = fingerprint_url(f"https://{domain}/", timeout=max(timeout, 10))
    if base.status == 0:
        base = fingerprint_url(f"http://{domain}/", timeout=max(timeout, 10))
    challenge = base.status in (403, 503) and base.cf_headers
    if base.status == 0:
        log("baseline unreachable; scoring will rely on passive signals", "warn")
    elif base.status in (403, 503) and base.cf_headers:
        log("baseline is a CDN challenge page; scoring confidence is reduced", "warn")

    ip_hosts, ip_sources, stats = gather_candidates(
        domain, passive_hosts, deep=deep, brute=brute,
        wordlist_path=wordlist_path, workers=max(workers * 2, 40),
    )
    stats["candidate_ips"] = len(ip_hosts)
    stats["cdn_ips"] = sum(1 for ip in ip_hosts if is_cdn(ip))
    log(f"candidate IPs: {len(ip_hosts)} ({stats['cdn_ips']} CDN)", "info")

    targets = [ip for ip in ip_hosts if not is_cdn(ip)]
    if not targets:
        targets = list(ip_hosts)

    def one(ip: str):
        return verify_candidate(ip, domain, ip_hosts[ip], ip_sources[ip], base,
                                timeout=timeout, deep=deep, challenge=challenge)

    results = run_parallel(one, targets, workers=workers)
    cands = [c for c in results.values() if c is not None]
    for c in cands:
        if c.cdn:
            c.score = max(0, c.score - 30)
            c.evidence.append("cdn-ip")
    cands.sort(key=lambda c: (-c.score, c.ip))
    merged: list[Candidate] = []
    clusters: dict[tuple[str, str], Candidate] = {}
    for c in cands:
        key = (c.provider, c.body_sha or str(c.fp.get("body_len", 0)))
        if c.provider and key in clusters:
            clusters[key].aliases.append(c.ip)
            continue
        clusters[key] = c
        merged.append(c)
    for c in merged:
        if c.aliases:
            c.evidence.append(f"aliases={len(c.aliases) + 1}")
    cands = merged
    stats["responsive"] = len(cands)
    stats["providers"] = sorted({c.provider for c in cands if c.provider})
    return {"baseline": base, "candidates": cands, "stats": stats,
            "ip_hosts": {ip: sorted(h) for ip, h in ip_hosts.items()}}
