"""HTTP/TLS fingerprinting, favicon hashing, and multi-signal comparison."""
from __future__ import annotations

import base64
import hashlib
import random
import re
import socket
import ssl
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import mmh3
import urllib3
from bs4 import BeautifulSoup

from .util import UA_POOL, fetch, jaccard, norm_text, shingles

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID
    _HAS_CRYPTO = True
except Exception:  # noqa: BLE001
    _HAS_CRYPTO = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_PAGE_MARKERS = [
    "welcome to nginx", "apache2 ubuntu default page", "apache2 debian default page",
    "iis windows server", "it works!", "default web site page", "site not configured",
    "domain not found", "no website configured", "web server's default page",
    "plesk", "cpanel", "index of /", "there is no website configured",
    "this domain is parked", "future home of something quite cool",
    "account suspended", "site temporarily unavailable",
]


@dataclass
class Fingerprint:
    url: str = ""
    final_url: str = ""
    status: int = 0
    title: str = ""
    text_tokens: list[str] = field(default_factory=list)
    text_sig: set[str] = field(default_factory=set)
    shingle_sig: set[str] = field(default_factory=set)
    body_len: int = 0
    body_sha: str = ""
    favicon: int | None = None
    server: str = ""
    ctype: str = ""
    powered: str = ""
    meta_generator: str = ""
    asset_hashes: set[str] = field(default_factory=set)
    cookie_names: set[str] = field(default_factory=set)
    headers: dict[str, str] = field(default_factory=dict)
    cert_sha: str = ""
    cert_names: list[str] = field(default_factory=list)
    cf_headers: bool = False
    default_page: bool = False

    def summary(self) -> dict[str, Any]:
        return {
            "url": self.url, "final_url": self.final_url, "status": self.status,
            "title": self.title, "body_len": self.body_len, "favicon_hash": self.favicon,
            "server": self.server, "content_type": self.ctype,
            "powered_by": self.powered, "meta_generator": self.meta_generator,
            "cert_sha256": self.cert_sha, "cert_names": self.cert_names,
            "cloudflare_headers": self.cf_headers, "default_page": self.default_page,
        }


def parse_html(html: str) -> dict[str, Any]:
    out: dict[str, Any] = {
        "title": "", "text": "", "generator": "", "assets": set(), "cookies": set(),
    }
    try:
        soup = BeautifulSoup(html[:500_000], "html.parser")
        if soup.title and soup.title.string:
            out["title"] = norm_text(str(soup.title.string))
        gen = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
        if gen and gen.get("content"):
            out["generator"] = norm_text(gen["content"])
        assets: set[str] = set()
        for tag, attr in (("script", "src"), ("link", "href"), ("img", "src")):
            for node in soup.find_all(tag):
                val = node.get(attr)
                if not val or val.startswith(("data:", "javascript:")):
                    continue
                path = urllib.parse.urlparse(val).path or val
                assets.add(hashlib.sha1(path.encode("utf-8", "ignore")).hexdigest()[:16])
        out["assets"] = assets
        for bad in soup(["script", "style", "noscript", "svg"]):
            bad.decompose()
        out["text"] = soup.get_text(" ")
    except Exception:
        out["text"] = re.sub(r"<[^>]+>", " ", html[:200_000])
    return out


def tokens_of(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]{4,}", text.lower())[:8000]


def default_page(title: str, body: str, server: str = "") -> bool:
    blob = f"{title} {body[:4000]} {server}".lower()
    return any(marker in blob for marker in DEFAULT_PAGE_MARKERS)


def cert_info(host: str, port: int = 443, sni: str | None = None,
              timeout: float = 8.0) -> tuple[str, list[str]]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni or host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                if not der:
                    return "", []
                return hashlib.sha256(der).hexdigest(), cert_names(der)
    except (OSError, ssl.SSLError, ValueError):
        return "", []


def cert_names(der: bytes) -> list[str]:
    names: set[str] = set()
    if _HAS_CRYPTO:
        try:
            cert = x509.load_der_x509_certificate(der, default_backend())
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                names.update(san.value.get_values_for_type(x509.DNSName))
            except x509.ExtensionNotFound:
                pass
            for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                val = attr.value if isinstance(attr.value, str) else str(attr.value)
                if "." in val:
                    names.add(val)
            return sorted(n for n in names if n and "." in n)
        except Exception:  # noqa: BLE001
            pass
    for raw in re.findall(rb"[a-zA-Z0-9*][a-zA-Z0-9.*_-]{1,60}\.[a-zA-Z]{2,12}", der):
        s = raw.decode("ascii", "ignore").strip("*.")
        if "." in s and " " not in s:
            names.add(s)
    return sorted(names)[:64]


def tls_meta(host: str, port: int = 443, sni: str | None = None,
             timeout: float = 8.0) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    out: dict[str, Any] = {}
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni or host) as ssock:
                out["version"] = ssock.version()
                out["cipher"] = (ssock.cipher() or ["", "", 0])[0]
                der = ssock.getpeercert(binary_form=True)
                if der and _HAS_CRYPTO:
                    cert = x509.load_der_x509_certificate(der, default_backend())
                    out["issuer"] = cert.issuer.rfc4514_string()
                    out["subject"] = cert.subject.rfc4514_string()
                    out["not_after"] = cert.not_valid_after_utc.isoformat()
                    out["sha256"] = hashlib.sha256(der).hexdigest()
                    try:
                        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        out["names"] = san.value.get_values_for_type(x509.DNSName)
                    except x509.ExtensionNotFound:
                        out["names"] = []
    except (OSError, ssl.SSLError, ValueError):
        return out
    return out


def _pool(host: str, port: int, scheme: str, sni: str, timeout: float):
    if scheme == "https":
        return urllib3.HTTPSConnectionPool(
            host, port=port,
            timeout=urllib3.Timeout(connect=timeout, read=timeout),
            cert_reqs="CERT_NONE", assert_hostname=False,
            server_hostname=sni, maxsize=1, retries=False, block=False,
        )
    return urllib3.HTTPConnectionPool(
        host, port=port,
        timeout=urllib3.Timeout(connect=timeout, read=timeout),
        maxsize=1, retries=False, block=False,
    )


def http_probe(
    host: str, port: int, scheme: str, host_header: str,
    path: str = "/", timeout: float = 8.0,
    extra_headers: dict[str, str] | None = None,
    sni: str | None = None,
) -> tuple[int, dict[str, str], bytes] | None:
    pool = None
    try:
        pool = _pool(host, port, scheme, sni or host_header, timeout)
        headers = {"Host": host_header, "User-Agent": random.choice(UA_POOL), "Accept": "*/*"}
        if extra_headers:
            headers.update(extra_headers)
        resp = pool.request("GET", path, headers=headers, redirect=False,
                            preload_content=False)
        try:
            data = resp.read(1_000_000) or b""
        finally:
            resp.release_conn()
        hdrs = {str(k).lower(): str(v) for k, v in resp.headers.items()}
        return resp.status, hdrs, data
    except Exception:
        return None
    finally:
        if pool is not None:
            try:
                pool.close()
            except Exception:
                pass


def favicon_hash(base_url: str, timeout: float = 8.0,
                 connect: tuple[str, int, str, str] | None = None,
                 html: str | None = None) -> int | None:
    """connect=(ip, port, scheme, host_header) to reach an origin directly."""
    icon_paths: list[str] = []
    if html is None:
        if connect:
            ip, port, scheme, host_header = connect
            pr = http_probe(ip, port, scheme, host_header, "/", timeout, sni=host_header)
            if pr is not None:
                html = pr[2][:300_000].decode("utf-8", "ignore")
        else:
            r = fetch(base_url, timeout=timeout)
            if r is not None and r.ok:
                html = r.text[:300_000]
    if html:
        icon_paths.extend(_icon_paths(html, base_url))
    icon_paths.append("/favicon.ico")

    seen: set[str] = set()
    for href in icon_paths[:6]:
        url = urllib.parse.urljoin(base_url, href)
        if url in seen:
            continue
        seen.add(url)
        if connect:
            ip, port, scheme, host_header = connect
            u = urllib.parse.urlparse(url)
            path = u.path + (("?" + u.query) if u.query else "")
            use_scheme = u.scheme or scheme
            use_port = u.port or (443 if use_scheme == "https" else 80)
            pr = http_probe(ip, use_port, use_scheme, host_header, path, timeout, sni=host_header)
            if pr is not None and pr[0] == 200 and pr[2]:
                return mmh3.hash(base64.b64encode(pr[2]))
        else:
            rr = fetch(url, timeout=timeout)
            if rr is not None and rr.ok and rr.content:
                return mmh3.hash(base64.b64encode(rr.content))
    return None


def _icon_paths(html: str, base_url: str) -> list[str]:
    paths: list[str] = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        for link in soup.find_all("link"):
            rel = " ".join(link.get("rel") or []).lower()
            if "icon" in rel and link.get("href"):
                paths.append(link["href"])
    except Exception:
        pass
    return paths


def fingerprint_url(url: str, timeout: float = 12.0, with_favicon: bool = True) -> Fingerprint:
    fp = Fingerprint(url=url)
    r = fetch(url, timeout=timeout, allow_redirects=True)
    if r is None:
        return fp
    fp.final_url = r.url
    fp.status = r.status_code
    fp.server = r.headers.get("server", "")
    fp.ctype = r.headers.get("content-type", "").split(";")[0].strip().lower()
    fp.powered = r.headers.get("x-powered-by", "")
    fp.headers = {k.lower(): v for k, v in r.headers.items()}
    fp.cf_headers = any(k in fp.headers for k in ("cf-ray", "cf-cache-status", "cf-mitigated")) \
        or "cloudflare" in fp.server.lower()
    fp.cookie_names = {c.name for c in r.cookies}
    html = r.text[:500_000]
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
    u = urllib.parse.urlparse(fp.final_url or url)
    fp.cert_sha, fp.cert_names = cert_info(
        u.hostname or "", u.port or (443 if u.scheme == "https" else 80),
        sni=u.hostname, timeout=timeout,
    )
    if with_favicon:
        fp.favicon = favicon_hash(fp.final_url or url, timeout=timeout)
    return fp


def compare(base: Fingerprint, cand: Fingerprint, domain: str) -> tuple[int, list[str]]:
    """Return (score 0..100, evidence list). Active signals only."""
    evidence: list[str] = []
    score = 0.0

    text_sim = jaccard(base.text_sig, cand.text_sig)
    shingle_sim = jaccard(base.shingle_sig, cand.shingle_sig)
    if text_sim >= 0.92:
        score += 34; evidence.append(f"text={text_sim:.2f} very-high")
    elif text_sim >= 0.80:
        score += 24; evidence.append(f"text={text_sim:.2f} high")
    elif text_sim >= 0.60:
        score += 14; evidence.append(f"text={text_sim:.2f} medium")
    elif text_sim >= 0.35:
        score += 6; evidence.append(f"text={text_sim:.2f} low")

    if shingle_sim >= 0.60:
        score += 12; evidence.append(f"shingle={shingle_sim:.2f}")
    elif shingle_sim >= 0.30:
        score += 6

    if base.title and cand.title and base.title.lower() == cand.title.lower():
        score += 16; evidence.append(f"title={cand.title!r}")
    if base.favicon is not None and cand.favicon is not None and base.favicon == cand.favicon:
        score += 14; evidence.append(f"favicon={cand.favicon}")
    if base.asset_hashes and cand.asset_hashes:
        asset_sim = jaccard(base.asset_hashes, cand.asset_hashes)
        if asset_sim >= 0.5:
            score += 10; evidence.append(f"assets={asset_sim:.2f}")
        elif asset_sim >= 0.2:
            score += 4
    if base.cookie_names and cand.cookie_names:
        cookie_sim = jaccard(base.cookie_names, cand.cookie_names)
        if cookie_sim >= 0.5:
            score += 6; evidence.append(f"cookies={cookie_sim:.2f}")
    if base.meta_generator and base.meta_generator.lower() == cand.meta_generator.lower():
        score += 4; evidence.append(f"generator={cand.meta_generator!r}")
    if base.status == cand.status:
        score += 4
    if base.ctype and cand.ctype and base.ctype == cand.ctype:
        score += 3
    if cand.cert_names and any(n == domain or n.endswith("." + domain) or
                               n.lstrip("*.") == domain for n in cand.cert_names):
        score += 8; evidence.append("cert-covers-domain")
    if base.body_len and cand.body_len:
        ratio = min(base.body_len, cand.body_len) / max(base.body_len, cand.body_len)
        if ratio >= 0.85:
            score += 4
        elif ratio >= 0.5:
            score += 2

    if cand.default_page:
        score -= 25; evidence.append("default-page")
    if cand.cf_headers:
        score -= 20; evidence.append("cdn-response")
    if base.status >= 400 and cand.status < 400:
        score -= 10; evidence.append("status-mismatch")
    if base.status < 400 and cand.status >= 500:
        score -= 10; evidence.append("server-error")

    return max(0, min(100, int(round(score)))), evidence
