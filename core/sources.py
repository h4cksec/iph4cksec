"""Keyless passive sources. Every function returns {hostname: set(ip)}.

No API keys, no paid feeds. Sources that are down return {}.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any

from bs4 import BeautifulSoup

from .util import dbg, fetch, get_json

IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)


def _norm_host(value: str, domain: str) -> str | None:
    value = (value or "").strip().lower().lstrip("*.").rstrip(".")
    if not value or " " in value or "/" in value:
        return None
    if value.startswith("http"):
        value = urllib.parse.urlparse(value).hostname or ""
    if not value or not HOST_RE.match(value):
        return None
    if value != domain and not value.endswith("." + domain):
        return None
    return value


def _add(out: dict[str, set[str]], host: str, domain: str, ip: str | None = None) -> None:
    h = _norm_host(host, domain)
    if not h:
        return
    out.setdefault(h, set())
    if ip and IP_RE.match(ip):
        out[h].add(ip)


def src_crtsh(domain: str, timeout: float = 20.0) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    r = fetch(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=timeout)
    if r is None or not r.ok:
        return out
    try:
        rows = r.json()
    except ValueError:
        return out
    for row in rows if isinstance(rows, list) else []:
        for field in ("name_value", "common_name"):
            for name in str(row.get(field, "")).splitlines():
                _add(out, name, domain)
    return out


def src_certspotter(domain: str, timeout: float = 20.0) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    url = ("https://api.certspotter.com/v1/issuances"
           f"?domain={domain}&include_subdomains=true&expand=dns_names")
    data = get_json(url, timeout=timeout)
    for cert in data if isinstance(data, list) else []:
        for name in cert.get("dns_names", []) or []:
            _add(out, name, domain)
    return out


def src_hackertarget(domain: str, timeout: float = 15.0) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    r = fetch(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=timeout)
    if r is None or not r.ok or "error" in r.text.lower()[:60]:
        return out
    for line in r.text.splitlines():
        if "," not in line:
            continue
        host, ip = line.split(",", 1)
        _add(out, host, domain, ip.strip())
    return out


def src_rapiddns(domain: str, timeout: float = 20.0) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    r = fetch(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=timeout)
    if r is None or not r.ok:
        return out
    try:
        soup = BeautifulSoup(r.text, "html.parser")
        for tr in soup.select("tr"):
            tds = [td.get_text(" ", strip=True) for td in tr.find_all("td")]
            if len(tds) >= 2 and "." in tds[0]:
                ip = tds[1] if IP_RE.match(tds[1]) else None
                _add(out, tds[0], domain, ip)
    except Exception:
        pass
    return out


def src_otx(domain: str, timeout: float = 15.0) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    data = get_json(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
        timeout=timeout,
    )
    for rec in (data or {}).get("passive_dns", []) if isinstance(data, dict) else []:
        _add(out, rec.get("hostname", ""), domain, rec.get("address"))
    return out


def src_urlscan(domain: str, timeout: float = 15.0) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    data = get_json(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100", timeout=timeout)
    for res in (data or {}).get("results", []) if isinstance(data, dict) else []:
        page = res.get("page", {}) or {}
        _add(out, page.get("domain", ""), domain, page.get("ip"))
    return out


def src_threatminer(domain: str, timeout: float = 15.0) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    data = get_json(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", timeout=timeout)
    for name in (data or {}).get("results", []) if isinstance(data, dict) else []:
        _add(out, str(name), domain)
    return out


def src_wayback(domain: str, timeout: float = 25.0) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    url = (f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
           "&output=json&collapse=urlkey&fl=original&limit=3000")
    r = fetch(url, timeout=timeout)
    if r is None or not r.ok or "Temporarily Offline" in r.text[:200]:
        return out
    try:
        rows = r.json()
    except ValueError:
        return out
    for row in rows[1:] if isinstance(rows, list) else []:
        if not row:
            continue
        try:
            host = urllib.parse.urlparse(row[0]).hostname or ""
        except ValueError:
            continue
        _add(out, host, domain)
    return out


def src_commoncrawl(domain: str, timeout: float = 25.0) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    coll = get_json("https://index.commoncrawl.org/collinfo.json", timeout=timeout)
    if not isinstance(coll, list) or not coll:
        return out
    for idx in coll[:2]:
        api = idx.get("cdx-api")
        if not api:
            continue
        r = fetch(
            api,
            timeout=timeout,
            params={"url": f"*.{domain}", "output": "json", "limit": 2000},
        )
        if r is None or not r.ok:
            continue
        for line in r.text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            url = row.get("url", "")
            try:
                host = urllib.parse.urlparse(url).hostname or ""
            except ValueError:
                continue
            _add(out, host, domain)
    return out


def src_duckduckgo(domain: str, timeout: float = 15.0) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    r = fetch(
        "https://html.duckduckgo.com/html/",
        timeout=timeout,
        params={"q": f"site:{domain}"},
        headers={"Accept-Language": "en-US,en;q=0.9"},
    )
    if r is None or not r.ok:
        return out
    try:
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.select("a.result__a"):
            href = a.get("href", "")
            if "uddg=" in href:
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
                href = (qs.get("uddg") or [""])[0]
            try:
                host = urllib.parse.urlparse(href).hostname or ""
            except ValueError:
                continue
            _add(out, host, domain)
    except Exception:
        pass
    return out


def src_subdomain_center(domain: str, timeout: float = 20.0) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    data = get_json(f"https://api.subdomain.center/?domain={domain}", timeout=timeout)
    if isinstance(data, list):
        for name in data:
            label = str(name).split(".")[0]
            if not label or label[0].isdigit() or re.match(r"^[a-z]\d{5,}$", label):
                continue
            _add(out, str(name), domain)
    return out


def src_mnemonic(domain: str, timeout: float = 20.0) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for query in (domain, f"www.{domain}"):
        data = get_json(
            f"https://api.mnemonic.no/pdns/v3/{query}?limit=1000",
            timeout=timeout,
        )
        if not isinstance(data, dict):
            continue
        for rec in data.get("data", []) or []:
            rrtype = str(rec.get("rrtype", "")).lower()
            answer = str(rec.get("answer", "")).strip().rstrip(".")
            if rrtype in ("a", "aaaa"):
                _add(out, rec.get("query", ""), domain, answer)
            elif rrtype == "cname":
                _add(out, answer, domain)
    return out


def src_mnemonic_host(host: str, timeout: float = 12.0) -> dict[str, set[str]]:
    """Historical A/AAAA for one hostname (passive DNS)."""
    out: dict[str, set[str]] = {}
    data = get_json(f"https://api.mnemonic.no/pdns/v3/{host}?limit=300", timeout=timeout)
    if not isinstance(data, dict):
        return out
    for rec in data.get("data", []) or []:
        rrtype = str(rec.get("rrtype", "")).lower()
        answer = str(rec.get("answer", "")).strip().rstrip(".")
        if rrtype in ("a", "aaaa") and IP_RE.match(answer):
            out.setdefault(host, set()).add(answer)
    return out


def src_anubis(domain: str, timeout: float = 15.0) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    r = fetch(f"https://jldc.me/anubis/subdomains/{domain}", timeout=timeout)
    if r is None or not r.ok:
        return out
    try:
        data = r.json()
    except ValueError:
        return out
    if isinstance(data, list):
        for name in data:
            _add(out, str(name), domain)
    return out


SOURCES: dict[str, Any] = {
    "crtsh": src_crtsh,
    "certspotter": src_certspotter,
    "hackertarget": src_hackertarget,
    "rapiddns": src_rapiddns,
    "otx": src_otx,
    "urlscan": src_urlscan,
    "threatminer": src_threatminer,
    "wayback": src_wayback,
    "commoncrawl": src_commoncrawl,
    "duckduckgo": src_duckduckgo,
    "subdomaincenter": src_subdomain_center,
    "mnemonic": src_mnemonic,
    "anubis": src_anubis,
}

FAST_SOURCES = ["crtsh", "certspotter", "hackertarget", "otx", "urlscan", "mnemonic", "rapiddns"]
DEEP_SOURCES = list(SOURCES.keys())


def gather_passive(domain: str, names: list[str], timeout: float = 20.0,
                   workers: int = 8) -> tuple[dict[str, set[str]], dict[str, int]]:
    """Run selected sources in parallel; return merged hosts and per-source counts."""
    from .util import run_parallel

    merged: dict[str, set[str]] = {}
    counts: dict[str, int] = {}

    def one(name: str):
        fn = SOURCES[name]
        return name, fn(domain, timeout)

    results = run_parallel(one, names, workers)
    for name, found in results.values() if results else []:
        if not isinstance(found, dict):
            continue
        counts[name] = len(found)
        for host, ips in found.items():
            merged.setdefault(host, set()).update(ips)
    return merged, counts


def reverse_ip(ip: str, timeout: float = 15.0) -> set[str]:
    """Keyless reverse-IP via hackertarget + InternetDB hostnames."""
    hosts: set[str] = set()
    r = fetch(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=timeout)
    if r is not None and r.ok and "error" not in r.text.lower()[:40]:
        for line in r.text.splitlines():
            line = line.strip().lower()
            if line and HOST_RE.match(line):
                hosts.add(line)
    data = get_json(f"https://internetdb.shodan.io/{ip}", timeout=timeout)
    if isinstance(data, dict):
        for h in data.get("hostnames", []) or []:
            h = str(h).strip().lower()
            if HOST_RE.match(h):
                hosts.add(h)
    return hosts


def internetdb(ip: str, timeout: float = 12.0) -> dict[str, Any]:
    data = get_json(f"https://internetdb.shodan.io/{ip}", timeout=timeout)
    return data if isinstance(data, dict) else {}
