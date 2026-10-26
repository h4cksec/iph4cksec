"""DNS toolkit: records, SPF recursion, DKIM/DMARC, AXFR, wildcard detection."""
from __future__ import annotations

import random
import re
import socket
import string
from typing import Any

import dns.exception
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone

from .util import dbg, run_parallel

RESOLVER = dns.resolver.Resolver()
RESOLVER.timeout = 4.0
RESOLVER.lifetime = 6.0
RESOLVER.edns = 0

DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "s1", "s2", "k1", "k2",
    "mail", "dkim", "smtp", "mta", "cm", "protonmail", "protonmail2",
    "protonmail3", "mandrill", "mailchimp", "sendgrid", "amazonses",
    "resend", "postmark", "everlytics", "zoho", "yahoo", "outlook",
]


def resolve(name: str, rtype: str = "A") -> list[str]:
    name = name.strip().rstrip(".")
    if not name:
        return []
    out: list[str] = []
    try:
        answers = RESOLVER.resolve(name, rtype, raise_on_no_answer=False)
        for rr in answers:
            if rtype in ("A", "AAAA"):
                out.append(str(rr).strip())
            elif rtype in ("MX", "NS", "CNAME", "PTR"):
                parts = str(rr).strip().split()
                out.append((parts[-1] if parts else str(rr)).rstrip("."))
            elif rtype == "TXT":
                if hasattr(rr, "strings"):
                    out.append(b"".join(rr.strings).decode("utf-8", "ignore"))
                else:
                    out.append(str(rr).strip().strip('"'))
            else:
                out.append(str(rr).strip())
    except (dns.exception.DNSException, ValueError, OSError):
        pass
    if not out and rtype == "A":
        try:
            out = list({ai[4][0] for ai in socket.getaddrinfo(name, None, socket.AF_INET)})
        except socket.gaierror:
            pass
    return sorted(set(x for x in out if x))


def resolve_many(names: list[str], workers: int = 40) -> dict[str, list[str]]:
    res = run_parallel(lambda n: resolve(n, "A") + resolve(n, "AAAA"), names, workers)
    return {n: (v or []) for n, v in res.items()}


def doh_resolve(name: str, rtype: str = "A", timeout: float = 8.0) -> list[str]:
    from .util import fetch
    r = fetch(
        "https://dns.google/resolve",
        timeout=timeout,
        params={"name": name, "type": rtype},
        headers={"Accept": "application/dns-json"},
    )
    if r is None or not r.ok:
        return []
    try:
        payload = r.json()
    except ValueError:
        return []
    out = []
    for ans in payload.get("Answer", []) or []:
        data = str(ans.get("data", "")).strip().strip('"')
        if rtype in ("A", "AAAA") and data:
            out.append(data)
        elif rtype in ("CNAME", "NS", "PTR") and data:
            out.append(data.rstrip("."))
        elif rtype == "TXT" and data:
            out.append(data)
    return sorted(set(out))


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def cname_chain(name: str, depth: int = 8) -> list[str]:
    chain: list[str] = []
    cur = name
    for _ in range(depth):
        nxt = resolve(cur, "CNAME")
        if not nxt:
            break
        target = nxt[0]
        if target in chain or target == cur:
            break
        chain.append(target)
        cur = target
    return chain


def wildcard_test(domain: str) -> tuple[bool, set[str]]:
    labels = "".join(random.choice(string.ascii_lowercase) for _ in range(14))
    probe = f"{labels}.{domain}"
    ips = set(resolve(probe, "A") + resolve(probe, "AAAA"))
    return bool(ips), ips


def axfr(domain: str, timeout: float = 6.0) -> list[str]:
    """Attempt a zone transfer against every authoritative NS."""
    found: set[str] = set()
    for ns in resolve(domain, "NS"):
        for ip in resolve(ns, "A"):
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ip, domain, timeout=timeout, lifetime=timeout * 2))
                for name in zone.nodes.keys():
                    host = str(name)
                    if host != "@":
                        found.add(host if host.endswith(domain) else f"{host}.{domain}")
                    else:
                        found.add(domain)
            except Exception as exc:  # noqa: BLE001
                dbg(f"axfr {ns} ({ip}) failed: {exc}")
    return sorted(found)


def dns_records(domain: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "DS", "SRV"):
        vals = resolve(domain, rtype)
        if vals:
            out[rtype] = vals
    return out


def spf_data(domain: str, depth: int = 0, seen: set[str] | None = None) -> dict[str, Any]:
    seen = seen or set()
    result: dict[str, Any] = {"records": [], "ips": set(), "includes": [], "redirects": []}
    if depth > 4 or domain in seen:
        return result
    seen.add(domain)
    for txt in resolve(domain, "TXT"):
        if "v=spf1" not in txt.lower():
            continue
        result["records"].append(txt)
        for token in txt.split():
            low = token.lower()
            if low.startswith(("ip4:", "ip6:")):
                result["ips"].add(token.split(":", 1)[1].split("/")[0])
            elif low.startswith("include:"):
                inc = token.split(":", 1)[1].rstrip(".")
                result["includes"].append(inc)
                sub = spf_data(inc, depth + 1, seen)
                result["ips"].update(sub["ips"])
                result["includes"].extend(sub["includes"])
                result["redirects"].extend(sub["redirects"])
            elif low.startswith("redirect="):
                red = token.split("=", 1)[1].rstrip(".")
                result["redirects"].append(red)
                sub = spf_data(red, depth + 1, seen)
                result["ips"].update(sub["ips"])
            elif low in ("a", "mx") or low.startswith(("a:", "mx:")):
                target = domain
                if ":" in low:
                    target = token.split(":", 1)[1].rstrip(".")
                if low.startswith("a"):
                    for ip in resolve(target, "A"):
                        result["ips"].add(ip)
                else:
                    for mx in resolve(target, "MX"):
                        for ip in resolve(mx, "A"):
                            result["ips"].add(ip)
    result["ips"] = sorted(result["ips"])
    result["includes"] = sorted(set(result["includes"]))
    result["redirects"] = sorted(set(result["redirects"]))
    return result


def _dkim_key_ok(txt: str) -> bool:
    m = re.search(r"(?:^|;)\s*p=([^;]*)", txt or "", re.I)
    return bool(m and m.group(1).strip())


def email_posture(domain: str) -> dict[str, Any]:
    spf = spf_data(domain)
    dmarc_records = [t for t in resolve(f"_dmarc.{domain}", "TXT") if "v=dmarc1" in t.lower()]
    dmarc_policy = ""
    for rec in dmarc_records:
        for part in rec.split(";"):
            part = part.strip()
            if part.lower().startswith("p="):
                dmarc_policy = part.split("=", 1)[1].strip()
    wildcard_txts = resolve(f"*._domainkey.{domain}", "TXT")
    wildcard_valid = any(_dkim_key_ok(t) for t in wildcard_txts)
    dkim = []
    for sel in DKIM_SELECTORS:
        txts = resolve(f"{sel}._domainkey.{domain}", "TXT")
        good = [t for t in txts if _dkim_key_ok(t)
                and not (wildcard_valid and t in wildcard_txts)]
        if good:
            dkim.append(sel)
    mta_sts = [t for t in resolve(f"_mta-sts.{domain}", "TXT") if "v=stsv1" in t.lower()]
    tls_rpt = [t for t in resolve(f"_smtp._tls.{domain}", "TXT") if "v=tlsrptv1" in t.lower()]
    bimi = [t for t in resolve(f"default._bimi.{domain}", "TXT") if "v=bimi1" in t.lower()]
    caa = resolve(domain, "CAA")
    ds = resolve(domain, "DS")
    return {
        "spf": spf,
        "dmarc": dmarc_records,
        "dmarc_policy": dmarc_policy,
        "dkim_selectors": dkim,
        "dkim_wildcard": wildcard_valid,
        "mta_sts": mta_sts,
        "tls_rpt": tls_rpt,
        "bimi": bimi,
        "caa": caa,
        "dnssec": bool(ds),
        "ds": ds,
    }


def dns_meta(domain: str) -> dict[str, Any]:
    """Everything a recon pass wants from DNS, in one dict."""
    recs = dns_records(domain)
    posture = email_posture(domain)
    extra_hosts: set[str] = set()
    for key in ("autodiscover", "autoconfig", "mail", "webmail", "smtp", "imap", "pop",
                "ftp", "vpn", "portal", "api", "dev", "staging", "mta-sts",
                "_acme-challenge", "www", "origin", "direct"):
        chain = cname_chain(f"{key}.{domain}")
        if chain:
            extra_hosts.add(f"{key}.{domain}")
            extra_hosts.update(chain)
    return {
        "records": recs,
        "posture": posture,
        "cname_hosts": sorted(extra_hosts),
        "mx": resolve(domain, "MX"),
        "ns": resolve(domain, "NS"),
        "soa": (resolve(domain, "SOA") or [""])[0],
        "wildcard": wildcard_test(domain)[0],
        "axfr": [],
    }
