"""Keyless IP / domain / ASN intelligence: RDAP, InternetDB, BGPView, geolocation."""
from __future__ import annotations

import ipaddress
from typing import Any

import dns.resolver

from . import dnsx, sources
from .fingerprint import cert_info, fingerprint_url
from .util import get_json


def _rdap_entity_names(entities: list[dict[str, Any]]) -> list[str]:
    names: list[str] = []
    for ent in entities or []:
        vcard = ent.get("vcardArray") or []
        if len(vcard) > 1:
            for item in vcard[1]:
                if item and item[0] == "fn" and len(item) > 3:
                    names.append(str(item[3]))
        names.extend(_rdap_entity_names(ent.get("entities", [])))
    return names


def _cymru_txt(name: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=6)
        out = []
        for rr in answers:
            if hasattr(rr, "strings"):
                out.append(b"".join(rr.strings).decode("utf-8", "ignore"))
            else:
                out.append(str(rr).strip().strip('"'))
        return out
    except Exception:  # noqa: BLE001
        return []


def cymru_ip(ip: str) -> dict[str, Any]:
    rev = ".".join(reversed(ip.split(".")))
    rows = _cymru_txt(f"{rev}.origin.asn.cymru.com")
    if not rows:
        return {}
    parts = [p.strip() for p in rows[0].split("|")]
    return {"prefix": parts[1] if len(parts) > 1 else "",
            "asn": parts[0] if parts else "", "country": parts[2] if len(parts) > 2 else ""}


def cymru_asn(asn: str) -> dict[str, Any]:
    rows = _cymru_txt(f"AS{asn}.asn.cymru.com")
    if not rows:
        return {}
    parts = [p.strip() for p in rows[0].split("|")]
    return {"asn": parts[0] if parts else asn,
            "country": parts[1] if len(parts) > 1 else "",
            "description": parts[-1] if parts else ""}


def ip_intel(ip: str) -> dict[str, Any]:
    out: dict[str, Any] = {"ip": ip, "reverse_dns": dnsx.reverse_dns(ip)}
    rdap = get_json(f"https://rdap.org/ip/{ip}", timeout=15)
    if isinstance(rdap, dict):
        out["rdap"] = {
            "name": rdap.get("name", ""), "handle": rdap.get("handle", ""),
            "country": rdap.get("country", ""), "type": rdap.get("type", ""),
            "start": rdap.get("startAddress", ""), "end": rdap.get("endAddress", ""),
            "entities": sorted(set(_rdap_entity_names(rdap.get("entities", []))))[:8],
            "remarks": [r.get("description") for r in rdap.get("remarks", []) if r.get("description")],
        }
    idb = sources.internetdb(ip)
    if idb:
        out["internetdb"] = {
            "ports": idb.get("ports", []), "hostnames": idb.get("hostnames", []),
            "cpes": idb.get("cpes", []), "tags": idb.get("tags", []),
            "vulns": idb.get("vulns", []),
        }
    bgp: list[dict[str, Any]] = []
    netinfo = get_json(
        f"https://stat.ripe.net/data/network-info/data.json?resource={ip}", timeout=15)
    if isinstance(netinfo, dict):
        payload = netinfo.get("data") or {}
        prefix = payload.get("prefix", "")
        for asn in payload.get("asns", []) or []:
            info = get_json(
                f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}",
                timeout=12)
            holder = ((info or {}).get("data") or {}).get("holder", "") if isinstance(info, dict) else ""
            bgp.append({"prefix": prefix, "asn": asn, "asn_name": holder,
                        "asn_desc": holder, "country": ""})
    if not bgp:
        cy = cymru_ip(ip)
        if cy:
            bgp.append({"prefix": cy.get("prefix"), "asn": cy.get("asn"),
                        "asn_name": "", "asn_desc": "", "country": cy.get("country")})
    out["bgp"] = bgp
    geo = get_json(f"https://ipwho.is/{ip}", timeout=10)
    if isinstance(geo, dict) and geo.get("success"):
        out["geo"] = {
            "country": geo.get("country"), "region": geo.get("region"),
            "city": geo.get("city"), "isp": (geo.get("connection") or {}).get("isp"),
            "org": (geo.get("connection") or {}).get("org"),
            "asn": (geo.get("connection") or {}).get("asn"),
            "lat": geo.get("latitude"), "lon": geo.get("longitude"),
        }
    return out


def domain_intel(domain: str) -> dict[str, Any]:
    out: dict[str, Any] = {"domain": domain}
    rdap = get_json(f"https://rdap.org/domain/{domain}", timeout=15)
    if isinstance(rdap, dict):
        events = {e.get("eventAction"): e.get("eventDate") for e in rdap.get("events", [])}
        out["rdap"] = {
            "handle": rdap.get("handle", ""), "status": rdap.get("status", []),
            "registrar": next((n for n in _rdap_entity_names(rdap.get("entities", []))
                               if "registrar" in n.lower()), ""),
            "entities": sorted(set(_rdap_entity_names(rdap.get("entities", []))))[:10],
            "registered": events.get("registration"), "expires": events.get("expiration"),
            "updated": events.get("last changed"),
            "nameservers": [n.get("ldhName", "").lower() for n in rdap.get("nameservers", [])],
        }
    meta = dnsx.dns_meta(domain)
    out["dns"] = meta
    out["cert"] = dict(zip(("sha256", "names"), cert_info(domain)))
    fp = fingerprint_url(f"https://{domain}/", timeout=12)
    if fp.status == 0:
        fp = fingerprint_url(f"http://{domain}/", timeout=12)
    out["http"] = fp.summary()
    ips = dnsx.resolve(domain, "A") + dnsx.resolve(domain, "AAAA")
    out["asn"] = []
    for ip in ips[:4]:
        intel = ip_intel(ip)
        out["asn"].append({"ip": ip, "bgp": intel.get("bgp", []), "geo": intel.get("geo", {})})
    return out


def asn_prefixes(asn: str) -> dict[str, Any]:
    asn = asn.upper().replace("AS", "")
    out: dict[str, Any] = {"asn": f"AS{asn}", "prefixes": [], "count": 0}
    data = get_json(
        f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}",
        timeout=25)
    if isinstance(data, dict):
        for p in ((data.get("data") or {}).get("prefixes") or []):
            out["prefixes"].append({"prefix": p.get("prefix"), "name": "",
                                    "description": "", "country": ""})
    out["count"] = len(out["prefixes"])
    info = get_json(
        f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}", timeout=15)
    if isinstance(info, dict):
        holder = (info.get("data") or {}).get("holder", "")
        out["name"] = holder
        out["description"] = holder
        out["country"] = ""
    if not out.get("name"):
        cy = cymru_asn(asn)
        out["name"] = cy.get("description", "")
        out["description"] = cy.get("description", "")
        out["country"] = cy.get("country", "")
    return out


def netblock_hosts(prefix: str, limit: int = 24) -> list[str]:
    """Sample a /24 (or smaller) and pull hostnames from InternetDB."""
    try:
        net = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return []
    hosts: set[str] = set()
    if net.num_addresses > 256:
        base = int(net.network_address)
        step = max(1, net.num_addresses // limit)
        candidates = [str(ipaddress.ip_address(base + i * step)) for i in range(limit)]
    else:
        candidates = [str(ip) for ip in list(net.hosts())[:limit]]
    for ip in candidates:
        for host in sources.internetdb(ip).get("hostnames", []) or []:
            hosts.add(str(host).lower())
    return sorted(hosts)[:500]
