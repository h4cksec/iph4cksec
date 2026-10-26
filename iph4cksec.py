#!/usr/bin/env python3
"""iph4cksec — keyless origin IP discovery and attack-surface intelligence.

No API keys. Passive sources + active multi-signal verification.
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import sys
import time
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import intel, origin, sources, takeover  # noqa: E402
from core.util import C, State, colorize, log, write_csv, write_json  # noqa: E402

VERSION = "2.0.0"
BANNER = r"""
 ___ ____  _   _ _  _    ____ _  ______  _____ ____ 
|_ _|  _ \| | | | || |  / ___| |/ / ___|| ____/ ___|
 | || |_) | |_| | || |_| |   | ' /\___ \|  _|| |    
 | ||  __/|  _  |__   _| |___| . \ ___) | |__| |___ 
|___|_|   |_| |_|  |_|  \____|_|\_\____/|_____\____|
                                                    
        iph4cksec  v""" + VERSION + """
        autor: h4cksec
"""

CONF = [(85, "HIGH"), (65, "MED"), (40, "LOW"), (0, "WEAK")]
CONF_COLOR = {"HIGH": C.GRN, "MED": C.YEL, "LOW": C.CYA, "WEAK": C.GRY}


def conf_label(score: int) -> str:
    for threshold, label in CONF:
        if score >= threshold:
            return label
    return "WEAK"


def print_candidates(cands: list[origin.Candidate], top: int = 25) -> None:
    if not cands:
        print(f"{C.YEL}no candidates responded to direct probes{C.R}")
        return
    print(f"\n{C.B}{'IP':<16} {'SCORE':>5} {'CONF':<5} {'ST':>4}  {'HOST':<34} EVIDENCE{C.R}")
    print(f"{C.GRY}{'-' * 118}{C.R}")
    for c in cands[:top]:
        label = conf_label(c.score)
        col = CONF_COLOR[label]
        host = (c.host or "-")[:34]
        ev = "; ".join(c.evidence)[:56]
        print(f"{c.ip:<16} {c.score:>5} {col}{label:<5}{C.R} {c.status:>4}  {host:<34} {C.GRY}{ev}{C.R}")
        if c.ports:
            ports = ",".join(str(p) for p in sorted(set(c.ports)))
            extra = f"      ports: {ports}"
            if c.tls.get("issuer"):
                extra += f" | tls: {c.tls.get('version', '')} {c.tls.get('issuer', '')[:48]}"
            if c.aliases:
                extra += f" | aliases: {', '.join(c.aliases[:8])}"
            print(f"{C.GRY}{extra}{C.R}")


def print_verdict(cands: list[origin.Candidate], domain: str, provider: str) -> None:
    if not cands:
        width = 72
        bar = "=" * width
        print(f"\n{C.B}{C.BG_RED}{C.BLK}{bar}{C.R}")
        for line in ("  SIN IP ORIGEN CONFIRMADA",
                     "  El origin puede estar firewalleado solo a rangos de CDN."):
            print(f"{C.B}{C.BG_RED}{C.BLK}{line.ljust(width)}{C.R}")
        print(f"{C.B}{C.BG_RED}{C.BLK}{bar}{C.R}")
        return
    best = cands[0]
    if best.score >= 85:
        label, bg = "IP ORIGEN REAL", C.BG_GRN
    elif best.score >= 65:
        label, bg = "PROBABLE IP ORIGEN", C.BG_YEL
    else:
        label, bg = "MEJOR CANDIDATO (NO CONFIRMADO)", C.BG_CYA
    ports = ",".join(str(p) for p in sorted(set(best.ports))) or "-"
    lines = [
        f"  {label}:  {best.ip}",
        f"  Confianza: {best.score}/100 {conf_label(best.score)}   Host: {best.host or domain}",
        f"  Status: {best.status}   Provider: {best.provider or 'directo'}   Puertos: {ports}",
        f"  Evidencia: {'; '.join(best.evidence)[:96]}",
    ]
    if len(cands) > 1 and cands[1].score >= 85:
        others = ", ".join(c.ip for c in cands[1:] if c.score >= 85)
        lines.append(f"  Otras IPs high: {others[:80]}")
    width = 88
    bar = "=" * width
    print(f"\n{C.B}{bg}{C.BLK}{bar}{C.R}")
    for line in lines:
        print(f"{C.B}{bg}{C.BLK}{line[:width].ljust(width)}{C.R}")
    print(f"{C.B}{bg}{C.BLK}{bar}{C.R}")
    if best.score < 85:
        print(f"{C.YEL}  No hay evidencia suficiente para llamarla IP real. Revisar a mano.{C.R}")


def print_verification(v: dict[str, Any]) -> None:
    def mark(ok: bool) -> str:
        return f"{C.GRN}OK{C.R}" if ok else f"{C.RED}NO{C.R}"

    print(f"\n{C.B}VERIFICACIÓN FINAL{C.R}")
    print(f"  {'DNS A/AAAA':<12} {', '.join(v['dns_records']) or '-'}  [{mark(v['dns_match'])}]")
    print(f"  {'HTTP':<12} {v['http_status']} {v['http_server']}  "
          f"[{mark(v['http_status'] in (200, 201, 204, 301, 302, 401, 403))}]")
    print(f"  {'Certificado':<12} {'cubre el dominio' if v['cert_ok'] else 'no cubre'}  "
          f"[{mark(v['cert_ok'])}]")
    body_ok = v['body_match'] or v['similarity'] >= 60
    print(f"  {'Body':<12} similitud {v['similarity']}/100  [{mark(body_ok)}]")
    print(f"  {'SPF':<12} {'IP presente' if v['spf_match'] else 'IP ausente'}  "
          f"[{mark(v['spf_match'])}]")
    print(f"  {'rDNS':<12} {v['reverse_dns'] or '-'}")
    color = C.GRN if v["verdict"] == "IP ORIGEN CONFIRMADA" else C.YEL
    print(f"\n  {C.B}{color}VEREDICTO: {v['verdict']}{C.R}")


def cmd_hunt(args: argparse.Namespace) -> int:
    domain = args.domain.lower().strip().rstrip(".")
    t0 = time.time()
    print(BANNER)
    log(f"target: {domain}", "info")
    names = sources.DEEP_SOURCES if args.deep else sources.FAST_SOURCES
    if args.sources:
        names = [n.strip() for n in args.sources.split(",") if n.strip() in sources.SOURCES]
    log(f"passive sources: {', '.join(names)}", "info")
    passive, counts = sources.gather_passive(
        domain, names, timeout=args.timeout * 2, workers=min(len(names), 10))
    for name in names:
        log(f"{name}: {counts.get(name, 0)} hosts", "dbg")
    log(f"passive total: {len(passive)} unique hosts", "ok")

    result = origin.discover(
        domain, passive,
        deep=args.deep, brute=args.brute, wordlist_path=args.wordlist,
        timeout=args.timeout, workers=args.workers,
    )
    cands: list[origin.Candidate] = result["candidates"]
    print_candidates(cands, top=args.top)

    findings: list[takeover.Finding] = []
    if not args.no_takeover and passive:
        log("checking subdomain takeover", "info")
        findings = takeover.scan(sorted(passive)[:400], workers=args.workers)

    if findings:
        print(f"\n{C.B}TAKEOVER CANDIDATES{C.R}")
        for f in findings:
            print(f"  {C.MAG}{f.host}{C.R} -> {f.cname} [{f.service}] {C.GRY}{f.marker}{C.R}")

    high = [c for c in cands if c.score >= 85]
    stats = result["stats"]
    elapsed = time.time() - t0
    base = result["baseline"]
    base_provider = origin.detect_provider(base.headers, base.server)
    print(f"\n{C.B}SUMMARY{C.R}  {len(passive)} hosts | {stats.get('candidate_ips', 0)} IPs | "
          f"{stats.get('cdn_ips', 0)} CDN | {len(cands)} responsive | "
          f"{len(high)} high-confidence | {elapsed:.1f}s")
    if base_provider:
        print(f"{C.CYA}apex fronted by {base_provider}{C.R}")
    print_verdict(cands, domain, base_provider)

    verification = None
    if cands:
        verification = origin.final_verify(cands[0], domain, result["baseline"], args.timeout)
        print_verification(verification)

    payload: dict[str, Any] = {
        "tool": "iph4cksec", "author": "h4cksec", "version": VERSION, "domain": domain,
        "elapsed_s": round(elapsed, 2), "stats": stats,
        "sources": counts,
        "baseline": result["baseline"].summary(),
        "candidates": [c.row() | {"services": c.services, "tls": c.tls,
                                  "fingerprint": c.fp} for c in cands],
        "takeovers": [f.row() for f in findings],
        "verification": verification,
    }
    if args.json:
        write_json(args.json, payload)
        log(f"json -> {args.json}", "ok")
    if args.csv:
        rows = [c.row() for c in cands]
        write_csv(args.csv, rows, ["ip", "score", "host", "source", "status", "server",
                                   "title", "favicon", "ports", "cert_names", "evidence",
                                   "tls_version", "tls_issuer"])
        log(f"csv -> {args.csv}", "ok")
    return 0


def cmd_intel(args: argparse.Namespace) -> int:
    target = args.target.strip()
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        is_ip = False
    data = intel.ip_intel(target) if is_ip else intel.domain_intel(target)
    if args.json:
        write_json(args.json, data)
        log(f"json -> {args.json}", "ok")
        return 0
    if is_ip:
        print(f"{C.B}IP {target}{C.R}")
        print(f"  rDNS     {data.get('reverse_dns') or '-'}")
        rdap = data.get("rdap") or {}
        if rdap:
            print(f"  netblock {rdap.get('start')} - {rdap.get('end')} ({rdap.get('name')})")
            print(f"  org      {', '.join(rdap.get('entities', []))[:100] or '-'}")
            print(f"  country  {rdap.get('country') or '-'}")
        geo = data.get("geo") or {}
        if geo:
            print(f"  geo      {geo.get('city')}, {geo.get('region')}, {geo.get('country')}"
                  f" | {geo.get('isp')} ({geo.get('asn')})")
        for b in data.get("bgp", []):
            print(f"  bgp      {b.get('prefix')} AS{b.get('asn')} {b.get('asn_name')}")
        idb = data.get("internetdb") or {}
        if idb:
            print(f"  ports    {idb.get('ports')}")
            print(f"  hostnames {', '.join(idb.get('hostnames', [])[:12]) or '-'}")
            if idb.get("tags"):
                print(f"  tags     {', '.join(idb.get('tags', []))}")
            if idb.get("vulns"):
                print(f"  vulns    {', '.join(idb.get('vulns', [])[:10])}")
    else:
        print(f"{C.B}DOMAIN {target}{C.R}")
        rdap = data.get("rdap") or {}
        if rdap:
            print(f"  registrar {rdap.get('registrar') or '-'}")
            print(f"  created   {rdap.get('registered') or '-'} | expires {rdap.get('expires') or '-'}")
            print(f"  status    {', '.join(rdap.get('status', []))}")
            print(f"  ns        {', '.join(rdap.get('nameservers', []))}")
        dns = data.get("dns") or {}
        recs = dns.get("records") or {}
        for rtype in ("A", "AAAA", "MX", "NS", "CAA", "DS"):
            if recs.get(rtype):
                print(f"  {rtype:<8} {', '.join(recs[rtype])}")
        posture = dns.get("posture") or {}
        spf = posture.get("spf") or {}
        print(f"  SPF      {'yes' if spf.get('records') else 'no'}"
              f" | ips={len(spf.get('ips', []))} includes={', '.join(spf.get('includes', [])[:5])}")
        dkim = ', '.join(posture.get('dkim_selectors', [])) or 'none'
        if posture.get('dkim_wildcard'):
            dkim += " (wildcard DNS, ignored)"
        print(f"  DMARC    {'yes p=' + posture.get('dmarc_policy', '') if posture.get('dmarc') else 'no'}"
              f" | DKIM {dkim}")
        print(f"  MTA-STS  {'yes' if posture.get('mta_sts') else 'no'}"
              f" | TLS-RPT {'yes' if posture.get('tls_rpt') else 'no'}"
              f" | DNSSEC {'yes' if posture.get('dnssec') else 'no'}")
        http = data.get("http") or {}
        if http.get("status"):
            print(f"  http     {http.get('status')} {http.get('server')} | "
                  f"title={http.get('title', '')[:60]!r}")
        cert = data.get("cert") or {}
        if cert.get("names"):
            print(f"  cert     {', '.join(cert.get('names', [])[:8])}")
        for row in data.get("asn", []):
            for b in row.get("bgp", [])[:2]:
                print(f"  asn      {row.get('ip')} -> {b.get('prefix')} AS{b.get('asn')} {b.get('asn_name')}")
    return 0


def cmd_asn(args: argparse.Namespace) -> int:
    data = intel.asn_prefixes(args.asn)
    print(f"{C.B}{data.get('asn')} {data.get('name') or ''}{C.R} {data.get('description') or ''}")
    print(f"prefixes: {data.get('count', 0)}")
    for p in data.get("prefixes", [])[:args.limit]:
        print(f"  {p.get('prefix'):<22} {p.get('country') or '':<3} {p.get('description') or p.get('name') or ''}")
    if args.hosts:
        print(f"\n{C.B}hostnames sampled from InternetDB{C.R}")
        for p in data.get("prefixes", [])[:args.limit]:
            for host in intel.netblock_hosts(p.get("prefix", ""), limit=8)[:40]:
                print(f"  {host}")
    if args.json:
        write_json(args.json, data)
        log(f"json -> {args.json}", "ok")
    return 0


def cmd_takeover(args: argparse.Namespace) -> int:
    hosts: list[str] = []
    if args.domain:
        domain = args.domain.lower().strip()
        passive, _ = sources.gather_passive(domain, sources.FAST_SOURCES, timeout=25, workers=8)
        hosts = sorted(passive)
        print(f"{C.B}{len(hosts)} hosts from passive sources{C.R}")
    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as fh:
            hosts += [line.strip().lower() for line in fh if line.strip() and not line.startswith("#")]
    hosts = sorted(set(hosts))
    if not hosts:
        log("no hosts to check", "warn")
        return 1
    findings = takeover.scan(hosts, workers=args.workers)
    if not findings:
        print(f"{C.GRN}no takeover fingerprints matched{C.R}")
        return 0
    for f in findings:
        print(f"{C.MAG}{f.host}{C.R} -> {f.cname} [{f.service}] status={f.status} marker={f.marker!r}")
    if args.json:
        write_json(args.json, [f.row() for f in findings])
        log(f"json -> {args.json}", "ok")
    return 0


def cmd_sources(_args: argparse.Namespace) -> int:
    for name in sources.DEEP_SOURCES:
        print(f"  {name:<16} {sources.SOURCES[name].__doc__ or ''}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="iph4cksec",
        description="Keyless origin IP discovery + attack-surface intelligence\n\n"
                    "Uso directo:  python3 iph4cksec.py dominio.com\n"
                    "autor: h4cksec",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--debug", action="store_true")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--stealth", action="store_true")
    p.add_argument("--no-color", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("hunt", help="find origin IP behind Cloudflare/CDN")
    h.add_argument("domain")
    depth = h.add_mutually_exclusive_group()
    depth.add_argument("--deep", dest="deep", action="store_true", help="all sources + AXFR + reverse-IP")
    depth.add_argument("--fast", dest="deep", action="store_false", help="fast passive set only")
    h.add_argument("--brute", action="store_true", help="wordlist + permutation DNS brute force")
    h.add_argument("--wordlist", help="custom wordlist path")
    h.add_argument("--sources", help="comma-separated source names")
    h.add_argument("--no-takeover", action="store_true")
    h.add_argument("--workers", type=int, default=24)
    h.add_argument("--timeout", type=float, default=7.0)
    h.add_argument("--top", type=int, default=25)
    h.add_argument("--json", help="write JSON report")
    h.add_argument("--csv", help="write CSV report")
    h.set_defaults(func=cmd_hunt, deep=True)

    i = sub.add_parser("intel", help="IP/domain intelligence")
    i.add_argument("target")
    i.add_argument("--json")
    i.set_defaults(func=cmd_intel)

    a = sub.add_parser("asn", help="ASN prefixes + sampled hostnames")
    a.add_argument("asn")
    a.add_argument("--hosts", action="store_true")
    a.add_argument("--limit", type=int, default=40)
    a.add_argument("--json")
    a.set_defaults(func=cmd_asn)

    t = sub.add_parser("takeover", help="subdomain takeover scan")
    t.add_argument("domain", nargs="?")
    t.add_argument("--file")
    t.add_argument("--workers", type=int, default=24)
    t.add_argument("--json")
    t.set_defaults(func=cmd_takeover)

    s = sub.add_parser("sources", help="list passive sources")
    s.set_defaults(func=cmd_sources)
    return p


COMMANDS = {"hunt", "intel", "asn", "takeover", "sources"}


def normalize_argv(argv: list[str]) -> list[str]:
    """Allow `iph4cksec dominio.com` as shorthand for `iph4cksec hunt dominio.com`."""
    if argv and argv[0] not in COMMANDS and not argv[0].startswith("-"):
        return ["hunt"] + argv
    return argv


def main() -> int:
    if len(sys.argv) == 1:
        colorize(sys.stdout.isatty())
        print(BANNER)
        build_parser().print_help()
        return 0
    args = build_parser().parse_args(normalize_argv(sys.argv[1:]))
    colorize(not args.no_color)
    State.debug = args.debug
    State.quiet = args.quiet
    State.stealth = args.stealth
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001
        log(f"fatal: {exc}", "err")
        if args.debug:
            raise
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
