"""Subdomain takeover detection from dangling CNAMEs, keyless."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import dnsx
from .util import fetch

# (service, cname suffix, body markers)
FINGERPRINTS: list[tuple[str, tuple[str, ...], tuple[str, ...]]] = [
    ("github-pages", ("github.io",), (
        "there isn't a github pages site here", "for root urls (like http://example.com)")),
    ("heroku", ("herokuapp.com", "herokussl.com"), (
        "no such app", "there is no app configured at that hostname",
        "heroku | no such app")),
    ("aws-s3", ("s3.amazonaws.com", "s3-website", "amazonaws.com"), (
        "nosuchbucket", "the specified bucket does not exist",
        "no such bucket")),
    ("azure", ("azurewebsites.net", "cloudapp.azure.com", "trafficmanager.net"), (
        "404 web site not found", "this web app is stopped", "error 404 - web app not found")),
    ("cloudfront", ("cloudfront.net",), (
        "the request could not be satisfied", "bad request")),
    ("fastly", ("fastly.net", "fastlylb.net"), (
        "fastly error: unknown domain", "unknown domain")),
    ("netlify", ("netlify.app", "netlify.com"), (
        "not found - request id", "page not found")),
    ("vercel", ("vercel.app", "now.sh"), (
        "the deployment could not be found", "deployment_not_found")),
    ("cloudflare-pages", ("pages.dev",), (
        "project not found", "could not find the requested project")),
    ("surge", ("surge.sh",), ("project not found", "surge.sh")),
    ("bitbucket", ("bitbucket.io",), ("repository not found",)),
    ("readme", ("readme.io",), ("project doesnt exist", "project doesn't exist")),
    ("zendesk", ("zendesk.com",), ("help center closed", "this help center no longer exists")),
    ("statuspage", ("statuspage.io",), ("status page not found", "you are not authorized")),
    ("ghost", ("ghost.io",), ("the thing you were looking for is no longer here",)),
    ("webflow", ("webflow.io",), ("this site is not published", "page not found")),
    ("shopify", ("myshopify.com",), ("sorry, this shop is currently unavailable",)),
    ("unbounce", ("unbounce.com", "unbouncepages.com"), ("page not found",)),
    ("tumblr", ("tumblr.com",), ("there's nothing here", "whatever you were looking for")),
    ("wordpress", ("wordpress.com",), ("doesn’t exist", "does not exist")),
    ("wpengine", ("wpengine.com", "wpenginepowered.com"), ("site not found",)),
    ("pantheon", ("pantheonsite.io",), ("404 unknown site", "site not found")),
    ("uservoice", ("uservoice.com",), ("this uservoice subdomain is no longer available",)),
    ("freshdesk", ("freshdesk.com",), ("this helpdesk is no longer available",)),
    ("helpscout", ("helpscoutdocs.com",), ("no settings were found",)),
    ("intercom", ("intercom.help",), ("this page is reserved",)),
    ("jetbrains-space", ("jetbrains.space",), ("space not found",)),
    ("glitch", ("glitch.me",), ("looks like this project is gone",)),
    ("render", ("onrender.com",), ("not found",)),
    ("fly", ("fly.dev",), ("could not find app",)),
    ("railway", ("railway.app",), ("application not found",)),
    ("northflank", ("northflank.app",), ("not found",)),
    ("cargo", ("cargocollective.com",), ("404 not found",)),
    ("kinsta", ("kinsta.cloud",), ("site not found",)),
    ("launchrock", ("launchrock.com",), ("this launchrock page is no longer active",)),
    ("smugmug", ("smugmug.com",), ("page not found",)),
    ("strikingly", ("strikingly.com",), ("page not found",)),
    ("simplebooklet", ("simplebooklet.com",), ("page not found",)),
    ("smartjobboard", ("smartjobboard.com",), ("not found",)),
    ("teamwork", ("teamwork.com",), ("not found",)),
    ("pingdom", ("pingdom.com",), ("not found",)),
    ("tictail", ("tictail.com",), ("not found",)),
]

SERVICES = {name: (suffixes, markers) for name, suffixes, markers in FINGERPRINTS}


@dataclass
class Finding:
    host: str
    cname: str
    service: str
    status: int
    marker: str

    def row(self) -> dict[str, Any]:
        return {"host": self.host, "cname": self.cname, "service": self.service,
                "status": self.status, "marker": self.marker}


def _match_service(cname: str) -> tuple[str, tuple[str, ...]] | None:
    low = cname.lower().rstrip(".")
    for name, suffixes, markers in FINGERPRINTS:
        if any(low.endswith(sfx) or f".{sfx}" in low for sfx in suffixes):
            return name, markers
    return None


def check_host(host: str, timeout: float = 10.0) -> Finding | None:
    chain = dnsx.cname_chain(host)
    if not chain:
        return None
    cname = chain[-1]
    match = _match_service(cname)
    if not match:
        return None
    service, markers = match
    for scheme in ("https", "http"):
        r = fetch(f"{scheme}://{host}/", timeout=timeout, allow_redirects=True)
        if r is None:
            continue
        body = (r.text or "")[:120_000].lower()
        for marker in markers:
            if marker in body:
                return Finding(host=host, cname=cname, service=service,
                               status=r.status_code, marker=marker)
        if r.status_code in (404, 410) and service in ("render", "northflank"):
            return Finding(host=host, cname=cname, service=service,
                           status=r.status_code, marker=f"http {r.status_code}")
    return None


def scan(hosts: list[str], workers: int = 20) -> list[Finding]:
    from .util import run_parallel

    results = run_parallel(lambda h: check_host(h), hosts, workers)
    return sorted((f for f in results.values() if f is not None), key=lambda f: f.host)
