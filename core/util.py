"""Shared utilities: HTTP session, logging, colors, math, parallelism."""
from __future__ import annotations

import hashlib
import json
import random
import re
import sys
import threading
import time
from typing import Any, Callable, Iterable, Sequence

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
]

_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"


class C:
    R = "\033[0m"; B = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GRN = "\033[32m"; YEL = "\033[33m"; BLU = "\033[34m"
    MAG = "\033[35m"; CYA = "\033[36m"; GRY = "\033[90m"; WHT = "\033[97m"
    BLK = "\033[30m"; BG_GRN = "\033[42m"; BG_YEL = "\033[43m"
    BG_CYA = "\033[46m"; BG_RED = "\033[41m"


def colorize(enabled: bool) -> None:
    if enabled:
        return
    for name in ("R", "B", "DIM", "RED", "GRN", "YEL", "BLU", "MAG", "CYA", "GRY", "WHT",
                 "BLK", "BG_GRN", "BG_YEL", "BG_CYA", "BG_RED"):
        setattr(C, name, "")


class State:
    quiet = False
    debug = False
    stealth = False
    _lock = threading.Lock()


def log(msg: str, level: str = "info") -> None:
    if State.quiet and level not in ("err", "ok"):
        return
    tag = {
        "info": f"{C.CYA}[*]{C.R}", "ok": f"{C.GRN}[+]{C.R}",
        "warn": f"{C.YEL}[!]{C.R}", "err": f"{C.RED}[-]{C.R}",
        "dbg": f"{C.GRY}[.]{C.R}", "hit": f"{C.MAG}[>]{C.R}",
    }.get(level, "[*]")
    with State._lock:
        print(f"{tag} {msg}", file=sys.stderr, flush=True)


def dbg(msg: str) -> None:
    if State.debug:
        log(msg, "dbg")


SESSION = requests.Session()
SESSION.headers.update({"User-Agent": random.choice(UA_POOL), "Accept": _ACCEPT})


def fetch(
    url: str,
    timeout: float = 12.0,
    headers: dict[str, str] | None = None,
    method: str = "GET",
    retries: int = 1,
    **kwargs: Any,
) -> requests.Response | None:
    h = {"User-Agent": random.choice(UA_POOL), "Accept": _ACCEPT}
    if headers:
        h.update(headers)
    if State.stealth:
        time.sleep(random.uniform(0.15, 0.45))
    for attempt in range(retries + 1):
        try:
            return SESSION.request(method, url, headers=h, timeout=timeout, verify=False, **kwargs)
        except requests.RequestException:
            if attempt < retries:
                time.sleep(0.4 * (attempt + 1))
    return None


def get_json(url: str, timeout: float = 12.0, headers: dict[str, str] | None = None) -> Any:
    r = fetch(url, timeout=timeout, headers=headers)
    if r is None or not r.ok:
        return None
    try:
        return r.json()
    except ValueError:
        return None


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()


def jaccard(a: set[Any], b: set[Any]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def shingles(tokens: Sequence[str], n: int = 3) -> set[str]:
    if len(tokens) < n:
        return {" ".join(tokens)} if tokens else set()
    return {" ".join(tokens[i:i + n]) for i in range(len(tokens) - n + 1)}


def norm_text(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def run_parallel(fn: Callable[[Any], Any], items: Iterable[Any], workers: int = 30) -> dict[Any, Any]:
    from concurrent.futures import ThreadPoolExecutor, as_completed
    out: dict[Any, Any] = {}
    items = list(items)
    if not items:
        return out
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(items)))) as pool:
        futs = {pool.submit(fn, item): item for item in items}
        for fut in as_completed(futs):
            item = futs[fut]
            try:
                out[item] = fut.result()
            except Exception as exc:  # noqa: BLE001
                dbg(f"task {item!r} failed: {exc}")
                out[item] = None
    return out


def chunks(seq: Sequence[Any], size: int) -> Iterable[Sequence[Any]]:
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def write_json(path: str, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False, default=list)


def write_csv(path: str, rows: list[dict[str, Any]], fields: list[str]) -> None:
    import csv
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow(row)
