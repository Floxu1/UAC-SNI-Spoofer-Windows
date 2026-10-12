"""ECH key (ECHConfigList) fetch + per-domain cache.

The URI form ``ech=cloudflare-ech.com+udp://1.1.1.1`` makes Xray fetch the
key itself on every dial (slow, one resolver, no fallback). We fetch the DNS
HTTPS record (type 65) ourselves from several resolvers in parallel, cache it
per ECH domain in ech_keys.json and hand Xray the raw base64 list.
"""
from __future__ import annotations

import base64
import concurrent.futures
import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Callable, Iterable

UDP_RESOLVERS = ("1.1.1.1", "1.0.0.1", "8.8.8.8", "9.9.9.9")
DOH_RESOLVERS = ("https://1.1.1.1/dns-query", "https://dns.google/dns-query")
FETCH_TIMEOUT = 2.0
_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_LOCK = threading.Lock()


def parse_ech_value(value: str) -> tuple[str, str]:
    """('cloudflare-ech.com', 'udp://1.1.1.1') for the domain+server form,
    ('', '') for a raw base64 list or an empty value."""
    value = str(value or "").strip()
    if not value or is_base64_list(value):
        return "", ""
    domain, _sep, server = value.partition("+")
    domain = domain.strip().strip(".").lower()
    if not domain or "." not in domain:
        return "", ""
    return domain, server.strip()


def is_base64_list(value: str) -> bool:
    value = str(value or "").strip()
    if len(value) < 16 or "." in value or "+" in value and "://" in value:
        return False
    if not _B64_RE.match(value):
        return False
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        return False
    return len(raw) >= 4 and int.from_bytes(raw[:2], "big") == len(raw) - 2


def _ech_from_answer(answer) -> str:
    for rrset in getattr(answer, "answer", []) or []:
        for item in rrset:
            params = getattr(item, "params", None) or {}
            ech = params.get(5)
            if ech is not None:
                data = getattr(ech, "ech", None)
                if data:
                    return base64.b64encode(bytes(data)).decode("ascii")
    return ""


def _query_udp(domain: str, server: str, timeout: float) -> str:
    import dns.message
    import dns.query
    message = dns.message.make_query(domain, "HTTPS")
    return _ech_from_answer(dns.query.udp(message, server, timeout=timeout))


def system_nameservers() -> list:
    """IPv4 DNS servers configured on this machine (Windows registry; no WMI/COM)."""
    servers = []
    try:
        import winreg
        base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as root:
            for index in range(winreg.QueryInfoKey(root)[0]):
                try:
                    with winreg.OpenKey(root, winreg.EnumKey(root, index)) as key:
                        for name in ("NameServer", "DhcpNameServer"):
                            try:
                                value = winreg.QueryValueEx(key, name)[0]
                            except OSError:
                                continue
                            for item in re.split(r"[ ,]+", str(value or "")):
                                if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", item) and item not in servers:
                                    servers.append(item)
                except OSError:
                    continue
    except Exception:
        pass
    return [s for s in servers if s not in UDP_RESOLVERS][:3]


def _query_system(domain: str, timeout: float) -> str:
    servers = system_nameservers()
    if not servers:
        return ""
    return race([(s, (lambda s=s: _query_udp(domain, s, timeout))) for s in servers], timeout)[0]


def _query_doh(domain: str, url: str, timeout: float) -> str:
    import dns.message
    import dns.query
    message = dns.message.make_query(domain, "HTTPS")
    return _ech_from_answer(dns.query.https(message, url, timeout=timeout))


def default_fetchers(domain: str, hint: str = "", timeout: float = FETCH_TIMEOUT):
    """[(label, callable)] - URI hint first, then the fixed fallbacks."""
    servers = list(UDP_RESOLVERS)
    hinted = re.match(r"^(?:udp://)?(\d{1,3}(?:\.\d{1,3}){3})(?::53)?$", str(hint or ""))
    if hinted and hinted.group(1) in servers:
        servers.remove(hinted.group(1))
    if hinted:
        servers.insert(0, hinted.group(1))
    return [(f"udp {s}", (lambda s=s: _query_udp(domain, s, timeout))) for s in servers]


def doh_fetchers(domain: str, timeout: float = 3.0):
    """Second stage: system resolver, then DoH (DoH is often blocked on MCI)."""
    return [("system", lambda: _query_system(domain, timeout))] + [(f"doh {u.split('/')[2]}", (lambda u=u: _query_doh(domain, u, timeout))) for u in DOH_RESOLVERS]


def race(fetchers: Iterable, deadline: float = 3.0) -> tuple[str, str]:
    """First non-empty result wins -> (key, label). ('', '') if all fail."""
    fetchers = list(fetchers)
    if not fetchers:
        return "", ""
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=len(fetchers), thread_name_prefix="ech-key")
    try:
        futures = {pool.submit(fn): label for label, fn in fetchers}
        end = time.monotonic() + deadline
        pending = set(futures)
        while pending:
            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            done, pending = concurrent.futures.wait(
                pending, timeout=remaining, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                try:
                    key = future.result()
                except Exception:
                    key = ""
                if key and is_base64_list(key):
                    return key, futures[future]
        return "", ""
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


class EchKeyCache:
    def __init__(self, path: Path | str):
        self.path = Path(path)

    def _load(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def get(self, domain: str) -> dict:
        entry = self._load().get(str(domain).lower())
        return entry if isinstance(entry, dict) and is_base64_list(entry.get("key", "")) else {}

    def put(self, domain: str, key: str, source: str, now: float | None = None) -> None:
        with _LOCK:
            data = self._load()
            data[str(domain).lower()] = {"key": key, "fetched_at": float(now or time.time()), "source": source}
            tmp = self.path.with_suffix(".tmp")
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
                os.replace(tmp, self.path)
            except OSError:
                pass


def format_age(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    if seconds < 3600:
        return f"{int(seconds // 60)}m"
    if seconds < 86400 * 2:
        return f"{seconds / 3600:.0f}h"
    return f"{seconds / 86400:.0f}d"


class EchResolution:
    __slots__ = ("value", "state", "source", "age", "domain")

    def __init__(self, value, state, source="", age=0.0, domain=""):
        self.value = value          # what Xray gets in echConfigList
        self.state = state          # fresh | cached | raw | none
        self.source = source
        self.age = age
        self.domain = domain


def resolve(ech_value: str, cache: EchKeyCache, log: Callable[[str], None] | None = None,
            fetchers=None, doh=None, deadline: float = 3.0, now: float | None = None) -> EchResolution:
    """Fresh key (parallel DNS race, DoH last) -> cached key -> original value. Never raises."""
    log = log or (lambda _m: None)
    value = str(ech_value or "").strip()
    if not value:
        return EchResolution("", "none")
    if is_base64_list(value):
        return EchResolution(value, "raw", "uri")
    domain, hint = parse_ech_value(value)
    if not domain:
        return EchResolution(value, "raw", "uri")
    now = float(now or time.time())
    try:
        key, label = race(fetchers if fetchers is not None else default_fetchers(domain, hint), deadline)
        if not key:
            key, label = race(doh if doh is not None else doh_fetchers(domain), deadline)
    except Exception as exc:
        key, label = "", ""
        log(f"ECH KEY: fetch error {type(exc).__name__}: {exc}")
    if key:
        cache.put(domain, key, label, now)
        log(f"ECH KEY: fetched via {label} (age 0m) for {domain}")
        return EchResolution(key, "fresh", label, 0.0, domain)
    entry = cache.get(domain)
    if entry:
        age = now - float(entry.get("fetched_at", now))
        log(f"ECH KEY: fetch failed (all resolvers); using cached (age {format_age(age)}) for {domain}")
        return EchResolution(entry["key"], "cached", entry.get("source", ""), age, domain)
    log(f"ECH KEY: fetch failed and no cache for {domain}; letting Xray resolve {value}")
    return EchResolution(value, "none", "", 0.0, domain)

