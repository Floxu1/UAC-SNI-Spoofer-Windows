"""Automatic clean Cloudflare edge IP finder for engine 1 (Xray/pattern core).

Pure Python (no Qt). Stage 1 re-tests cached good IPs for the carrier, stage 2
samples Cloudflare ranges. A probe is a TCP connect to :443 followed by a real
TLS ClientHello carrying the configured fake SNI; only a completed handshake
(the edge answered with a real ServerHello) counts as success.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import os
import random
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

CLOUDFLARE_RANGES = (
    "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "162.159.0.0/16",
    "188.114.96.0/20", "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20",
    "198.41.128.0/17", "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "197.234.240.0/22", "131.0.72.0/22",
)
FAILS_BEFORE_COOLDOWN = 3
COOLDOWN_SECONDS = 30 * 60
MAX_CACHE_PER_CARRIER = 60
SETTING_KEY = "auto_clean_ip"


def valid_ipv4(value) -> str:
    try:
        return str(ipaddress.IPv4Address(str(value or "").strip()))
    except (ipaddress.AddressValueError, ValueError):
        return ""


def split_ips(value) -> list:
    if isinstance(value, (list, tuple)):
        items = value
    else:
        items = str(value or "").replace(";", ",").split(",")
    return [ip for ip in (valid_ipv4(v) for v in items) if ip]


def order_edges(gene_edges="", clean_edges="", rest: Iterable = (), session_edge="") -> list:
    """Final edge order: the session-preferred IP (Full scan 'Use this IP'),
    then gene edges (only when a gene is used), then clean IPs, then the
    normal list. Deduplicated, order kept."""
    raw = [*split_ips(session_edge), *split_ips(gene_edges), *split_ips(clean_edges), *split_ips(list(rest))]
    return list(dict.fromkeys(raw))


@dataclass
class ProbeResult:
    ip: str
    ok: bool
    latency_ms: float = 0.0
    error: str = ""
    source: str = "scan"


def probe_ip(ip: str, fake_sni: str, port: int = 443, timeout: float = 2.0) -> ProbeResult:
    """TCP connect + TLS handshake with the fake SNI. Never raises."""
    started = time.perf_counter()
    sock = None
    try:
        sock = socket.create_connection((ip, int(port)), timeout=timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(["http/1.1"])
        except Exception:
            pass
        sock.settimeout(timeout)
        tls = ctx.wrap_socket(sock, server_hostname=(fake_sni or None), do_handshake_on_connect=False)
        sock = tls
        tls.do_handshake()
        return ProbeResult(ip, True, (time.perf_counter() - started) * 1000.0)
    except Exception as exc:  # timeout, reset, TLS alert ...
        return ProbeResult(ip, False, (time.perf_counter() - started) * 1000.0,
                           type(exc).__name__)
    finally:
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass


def sample_cloudflare(count: int, rng: random.Random | None = None, exclude: Iterable = ()) -> list:
    rng = rng or random.Random()
    nets = [ipaddress.IPv4Network(n) for n in CLOUDFLARE_RANGES]
    weights = [n.num_addresses for n in nets]
    skip = set(exclude)
    out: list = []
    guard = 0
    while len(out) < count and guard < count * 20:
        guard += 1
        net = rng.choices(nets, weights=weights)[0]
        host = net.network_address + rng.randrange(1, net.num_addresses - 1)
        ip = str(host)
        if ip.endswith(".0") or ip.endswith(".255") or ip in skip or ip in out:
            continue
        out.append(ip)
    return out


class CleanIpCache:
    """Per-carrier cache of probed edges. Thread-safe; atomic file writes."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._data: dict = {}
        self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            self._data = raw if isinstance(raw, dict) else {}
        except Exception:
            self._data = {}

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._data, indent=1, sort_keys=True), encoding="utf-8")
            os.replace(tmp, self.path)
        except Exception:
            pass

    def _bucket(self, carrier: str) -> dict:
        key = str(carrier or "auto").lower()
        bucket = self._data.get(key)
        if not isinstance(bucket, dict):
            bucket = {}
            self._data[key] = bucket
        return bucket

    def record(self, carrier: str, ip: str, ok: bool, latency_ms: float = 0.0,
               now: float | None = None, save: bool = True) -> None:
        ip = valid_ipv4(ip)
        if not ip:
            return
        now = time.time() if now is None else float(now)
        with self._lock:
            bucket = self._bucket(carrier)
            entry = bucket.get(ip) if isinstance(bucket.get(ip), dict) else {}
            entry.setdefault("ok", 0); entry.setdefault("fail", 0); entry.setdefault("streak_fail", 0)
            if ok:
                entry["ok"] = int(entry["ok"]) + 1
                entry["streak_fail"] = 0
                entry["last_ok"] = now
                entry["cool_until"] = 0
                old = float(entry.get("latency_ms", 0) or 0)
                entry["latency_ms"] = round(latency_ms if old <= 0 else old * 0.6 + latency_ms * 0.4, 1)
            else:
                entry["fail"] = int(entry["fail"]) + 1
                entry["streak_fail"] = int(entry["streak_fail"]) + 1
                if entry["streak_fail"] >= FAILS_BEFORE_COOLDOWN:
                    entry["cool_until"] = now + COOLDOWN_SECONDS
            bucket[ip] = entry
            if len(bucket) > MAX_CACHE_PER_CARRIER:
                ranked = rank_entries(bucket, now, include_cooled=True)
                keep = set(ranked[:MAX_CACHE_PER_CARRIER])
                for key in list(bucket):
                    if key not in keep:
                        bucket.pop(key, None)
            if save:
                self._save()

    def flush(self) -> None:
        with self._lock:
            self._save()

    def entries(self, carrier: str) -> dict:
        with self._lock:
            return json.loads(json.dumps(self._bucket(carrier)))

    def good_ips(self, carrier: str, now: float | None = None, limit: int = 10) -> list:
        now = time.time() if now is None else float(now)
        with self._lock:
            bucket = self._bucket(carrier)
            ranked = rank_entries({k: v for k, v in bucket.items() if int(v.get("ok", 0)) > 0}, now)
            return ranked[:limit]

    def is_cooled(self, carrier: str, ip: str, now: float | None = None) -> bool:
        now = time.time() if now is None else float(now)
        with self._lock:
            entry = self._bucket(carrier).get(ip) or {}
            return float(entry.get("cool_until", 0) or 0) > now


def entry_score(entry: dict) -> float:
    """Lower is better: latency penalised by failure ratio."""
    ok = int(entry.get("ok", 0) or 0); fail = int(entry.get("fail", 0) or 0)
    total = ok + fail
    ratio = ok / total if total else 0.0
    latency = float(entry.get("latency_ms", 0) or 0) or 5000.0
    return latency * (1.0 + 2.0 * (1.0 - ratio)) + 300.0 * int(entry.get("streak_fail", 0) or 0)


def rank_entries(bucket: dict, now: float, include_cooled: bool = False) -> list:
    items = []
    for ip, entry in bucket.items():
        if not isinstance(entry, dict):
            continue
        if not include_cooled and float(entry.get("cool_until", 0) or 0) > now:
            continue
        items.append((entry_score(entry), ip))
    items.sort()
    return [ip for _score, ip in items]


def rank_results(results: Iterable[ProbeResult], top: int = 3) -> list:
    good = sorted((r for r in results if r.ok), key=lambda r: r.latency_ms)
    return good[:top]


def scan(ips: list, fake_sni: str, *, workers: int = 50, deadline: float = 5.0,
         timeout: float = 2.0, cancel: threading.Event | None = None,
         on_result: Callable[[ProbeResult], None] | None = None,
         stop_when: Callable[[list], bool] | None = None,
         source: str = "scan", probe: Callable = probe_ip) -> list:
    """Probe ips concurrently; returns all finished results. Never raises."""
    results: list = []
    if not ips:
        return results
    started = time.monotonic()
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(workers, len(ips))),
                                                 thread_name_prefix="clean-ip")
    try:
        futures = [pool.submit(probe, ip, fake_sni, 443, timeout) for ip in ips]
        pending = set(futures)
        while pending:
            if cancel is not None and cancel.is_set():
                break
            remaining = deadline - (time.monotonic() - started)
            if remaining <= 0:
                break
            done, pending = concurrent.futures.wait(
                pending, timeout=min(0.2, remaining),
                return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                try:
                    result = future.result()
                except Exception as exc:
                    continue
                result.source = source
                results.append(result)
                if on_result is not None:
                    try:
                        on_result(result)
                    except Exception:
                        pass
            if stop_when is not None and stop_when(results):
                break
    except Exception:
        pass
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return results


def _early_stop(started: float, want: int = 3, early_after: float = 1.5):
    def check(results: list) -> bool:
        good = sum(1 for r in results if r.ok)
        return good >= want or (good >= 1 and time.monotonic() - started >= early_after)
    return check


def find_clean_ips(cache: CleanIpCache, carrier: str, fake_sni: str, seeds: Iterable = (),
                   *, sample: int = 150, workers: int = 50, budget: float = 5.0, top: int = 3,
                   cancel: threading.Event | None = None, log: Callable[[str], None] | None = None,
                   probe: Callable = probe_ip, rng: random.Random | None = None) -> list:
    """Return up to `top` ProbeResults (source 'cache' or 'scan'). Never raises."""
    log = log or (lambda _m: None)
    try:
        started = time.monotonic()
        now = time.time()
        cached = [ip for ip in cache.good_ips(carrier, now, limit=8)]
        if cached:
            res = scan(cached, fake_sni, workers=len(cached), deadline=min(2.5, budget),
                       cancel=cancel, source="cache", probe=probe,
                       stop_when=_early_stop(started, top, 1.0))
            for r in res:
                cache.record(carrier, r.ip, r.ok, r.latency_ms, save=False)
            cache.flush()
            good = rank_results(res, top)
            if good:
                return good
        remaining = budget - (time.monotonic() - started)
        if remaining <= 0.3 or (cancel is not None and cancel.is_set()):
            return []
        seed_ips = [ip for ip in split_ips(list(seeds)) if not cache.is_cooled(carrier, ip, now)]
        pool = list(dict.fromkeys(seed_ips + sample_cloudflare(
            sample, rng, exclude=[*cached, *seed_ips])))
        pool = [ip for ip in pool if not cache.is_cooled(carrier, ip, now)]
        res = scan(pool, fake_sni, workers=workers, deadline=remaining, cancel=cancel,
                   source="scan", probe=probe, stop_when=_early_stop(time.monotonic(), top, 1.5))
        for r in res:
            if r.ok or r.ip in seed_ips or r.ip in cached:
                cache.record(carrier, r.ip, r.ok, r.latency_ms, save=False)
        cache.flush()
        return rank_results(res, top)
    except Exception as exc:
        log(f"CLEAN IP: scanner error {type(exc).__name__}: {exc}; using normal edges")
        return []


class BackgroundRefresher:
    """Light periodic refresh while connected. Skips the active edges, since
    the pattern core intercepts traffic to those."""

    def __init__(self, cache: CleanIpCache, carrier: str, fake_sni: str,
                 active_edges: Iterable = (), interval: float = 240.0, sample: int = 15,
                 log: Callable[[str], None] | None = None,
                 alive: Callable[[], bool] | None = None):
        self.alive = alive
        self.cache = cache; self.carrier = carrier; self.fake_sni = fake_sni
        self.active = set(split_ips(list(active_edges)))
        self.interval = float(interval); self.sample = int(sample)
        self.log = log or (lambda _m: None)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="clean-ip-refresh", daemon=True)

    def start(self) -> "BackgroundRefresher":
        self._thread.start(); return self

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                if self.alive is not None and not self.alive():
                    break
                cached = [ip for ip in self.cache.good_ips(self.carrier, limit=6) if ip not in self.active]
                ips = cached + sample_cloudflare(self.sample, exclude=[*cached, *self.active])
                res = scan(ips, self.fake_sni, workers=10, deadline=6.0, cancel=self._stop, source="refresh")
                for r in res:
                    if r.ok or r.ip in cached:
                        self.cache.record(self.carrier, r.ip, r.ok, r.latency_ms, save=False)
                self.cache.flush()
                good = sum(1 for r in res if r.ok)
                self.log(f"CLEAN IP: background refresh {good}/{len(res)} ok")
            except Exception:
                pass
