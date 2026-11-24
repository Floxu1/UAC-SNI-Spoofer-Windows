"""Stage 0 - endpoint quality pre-scan (اسکن اولیه IP).

Per sampled Cloudflare edge IP, a plain (no spoofing) measurement repeated
``repeats`` times: TCP 443 connect latency, then TLS handshake + a small
``GET /cdn-cgi/trace``. Same direct TLS path as ``LiveScorer.probe_direct``;
no new DPI primitives. Concurrency is bounded, total bytes respect a budget
derived from the lab traffic cap, and progress is saved to data/edges.json so
an interrupted scan resumes.
"""
from __future__ import annotations

import random
import socket
import ssl
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .edges import (
    DEFAULT_KEEP,
    DEFAULT_SAMPLE_SIZE,
    EdgeCache,
    EdgeResult,
    edge_sources,
    pool_ips,
    resolve_edge_pool,
    sample_ips,
    scan_ranges,
    select_diverse,
    subnet24,
)
from .live_probe import HTTP_PROBE_PATH, classify_failure

LogFn = Callable[[str], None]
ProgressFn = Callable[[int, int, "EdgeResult | None"], None]

# Rough on-wire cost: TLS handshake with CF cert chain + trace response.
TLS_PROBE_BYTES = 6500
TCP_ONLY_BYTES = 300


@dataclass
class EdgeScanConfig:
    sample_size: int = DEFAULT_SAMPLE_SIZE
    keep: int = DEFAULT_KEEP
    repeats: int = 2
    concurrency: int = 12
    connect_timeout_s: float = 2.0
    tls_timeout_s: float = 3.0
    host: str = "www.cloudflare.com"
    http_path: str = HTTP_PROBE_PATH
    budget_bytes: int = 15 * 1024 * 1024
    min_success: float = 0.5
    uac_root: str = ""
    seed: int = 1337
    network_id: str = ""
    save_every: int = 10


def probe_once(ip: str, host: str, connect_timeout: float, tls_timeout: float,
               path: str = HTTP_PROBE_PATH) -> dict:
    """One TCP + TLS + /cdn-cgi/trace round. Returns a small dict."""
    out = {"tcp_ok": False, "tls_ok": False, "tcp_ms": 0.0, "tls_ms": 0.0,
           "bytes": 0, "error": "", "colo": ""}
    started = time.perf_counter()
    try:
        raw = socket.create_connection((ip, 443), timeout=connect_timeout)
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"tcp {classify_failure(exc) or 'other'}: {type(exc).__name__}"
        out["bytes"] = 120
        return out
    out["tcp_ok"] = True
    out["tcp_ms"] = (time.perf_counter() - started) * 1000
    out["bytes"] = TCP_ONLY_BYTES
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        raw.settimeout(tls_timeout)
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            raw = None
            request = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: GeneLab/1.0\r\n"
                       "Accept: */*\r\nConnection: close\r\n\r\n").encode("ascii", "ignore")
            tls.sendall(request)
            body = b""
            deadline = time.monotonic() + tls_timeout
            while time.monotonic() < deadline and len(body) < 4096:
                try:
                    piece = tls.recv(2048)
                except socket.timeout:
                    break
                if not piece:
                    break
                body += piece
                if b"colo=" in body and b"\n" in body.split(b"colo=", 1)[1]:
                    break
            out["bytes"] = TLS_PROBE_BYTES + len(body)
            if b"HTTP/" in body or b"fl=" in body:
                out["tls_ok"] = True
                out["tls_ms"] = (time.perf_counter() - started) * 1000
                if b"colo=" in body:
                    out["colo"] = body.split(b"colo=", 1)[1].split(b"\n", 1)[0].decode(
                        "ascii", "ignore").strip()[:8]
            else:
                out["error"] = "tls ok, no http body"
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"tls {classify_failure(exc) or 'other'}: {type(exc).__name__}"
        out["bytes"] = max(out["bytes"], 2500)
    finally:
        if raw is not None:
            try:
                raw.close()
            except OSError:
                pass
    return out


ProbeFn = Callable[[str, str, float, float, str], dict]


class EdgeScanner:
    def __init__(self, config: EdgeScanConfig | None = None, cache_path: str | Path = "data/edges.json",
                 log: LogFn | None = None, progress: ProgressFn | None = None,
                 probe: ProbeFn | None = None) -> None:
        self.config = config or EdgeScanConfig()
        self.cache = EdgeCache(cache_path)
        self.log = log or (lambda _m: None)
        self.progress = progress or (lambda _d, _t, _r: None)
        self.probe = probe or probe_once
        self._stop = threading.Event()
        self.traffic_bytes = 0
        self.session_bytes = 0  # bytes spent by this process (excludes resumed results)

    def request_stop(self) -> None:
        self._stop.set()

    def _params(self) -> dict:
        c = self.config
        return {"sample_size": int(c.sample_size), "keep": int(c.keep), "repeats": int(c.repeats),
                "host": c.host, "seed": int(c.seed)}

    def cached_pool(self, now: float | None = None) -> list[str]:
        return self.cache.fresh_pool(now, network_id=self.config.network_id)

    def measure(self, ip: str) -> EdgeResult:
        c = self.config
        result = EdgeResult(ip=ip, tested_at=time.time())
        for _ in range(max(1, int(c.repeats))):
            if self._stop.is_set():
                break
            data = self.probe(ip, c.host, c.connect_timeout_s, c.tls_timeout_s, c.http_path)
            result.attempts += 1
            result.traffic_bytes += int(data.get("bytes", 0) or 0)
            if data.get("tcp_ok"):
                result.tcp_ok += 1
                result.tcp_ms.append(float(data.get("tcp_ms", 0.0)))
            if data.get("tls_ok"):
                result.tls_ok += 1
                result.tls_ms.append(float(data.get("tls_ms", 0.0)))
                result.colo = str(data.get("colo", "") or result.colo)
            elif data.get("error"):
                result.last_error = str(data["error"])[:120]
            if not data.get("tcp_ok"):
                break  # unreachable - do not burn repeats
        return result

    def run(self, force: bool = False) -> dict:
        """Scan (or resume / reuse). Returns the edges.json payload."""
        c = self.config
        if not force:
            existing = self.cache.load()
            if self.cache.is_fresh(existing, network_id=c.network_id):
                self.log(f"EDGE SCAN cached pool fresh: {len(existing.get('selected', []))} ips "
                         f"({self.cache.path})")
                return existing
        seeds = edge_sources(c.uac_root)
        ranges = scan_ranges(seeds)
        params = self._params()
        previous = self.cache.load()
        results: dict[str, EdgeResult] = {}
        if (previous and not previous.get("complete") and previous.get("params") == params
                and previous.get("sample")):
            sample = [str(x) for x in previous["sample"]]
            for ip, raw in dict(previous.get("results") or {}).items():
                if isinstance(raw, dict):
                    results[ip] = EdgeResult.from_dict(raw)
            self.log(f"EDGE SCAN resume: {len(results)}/{len(sample)} already measured")
        else:
            sample = sample_ips(ranges, c.sample_size, seeds, random.Random(c.seed))
        self.traffic_bytes = sum(r.traffic_bytes for r in results.values())
        resumed_bytes = self.traffic_bytes
        payload = {
            "complete": False, "started_at": time.time(), "network_id": c.network_id,
            "params": params, "source": {"edges": seeds, "ranges": ranges},
            "sample": sample,
        }
        self.log(f"EDGE SCAN start: {len(sample)} ips from {len(ranges)} /24 ranges "
                 f"({len(seeds)} UAC edges) repeats={c.repeats} conc={c.concurrency} "
                 f"budget={c.budget_bytes // 1024} KB")
        todo = [ip for ip in sample if ip not in results]
        total = len(sample)
        done = total - len(todo)
        self.progress(done, total, None)
        lock = threading.Lock()
        since_save = 0

        def snapshot(complete: bool) -> dict:
            selected = select_diverse(results.values(), c.keep, c.min_success)
            data = dict(payload)
            data["results"] = {ip: r.to_dict() for ip, r in results.items()}
            data["selected"] = [
                {"ip": r.ip, "score": r.score, "success_rate": round(r.success_rate, 3),
                 "tcp_ms": round(r.median_tcp_ms, 1), "tls_ms": round(r.median_ms, 1),
                 "jitter_ms": round(r.jitter_ms, 1), "subnet": subnet24(r.ip), "colo": r.colo}
                for r in selected
            ]
            data["complete"] = complete
            data["traffic_bytes"] = self.traffic_bytes
            if complete:
                data["finished_at"] = time.time()
            return data

        workers = max(1, min(32, int(c.concurrency)))
        budget_hit = False
        with ThreadPoolExecutor(max_workers=workers) as pool:
            pending = set()
            queue = list(todo)
            while (queue or pending) and not self._stop.is_set():
                while queue and len(pending) < workers and not self._stop.is_set():
                    if self.traffic_bytes >= c.budget_bytes:
                        budget_hit = True
                        queue.clear()
                        break
                    pending.add(pool.submit(self.measure, queue.pop(0)))
                if not pending:
                    break
                finished, pending = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)
                for fut in finished:
                    res = fut.result()
                    with lock:
                        results[res.ip] = res
                        self.traffic_bytes += res.traffic_bytes
                        done += 1
                        since_save += 1
                    self.progress(done, total, res)
                    if since_save >= max(1, int(c.save_every)):
                        since_save = 0
                        self.cache.save(snapshot(False))
        stopped = self._stop.is_set()
        if budget_hit:
            self.log(f"EDGE SCAN traffic budget reached after {done}/{total} ips")
        self.session_bytes = max(0, self.traffic_bytes - resumed_bytes)
        complete = not stopped
        final = snapshot(complete)
        self.cache.save(final)
        ok = sum(1 for r in results.values() if r.tls_ok)
        self.log(f"EDGE SCAN {'done' if complete else 'stopped (resumable)'}: measured={len(results)} "
                 f"tls_ok={ok} selected={len(final['selected'])} "
                 f"traffic={self.traffic_bytes / 1024:.0f} KB")
        for index, item in enumerate(final["selected"], 1):
            self.log(f"  EDGE #{index:02d} {item['ip']:<15} score={item['score']:.3f} "
                     f"ok={item['success_rate']:.0%} tls={item['tls_ms']:.0f}ms "
                     f"tcp={item['tcp_ms']:.0f}ms jit={item['jitter_ms']:.0f}ms {item['subnet']}")
        return final


def selected_pool(payload: dict) -> list[str]:
    return pool_ips(payload.get("selected", []) if payload else [])


# Stage 0 may use at most this share of the lab traffic cap.
EDGE_SCAN_CAP_SHARE = 0.30


def edge_scan_budget(traffic_cap_mb: float) -> int:
    return int(max(1.0, float(traffic_cap_mb or 50.0)) * 1024 * 1024 * EDGE_SCAN_CAP_SHARE)


def stage0_pool(scanner: EdgeScanner, fallback, min_size: int, *, use_cache: bool,
                force: bool, log) -> tuple[list[str], int]:
    """Run / reuse Stage 0 and return (edge list for genes, bytes spent)."""
    pool: list[str] = []
    spent = 0
    if use_cache and not force:
        pool = scanner.cached_pool()
        if pool:
            log(f"STAGE0 cached edge pool ({len(pool)} ips, <6h) - skipping scan")
    if not pool:
        log("STAGE0 اسکن اولیه IP / edge pre-scan starting")
        payload = scanner.run(force=True)
        spent = int(scanner.session_bytes)
        pool = [str(x.get("ip")) for x in payload.get("selected", []) if x.get("ip")]
    edges = resolve_edge_pool(pool, list(fallback or ()), min_size, log=log)
    if edges and edges[: len(pool)] == pool and len(pool) >= min_size:
        log(f"STAGE0 gene evaluation uses edge pool: {len(edges)} ips "
            f"(first: {', '.join(edges[:5])})")
    return edges, spent
