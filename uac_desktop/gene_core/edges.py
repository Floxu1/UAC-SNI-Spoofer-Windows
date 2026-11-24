"""Cloudflare edge sources + endpoint-quality pool for Gene Lab (Stage 0).

The candidate ranges are the edge IPs that the UAC Spoofer desktop app already
uses for engine 1 (PatternSniCore / Xray), widened to their /24 so Stage 0 can
find healthy neighbours on the same anycast blocks. Nothing here opens a
socket; network probing lives in ``edge_scan``.

``UAC_BUILTIN_EDGES`` is a synced copy (2026-10-11) of:
  uac_desktop/models.py          DEFAULT_ADDRESS/FALLBACK, Tuning defaults,
                                 Irancell preset, MCI protected edges
  uac_desktop/pattern_core/core.py  UPSTREAM_DEFAULT_IP + fallback defaults
  uac_desktop/verified_configs.py   VERIFIED_SPOOF_EDGE
  uac_desktop/engine.py             MCI_FINALMASK_EDGES
  uac_desktop/fragment_proxy.py     carrier edge lists
``sync_uac_edges()`` re-reads those files when the UAC project is present.
"""
from __future__ import annotations

import ipaddress
import json
import math
import os
import random
import re
import statistics
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

UAC_BUILTIN_EDGES: dict[str, tuple[str, ...]] = {
    "auto": ("104.18.32.47", "172.64.155.209", "188.114.99.0", "104.18.8.83", "104.18.9.83"),
    "irancell": ("104.19.229.21", "104.19.230.21", "104.18.8.83", "104.18.9.83"),
    "mci": ("104.18.1.1", "172.66.0.1", "104.18.8.83", "104.18.9.83"),
}

UAC_EDGE_FILES = (
    "uac_desktop/models.py",
    "uac_desktop/pattern_core/core.py",
    "uac_desktop/verified_configs.py",
    "uac_desktop/engine.py",
    "uac_desktop/fragment_proxy.py",
)

# Cloudflare's published IPv4 blocks - used only as a filter so that private /
# loopback literals in the UAC sources are never treated as edges.
CLOUDFLARE_V4 = tuple(ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
))

EDGE_CACHE_VERSION = 1
FRESH_SECONDS = 6 * 3600
DEFAULT_SAMPLE_SIZE = 300
DEFAULT_KEEP = 30
_IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])")


def is_cloudflare(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(str(ip).strip())
    except (ipaddress.AddressValueError, ValueError):
        return False
    return any(addr in net for net in CLOUDFLARE_V4)


def subnet24(ip: str) -> str:
    return str(ipaddress.ip_network(f"{str(ip).strip()}/24", strict=False))


def _dedupe(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and is_cloudflare(text) and text not in out:
            out.append(text)
    return out


def builtin_edges() -> list[str]:
    return _dedupe(ip for edges in UAC_BUILTIN_EDGES.values() for ip in edges)


def sync_uac_edges(uac_root: str | Path | None) -> list[str]:
    """Read Cloudflare edge literals from the UAC sources; [] if unavailable."""
    if not uac_root:
        return []
    found: list[str] = []
    for rel in UAC_EDGE_FILES:
        path = Path(uac_root) / rel
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        found.extend(_IPV4_RE.findall(text))
    return _dedupe(found)


def edge_sources(uac_root: str | Path | None = None,
                 extra: Iterable[str] = ()) -> list[str]:
    """Seed edges: live UAC sources (if found) + synced copy + extras."""
    return _dedupe([*sync_uac_edges(uac_root), *builtin_edges(), *extra])


def scan_ranges(seeds: Iterable[str]) -> list[str]:
    """The /24 blocks that contain the seed edges (scan ranges)."""
    out: list[str] = []
    for ip in seeds:
        try:
            net = subnet24(ip)
        except ValueError:
            continue
        if net not in out:
            out.append(net)
    return out


def sample_ips(ranges: Iterable[str], count: int = DEFAULT_SAMPLE_SIZE,
               seeds: Iterable[str] = (), rng: random.Random | None = None) -> list[str]:
    """Stratified sample: seeds first, then an even share from every range.

    Order is interleaved across ranges so a partial scan is still diverse.
    """
    rng = rng or random.Random(1337)
    count = max(1, int(count))
    nets = [ipaddress.ip_network(r, strict=False) for r in ranges]
    chosen: list[str] = []
    for ip in seeds:
        text = str(ip).strip()
        if text and text not in chosen and len(chosen) < count:
            chosen.append(text)
    if not nets:
        return chosen[:count]
    per_net = math.ceil(max(0, count - len(chosen)) / len(nets))
    buckets: list[list[str]] = []
    for net in nets:
        hosts = [str(h) for h in net.hosts()]
        hosts = [h for h in hosts if h not in chosen and not h.endswith(".255")]
        rng.shuffle(hosts)
        buckets.append(hosts[:per_net])
    index = 0
    while len(chosen) < count and any(buckets):
        bucket = buckets[index % len(buckets)]
        if bucket:
            chosen.append(bucket.pop(0))
        index += 1
    return chosen[:count]


@dataclass
class EdgeResult:
    ip: str
    attempts: int = 0
    tcp_ok: int = 0
    tls_ok: int = 0
    tcp_ms: list[float] = field(default_factory=list)
    tls_ms: list[float] = field(default_factory=list)
    last_error: str = ""
    colo: str = ""
    traffic_bytes: int = 0
    tested_at: float = 0.0

    @property
    def success_rate(self) -> float:
        return self.tls_ok / self.attempts if self.attempts else 0.0

    @property
    def median_ms(self) -> float:
        return float(statistics.median(self.tls_ms)) if self.tls_ms else 0.0

    @property
    def median_tcp_ms(self) -> float:
        return float(statistics.median(self.tcp_ms)) if self.tcp_ms else 0.0

    @property
    def jitter_ms(self) -> float:
        if len(self.tls_ms) < 2:
            return 0.0
        return float(statistics.pstdev(self.tls_ms))

    @property
    def score(self) -> float:
        return score_edge(self.success_rate, self.median_ms, self.jitter_ms, self.attempts)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["tcp_ms"] = [round(x, 1) for x in self.tcp_ms]
        data["tls_ms"] = [round(x, 1) for x in self.tls_ms]
        return data

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "EdgeResult":
        valid = {"ip", "attempts", "tcp_ok", "tls_ok", "tcp_ms", "tls_ms",
                 "last_error", "colo", "traffic_bytes", "tested_at"}
        return cls(**{k: v for k, v in dict(raw or {}).items() if k in valid})


def score_edge(success_rate: float, median_ms: float, jitter_ms: float,
               attempts: int = 1) -> float:
    """0..1 quality: 60% success rate, 30% latency, 10% jitter."""
    if attempts <= 0 or success_rate <= 0:
        return 0.0
    latency = max(0.0, 1.0 - float(median_ms) / 1500.0)
    jitter = max(0.0, 1.0 - float(jitter_ms) / 300.0)
    return round(0.6 * success_rate + 0.3 * latency + 0.1 * jitter, 4)


def select_diverse(results: Iterable[EdgeResult], keep: int = DEFAULT_KEEP,
                   min_success: float = 0.5) -> list[EdgeResult]:
    """Top IPs, spread round-robin across /24s (best /24 first).

    IPs below ``min_success`` are never selected.
    """
    keep = max(1, int(keep))
    good = [r for r in results if r.attempts and r.success_rate >= min_success and r.score > 0]
    good.sort(key=lambda r: (-r.score, r.median_ms, r.ip))
    groups: dict[str, list[EdgeResult]] = {}
    for item in good:
        groups.setdefault(subnet24(item.ip), []).append(item)
    order = sorted(groups, key=lambda net: (-groups[net][0].score, net))
    picked: list[EdgeResult] = []
    depth = 0
    while len(picked) < keep and any(len(groups[n]) > depth for n in order):
        for net in order:
            if len(groups[net]) > depth:
                picked.append(groups[net][depth])
                if len(picked) >= keep:
                    break
        depth += 1
    return picked


def pool_ips(selected: Iterable[Any]) -> list[str]:
    out = []
    for item in selected:
        ip = item.ip if isinstance(item, EdgeResult) else str((item or {}).get("ip", ""))
        if ip and ip not in out:
            out.append(ip)
    return out


def resolve_edge_pool(pool: Iterable[str], fallback: Iterable[str],
                      min_size: int, log=None) -> list[str]:
    """Pool IPs if there are enough; otherwise pool first + existing list."""
    pool = [p for p in pool if p]
    fallback = [f for f in fallback if f]
    if len(pool) >= max(1, int(min_size)):
        return pool
    merged = list(dict.fromkeys([*pool, *fallback]))
    if log:
        log(f"EDGE POOL too few ({len(pool)} < {min_size}); falling back to existing edge list "
            f"({len(merged)} ips)")
    return merged


class EdgeCache:
    """data/edges.json: atomic writes, partial (resumable) and complete scans."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return raw if isinstance(raw, dict) and raw.get("version") == EDGE_CACHE_VERSION else {}

    def save(self, payload: dict[str, Any]) -> None:
        payload = dict(payload)
        payload["version"] = EDGE_CACHE_VERSION
        payload["updated_at"] = time.time()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix="edges.", suffix=".tmp", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    @staticmethod
    def is_fresh(payload: dict[str, Any], now: float | None = None,
                 max_age_s: float = FRESH_SECONDS, network_id: str = "") -> bool:
        if not payload or not payload.get("complete") or not payload.get("selected"):
            return False
        now = time.time() if now is None else now
        age = now - float(payload.get("finished_at", payload.get("updated_at", 0)) or 0)
        if age < 0 or age > max_age_s:
            return False
        cached_net = str(payload.get("network_id", "") or "")
        if network_id and cached_net and network_id not in {"unknown", "auto"} \
                and cached_net not in {"unknown", "auto"} and cached_net != network_id:
            return False
        return True

    def fresh_pool(self, now: float | None = None, network_id: str = "") -> list[str]:
        payload = self.load()
        return pool_ips(payload.get("selected", [])) if self.is_fresh(payload, now, network_id=network_id) else []
