"""Carrier-aware SNI Maker finder (engine 1).

Pipeline: detect carrier -> carrier-only clean IPs -> per-edge rounds of real
tunnel tests (HTTP 204 x2 + small download through local Xray) -> rank ->
tag. Pure logic is Qt-free and unit tested; the tunnel itself is the existing
SniBatchTester (xray + pattern core), so behaviour matches a real connect.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from typing import Callable, Iterable

from . import clean_ip as _clean

ASN_CARRIERS = {197207: "mci", 44244: "irancell"}
NAME_HINTS = (("irancell", "irancell"), ("mtn", "irancell"),
              ("mobile communication company of iran", "mci"), ("mcci", "mci"),
              ("hamrah", "mci"))
PREFERRED_URLS = {
    "irancell": "https://www.youtube.com/generate_204",
    "mci": "https://www.gstatic.com/generate_204",
    "auto": "https://www.gstatic.com/generate_204",
}
BUILTIN_METHOD = {"irancell": "full5", "mci": "tls_sni_records", "auto": "wrong_seq"}
DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes={n}"
TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
STALE_SECONDS = 24 * 3600
DEMOTE_AFTER = 2
META_KEY = "finder"


# ---------------------------------------------------------------- carrier
def _asn_number(value) -> int:
    text = str(value or "").strip().upper()
    if text.startswith("AS"):
        text = text[2:]
    digits = ""
    for ch in text:
        if ch.isdigit():
            digits += ch
        else:
            break
    return int(digits) if digits else 0


def parse_carrier(payload) -> tuple:
    """(carrier, asn_text) from ipwho.is / ip-api / ipinfo style JSON."""
    if not isinstance(payload, dict):
        return "", ""
    conn = payload.get("connection") if isinstance(payload.get("connection"), dict) else {}
    candidates = [conn.get("asn"), payload.get("asn"), payload.get("as"), payload.get("org")]
    names = " ".join(str(x or "") for x in (conn.get("isp"), conn.get("org"), payload.get("isp"),
                                           payload.get("org"), payload.get("as"))).lower()
    asn_text = ""
    for value in candidates:
        number = _asn_number(value)
        if number:
            asn_text = f"AS{number}"
            if number in ASN_CARRIERS:
                return ASN_CARRIERS[number], asn_text
    for hint, carrier in NAME_HINTS:
        if hint in names:
            return carrier, asn_text
    return "", asn_text


def detect_carrier(fallback: str = "auto", timeout: float = 4.0, get=None) -> dict:
    """{'carrier','source','asn','fallback'} - never raises."""
    fallback = str(fallback or "auto").lower()
    urls = ("https://ipwho.is/", "http://ip-api.com/json/?fields=as,isp,org", "https://ipinfo.io/json")
    try:
        if get is None:
            import requests
            session = requests.Session(); session.trust_env = False
            get = lambda url: session.get(url, timeout=timeout).json()
        for url in urls:
            try:
                carrier, asn = parse_carrier(get(url))
            except Exception:
                continue
            if carrier:
                return {"carrier": carrier, "source": "asn", "asn": asn, "fallback": False}
    except Exception:
        pass
    return {"carrier": fallback if fallback in BUILTIN_METHOD else "auto",
            "source": "setting", "asn": "", "fallback": True}


def network_key() -> str:
    try:
        from .pow.coordinator import detect_network
        return str(detect_network()[0] or "default")
    except Exception:
        return "default"


# ---------------------------------------------------------------- route
def connect_route(carrier: str, tuning, gene: dict | None = None) -> tuple:
    """(method, fake_sni, gene_ops_json) the way a real connect would use them.
    Genes apply to auto/Irancell only (MCI stays built-in)."""
    carrier = str(carrier or "auto").lower()
    method = BUILTIN_METHOD.get(carrier, "wrong_seq")
    fake_sni = str(getattr(tuning, "pattern_fake_sni", "") or "").strip() or "chatgpt.com"
    ops = ""
    if isinstance(gene, dict) and gene and carrier in {"auto", "irancell"}:
        gm = str(gene.get("method", "") or "").lower()
        if gm in {"wrong_seq", "tls_sni_records", "full5", "full10", "full20", "primitive"}:
            method = gm
            fake_sni = str(gene.get("fake_sni", "") or "").strip() or fake_sni
            if gm == "primitive" and isinstance(gene.get("ops"), list):
                import json
                ops = json.dumps(gene["ops"])
    return method, fake_sni, ops


def edge_rounds(clean_ips: Iterable, seeds: Iterable = (), max_edges: int = 3) -> list:
    """Edges to try per config, clean IPs first, seeds only if no clean IP."""
    ordered = _clean.split_ips(list(clean_ips))
    if not ordered:
        ordered = _clean.split_ips(list(seeds))
    return list(dict.fromkeys(ordered))[:max_edges]


# ---------------------------------------------------------------- results
@dataclass
class FinderResult:
    profile: object
    ok: bool = False
    edge: str = ""
    latency_ms: float = 0.0
    samples_ok: int = 0
    samples: int = 0
    throughput_kbps: float = 0.0
    country_code: str = ""
    exit_ip: str = ""
    error: str = ""

    @property
    def success_ratio(self) -> float:
        return self.samples_ok / self.samples if self.samples else (1.0 if self.ok else 0.0)

    @property
    def score(self) -> float:
        if not self.ok:
            return 0.0
        lat = max(1.0, self.latency_ms)
        return round(1000.0 * self.success_ratio + 300000.0 / (lat + 200.0) + min(self.throughput_kbps, 5000) / 50.0, 1)


def rank(results: Iterable[FinderResult], top: int = 10) -> list:
    good = [r for r in results if r.ok]
    good.sort(key=lambda r: (-r.success_ratio, r.latency_ms, -r.throughput_kbps))
    return good[:max(1, int(top))]


def tag_profile(profile, result: FinderResult, carrier: str, network: str, fake_sni: str,
                method: str, now: float | None = None):
    now = time.time() if now is None else float(now)
    tagged = replace(profile)
    tagged.address = result.edge
    tagged.fallback_address = ""
    tagged.spoof_fake_sni = fake_sni
    tagged.last_ping_ok = True
    tagged.last_ping_ms = float(result.latency_ms)
    tagged.verified_spoof = True
    if result.country_code:
        tagged.country_code = result.country_code
        tagged.observed_country_code = result.country_code
        tagged.observed_exit_ip = result.exit_ip
        tagged.country_verified_at = now
        tagged.country_source = "sni-finder"
    meta = dict(getattr(profile, "maker_meta", {}) or {})
    meta.update({META_KEY: True, "carrier": carrier, "network": network, "edge": result.edge,
                 "fake_sni": fake_sni, "method": method, "tested_at": now, "score": result.score,
                 "fail_streak": 0, "demoted": False})
    tagged.maker_meta = meta
    return tagged


def is_finder_profile(profile) -> bool:
    return bool((getattr(profile, "maker_meta", {}) or {}).get(META_KEY))


def is_stale(profile, carrier: str, network: str, now: float | None = None,
             max_age: float = STALE_SECONDS) -> bool:
    if not is_finder_profile(profile):
        return False
    meta = profile.maker_meta
    now = time.time() if now is None else float(now)
    return (now - float(meta.get("tested_at", 0) or 0) > max_age
            or str(meta.get("carrier", "")) != str(carrier)
            or str(meta.get("network", "")) != str(network))


def mark_revalidated(profile, ok: bool, latency_ms: float = 0.0, carrier: str = "",
                     network: str = "", now: float | None = None):
    """Returns updated copy; demotes (never deletes) after DEMOTE_AFTER fails."""
    now = time.time() if now is None else float(now)
    p = replace(profile)
    meta = dict(getattr(profile, "maker_meta", {}) or {})
    if ok:
        meta.update({"fail_streak": 0, "demoted": False, "tested_at": now})
        if carrier:
            meta["carrier"] = carrier
        if network:
            meta["network"] = network
        p.last_ping_ok = True; p.last_ping_ms = float(latency_ms)
    else:
        meta["fail_streak"] = int(meta.get("fail_streak", 0) or 0) + 1
        meta["tested_at"] = now
        if meta["fail_streak"] >= DEMOTE_AFTER:
            meta["demoted"] = True
            p.last_ping_ok = False
    p.maker_meta = meta
    return p


def merge_profiles(existing: list, new_profiles: Iterable, signature: Callable) -> tuple:
    """Add/update finder profiles only. A matching profile that was not created
    by the finder is never touched. Returns (merged_list, added, updated, skipped)."""
    merged = list(existing)
    by_sig = {}
    for index, p in enumerate(merged):
        try:
            by_sig[signature(p)] = index
        except Exception:
            continue
    added = updated = skipped = 0
    for p in new_profiles:
        sig = signature(p)
        index = by_sig.get(sig)
        if index is None:
            for i, old in enumerate(merged):
                if old.id == p.id:
                    index = i; break
        if index is None:
            merged.append(p); by_sig[sig] = len(merged) - 1; added += 1
        elif is_finder_profile(merged[index]):
            keep_id = merged[index].id
            merged[index] = replace(p, id=keep_id); updated += 1
        else:
            skipped += 1
    return merged, added, updated, skipped


# ---------------------------------------------------------------- probe
def make_probe(carrier: str, samples: int = 2, download_bytes: int = 262144):
    """Probe compatible with SniBatchTester.run(probe=...)."""
    url = PREFERRED_URLS.get(str(carrier or "auto").lower(), PREFERRED_URLS["auto"])

    def probe(profile, port, timeout, cancel):
        import requests
        from .sni_batch import LiveConfigResult
        result = LiveConfigResult(profile=profile)
        proxies = {"http": f"http://127.0.0.1:{port}", "https": f"http://127.0.0.1:{port}"}
        session = requests.Session(); session.trust_env = False
        per = max(2.0, float(timeout) / (samples + 1))
        latencies = []; errors = []
        try:
            for _ in range(max(1, samples)):
                if cancel.is_set():
                    result.error = "cancelled"; return result
                try:
                    started = time.perf_counter()
                    resp = session.get(url, proxies=proxies, timeout=(min(3.0, per), per))
                    if resp.status_code in (200, 204):
                        latencies.append((time.perf_counter() - started) * 1000.0)
                    else:
                        errors.append(f"HTTP {resp.status_code}")
                except Exception as exc:
                    errors.append(type(exc).__name__)
            result.samples = max(1, samples); result.samples_ok = len(latencies)
            result.throughput_kbps = 0.0
            if latencies and not cancel.is_set():
                try:
                    started = time.perf_counter()
                    resp = session.get(DOWNLOAD_URL.format(n=int(download_bytes)), proxies=proxies,
                                       timeout=(min(3.0, per), per * 2))
                    size = len(resp.content or b"")
                    secs = max(0.001, time.perf_counter() - started)
                    if size >= download_bytes // 2:
                        result.throughput_kbps = size / 1024.0 / secs
                except Exception as exc:
                    errors.append(f"download {type(exc).__name__}")
                try:
                    resp = session.get(TRACE_URL, proxies=proxies, timeout=(min(3.0, per), per))
                    info = dict(line.split("=", 1) for line in resp.text.splitlines() if "=" in line)
                    result.country_code = str(info.get("loc", "")).upper()
                    result.exit_ip = str(info.get("ip", ""))
                except Exception:
                    pass
            result.ok = bool(latencies)
            result.ping_ms = sum(latencies) / len(latencies) if latencies else 0.0
            if not result.ok:
                result.error = " | ".join(errors[-2:]) or "no 204"
            return result
        finally:
            session.close()
    return probe


# ---------------------------------------------------------------- runner
@dataclass
class FinderReport:
    carrier: str = "auto"
    carrier_source: str = "setting"
    asn: str = ""
    network: str = "default"
    method: str = ""
    fake_sni: str = ""
    clean_ips: list = field(default_factory=list)
    edges: list = field(default_factory=list)
    tested: int = 0
    results: list = field(default_factory=list)      # ranked FinderResult
    profiles: list = field(default_factory=list)     # tagged profiles (top N)
    error: str = ""


def run_finder(profiles: list, tuning, *, carrier_info: dict, network: str, gene: dict | None,
               cache, cancel, log: Callable[[str], None] = None,
               progress: Callable[[str, int, int], None] = None,
               workers: int = 20, timeout: float = 12.0, top: int = 10,
               tester_factory=None, clean_finder=None) -> FinderReport:
    log = log or (lambda _m: None)
    progress = progress or (lambda *_a: None)
    carrier = str(carrier_info.get("carrier", "auto") or "auto")
    report = FinderReport(carrier=carrier, carrier_source=str(carrier_info.get("source", "")),
                          asn=str(carrier_info.get("asn", "")), network=network)
    method, fake_sni, ops = connect_route(carrier, tuning, gene)
    report.method, report.fake_sni = method, fake_sni
    workers = max(1, min(32, int(workers)))
    log(f"SNI FINDER: carrier={carrier} ({report.carrier_source} {report.asn}) network={network} "
        f"method={method} fakeSni={fake_sni} configs={len(profiles)}")
    seeds = [getattr(tuning, "pattern_connect_ip", ""),
             *str(getattr(tuning, "pattern_fallback_ips", "") or "").split(",")]
    own = [getattr(p, "address", "") for p in profiles]
    progress("clean", 0, 1)
    finder = clean_finder or _clean.find_clean_ips
    picks = finder(cache, carrier, fake_sni, [*own, *seeds], sample=150, workers=50,
                   budget=8.0, top=5, cancel=cancel, log=log)
    report.clean_ips = [r.ip for r in picks]
    report.edges = edge_rounds(report.clean_ips, seeds, 3)
    log(f"SNI FINDER: clean IPs ({carrier}) = {','.join(report.clean_ips) or '-'}; edges={report.edges}")
    if not report.edges:
        report.error = "no edge"
        return report
    if tester_factory is None:
        from .sni_batch import SniBatchTester
        tester_factory = lambda: SniBatchTester(log)
    probe = make_probe(carrier)
    pending = list(profiles)
    winners = {}
    for round_index, edge in enumerate(report.edges, 1):
        if not pending or cancel.is_set():
            break
        batch = [replace(p, address=edge, fallback_address="") for p in pending]
        t = replace(tuning, carrier_mode=carrier, pattern_connect_ip=edge, pattern_fallback_ips="",
                    pattern_fake_sni=fake_sni, xray_mux_enabled=False)
        for attr, value in (("pattern_session_edge", edge), ("pattern_clean_edges", ""),
                            ("pattern_gene_edges", ""), ("pattern_gene_ops", ops)):
            if hasattr(t, attr):
                setattr(t, attr, value)
        progress("test", round_index, len(report.edges))
        tester = tester_factory()
        try:
            live = tester.run(batch, t, cancel, workers=workers, timeout=timeout,
                              strategy=method, probe=probe)
        finally:
            try:
                tester.stop()
            except Exception:
                pass
        ok_on_edge = 0
        still = []
        by_id = {id(b): p for b, p in zip(batch, pending)}
        lookup = {b.id: p for b, p in zip(batch, pending)}
        tested_ids = set()
        for r in live or []:
            original = lookup.get(getattr(r.profile, "id", ""), None)
            if original is None:
                continue
            tested_ids.add(original.id)
            fr = FinderResult(profile=original, ok=bool(r.ok), edge=edge,
                              latency_ms=float(getattr(r, "ping_ms", 0) or 0),
                              samples_ok=int(getattr(r, "samples_ok", 1 if r.ok else 0) or 0),
                              samples=int(getattr(r, "samples", 1) or 1),
                              throughput_kbps=float(getattr(r, "throughput_kbps", 0) or 0),
                              country_code=str(getattr(r, "country_code", "") or ""),
                              exit_ip=str(getattr(r, "exit_ip", "") or ""),
                              error=str(getattr(r, "error", "") or ""))
            if fr.ok:
                winners[original.id] = fr; ok_on_edge += 1
            else:
                still.append(original)
        still += [p for p in pending if p.id not in tested_ids and p.id not in winners]
        pending = still
        try:
            cache.record(carrier, edge, ok_on_edge > 0, 0.0)
        except Exception:
            pass
        log(f"SNI FINDER: round {round_index} edge={edge} ok={ok_on_edge} remaining={len(pending)}")
    report.tested = len(profiles)
    report.results = rank(winners.values(), top)
    report.profiles = [tag_profile(r.profile, r, carrier, network, fake_sni, method)
                       for r in report.results]
    for r in report.results:
        log(f"SNI FINDER: OK {getattr(r.profile, 'name', '')} edge={r.edge} {r.latency_ms:.0f} ms "
            f"{r.samples_ok}/{r.samples} {r.throughput_kbps:.0f} KB/s {r.country_code}")
    return report
