"""Live fitness: real PatternSniCore tunnel to Cloudflare edges.

Measures what the UAC Spoofer Xray engine needs — whether a gene applied via
WinDivert/Pattern lets the local forwarder complete TLS + a small data transfer
to a Cloudflare edge IP, compared with a plain baseline on the same edge.

Only exercises methods already in pattern_core (wrong_seq, plain, full5/10/20,
multi64, tls_sni_records, sni_boundary, sni_split). No new DPI primitives.
"""
from __future__ import annotations

import errno
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Callable

from .schema import GeneStrategy, merge_working_ips
from .score import ScoreResult

LogFn = Callable[[str], None]

# Probe SNI / Host for CF edges (tunnel reachability, NOT "unblock a website").
DEFAULT_TEST_HOSTS = (
    "www.cloudflare.com",
    "speed.cloudflare.com",
    "www.cloudflare.com",
)

# Edges used by UAC Spoofer Pattern defaults / common CF anycast.
DEFAULT_EDGE_IPS = (
    "104.18.32.47",
    "172.64.155.209",
    "104.18.8.83",
    "104.18.9.83",
    "104.16.1.51",
    "104.19.229.21",
    "188.114.99.0",
    "104.18.1.1",
)

DEFAULT_UAC_ROOTS = (
    Path(__file__).resolve().parents[2],
    Path(__file__).resolve().parents[2] / "uac_spoofer_ref",
)

HTTP_PROBE_PATH = "/cdn-cgi/trace"


def is_admin() -> bool:
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def find_uac_root(explicit: str | Path | None = None) -> Path | None:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    env = __import__("os").environ.get("GENE_LAB_UAC_ROOT", "").strip()
    if env:
        candidates.append(Path(env))
    candidates.extend(DEFAULT_UAC_ROOTS)
    for path in candidates:
        if (path / "uac_desktop" / "pattern_core" / "core.py").is_file():
            return path.resolve()
    return None


def ensure_uac_on_path(uac_root: Path | None = None) -> Path:
    root = uac_root or find_uac_root()
    if root is None:
        raise RuntimeError(
            "UAC Spoofer project not found. Set GENE_LAB_UAC_ROOT or install "
            "next to Gene Lab."
        )
    root_s = str(root)
    if root_s not in sys.path:
        sys.path.insert(0, root_s)
    return root


@dataclass(slots=True)
class ProbeOutcome:
    success: bool
    failure_type: str  # "", reset, timeout, other, offline, skipped
    latency_ms: float
    traffic_bytes: int
    host: str = ""
    ip: str = ""
    detail: str = ""
    transfer_bytes: int = 0


@dataclass
class LiveStats:
    probes: int = 0
    successes: int = 0
    fail_reset: int = 0
    fail_timeout: int = 0
    fail_other: int = 0
    baseline_open: int = 0
    traffic_bytes: int = 0
    network_id: str = "unknown"
    last_error: str = ""

    def as_dict(self) -> dict:
        return {
            "probes": self.probes,
            "successes": self.successes,
            "fail_reset": self.fail_reset,
            "fail_timeout": self.fail_timeout,
            "fail_other": self.fail_other,
            "baseline_open": self.baseline_open,
            "traffic_bytes": self.traffic_bytes,
            "network_id": self.network_id,
            "last_error": self.last_error,
        }


@dataclass
class LiveProbeConfig:
    test_hosts: tuple[str, ...] = DEFAULT_TEST_HOSTS
    edge_ips: tuple[str, ...] = DEFAULT_EDGE_IPS
    connect_timeout_s: float = 3.0
    handshake_timeout_s: float = 5.0
    confirm_ips: int = 3
    max_parallel: int = 2
    min_gap_s: float = 0.15
    connectivity_host: str = "1.1.1.1"
    connectivity_port: int = 53
    uac_root: str = ""
    local_port_base: int = 41443
    http_path: str = HTTP_PROBE_PATH
    # Extra edges probed during the confirmation stage after first wins.
    confirm_extra_rounds: int = 2


def classify_failure(exc: BaseException) -> str:
    if isinstance(exc, TimeoutError) or isinstance(exc, socket.timeout):
        return "timeout"
    if isinstance(exc, ConnectionResetError):
        return "reset"
    if isinstance(exc, ConnectionRefusedError):
        return "other"
    if isinstance(exc, OSError):
        win = getattr(exc, "winerror", None)
        err = getattr(exc, "errno", None)
        if err in {errno.ETIMEDOUT, errno.EAGAIN} or win in {10060}:
            return "timeout"
        if err in {errno.ECONNRESET, errno.EPIPE} or win in {10054, 10053}:
            return "reset"
        return "other"
    if isinstance(exc, ssl.SSLError):
        text = str(exc).lower()
        if "timed out" in text or "timeout" in text:
            return "timeout"
        if "reset" in text:
            return "reset"
        # Certificate issues after a ServerHello still mean DPI let us through.
        if "certificate" in text or "hostname" in text or "verify" in text:
            return ""
        return "other"
    return "other"


class LiveScorer:
    """Score strategies by real Pattern tunnel reachability to CF edges."""

    def __init__(
        self,
        config: LiveProbeConfig | None = None,
        log: LogFn | None = None,
        network_id: str = "unknown",
    ) -> None:
        self.config = config or LiveProbeConfig()
        self.log = log or (lambda _m: None)
        self.network_id = network_id
        self.stats = LiveStats(network_id=network_id)
        self._lock = threading.Lock()
        self._last_probe_at = 0.0
        self._baseline_cache: dict[tuple[str, str], tuple[float, ProbeOutcome]] = {}
        self._pattern_cls = None
        self._uac_root: Path | None = None
        self._port_seq = 0
        self._stop = False

    def request_stop(self) -> None:
        self._stop = True

    def _import_runtime(self) -> None:
        if self._pattern_cls is not None:
            return
        root = ensure_uac_on_path(Path(self.config.uac_root) if self.config.uac_root else None)
        self._uac_root = root
        from uac_desktop.pattern_core import PatternSniCore  # type: ignore
        self._pattern_cls = PatternSniCore
        self.log(f"LIVE runtime ready uac_root={root}")

    def connectivity_ok(self) -> bool:
        host = self.config.connectivity_host
        port = int(self.config.connectivity_port)
        try:
            with socket.create_connection((host, port), timeout=2.0):
                return True
        except OSError:
            pass
        for probe_host in ("1.1.1.1", "8.8.8.8", "4.2.2.4"):
            try:
                with socket.create_connection((probe_host, 443), timeout=2.0):
                    return True
            except OSError:
                continue
        return False

    def wait_for_connectivity(self, pause_check: Callable[[], bool] | None = None) -> bool:
        notified = False
        while not self._stop:
            if self.connectivity_ok():
                if notified:
                    self.log("LIVE connectivity restored — resuming")
                return True
            if not notified:
                self.log("LIVE connectivity lost — pausing probes")
                notified = True
            for _ in range(20):
                if self._stop:
                    return False
                if pause_check and pause_check():
                    time.sleep(0.05)
                    continue
                time.sleep(0.25)
        return False

    def _rate_limit(self) -> None:
        gap = max(0.0, float(self.config.min_gap_s))
        with self._lock:
            now = time.monotonic()
            wait = self._last_probe_at + gap - now
            if wait > 0:
                time.sleep(wait)
            self._last_probe_at = time.monotonic()

    def _next_local_port(self) -> int:
        with self._lock:
            self._port_seq = (self._port_seq + 1) % 200
            return int(self.config.local_port_base) + self._port_seq

    def _record(self, outcome: ProbeOutcome, *, is_baseline: bool = False) -> None:
        with self._lock:
            self.stats.probes += 1
            self.stats.traffic_bytes += max(0, int(outcome.traffic_bytes))
            if is_baseline and outcome.success:
                self.stats.baseline_open += 1
            elif outcome.success:
                self.stats.successes += 1
            elif outcome.failure_type == "reset":
                self.stats.fail_reset += 1
            elif outcome.failure_type == "timeout":
                self.stats.fail_timeout += 1
            elif outcome.failure_type not in {"", "skipped", "offline"}:
                self.stats.fail_other += 1
            if outcome.detail and not outcome.success:
                self.stats.last_error = outcome.detail[:240]

    def _probe_sni(self, index: int = 0) -> str:
        hosts = [h.strip() for h in self.config.test_hosts if str(h).strip()]
        if not hosts:
            hosts = list(DEFAULT_TEST_HOSTS)
        return hosts[index % len(hosts)]

    def _edges(self) -> list[str]:
        edges = [e.strip() for e in self.config.edge_ips if str(e).strip()]
        return edges or list(DEFAULT_EDGE_IPS)

    def _build_profile_tuning(
        self,
        method: str,
        fake_sni: str,
        host: str,
        ip: str,
        local_port: int,
        *,
        fake_repeat: int = 1,
        inject_delay_ms: int = 1,
        fragment_delay_ms: int = 0,
        chunk_size: int = 5,
    ):
        profile = SimpleNamespace(
            address=ip,
            fallback_address=ip,
            port=443,
            sni=host,
            config_port=local_port,
            origin="gene_lab",
            name=f"gene-{method}",
        )
        delay = int(fragment_delay_ms)
        tuning = SimpleNamespace(
            carrier_mode="auto",
            pattern_connect_ip=ip,
            pattern_fallback_ips=ip,
            pattern_use_profile_edges=False,
            pattern_fake_sni=fake_sni or host,
            pattern_fake_repeat=max(1, int(fake_repeat)),
            pattern_inject_delay_ms=int(inject_delay_ms),
            pattern_ack_timeout_ms=int(self.config.handshake_timeout_s * 1000),
            pattern_connect_timeout_ms=int(self.config.connect_timeout_s * 1000),
            pattern_relay_buffer_kb=128,
            pattern_socket_buffer_kb=256,
            pattern_max_sessions=4,
            pattern_edge_failure_cooldown_s=4,
            pattern_keepalive_idle_s=11,
            pattern_keepalive_interval_s=3,
            pattern_keepalive_count=3,
            pattern_upload_optimized=True,
            pattern_quality_preset="gene_lab",
            sni_split_delay_ms=delay,
            multi_delay_ms=delay,
            tls_record_delay_ms=delay,
            multi_fragment_size=max(1, int(chunk_size)),
        )
        return profile, tuning

    def _http_request(self, host: str) -> bytes:
        path = str(self.config.http_path or HTTP_PROBE_PATH).strip() or HTTP_PROBE_PATH
        if not path.startswith("/"):
            path = "/" + path
        return (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: GeneLab/1.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii", errors="ignore")

    def _tls_exchange(self, raw: socket.socket, host: str, started: float) -> ProbeOutcome:
        """Complete TLS handshake + small HTTP GET; return outcome (ip filled by caller)."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        transfer = 0
        try:
            with ctx.wrap_socket(
                raw, server_hostname=host, do_handshake_on_connect=False
            ) as tls:
                raw = None  # ownership transferred
                tls.settimeout(self.config.handshake_timeout_s)
                tls.do_handshake()
                req = self._http_request(host)
                tls.sendall(req)
                chunks: list[bytes] = []
                deadline = time.monotonic() + self.config.handshake_timeout_s
                while time.monotonic() < deadline and sum(len(c) for c in chunks) < 8192:
                    try:
                        piece = tls.recv(2048)
                    except socket.timeout:
                        break
                    if not piece:
                        break
                    chunks.append(piece)
                    # Enough to validate an HTTP response or CF trace body.
                    blob = b"".join(chunks)
                    if b"HTTP/" in blob or b"fl=" in blob or b"colo=" in blob:
                        break
                body = b"".join(chunks)
                transfer = len(req) + len(body)
                latency = (time.perf_counter() - started) * 1000
                ok = (
                    b"HTTP/" in body
                    or b"fl=" in body
                    or b"colo=" in body
                    or (len(body) >= 32 and body[:1] not in {b"\x00", b"\x15"})
                )
                if ok:
                    return ProbeOutcome(
                        True, "", latency, 9000 + transfer, host, "",
                        "tls+http ok", transfer_bytes=transfer,
                    )
                # Handshake alone — soft success with lower credit (caller may weight).
                return ProbeOutcome(
                    True, "", latency, 7000 + transfer, host, "",
                    "tls ok (no http body)", transfer_bytes=transfer,
                )
        except Exception as exc:  # noqa: BLE001
            kind = classify_failure(exc)
            latency = (time.perf_counter() - started) * 1000
            if isinstance(exc, ssl.SSLError) and kind == "":
                return ProbeOutcome(
                    True, "", latency, 6000, host, "",
                    f"tls soft-ok: {exc}", transfer_bytes=transfer,
                )
            return ProbeOutcome(
                False, kind or "other", latency, 2000 + transfer, host, "",
                f"{type(exc).__name__}: {exc}", transfer_bytes=transfer,
            )
        finally:
            if raw is not None:
                try:
                    raw.close()
                except OSError:
                    pass

    def probe_direct(self, host: str, ip: str) -> ProbeOutcome:
        """Baseline without Pattern — direct TLS to the edge."""
        cache_key = ("direct", host, ip)
        cached = self._baseline_cache.get(cache_key)
        if cached and (time.monotonic() - cached[0]) < 45.0:
            return cached[1]
        self._rate_limit()
        started = time.perf_counter()
        try:
            raw = socket.create_connection(
                (ip, 443), timeout=self.config.connect_timeout_s
            )
            outcome = self._tls_exchange(raw, host, started)
            outcome.ip = ip
            outcome.host = host
            if outcome.success:
                outcome.detail = "baseline_direct_open:" + (outcome.detail or "")
        except Exception as exc:  # noqa: BLE001
            kind = classify_failure(exc)
            outcome = ProbeOutcome(
                False, kind or "other", (time.perf_counter() - started) * 1000,
                1500, host, ip, f"baseline direct {type(exc).__name__}: {exc}",
            )
        self._baseline_cache[cache_key] = (time.monotonic(), outcome)
        return outcome

    def probe_plain(self, host: str, ip: str) -> ProbeOutcome:
        """Baseline via Pattern with method=plain (no WinDivert spoof)."""
        cache_key = ("plain", host, ip)
        cached = self._baseline_cache.get(cache_key)
        if cached and (time.monotonic() - cached[0]) < 45.0:
            return cached[1]
        outcome = self._probe_method(
            method="plain",
            fake_sni=host,
            host=host,
            ip=ip,
            fake_repeat=1,
            inject_delay_ms=0,
            fragment_delay_ms=0,
            chunk_size=5,
        )
        if outcome.success:
            outcome.detail = "baseline_plain_open:" + (outcome.detail or "")
        self._baseline_cache[cache_key] = (time.monotonic(), outcome)
        return outcome

    def probe_baseline(self, host: str, ip: str) -> ProbeOutcome:
        """Prefer Pattern plain; fall back to direct if Pattern unavailable."""
        try:
            self._import_runtime()
            return self.probe_plain(host, ip)
        except Exception as exc:  # noqa: BLE001
            self.log(f"LIVE plain baseline fallback to direct: {exc}")
            return self.probe_direct(host, ip)

    def _probe_method(
        self,
        *,
        method: str,
        fake_sni: str,
        host: str,
        ip: str,
        fake_repeat: int,
        inject_delay_ms: int,
        fragment_delay_ms: int,
        chunk_size: int,
    ) -> ProbeOutcome:
        self._import_runtime()
        assert self._pattern_cls is not None
        if method == "wrong_seq" and not is_admin():
            return ProbeOutcome(
                False, "skipped", 0.0, 0, host, ip,
                "wrong_seq requires Administrator / WinDivert",
            )
        self._rate_limit()
        local_port = self._next_local_port()
        profile, tuning = self._build_profile_tuning(
            method, fake_sni, host, ip, local_port,
            fake_repeat=fake_repeat,
            inject_delay_ms=inject_delay_ms,
            fragment_delay_ms=fragment_delay_ms,
            chunk_size=chunk_size,
        )
        core = self._pattern_cls(log=lambda m: self.log(f"PATTERN {m}"))
        started = time.perf_counter()
        traffic = 0
        try:
            core.start(profile, tuning, forced_strategy=method)
            raw = socket.create_connection(
                ("127.0.0.1", local_port), timeout=self.config.connect_timeout_s
            )
            outcome = self._tls_exchange(raw, host, started)
            outcome.ip = ip
            outcome.host = host
            traffic = max(0, getattr(core, "upload", 0) + getattr(core, "download", 0))
            outcome.traffic_bytes = max(outcome.traffic_bytes, 5000 + traffic)
            return outcome
        except Exception as exc:  # noqa: BLE001
            kind = classify_failure(exc)
            traffic = 2000 + max(0, getattr(core, "upload", 0) + getattr(core, "download", 0))
            if isinstance(exc, ssl.SSLError) and kind == "":
                return ProbeOutcome(
                    True, "", (time.perf_counter() - started) * 1000,
                    max(traffic, 7000), host, ip, f"tls soft-ok: {exc}",
                )
            return ProbeOutcome(
                False, kind or "other", (time.perf_counter() - started) * 1000,
                traffic, host, ip, f"{type(exc).__name__}: {exc}",
            )
        finally:
            try:
                core.stop()
            except Exception:
                pass

    def probe_strategy(self, strategy: GeneStrategy, host: str, ip: str) -> ProbeOutcome:
        return self._probe_method(
            method=strategy.method,
            fake_sni=strategy.fake_sni,
            host=host,
            ip=ip,
            fake_repeat=strategy.fake_repeat,
            inject_delay_ms=strategy.inject_delay_ms,
            fragment_delay_ms=strategy.fragment_delay_ms,
            chunk_size=strategy.chunk_size,
        )

    def _merge_confirmed_ips(self, strategy: GeneStrategy, ips: list[str]) -> None:
        seen = list(strategy.confirmed_ips or [])
        for ip in ips:
            text = str(ip or "").strip()
            if text and text not in seen:
                seen.append(text)
        strategy.confirmed_ips = seen[:16]
        strategy.confirm_need = max(1, int(self.config.confirm_ips))
        strategy.confirmed = (
            strategy.mode == "live"
            and not strategy.simulated
            and len(strategy.confirmed_ips) >= strategy.confirm_need
        )
        strategy.recommended = bool(strategy.confirmed)

    def _score_from_trials(
        self,
        strategy: GeneStrategy,
        *,
        strong_ips: list[str],
        weak_ips: list[str],
        latencies: list[float],
        baseline_latencies: list[float],
        transfers: list[int],
        fail_counts: dict[str, int],
        details: list[str],
        traffic_total: int,
        strong_trials: list[tuple[str, float]] | None = None,
    ) -> ScoreResult:
        need = max(1, int(self.config.confirm_ips))
        strategy.mode = "live"
        strategy.simulated = False
        strategy.confirm_need = need
        self._merge_confirmed_ips(strategy, strong_ips)
        if strong_trials:
            # Part B: remember the distinct edges this gene actually worked on.
            strategy.working_ips = merge_working_ips(strategy.working_ips, strong_trials)

        # Distinct strong IPs drive confirmation; weak (baseline also open) do not.
        n_strong = len(set(strong_ips))
        n_weak = len(set(weak_ips))
        confirmed = n_strong >= need

        avg_ms = sum(latencies) / len(latencies) if latencies else 0.0
        base_ms = (
            sum(baseline_latencies) / len(baseline_latencies)
            if baseline_latencies else 0.0
        )
        avg_transfer = sum(transfers) / len(transfers) if transfers else 0.0

        # Latency / throughput bonuses — keep scores differentiated.
        latency_bonus = 0.0
        if avg_ms > 0:
            latency_bonus = max(-0.06, min(0.08, (400.0 - avg_ms) / 2500.0))
            if base_ms > 0 and avg_ms < base_ms:
                latency_bonus += min(0.05, (base_ms - avg_ms) / 2000.0)
        transfer_bonus = min(0.04, avg_transfer / 200_000.0)

        if confirmed:
            score = 0.78 + min(0.14, 0.04 * n_strong) + latency_bonus + transfer_bonus
            success = True
            detail = (
                f"confirmed strong={n_strong}/{need} weak={n_weak} "
                + ";".join(details[:8])
            )
            strategy.notes = ((strategy.notes or "") + " | live-confirmed").strip(" |")
        elif n_strong > 0:
            score = 0.48 + 0.08 * n_strong + latency_bonus + transfer_bonus
            success = True
            detail = (
                f"unconfirmed strong={n_strong}/{need} ips={','.join(sorted(set(strong_ips))[:4])} "
                + ";".join(details[:8])
            )
        elif n_weak > 0:
            # Tunnel works but plain/direct also works — gene not proven necessary.
            score = 0.18 + 0.03 * n_weak + max(0.0, latency_bonus) * 0.5
            success = False
            detail = (
                f"baseline_also_open weak={n_weak} — gene not required on these edges; "
                + ";".join(details[:8])
            )
        else:
            score = 0.06
            success = False
            detail = (
                f"fail reset={fail_counts.get('reset', 0)} "
                f"timeout={fail_counts.get('timeout', 0)} "
                f"other={fail_counts.get('other', 0)} "
                + ";".join(details[:8])
            )

        strategy.fail_reset = int(getattr(strategy, "fail_reset", 0) or 0) + fail_counts.get("reset", 0)
        strategy.fail_timeout = int(getattr(strategy, "fail_timeout", 0) or 0) + fail_counts.get("timeout", 0)
        strategy.fail_other = int(getattr(strategy, "fail_other", 0) or 0) + fail_counts.get("other", 0)
        strategy.confirmed = confirmed
        strategy.recommended = confirmed

        return ScoreResult(
            success=success,
            score=round(min(1.0, max(0.0, score)), 4),
            latency_ms=round(avg_ms, 1),
            traffic_bytes=max(0, traffic_total),
            detail=detail[:500],
        )

    def _pair_trial(
        self,
        strategy: GeneStrategy,
        host: str,
        ip: str,
        pause_check: Callable[[], bool] | None,
    ) -> tuple[ProbeOutcome, ProbeOutcome | None]:
        if self._stop:
            return ProbeOutcome(False, "skipped", 0, 0, host, ip, "stopped"), None
        if pause_check:
            while pause_check() and not self._stop:
                time.sleep(0.05)
        if not self.connectivity_ok():
            return ProbeOutcome(False, "offline", 0, 0, host, ip, "offline"), None
        baseline = self.probe_baseline(host, ip)
        self._record(baseline, is_baseline=True)
        outcome = self.probe_strategy(strategy, host, ip)
        self._record(outcome, is_baseline=False)
        return baseline, outcome

    def score(
        self,
        strategy: GeneStrategy,
        pause_check: Callable[[], bool] | None = None,
        *,
        edge_limit: int | None = None,
        only_new_ips: bool = False,
    ) -> ScoreResult:
        """Evaluate gene vs plain/direct baseline across distinct edge IPs."""
        if not self.wait_for_connectivity(pause_check):
            return ScoreResult(False, 0.0, 0.0, 0, "offline/stopped")

        edges = self._edges()
        already = set(strategy.confirmed_ips or [])
        if only_new_ips:
            edges = [e for e in edges if e not in already]
        need = max(1, int(self.config.confirm_ips))
        # First pass: probe enough edges to have a chance at confirmation.
        limit = edge_limit if edge_limit is not None else max(need, min(len(edges), need + 2))
        targets = []
        for index, edge in enumerate(edges[:limit]):
            targets.append((self._probe_sni(index), edge))

        strong_ips: list[str] = []
        strong_trials: list[tuple[str, float]] = []
        weak_ips: list[str] = []
        latencies: list[float] = []
        baseline_latencies: list[float] = []
        transfers: list[int] = []
        fail_counts = {"reset": 0, "timeout": 0, "other": 0}
        details: list[str] = []
        traffic_total = 0

        workers = max(1, min(int(self.config.max_parallel), 3))
        index = 0
        while index < len(targets) and len(set(strong_ips)) < need and not self._stop:
            batch = targets[index:index + workers]
            index += workers
            if not self.wait_for_connectivity(pause_check):
                break
            with ThreadPoolExecutor(max_workers=len(batch)) as pool:
                futures = [
                    pool.submit(self._pair_trial, strategy, host, ip, pause_check)
                    for host, ip in batch
                ]
                for fut in as_completed(futures):
                    baseline, outcome = fut.result()
                    if outcome is None:
                        continue
                    traffic_total += int(outcome.traffic_bytes) + int(baseline.traffic_bytes)
                    tag = f"{outcome.host}@{outcome.ip}"
                    if outcome.success and not baseline.success:
                        strong_ips.append(outcome.ip)
                        strong_trials.append((outcome.ip, float(outcome.latency_ms)))
                        latencies.append(outcome.latency_ms)
                        transfers.append(int(outcome.transfer_bytes or 0))
                        details.append(f"{tag}:strong")
                    elif outcome.success and baseline.success:
                        weak_ips.append(outcome.ip)
                        latencies.append(outcome.latency_ms)
                        baseline_latencies.append(baseline.latency_ms)
                        transfers.append(int(outcome.transfer_bytes or 0))
                        details.append(f"{tag}:baseline_also_open")
                    else:
                        kind = outcome.failure_type or "other"
                        fail_counts[kind] = fail_counts.get(kind, 0) + 1
                        details.append(f"{tag}:{kind}")

        # Keep previously confirmed strong IPs.
        for ip in already:
            if ip not in strong_ips:
                strong_ips.append(ip)

        return self._score_from_trials(
            strategy,
            strong_ips=strong_ips,
            weak_ips=weak_ips,
            latencies=latencies,
            baseline_latencies=baseline_latencies,
            transfers=transfers,
            fail_counts=fail_counts,
            details=details,
            traffic_total=traffic_total,
            strong_trials=strong_trials,
        )

    def confirm_more(
        self,
        strategy: GeneStrategy,
        pause_check: Callable[[], bool] | None = None,
    ) -> ScoreResult:
        """Confirmation stage: re-test on additional distinct edges until need met."""
        need = max(1, int(self.config.confirm_ips))
        have = len(strategy.confirmed_ips or [])
        if have >= need:
            strategy.confirmed = True
            strategy.recommended = True
            return ScoreResult(
                True, strategy.score or 0.85, strategy.avg_ms, 0,
                f"already confirmed {have}/{need}",
            )
        remaining = need - have
        # Probe unused edges; allow a few extras in case of failures.
        extra = remaining + max(1, int(self.config.confirm_extra_rounds))
        self.log(
            f"CONFIRM {strategy.name} need={need} have={have} trying +{extra} edges"
        )
        return self.score(
            strategy,
            pause_check=pause_check,
            edge_limit=extra,
            only_new_ips=True,
        )
