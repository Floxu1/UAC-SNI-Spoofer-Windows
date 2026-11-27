"""UAC Tor session coordinator: All transports reliable, real GeoIP, verified browsing & Autopilot."""
from __future__ import annotations

import shutil
import tempfile
import threading
import time
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass, replace
from pathlib import Path

from ..application_settings import ConnectionPreferences
from ..engine import WindowsProxy
from ..pow.coordinator import _physical_uplink_mtu
from ..traffic import loopback_ports
from .bridges import (
    DEFAULT_SNOWFLAKE_BRIDGES,
    auto_fetch_bridges,
    extract_bridges_from_text,
    load_local_pt_bridges,
    rank_reachable_bridges,
)
from .binaries import ensure_tor_binaries
from .config import build_torrc, find_pt_binary, find_tor_binary
from .output import SingBoxRunner, require_admin, start_tor_mixed_proxy, start_tor_tun
from .probe import quick_tor_ping, verify_http_proxy, verify_tor_exit
from .pt_proxy import TorBridgeProxy
from .runner import TorControlClient, TorProcess
from .store import TorSettings, TorStore


@dataclass(frozen=True)
class TorOptions:
    vpn: bool = False
    routing_mode: str = "bypass"
    processes: tuple[str, ...] = ()
    system_proxy: bool | None = None
    privacy: ConnectionPreferences | None = None


@dataclass(frozen=True)
class TorStatus:
    phase: str = "idle"
    detail: str = ""
    progress: int = 0
    transport: str = ""
    bridge_method: str = ""
    socks_port: int = 0
    http_port: int = 0
    control_port: int = 0
    dns_port: int = 0
    exit_ip: str = ""
    country: str = ""
    is_tor: bool = False
    latency_ms: int = 0
    tx_bytes: int = 0
    rx_bytes: int = 0
    circuit: tuple[str, ...] = ()
    disconnect_failed: bool = False


class _TorCancelled(RuntimeError):
    pass


class TorCoordinator:
    def __init__(
        self,
        directory: Path,
        *,
        status: Callable[[TorStatus], None],
        log: Callable[[str], None],
    ) -> None:
        self.store = TorStore(directory)
        self._report = status
        self._log = log
        self._lock = threading.RLock()
        self._worker: threading.Thread | None = None
        self._stop = threading.Event()
        self._refresh_exit = threading.Event()
        self._new_identity_req = threading.Event()
        self._session_vpn: bool | None = None
        self._proxy: WindowsProxy | None = None
        self._control: TorControlClient | None = None
        self._system_proxy_requested = True
        self._status = TorStatus()

    @property
    def status(self) -> TorStatus:
        with self._lock:
            return self._status

    @property
    def active(self) -> bool:
        with self._lock:
            return self._worker is not None

    @property
    def session_vpn(self) -> bool | None:
        with self._lock:
            return self._session_vpn if self._worker is not None else None

    @property
    def system_proxy_enabled(self) -> bool | None:
        proxy = self._proxy
        return proxy.session_enabled if proxy is not None else None

    def set_system_proxy_enabled(self, enabled: bool) -> None:
        with self._lock:
            proxy = self._proxy
            if proxy is None or self._status.phase != "connected" or self._stop.is_set():
                raise RuntimeError("Tor local proxy is not ready.")
            proxy.set_session_enabled(enabled)
            self._system_proxy_requested = enabled

    def request_new_identity(self) -> bool:
        with self._lock:
            if self._status.phase != "connected" or self._control is None:
                return False
            self._new_identity_req.set()
            return True

    def request_exit_refresh(self) -> None:
        with self._lock:
            if self._status.phase == "connected":
                self._refresh_exit.set()

    def clear_cache(self) -> bool:
        if self.active:
            return False
        shutil.rmtree(self.store.directory / "tor-data", ignore_errors=True)
        for path in (self.store.bridges_cache_path, self.store.dns_cache_path):
            path.unlink(missing_ok=True)
        self._log("Tor consensus, bridge cache, and DNS cache cleared")
        return True

    def connect(self, options: TorOptions, *, settings: TorSettings | None = None) -> bool:
        with self._lock:
            if self._worker is not None:
                return False
            self._stop = threading.Event()
            self._refresh_exit.clear()
            self._new_identity_req.clear()
            self._session_vpn = options.vpn
            self._system_proxy_requested = (not options.vpn) if options.system_proxy is None else options.system_proxy
            settings = settings if settings is not None else self.store.settings()
            self._status = TorStatus(phase="starting", progress=5, detail="Starting Tor")
            self._log(f"Tor connecting: transport={settings.transport} ({'VPN' if options.vpn else 'Proxy'})")
            self._worker = threading.Thread(
                target=self._run, args=(options, settings), name="tor-session", daemon=True
            )
            self._report(self._status)
            self._worker.start()
            return True

    def disconnect(self) -> None:
        with self._lock:
            if self._worker is not None:
                if not self._stop.is_set():
                    self._log("Tor disconnecting")
                self._stop.set()
                self._publish(phase="stopping", detail="Closing Tor session")
            elif self._status != TorStatus():
                self._status = TorStatus()
                self._report(self._status)

    def wait(self, timeout: float = 10.0) -> bool:
        with self._lock:
            worker = self._worker
        if worker is None:
            return True
        worker.join(timeout)
        return not worker.is_alive()

    def _publish(self, **changes) -> None:
        with self._lock:
            if self._stop.is_set() and changes.get("phase") != "stopping":
                return
            self._status = replace(self._status, **changes)
            self._report(self._status)

    def _check_stop(self) -> None:
        if self._stop.is_set():
            raise _TorCancelled()

    def _restore_proxy(self, proxy: WindowsProxy) -> None:
        with self._lock:
            self._proxy = None
            proxy.restore_session()

    def _plan_transports(self, settings: TorSettings) -> list[str]:
        if settings.transport != "auto":
            return [settings.transport]
        custom = extract_bridges_from_text(settings.custom_bridges)
        has_lyrebird = bool(find_pt_binary("lyrebird.exe") or find_pt_binary("obfs4proxy.exe"))
        has_snowflake = bool(find_pt_binary("snowflake-client.exe") or has_lyrebird)

        plan: list[str] = []
        winner_tr, _winner_m = self.store.autopilot_winner()
        if winner_tr in ("custom", "webtunnel", "snowflake", "obfs4", "direct"):
            if winner_tr != "custom" or custom:
                plan.append(winner_tr)
        if custom and "custom" not in plan:
            plan.append("custom")
        if has_lyrebird and "webtunnel" not in plan:
            plan.append("webtunnel")
        if has_snowflake and "snowflake" not in plan:
            plan.append("snowflake")
        if has_lyrebird and "obfs4" not in plan:
            plan.append("obfs4")
        if "direct" not in plan:
            plan.append("direct")
        self._log(f"Tor Autopilot plan: {' -> '.join(plan)}")
        return plan

    def _filter_reachable(self, mode: str, lines: list[str]) -> list[str]:
        if mode == "snowflake" or len(lines) <= 1:
            return lines
        ranked = rank_reachable_bridges(lines[:30], timeout=2.5, cancel=self._stop)
        if ranked:
            dropped = len(lines[:30]) - len(ranked)
            if dropped > 0:
                self._log(f"Tor {mode}: kept {len(ranked)} reachable bridge(s) (filtered {dropped} unreachable)")
            return [line for line, _ms in ranked[:12]]
        return []

    def _resolve_bridges_for(self, mode: str, settings: TorSettings, *, force_fresh: bool = False) -> tuple[list[str], str]:
        if mode == "direct":
            return [], "direct"
        if mode == "custom":
            lines = extract_bridges_from_text(settings.custom_bridges)
            if not lines:
                raise RuntimeError("No valid custom bridge lines configured")
            live = self._filter_reachable("custom", lines)
            return (live or lines), "custom"

        if not force_fresh:
            user_lines = extract_bridges_from_text(settings.custom_bridges, mode)
            if user_lines:
                live = self._filter_reachable(mode, user_lines)
                if live:
                    return live, "user"
            cached = self.store.cached_bridges(mode)
            if cached:
                live = self._filter_reachable(mode, cached)
                if live:
                    return live, "cache"

        # Always auto-fetch bridges for webtunnel / snowflake / obfs4 when missing or unreachable
        if settings.transport == "auto" or settings.auto_fetch_bridges or force_fresh or mode in ("webtunnel", "snowflake", "obfs4"):
            self._publish(phase="fetching", progress=12, detail=f"Auto-fetching {mode} bridges")
            res = auto_fetch_bridges(
                mode,
                source=settings.bridge_source,
                custom_relay=settings.bridge_relay_url,
                upstream_proxy=settings.upstream_proxy,
                data_dir=self.store.directory.parent,
                last_winner=self.store.last_winner_method(),
                dns_cache=self.store.load_dns_cache(),
                save_dns_cache=self.store.save_dns_cache,
                cancel=self._stop,
                log=self._log,
            )
            self._check_stop()
            pool: list[str] = list(res.bridges) if res.ok else []
            # Merge bundled pt_config.json bridges for obfs4/snowflake so we have a larger reachable pool
            if mode in ("obfs4", "snowflake"):
                for b in load_local_pt_bridges(mode):
                    if b not in pool:
                        pool.append(b)
            if mode == "snowflake":
                for b in DEFAULT_SNOWFLAKE_BRIDGES:
                    if b not in pool:
                        pool.append(b)
            if pool:
                live = self._filter_reachable(mode, pool) if mode in ("webtunnel", "obfs4") else pool
                chosen = live or pool[:12]
                self.store.save_cached_bridges(mode, chosen, res.method or "auto", res.source or "auto")
                return chosen, (res.source or res.method or "auto")

        if mode == "snowflake":
            return list(DEFAULT_SNOWFLAKE_BRIDGES), "builtin"
        cached = self.store.cached_bridges(mode, max_age_s=0)
        return cached, "cache" if cached else ""

    def _run(self, options: TorOptions, settings: TorSettings) -> None:
        final = TorStatus()
        stop_error = None
        try:
            if options.vpn:
                require_admin()
            binary = find_tor_binary()
            if binary is None or (find_pt_binary("lyrebird.exe") is None and find_pt_binary("obfs4proxy.exe") is None):
                self._publish(phase="starting", progress=8, detail="Downloading Tor core")
                binary = ensure_tor_binaries(proxy=settings.upstream_proxy, cancel=self._stop, log=self._log)
                self._check_stop()
            self.store.directory.mkdir(parents=True, exist_ok=True)
            data_dir = self.store.directory / "tor-data"
            data_dir.mkdir(parents=True, exist_ok=True)
            transports = self._plan_transports(settings)

            with tempfile.TemporaryDirectory(prefix="session-", dir=self.store.directory) as session_dir:
                work_dir = Path(session_dir)
                retries = 0
                while True:
                    self._check_stop()
                    with ExitStack() as active:
                        pt_proxy_port = 0
                        if not settings.upstream_proxy:
                            pt_proxy = TorBridgeProxy(
                                dns_cache=self.store.load_dns_cache(),
                                save_dns_cache=self.store.save_dns_cache,
                                log=self._log,
                            )
                            pt_proxy_port = pt_proxy.start()
                            active.callback(pt_proxy.close)
                            self._log(f"Tor PT DNS/Bypass proxy ready on 127.0.0.1:{pt_proxy_port}")

                        tor_proc, control, chosen_transport, bridge_method, ports = self._bootstrap_any(
                            active, binary, data_dir, work_dir, settings, transports, pt_proxy_port=pt_proxy_port
                        )
                        socks_port, http_port, control_port, dns_port = ports
                        self._control = control
                        active.callback(lambda: setattr(self, "_control", None))

                        self._publish(phase="checking", progress=92, detail="Verifying Tor exit & country")
                        exit_info = verify_tor_exit(socks_port, control=control, timeout=16.0)
                        self._check_stop()
                        if not exit_info.ok:
                            raise RuntimeError(f"Tor bootstrapped but exit verification failed: {exit_info.detail}")

                        self.store.save_autopilot_winner(chosen_transport, bridge_method)

                        proxy_http_port = http_port
                        proxy_socks_port = socks_port
                        tun_runner: SingBoxRunner | None = None
                        mixed_runner: SingBoxRunner | None = None

                        need_mixed = (
                            not options.vpn
                            and (
                                bool(options.processes)
                                or settings.routing_mode == "only"
                                or settings.iran_direct
                                or bool(settings.domains_direct)
                                or bool(settings.ips_direct)
                            )
                        )
                        if options.vpn:
                            tun_runner = start_tor_tun(
                                work_dir,
                                settings,
                                socks_port=socks_port,
                                dns_port=dns_port,
                                processes=options.processes,
                                uplink_mtu=_physical_uplink_mtu(),
                                cancel=self._stop,
                                log=self._log,
                                privacy=options.privacy,
                                proxy_port=0,
                            )
                            active.callback(tun_runner.close)
                        elif need_mixed:
                            try:
                                mixed_port, = loopback_ports(1, exclude=(*ports, pt_proxy_port))
                                # mixed_proxy_no_dns_port
                                mixed_runner = start_tor_mixed_proxy(
                                    work_dir,
                                    settings,
                                    listen_port=mixed_port,
                                    socks_port=socks_port,
                                    processes=options.processes,
                                    cancel=self._stop,
                                    log=self._log,
                                )
                                ok_http, detail_http = verify_http_proxy(mixed_port, timeout=10.0)
                                if ok_http:
                                    active.callback(mixed_runner.close)
                                    proxy_http_port = mixed_port
                                    proxy_socks_port = mixed_port
                                    self._log(f"Tor mixed proxy verified on 127.0.0.1:{mixed_port} ({detail_http})")
                                else:
                                    self._log(f"Tor mixed proxy probe failed ({detail_http}); using native Tor HTTP/SOCKS ports")
                                    mixed_runner.close()
                                    mixed_runner = None
                            except Exception as exc:
                                self._log(f"Tor mixed proxy skipped ({exc}); using native Tor HTTP/SOCKS ports")
                                mixed_runner = None

                        if not options.vpn and mixed_runner is None:
                            ok_native, detail_native = verify_http_proxy(proxy_http_port, timeout=10.0)
                            self._log(f"Tor native HTTP tunnel probe on 127.0.0.1:{proxy_http_port}: {'OK' if ok_native else detail_native}")

                        proxy = WindowsProxy(self._log)
                        active.callback(self._restore_proxy, proxy)
                        proxy.bind_session(
                            proxy_socks_port,
                            proxy_http_port,
                            enabled=self._system_proxy_requested,
                            tun=options.vpn,
                        )
                        self._proxy = proxy
                        self._check_stop()

                        retries = 0
                        circuit = tuple(control.circuit_path())
                        self._publish(
                            phase="connected",
                            progress=100,
                            detail="Tor connected" + (" (Verified Tor exit)" if exit_info.is_tor else ""),
                            transport=chosen_transport,
                            bridge_method=bridge_method,
                            socks_port=proxy_socks_port,
                            http_port=proxy_http_port,
                            control_port=control_port,
                            dns_port=dns_port,
                            exit_ip=exit_info.ip,
                            country=exit_info.country,
                            is_tor=exit_info.is_tor,
                            latency_ms=exit_info.latency_ms,
                            circuit=circuit,
                        )
                        self._log(
                            f"Tor connected via {chosen_transport} ({bridge_method or 'direct'}) "
                            f"exit={exit_info.ip} ({exit_info.country or '?'}) {exit_info.latency_ms}ms"
                        )
                        drop_reason = self._monitor(tor_proc, control, tun_runner, mixed_runner, socks_port)
                        if not settings.auto_reconnect or retries >= 2:
                            raise RuntimeError(drop_reason)
                        retries += 1
                        self._log(f"Tor reconnecting ({retries}/2): {drop_reason}")
                        self._publish(phase="starting", progress=10, detail=f"Reconnecting Tor: {drop_reason}")
                    self._stop.wait(2.0)
        except _TorCancelled:
            pass
        except Exception as exc:
            if self._stop.is_set():
                stop_error = exc
                self._log(f"Tor disconnect error: {exc}")
            else:
                final = TorStatus(phase="error", detail=str(exc))
                self._log(f"Tor failed: {exc}")
        finally:
            with self._lock:
                if self._stop.is_set():
                    self._log("Tor stopped")
                    self._status = (
                        TorStatus(phase="error", detail=str(stop_error), disconnect_failed=True)
                        if stop_error is not None
                        else TorStatus()
                    )
                else:
                    self._status = final
                self._worker = None
                self._report(self._status)

    def _bootstrap_any(
        self,
        active: ExitStack,
        binary: Path,
        data_dir: Path,
        work_dir: Path,
        settings: TorSettings,
        transports: list[str],
        *,
        pt_proxy_port: int = 0,
    ):
        last_error = "No Tor transport succeeded"
        base_budget = float(settings.bootstrap_timeout_s)
        stall_s = float(settings.stall_fail_s)
        tried_sets: set[tuple] = set()

        for idx, mode in enumerate(transports):
            self._check_stop()
            # Snowflake also tries without Socks5Proxy as fallback if proxy check rejects it
            if mode == "snowflake":
                sub_plans = [(False, pt_proxy_port), (False, 0)]
            elif mode in ("webtunnel", "obfs4"):
                sub_plans = [(False, pt_proxy_port), (True, pt_proxy_port)]
            else:
                sub_plans = [(False, pt_proxy_port)]

            for force_fresh, use_proxy_port in sub_plans:
                self._check_stop()
                bridges, method = self._resolve_bridges_for(mode, settings, force_fresh=force_fresh)
                if mode != "direct" and not bridges:
                    self._log(f"Tor skipping {mode}: no bridges available")
                    break
                sig = (mode, use_proxy_port, *sorted(bridges))
                if mode != "direct" and sig in tried_sets:
                    continue
                tried_sets.add(sig)

                ports = self._allocate_ports(settings, exclude=(pt_proxy_port,) if pt_proxy_port else ())
                socks_port, http_port, control_port, dns_port = ports
                stamp = int(time.monotonic() * 1000)
                cookie_path = work_dir / f"cookie-{idx}-{stamp}"
                torrc_path = work_dir / f"torrc-{idx}-{stamp}"
                torrc_text = build_torrc(
                    settings,
                    data_dir=data_dir,
                    cookie_path=cookie_path,
                    socks_port=socks_port,
                    http_port=http_port,
                    control_port=control_port,
                    dns_port=dns_port,
                    bridges=bridges,
                    transport_mode=mode,
                    pt_proxy_port=use_proxy_port,
                )
                torrc_path.write_text(torrc_text, encoding="utf-8")
                budget = max(base_budget, 90.0) if mode == "snowflake" else base_budget
                exit_tag = f" exit={settings.exit_country_code.upper()}" if settings.exit_country_code else ""
                self._publish(
                    phase="bootstrapping",
                    progress=15,
                    detail=f"Bootstrapping Tor ({mode})",
                    transport=mode,
                    bridge_method=method,
                )
                self._log(
                    f"Tor attempt {idx + 1}/{len(transports)}: transport={mode} "
                    f"bridges={len(bridges)} source={method}{exit_tag} budget={int(budget)}s"
                )

                def on_boot(pct: int, tag: str, summary: str, current_mode=mode) -> None:
                    scaled = 15 + int(pct * 0.75)
                    self._publish(
                        phase="bootstrapping",
                        progress=min(90, scaled),
                        detail=f"{current_mode}: {pct}% · {summary}",
                    )

                with ExitStack() as attempt:
                    proc = TorProcess(binary, torrc_path, work_dir, on_log=self._log, on_bootstrap=on_boot)
                    attempt.callback(proc.close)
                    if proc.wait_bootstrapped(budget, self._stop, stall_fail_s=stall_s):
                        self._check_stop()
                        control = TorControlClient(control_port, cookie_path)
                        active.enter_context(attempt.pop_all())
                        return proc, control, mode, method, ports
                    self._check_stop()
                    last_error = proc.last_error or f"{mode} did not bootstrap within {int(budget)}s"
                    self._log(f"Tor attempt {mode} ({method}) failed: {last_error}")
                if mode in ("webtunnel", "obfs4") and method not in ("cache", "user"):
                    break
        raise RuntimeError(last_error)

    @staticmethod
    def _allocate_ports(settings: TorSettings, *, exclude: tuple[int, ...] = ()) -> tuple[int, int, int, int]:
        chosen = [settings.socks_port, settings.http_port, settings.control_port, settings.dns_port]
        needed = sum(1 for p in chosen if p == 0)
        excl = tuple(p for p in (*chosen, *exclude) if p > 0)
        auto = list(loopback_ports(needed, exclude=excl)) if needed else []
        out = []
        for p in chosen:
            out.append(p if p > 0 else auto.pop(0))
        return out[0], out[1], out[2], out[3]

    def _monitor(
        self,
        tor_proc: TorProcess,
        control: TorControlClient,
        tun_runner: SingBoxRunner | None,
        mixed_runner: SingBoxRunner | None,
        socks_port: int,
    ) -> str:
        next_stats = time.monotonic() + 1.0
        next_ping = time.monotonic() + 25.0
        while not self._stop.is_set():
            if not tor_proc.running():
                return tor_proc.last_error or "Tor process exited unexpectedly"
            if tun_runner is not None and not tun_runner.running():
                return "Tor TUN helper stopped unexpectedly"
            if mixed_runner is not None and not mixed_runner.running():
                return "Tor proxy helper stopped unexpectedly"

            if self._new_identity_req.is_set():
                self._new_identity_req.clear()
                try:
                    if control.new_identity():
                        self._log("Tor New Identity (NEWNYM) signal sent")
                        self._stop.wait(1.5)
                        info = verify_tor_exit(socks_port, control=control, timeout=12.0)
                        if info.ok:
                            self._publish(
                                exit_ip=info.ip,
                                country=info.country,
                                is_tor=info.is_tor,
                                latency_ms=info.latency_ms,
                                circuit=tuple(control.circuit_path()),
                            )
                            self._log(f"Tor new exit IP: {info.ip} ({info.country or '?'})")
                except Exception as exc:
                    self._log(f"Tor New Identity failed: {exc}")

            if self._refresh_exit.is_set():
                self._refresh_exit.clear()
                info = verify_tor_exit(socks_port, control=control, timeout=10.0)
                if info.ok:
                    self._publish(
                        exit_ip=info.ip,
                        country=info.country,
                        is_tor=info.is_tor,
                        latency_ms=info.latency_ms,
                        circuit=tuple(control.circuit_path()),
                    )

            now = time.monotonic()
            if now >= next_stats:
                counts = control.traffic()
                if counts is not None:
                    self._publish(tx_bytes=counts[0], rx_bytes=counts[1])
                next_stats = now + 2.0
            if now >= next_ping:
                ms = quick_tor_ping(socks_port, timeout=8.0)
                if ms > 0:
                    self._publish(latency_ms=ms, circuit=tuple(control.circuit_path()))
                next_ping = now + 30.0
            self._stop.wait(0.25)
        raise _TorCancelled()
