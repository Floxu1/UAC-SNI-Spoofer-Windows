from __future__ import annotations

import http.client
import tempfile
import threading
import time
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass, replace
from pathlib import Path

from ..paths import BIN
from ..pow.config import identity_path
from ..pow.coordinator import _physical_uplink_mtu, detect_network
from ..pow.kill_switch import VpnKillSwitch
from ..pow.network_watch import NetworkNotifications
from ..pow.psiphon import PsiphonProcess, find_helper
from .carrier import DirectCancelled, DirectCarrier, NativeAttempt, ensure_active, loopback_port
from .country import start_country
from .output import (
    DIRECT_MASK, DIRECT_NATIVE, DIRECT_XRAY, OwnedHelper, OutputError,
    require_admin, start_masks, start_tun, start_xray, verify_tun,
)
from ..traffic import loopback_ports, SessionTraffic, xray_traffic
from .probe import ProbeResult, select_dns, trace, verify_http_proxy, verify_https, verify_payload
from .resolvers import parse_resolver
from .store import DirectSettings, DirectStore
from ..application_settings import ConnectionPreferences
from ..engine import WindowsProxy
from .xray import build_config


@dataclass(frozen=True)
class DirectOptions:
    vpn: bool = True
    kill_switch: bool = False
    routing_mode: str = "all"
    processes: tuple[str, ...] = ()
    whitelist: tuple[str, ...] = ()
    dns_server: str = "1.1.1.1"
    mtu: int = 1400
    socks_port: int = 0
    http_port: int = 0
    system_proxy: bool | None = None
    privacy: ConnectionPreferences | None = None


@dataclass(frozen=True)
class DirectStatus:
    phase: str = "idle"
    detail: str = ""
    progress: int = 0
    socks_port: int = 0
    http_port: int = 0
    carrier: str = ""
    resolver: str = ""
    dns_ms: int = 0
    exit_ip: str = ""
    country: str = ""
    protected: bool = False
    tx_bytes: int = 0
    rx_bytes: int = 0
    probe_port: int = 0
    dns_lab_port: int = 0
    resolver_address: str = ""
    dns_udp_supported: bool = True
    disconnect_failed: bool = False


@dataclass
class _Route:
    socks_port: int
    http_port: int
    stats_port: int
    probe_port: int
    dns_lab_port: int
    traffic: SessionTraffic
    is_chained: bool
    carrier: NativeAttempt | None
    xray: OwnedHelper
    tun: OwnedHelper | None
    country: PsiphonProcess | None

    def healthy(self) -> bool:
        return (self.xray.running() and (self.tun is None or self.tun.running())
                and (self.carrier is None or self.carrier.running())
                and (self.country is None or self.country.running and self.country.connected.is_set()))


class _PayloadFailure(RuntimeError):
    def __init__(self, result: ProbeResult, carrier: str | None) -> None:
        super().__init__(result.detail)
        self.carrier = carrier


def _network_key() -> str:
    key, _ = detect_network()
    return "" if key == "default" else key


class DirectCoordinator:
    def __init__(self, directory: Path, pow_directory: Path, *,
                 status: Callable[[DirectStatus], None], log: Callable[[str], None]) -> None:
        self.store = DirectStore(directory)
        self._log = log
        self._report = status
        self._lock = threading.RLock()
        self._worker: threading.Thread | None = None
        self._stop = threading.Event()
        self._network_event = threading.Event()
        self._resume = threading.Event()
        self._pause_request = threading.Event()
        self._exit_refresh = threading.Event()
        self._paused = False
        self._pending_dns: DirectSettings | None = None
        self._session_vpn: bool | None = None
        self._proxy: WindowsProxy | None = None
        self._system_proxy_requested = False
        self._status = DirectStatus()
        self._carrier = DirectCarrier(self.store, identity_path(pow_directory), _network_key, log)

    @property
    def status(self) -> DirectStatus:
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
                raise RuntimeError("Direct's local proxy is not ready.")
            proxy.set_session_enabled(enabled)
            self._system_proxy_requested = enabled

    def _restore_system_proxy(self, proxy: WindowsProxy) -> None:
        with self._lock:
            self._proxy = None
            proxy.restore_session()

    def connect(self, options: DirectOptions, *, settings: DirectSettings | None = None) -> bool:
        with self._lock:
            if self._worker is not None:
                return False
            if options.socks_port and options.socks_port == options.http_port:
                raise ValueError("Direct SOCKS and HTTP ports must differ")
            self._stop = threading.Event()
            self._network_event.clear()
            self._resume.clear()
            self._pause_request.clear()
            self._exit_refresh.clear()
            self._paused = False
            self._pending_dns = None
            self._session_vpn = options.vpn
            self._system_proxy_requested = not options.vpn if options.system_proxy is None else options.system_proxy
            self._status = DirectStatus(phase="starting", progress=5)
            settings = settings if settings is not None else self.store.settings()
            output = "VPN" if options.vpn else "Proxy"
            method = "WireGuard over Direct" if settings.wireguard_over_direct else "Direct TLS"
            self._log(f"Direct connecting: {method} ({output})")
            self._worker = threading.Thread(target=self._run, args=(options, settings),
                                            name="direct-session", daemon=True)
            self._report(self._status)
            self._worker.start()
            return True

    def disconnect(self) -> None:
        with self._lock:
            if self._worker is not None:
                if not self._stop.is_set():
                    self._log("Direct disconnecting")
                self._stop.set()
                self._publish(phase="stopping", detail="Closing Direct session")
            elif self._status != DirectStatus():
                self._status = DirectStatus()
                self._report(self._status)

    def notify_resume(self) -> None:
        self._resume.set()
        self._network_event.set()

    def request_exit_refresh(self) -> None:
        with self._lock:
            if self._status.phase in ("connected", "paused"):
                self._exit_refresh.set()

    def reload_dns(self, settings: DirectSettings) -> bool:
        with self._lock:
            if self._worker is None or self._stop.is_set() or self._status.phase not in ("connected", "paused"):
                return False
            self._pending_dns = settings
            self._network_event.set()
            return True

    def set_paused(self, paused: bool, *, proxy_only: bool = False) -> bool:
        with self._lock:
            if proxy_only and self._session_vpn is not False:
                return False
            if self._status.phase not in ("connected", "paused") or self._paused == paused:
                return False
            self._paused = paused
            self._log("Direct pause requested" if paused else "Direct resume requested")
            self._pause_request.set()
            self._network_event.set()
            return True

    def wait(self, timeout: float) -> bool:
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

    def _run(self, options: DirectOptions, settings: DirectSettings) -> None:
        final = DirectStatus()
        stop_error = None
        guard = None
        notifications = None
        try:
            if options.vpn:
                require_admin()
            try:
                notifications = NetworkNotifications(self._network_event)
            except OSError as error:
                self._log(f"Direct network notifications unavailable: {error}")
            self.store.directory.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix="session-", dir=self.store.directory) as session:
                directory = Path(session)
                socks_port = options.socks_port or loopback_port()
                http_port = options.http_port or loopback_port()
                while http_port == socks_port:
                    http_port = loopback_port()
                recovered = False
                was_paused = False
                while True:
                    ensure_active(self._stop)
                    with self._lock:
                        if self._pending_dns is not None:
                            update, self._pending_dns = self._pending_dns, None
                            settings = replace(settings, auto_select_dns=update.auto_select_dns,
                                               pinned_dns=update.pinned_dns, unfiltered_dns=update.unfiltered_dns)
                    self._pause_request.clear()
                    if options.vpn and options.kill_switch:
                        if self._paused and guard:
                            guard.close()
                            guard = None
                            self._publish(protected=False)
                        elif not self._paused and guard is None:
                            psiphon = find_helper()
                            if psiphon is None:
                                raise OutputError("Direct VPN protection requires the packaged Psiphon helper")
                            guard = VpnKillSwitch(BIN / "uac-direct-guard.exe", DIRECT_NATIVE, psiphon,
                                                  direct_helpers=(DIRECT_XRAY, DIRECT_MASK))
                            self._publish(protected=True)
                    allow = guard.set_tunnel if guard else lambda _allowed: None
                    network = _network_key()
                    with ExitStack() as active:
                        route = self._connect_route(active, settings, options, directory, socks_port,
                                                    http_port, self._paused, allow)
                        ensure_active(self._stop)
                        proxy = WindowsProxy(self._log)
                        active.callback(self._restore_system_proxy, proxy)
                        tun_active = route.tun is not None
                        proxy.bind_session(http_port if tun_active else socks_port, http_port,
                                           enabled=self._system_proxy_requested, tun=tun_active)
                        self._proxy = proxy
                        ensure_active(self._stop)
                        if not route.healthy():
                            raise OutputError("Direct helper stopped before output activation")
                        if route.carrier:
                            try:
                                self._carrier.remember_verified(route.carrier)
                            except OSError as error:
                                self._log(f"Direct could not save the verified route: {error}")
                        self._publish(phase="paused" if self._paused else "connected", progress=100,
                                      detail="Direct connection paused" if self._paused else "Direct DNS and HTTPS verified",
                                      socks_port=socks_port, http_port=http_port, probe_port=route.probe_port,
                                      dns_lab_port=route.dns_lab_port)
                        if not self._stop.is_set():
                            self._log("Direct paused" if self._paused else
                                      "Direct resumed" if was_paused else "Direct connected")
                        was_paused = self._paused
                        reason = self._monitor(route, network, options, guard)
                        if reason in ("pause", "dns"):
                            recovered = False
                        elif recovered:
                            raise OutputError(f"Direct recovery stopped: {reason}")
                        else:
                            recovered = True
                            self._log(f"Direct recovering: {reason}")
                        self._publish(phase="recovering", detail="Applying the selected DNS" if reason == "dns" else reason, progress=5)
                    if reason not in ("pause", "dns"):
                        self._stop.wait(1)
        except DirectCancelled:
            pass
        except Exception as error:
            if self._stop.is_set():
                stop_error = error
                self._log(f"Direct disconnect failed: {error}")
            else:
                final = DirectStatus(phase="error", detail=str(error))
                self._log(f"Direct failed: {error}")
                if guard and guard.running and not self._paused:
                    try:
                        guard.set_tunnel(False)
                        self._publish(phase="error", progress=0, detail=f"{error}. VPN protection remains active.",
                                      protected=True, socks_port=0, http_port=0)
                        while guard.running and not self._stop.wait(0.25):
                            pass
                    except (OSError, RuntimeError) as guard_error:
                        self._log(f"Direct could not keep VPN protection active: {guard_error}")
        finally:
            try:
                if notifications:
                    notifications.close()
                if guard:
                    guard.close()
            except Exception as error:
                stop_error = error
                self._log(f"Direct cleanup failed: {error}")
            finally:
                with self._lock:
                    if self._stop.is_set():
                        self._log("Direct stopped")
                    if self._stop.is_set():
                        self._status = (DirectStatus(phase="error", detail=str(stop_error), disconnect_failed=True)
                                        if stop_error is not None else DirectStatus())
                    else:
                        self._status = final
                    self._worker = None
                    self._report(self._status)

    def _connect_route(self, active: ExitStack, settings: DirectSettings, options: DirectOptions,
                       directory: Path, socks_port: int, http_port: int, paused: bool,
                       allow_tunnel: Callable[[bool], None]) -> _Route:
        skip = None
        for _ in range(2):
            with ExitStack() as attempt:
                try:
                    route = self._start_route(attempt, settings, options, directory, socks_port,
                                              http_port, paused, allow_tunnel, skip)
                except _PayloadFailure as error:
                    if not error.carrier or skip:
                        what = " on the alternate route" if skip else ""
                        raise OutputError(f"Direct DNS or HTTPS check failed{what}: {error}") from error
                    skip = error.carrier
                    self._log(f"Direct payload failed via {skip}; trying another carrier: {error}")
                    continue
                active.enter_context(attempt.pop_all())
                return route
        raise OutputError("Direct could not establish a verified route")

    def _start_route(self, stack: ExitStack, settings: DirectSettings, options: DirectOptions,
                     directory: Path, socks: int, http: int, paused: bool,
                     allow_tunnel: Callable[[bool], None], skip: str | None) -> _Route:
        self._publish(phase="starting", progress=10, detail="Preparing Direct routes",
                      socks_port=0, http_port=0, resolver="", resolver_address="", dns_ms=0, carrier="", country="", exit_ip="",
                      tx_bytes=0, rx_bytes=0, probe_port=0, dns_lab_port=0, dns_udp_supported=True)
        carrier = None
        country = None
        resolve = None
        region = ""
        exit_port = 0
        if settings.wireguard_over_direct and not paused:
            self._publish(detail="Trying another carrier" if skip else "Preparing WireGuard over Direct")
            carrier = self._carrier.start(settings, self._stop, skip)
            stack.callback(carrier.close)
            exit_port = carrier.port
            region = settings.exit_country_code.upper()
            self._publish(carrier=carrier.selected_peer or "", dns_udp_supported=not region)
            if region:
                exit_port = loopback_port()

        def country_exit():
            self._publish(progress=60 if not settings.auto_select_dns else 35,
                          detail=f"Connecting selected exit {region}")
            helper = start_country(self.store.directory / "country", carrier.port, exit_port, region,
                                   self._stop, self._log)
            stack.callback(helper.stop)
            return helper

        if settings.auto_select_dns and not paused:
            if region:
                country = country_exit()
            self._publish(progress=45, detail="Testing secure DNS")
            selection = select_dns(exit_port, self._stop)
            if selection:
                resolve, latency = selection
                self._publish(resolver=resolve.label, resolver_address=resolve.url, dns_ms=latency)
            else:
                self._log("Direct resolver selection had no usable result; using configured DNS")
        elif settings.pinned_dns and not paused:
            resolve = parse_resolver(settings.pinned_dns)
            if region and resolve.protocol == "UDP":
                self._log("Direct selected country does not support UDP DNS; using fallback DNS")
                resolve = None
            else:
                self._publish(resolver=resolve.label, resolver_address=resolve.url)
        if resolve:
            self._log(f"Direct DNS preference: {resolve.label} ({resolve.protocol})")

        self._publish(progress=50, detail="Starting Direct Xray routes")
        masks = start_masks(directory, settings.ipv6, stack, self._stop, self._log) if not carrier and not paused else {}
        stats_port, probe_port, dns_lab_port = loopback_ports(3, exclude=(socks, http, exit_port, *masks.values()))
        native_http = 0 if options.vpn and not paused else http
        guarded = options.vpn and options.kill_switch and not paused
        routing_settings = replace(settings, iran_direct=False, domains_direct="", ips_direct="") if guarded else settings
        for noise in ((True, False) if settings.udp_noise else (False,)):
            config = build_config(routing_settings, socks, http_port=native_http, stats_port=stats_port,
                                  probe_port=probe_port, dns_lab_port=dns_lab_port,
                                  exit_port=exit_port, country_exit=bool(region),
                                  session_dns=resolve, paused=paused, noise_allowed=noise,
                                  mask_ports=masks, whitelist=() if guarded else options.whitelist)
            try:
                xray = start_xray(directory, config, socks, native_http, self._stop, self._log)
                stack.callback(xray.close)
                break
            except OutputError:
                if not noise:
                    raise
                self._log("Direct retrying Xray startup with UDP noise disabled")
        tun = None
        if options.vpn and not paused:
            tun = start_tun(directory, settings, socks, options.dns_server, options.routing_mode,
                            options.processes, options.mtu, _physical_uplink_mtu(), self._stop,
                            self._log, allow_tunnel, privacy=options.privacy, proxy_port=http)
            stack.callback(tun.close)
            stack.callback(allow_tunnel, False)
        if region and not settings.auto_select_dns:
            country = country_exit()

        self._publish(phase="checking", progress=75, detail="Checking DNS and HTTPS payload")
        rounds = 8 if region else 3 if settings.adaptive_client_hello else 2
        for index in range(rounds):
            result = verify_payload(probe_port, options.dns_server, self._stop)
            if result.ok and http:
                output = verify_http_proxy(http)
                result = ProbeResult(output.ok, f"{result.detail}; {output.detail}")
            if result.ok and tun:
                output = verify_tun(probe_port, options.dns_server, bool(carrier), self._stop)
                result = ProbeResult(output.ok, f"{result.detail}; {output.detail}")
            if result.ok:
                break
            self._log(f"Direct startup check {index + 1}/{rounds} failed: {result.detail}")
            if index + 1 < rounds:
                self._stop.wait(1 if region else 0.3)
        ensure_active(self._stop)
        if not result.ok:
            peer = carrier.selected_peer if carrier else None
            raise _PayloadFailure(result, peer.partition(":")[0] if peer else None)
        self._log(f"Direct DNS and HTTPS verified: {result.detail}")
        self._read_exit(probe_port, region)
        traffic = SessionTraffic()
        counts = xray_traffic(DIRECT_XRAY, stats_port)
        if counts is not None:
            traffic.update({stats_port: counts})
        return _Route(socks, http, stats_port, probe_port, dns_lab_port, traffic, bool(carrier), carrier, xray, tun, country)

    def _read_exit(self, socks: int, region: str = "", *, manual=False) -> None:
        try:
            exit_trace = trace(socks)
            ip = exit_trace.get("ip", "")
            country = region or exit_trace.get("loc", "")
            if manual and not ip:
                raise OSError("No public IP returned by the route")
            self._publish(country=country, exit_ip=ip)
            if manual and not self._stop.is_set():
                self._log(f"Direct public IP: {ip} ({country or 'unknown'})")
        except (OSError, http.client.HTTPException) as error:
            self._log(f"Direct exit details unavailable: {error}")

    def _monitor(self, route: _Route, network: str, options: DirectOptions,
                 guard: VpnKillSwitch | None) -> str:
        due = time.monotonic() + 8
        stats_due = time.monotonic()
        failures = 0
        while True:
            ensure_active(self._stop)
            if self._pause_request.is_set():
                return "pause"
            if self._pending_dns is not None and not self._paused:
                return "dns"
            if guard and not guard.running:
                raise OutputError("Direct VPN protection stopped")
            if not route.healthy():
                return "A Direct connection helper stopped"
            if self._exit_refresh.is_set():
                self._exit_refresh.clear()
                self._read_exit(route.probe_port, manual=True)
            if self._network_event.is_set():
                self._network_event.clear()
                resumed = self._resume.is_set()
                self._resume.clear()
                current = _network_key()
                if current and current != network:
                    return "The Windows uplink changed"
                if resumed:
                    due = time.monotonic()
            now = time.monotonic()
            if now >= stats_due:
                counts = xray_traffic(DIRECT_XRAY, route.stats_port)
                if counts is not None:
                    upload, download = route.traffic.update({route.stats_port: counts})
                    self._publish(tx_bytes=upload, rx_bytes=download)
                stats_due = time.monotonic() + 2
            if now < due:
                self._stop.wait(min(0.25, due - now))
                continue
            if route.tun:
                result = verify_tun(route.probe_port, options.dns_server, route.is_chained, self._stop)
            elif failures == 0:
                result = verify_https("https://www.cloudflare.com/cdn-cgi/trace", route.probe_port, timeout=2)
                if not result.ok:
                    result = verify_payload(route.probe_port, options.dns_server, self._stop)
            else:
                result = verify_payload(route.probe_port, options.dns_server, self._stop)
            if result.ok:
                failures = 0
                due = time.monotonic() + 30
            else:
                failures += 1
                self._log(f"Direct health check {failures}/3 failed: {result.detail}")
                if failures == 3:
                    return f"Direct health checks failed: {result.detail}"
                due = time.monotonic() + 10
