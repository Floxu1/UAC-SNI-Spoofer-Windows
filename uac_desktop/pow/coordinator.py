"""PoW connection coordinator — Windows port of ``PowConnectionCoordinator``.

Same order of operations as mobile:

1. Raise the outer aether leg (MASQUE / WoW / WireGuard ladder, per-plan
   budgets, scan-once so one failed hunt returns to Python).
2. Start the Psiphon inner hop through it (strategy ladder, remembered
   winner first, region-pinned attempt first when an exit country is set).
   WARP-only mode skips Psiphon.
3. Expose the exit: Windows System Proxy (default, like the desktop engine)
   or whole-device TUN through sing-box pointed at the exit SOCKS.

Never runs alongside the Xray engine: the UI disconnects Xray before a PoW
connect and refuses the reverse while PoW is up (same rule as mobile —
never two engines at once).
"""

from __future__ import annotations

import hashlib
import json
import math
import socket
import subprocess
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable

from . import runner as runner_module
from .config import (
    CHAIN_SOCKS_PORT,
    DISCOVERY_CACHE,
    DISCOVERY_FRESH,
    PSIPHON_SOCKS_PORT,
    RECIPE_MASQUE_H2_SAVED,
    SCAN_TURBO,
    LastConnect,
    PowSettings,
    chain_outer_json,
    outer_budget_ms,
    outer_label,
    outer_plan,
    psiphon_config,
    uses_mci_firewall,
)
from .config import (
    H2_FRAG_AUTO,
    AdaptiveObfuscation,
    attempt_scan_mode,
    h2_fragment_effective,
    is_jitter_high,
    psiphon_wait_seconds,
)
from .identity import read_identity
from .psiphon import PsiphonProcess
from .regions import egress_region, region_name
from .runner import AetherProcess, prepare_identity, tcp_accepts
from . import speed as speed_module
from .status import PowPhase, PowStatusStore, stage_line
from .warmup import PROBE_TARGETS, PathWarmup, measure_path

LogCallback = Callable[[str], None]

#: Local HTTP CONNECT forwarder (Windows proxy needs http+https+socks).
FORWARD_HTTP_PORT = 1822
POW_HELPER_PROCESSES = ("aether.exe", "uac-psiphon.exe", "uac_psiphon.exe")
#: Give the exit SOCKS a moment to serve before the proxy points at it.
_EXIT_GRACE_SECONDS = 1.0
#: A new connect waits this long for the previous attempt (or a watchdog
#: reconnect) to unwind before it takes over the helpers and ports.
_PREVIOUS_WORK_WAIT_S = 30.0
#: Tunnel RTT probe: SOCKS CONNECT through Psiphon (granted after the
#: server opened the port forward, so it measures the whole chain).
_RTT_PROBE_TARGET = ("www.gstatic.com", 443)
_RTT_PROBE_SAMPLES = 3
_INNER_RETUNE_TIMEOUT_S = 20

_DEFAULT_UPLINK = (
    "$r=Get-NetRoute -DestinationPrefix @('0.0.0.0/0','::/0') -ErrorAction SilentlyContinue | "
    "Where-Object { $_.InterfaceAlias -notlike 'UAC-Spoofer*' } | "
    "Sort-Object { $_.RouteMetric + $_.InterfaceMetric } | Select-Object -First 1; "
)
_NETWORK_SCRIPT = _DEFAULT_UPLINK + (
    "if ($r) { $n=Get-NetNeighbor -InterfaceIndex $r.ifIndex -IPAddress $r.NextHop -ErrorAction SilentlyContinue | Select-Object -First 1; "
    "$p=Get-NetConnectionProfile -InterfaceIndex $r.ifIndex -ErrorAction SilentlyContinue | Select-Object -First 1; "
    "'{0}|{1}|{2}|{3}' -f $r.InterfaceAlias,$r.NextHop,$n.LinkLayerAddress,$p.Name }"
)

_UPLINK_MTU_SCRIPT = _DEFAULT_UPLINK + (
    "if ($r) { (Get-NetIPInterface -InterfaceIndex $r.ifIndex -AddressFamily $r.AddressFamily "
    "-ErrorAction SilentlyContinue | Select-Object -First 1).NlMtu }"
)


def _query_uplink(script: str) -> str:
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        line = (result.stdout or "").strip().splitlines()
        return line[-1] if line and result.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _physical_uplink_mtu() -> int:
    try:
        return int(_query_uplink(_UPLINK_MTU_SCRIPT))
    except ValueError:
        return 0


def detect_network() -> tuple[str, str]:
    """Identify the current uplink by gateway MAC and network profile."""
    parts = _query_uplink(_NETWORK_SCRIPT).split("|")
    if len(parts) < 4:
        return "default", "unknown network"
    alias, hop, mac, profile = (part.strip() for part in parts[:4])
    identity = f"{(mac or hop).lower()}|{profile}"
    if not (mac or hop or profile):
        return "default", "unknown network"
    key = hashlib.sha1(identity.encode("utf-8")).hexdigest()[:12]
    label = profile or alias or "network"
    return key, label


class PowEngineError(RuntimeError):
    pass


MCI_WG_BUDGET_MS = 20_000


class PowCoordinator:
    def __init__(
        self,
        data_dir: Path,
        store,
        status: PowStatusStore | None = None,
        log: LogCallback | None = None,
    ) -> None:
        self._data_dir = Path(data_dir)
        self._store = store
        self._status = status or PowStatusStore()
        self._log = log or (lambda _message: None)
        self._warmup = PathWarmup(store, self._emit_log)
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._epoch = 0
        self._aether = AetherProcess(on_log=self._on_native_log)
        self._psiphon = PsiphonProcess(on_notice=self._on_psiphon_notice)
        self._forwarder = None
        self._proxy = None
        # Local HTTP port for the Windows proxy, read from the store per connect.
        self._forward_port = FORWARD_HTTP_PORT
        # Psiphon local SOCKS (the exit SOCKS when chained), read per connect.
        self._psiphon_port = PSIPHON_SOCKS_PORT
        # True once this coordinator pointed the Windows proxy at itself; the
        # user's original proxy values are restored on disconnect.
        self._proxy_session = False
        self._system_proxy_requested = False
        self._tun_process: subprocess.Popen | None = None
        self._tun_job = None
        self._kill_switch = None
        self._site_log = None
        self._tun_fell_back = False
        self._bypass_processes: list[str] = []
        self._watchdog: threading.Thread | None = None
        self._dialing = ""
        # Speed options state (all idle when the toggles are off).
        self._speed = PowSettings()
        self._extras: list = []
        self._router = None
        self._chain_port = CHAIN_SOCKS_PORT
        self._accepted_peers: list[str] = []
        self._won_peer = ""
        self._h3_transport = ""
        self._exit_info: dict = {}
        self._sessions: list[dict] = []
        self._parallel_note = ""
        self._parallel_cancel = threading.Event()
        self._main_restart_owner = None
        self._parallel_thread = None
        self._connected = threading.Event()
        self._exit_port = 0
        self._exit_region = ""
        self._inner_config = ""
        self._inner_strategy = ""
        self._lan_process = None
        self._lan_config = None
        self._lan_endpoint = ("", "")
        self._lan_error = ""
        self._inner_router = None
        self._psiphon_secondary = None
        self._psiphon_ghost = None
        self._ghost_serving = False
        self._ghost_next_primary_retry = 0.0
        self._outer_label = ""
        self._direct_psiphon = False
        self._warp_only = False
        self._proxy_mode = True
        self._paused = False
        self._network_key = "default"
        self._network_label = ""
        self._network_ready = threading.Event()
        self._network_detector = detect_network
        # Overlapping-reconnect guard: each connect / watchdog thread records
        # the epoch it works for; a newer connect waits for older work to end.
        self._tls = threading.local()
        # Serialises everything that tears down / brings up the exit (TUN or
        # Windows proxy): live mode switch, watchdog reconnect, disconnect.
        self._exit_lock = threading.RLock()
        self._exit_control = threading.Lock()
        self._path_cancel = threading.Event()
        self._route_pending = threading.Event()
        self._network_changed = threading.Event()
        self._retune_lock = threading.RLock()
        self._resumed = threading.Event()
        self._work_cv = threading.Condition()
        self._work_count = 0
        self._adaptive = AdaptiveObfuscation(self._data_dir, log=self._emit_log)

    # -- state ------------------------------------------------------------
    @property
    def status(self) -> PowStatusStore:
        return self._status

    @property
    def running(self) -> bool:
        return self._connected.is_set()

    @property
    def actual_proxy_mode(self) -> bool | None:
        """True for Windows proxy, False for TUN, None without an active route."""
        if (not self._connected.is_set() or self._paused or self._path_cancel.is_set()
                or self._route_pending.is_set()):
            return None
        return self._proxy_mode

    @property
    def session_proxy_mode(self) -> bool | None:
        """Selected output, including while the session is paused."""
        return self._proxy_mode if self._connected.is_set() else None

    @property
    def system_proxy_enabled(self) -> bool | None:
        proxy = self._proxy
        return proxy.session_enabled if proxy is not None else None

    def set_system_proxy_enabled(self, enabled: bool) -> None:
        if not self._exit_lock.acquire(blocking=False):
            raise RuntimeError("PoW is updating its route. Try again when connected.")
        try:
            proxy = self._proxy
            if proxy is None or self.actual_proxy_mode is None or self._stop.is_set():
                raise RuntimeError("PoW's local proxy is not ready.")
            self._proxy_session = True
            proxy.set_session_enabled(enabled)
            self._system_proxy_requested = enabled
        finally:
            self._exit_lock.release()

    @property
    def protected(self) -> bool:
        guard = self._kill_switch
        return guard is not None and guard.running

    def _ensure_kill_switch(self) -> None:
        if self._proxy_mode or self._paused or not self._speed.kill_switch or self.protected:
            return
        from ..paths import BIN
        from .kill_switch import VpnKillSwitch
        from .psiphon import find_helper
        from .runner import find_aether_binary

        self._close_kill_switch()
        self._ensure_active()
        binary = BIN / "uac-pow-guard.exe"
        aether = find_aether_binary()
        psiphon = find_helper()
        if not binary.is_file() or aether is None or psiphon is None:
            raise PowEngineError("The VPN kill switch requires the bundled WFP, Aether and Psiphon helpers")
        try:
            self._kill_switch = VpnKillSwitch(binary, aether, psiphon)
        except (OSError, RuntimeError) as exc:
            raise PowEngineError(f"Could not activate the VPN kill switch: {exc}") from exc
        self._emit_log("VPN kill switch is active")

    def _allow_tun_under_guard(self) -> None:
        if self._kill_switch is not None:
            try:
                self._kill_switch.set_tunnel(True)
            except (OSError, RuntimeError) as exc:
                raise PowEngineError(f"Could not authorize the Windows TUN interface: {exc}") from exc

    def _close_kill_switch(self) -> None:
        guard, self._kill_switch = self._kill_switch, None
        if guard is not None:
            guard.close()

    @property
    def paused(self) -> bool:
        return self._paused

    @contextmanager
    def _change_exit(self, unchanged: Callable[[], bool]):
        """Cancel background path work before taking ownership of the system route."""
        epoch = self._epoch
        with self._exit_control:
            with self._lock:
                if self._epoch != epoch or not self.running or self._stop.is_set() or unchanged():
                    cancelled = None
                else:
                    cancelled = self._path_cancel
                    cancelled.set()
            if cancelled is None:
                yield False
                return
            previous_epoch = getattr(self._tls, "epoch", None)
            try:
                with self._exit_lock, self._session_work():
                    self._tls.epoch = epoch
                    yield self._epoch == epoch and self.running and not self._stop.is_set()
            finally:
                self._tls.epoch = previous_epoch
                with self._lock:
                    if (self._epoch == epoch and self._path_cancel is cancelled
                            and not self._stop.is_set()):
                        self._path_cancel = threading.Event()

    def _queue_route_recovery(self) -> None:
        self._route_pending.set()
        self._status.update(
            PowPhase.OUTER, 30, "Restoring the selected route", outer_label=self._outer_label
        )

    def _exit_legs_alive(self) -> bool:
        if (self._warp_only or not self._direct_psiphon) and not self._aether.running:
            return False
        if self._warp_only:
            return True
        if self._ghost_serving and self._psiphon_ghost is not None:
            return self._psiphon_ghost.running
        return self._psiphon.running

    def _can_rebind_exit(self, verify_payload: bool) -> bool:
        if not self._exit_legs_alive():
            return False
        if not verify_payload:
            return True
        from .tun_guard import verify_proxy

        ok, _ = verify_proxy(self._exit_port, "socks5h", timeout=2, stop=self._stop)
        self._ensure_active()
        return ok

    def set_paused(self, paused: bool | None, *, proxy_only: bool = False) -> None:
        """Apply a pause state, or toggle under the route lock for a UI click."""
        def unchanged():
            return ((paused is not None and self._paused == paused)
                    or (proxy_only and (not self._proxy_mode or self._status.snapshot().phase not in
                                       (PowPhase.CONNECTED, PowPhase.PAUSED))))

        with self._change_exit(unchanged) as owned:
            paused = not self._paused if paused is None else paused
            if not owned or self._paused == paused:
                return
            epoch = self._epoch
            self._ensure_active()
            if paused:
                if self._status.snapshot().phase != PowPhase.CONNECTED:
                    self._route_pending.set()
                self._paused = True
                self._teardown_exit()
                self._restore_windows_proxy()
                self._close_kill_switch()
                self._status.update(PowPhase.PAUSED, 100, "PoW paused · traffic uses the network directly")
                self._emit_log("PoW paused · Windows proxy restored")
                return
            try:
                self._paused = False
                self._status.update(PowPhase.BRIDGING, 80, "Restoring the selected route")
                self._ensure_kill_switch()
                if not self._can_rebind_exit(verify_payload=self._route_pending.is_set()):
                    if not self._proxy_mode:
                        self._require_tun_admin()
                    self._queue_route_recovery()
                    return
                if self._proxy_mode and self._inner_router is not None and not self._ghost_serving:
                    self._stop_inner_pool()
                    self._exit_port = self._psiphon_port
                elif (not self._proxy_mode and not self._warp_only
                      and self._inner_router is None):
                    self._start_inner_pool()
                if self._proxy_mode:
                    self._enable_proxy()
                else:
                    self._enable_tun()
                self._ensure_active()
                self._route_pending.clear()
                self._paused = False
                self.apply_lan_share()
                self._status.update(PowPhase.CONNECTED, 100, "UAC PoW ready", outer_label=self._outer_label)
                self._emit_log("PoW resumed · proxy path verified" if proxy_only else "PoW resumed")
                self._warm_path()
            except Exception as exc:
                self._paused = False
                if self._epoch == epoch and not self._stop.is_set():
                    self._fail(f"Could not resume PoW: {exc}")
                raise

    def switch_exit_mode(self, target) -> str:
        """Live TUN <-> Windows proxy switch while connected.

        The old exit is really torn down (sing-box TUN stopped / system proxy
        restored) before the new one starts; the legs stay up. ``target`` may be
        a callable so several quick clicks converge on the latest choice.
        """
        def requested_proxy() -> bool | None:
            return target() if callable(target) else target

        with self._change_exit(lambda: requested_proxy() in (None, self._proxy_mode)) as owned:
            want_proxy = requested_proxy()
            if not owned or want_proxy is None:
                return "unchanged" if self.running and want_proxy == self._proxy_mode else "idle"
            if self._paused:
                self._proxy_mode = want_proxy
                return "paused"
            current = self._proxy_mode
            if current == want_proxy:
                if self._status.snapshot().phase == PowPhase.OUTER:
                    self._queue_route_recovery()
                return "unchanged"
            names = {True: "Windows proxy", False: "TUN"}
            self._emit_log(f"Switching exit {names[current]} -> {names[want_proxy]} while connected")
            recovering = self._route_pending.is_set() or self._status.snapshot().phase == PowPhase.OUTER
            try:
                self._ensure_active()
                self._status.update(PowPhase.BRIDGING, 80, f"Switching to {names[want_proxy]}")
                self._teardown_exit()
                self._proxy_mode = want_proxy
                self._tun_fell_back = False
                if want_proxy:
                    self._close_kill_switch()
                else:
                    self._ensure_kill_switch()
                if not self._can_rebind_exit(verify_payload=recovering):
                    if not want_proxy:
                        self._require_tun_admin()
                    self._queue_route_recovery()
                    return "pending"
                if not self._warp_only and not self._ghost_serving:
                    self._stop_inner_pool()
                    self._exit_port = self._psiphon_port
                    self._start_inner_pool()
                if want_proxy:
                    self._enable_proxy()
                else:
                    self._enable_tun()
                self._ensure_active()
            except Exception as exc:
                if self._stop.is_set() or self._owner_epoch_stale():
                    return "stopped"
                self._fail(f"exit switch failed: {exc}")
                return "failed"
            self._status.update(PowPhase.CONNECTED, 100, "UAC PoW ready", outer_label=self._outer_label)
            self._route_pending.clear()
            self.apply_lan_share()
            self._warm_path()
            self._emit_log(f"Exit now: {names[want_proxy]}")
            return "proxy" if want_proxy else "tun"

    @property
    def lan_share_status(self) -> tuple[str, str]:
        process = self._lan_process
        settings = self._lan_config
        address, _ = self._lan_endpoint
        if process is not None and process.poll() is None and settings is not None:
            return f"{address}:{settings.lan_share_port}", ""
        return "", self._lan_error

    def apply_lan_share(self, settings: PowSettings | None = None) -> None:
        from . import lan_share

        with self._exit_lock:
            if settings is not None:
                self._lan_config = settings
            self._stop_lan_share()
            self._lan_error = ""
            settings = self._lan_config
            if not settings or not settings.lan_share or not self._connected.is_set() or self._paused:
                return
            try:
                self._ensure_active()
                proc, endpoint = lan_share.start(self._data_dir, settings, self._exit_port, self._stop)
                self._lan_process = proc
                self._lan_endpoint = endpoint
                self._emit_log(f"LAN share ({settings.lan_share_mode}): {endpoint[0]}:{settings.lan_share_port}")
            except Exception as exc:
                self._lan_error = str(exc)
                self._emit_log(f"LAN share unavailable: {exc}")

    def _check_lan_interface(self) -> None:
        from .lan_share import endpoint

        process = self._lan_process
        if process is None:
            return
        try:
            current = endpoint()
        except (RuntimeError, OSError, subprocess.TimeoutExpired):
            current = None
        with self._exit_lock:
            if self._lan_process is not process:
                return
            if process.poll() is not None or current != self._lan_endpoint:
                self._stop_lan_share()
                self._lan_error = "The private network or LAN listener is no longer available."
                self._emit_log(f"LAN share stopped: {self._lan_error}")

    def _stop_lan_share(self) -> bool:
        with self._exit_lock:
            if self._lan_process is not None:
                from .lan_share import close
                proc, self._lan_process = self._lan_process, None
                try:
                    close(proc)
                except (OSError, subprocess.TimeoutExpired) as exc:
                    self._emit_log(f"Could not stop the LAN listener: {exc}")
                    return False
        return True

    def _teardown_exit(self) -> bool:
        """Stop whatever carries the exit: sing-box (TUN or App Bypass proxy),
        the HTTP forwarder and the Windows system proxy."""
        success = True
        proxy, self._proxy = self._proxy, None
        if proxy is not None:
            try:
                proxy.suspend()
            except Exception:
                success = False
        self._warmup.cancel()
        success = self._stop_tun_process() is not False and success
        success = self._stop_lan_share() is not False and success
        forwarder, self._forwarder = self._forwarder, None
        if forwarder is not None:
            try:
                forwarder.stop()
            except Exception:
                success = False
        return success

    @property
    def exit_port(self) -> int:
        return self._exit_port

    def traffic_sources(self):
        # In a chain the inner leg carries the user's traffic; counting Aether
        # there too would add the same payload again with tunnel overhead.
        lanes = (self._aether,) if self._warp_only else (
            self._psiphon, self._psiphon_secondary, self._psiphon_ghost,
        )
        sources = {}
        for lane in lanes:
            if lane is not None:
                owner, counts = lane.traffic_snapshot()
                if owner is not None:
                    sources[owner] = counts
        return sources

    @property
    def forward_http_port(self) -> int:
        """Local HTTP port the Windows proxy uses for this session."""
        return int(self._forward_port or FORWARD_HTTP_PORT)

    @property
    def psiphon_socks_port(self) -> int:
        return int(self._psiphon_port or PSIPHON_SOCKS_PORT)

    def _configured_psiphon_port(self) -> int:
        try:
            return int(self._store.psiphon_socks_port())
        except Exception:
            return PSIPHON_SOCKS_PORT

    def _configured_forward_port(self) -> int:
        try:
            return int(self._store.proxy_http_port())
        except Exception:
            return FORWARD_HTTP_PORT

    def _restore_windows_proxy(self) -> bool:
        """Give the user back their own proxy values after a PoW session."""
        if not self._proxy_session:
            return True
        self._proxy_session = False
        try:
            from ..engine import WindowsProxy

            proxy = WindowsProxy(log=self._emit_log)
            if proxy.disable() is False and proxy.has_pending_restore:
                return False
        except Exception as exc:
            self._emit_log(f"Windows proxy restore pending: {exc}")
            return False
        return True

    @property
    def exit_region(self) -> str:
        return self._exit_region

    @property
    def outer_label_text(self) -> str:
        return self._outer_label

    # -- public ------------------------------------------------------------
    def connect(
        self,
        settings: PowSettings,
        proxy_mode: bool = True,
        bypass_processes: list[str] | None = None,
        *, cancel: threading.Event | None = None, system_proxy: bool | None = None,
    ) -> str:
        """Blocking connect. Raises PowEngineError on failure."""
        settings = settings.validated()
        with self._lock:
            if cancel is not None and cancel.is_set():
                raise PowEngineError("stopped")
            self._epoch += 1
            self._connect_epoch = self._epoch
            my_epoch = self._epoch
        self._tls.epoch = my_epoch
        self.disconnect(quiet=True, epoch=my_epoch)
        if self._wait_previous_work(my_epoch):
            # The older attempt may have started a helper after the first
            # cleanup ran; sweep once more now that it has unwound.
            self.disconnect(quiet=True, epoch=my_epoch)
        with self._lock:
            if self._epoch != my_epoch:
                raise PowEngineError("stopped")
            self._stop.clear()
            self._path_cancel = threading.Event()
            self._route_pending.clear()
            if cancel is not None and cancel.is_set():
                self.request_stop()
                raise PowEngineError("stopped")
        self._forward_port = self._configured_forward_port()
        self._psiphon_port = self._configured_psiphon_port()
        if self._psiphon_port != PSIPHON_SOCKS_PORT and (
                settings.chain_psiphon or settings.direct_psiphon_first):
            # Only a custom port is pre-checked; the default keeps today's path.
            from ..proxy_ports import busy_reason as _busy, is_app_helper as _ours

            problem = _busy(self._psiphon_port, _ours)
            if problem:
                raise PowEngineError(
                    f"Psiphon SOCKS port is not free: {problem}. "
                    "Change it in Network Tools > Proxy Port."
                )
        if proxy_mode:
            from ..proxy_ports import busy_reason, is_app_helper

            problem = busy_reason(self._forward_port, is_app_helper)
            if problem:
                raise PowEngineError(
                    f"Local proxy port is not free: {problem}. "
                    "Change it in Network Tools > Proxy Port."
                )
        try:
            with self._session_work():
                self._ensure_active()
                self._system_proxy_requested = proxy_mode if system_proxy is None else system_proxy
                return self._connect_session(settings, proxy_mode, bypass_processes)
        except Exception as exc:
            if self._epoch == my_epoch and not self._stop.is_set():
                reason = str(exc) or type(exc).__name__
                if not proxy_mode and settings.kill_switch:
                    try:
                        with self._exit_lock:
                            self._ensure_kill_switch()
                    except PowEngineError as guard_error:
                        if str(guard_error) != reason:
                            reason += f". {guard_error}"
                self.disconnect(quiet=True, epoch=my_epoch, keep_guard=self.protected)
                if self._epoch == my_epoch:
                    if self.protected:
                        reason += ". Kill switch is still active."
                    self._status.update(PowPhase.FAILED, 0, reason)
            raise

    # -- overlapping-reconnect guard ---------------------------------------
    def _owner_epoch_stale(self) -> bool:
        """True when this thread works for a connect that a newer one replaced."""
        mine = getattr(self._tls, "epoch", None)
        return mine is not None and mine != self._epoch

    def _session_work(self):
        coordinator = self

        class _Work:
            def __enter__(self_inner):
                with coordinator._work_cv:
                    coordinator._work_count += 1
                return self_inner

            def __exit__(self_inner, *_exc):
                with coordinator._work_cv:
                    coordinator._work_count -= 1
                    coordinator._work_cv.notify_all()
                return False

        return _Work()

    @contextmanager
    def _path_work(self, epoch: int):
        """Bind a background operation to the session and the current route intent."""
        previous_stop = getattr(self._tls, "path_stop", None)
        previous_epoch = getattr(self._tls, "epoch", None)
        with self._lock:
            stop = previous_stop if previous_stop is not None else self._path_cancel
        self._tls.path_stop = stop
        self._tls.epoch = epoch
        try:
            with self._session_work():
                yield stop
        finally:
            self._tls.path_stop = previous_stop
            self._tls.epoch = previous_epoch

    def _dial_stop(self):
        return getattr(self._tls, "path_stop", None) or self._stop

    def _wait_previous_work(self, epoch: int) -> bool:
        """Wait for an older connect / reconnect to stop. True if one was running."""
        with self._work_cv:
            if self._work_count <= 0:
                return False
            self._emit_log("Waiting for the previous UAC PoW attempt to stop")
            deadline = time.monotonic() + _PREVIOUS_WORK_WAIT_S
            while self._work_count > 0 and self._epoch == epoch:
                left = deadline - time.monotonic()
                if left <= 0:
                    self._emit_log("Previous UAC PoW attempt is still stopping; continuing")
                    break
                self._work_cv.wait(min(left, 0.5))
        return True

    def _connect_session(
        self,
        settings: PowSettings,
        proxy_mode: bool,
        bypass_processes: list[str] | None,
    ) -> str:
        status = self._status
        self._proxy_mode = proxy_mode
        self._tun_fell_back = False
        self._bypass_processes = [
            str(item).strip()
            for item in (bypass_processes or [])
            if str(item).strip()
        ]
        from .config import EXIT_CHAIN, EXIT_PSIPHON, EXIT_WARP, EXPERIMENTAL_H3_RECIPES

        self._start_network_detect()
        status = self._status
        status.reset()
        status.update(PowPhase.STARTING, 5, "Starting UAC PoW")

        self._speed = settings
        try:
            expired = self._store.expire_path_cache()
            if expired:
                self._emit_log(f"Expired {expired} learned WARP endpoint cache(s)")
        except OSError as exc:
            self._emit_log(f"Could not expire the WARP endpoint cache: {exc}")
        self._accepted_peers = []
        self._won_peer = ""
        self._h3_transport = ""
        self._chain_port = CHAIN_SOCKS_PORT
        mci = uses_mci_firewall(settings)
        plan = outer_plan(settings, mci)
        self._log_speed_options(settings, mci)
        experimental = settings.link_recipe in EXPERIMENTAL_H3_RECIPES
        psiphon_only = settings.exit_mode == EXIT_PSIPHON
        outer = None
        fast_direct = (
            settings.exit_mode == EXIT_CHAIN and not experimental
            and settings.direct_psiphon_first and self._try_direct_psiphon_fast(settings)
        )
        if not psiphon_only and not fast_direct:
            ordered = plan.protocols if plan.fixed_order else self._order_ladder(plan.protocols)
            ordered, preferred = self._apply_transport_choice(settings, plan, ordered)
            outer = self._raise_outer_leg(settings, plan.protocols, ordered, mci, preferred=preferred)
            if outer is not None and not experimental and not self._stop.is_set():
                self._start_parallel_masque(settings, mci)
        self._ensure_active()
        chain = settings.exit_mode != EXIT_WARP
        if outer is None and (not chain or (experimental and not psiphon_only)):
            raise PowEngineError("WARP did not come up")

        if not chain:
            outer_name = outer or "WARP"
            self._warp_only = True
            self._exit_port = self._chain_port
            self._outer_label = outer_name
        else:
            self._direct_psiphon = outer is None
            outer_name = outer or "Psiphon"
            if self._direct_psiphon and not fast_direct and not psiphon_only:
                self._emit_log("No WARP transport came up; Psiphon will connect on its own")
            self._ensure_active()
            status.update(
                PowPhase.INNER,
                55,
                "Starting Psiphon directly"
                if self._direct_psiphon
                else f"Starting Psiphon through {outer_name}",
                outer_label=outer_name,
            )
            self._outer_label = outer_name
            if not fast_direct:
                self._start_psiphon_tunnel(settings)
            self._exit_port = self._psiphon_port
            self._select_startup_route(settings, mci)
            self._start_inner_pool()

        with self._exit_lock:
            self._ensure_active()
            if proxy_mode:
                status.update(PowPhase.BRIDGING, 88, "Preparing the local PoW proxy")
                self._enable_proxy()
            else:
                status.update(PowPhase.BRIDGING, 90, "Routing device traffic through UAC PoW")
                self._enable_tun()
            self._ensure_active()

        self._store.save_last_connect(
            LastConnect(
                protocol="psiphon" if (chain and self._direct_psiphon) else self._last_outer_protocol or "psiphon",
                transport=self._won_transport,
                ip=self._won_ip,
                peer=self._won_peer,
                through_psiphon=chain,
            )
        )
        if chain:
            ready = (
                f"UAC PoW ready · Tunnel through Psiphon over {outer_name}"
                if not self._direct_psiphon
                else "UAC PoW ready · Tunnel through Psiphon"
            )
        else:
            ready = "UAC PoW ready · WARP only"
            if not proxy_mode:
                ready = "UAC PoW ready · Tunnel VPN through WARP"
        status.update(PowPhase.CONNECTED, 100, ready, outer_label=outer_name)
        self._emit_log(ready)
        self._connected.set()
        if not self._direct_psiphon:
            self._remember_h2_for_direct()
        self._start_watchdog()
        self.apply_lan_share(settings)
        self._start_adaptive_monitor()
        self._warm_path(force=True)
        if settings.lowest_rtt_ip:
            self._start_clean_ip_memory()
        self.refresh_exit_info(background=True)
        if proxy_mode or self._tun_fell_back:
            return f"UAC PoW ready · Proxy 127.0.0.1:{self._exit_port}"
        return ready

    def _remember_h2_for_direct(self) -> None:
        network = self._network_key
        snapshot = getattr(self._aether, "verified_h2_profile", lambda: None)()
        if not snapshot or not network or network == "default" or self._won_transport != "h2":
            return
        peer, config = snapshot
        epoch = self._epoch

        def record() -> None:
            try:
                current, _ = self._network_detector()
                if current == network and self._epoch == epoch and not self._stop.is_set():
                    from ..direct.store import DirectStore

                    DirectStore(self._data_dir.parent / "direct").save_verified("pow", network, peer, config)
            except (OSError, RuntimeError, ValueError):
                pass

        threading.Thread(target=record, name="pow-direct-profile", daemon=True).start()

    def request_stop(self) -> None:
        self._stop.set()
        self._path_cancel.set()

    def disconnect(
        self, quiet: bool = False, epoch: int | None = None, *, keep_guard: bool = False
    ) -> bool:
        with self._lock:
            if epoch is None:
                self._epoch += 1
            elif self._epoch != epoch:
                # A newer connect owns the processes. This cancel is stale.
                return False
            seen = self._epoch
            self.request_stop()
            self._route_pending.clear()
            self._connected.clear()
            self._paused = False
            watchdog, self._watchdog = self._watchdog, None
        with self._exit_lock:
            if self._epoch != seen:
                return False
            try:
                success = self._teardown_exit() is not False
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                self._emit_log(f"PoW output cleanup failed: {exc}")
                success = False
            success = self._restore_windows_proxy() is not False and success
            if not keep_guard:
                try:
                    self._close_kill_switch()
                except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                    self._emit_log(f"Could not close the PoW kill switch: {exc}")
                    success = False
            try:
                success = self._stop_inner_pool() is not False and success
            except Exception as exc:
                self._emit_log(f"PoW inner pool cleanup failed: {exc}")
                success = False
            self._inner_config = ""
            try:
                success = self._psiphon.stop() is not False and success
            except Exception:
                success = False
            try:
                success = self._aether.stop() is not False and success
            except Exception:
                success = False
            success = self._stop_parallel_masque() is not False and success
            self._exit_info = {}
            self._parallel_note = ""
            self._warmup.flush()
            self._exit_port = 0
            self._outer_label = ""
            self._exit_region = ""
            self._direct_psiphon = False
            self._warp_only = False
            self._last_outer_protocol = ""
            self._won_transport = ""
            self._won_ip = ""
            if not quiet:
                try:
                    self._status.reset()
                except Exception:
                    pass
        if watchdog is not None and watchdog is not threading.current_thread() and watchdog.is_alive():
            watchdog.join(timeout=2)
            success = not watchdog.is_alive() and success
        return success

    # -- outer leg ----------------------------------------------------------
    _last_outer_protocol: str = ""
    _won_transport: str = ""
    _won_ip: str = ""

    def forget_learned(self) -> None:
        self._warmup.forget()

    def _warm_path(self, *, force: bool = False) -> None:
        if (not self.running or self._stop.is_set() or self._paused
                or self._status.snapshot().phase != PowPhase.CONNECTED):
            return
        if self._proxy_mode and self._proxy is None:
            return
        if not self._proxy_mode and self._tun_process is None:
            return
        self._warmup.kick(self._exit_port, tun=not self._proxy_mode,
                          optimized=self._speed.optimized_mode,
                          iran_direct=self._speed.iran_direct, force=force)

    def _order_ladder(self, ladder: list[str]) -> list[str]:
        remembered = None
        try:
            remembered = self._store.remembered_outer_protocol()
        except Exception:
            remembered = None
        ordered = list(ladder)
        if remembered in ordered[1:]:
            ordered.remove(remembered)
            ordered.insert(1, remembered)
        return ordered

    def _apply_transport_choice(self, settings: PowSettings, plan, ordered: list[str]):
        """Honour Settings > WARP tunnel > Transport.

        The dial plan comes from Link recipe + firewall (Auto on Hamrah Aval =
        MASQUE HTTP/2 only). An explicit Transport choice is tried first and
        the plan stays as the fallback, so the default (Auto) is unchanged.
        An explicit Link recipe pins the protocol and wins over Transport.
        """
        from .config import OUTER_AUTO, OUTER_LADDER, RECIPE_AUTO

        choice = (settings.outer_transport or OUTER_AUTO).strip().lower()
        if choice == OUTER_AUTO or choice not in OUTER_LADDER:
            return ordered, ""
        label = outer_label(choice)
        if settings.link_recipe != RECIPE_AUTO:
            pinned = ", ".join(outer_label(p) for p in plan.protocols)
            self._emit_log(
                f"Transport {label} not used: Link recipe '{settings.link_recipe}' pins {pinned}"
            )
            return ordered, ""
        rest = [p for p in ordered if p != choice]
        if rest:
            self._emit_log(
                f"Transport: {label} first (your choice); then "
                f"{', '.join(outer_label(p) for p in rest)} ({plan.summary}) as the fallback"
            )
        else:
            self._emit_log(f"Transport: {label} (your choice)")
        return [choice] + rest, choice

    def _raise_outer_leg(
        self,
        settings: PowSettings,
        ladder: list[str],
        ordered: list[str],
        mci: bool,
        preferred: str = "",
        *,
        retune: bool = False,
        discovery: str = DISCOVERY_CACHE,
    ) -> str | None:
        stop = self._dial_stop()
        status = self._status
        plan = outer_plan(settings, mci)
        scan_mode = SCAN_TURBO if discovery == DISCOVERY_FRESH else settings.scan_mode
        for offset, protocol in enumerate(ordered):
            self._ensure_active()
            label = outer_label(protocol)
            # Mobile parity: the first MASQUE attempt runs the thorough scan
            # (180 s budget); later attempts use the user's scan mode.
            carried_h3 = protocol == "masque" and plan.masque_transport == "h3-over-h2"
            attempt_scan = scan_mode if carried_h3 else attempt_scan_mode(protocol, offset, scan_mode, retune)
            budget = outer_budget_ms(protocol, retune=retune and not carried_h3, scan_mode=attempt_scan)
            self._dialing = protocol
            if mci and protocol == "wireguard" and offset < len(ordered) - 1:
                # Plain WireGuard is UDP-only to Cloudflare and Hamrah Aval drops
                # it; one obfuscated hunt is enough before the fallback runs.
                budget = min(budget, MCI_WG_BUDGET_MS)
                self._emit_log(
                    "WireGuard on Hamrah Aval: UDP WireGuard to Cloudflare is usually "
                    f"blocked here; trying for {budget // 1000}s before falling back"
                )
            status.update(
                PowPhase.OUTER, 20 + offset * 10, f"Connecting {label}", outer_label=label
            )
            self._emit_log(
                f"Outer attempt {offset + 1}/{len(ordered)}: {label} "
                f"({budget // 1000}s, {attempt_scan})"
            )
            if protocol == "masque" and self._identity_ready():
                self._emit_log("Key: validating saved WARP identity and MASQUE certificate")
                try:
                    prepare_identity(self._data_dir, settings, protocol,
                                     on_log=self._on_native_log, stop=stop)
                except Exception as exc:
                    self._ensure_active()
                    self._emit_log(f"Cached MASQUE prepare failed: {exc}")
                    status.note("Saved WARP identity could not be prepared", True)
                    continue
            else:
                status.update(
                    PowPhase.OUTER, 15 + offset * 10, "Getting a WARP key", outer_label=label
                )
                error = self._fetch_key(settings, protocol, label)
                if stop.is_set():
                    return None
                if error is not None:
                    self._emit_log(f"{label} could not be prepared: {error}")
                    status.note(f"{label} key request failed", True)
                    continue
                status.update(
                    PowPhase.OUTER, 20 + offset * 10, f"Connecting {label}", outer_label=label
                )
            plan_now = plan
            h3_first = self._irancell_h3_applies(settings, mci, protocol)
            if protocol == "masque" and settings.lowest_rtt_ip:
                self._prefer_lowest_rtt_ip()
            self._emit_log(
                f"Connecting {label}"
                + (f" over HTTP/{'2' if plan_now.masque_transport == 'h2' else '3'}" if protocol == "masque" else "")
                + f" · IP scan {plan_now.ip_for(protocol)} · {attempt_scan}"
                + (" · split ClientHello" if plan_now.fragment and protocol == "masque" else "")
            )
            if protocol == "masque":
                self._log_h2_fragment(settings, plan_now)
            if h3_first:
                ready = self._dial_irancell_h3(settings, mci, attempt_scan, budget, discovery)
            else:
                outer_json = chain_outer_json(
                    self._data_dir,
                    protocol,
                    settings,
                    discovery=discovery,
                    scan_mode=attempt_scan,
                    mci=mci,
                )
                try:
                    with self._lock:
                        if self._epoch != self._connect_epoch or self._owner_epoch_stale():
                            raise PowEngineError("stopped")
                        if discovery == DISCOVERY_FRESH:
                            self._aether.start(outer_json, {"AETHER_QUICK_RECONNECT": "0"})
                        else:
                            self._aether.start(outer_json)
                except PowEngineError:
                    raise
                except Exception as exc:
                    self._emit_log(f"{label} could not start: {exc}")
                    if protocol == "masque":
                        status.note("Scan finished. Staying on this method.", True)
                        return None
                    continue
                ready = self._aether.wait_ready(CHAIN_SOCKS_PORT, budget, stop)
            if ready:
                self._ensure_active()
                try:
                    self._store.save_outer_protocol(protocol)
                except Exception:
                    pass
                self._last_outer_protocol = protocol
                plan = outer_plan(settings, mci)
                self._won_transport = (
                    (self._h3_transport or plan.masque_transport) if protocol == "masque" else ""
                )
                self._won_ip = (
                    settings.masque_ip_version if protocol == "masque" and settings.masque_ip_version != "auto"
                    else plan.ip_for(protocol)
                )
                if preferred and protocol != preferred:
                    wanted = outer_label(preferred)
                    self._emit_log(
                        f"{wanted} did not connect; fell back to {label}, which is carrying the outer leg"
                    )
                    return f"{label} ({wanted} failed, fell back)"
                self._emit_log(f"{label} is carrying the outer leg")
                return label
            if stop.is_set():
                if not self._owner_epoch_stale():
                    self._aether.stop()
                return None
            self._emit_log(f"{label} did not come up in {budget // 1000}s")
            try:
                self._aether.stop()
            except Exception:
                pass
            if protocol == "masque":
                # A finished MASQUE scan stays on this method: the certificate
                # retry already ran inside the core.
                status.note("Scan finished. Staying on this method.", True)
                return None
        return None

    # -- speed options (Settings > Speed; every one is off by default) ---------
    def _log_speed_options(self, settings: PowSettings, mci: bool) -> None:
        on = [
            name
            for flag, name in (
                (settings.parallel_masque, "parallel MASQUE"),
                (settings.irancell_h3, "HTTP/3 on Irancell"),
                (settings.direct_psiphon_first, "direct Psiphon first"),
                (settings.lowest_rtt_ip, "lowest-latency clean IP"),
            )
            if flag
        ]
        if not on:
            return
        self._emit_log("Speed options on: " + ", ".join(on))
        if settings.irancell_h3 and mci:
            self._emit_log(
                "HTTP/3 on Irancell: not used; this connect uses the Hamrah Aval plan "
                "(firewall MCI, or Auto, which counts as Hamrah Aval on desktop). Staying on HTTP/2"
            )

    def _irancell_h3_applies(self, settings: PowSettings, mci: bool, protocol: str) -> bool:
        from .config import RECIPE_AUTO

        if not settings.irancell_h3 or mci or protocol != "masque":
            return False
        if settings.link_recipe != RECIPE_AUTO:
            self._emit_log(
                f"HTTP/3 on Irancell: not used; Link recipe '{settings.link_recipe}' pins the transport"
            )
            return False
        return True

    def _dial_irancell_h3(
        self, settings: PowSettings, mci: bool, scan_mode: str, budget: int, discovery: str
    ) -> bool:
        """Irancell: MASQUE over HTTP/3 for a short window, then HTTP/2."""
        from .config import IRANCELL_H3_BUDGET_MS

        stop = self._dial_stop()
        h3_budget = min(budget, IRANCELL_H3_BUDGET_MS)
        self._h3_transport = ""
        for transport, window in (("h3", h3_budget), ("h2", budget)):
            self._ensure_active()
            if transport == "h3":
                self._emit_log(
                    f"HTTP/3 on Irancell: trying MASQUE over HTTP/3 for {window // 1000}s, then HTTP/2"
                )
            outer_json = chain_outer_json(
                self._data_dir,
                "masque",
                settings,
                discovery=discovery,
                scan_mode=scan_mode,
                mci=mci,
                masque_transport=transport,
            )
            try:
                with self._lock:
                    if self._epoch != self._connect_epoch or self._owner_epoch_stale():
                        raise PowEngineError("stopped")
                    if discovery == DISCOVERY_FRESH:
                        self._aether.start(outer_json, {"AETHER_QUICK_RECONNECT": "0"})
                    else:
                        self._aether.start(outer_json)
            except PowEngineError:
                raise
            except Exception as exc:
                self._emit_log(f"MASQUE over HTTP/{'3' if transport == 'h3' else '2'} could not start: {exc}")
                continue
            if self._aether.wait_ready(CHAIN_SOCKS_PORT, window, stop):
                self._ensure_active()
                self._h3_transport = transport
                self._emit_log(
                    "HTTP/3 on Irancell: HTTP/3 won"
                    if transport == "h3"
                    else "HTTP/3 on Irancell: HTTP/2 fallback won"
                )
                return True
            if stop.is_set():
                if not self._owner_epoch_stale():
                    self._aether.stop()
                return False
            try:
                self._aether.stop()
            except Exception:
                pass
            if transport == "h3":
                self._emit_log(
                    f"HTTP/3 on Irancell: HTTP/3 did not come up in {window // 1000}s; "
                    "falling back to MASQUE over HTTP/2"
                )
        return False

    def _try_direct_psiphon_fast(self, settings: PowSettings) -> bool:
        """Direct Psiphon fast mode: one short direct try; True = WARP skipped."""
        from dataclasses import replace

        from .config import DIRECT_FAST_BUDGET_S, psiphon_config

        if not settings.chain_psiphon:
            self._emit_log("Direct Psiphon first: skipped; Psiphon chain is off (WARP only)")
            return False
        self._ensure_active()
        self._network_ready.wait(1.0)
        network = self._network_key or "default"
        ladder, start, _reason = self._strategy_order(True, network)
        strategy = replace(ladder[start], timeout_seconds=DIRECT_FAST_BUDGET_S)
        inner_dir = self._data_dir / "uac-pow-inner"
        inner_dir.mkdir(parents=True, exist_ok=True)
        self._status.update(PowPhase.INNER, 10, "Trying Psiphon directly (fast mode)")
        self._emit_log(
            f"Direct Psiphon first: trying Psiphon without WARP for {DIRECT_FAST_BUDGET_S}s "
            f"via {strategy.name} ({strategy.label})"
        )
        config_json = psiphon_config(
            socks_port=self._psiphon_port,
            data_directory=str(inner_dir),
            preferred_region=egress_region(settings.exit_country_code) or None,
            strategy=strategy,
            optimized_mode=settings.optimized_mode,
            direct=True,
            iran_direct=settings.iran_direct,
        )
        started = time.monotonic()
        try:
            self._psiphon.start(
                config_json,
                self._data_dir,
                meek_only=bool(strategy.preferred_protocols)
                and all(p.startswith("FRONTED-") for p in strategy.preferred_protocols),
            )
        except Exception as exc:
            self._emit_log(f"Direct Psiphon first: could not start ({exc}); continuing with WARP + Psiphon")
            return False
        if self._psiphon.wait_connected(float(DIRECT_FAST_BUDGET_S), self._stop):
            self._ensure_active()
            self._inner_config = config_json
            self._direct_psiphon = True
            self._exit_region = getattr(self._psiphon, "server_region", "") or ""
            self._emit_log(
                f"Direct Psiphon first: direct Psiphon won in {time.monotonic() - started:.1f}s "
                f"via {strategy.name}; WARP skipped"
            )
            self._after_psiphon_connected(network, strategy.name, True, remember_region=False)
            return True
        try:
            self._psiphon.stop()
        except Exception:
            pass
        if not self._stop.is_set():
            self._emit_log(
                f"Direct Psiphon first: no direct connect in {DIRECT_FAST_BUDGET_S}s; "
                "continuing with WARP + Psiphon"
            )
        return False

    def _note_peer(self, text: str, peer: str) -> None:
        if text.startswith("Saved clean"):
            self._won_peer = peer
        if peer not in self._accepted_peers:
            self._accepted_peers.append(peer)
            del self._accepted_peers[:-16]

    def _clean_candidates(self, network: str) -> tuple[list[str], dict[str, int]]:
        saved = speed_module.read_clean_list(self._data_dir)
        try:
            pool = self._store.clean_pool(network)
        except Exception:
            pool = {}
        extra = [p for p in list(pool) + list(self._accepted_peers) if p not in saved]
        merged = list(dict.fromkeys(saved + extra))
        if len(merged) < 3:
            harvested = speed_module.harvest_core_log(self._data_dir)
            merged = list(dict.fromkeys(merged + harvested))
        return merged, pool

    def _prefer_lowest_rtt_ip(self) -> None:
        """Order the saved clean HTTP/2 list lowest-RTT first (capped wait)."""
        started = time.monotonic()
        self._network_ready.wait(speed_module.NETWORK_WAIT_S)
        network = self._network_key or "default"
        candidates, pool = self._clean_candidates(network)
        if len(candidates) < 2:
            self._emit_log(
                f"Lowest-latency IP: {len(candidates)} known clean address(es) on this network; "
                "normal order this time (addresses found now are measured for next time)"
            )
            return
        ranked = speed_module.rank_peers(candidates, speed_module.RANK_CAP_S)
        took = int((time.monotonic() - started) * 1000)
        if not ranked:
            self._emit_log(
                f"Lowest-latency IP: none of {len(candidates)} saved addresses answered within "
                f"{speed_module.RANK_CAP_S:.0f}s; normal order"
            )
            return
        saved = speed_module.read_clean_list(self._data_dir)
        try:
            speed_module.write_clean_list(
                self._data_dir, speed_module.ordered_clean_list(candidates, ranked)
            )
        except OSError as exc:
            self._emit_log(f"Lowest-latency IP: could not reorder the clean list ({exc})")
            return
        best, best_rtt = ranked[0]
        self._emit_log(
            f"Lowest-latency IP: measured {len(ranked)}/{len(candidates)} clean addresses in {took} ms; "
            f"{best} ({best_rtt} ms) goes first"
            + (f" (was {saved[0]})" if saved and saved[0] != best else "")
        )
        pool.update({peer: rtt for peer, rtt in ranked})
        try:
            self._store.save_clean_pool(network, pool, speed_module.POOL_LIMIT)
        except Exception:
            pass

    def _start_clean_ip_memory(self) -> None:
        """Remember accepted clean IPs per network and re-measure them while idle."""
        epoch = self._epoch

        def _work() -> None:
            network = self._network()
            try:
                pool = self._store.clean_pool(network)
                for peer in self._accepted_peers:
                    pool.setdefault(peer, 0)
                self._store.save_clean_pool(network, pool, speed_module.POOL_LIMIT)
            except Exception:
                pass
            last_best = ""
            while not self._stop.wait(speed_module.REMEASURE_PERIOD_S):
                if self._epoch != epoch or not self._connected.is_set():
                    return
                if self._tun_process is not None:
                    # Under TUN the probe would be answered by our own tunnel
                    # stack (1-14 ms, not real); measure only without TUN.
                    continue
                candidates, pool = self._clean_candidates(network)
                ranked = speed_module.rank_peers(candidates, 3.0)
                if not ranked or self._stop.is_set() or self._epoch != epoch:
                    continue
                pool.update({peer: rtt for peer, rtt in ranked})
                try:
                    self._store.save_clean_pool(network, pool, speed_module.POOL_LIMIT)
                    speed_module.write_clean_list(
                        self._data_dir, speed_module.ordered_clean_list(candidates, ranked)
                    )
                except Exception:
                    continue
                best, rtt = ranked[0]
                if best != last_best:
                    last_best = best
                    self._emit_log(
                        f"Lowest-latency IP: re-measured {len(ranked)} addresses; best on this network "
                        f"is {best} ({rtt} ms), used first on the next connect"
                    )

        threading.Thread(target=_work, name="pow-clean-ip-memory", daemon=True).start()

    def _make_extra_aether(self):
        from collections import deque

        lines: deque = deque(maxlen=20)
        process = AetherProcess(on_log=lambda line: lines.append(line))
        process.last_lines = lines
        return process

    def _parallel_skip(self, reason: str) -> None:
        self._parallel_note = reason
        self._emit_log(f"Parallel MASQUE: {reason}")

    def _start_parallel_masque(self, settings: PowSettings, mci: bool) -> None:
        """Parallel MASQUE: a sticky router in front of the main session now;
        extra HTTP/2 sessions join it in the background as soon as they are up,
        so the first connect gets them too and nothing reconnects."""
        self._parallel_note = ""
        if not settings.parallel_masque:
            return
        if self._last_outer_protocol != "masque" or (self._won_transport or "h2") != "h2":
            self._parallel_skip("only for MASQUE over HTTP/2; staying on one session")
            return
        router = speed_module.StickyRouter(
            speed_module.ROUTER_PORT, [CHAIN_SOCKS_PORT], log=self._emit_log
        )
        try:
            router.start()
        except OSError as exc:
            self._parallel_skip(f"router could not listen ({exc}); staying on one session")
            return
        try:
            with self._lock:
                self._ensure_active()
                self._router = router
                self._parallel_cancel = stop = threading.Event()
                self._chain_port = speed_module.ROUTER_PORT
                self._sessions = [{"port": CHAIN_SOCKS_PORT, "peer": self._won_peer, "process": None}]
        except PowEngineError:
            router.stop()
            raise
        self._parallel_note = "looking for more clean addresses…"
        self._emit_log(
            f"Parallel MASQUE: router on 127.0.0.1:{speed_module.ROUTER_PORT} in front of the main session; "
            "extra sessions join in the background (no reconnect)"
        )
        epoch = self._epoch
        thread = threading.Thread(
            target=self._grow_parallel, args=(settings, mci, epoch, stop), name="pow-parallel-grow", daemon=True
        )
        self._parallel_thread = thread
        thread.start()

    def _parallel_alive(self, epoch: int, stop: threading.Event) -> bool:
        return (self._router is not None and self._epoch == epoch and self._parallel_cancel is stop
                and not stop.is_set() and not self._stop.is_set())

    def _launch_extra(self, settings: PowSettings, mci: bool, port: int, peer: str, config_dir=None):
        payload = json.loads(
            chain_outer_json(self._data_dir, "masque", settings, scan_mode=settings.scan_mode, mci=mci, masque_transport="h2")
        )
        payload["listen"] = f"127.0.0.1:{port}"
        if config_dir is not None:
            payload["config_path"] = str(Path(config_dir) / Path(payload["config_path"]).name)
            payload["endpoint_cache_path"] = str(Path(config_dir) / Path(payload["endpoint_cache_path"]).name)
        process = self._make_extra_aether()
        process.start(
            json.dumps(payload),
            extra_env={"AETHER_MASQUE_H2_PEER": peer} if peer else None,
            tail_core_log=False,
        )
        return process

    def _join_router(self, port: int, peer: str, process, epoch: int, stop: threading.Event) -> bool:
        with self._lock:
            router = self._router if self._parallel_alive(epoch, stop) else None
            if router is not None:
                router.add_upstream(port)
                self._extras.append(process)
                self._sessions.append({"port": port, "peer": peer, "process": process})
                self._parallel_note = ""
        if router is None:
            process.stop()
            return False
        self._emit_log(
            f"Parallel MASQUE: session to {peer or 'a scanned address'} is up on {port}; "
            f"{len(self._sessions)} sessions, new connections are spread per site"
        )
        return True

    def _grow_parallel(self, settings: PowSettings, mci: bool, epoch: int, stop: threading.Event) -> None:
        from .config import PARALLEL_DISCOVERY_BUDGET_MS, PARALLEL_EXTRA_BUDGET_MS

        free_ports = list(speed_module.EXTRA_PORTS)
        network = self._network_key or "default"
        candidates, _pool = self._clean_candidates(network)
        others = [p for p in candidates if p != self._won_peer][: len(free_ports)]
        reasons: list[str] = []
        if others:
            self._emit_log("Parallel MASQUE: trying extra sessions to " + ", ".join(others))
        for peer in others:
            if not self._parallel_alive(epoch, stop):
                return
            port = free_ports[0]
            try:
                process = self._launch_extra(settings, mci, port, peer)
            except Exception as exc:
                reasons.append(f"{peer} could not start ({exc})")
                continue
            if process.wait_ready(port, PARALLEL_EXTRA_BUDGET_MS, stop):
                if not self._join_router(port, peer, process, epoch, stop):
                    return
                free_ports.pop(0)
                continue
            last = getattr(process, "last_lines", None)
            why = (last[-1] if last else "").strip()[:160]
            reasons.append(f"{peer} did not come up in {PARALLEL_EXTRA_BUDGET_MS // 1000}s" + (f" ({why})" if why else ""))
            self._emit_log(f"Parallel MASQUE: {reasons[-1]}")
            try:
                process.stop()
            except Exception:
                pass
        if not self._parallel_alive(epoch, stop):
            return
        if len(self._sessions) >= 2 or not free_ports:
            if len(self._sessions) >= 2:
                threading.Thread(target=self._trace_sessions, name="pow-session-trace", daemon=True).start()
            return
        # No second address known on this network (first connect): one extra
        # session scans for its own clean address with a copy of the identity
        # in its own folder, so the main saved list is left alone.
        scan_dir = self._data_dir / "parallel"
        try:
            scan_dir.mkdir(parents=True, exist_ok=True)
            from .config import identity_path

            source = identity_path(self._data_dir)
            (scan_dir / source.name).write_bytes(source.read_bytes())
        except OSError as exc:
            self._parallel_skip(f"could not prepare the scan session ({exc}); one session")
            return
        port = free_ports[0]
        self._emit_log(
            f"Parallel MASQUE: no second clean address known yet; an extra session scans for one "
            f"(up to {PARALLEL_DISCOVERY_BUDGET_MS // 1000}s, the main session is not touched)"
        )
        try:
            process = self._launch_extra(settings, mci, port, "", config_dir=scan_dir)
        except Exception as exc:
            self._parallel_skip(f"scan session could not start ({exc}); one session")
            return
        if process.wait_ready(port, PARALLEL_DISCOVERY_BUDGET_MS, stop):
            found = speed_module.read_clean_list(scan_dir)
            peer = found[0] if found else ""
            if not self._join_router(port, peer, process, epoch, stop):
                return
            if peer:
                try:
                    pool = self._store.clean_pool(network)
                    pool.setdefault(peer, 0)
                    for extra in speed_module.harvest_core_log(scan_dir):
                        pool.setdefault(extra, 0)
                    self._store.save_clean_pool(network, pool, speed_module.POOL_LIMIT)
                except Exception:
                    pass
            threading.Thread(target=self._trace_sessions, name="pow-session-trace", daemon=True).start()
            return
        try:
            process.stop()
        except Exception:
            pass
        if self._parallel_alive(epoch, stop):
            last = getattr(process, "last_lines", None)
            why = (last[-1] if last else "").strip()[:160]
            reasons.append("the scan session found no clean address" + (f" ({why})" if why else ""))
            self._parallel_skip("; ".join(reasons) + "; staying on one session")

    def _trace_sessions(self) -> None:
        for session in list(self._sessions):
            if self._stop.is_set():
                return
            info = speed_module.cf_trace(session["port"], timeout=8.0)
            colo = info.get("colo", "")
            session["colo"] = colo
            session["country"] = speed_module.colo_country(colo) or info.get("loc", "")
        if self._sessions and not self._stop.is_set():
            self._emit_log(
                "Parallel MASQUE sessions: "
                + "; ".join(
                    f"{s.get('peer') or 'main'} via {s.get('colo') or '?'}"
                    + (f" ({s['country']})" if s.get("country") else "")
                    for s in self._sessions
                )
            )

    @property
    def parallel_note(self) -> str:
        """Why Parallel MASQUE is on but not running (empty when it runs or is off)."""
        return "" if (self._router is not None and len(self._sessions) >= 2) else self._parallel_note

    def parallel_sessions(self) -> list[dict]:
        """Live view of the parallel MASQUE sessions; [] unless 2+ are up."""
        router = self._router
        sessions = list(self._sessions)
        if router is None or len(sessions) < 2:
            return []
        now = time.monotonic()
        out = []
        for index, session in enumerate(sessions):
            process = session.get("process")
            alive = self._aether.running if process is None else bool(getattr(process, "running", True))
            down_until = router._down.get(index, 0.0) if hasattr(router, "_down") else 0.0
            count = router.counts[index] if index < len(getattr(router, "counts", [])) else 0
            if not alive:
                state = "down"
            elif down_until > now:
                state = "skipped"
            elif count > 0:
                state = "up"
            else:
                state = "standby"
            out.append({
                "peer": session.get("peer", ""),
                "colo": session.get("colo", ""),
                "country": session.get("country", ""),
                "state": state,
                "connections": count,
                "main": index == 0,
            })
        return out

    @property
    def exit_info(self) -> dict:
        info = dict(self._exit_info)
        if not info.get("country") and self._exit_region:
            info["country"] = self._exit_region
        return info

    def refresh_exit_info(self, background: bool = False) -> dict:
        """Exit IP + country via one Cloudflare trace through the exit SOCKS (cached per connect)."""
        epoch = self._epoch

        def _work() -> dict:
            port = self._exit_port
            if not port:
                return {}
            info = speed_module.cf_trace(port, timeout=10.0)
            if not info or self._epoch != epoch or self._stop.is_set():
                return {}
            country = (info.get("loc") or "").upper()
            if country in ("XX", "T1"):
                country = ""
            self._exit_info = {"ip": info.get("ip", ""), "country": country or self._exit_region, "colo": info.get("colo", "")}
            self._emit_log(
                f"Exit IP {self._exit_info['ip']}"
                + (f" ({self._exit_info['country']})" if self._exit_info.get("country") else "")
            )
            return dict(self._exit_info)

        if background:
            threading.Thread(target=_work, name="pow-exit-ip", daemon=True).start()
            return {}
        return _work()

    def _stop_parallel_masque(self) -> bool:
        with self._lock:
            self._parallel_cancel.set()
            self._sessions = []
            router, self._router = self._router, None
            extras_now, self._extras = self._extras, []
            self._chain_port = CHAIN_SOCKS_PORT
        success = True
        if router is not None:
            try:
                router.stop()
            except Exception:
                success = False
        for process in extras_now:
            try:
                success = process.stop() is not False and success
            except Exception:
                success = False
        return success

    # -- key fetch (mobile parity: race, then one ECH retry) ------------------------
    _KEY_ROUTE_NAMES = {
        "oob": "OOB",
        "relay": "رله",
        "ech": "ECH",
        "fragment": "split ClientHello",
        "external": "current network",
        "net": ".NET lane",
    }

    def _fetch_key(self, settings: PowSettings, protocol: str, label: str) -> str | None:
        """Get the WARP key (+ MASQUE certificate). Returns an error text or None."""
        from .config import (
            KEY_AUTO,
            KEY_FETCH_FALLBACK,
            KEY_FETCH_IDLE_TIMEOUT_S,
            KEY_FETCH_RETRY_TIMEOUT_S,
            KEY_FETCH_TIMEOUT_S,
        )

        stop = self._dial_stop()
        mode = settings.key_fetch or KEY_AUTO
        attempts = [(mode, KEY_FETCH_TIMEOUT_S)]
        if mode == KEY_AUTO:
            attempts.append((KEY_FETCH_FALLBACK, KEY_FETCH_RETRY_TIMEOUT_S))
        last_error = "no attempt ran"
        # .NET/SChannel lane (bin\keyfetch-net.ps1): on some networks (AS48944)
        # the core never gets an HTTP answer while this lane does, so for the
        # auto and oob routes it runs FIRST on Windows (capped at
        # NET_KEY_LANE_FIRST_TIMEOUT_S); if it fails the core runs exactly as
        # before. UAC_NET_KEYFETCH_FORCE=1 also runs it first for the other
        # explicit routes (testing); UAC_NET_KEYFETCH=0 disables it.
        import os as _os
        net_force = _os.environ.get("UAC_NET_KEYFETCH_FORCE", "").strip().lower() in ("1", "true", "yes", "on")
        net_off = self.protected or (
            _os.environ.get("UAC_NET_KEYFETCH", "").strip().lower() in ("0", "off", "false", "no")
        )
        net_tried = False
        if protocol == "masque" and not net_off and (mode in (KEY_AUTO, "oob") or net_force) and _os.name == "nt":
            if net_force and mode not in (KEY_AUTO, "oob"):
                self._emit_log("Key: UAC_NET_KEYFETCH_FORCE is set; trying the .NET lane before the core")
            self._emit_log(
                f"Key (.NET): trying first for {label} (SChannel TLS 1.2 with OOB, up to "
                f"{int(self.NET_KEY_LANE_FIRST_TIMEOUT_S)}s); if it fails the core's {self._KEY_ROUTE_NAMES.get(mode, mode) if mode != KEY_AUTO else 'auto'} route runs next"
            )
            net_tried = True
            if self._net_key_lane(protocol, label, timeout=self.NET_KEY_LANE_FIRST_TIMEOUT_S):
                return None
            if stop.is_set():
                self._emit_log("Key fetch cancelled")
                return "stopped"
        for index, (camo, timeout) in enumerate(attempts):
            if stop.is_set():
                return "stopped"
            if camo == KEY_AUTO:
                how = ("OOB first, one method at a time (disoob-byte0-ttl1, then oob-insni+5-ttl1, then oob-byte0-nottl; the first that gets the key wins); only if all three fail: "
                       "رله (relay, after a 2.5s head start), "
                       "ECH, split ClientHello and the current network; first ready route wins")
            else:
                how = f"{self._KEY_ROUTE_NAMES.get(camo, camo)} only"
            prefix = "Key fetch" if index == 0 else "Key fetch retry"
            self._emit_log(
                f"{prefix} for {label}: {how} (no overall limit like mobile: runs while the core "
                f"reports progress, gives up after {int(KEY_FETCH_IDLE_TIMEOUT_S)}s without output, "
                f"safety cap {int(timeout)}s)"
            )
            self._key_route = ""
            self._oob_method = ""
            started = time.monotonic()
            try:
                prepare_identity(
                    self._data_dir,
                    settings,
                    protocol,
                    on_log=self._on_native_log,
                    stop=stop,
                    timeout=timeout,
                    api_camo=camo,
                )
            except Exception as exc:
                if stop.is_set():
                    self._emit_log("Key fetch cancelled")
                    return "stopped"
                last_error = str(exc)
                self._emit_log(f"{prefix} failed after {time.monotonic() - started:.0f}s: {last_error}")
                if index == 0 and camo == KEY_AUTO and protocol == "masque" and not net_off and not net_tried:
                    if self._net_key_lane(protocol, label):
                        return None
                    if stop.is_set():
                        return "stopped"
                continue
            route = self._KEY_ROUTE_NAMES.get(self._key_route or camo, self._key_route or camo)
            if (self._key_route or camo) == "oob" and getattr(self, "_oob_method", ""):
                route = f"{route} ({self._oob_method})"
            if camo == KEY_AUTO and not self._key_route:
                route = "the race"
            self._emit_log(f"Key fetch done in {time.monotonic() - started:.0f}s via {route}")
            if protocol == "masque":
                if self._identity_ready():
                    self._emit_log("Cert: MASQUE certificate saved with the key")
                else:
                    self._emit_log("Cert: the key was saved but no MASQUE certificate came back")
            return None
        return last_error

    #: Safety cap for keyfetch-net.ps1 (3 methods x handshake + reg + PATCH).
    NET_KEY_LANE_TIMEOUT_S = 150
    #: Cap when the lane runs first, before the core (it took ~5 s on MCI).
    NET_KEY_LANE_FIRST_TIMEOUT_S = 60

    def _net_key_lane(self, protocol: str, label: str, timeout: float | None = None) -> bool:
        """Fallback key fetch through ``bin\\keyfetch-net.ps1``.

        The script registers a WARP device and enrolls a MASQUE key over a
        .NET SslStream (SChannel TLS 1.2) whose first write carries a TCP
        urgent byte, then writes ``uac-pow.toml`` in aether's own format.
        Returns True when the saved identity is ready for MASQUE.
        """
        import os as _os

        stop = self._dial_stop()
        if protocol != "masque" or _os.name != "nt":
            return False
        binary = runner_module.find_aether_binary()
        script = binary.parent / "keyfetch-net.ps1" if binary is not None else None
        if script is None or not script.is_file():
            self._emit_log("Key: .NET lane skipped (keyfetch-net.ps1 is missing from the bin folder)")
            return False
        self._emit_log(f"Key: trying the .NET lane for {label} (SChannel TLS 1.2 with OOB, 3 methods)")
        args = [
            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", str(script), str(self._data_dir),
        ]
        cap = float(timeout if timeout is not None else self.NET_KEY_LANE_TIMEOUT_S)
        started = time.monotonic()
        try:
            process = subprocess.Popen(
                args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception as exc:
            self._emit_log(f"Key: .NET lane could not start: {exc}")
            return False

        def _pump() -> None:
            # Stream each line to the log as soon as the script prints it.
            try:
                stream = process.stdout
                while True:
                    line = stream.readline()
                    if not line:
                        break
                    text = line.strip()
                    if text:
                        self._emit_log(f"Key (.NET): {text[:300]}")
            except Exception:
                pass

        reader = threading.Thread(target=_pump, name="pow-net-keyfetch", daemon=True)
        reader.start()
        deadline = started + cap
        while process.poll() is None:
            if stop.is_set() or time.monotonic() >= deadline:
                try:
                    process.kill()
                except Exception:
                    pass
                if not stop.is_set():
                    self._emit_log(f"Key (.NET): timed out after {int(cap)}s")
                break
            time.sleep(0.2)
        try:
            process.wait(timeout=5)
        except Exception:
            pass
        reader.join(timeout=2)
        elapsed = time.monotonic() - started
        if process.returncode == 0 and self._identity_ready():
            self._key_route = "net"
            self._emit_log(f"Key fetch done in {elapsed:.0f}s via the .NET lane")
            self._emit_log("Cert: MASQUE certificate saved with the key")
            return True
        self._emit_log(
            f"Key: .NET lane got no key after {elapsed:.0f}s (exit {process.returncode}); "
            "continuing with the remaining routes"
        )
        return False

    # -- inner hop -----------------------------------------------------------
    # -- network memory ---------------------------------------------------------
    def _start_network_detect(self) -> None:
        self._network_ready.clear()
        self._network_key = "default"
        self._network_label = ""
        detector = self._network_detector

        def _detect() -> None:
            try:
                key, label = detector()
                self._network_key, self._network_label = key or "default", label or ""
            except Exception:
                pass
            finally:
                self._network_ready.set()

        threading.Thread(target=_detect, name="pow-network-key", daemon=True).start()

    def _network(self) -> str:
        # Detection runs while the outer leg comes up; never hold Psiphon long.
        self._network_ready.wait(5.0)
        return self._network_key or "default"

    # -- inner hop -----------------------------------------------------------
    def _strategy_order(self, direct: bool = False, network: str = "default"):
        """(ladder, start index, reason) for this leg and network."""
        from .config import rtt_key, start_index, strategy_ladder, strategy_signature

        ladder = strategy_ladder(direct)
        shape = strategy_signature(direct)
        remembered = None
        rtts: dict[str, int] = {}
        try:
            remembered = self._store.network_strategy_index(network, shape, len(ladder))
            if remembered is None and network == "default":
                remembered = self._store.remembered_strategy_index(len(ladder), shape)
            saved = self._store.strategy_rtts(network, [rtt_key(direct, s.name) for s in ladder])
            rtts = {s.name: saved[rtt_key(direct, s.name)] for s in ladder if rtt_key(direct, s.name) in saved}
        except Exception:
            remembered = None
        start = start_index(ladder, remembered, rtts)
        if len(rtts) >= 2:
            reason = "lower RTT " + ", ".join(f"{name} {ms}ms" for name, ms in rtts.items())
        elif remembered is not None:
            reason = "remembered for this network"
        else:
            reason = "default"
        return ladder, start, reason

    def _start_psiphon_tunnel(self, settings: PowSettings, *, retune: bool = False) -> None:
        from .config import (
            NEARBY,
            NEARBY_PHASE_TIMEOUT_SECONDS,
            REGION_PHASE_TIMEOUT_SECONDS,
            auto_bias_region,
            psiphon_config,
            strategy_signature,
        )

        stop = self._dial_stop()
        status = self._status
        direct = self._direct_psiphon
        inner_dir = self._data_dir / "uac-pow-inner"
        inner_dir.mkdir(parents=True, exist_ok=True)
        network = self._network()
        if self._network_label:
            self._emit_log(f"Network: {self._network_label} (memory key {network})")
        ladder, start, reason = self._strategy_order(direct, network)
        ordered = ladder[start:] + ladder[:start]
        shape = strategy_signature(direct)
        self._emit_log(
            "Psiphon strategy order ("
            + ("direct" if direct else "behind WARP")
            + "): "
            + " -> ".join(f"{s.name} {s.label} {s.timeout_seconds}s" for s in ladder)
            + f"; starting at {ordered[0].name} ({reason})"
        )

        explicit = egress_region(settings.exit_country_code)
        bias_region = None
        if explicit is None and not direct and not retune:
            try:
                bias_region = auto_bias_region(
                    self._store.remembered_region(network), self._store.available_regions()
                )
            except Exception:
                bias_region = None
        if explicit:
            self._emit_log(f"Psiphon region: user choice {region_name(explicit)} ({explicit})")
        elif bias_region:
            remembered_region = False
            try:
                remembered_region = self._store.remembered_region(network) == bias_region
            except Exception:
                pass
            self._emit_log(
                f"Psiphon region: Automatic -> nearby {region_name(bias_region)} ({bias_region}"
                + (", remembered" if remembered_region else "")
                + f") for {NEARBY_PHASE_TIMEOUT_SECONDS}s, then any country"
            )
        else:
            self._emit_log("Psiphon region: any country")

        # (strategy, region, bias, fallback seconds). The real wait is the
        # EstablishTunnelTimeoutSeconds of the config built for that attempt
        # plus the mobile margin (see psiphon_wait_seconds).
        attempts: list[tuple] = []
        if explicit:
            attempts.append((ordered[0], explicit, False, REGION_PHASE_TIMEOUT_SECONDS))
        elif bias_region:
            attempts.append((ordered[0], bias_region, True, NEARBY_PHASE_TIMEOUT_SECONDS))
        for strategy in ordered:
            attempts.append((strategy, "", False, strategy.timeout_seconds))

        deadline = time.monotonic() + _INNER_RETUNE_TIMEOUT_S if retune else None
        for strategy, preferred, bias, fallback in attempts:
            self._ensure_active()
            if deadline is not None and time.monotonic() >= deadline:
                break
            config_json = psiphon_config(
                socks_port=self._psiphon_port,
                data_directory=str(inner_dir),
                preferred_region=preferred or None,
                strategy=strategy,
                optimized_mode=settings.optimized_mode,
                direct=direct,
                region_bias=bias,
                upstream_port=self._chain_port,
                iran_direct=settings.iran_direct,
            )
            timeout = psiphon_wait_seconds(config_json, fallback, bias)
            allowed = timeout if deadline is None else min(timeout, math.ceil(deadline - time.monotonic()))
            if allowed <= 0:
                break
            self._emit_log(
                f"Psiphon strategy {strategy.name} ({strategy.label})"
                + (f" region={preferred}" if preferred else "")
                + (f" (nearby, {NEARBY_PHASE_TIMEOUT_SECONDS}s then any)" if bias else "")
                + f"; waiting up to {allowed}s"
            )
            try:
                self._psiphon.start(
                    config_json,
                    self._data_dir,
                    meek_only=direct
                    and strategy.preferred_protocols
                    and all(p.startswith("FRONTED-") for p in strategy.preferred_protocols),
                )
            except Exception as exc:
                self._emit_log(f"Psiphon strategy {strategy.name} could not start: {exc}")
                continue
            remaining = timeout if deadline is None else min(timeout, deadline - time.monotonic())
            if remaining > 0 and self._psiphon.wait_connected(float(remaining), stop):
                self._ensure_active()
                self._inner_config = config_json
                self._inner_strategy = strategy.name
                index = [s.name for s in ladder].index(strategy.name)
                try:
                    self._store.save_network_strategy(network, shape, index)
                except Exception:
                    pass
                try:
                    regions = self._psiphon.available_regions
                    if regions:
                        self._store.remember_available_regions(regions)
                except Exception:
                    pass
                self._exit_region = self._psiphon.server_region
                self._emit_log(
                    f"Psiphon connected via {strategy.name}"
                    + (f" region={self._exit_region}" if self._exit_region else "")
                )
                if bias:
                    self._emit_log(
                        f"Connected in nearby country {region_name(preferred)} ({preferred})"
                    )
                self._after_psiphon_connected(
                    network, strategy.name, direct, remember_region=(explicit is None and not direct)
                )
                return
            try:
                self._psiphon.stop()
            except Exception:
                pass
            if preferred:
                self._emit_log(
                    ("Nearby country " if bias else "Preferred country ")
                    + f"{region_name(preferred)} ({preferred}) did not connect within {allowed}s"
                )
            else:
                self._emit_log(f"Psiphon strategy {strategy.name} did not connect within {allowed}s")
        self._ensure_active()
        if not retune:
            status.update(PowPhase.FAILED, 0, "Psiphon did not connect in time")
        raise PowEngineError("Psiphon did not connect in time")

    def _select_startup_route(self, settings: PowSettings, mci: bool) -> None:
        import ipaddress

        from .config import psiphon_config, strategy_ladder

        if (
            not settings.startup_speed_test or self._direct_psiphon
            or self._won_transport != "h2" or not self._inner_config or not self._inner_strategy
        ):
            return
        if self._chain_port != CHAIN_SOCKS_PORT:
            self._emit_log("Startup download test unavailable while parallel MASQUE is active")
            return
        initial = (self._won_peer, self._inner_strategy)
        parsed = speed_module.split_peer(initial[0])
        if parsed is None:
            return
        try:
            family = ipaddress.ip_address(parsed[0]).version
        except ValueError:
            return
        strategies = {strategy.name: strategy for strategy in strategy_ladder(False)}
        config = json.loads(self._inner_config)
        original_config = self._inner_config
        country = config.get("EgressRegion") or None
        candidates = []
        for peer in speed_module.read_clean_list(self._data_dir):
            target = speed_module.split_peer(peer)
            if peer == initial[0] or target is None:
                continue
            try:
                if ipaddress.ip_address(target[0]).version != family:
                    continue
            except ValueError:
                continue
            candidates.append((peer, initial[1]))
            break
        candidates.extend((initial[0], name) for name in strategies if name != initial[1])
        if not candidates:
            return
        baseline = speed_module.startup_download_rate(
            self._psiphon_port, time.monotonic() + 7, self._stop
        )
        self._ensure_active()
        if baseline <= 0:
            self._emit_log("Startup download sample unavailable; keeping active route")
            return
        self._status.note("Comparing startup download routes")
        self._emit_log(f"Startup download baseline: {baseline // 1000} kbit/s")

        def activate(route: tuple[str, str], deadline: float) -> bool:
            self._ensure_active()
            peer, name = route
            trial = json.loads(chain_outer_json(
                self._data_dir, "masque", settings, scan_mode=settings.scan_mode, mci=mci
            ))
            trial["forced_peer"] = peer
            chosen = original_config
            if route != initial:
                data = self._data_dir / "uac-pow-speed" / hashlib.sha256(
                    f"{peer}|{name}|{country}".encode()
                ).hexdigest()[:16]
                data.mkdir(parents=True, exist_ok=True)
                chosen = psiphon_config(
                    self._psiphon_port, str(data), country, strategies[name],
                    settings.optimized_mode, region_bias=bool(country),
                )
            self._psiphon.stop()
            self._aether.stop()
            try:
                with self._lock:
                    self._ensure_active()
                    self._aether.start(json.dumps(trial))
                budget_ms = int(max(0, deadline - time.monotonic()) * 1000)
                if not self._aether.wait_ready(CHAIN_SOCKS_PORT, budget_ms, self._stop):
                    return False
                with self._lock:
                    self._ensure_active()
                    self._psiphon.start(chosen, self._data_dir)
                if not self._psiphon.wait_connected(max(0, deadline - time.monotonic()), self._stop):
                    return False
                self._ensure_active()
                self._inner_config = chosen
                self._won_peer, self._inner_strategy = route
                self._exit_region = self._psiphon.server_region
                return True
            except Exception as exc:
                self._ensure_active()
                self._emit_log(f"Startup route trial failed: {exc}")
                return False

        deadline = time.monotonic() + 60
        best, live, last_working = initial, initial, initial
        rate = baseline
        for candidate in candidates[:2]:
            if deadline - time.monotonic() < 10:
                break
            live = None
            if not activate(candidate, min(deadline, time.monotonic() + 30)):
                break
            live = last_working = candidate
            sample = speed_module.startup_download_rate(self._psiphon_port, deadline, self._stop)
            self._ensure_active()
            self._emit_log(f"Startup route {candidate[0]} ({candidate[1]}): {sample // 1000} kbit/s")
            if sample > rate * 1.10:
                best, rate = candidate, sample
        if live == best:
            return
        recovery = time.monotonic() + 60
        for route in dict.fromkeys((best, last_working, initial)):
            if time.monotonic() >= recovery:
                break
            if activate(route, min(recovery, time.monotonic() + 30)):
                self._emit_log(f"Startup download route selected: {route[0]} ({route[1]})")
                return
        raise PowEngineError("Previously working MASQUE H2 paths could not reconnect")

    def _start_inner_pool(self) -> None:
        from .speed import StickyRouter
        from .tun_guard import verify_proxy

        if self._proxy_mode or not self._inner_config:
            return
        with self._lock:
            self._ensure_active()
            if self._inner_router is None:
                router = StickyRouter(0, [self._psiphon_port], log=self._emit_log)
                router.start()
                self._inner_router = router
            else:
                router = self._inner_router
                router.set_upstreams([self._psiphon_port])
            self._exit_port = router.listen_port
            if not self._speed.psiphon_tunnel_pool:
                return
            process = PsiphonProcess()
            self._psiphon_secondary = process
        epoch = self._epoch
        data = self._data_dir / "uac-pow-inner-secondary"
        config = json.loads(self._inner_config)
        config.update(
            DataDirectory=str(data), DataRootDirectory=str(data),
            LocalSocksProxyPort=0, EstablishTunnelTimeoutSeconds=90,
            ConnectionWorkerPoolSize=min(config["ConnectionWorkerPoolSize"], 6),
        )
        config.pop("TunnelPoolSize", None)

        def _warm() -> None:
            self._tls.epoch = epoch
            try:
                with self._session_work():
                    with self._lock:
                        if self._psiphon_secondary is not process:
                            return
                        self._ensure_active()
                        process.start(json.dumps(config), data)
                    if not process.wait_connected(90, self._stop) or not process.socks_port:
                        raise PowEngineError("secondary Psiphon did not connect")
                    ok, why = verify_proxy(process.socks_port, "socks5h")
                    if not ok:
                        raise PowEngineError(f"secondary Psiphon validation failed: {why}")
                    self._ensure_active()
                    with self._lock:
                        if self._inner_router is router and self._psiphon_secondary is process:
                            router.add_upstream(process.socks_port)
                            self._emit_log("Secondary Psiphon tunnel ready")
                            return
            except Exception as exc:
                if not self._stop.is_set() and self._epoch == epoch:
                    self._emit_log(f"Secondary Psiphon unavailable: {exc}")
            process.stop()

        threading.Thread(target=_warm, name="pow-psiphon-secondary", daemon=True).start()

    def _stop_inner_pool(self, keep_router: bool = False) -> bool:
        with self._lock:
            router = self._inner_router
            if router is not None and keep_router:
                router.set_upstreams([self._psiphon_port])
            else:
                self._inner_router = None
            process, self._psiphon_secondary = self._psiphon_secondary, None
            ghost, self._psiphon_ghost = self._psiphon_ghost, None
            self._ghost_serving = False
        success = ghost is None or ghost.stop() is not False
        if router is not None and not keep_router:
            router.stop()
        if process is not None:
            success = process.stop() is not False and success
        return success

    def _try_ghost_handover(self, reason: str) -> bool:
        from .tun_guard import verify_proxy

        if not self._retune_lock.acquire(blocking=False):
            return False
        ghost = None
        switched = False
        epoch = self._epoch
        try:
            with self._path_work(epoch) as stop:
                with self._lock:
                    router = self._inner_router
                    if not self._ghost_eligible():
                        return False
                    self._ensure_active()
                    ghost = PsiphonProcess()
                    self._psiphon_ghost = ghost
                    data = self._data_dir / "uac-pow-inner-ghost"
                    config = json.loads(self._inner_config)
                    config.update(
                        DataDirectory=str(data), DataRootDirectory=str(data),
                        LocalSocksProxyPort=0, EstablishTunnelTimeoutSeconds=38,
                        ConnectionWorkerPoolSize=min(config["ConnectionWorkerPoolSize"], 6),
                    )
                    config.pop("TunnelPoolSize", None)
                    self._emit_log(f"Ghost handover: warming a second Psiphon path ({reason})")
                    ghost.start(json.dumps(config), data, meek_only=self._direct_meek_only(config))
                if not ghost.wait_connected(38, stop) or not ghost.socks_port:
                    self._emit_log("Ghost helper did not connect; retaining the primary path")
                    return False
                if not verify_proxy(ghost.socks_port, "socks5h", timeout=2, stop=stop)[0]:
                    self._emit_log("Ghost path did not validate; retaining the primary path")
                    return False

                with self._exit_lock:
                    with self._lock:
                        self._ensure_active()
                        if (self._epoch != epoch or self._inner_router is not router
                                or self._psiphon_ghost is not ghost or self._paused):
                            return False
                        router.set_upstreams([ghost.socks_port])
                        self._ghost_serving = True
                        switched = True
                    self._emit_log("Ghost path verified and serving new connections")
                    self._psiphon.stop()
                    self._start_primary_behind_ghost()
                if self._psiphon.wait_connected(20, stop):
                    self._finish_ghost()
                return True
        except Exception as exc:
            if not self._stop.is_set() and self._epoch == epoch:
                self._emit_log(f"Ghost handover error: {exc}")
            return self._ghost_serving and self._psiphon_ghost is ghost
        finally:
            if ghost is not None:
                with self._lock:
                    owned = self._psiphon_ghost is ghost
                    cleanup = owned and not switched
                    if cleanup:
                        self._psiphon_ghost = None
                if cleanup:
                    ghost.stop()
            self._retune_lock.release()

    def _ghost_eligible(self) -> bool:
        return (
            not self._proxy_mode and not self._paused and self.running and not self._stop.is_set()
            and self._tun_process is not None and self._tun_process.poll() is None
            and self._inner_router is not None and not self._speed.psiphon_tunnel_pool
            and self._psiphon_ghost is None and bool(self._inner_config) and self._psiphon.running
        )

    def _direct_meek_only(self, config: dict) -> bool:
        protocols = config.get("LimitTunnelProtocols", [])
        return bool(self._direct_psiphon and protocols and all(
            protocol.startswith("FRONTED-") for protocol in protocols
        ))

    def _start_primary_behind_ghost(self) -> None:
        with self._lock:
            self._ensure_active()
            if not self._ghost_serving:
                return
            self._ghost_next_primary_retry = time.monotonic() + 20
            config = json.loads(self._inner_config)
            config["EstablishTunnelTimeoutSeconds"] = 20
            if not self._speed.exit_country_code:
                config["EgressRegion"] = ""
            try:
                self._psiphon.start(json.dumps(config), self._data_dir, meek_only=self._direct_meek_only(config))
            except (OSError, RuntimeError) as exc:
                self._emit_log(f"Primary Psiphon could not restart; the ghost continues serving: {exc}")

    def _finish_ghost(self) -> None:
        from .tun_guard import verify_proxy

        ghost = self._psiphon_ghost
        router = self._inner_router
        if ghost is None or router is None or not self._ghost_serving or self._paused:
            return
        if not self._psiphon.running:
            if time.monotonic() >= self._ghost_next_primary_retry:
                self._start_primary_behind_ghost()
            return
        if not self._psiphon.connected.is_set():
            return
        if not verify_proxy(self._psiphon_port, "socks5h", timeout=2, stop=self._dial_stop())[0]:
            return

        with self._exit_lock:
            with self._lock:
                self._ensure_active()
                if self._psiphon_ghost is not ghost or self._inner_router is not router or self._paused:
                    return
                router.set_upstreams([self._psiphon_port])
                self._ghost_serving = False
        self._emit_log("Primary path verified; existing ghost streams have time to drain")

        def drain() -> None:
            self._stop.wait(3)
            with self._lock:
                if self._psiphon_ghost is not ghost:
                    return
                self._psiphon_ghost = None
            ghost.stop()

        threading.Thread(target=drain, name="pow-ghost-drain", daemon=True).start()

    def _after_psiphon_connected(
        self, network: str, strategy_name: str, direct: bool, remember_region: bool
    ) -> None:
        """Remember the nearby exit and the tunnel RTT for this network, off the connect path."""
        from .config import NEARBY, rtt_key

        epoch = self._epoch
        psiphon = self._psiphon

        def _work() -> None:
            deadline = time.monotonic() + 6.0
            while not getattr(psiphon, "server_region", "") and time.monotonic() < deadline:
                if self._stop.is_set() or self._epoch != epoch:
                    return
                time.sleep(0.2)
            code = str(getattr(psiphon, "server_region", "") or "").strip().upper()
            if code:
                self._exit_region = code
            if remember_region and code in NEARBY:
                try:
                    if self._store.remembered_region(network) != code:
                        self._store.save_region(network, code)
                        self._emit_log(
                            f"Remembered exit {region_name(code)} ({code}) for this network; "
                            "next Automatic connect tries it first"
                        )
                except Exception:
                    pass
            # Let the proxy/TUN come up first; then sample the tunnel RTT.
            for _ in range(15):
                if self._stop.is_set() or self._epoch != epoch:
                    return
                if self._connected.is_set():
                    break
                time.sleep(0.2)
            rtt = self._measure_tunnel_rtt()
            if rtt <= 0 or self._stop.is_set() or self._epoch != epoch:
                return
            try:
                self._store.save_strategy_rtt(network, rtt_key(direct, strategy_name), rtt)
            except Exception:
                pass
            self._emit_log(f"Psiphon tunnel RTT {rtt} ms via {strategy_name}; saved for this network")

        threading.Thread(target=_work, name="pow-psiphon-memory", daemon=True).start()

    def _measure_tunnel_rtt(self, samples_to_take: int = _RTT_PROBE_SAMPLES, timeout: float = 8) -> int:
        host, port = _RTT_PROBE_TARGET
        name = host.encode("idna")
        request = bytes([0x05, 0x01, 0x00, 0x03, len(name)]) + name + port.to_bytes(2, "big")
        samples: list[int] = []
        for _ in range(samples_to_take):
            if self._stop.is_set():
                break
            try:
                socks_port = self._exit_port or (self._chain_port if self._warp_only else self._psiphon_port)
                with socket.create_connection(("127.0.0.1", socks_port), timeout=timeout) as sock:
                    sock.sendall(b"\x05\x01\x00")
                    if sock.recv(2) != b"\x05\x00":
                        continue
                    started = time.monotonic()
                    sock.sendall(request)
                    reply = sock.recv(10)
                    elapsed = int((time.monotonic() - started) * 1000)
                    if len(reply) >= 2 and reply[1] == 0x00 and elapsed > 0:
                        samples.append(elapsed)
            except OSError:
                continue
        return min(samples) if samples else 0

    # -- exit wiring ----------------------------------------------------------
    def _bind_system_proxy(self, socks_port: int, http_port: int, *, tun: bool = False) -> None:
        from ..engine import WindowsProxy

        proxy = self._proxy = WindowsProxy(log=self._emit_log)
        if tun or self._system_proxy_requested:
            self._proxy_session = True
        proxy.bind_session(socks_port, http_port, tun=tun, enabled=self._system_proxy_requested)

    def _enable_proxy(self) -> None:
        from ..engine import build_singbox_proxy_bypass_config
        from ..paths import BIN
        from .forwarder import HttpToSocks
        from .routing import apply_rules
        from .tun_guard import KillOnCloseJob, verify_proxy

        port = int(self._forward_port or FORWARD_HTTP_PORT)
        if not tcp_accepts(self._exit_port):
            self._dial_stop().wait(_EXIT_GRACE_SECONDS)
        self._ensure_active()
        if not tcp_accepts(self._exit_port):
            raise PowEngineError("exit proxy is not listening")

        bypass = self._bypass_processes if self._speed.routing_mode == "bypass" else []
        if (bypass or self._speed.routing_mode == "only" or self._speed.iran_direct
                or self._speed.domains_direct or self._speed.ips_direct):
            # Process-aware local mixed proxy so App Bypass matches engine 1.
            binary = BIN / "sing-box.exe"
            if not binary.is_file():
                raise PowEngineError("sing-box.exe is missing from the app bin folder")
            config = build_singbox_proxy_bypass_config(
                bypass,
                listen_port=port,
                socks_port=self._exit_port,
                helper_processes=POW_HELPER_PROCESSES,
            )
            apply_rules(config, self._speed, self._bypass_processes, BIN / "geosite.dat",
                        tun=False, warp_only=self._warp_only)
            config_path = self._data_dir / "pow-sing-box-proxy.json"
            config_path.write_text(
                json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            checked = subprocess.run(
                [str(binary), "check", "-c", str(config_path)],
                cwd=str(config_path.parent),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                timeout=15,
            )
            if checked.returncode:
                detail = (checked.stderr or checked.stdout or "invalid configuration").strip()
                raise PowEngineError(f"sing-box config check failed: {detail[:300]}")
            process = subprocess.Popen(
                [str(binary), "run", "-c", str(config_path)],
                cwd=str(config_path.parent),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            time.sleep(0.8)
            if process.poll() is not None:
                raise PowEngineError(
                    f"sing-box proxy exited immediately ({process.returncode}); "
                    f"is 127.0.0.1:{port} free?"
                )
            if not tcp_accepts(port):
                try:
                    process.terminate()
                except Exception:
                    pass
                raise PowEngineError("local App Bypass proxy did not start")
            self._tun_process = process
            job = KillOnCloseJob()
            if job.assign(process):
                self._tun_job = job
            else:
                job.close()
                self._emit_log("Could not assign the mixed proxy to the Windows cleanup job")
            for scheme in ("http", "socks5h"):
                ok, why = verify_proxy(port, scheme, stop=self._dial_stop())
                if not ok:
                    raise PowEngineError(f"local {scheme} proxy could not carry traffic: {why}")
            self._ensure_active()
            # Mixed inbound serves both HTTP and SOCKS on the same port.
            self._bind_system_proxy(port, port)
            self._emit_log(
                f"App Bypass mixed 127.0.0.1:{port} "
                f"({len(bypass)} direct apps) → SOCKS 127.0.0.1:{self._exit_port}"
            )
            return

        forwarder = HttpToSocks(port, "127.0.0.1", self._exit_port)
        try:
            forwarder.start()
        except OSError as exc:
            raise PowEngineError(
                f"local HTTP proxy port 127.0.0.1:{port} could not be opened: {exc}"
            ) from exc
        if not tcp_accepts(port):
            forwarder.stop()
            raise PowEngineError("local HTTP forwarder did not start")
        self._forwarder = forwarder
        ok, why = verify_proxy(port, "http", stop=self._dial_stop())
        if not ok:
            raise PowEngineError(f"local HTTP proxy could not carry traffic: {why}")
        self._ensure_active()
        self._bind_system_proxy(self._exit_port, port)
        self._emit_log(
            f"Local SOCKS 127.0.0.1:{self._exit_port} "
            f"HTTP 127.0.0.1:{port}"
        )

    @staticmethod
    def _require_tun_admin() -> None:
        import ctypes
        import sys

        if sys.platform == "win32":
            try:
                admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                admin = False
            if not admin:
                raise PowEngineError("TUN needs administrator access")

    def _enable_tun(self) -> None:
        """Whole-device TUN, verified for real before we call it connected."""
        from ..proxy_ports import listener_pid
        from . import tun_guard

        self._require_tun_admin()
        self._ensure_kill_switch()
        from ..paths import BIN

        binary = BIN / "sing-box.exe"
        if not binary.is_file():
            raise PowEngineError("sing-box.exe is missing")
        self._ensure_active()
        if self._exit_port <= 0:
            # A newer connect / disconnect reset the exit; never point TUN at port 0.
            raise PowEngineError("exit proxy is not listening")
        if not tcp_accepts(self._exit_port):
            self._dial_stop().wait(_EXIT_GRACE_SECONDS)
        self._ensure_active()
        if not tcp_accepts(self._exit_port):
            raise PowEngineError("exit proxy is not listening")
        config_path = self._data_dir / "pow-sing-box-tun.json"
        # A crashed earlier run may still hold the adapter and routes.
        tun_guard.kill_stale(str(config_path), self._emit_log)
        self._ensure_active()
        last = ""
        mtu = tun_guard.effective_mtu(self._speed.tun_mtu, _physical_uplink_mtu())
        attempts = (
            (("gvisor", mtu),) if self._speed.tun_backend == "gvisor"
            else (("mixed", mtu), ("gvisor", min(mtu, 1280)), ("system", min(mtu, 1280)))
        )
        for attempt, (stack, mtu) in enumerate(attempts, 1):
            self._ensure_active()
            if attempt > 1:
                self._emit_log(f"TUN repair {attempt}/{len(attempts)}: stack {stack}, MTU {mtu}")
            try:
                self._start_tun_process(binary, config_path, stack, mtu)
            except PowEngineError as exc:
                last = str(exc)
                self._stop_tun_process()
                continue
            started_tun = self._tun_process
            ok, reason, facts = False, "", {}
            for _ in range(2):
                try:
                    self._ensure_active()
                except PowEngineError:
                    # Replaced mid-check: drop only the sing-box this attempt started.
                    if started_tun is not None and self._tun_process is started_tun:
                        self._stop_tun_process()
                    raise
                ok, reason, facts = tun_guard.verify_tun(self._exit_port, stop=self._dial_stop())
                if ok:
                    break
                if self._dial_stop().wait(1.5):
                    break
            if ok:
                self._ensure_active()
                port = self.forward_http_port
                if started_tun is None or listener_pid(port) != started_tun.pid:
                    raise PowEngineError("TUN local proxy did not start")
                self._bind_system_proxy(port, port, tun=True)
                self._tun_stack = (stack, mtu)
                self._emit_log(
                    f"TUN verified: DNS {facts.get('dns_ms', 0)} ms, HTTPS {facts.get('https_ms', 0)} ms, "
                    f"exit {facts.get('ip', '?')} ({facts.get('loc', '?')})"
                )
                return
            last = reason
            self._emit_log(f"TUN check failed: {reason}")
            self._stop_tun_process()
        self._ensure_active()
        vpn = tun_guard.other_vpn()
        if vpn:
            self._emit_log(f"Another VPN is active: {vpn}")
        raise PowEngineError(f"TUN did not pass the check ({last})")

    def _start_tun_process(self, binary, config_path, stack: str, mtu: int) -> None:
        from ..engine import build_singbox_tun_config
        from ..paths import BIN
        from . import tun_guard
        from .routing import add_tun_proxy_listener, apply_rules

        bypass = self._bypass_processes if self._speed.routing_mode == "bypass" else []
        config = tun_guard.harden_config(
            build_singbox_tun_config(
                bypass,
                [],
                None,
                None,
                None,
                socks_port=self._exit_port,
                helper_processes=POW_HELPER_PROCESSES,
            ),
            stack=stack,
            mtu=mtu,
            ipv6_block=self._speed.ipv6_block,
        )
        apply_rules(config, self._speed, self._bypass_processes, BIN / "geosite.dat",
                    tun=True, warp_only=self._warp_only)
        add_tun_proxy_listener(config, self.forward_http_port, dns_sinkhole=self._speed.dns_sinkhole,
                               ipv6_block=self._speed.ipv6_block)
        tmp = config_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(config_path)
        checked = subprocess.run(
            [str(binary), "check", "-c", str(config_path)],
            cwd=str(config_path.parent),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            timeout=15,
        )
        if checked.returncode:
            detail = (checked.stderr or checked.stdout or "invalid configuration").strip()
            raise PowEngineError(f"sing-box config check failed: {detail[:300]}")
        job = tun_guard.KillOnCloseJob()
        process = subprocess.Popen(
            [str(binary), "run", "-c", str(config_path)],
            cwd=str(config_path.parent),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        job.assign(process)
        self._tun_job = job
        self._tun_process = process
        def observe_tunnel_host(host: str) -> None:
            if self._tun_process is process and not self._stop.is_set():
                self._warmup.note(host)

        self._site_log = tun_guard.SiteLog(
            process.stderr, self._emit_log, show_direct=bool(self._bypass_processes),
            observe_tunnel_host=observe_tunnel_host,
        )
        self._dial_stop().wait(1.5)
        self._ensure_active()
        if process.poll() is not None:
            raise PowEngineError(f"sing-box TUN exited immediately ({process.returncode})")
        self._allow_tun_under_guard()
        bypass_note = (
            f" · {len(self._bypass_processes)} App Bypass"
            if self._bypass_processes else ""
        )
        self._emit_log(
            f"sing-box TUN running → SOCKS 127.0.0.1:{self._exit_port}{bypass_note}"
        )

    def _restart_tun(self) -> bool:
        """Watchdog heal: restart sing-box with the last good stack."""
        from ..paths import BIN
        from . import tun_guard

        if self._stop.is_set() or self._owner_epoch_stale() or self._exit_port <= 0:
            return False
        stack, _ = getattr(self, "_tun_stack", tun_guard.TUN_ATTEMPTS[0])
        preferred_mtu = self._speed.tun_mtu
        if stack == "system" or (stack == "gvisor" and self._speed.tun_backend != "gvisor"):
            preferred_mtu = min(preferred_mtu, 1280)
        mtu = tun_guard.effective_mtu(preferred_mtu, _physical_uplink_mtu())
        self._stop_tun_process()
        try:
            self._start_tun_process(BIN / "sing-box.exe", self._data_dir / "pow-sing-box-tun.json", stack, mtu)
        except PowEngineError:
            return False
        ok, _reason, _facts = tun_guard.verify_tun(self._exit_port, stop=self._dial_stop())
        return ok

    def _stop_tun_process(self) -> bool:
        success = True
        self._warmup.cancel()
        process, self._tun_process = self._tun_process, None
        if process is not None and self.protected:
            try:
                self._kill_switch.set_tunnel(False)
            except (OSError, RuntimeError) as exc:
                self._emit_log(f"Could not revoke the TUN interface permission: {exc}")
                success = False
        job, self._tun_job = getattr(self, "_tun_job", None), None
        self._site_log = None
        if process is not None:
            try:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=6)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
            except Exception:
                success = False
        if job is not None:
            job.close()
        return success

    def _identity_ready(self) -> bool:
        from .config import identity_path

        path = identity_path(self._data_dir)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        return "device_id" in text and "BEGIN CERTIFICATE" in text

    def _ensure_active(self) -> None:
        if self._dial_stop().is_set() or self._stop.is_set() or self._owner_epoch_stale():
            raise PowEngineError("stopped")

    def _log_h2_fragment(self, settings: PowSettings, plan) -> None:
        adaptive = self._adaptive.adaptive_on()
        effective = h2_fragment_effective(settings, "masque", plan, adaptive)
        self._emit_log(
            f"H2 fragment: mode={settings.h2_fragment_mode} effective={str(effective).lower()}"
            f" (recipe={str(plan.fragment).lower()} adaptive={str(adaptive).lower()}"
            f" transport={plan.masque_transport})"
        )

    def _start_adaptive_monitor(self) -> None:
        settings = self._speed
        epoch = self._epoch
        stop = self._stop
        adaptive = self._adaptive

        def _work() -> None:
            self._tls.epoch = epoch
            if stop.wait(5):
                return
            baseline = 0
            opening: list[int] = []
            streak = 0
            retunes = 0
            last_retune = 0.0
            last_stable = time.monotonic()
            recent: list[int] = []
            last_bytes = 0
            last_at = time.monotonic()
            last_router = None
            while self._epoch == epoch and self.running and not stop.is_set():
                interval = 15 if settings.optimized_mode else 7
                if (self._proxy_mode or self._paused
                        or self._status.snapshot().phase != PowPhase.CONNECTED):
                    streak = 0
                    if stop.wait(interval):
                        return
                    continue
                router = self._inner_router
                if (router is None and not self._warp_only) or self._ghost_serving:
                    if stop.wait(interval):
                        return
                    continue
                byte_count, streams, latencies = router.sample_activity() if router else (0, 0, [])
                now = time.monotonic()
                rate = ((byte_count - last_bytes) / max(0.001, now - last_at)
                        if router is last_router else 0)
                last_at, last_bytes, last_router = now, byte_count, router
                if settings.optimized_mode and (rate >= 200 * 1024 or (streams >= 16 and rate >= 32 * 1024)):
                    streak = 0
                    if stop.wait(interval):
                        return
                    continue
                if settings.optimized_mode and latencies:
                    ordered = sorted(latencies)
                    sample = ordered[(len(ordered) + 3) // 4 - 1]
                else:
                    targets = PROBE_TARGETS[:1] if settings.optimized_mode else PROBE_TARGETS
                    sample = measure_path(self._exit_port, stop, targets=targets)
                if stop.is_set() or self._epoch != epoch:
                    return
                if not settings.optimized_mode and len(opening) < 3:
                    opening.append(sample)
                    if len(opening) < 3:
                        if stop.wait(0.55):
                            return
                        continue
                    good = sorted(value for value in opening if value > 0)
                    baseline = good[len(good) // 2] if good else 0
                    recent = good
                recent = (recent + [sample])[-4:]
                jitter = is_jitter_high(recent)
                if self._last_outer_protocol == "masque" and settings.h2_fragment_mode == H2_FRAG_AUTO:
                    adaptive.should_disable(settings, int((now - last_stable) * 1000))
                    adaptive.on_probe(sample > 0, jitter)
                    if sample > 0 and jitter:
                        adaptive.should_enable(settings, True)
                if sample <= 0 or (baseline > 0 and sample >= max(baseline * 155 // 100, baseline + 160)):
                    streak += 1
                else:
                    streak = 0
                    last_stable = now
                    if not baseline:
                        baseline = sample
                    elif sample < baseline:
                        baseline = (baseline * 3 + sample) // 4
                required = 4 if settings.optimized_mode else (3 if jitter else 2)
                limit = 3 if settings.optimized_mode else 5
                if streak >= required and retunes < limit and now - last_retune >= 22:
                    streak = 0
                    retunes += 1
                    if self._refresh_quality_path(epoch, f"latency {sample} ms, baseline {baseline} ms"):
                        last_retune = time.monotonic()
                        baseline = 0
                        recent.clear()
                if stop.wait(interval):
                    return

        threading.Thread(target=_work, name="pow-session-quality", daemon=True).start()

    def _emit_log(self, message: str) -> None:
        try:
            self._log(message)
        except Exception:
            pass

    _key_route: str = ""

    def _on_native_log(self, line: str) -> None:
        text = (line or "").strip()
        if not text:
            return
        peer = speed_module.accepted_peer(text)
        if peer:
            self._note_peer(text, peer)
        # Clean-IP step of the key/cert request (same core flow as mobile:
        # probe Cloudflare key edges from this network, then race ECH / split
        # ClientHello / direct through the clean one that answered).
        if text.startswith("Key: probing ") and "clean key edge" in text:
            self._clean_answered = 0
            self._emit_log("Clean-IP scan for the key/cert request: " + text[len("Key: "):])
        elif text.startswith("Key: clean key address ") and text.endswith(" answered"):
            self._clean_answered = getattr(self, "_clean_answered", 0) + 1
        elif text.startswith("Key: key request will use "):
            chosen = text[len("Key: key request will use "):].strip()
            self._emit_log(
                f"Clean IP for key/cert: {chosen} "
                f"({getattr(self, '_clean_answered', 0)} clean edges answered)"
            )
        elif text.startswith("Key: clean-edge probe returned nothing"):
            self._emit_log("Clean-IP scan found no edge; the racers fall back to the pinned list")
        elif text.startswith(("MASQUE identity refused", "New MASQUE certificate issued",
                              "Could not refresh the MASQUE certificate",
                              "The MASQUE certificate could not be renewed")):
            self._emit_log("Cert loop: " + text[:280])
        if text.startswith("Key:") and "account key won via " in text:
            route = text.split("account key won via ", 1)[1].split()[0].strip()
            self._key_route = route
            self._emit_log(
                f"Key fetch: {self._KEY_ROUTE_NAMES.get(route, route)} won the race; "
                "the other routes were cancelled"
            )
        if text.startswith("Key: OOB method ") and " won" in text:
            self._oob_method = text.split("OOB method ", 1)[1].split()[0].strip()
            self._emit_log(f"Key fetch: OOB method {self._oob_method} won")
        if text.startswith("Key:") or text.startswith("Cert:"):
            self._emit_log(text[:300])
        if self._dialing in ("wireguard", "gool") and text.startswith(("[+]", "[-]", "[*]", "[wg]")):
            # WireGuard/WoW only log to stderr; surface them so a failure has a reason.
            self._emit_log(f"{outer_label(self._dialing)} core: {text[:300]}")
            return
        mapped = stage_line(text)
        if mapped is None:
            return
        if not (text.startswith("Key:") or text.startswith("Cert:")):
            self._emit_log(mapped[:300])
        if mapped.startswith("Scan "):
            parts = mapped.split(" ")
            self._status.scan(mapped, parts[-1] if len(parts) > 2 else "other")
        else:
            failed = mapped.startswith(
                ("Every saved", "Tunnel did not", "UDP/1701 did not", "No usable MASQUE")
            )
            self._status.note(mapped, failed)

    def _on_psiphon_notice(self, kind: str, data: dict) -> None:
        if kind == "log":
            message = str(data.get("message", ""))[:300]
            if message:
                self._emit_log(f"Psiphon: {message}")
        elif kind in ("Error", "Alert"):
            message = str(data.get("message", "")).strip()
            if message:
                self._emit_log(f"Psiphon {kind.lower()}: {message[:300]}")
        elif kind == "Diagnostic":
            text = str(data)[:300]
            if text and text != "{}":
                self._emit_log(f"Psiphon diagnostic: {text}")
        elif kind == "ConnectedServerRegion":
            region = str(data.get("region", ""))
            if region:
                self._exit_region = region

    # -- watchdog ---------------------------------------------------------------
    def notify_resume(self) -> None:
        self._resumed.set()
        self._network_changed.set()

    def _start_watchdog(self) -> None:
        from .network_watch import NetworkNotifications
        from .tun_guard import verify_proxy

        epoch = self._epoch
        stop = self._stop
        self._network_changed.clear()
        self._resumed.clear()

        def _watch() -> None:
            self._tls.epoch = epoch
            try:
                notifications = NetworkNotifications(self._network_changed)
            except OSError as exc:
                notifications = None
                self._emit_log(f"Could not register network change notifications: {exc}")
            try:
                _watch_session()
            finally:
                if notifications is not None:
                    notifications.close()

        def _watch_session() -> None:
            next_probe = time.monotonic() + 30
            strikes = 0
            uplink = self._network()
            while not stop.wait(3):
                if self._epoch != epoch or not self._connected.is_set():
                    return
                if self._paused or self._path_cancel.is_set():
                    continue
                if not self._retune_lock.acquire(blocking=False):
                    continue
                self._retune_lock.release()
                if self._route_pending.is_set():
                    if not self._recover(epoch, "selected route changed", immediate=True):
                        return
                    continue
                if not self._proxy_mode and self._speed.kill_switch and not self.protected:
                    if not self._recover(epoch, "VPN kill switch helper exited"):
                        return
                    continue
                outer_dead = (self._warp_only or not self._direct_psiphon) and not self._aether.running
                if self._ghost_serving and not outer_dead and self._retune_lock.acquire(blocking=False):
                    try:
                        with self._path_work(epoch):
                            self._finish_ghost()
                    except PowEngineError:
                        if self._stop.is_set() or self._epoch != epoch:
                            return
                    finally:
                        self._retune_lock.release()
                ghost = self._psiphon_ghost if self._ghost_serving else None
                inner_dead = (not self._warp_only) and not (
                    ghost.running if ghost is not None else self._psiphon.running
                )
                if outer_dead or inner_dead:
                    if outer_dead:
                        reason = f"outer leg exited ({self._aether.exit_detail()})"
                    else:
                        reason = "Psiphon exited"
                    self._emit_log(f"UAC PoW leg lost: {reason}")
                    if outer_dead and not inner_dead and self._promote_parallel(epoch):
                        continue
                    if not self._recover(epoch, reason):
                        return
                    continue
                if self._network_changed.is_set():
                    self._network_changed.clear()
                    key, label = self._network_detector()
                    resumed = self._resumed.is_set()
                    self._resumed.clear()
                    if self._epoch != epoch or stop.is_set():
                        return
                    self._check_lan_interface()
                    if key != uplink or resumed:
                        uplink = key
                        self._stop_lan_share()
                        self._network_key, self._network_label = key, label
                        ok, _ = verify_proxy(self._exit_port, "socks5h", timeout=2)
                        if not ok and not self._recover(epoch, "underlying network changed"):
                            return
                        if self._lan_process is None:
                            self.apply_lan_share()
                        strikes = 0
                if time.monotonic() >= next_probe:
                    next_probe = time.monotonic() + 30
                    self._check_lan_interface()
                    ok, why = verify_proxy(self._exit_port, "socks5h", timeout=2)
                    strikes = 0 if ok else strikes + 1
                    if strikes >= 2:
                        if not self._recover(epoch, f"exit probe failed: {why}"):
                            return
                        strikes = 0
                if not self._tun_healthy(epoch):
                    return

        self._tun_misses = 0
        self._tun_next_probe = time.monotonic() + 30
        thread = threading.Thread(target=_watch, name="pow-watchdog", daemon=True)
        self._watchdog = thread
        thread.start()

    # -- auto-reconnect -------------------------------------------------------------
    def _alive_extras(self) -> list:
        return [s for s in list(getattr(self, "_sessions", []) or [])
                if s.get("process") is not None and getattr(s["process"], "running", False)]

    def _promote_parallel(self, epoch: int) -> bool:
        """Keep live extras serving while restoring the main MASQUE listener."""
        with self._lock:
            parallel = self._parallel_cancel
            extras = self._alive_extras()
            if not self._parallel_alive(epoch, parallel) or not extras:
                return False
            if self._main_restart_owner is parallel:
                return True
            self._main_restart_owner = parallel
        self._emit_log(f"Main session down; {len(extras)} parallel session(s) keep carrying traffic")

        def _bring_back() -> None:
            try:
                with self._path_work(epoch) as stop:
                    delay = 2.0
                    while not stop.is_set() and self._parallel_alive(epoch, parallel):
                        if not self._retune_lock.acquire(blocking=False):
                            return
                        try:
                            if self._paused or stop.is_set() or not self._parallel_alive(epoch, parallel):
                                return
                            if not self._alive_extras():
                                return
                            old = self._aether
                            settings = self._speed
                            mci = uses_mci_firewall(settings)
                            candidates, _pool = self._clean_candidates(self._network_key or "default")
                            peer = (candidates or [self._won_peer or ""])[0]
                            process = self._launch_extra(settings, mci, CHAIN_SOCKS_PORT, peer)
                            installed = False
                            try:
                                if process.wait_ready(CHAIN_SOCKS_PORT, 45_000, stop):
                                    with self._lock:
                                        if (self._parallel_alive(epoch, parallel) and not stop.is_set()
                                                and not self._paused and self._aether is old):
                                            self._aether = process
                                            installed = True
                                if installed:
                                    old.stop()
                                    self._emit_log(f"Main session back on {peer or 'a scanned address'}")
                                    return
                            finally:
                                if not installed:
                                    process.stop()
                        except Exception as exc:
                            if not stop.is_set() and self._parallel_alive(epoch, parallel):
                                self._emit_log(f"Parallel MASQUE main restart failed: {exc}")
                        finally:
                            self._retune_lock.release()
                        if stop.wait(delay):
                            return
                        delay = min(delay * 2, 60.0)
            finally:
                with self._lock:
                    if self._main_restart_owner is parallel:
                        self._main_restart_owner = None

        threading.Thread(target=_bring_back, name="pow-main-restart", daemon=True).start()
        return True

    def _raise_legs_again(self, *, retune: bool = False, fresh: bool = False) -> None:
        self._stop_inner_pool(keep_router=not self._proxy_mode)
        settings = self._speed
        mci = uses_mci_firewall(settings)
        try:
            self._psiphon.stop()
        except Exception:
            pass
        try:
            self._aether.stop()
        except Exception:
            pass
        self._stop_parallel_masque()
        if fresh:
            self._store.forget_path_cache(keep_clean_h2=settings.link_recipe == RECIPE_MASQUE_H2_SAVED)
        plan = outer_plan(settings, mci)
        if retune:
            preferred_path = self._last_outer_protocol or self._store.remembered_outer_protocol()
            ordered = sorted(plan.protocols, key=lambda protocol: protocol != preferred_path)
        else:
            ordered = plan.protocols if plan.fixed_order else self._order_ladder(plan.protocols)
        ordered, preferred = self._apply_transport_choice(settings, plan, ordered)
        outer = None
        if not self._direct_psiphon or self._warp_only:
            outer = self._raise_outer_leg(
                settings, plan.protocols, ordered, mci, preferred=preferred,
                retune=retune, discovery=DISCOVERY_FRESH if fresh else DISCOVERY_CACHE,
            )
            if outer is None:
                raise PowEngineError("WARP did not come up")
            self._outer_label = outer
            if not self._stop.is_set():
                self._start_parallel_masque(settings, mci)
        self._ensure_active()
        if self._warp_only:
            self._exit_port = self._chain_port
        else:
            self._start_psiphon_tunnel(settings, retune=retune)
            self._exit_port = self._psiphon_port
            self._start_inner_pool()

    def _refresh_quality_path(self, epoch: int, reason: str) -> bool:
        if not self._retune_lock.acquire(blocking=False):
            return False
        try:
            with self._path_work(epoch) as stop:
                if self._epoch != epoch or stop.is_set():
                    return False
                if self._ghost_eligible():
                    # Android keeps the live path if a make-before-break attempt fails.
                    return self._try_ghost_handover(reason)
                with self._exit_lock:
                    if (self._epoch != epoch or stop.is_set() or self._paused
                            or self._proxy_mode or not self.running or self._ghost_serving
                            or self._tun_process is None or self._tun_process.poll() is not None):
                        return False
                    previous_exit = self._exit_port
                    self._warmup.cancel()
                    self._status.update(PowPhase.OUTER, 30, "Refreshing the PoW path", outer_label=self._outer_label)
                    self._emit_log(f"Refreshing the PoW path after {reason}")
                    try:
                        if self._warp_only:
                            self._raise_legs_again(retune=True, fresh=not self._speed.optimized_mode)
                        else:
                            self._refresh_inner_then_warp()
                        self._verify_rebuilt_exit(previous_exit)
                        self._ensure_active()
                        self._status.update(PowPhase.CONNECTED, 100, "UAC PoW ready", outer_label=self._outer_label)
                    except Exception as exc:
                        if stop.is_set():
                            return False
                        self._emit_log(f"PoW path refresh failed: {exc}")
                    else:
                        self._emit_log("UAC PoW path refreshed")
                        self._warm_path()
                        self.refresh_exit_info(background=True)
                        return True
                if self._epoch == epoch and not stop.is_set():
                    self._recover(epoch, "quality retune failed")
                return False
        finally:
            self._retune_lock.release()

    def _recover(self, epoch: int, reason: str, *, immediate: bool = False) -> bool:
        """Wait for recovery while keeping the session's routing in place."""
        if not self._retune_lock.acquire(blocking=False):
            return True
        try:
            with self._path_work(epoch):
                return self._recover_inner(epoch, reason, immediate=immediate)
        finally:
            self._retune_lock.release()

    def _wait_for_restore(self, epoch: int, delay: float) -> bool | None:
        """None cancels; True restarts backoff after an available uplink."""
        deadline = time.monotonic() + delay
        stop = self._dial_stop()
        while not stop.is_set() and self._epoch == epoch and not self._paused:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            if not self._network_changed.wait(min(0.25, remaining)):
                continue
            self._network_changed.clear()
            resumed = self._resumed.is_set()
            self._resumed.clear()
            key, label = self._network_detector()
            previous = self._network_key
            self._network_key, self._network_label = key, label
            if key != "default" and (resumed or key != previous):
                return True
        return None

    def _rebuild_inner(self) -> None:
        self._stop_inner_pool(keep_router=not self._proxy_mode)
        self._psiphon.stop()
        self._ensure_active()
        self._start_psiphon_tunnel(self._speed, retune=True)
        self._exit_port = self._psiphon_port
        self._start_inner_pool()

    def _refresh_inner_then_warp(self) -> None:
        try:
            self._rebuild_inner()
        except PowEngineError:
            self._ensure_active()
            if self._direct_psiphon:
                raise
            self._emit_log("Inner refresh failed; searching for a fresh WARP path")
            self._raise_legs_again(retune=True, fresh=True)

    def _repair_legs(self) -> None:
        from .tun_guard import verify_proxy

        if (not self._warp_only and not self._direct_psiphon and self._aether.running
                and verify_proxy(self._chain_port, "socks5h", timeout=2, stop=self._dial_stop())[0]):
            self._emit_log("Outer path verified; rebuilding Psiphon behind WARP")
            self._refresh_inner_then_warp()
        elif self._direct_psiphon and not self._warp_only:
            self._rebuild_inner()
        else:
            self._raise_legs_again(retune=True, fresh=True)

    def _verify_rebuilt_exit(self, previous_exit: int) -> None:
        from . import tun_guard

        success, why = tun_guard.verify_proxy(self._exit_port, "socks5h", stop=self._dial_stop())
        if not success:
            raise PowEngineError(f"recovered exit could not carry traffic: {why}")
        self._ensure_active()
        if self._proxy_mode:
            if self._proxy is not None and self._exit_port == previous_exit:
                ok, why = tun_guard.verify_proxy(self._forward_port, "http", stop=self._dial_stop())
                if ok:
                    return
                self._emit_log(f"Rebuilding the local proxy: {why}")
            self._teardown_exit()
            self._enable_proxy()
        else:
            if (self._tun_process is not None and self._tun_process.poll() is None
                    and self._exit_port == previous_exit):
                ok, why, _facts = tun_guard.verify_tun(self._exit_port, stop=self._dial_stop())
                if ok:
                    return
                self._emit_log(f"Rebuilding TUN after verification failed: {why}")
            self._stop_tun_process()
            self._enable_tun()

    def _recover_inner(self, epoch: int, reason: str, *, immediate: bool = False) -> bool:
        stop = self._dial_stop()
        started = time.monotonic()
        backoff = (5, 15, 30, 60, 120)
        attempt = 0
        with self._exit_lock:
            if stop.is_set() or self._epoch != epoch or self._paused:
                return self._epoch == epoch and not self._stop.is_set()
            self._warmup.cancel()
            self._stop_lan_share()
            self._status.update(PowPhase.OUTER, 30, f"Reconnecting after {reason}.", outer_label=self._outer_label)
            self._emit_log(f"Reconnecting: {reason}")
        while not stop.is_set() and self._epoch == epoch and not self._paused:
            delay = 0 if immediate else backoff[min(attempt, len(backoff) - 1)]
            available = self._wait_for_restore(epoch, delay)
            if available is None:
                break
            if available:
                attempt = 0
                self._emit_log("Network restored; retrying PoW now")
            elif not immediate:
                attempt += 1
            immediate = False
            previous_exit = self._exit_port
            try:
                self._ensure_active()
                with self._exit_lock:
                    if self._paused:
                        return True
                    if not self._proxy_mode and self._speed.kill_switch and not self.protected:
                        self._ensure_kill_switch()
                        if self._tun_process is not None and self._tun_process.poll() is None:
                            self._allow_tun_under_guard()
                    self._repair_legs()
                    self._ensure_active()
                    self._verify_rebuilt_exit(previous_exit)
                    self._ensure_active()
                    self._route_pending.clear()
                    self._status.update(PowPhase.CONNECTED, 100, "UAC PoW ready", outer_label=self._outer_label)
                self._emit_log(f"Reconnected in {int(time.monotonic() - started)}s")
                self.apply_lan_share()
                self._warm_path()
                self.refresh_exit_info(background=True)
                return True
            except Exception as exc:
                if self._stop.is_set() or self._epoch != epoch:
                    return False
                if stop.is_set():
                    return True
                self._emit_log(f"Reconnect attempt failed: {type(exc).__name__}: {exc}")
        return (self._paused or stop.is_set()) and self._epoch == epoch and not self._stop.is_set()

    def _tun_healthy(self, epoch: int) -> bool:
        """False when the watchdog should stop. Heals TUN in place."""
        from . import tun_guard

        with self._path_work(epoch) as stop, self._exit_lock:
            if self._epoch != epoch or self._stop.is_set():
                return False
            if self._paused or self._proxy_mode or stop.is_set():
                return True
            process = self._tun_process
            dead = process is None or process.poll() is not None
            if not dead and time.monotonic() < self._tun_next_probe:
                return True
            self._tun_next_probe = time.monotonic() + 30
            if not dead and tun_guard.quick_health():
                self._tun_misses = 0
                return True
            self._tun_misses = 0 if dead else self._tun_misses + 1
            if not dead and self._tun_misses < 2:
                return True
            self._emit_log("TUN health check failed; repairing the system tunnel")
            if self._restart_tun():
                self._tun_misses = 0
                self._emit_log("TUN repaired")
                self._warm_path()
                return True
            if stop.is_set():
                return self._epoch == epoch and not self._stop.is_set()
        return self._recover(epoch, "system tunnel stopped working")

    def _fail(self, reason: str) -> None:
        if self._stop.is_set():
            return
        self.disconnect(quiet=True, epoch=self._epoch, keep_guard=self.protected)
        if self.protected:
            reason += ". Kill switch is still active."
        self._emit_log(f"UAC PoW path lost: {reason}")
        try:
            self._status.update(PowPhase.FAILED, 0, reason)
        except Exception:
            pass
        self._connected.clear()
