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
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

from . import runner as runner_module
from .config import (
    CHAIN_SOCKS_PORT,
    PSIPHON_SOCKS_PORT,
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
    ADAPTIVE_PROBE_INTERVAL_S,
    ADAPTIVE_SETTLE_S,
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

_NETWORK_SCRIPT = (
    "$r=Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | "
    "Where-Object { $_.InterfaceAlias -notlike 'UAC-Spoofer*' } | "
    "Sort-Object { $_.RouteMetric + $_.InterfaceMetric } | Select-Object -First 1; "
    "if ($r) { $n=Get-NetNeighbor -IPAddress $r.NextHop -ErrorAction SilentlyContinue | Select-Object -First 1; "
    "$p=Get-NetConnectionProfile -InterfaceIndex $r.ifIndex -ErrorAction SilentlyContinue | Select-Object -First 1; "
    "'{0}|{1}|{2}|{3}' -f $r.InterfaceAlias,$r.NextHop,$n.LinkLayerAddress,$p.Name }"
)


def detect_network() -> tuple[str, str]:
    """(key, label) for the current uplink: gateway MAC + network profile.

    Desktop stand-in for mobile ``PowNetworkScoreboard.networkKey``. Falls
    back to ``default`` when Windows does not tell us.
    """
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _NETWORK_SCRIPT],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        line = (result.stdout or "").strip().splitlines()
        parts = line[-1].split("|") if line else []
    except Exception:
        parts = []
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
        self._tun_process: subprocess.Popen | None = None
        self._tun_job = None
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
        self._parallel_thread = None
        self._connected = threading.Event()
        self._exit_port = 0
        self._exit_region = ""
        self._outer_label = ""
        self._direct_psiphon = False
        self._warp_only = False
        self._proxy_mode = True
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
        """Real exit of the running session: True = Windows proxy (chosen or TUN
        fallback), False = TUN, None = not connected."""
        if not self._connected.is_set():
            return None
        return bool(self._proxy_mode or getattr(self, "_tun_fell_back", False))

    def switch_exit_mode(self, target) -> str:
        """Live TUN <-> Windows proxy switch while connected.

        The old exit is really torn down (sing-box TUN stopped / system proxy
        restored) before the new one starts; the legs stay up. ``target`` may be
        a callable so several quick clicks converge on the latest choice.
        """
        with self._exit_lock:
            want_proxy = bool(target() if callable(target) else target)
            if not self._connected.is_set():
                return "idle"
            current = bool(self._proxy_mode or getattr(self, "_tun_fell_back", False))
            if current == want_proxy:
                if want_proxy:
                    self._proxy_mode = True
                return "unchanged"
            self._tls.epoch = self._epoch
            with self._session_work():
                names = {True: "Windows proxy", False: "TUN"}
                self._emit_log(f"Switching exit {names[current]} -> {names[want_proxy]} while connected")
                self._teardown_exit()
                self._proxy_mode = want_proxy
                self._tun_fell_back = False
                try:
                    self._ensure_active()
                    if want_proxy:
                        self._enable_proxy()
                    else:
                        self._enable_tun()
                except PowEngineError as exc:
                    if self._stop.is_set() or self._owner_epoch_stale():
                        return "stopped"
                    self._emit_log(f"Exit switch failed: {exc}")
                    self._teardown_exit()
                    try:
                        self._tun_fell_back = not want_proxy
                        self._enable_proxy()
                    except Exception as again:
                        self._fail(f"exit switch failed: {again}")
                        return "failed"
                actual = bool(self._proxy_mode or self._tun_fell_back)
                self._emit_log(
                    f"Exit now: {names[actual]}"
                    + (" (TUN unavailable, Windows proxy instead)" if self._tun_fell_back else "")
                )
                return "proxy" if actual else "tun"

    def _teardown_exit(self) -> None:
        """Stop whatever carries the exit: sing-box (TUN or App Bypass proxy),
        the HTTP forwarder and the Windows system proxy."""
        self._stop_tun_process()
        forwarder, self._forwarder = self._forwarder, None
        if forwarder is not None:
            try:
                forwarder.stop()
            except Exception:
                pass
        proxy, self._proxy = self._proxy, None
        if proxy is not None:
            try:
                proxy.suspend()
            except Exception:
                pass

    @property
    def exit_port(self) -> int:
        return self._exit_port

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

    def _restore_windows_proxy(self) -> None:
        """Give the user back their own proxy values after a PoW session."""
        if not self._proxy_session:
            return
        self._proxy_session = False
        try:
            from ..engine import WindowsProxy

            WindowsProxy(log=self._emit_log).disable()
        except Exception as exc:
            self._emit_log(f"Windows proxy restore pending: {exc}")

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
    ) -> str:
        """Blocking connect. Raises PowEngineError on failure."""
        settings = settings.validated()
        with self._lock:
            self._epoch += 1
            self._connect_epoch = self._epoch
            my_epoch = self._epoch
        self._tls.epoch = my_epoch
        self.disconnect(quiet=True, epoch=my_epoch)
        if self._wait_previous_work(my_epoch):
            # The older attempt may have started a helper after the first
            # cleanup ran; sweep once more now that it has unwound.
            self.disconnect(quiet=True, epoch=my_epoch)
        if self._epoch != my_epoch:
            raise PowEngineError("stopped")
        self._stop.clear()
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
        with self._session_work():
            return self._connect_session(settings, proxy_mode, bypass_processes)

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
        self._start_network_detect()
        status = self._status
        status.reset()
        status.update(PowPhase.STARTING, 5, "Starting UAC PoW")

        self._speed = settings
        self._accepted_peers = []
        self._won_peer = ""
        self._h3_transport = ""
        self._chain_port = CHAIN_SOCKS_PORT
        mci = uses_mci_firewall(settings)
        plan = outer_plan(settings, mci)
        self._log_speed_options(settings, mci)
        ordered = self._order_ladder(plan.protocols)
        ordered, preferred = self._apply_transport_choice(settings, plan, ordered)
        if not ordered:
            raise PowEngineError("no WARP transport selected")

        fast_direct = False
        if settings.direct_psiphon_first:
            fast_direct = self._try_direct_psiphon_fast(settings)
        if fast_direct:
            outer = None
        else:
            outer = self._raise_outer_leg(settings, plan.protocols, ordered, mci, preferred=preferred)
            if outer is not None and not self._stop.is_set():
                self._start_parallel_masque(settings, mci)
        if self._stop.is_set():
            raise PowEngineError("stopped")
        chain = settings.chain_psiphon
        if not chain and outer is None:
            status.update(PowPhase.FAILED, 0, "WARP did not come up")
            raise PowEngineError("WARP did not come up")

        if not chain:
            outer_name = outer or "WARP"
            self._warp_only = True
            self._exit_port = self._chain_port
            self._outer_label = outer_name
        else:
            self._direct_psiphon = outer is None
            outer_name = outer or "Psiphon"
            if self._direct_psiphon and not fast_direct:
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

        self._ensure_active()
        if proxy_mode:
            status.update(PowPhase.BRIDGING, 88, "Pointing Windows proxy at UAC PoW")
            self._enable_proxy()
        else:
            status.update(PowPhase.BRIDGING, 90, "Routing device traffic through UAC PoW")
            self._enable_tun()

        self._store.save_last_connect(
            LastConnect(
                protocol="psiphon" if (chain and self._direct_psiphon) else self._last_outer_protocol or "psiphon",
                transport=self._won_transport,
                ip=self._won_ip,
                peer="",
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
        self._start_watchdog()
        self._start_adaptive_monitor()
        if settings.lowest_rtt_ip:
            self._start_clean_ip_memory()
        self.refresh_exit_info(background=True)
        if proxy_mode or self._tun_fell_back:
            return f"UAC PoW ready · Proxy 127.0.0.1:{self._exit_port}"
        return ready

    def disconnect(self, quiet: bool = False, epoch: int | None = None) -> None:
        with self._lock:
            if epoch is None:
                self._epoch += 1
            elif self._epoch != epoch:
                # A newer connect owns the processes. This cancel is stale.
                return
            seen = self._epoch
            self._stop.set()
        self._connected.clear()
        watchdog, self._watchdog = self._watchdog, None
        if watchdog is not None and watchdog.is_alive():
            watchdog.join(timeout=2)
        if self._epoch != seen:
            return
        try:
            self._psiphon.stop()
        except Exception:
            pass
        try:
            self._aether.stop()
        except Exception:
            pass
        self._stop_parallel_masque()
        self._exit_info = {}
        self._parallel_note = ""
        with self._exit_lock:
            self._teardown_exit()
            self._restore_windows_proxy()
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

    # -- outer leg ----------------------------------------------------------
    _last_outer_protocol: str = ""
    _won_transport: str = ""
    _won_ip: str = ""

    def _order_ladder(self, ladder: list[str]) -> list[str]:
        remembered = None
        try:
            remembered = self._store.remembered_outer_protocol()
        except Exception:
            remembered = None
        ordered = list(ladder)
        if remembered in ordered:
            ordered.remove(remembered)
            ordered.insert(0, remembered)
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
    ) -> str | None:
        status = self._status
        for offset, protocol in enumerate(ordered):
            self._ensure_active()
            label = outer_label(protocol)
            # Mobile parity: the first MASQUE attempt runs the thorough scan
            # (180 s budget); later attempts use the user's scan mode.
            attempt_scan = attempt_scan_mode(protocol, offset, settings.scan_mode)
            budget = outer_budget_ms(protocol, scan_mode=attempt_scan)
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
                self._emit_log("Key: saved WARP key and MASQUE certificate found; skipping the key request")
            else:
                status.update(
                    PowPhase.OUTER, 15 + offset * 10, "Getting a WARP key", outer_label=label
                )
                error = self._fetch_key(settings, protocol, label)
                if self._stop.is_set():
                    return None
                if error is not None:
                    self._emit_log(f"{label} could not be prepared: {error}")
                    if protocol == "masque":
                        self._emit_log(
                            "Key fetch failed on every route; Psiphon will try to connect on its own"
                            if settings.chain_psiphon
                            else "Key fetch failed on every route"
                        )
                        status.note("Key request failed. Staying on this method.", True)
                        return None
                    continue
                status.update(
                    PowPhase.OUTER, 20 + offset * 10, f"Connecting {label}", outer_label=label
                )
            plan_now = outer_plan(settings, mci)
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
                ready = self._dial_irancell_h3(settings, mci, attempt_scan, budget)
            else:
                outer_json = chain_outer_json(
                    self._data_dir,
                    protocol,
                    settings,
                    scan_mode=attempt_scan,
                    mci=mci,
                )
                try:
                    with self._lock:
                        if self._epoch != self._connect_epoch or self._owner_epoch_stale():
                            raise PowEngineError("stopped")
                        self._aether.start(outer_json)
                except PowEngineError:
                    raise
                except Exception as exc:
                    self._emit_log(f"{label} could not start: {exc}")
                    if protocol == "masque":
                        status.note("Scan finished. Staying on this method.", True)
                        return None
                    continue
                ready = self._aether.wait_ready(CHAIN_SOCKS_PORT, budget, self._stop)
            if ready:
                try:
                    self._store.save_outer_protocol(protocol)
                except Exception:
                    pass
                self._last_outer_protocol = protocol
                plan = outer_plan(settings, mci)
                self._won_transport = (
                    (self._h3_transport or plan.masque_transport) if protocol == "masque" else ""
                )
                self._won_ip = plan.ip_for(protocol)
                if preferred and protocol != preferred:
                    wanted = outer_label(preferred)
                    self._emit_log(
                        f"{wanted} did not connect; fell back to {label}, which is carrying the outer leg"
                    )
                    return f"{label} ({wanted} failed, fell back)"
                self._emit_log(f"{label} is carrying the outer leg")
                return label
            if self._stop.is_set():
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
        self, settings: PowSettings, mci: bool, scan_mode: str, budget: int
    ) -> bool:
        """Irancell: MASQUE over HTTP/3 for a short window, then HTTP/2."""
        from .config import IRANCELL_H3_BUDGET_MS

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
                scan_mode=scan_mode,
                mci=mci,
                masque_transport=transport,
            )
            try:
                with self._lock:
                    if self._epoch != self._connect_epoch or self._owner_epoch_stale():
                        raise PowEngineError("stopped")
                    self._aether.start(outer_json)
            except PowEngineError:
                raise
            except Exception as exc:
                self._emit_log(f"MASQUE over HTTP/{'3' if transport == 'h3' else '2'} could not start: {exc}")
                continue
            if self._aether.wait_ready(CHAIN_SOCKS_PORT, window, self._stop):
                self._h3_transport = transport
                self._emit_log(
                    "HTTP/3 on Irancell: HTTP/3 won"
                    if transport == "h3"
                    else "HTTP/3 on Irancell: HTTP/2 fallback won"
                )
                return True
            if self._stop.is_set():
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
        self._router = router
        self._chain_port = speed_module.ROUTER_PORT
        self._sessions = [{"port": CHAIN_SOCKS_PORT, "peer": self._won_peer, "process": None}]
        self._parallel_note = "looking for more clean addresses…"
        self._emit_log(
            f"Parallel MASQUE: router on 127.0.0.1:{speed_module.ROUTER_PORT} in front of the main session; "
            "extra sessions join in the background (no reconnect)"
        )
        epoch = self._epoch
        thread = threading.Thread(
            target=self._grow_parallel, args=(settings, mci, epoch), name="pow-parallel-grow", daemon=True
        )
        self._parallel_thread = thread
        thread.start()

    def _parallel_alive(self, epoch: int) -> bool:
        return self._router is not None and self._epoch == epoch and not self._stop.is_set()

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

    def _join_router(self, port: int, peer: str, process) -> None:
        with self._lock:
            router = self._router
            if router is not None:
                router.add_upstream(port)
                self._extras.append(process)
                self._sessions.append({"port": port, "peer": peer, "process": process})
                self._parallel_note = ""
        if router is None:
            process.stop()
            return
        self._emit_log(
            f"Parallel MASQUE: session to {peer or 'a scanned address'} is up on {port}; "
            f"{len(self._sessions)} sessions, new connections are spread per site"
        )

    def _grow_parallel(self, settings: PowSettings, mci: bool, epoch: int) -> None:
        from .config import PARALLEL_DISCOVERY_BUDGET_MS, PARALLEL_EXTRA_BUDGET_MS

        free_ports = list(speed_module.EXTRA_PORTS)
        network = self._network_key or "default"
        candidates, _pool = self._clean_candidates(network)
        others = [p for p in candidates if p != self._won_peer][: len(free_ports)]
        reasons: list[str] = []
        if others:
            self._emit_log("Parallel MASQUE: trying extra sessions to " + ", ".join(others))
        for peer in others:
            if not self._parallel_alive(epoch):
                return
            port = free_ports[0]
            try:
                process = self._launch_extra(settings, mci, port, peer)
            except Exception as exc:
                reasons.append(f"{peer} could not start ({exc})")
                continue
            if process.wait_ready(port, PARALLEL_EXTRA_BUDGET_MS, self._stop) and self._parallel_alive(epoch):
                free_ports.pop(0)
                self._join_router(port, peer, process)
                continue
            last = getattr(process, "last_lines", None)
            why = (last[-1] if last else "").strip()[:160]
            reasons.append(f"{peer} did not come up in {PARALLEL_EXTRA_BUDGET_MS // 1000}s" + (f" ({why})" if why else ""))
            self._emit_log(f"Parallel MASQUE: {reasons[-1]}")
            try:
                process.stop()
            except Exception:
                pass
        if len(self._sessions) >= 2 or not free_ports or not self._parallel_alive(epoch):
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
        if process.wait_ready(port, PARALLEL_DISCOVERY_BUDGET_MS, self._stop) and self._parallel_alive(epoch):
            found = speed_module.read_clean_list(scan_dir)
            peer = found[0] if found else ""
            self._join_router(port, peer, process)
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
        if self._parallel_alive(epoch):
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

    def _stop_parallel_masque(self) -> None:
        with self._lock:
            self._sessions = []
            router, self._router = self._router, None
            extras_now, self._extras = self._extras, []
        if router is not None:
            try:
                router.stop()
            except Exception:
                pass
        for process in extras_now:
            try:
                process.stop()
            except Exception:
                pass
        self._chain_port = CHAIN_SOCKS_PORT

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
        net_off = _os.environ.get("UAC_NET_KEYFETCH", "").strip().lower() in ("0", "off", "false", "no")
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
            if self._stop.is_set():
                self._emit_log("Key fetch cancelled")
                return "stopped"
        for index, (camo, timeout) in enumerate(attempts):
            if self._stop.is_set():
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
                    stop=self._stop,
                    timeout=timeout,
                    api_camo=camo,
                )
            except Exception as exc:
                if self._stop.is_set():
                    self._emit_log("Key fetch cancelled")
                    return "stopped"
                last_error = str(exc)
                self._emit_log(f"{prefix} failed after {time.monotonic() - started:.0f}s: {last_error}")
                if index == 0 and camo == KEY_AUTO and protocol == "masque" and not net_off and not net_tried:
                    if self._net_key_lane(protocol, label):
                        return None
                    if self._stop.is_set():
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
            if self._stop.is_set() or time.monotonic() >= deadline:
                try:
                    process.kill()
                except Exception:
                    pass
                if not self._stop.is_set():
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

    def _start_psiphon_tunnel(self, settings: PowSettings) -> None:
        from .config import (
            NEARBY,
            NEARBY_PHASE_TIMEOUT_SECONDS,
            REGION_PHASE_TIMEOUT_SECONDS,
            auto_bias_region,
            psiphon_config,
            strategy_signature,
        )

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
        if explicit is None and not direct:
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

        for strategy, preferred, bias, fallback in attempts:
            self._ensure_active()
            config_json = psiphon_config(
                socks_port=self._psiphon_port,
                data_directory=str(inner_dir),
                preferred_region=preferred or None,
                strategy=strategy,
                optimized_mode=settings.optimized_mode,
                direct=direct,
                region_bias=bias,
                upstream_port=self._chain_port,
            )
            timeout = psiphon_wait_seconds(config_json, fallback, bias)
            self._emit_log(
                f"Psiphon strategy {strategy.name} ({strategy.label})"
                + (f" region={preferred}" if preferred else "")
                + (f" (nearby, {NEARBY_PHASE_TIMEOUT_SECONDS}s then any)" if bias else "")
                + f"; waiting up to {timeout}s"
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
            if self._psiphon.wait_connected(float(timeout), self._stop):
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
                    + f"{region_name(preferred)} ({preferred}) did not connect in {timeout}s; trying any country"
                )
            else:
                self._emit_log(f"Psiphon strategy {strategy.name} did not connect in {timeout}s")
        status.update(PowPhase.FAILED, 0, "Psiphon did not connect in time")
        raise PowEngineError("Psiphon did not connect in time")

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

    def _measure_tunnel_rtt(self) -> int:
        host, port = _RTT_PROBE_TARGET
        name = host.encode("idna")
        request = bytes([0x05, 0x01, 0x00, 0x03, len(name)]) + name + port.to_bytes(2, "big")
        samples: list[int] = []
        for _ in range(_RTT_PROBE_SAMPLES):
            if self._stop.is_set():
                break
            try:
                socks_port = self._chain_port if self._warp_only else self._psiphon_port
                with socket.create_connection(("127.0.0.1", socks_port), timeout=8) as sock:
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
    def _enable_proxy(self) -> None:
        from ..engine import WindowsProxy, build_singbox_proxy_bypass_config
        from ..paths import BIN
        from .forwarder import HttpToSocks

        port = int(self._forward_port or FORWARD_HTTP_PORT)
        if not tcp_accepts(self._exit_port):
            time.sleep(_EXIT_GRACE_SECONDS)
        if not tcp_accepts(self._exit_port):
            raise PowEngineError("exit proxy is not listening")

        bypass = list(self._bypass_processes)
        if bypass:
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
            proxy = WindowsProxy(log=self._emit_log)
            # Mixed inbound serves both HTTP and SOCKS on the same port.
            proxy.resume(socks_port=port, http_port=port)
            self._proxy = proxy
            self._proxy_session = True
            self._emit_log(
                f"Windows system proxy → App Bypass mixed 127.0.0.1:{port} "
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
        proxy = WindowsProxy(log=self._emit_log)
        proxy.resume(socks_port=self._exit_port, http_port=port)
        self._proxy = proxy
        self._proxy_session = True
        self._emit_log(
            f"Windows system proxy → SOCKS 127.0.0.1:{self._exit_port} "
            f"HTTP 127.0.0.1:{port}"
        )

    def _enable_tun(self) -> None:
        """Whole-device TUN, verified for real before we call it connected.

        Falls back to the Windows proxy (and says why) instead of failing the
        whole connect when TUN cannot work on this PC.
        """
        import ctypes
        import sys

        from . import tun_guard

        if sys.platform == "win32":
            try:
                admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                admin = False
            if not admin:
                self._tun_fallback("TUN needs administrator access")
                return
        from ..paths import BIN

        binary = BIN / "sing-box.exe"
        if not binary.is_file():
            self._tun_fallback("sing-box.exe is missing")
            return
        self._ensure_active()
        if self._exit_port <= 0:
            # A newer connect / disconnect reset the exit; never point TUN at port 0.
            raise PowEngineError("exit proxy is not listening")
        if not tcp_accepts(self._exit_port):
            time.sleep(_EXIT_GRACE_SECONDS)
        if not tcp_accepts(self._exit_port):
            raise PowEngineError("exit proxy is not listening")
        config_path = self._data_dir / "pow-sing-box-tun.json"
        # A crashed earlier run may still hold the adapter and routes.
        tun_guard.kill_stale(str(config_path), self._emit_log)
        last = ""
        for attempt, (stack, mtu) in enumerate(tun_guard.TUN_ATTEMPTS, 1):
            self._ensure_active()
            if attempt > 1:
                self._emit_log(f"TUN repair {attempt}/{len(tun_guard.TUN_ATTEMPTS)}: stack {stack}, MTU {mtu}")
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
                ok, reason, facts = tun_guard.verify_tun(self._exit_port)
                if ok:
                    break
                time.sleep(1.5)
            if ok:
                self._tun_stack = (stack, mtu)
                self._emit_log(
                    f"TUN verified: DNS {facts.get('dns_ms', 0)} ms, HTTPS {facts.get('https_ms', 0)} ms, "
                    f"exit {facts.get('ip', '?')} ({facts.get('loc', '?')})"
                )
                return
            last = reason
            self._emit_log(f"TUN check failed: {reason}")
            self._stop_tun_process()
        vpn = tun_guard.other_vpn()
        if vpn:
            self._emit_log(f"Another VPN is active: {vpn}")
        self._tun_fallback(f"TUN did not pass the check ({last})")

    def _tun_fallback(self, reason: str) -> None:
        self._stop_tun_process()
        self._emit_log(f"TUN unavailable, using Windows proxy instead: {reason}")
        self._tun_fell_back = True
        self._enable_proxy()

    def _start_tun_process(self, binary, config_path, stack: str, mtu: int) -> None:
        from ..engine import build_singbox_tun_config
        from . import tun_guard

        config = tun_guard.harden_config(
            build_singbox_tun_config(
                self._bypass_processes,
                [],
                None,
                None,
                None,
                socks_port=self._exit_port,
                helper_processes=POW_HELPER_PROCESSES,
            ),
            stack=stack,
            mtu=mtu,
        )
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
        self._site_log = tun_guard.SiteLog(process.stderr, self._emit_log, show_direct=bool(self._bypass_processes))
        time.sleep(1.5)
        if process.poll() is not None:
            raise PowEngineError(f"sing-box TUN exited immediately ({process.returncode})")
        # Traffic now leaves through TUN; the system proxy must not fight it.
        proxy, self._proxy = self._proxy, None
        if proxy is not None:
            try:
                proxy.suspend()
            except Exception:
                pass
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
        stack, mtu = getattr(self, "_tun_stack", tun_guard.TUN_ATTEMPTS[0])
        self._stop_tun_process()
        try:
            self._start_tun_process(BIN / "sing-box.exe", self._data_dir / "pow-sing-box-tun.json", stack, mtu)
        except PowEngineError:
            return False
        ok, _reason, _facts = tun_guard.verify_tun(self._exit_port)
        return ok

    def _stop_tun_process(self) -> None:
        process, self._tun_process = self._tun_process, None
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
            except Exception:
                pass
        if job is not None:
            job.close()

    def _identity_ready(self) -> bool:
        from .config import identity_path

        path = identity_path(self._data_dir)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        return "device_id" in text and "BEGIN CERTIFICATE" in text

    def _ensure_active(self) -> None:
        if self._stop.is_set() or self._owner_epoch_stale():
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
        """Mobile PowAdaptiveObfuscation: sample the path RTT, count DPI-like
        failures/jitter, flip the adaptive H2-fragment flag. The flag is read at
        the next outer (re)connect; it never forces a reconnect by itself."""
        settings = self._speed
        if self._last_outer_protocol != "masque":
            return
        if settings.h2_fragment_mode != H2_FRAG_AUTO:
            return
        epoch = self._epoch
        stop = self._stop
        adaptive = self._adaptive

        def _work() -> None:
            self._tls.epoch = epoch
            if stop.wait(ADAPTIVE_SETTLE_S):
                return
            recent: list[int] = []
            stable_since = time.monotonic()
            while not stop.is_set():
                if self._epoch != epoch or not self._connected.is_set():
                    return
                try:
                    adaptive.should_disable(self._speed, int((time.monotonic() - stable_since) * 1000))
                    sample = int(self._measure_tunnel_rtt() or 0)
                    if stop.is_set() or self._epoch != epoch:
                        return
                    jitter = is_jitter_high(recent + [sample])
                    adaptive.on_probe(sample > 0, jitter)
                    if jitter and sample > 0:
                        adaptive.should_enable(self._speed, True)
                    if sample <= 0 or jitter:
                        stable_since = time.monotonic()
                    recent = (recent + [sample])[-4:]
                except Exception:
                    pass
                if stop.wait(ADAPTIVE_PROBE_INTERVAL_S):
                    return

        threading.Thread(target=_work, name="pow-adaptive-h2", daemon=True).start()

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
        elif kind == "Diagnostic":
            text = str(data)[:300]
            if text and text != "{}":
                self._emit_log(f"Psiphon diagnostic: {text}")
        elif kind == "ConnectedServerRegion":
            region = str(data.get("region", ""))
            if region:
                self._exit_region = region

    # -- watchdog ---------------------------------------------------------------
    def _start_watchdog(self) -> None:
        epoch = self._epoch
        stop = self._stop

        def _watch() -> None:
            # Bound to this connect: a later connect clears _stop and restarts
            # the processes; an old watchdog must never judge the new session.
            self._tls.epoch = epoch
            while not stop.wait(3):
                if self._epoch != epoch or not self._connected.is_set():
                    return
                outer_dead = (self._warp_only or not self._direct_psiphon) and not self._aether.running
                inner_dead = (not self._warp_only) and not self._psiphon.running
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
        """Main MASQUE session died but parallel ones live: the router already
        skips the dead upstream, so traffic keeps flowing. Bring the main
        session back on its port in the background."""
        if self._router is None or not self._alive_extras():
            return False
        alive = len(self._alive_extras())
        self._emit_log(f"Main session down; {alive} parallel session(s) keep carrying traffic")
        if getattr(self, "_main_restarting", False):
            return True
        self._main_restarting = True

        def _bring_back() -> None:
            delay = 2.0
            try:
                while not self._stop.is_set() and self._epoch == epoch:
                    settings = self._speed
                    mci = uses_mci_firewall(settings)
                    candidates, _pool = self._clean_candidates(self._network_key or "default")
                    peer = (candidates or [self._won_peer or ""])[0]
                    try:
                        process = self._launch_extra(settings, mci, CHAIN_SOCKS_PORT, peer)
                    except Exception:
                        process = None
                    if process is not None and process.wait_ready(CHAIN_SOCKS_PORT, 45_000, self._stop):
                        old = self._aether
                        self._aether = process
                        try:
                            old.stop()
                        except Exception:
                            pass
                        self._emit_log(f"Main session back on {peer or 'a scanned address'}")
                        return
                    if process is not None:
                        try:
                            process.stop()
                        except Exception:
                            pass
                    if not self._alive_extras():
                        return  # the watchdog takes over with a full reconnect
                    if self._stop.wait(delay):
                        return
                    delay = min(delay * 2, 60.0)
            finally:
                self._main_restarting = False

        threading.Thread(target=_bring_back, name="pow-main-restart", daemon=True).start()
        return True

    def _raise_legs_again(self) -> None:
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
        plan = outer_plan(settings, mci)
        ordered = self._order_ladder(plan.protocols)
        ordered, preferred = self._apply_transport_choice(settings, plan, ordered)
        outer = None
        if not self._direct_psiphon or self._warp_only:
            outer = self._raise_outer_leg(settings, plan.protocols, ordered, mci, preferred=preferred)
            if outer is None:
                raise PowEngineError("WARP did not come up")
            if not self._stop.is_set():
                self._start_parallel_masque(settings, mci)
        self._ensure_active()
        if self._warp_only:
            self._exit_port = self._chain_port
        else:
            self._start_psiphon_tunnel(settings)
            self._exit_port = self._psiphon_port

    def _recover(self, epoch: int, reason: str) -> bool:
        """Keep the session: rebuild the legs with backoff. TUN stays up (no leak)
        for up to RECOVER_HOLD_S; after that it is released so the normal
        internet works, and re-armed once the legs are back. Returns False
        only when the user stopped the session."""
        with self._session_work():
            return self._recover_inner(epoch, reason)

    def _recover_inner(self, epoch: int, reason: str) -> bool:
        from . import tun_guard

        hold_s = 90.0
        started = time.monotonic()
        released = False
        delay = 2.0
        attempt = 0
        tun_wanted = (not self._proxy_mode) and not getattr(self, "_tun_fell_back", False)
        proxy_wanted = self._proxy is not None or not tun_wanted
        self._emit_log(f"Reconnecting: {reason}")
        try:
            self._status.update(PowPhase.OUTER, 30, "Reconnecting", outer_label=self._outer_label)
        except Exception:
            pass
        while not self._stop.is_set() and self._epoch == epoch:
            attempt += 1
            old_exit = self._exit_port
            try:
                self._raise_legs_again()
                if not tcp_accepts(self._exit_port):
                    time.sleep(_EXIT_GRACE_SECONDS)
                if not tcp_accepts(self._exit_port):
                    raise PowEngineError("exit proxy is not listening")
                with self._exit_lock:
                    # A live exit switch may have changed the mode meanwhile.
                    self._ensure_active()
                    tun_wanted = (not self._proxy_mode) and not getattr(self, "_tun_fell_back", False)
                    proxy_wanted = proxy_wanted or not tun_wanted
                    if tun_wanted:
                        if released or self._tun_process is None or self._exit_port != old_exit:
                            self._stop_tun_process()
                            self._enable_tun()
                        else:
                            ok, why, _facts = tun_guard.verify_tun(self._exit_port)
                            if not ok:
                                self._emit_log(f"TUN check failed: {why}")
                                self._stop_tun_process()
                                self._enable_tun()
                            else:
                                self._emit_log("TUN verified again after reconnect")
                    elif proxy_wanted and (released or self._proxy is None):
                        self._enable_proxy()
                took = int(time.monotonic() - started)
                self._emit_log(f"Reconnected in {took}s (attempt {attempt})")
                try:
                    self._status.update(PowPhase.CONNECTED, 100, "UAC PoW ready", outer_label=self._outer_label)
                except Exception:
                    pass
                self.refresh_exit_info(background=True)
                return True
            except PowEngineError as exc:
                if self._stop.is_set() or self._epoch != epoch:
                    return False
                self._emit_log(f"Reconnect attempt {attempt} failed: {exc}")
            except Exception as exc:  # never let the watchdog die silently
                self._emit_log(f"Reconnect attempt {attempt} failed: {type(exc).__name__}: {exc}")
            if not released and time.monotonic() - started > hold_s:
                released = True
                self._stop_tun_process()
                proxy, self._proxy = self._proxy, None
                if proxy is not None:
                    try:
                        proxy.suspend()
                    except Exception:
                        pass
                self._emit_log("Reconnect is taking long; normal internet restored while retrying")
            if self._stop.wait(delay):
                return False
            delay = min(delay * 2, 30.0)
        return False

    def _tun_healthy(self, epoch: int) -> bool:
        """False when the watchdog should stop. Heals TUN in place."""
        from . import tun_guard

        process = self._tun_process
        if process is None or getattr(self, "_tun_fell_back", False) or self._proxy_mode:
            return True
        dead = process.poll() is not None
        if not dead and time.monotonic() < self._tun_next_probe:
            return True
        self._tun_next_probe = time.monotonic() + 30
        if not dead and tun_guard.quick_health():
            self._tun_misses = 0
            return True
        self._tun_misses = 0 if dead else self._tun_misses + 1
        if not dead and self._tun_misses < 2:
            return True
        if self._epoch != epoch or self._stop.is_set():
            return False
        self._emit_log("TUN health check failed; repairing the system tunnel")
        if self._restart_tun():
            self._tun_misses = 0
            self._emit_log("TUN repaired")
            return True
        self._fail("system tunnel stopped working")
        return False

    def _fail(self, reason: str) -> None:
        if self._stop.is_set():
            return
        # Never leave the PC routed into a dead tunnel: drop TUN at once so
        # the normal internet comes back while we reconnect or give up.
        self._stop_tun_process()
        proxy, self._proxy = self._proxy, None
        if proxy is not None:
            try:
                proxy.suspend()
            except Exception:
                pass
        self._emit_log(f"UAC PoW path lost: {reason}")
        try:
            self._status.update(PowPhase.FAILED, 0, reason)
        except Exception:
            pass
        self._connected.clear()
