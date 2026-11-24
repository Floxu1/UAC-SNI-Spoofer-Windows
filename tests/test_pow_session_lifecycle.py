"""Exercise recovery and handover without changing the host's routes."""

import json
import socket
import socketserver
import threading
from contextlib import contextmanager

import pytest

from uac_desktop.pow import config, coordinator as module, tun_guard
from uac_desktop.pow.status import PowPhase
from uac_desktop.pow.store import PowStore


class SocksPeer(socketserver.StreamRequestHandler):
    def handle(self):
        if self.rfile.read(3) != bytes((5, 1, 0)):
            return
        self.wfile.write(bytes((5, 0)))
        if self.rfile.read(10) != bytes((5, 1, 0, 1, 127, 0, 0, 1, 0, 80)):
            return
        self.wfile.write(bytes((5, 0, 0, 1, 127, 0, 0, 1, 0, 1)))
        while self.rfile.read(1):
            self.wfile.write(self.server.tag)


@contextmanager
def peer(tag):
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), SocksPeer) as server:
        server.daemon_threads = True
        server.tag = tag
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            thread.join(timeout=2)


@contextmanager
def open_stream(port):
    with socket.create_connection(("127.0.0.1", port), timeout=2) as sock, sock.makefile("rb") as reply:
        sock.sendall(bytes((5, 1, 0)))
        assert reply.read(2) == bytes((5, 0))
        sock.sendall(bytes((5, 1, 0, 1, 127, 0, 0, 1, 0, 80)))
        assert reply.read(10)[:2] == bytes((5, 0))
        yield sock, reply


def sample(port):
    with open_stream(port) as (sock, reply):
        sock.sendall(b"?")
        return reply.read(1)


class Helper:
    def __init__(self, port):
        self.socks_port = port
        self.connected = threading.Event()
        self.running = True
        self.stops = 0

    def start(self, payload, data, meek_only=False):
        self.running = True
        self.connected.set()

    def wait_connected(self, timeout, stop):
        return self.connected.is_set() and not stop.is_set()

    def stop(self):
        self.stops += 1
        self.running = False
        self.connected.clear()


class Tun:
    def poll(self):
        return None


def session(tmp_path):
    result = module.PowCoordinator(tmp_path, PowStore(tmp_path))
    result._connected.set()
    result._proxy_mode = False
    result._tun_process = Tun()
    result._inner_config = json.dumps({"ConnectionWorkerPoolSize": 6})
    return result


def test_quality_sampling_begins_after_switching_from_proxy_to_vpn(tmp_path, monkeypatch):
    coordinator = session(tmp_path)
    coordinator._proxy_mode = True
    coordinator.status.update(PowPhase.CONNECTED, 100, "ready")
    phases = []

    class Stop:
        def wait(self, seconds):
            phases.append(seconds)
            if len(phases) == 2:
                coordinator._proxy_mode = False
            return len(phases) >= 3

        def is_set(self):
            return False

    class Router:
        def sample_activity(self):
            return 0, 0, []

    class InlineWorker:
        def __init__(self, target, **_options):
            self.start = target

    def sample_rtt(*_args, **_options):
        assert not coordinator._proxy_mode
        phases.append("sample")
        return 60

    coordinator._stop = Stop()
    coordinator._inner_router = Router()
    monkeypatch.setattr(module, "measure_path", sample_rtt)
    monkeypatch.setattr(module.threading, "Thread", InlineWorker)
    coordinator._start_adaptive_monitor()
    assert phases == [5, 15, "sample", 15]


def test_failed_ghost_probe_retains_primary_port_and_stream(tmp_path, monkeypatch):
    with peer(b"P") as primary, peer(b"G") as fallback:
        coordinator = session(tmp_path)
        coordinator._psiphon = Helper(primary)
        coordinator._psiphon_port = primary
        coordinator._start_inner_pool()
        ghost = Helper(fallback)
        monkeypatch.setattr(module, "PsiphonProcess", lambda: ghost)
        monkeypatch.setattr(tun_guard, "verify_proxy", lambda *a, **k: (False, "timeout"))
        try:
            assert not coordinator._try_ghost_handover("fixture")
            assert coordinator._psiphon.stops == 0
            assert ghost.stops == 1
            assert sample(coordinator.exit_port) == b"P"
        finally:
            coordinator._stop_inner_pool()


def test_passive_latency_waits_for_an_upstream_payload_byte(tmp_path):
    with peer(b"P") as upstream:
        coordinator = session(tmp_path)
        coordinator._psiphon_port = upstream
        coordinator._start_inner_pool()
        try:
            with open_stream(coordinator.exit_port) as (sock, reply):
                assert coordinator._inner_router.sample_activity()[2] == []
                sock.sendall(b"?")
                assert reply.read(1) == b"P"
                assert coordinator._inner_router.sample_activity()[2][0] > 0
        finally:
            coordinator._stop_inner_pool()


def test_ghost_and_handback_preserve_router_and_open_ghost_stream(tmp_path, monkeypatch):
    with peer(b"P") as primary, peer(b"G") as fallback:
        coordinator = session(tmp_path)
        coordinator._psiphon = Helper(primary)
        coordinator._psiphon_port = primary
        coordinator._start_inner_pool()
        end_port = coordinator.exit_port
        ghost = Helper(fallback)
        monkeypatch.setattr(module, "PsiphonProcess", lambda: ghost)
        monkeypatch.setattr(tun_guard, "verify_proxy", lambda port, *a, **k: (sample(port) in (b"G", b"P"), ""))
        restart_primary = coordinator._start_primary_behind_ghost
        coordinator._start_primary_behind_ghost = lambda: None
        try:
            assert coordinator._try_ghost_handover("fixture")
            assert coordinator._ghost_serving
            assert sample(end_port) == b"G"
            with open_stream(end_port) as (sock, reply):
                restart_primary()
                coordinator._finish_ghost()
                assert coordinator.exit_port == end_port
                assert sample(end_port) == b"P"
                assert not coordinator._ghost_serving
                assert ghost.stops == 0
                sock.sendall(b"?")
                assert reply.read(1) == b"G"
        finally:
            coordinator._stop_inner_pool()


def test_restore_wait_wakes_on_available_uplink(tmp_path, monkeypatch):
    coordinator = session(tmp_path)
    coordinator._network_key = "default"
    monkeypatch.setattr(coordinator, "_network_detector", lambda: ("ethernet", "Wired"))
    results = []
    thread = threading.Thread(target=lambda: results.append(coordinator._wait_for_restore(0, 120)))
    thread.start()
    try:
        coordinator._network_changed.set()
        thread.join(timeout=2)
        assert results == [True]
        assert coordinator._network_key == "ethernet"
    finally:
        coordinator._stop.set()
        thread.join(timeout=2)


@pytest.mark.parametrize("command", ["pause", "proxy"])
def test_exit_command_interrupts_a_blocked_background_repair(tmp_path, monkeypatch, command):
    coordinator = session(tmp_path)
    coordinator.status.update(PowPhase.CONNECTED, 100, "ready")
    started = threading.Event()
    cancelled = threading.Event()
    actions = []
    outcome = []
    monkeypatch.setattr(coordinator, "_wait_for_restore", lambda epoch, delay: False)
    monkeypatch.setattr(coordinator, "_teardown_exit", lambda: actions.append("teardown"))
    monkeypatch.setattr(coordinator, "_close_kill_switch", lambda: actions.append("release WFP"))
    monkeypatch.setattr(coordinator, "_restore_windows_proxy", lambda: actions.append("restore proxy"))
    monkeypatch.setattr(coordinator, "refresh_exit_info", lambda **kwargs: None)
    monkeypatch.setattr(coordinator, "_require_tun_admin", lambda: None)

    def blocked_repair():
        started.set()
        if coordinator._dial_stop().wait(3):
            cancelled.set()
        coordinator._ensure_active()
        raise AssertionError("a blocked repair must observe the route change")

    monkeypatch.setattr(coordinator, "_repair_legs", blocked_repair)
    worker = threading.Thread(target=lambda: outcome.append(coordinator._recover(0, "fixture")), daemon=True)
    worker.start()
    try:
        assert started.wait(2)
        if command == "pause":
            coordinator.set_paused(True)
            assert coordinator.status.snapshot().phase == PowPhase.PAUSED
            assert actions == ["teardown", "restore proxy", "release WFP"]
            coordinator.set_paused(False)
        else:
            assert coordinator.switch_exit_mode(True) == "pending"
            assert actions == ["teardown", "release WFP"]
        worker.join(timeout=2)
        assert cancelled.is_set() and not worker.is_alive()
        assert outcome == [True]
        assert coordinator.status.snapshot().phase == PowPhase.OUTER
        assert coordinator.actual_proxy_mode is None
        assert coordinator.running and not coordinator._stop.is_set()
        assert coordinator._route_pending.is_set()

        monkeypatch.setattr(coordinator, "_repair_legs", lambda: actions.append("repair"))
        monkeypatch.setattr(coordinator, "_verify_rebuilt_exit", lambda port: actions.append(coordinator._proxy_mode))
        assert coordinator._recover(0, "selected route changed", immediate=True)
        assert actions[-2:] == ["repair", command == "proxy"]
        assert coordinator.actual_proxy_mode == (command == "proxy")
        assert coordinator.status.snapshot().phase == PowPhase.CONNECTED
    finally:
        coordinator._stop.set()
        coordinator._path_cancel.set()
        worker.join(timeout=2)


def test_parallel_result_cannot_install_on_a_replaced_router(tmp_path, monkeypatch):
    coordinator = session(tmp_path)
    coordinator._router = module.speed_module.StickyRouter(0, [1820])
    coordinator._sessions = [{"process": Helper(1830)}]
    started = threading.Event()
    allow_ready = threading.Event()
    rejected = threading.Event()
    replacement = Helper(1820)

    class Candidate(Helper):
        def wait_connected(self, timeout, stop):
            raise AssertionError("the worker probes the Aether listener")

        def wait_ready(self, port, budget, stop):
            started.set()
            return allow_ready.wait(2)

        def stop(self):
            super().stop()
            rejected.set()

    candidate = Candidate(1820)
    monkeypatch.setattr(coordinator, "_launch_extra", lambda *args: candidate)
    monkeypatch.setattr(coordinator, "_clean_candidates", lambda *_args: ([], {}))
    assert coordinator._promote_parallel(0)
    try:
        assert started.wait(2)
        coordinator._stop_parallel_masque()
        with coordinator._lock:
            coordinator._parallel_cancel = threading.Event()
            coordinator._router = module.speed_module.StickyRouter(0, [1820])
            coordinator._aether = replacement
        allow_ready.set()
        assert rejected.wait(2)
        assert coordinator._aether is replacement
        assert replacement.stops == 0
    finally:
        allow_ready.set()
        coordinator._stop_parallel_masque()


def test_exit_switch_publishes_the_new_mode_only_after_verification(tmp_path, monkeypatch):
    coordinator = session(tmp_path)
    coordinator._proxy_mode = True
    coordinator._direct_psiphon = True
    coordinator._psiphon = Helper(1821)
    coordinator.status.update(PowPhase.CONNECTED, 100, "ready")
    monkeypatch.setattr(coordinator, "_teardown_exit", lambda: None)
    monkeypatch.setattr(coordinator, "_start_inner_pool", lambda: None)
    monkeypatch.setattr(coordinator, "_warm_path", lambda: None)

    def verify_tun():
        assert coordinator.actual_proxy_mode is None
        assert coordinator.status.snapshot().phase == PowPhase.BRIDGING

    monkeypatch.setattr(coordinator, "_enable_tun", verify_tun)
    assert coordinator.switch_exit_mode(False) == "tun"
    assert coordinator.actual_proxy_mode is False
    assert coordinator.status.snapshot().phase == PowPhase.CONNECTED


def test_cancelled_output_change_does_not_start_tun(tmp_path, monkeypatch):
    coordinator = session(tmp_path)
    coordinator._proxy_mode = True
    changes = []
    monkeypatch.setattr(coordinator, "_enable_tun", lambda: changes.append("tun"))
    monkeypatch.setattr(coordinator, "_teardown_exit", lambda: changes.append("stop"))
    monkeypatch.setattr(coordinator._psiphon, "stop", lambda: changes.append("helper stop"))

    assert coordinator.switch_exit_mode(lambda: None) == "idle"
    assert coordinator.actual_proxy_mode is True
    assert not changes

    coordinator.request_stop()
    coordinator.disconnect()
    assert not coordinator.running
    assert changes[:2] == ["stop", "helper stop"]


@pytest.mark.parametrize("cancel_during_cleanup", (False, True))
def test_cancel_during_startup_cannot_activate_an_output(tmp_path, monkeypatch, cancel_during_cleanup):
    coordinator = module.PowCoordinator(tmp_path, PowStore(tmp_path))
    cancel = threading.Event()
    if cancel_during_cleanup:
        monkeypatch.setattr(coordinator, "disconnect", lambda **_kwargs: cancel.set())
    else:
        cancel.set()

    with pytest.raises(module.PowEngineError, match="^stopped$"):
        coordinator.connect(coordinator._store.snapshot(), cancel=cancel)
    assert not coordinator.running


def test_resume_reuses_a_live_exit_after_interrupted_recovery(tmp_path, monkeypatch):
    coordinator = session(tmp_path)
    coordinator._proxy_mode = True
    coordinator._direct_psiphon = True
    coordinator._psiphon = Helper(1821)
    coordinator._exit_port = 1821
    coordinator._paused = True
    coordinator._route_pending.set()
    coordinator.status.update(PowPhase.PAUSED, 100, "paused")
    probes = []
    monkeypatch.setattr(tun_guard, "verify_proxy",
                        lambda port, scheme, **kwargs: (probes.append((port, scheme)) or True, ""))
    monkeypatch.setattr(coordinator, "_enable_proxy", lambda: probes.append("route verified"))
    coordinator.set_paused(False)
    assert probes == [(1821, "socks5h"), "route verified"]
    assert coordinator._psiphon.stops == 0
    assert not coordinator._route_pending.is_set()
    assert coordinator.status.snapshot().phase == PowPhase.CONNECTED


def test_recovery_keeps_tun_and_uses_android_backoff(tmp_path, monkeypatch):
    coordinator = session(tmp_path)
    coordinator._psiphon = Helper(1821)
    coordinator._start_inner_pool()
    tun, port = coordinator._tun_process, coordinator.exit_port
    delays, attempts = [], []
    monkeypatch.setattr(coordinator, "_wait_for_restore", lambda epoch, delay: delays.append(delay) or False)
    monkeypatch.setattr(coordinator, "_enable_tun", lambda: (_ for _ in ()).throw(AssertionError("TUN rebuilt")))

    def repair():
        attempts.append(1)
        if len(attempts) < 3:
            raise module.PowEngineError("network offline")

    monkeypatch.setattr(coordinator, "_repair_legs", repair)
    monkeypatch.setattr(tun_guard, "verify_proxy", lambda *a, **k: (True, ""))
    monkeypatch.setattr(tun_guard, "verify_tun", lambda *a, **k: (True, "", {}))
    monkeypatch.setattr(coordinator, "refresh_exit_info", lambda **kw: None)
    try:
        assert coordinator._recover(0, "fixture")
        assert delays == [5, 15, 30]
        assert coordinator._tun_process is tun
        assert coordinator.exit_port == port
        assert coordinator.status.snapshot().phase == PowPhase.CONNECTED
    finally:
        coordinator._stop_inner_pool()


def test_verified_outer_rebuilds_only_inner(tmp_path, monkeypatch):
    coordinator = session(tmp_path)
    coordinator._aether = Helper(1820)
    actions = []
    monkeypatch.setattr(tun_guard, "verify_proxy", lambda port, *a, **k: (port == 1820, ""))
    monkeypatch.setattr(coordinator, "_rebuild_inner", lambda: actions.append("inner"))
    monkeypatch.setattr(coordinator, "_raise_legs_again", lambda: actions.append("full"))
    coordinator._repair_legs()
    assert actions == ["inner"]


@pytest.mark.parametrize("mode", ["ghost-failure", "pool", "warp"])
def test_quality_refresh_follows_android_path_order(tmp_path, monkeypatch, mode):
    coordinator = session(tmp_path)
    coordinator._psiphon = Helper(1821)
    if mode == "warp":
        coordinator._warp_only = True
        coordinator._exit_port = 1820
    else:
        coordinator._start_inner_pool()
    coordinator._speed = config.PowSettings(psiphon_tunnel_pool=mode == "pool")
    port = coordinator.exit_port
    actions = []

    def inner_timeout():
        actions.append("inner")
        raise module.PowEngineError("Psiphon timeout")

    monkeypatch.setattr(coordinator, "_rebuild_inner", inner_timeout)
    monkeypatch.setattr(coordinator, "_try_ghost_handover", lambda reason: actions.append("ghost") or False)
    monkeypatch.setattr(coordinator, "_raise_legs_again", lambda **kwargs: actions.append(kwargs))
    monkeypatch.setattr(coordinator, "_verify_rebuilt_exit", lambda previous: actions.append(previous))
    monkeypatch.setattr(coordinator, "refresh_exit_info", lambda **kwargs: None)
    monkeypatch.setattr(coordinator, "_warm_path", lambda **kwargs: None)
    try:
        assert coordinator._refresh_quality_path(0, "degraded") == (mode != "ghost-failure")
        expected = {
            "ghost-failure": ["ghost"],
            "pool": ["inner", {"retune": True, "fresh": True}, port],
            "warp": [{"retune": True, "fresh": False}, port],
        }
        assert actions == expected[mode]
        assert coordinator.exit_port == port
    finally:
        coordinator._stop_inner_pool()


@pytest.mark.parametrize("recipe, expected", [
    ("masque-h2", 14_000),
    ("masque-h3-over-h2", 90_000),
])
def test_fresh_retune_uses_native_discovery_and_budget(tmp_path, monkeypatch, recipe, expected):
    coordinator = session(tmp_path)
    coordinator._connect_epoch = coordinator._epoch
    monkeypatch.setattr(coordinator, "_identity_ready", lambda: True)
    monkeypatch.setattr(module, "prepare_identity", lambda *args, **kwargs: None)
    actions = {}

    class Aether:
        def start(self, raw, env):
            actions["payload"] = json.loads(raw)
            actions["env"] = env

        def wait_ready(self, port, budget, _stop):
            actions["ready"] = port, budget
            return True

    coordinator._aether = Aether()
    settings = config.PowSettings(link_recipe=recipe, scan_mode="thorough")
    assert coordinator._raise_outer_leg(
        settings, ["masque"], ["masque"], False, retune=True, discovery="fresh"
    )
    assert actions["payload"]["endpoint_discovery"] == "fresh"
    assert actions["payload"]["scan_mode"] == "turbo"
    assert actions["env"] == {"AETHER_QUICK_RECONNECT": "0"}
    assert actions["ready"] == (1820, expected)


def test_psiphon_retune_uses_one_bounded_deadline(tmp_path, monkeypatch):
    coordinator = session(tmp_path)
    coordinator._network_ready.set()
    now = [100.0]
    attempts = []

    class Psiphon(Helper):
        def wait_connected(self, timeout, stop):
            attempts.append(timeout)
            now[0] += timeout
            return False

    coordinator._psiphon = Psiphon(1821)
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    with pytest.raises(module.PowEngineError, match="Psiphon"):
        coordinator._start_psiphon_tunnel(config.PowSettings(), retune=True)
    assert attempts == [20]
    assert not coordinator._psiphon.running


def test_watchdog_repairs_a_missing_tun_on_the_active_vpn_session(tmp_path, monkeypatch):
    coordinator = session(tmp_path)
    coordinator._tun_process = None
    actions = []
    monkeypatch.setattr(coordinator, "_restart_tun", lambda: actions.append("repair") or False)
    monkeypatch.setattr(coordinator, "_recover", lambda epoch, reason: actions.append(reason) or True)
    assert coordinator._tun_healthy(coordinator._epoch)
    assert actions == ["repair", "system tunnel stopped working"]
    coordinator._paused = True
    assert coordinator._tun_healthy(coordinator._epoch)
    assert len(actions) == 2


def test_kill_switch_is_retained_after_connection_failure_and_released_on_stop(tmp_path, monkeypatch):
    class Guard:
        running = True

        def close(self):
            self.running = False

        def set_tunnel(self, allowed):
            assert not allowed

    coordinator = module.PowCoordinator(tmp_path, PowStore(tmp_path))
    guard = Guard()
    monkeypatch.setattr(coordinator, "_ensure_kill_switch", lambda: setattr(coordinator, "_kill_switch", guard))
    monkeypatch.setattr(coordinator, "_raise_outer_leg", lambda *a, **k: None)
    with pytest.raises(module.PowEngineError, match="WARP did not come up"):
        coordinator.connect(config.PowSettings(exit_mode="warp", kill_switch=True), proxy_mode=False)
    assert coordinator.protected and not coordinator.running
    assert coordinator.status.snapshot().phase == PowPhase.FAILED
    assert "Kill switch is still active" in coordinator.status.snapshot().detail
    coordinator.disconnect()
    assert not coordinator.protected
    assert not guard.running
