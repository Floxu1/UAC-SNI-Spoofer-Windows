"""PoW runner/coordinator tests — ladder order, cert-stay rule, ports.

All subprocesses are faked: no binaries, no network, no registry.
"""

from __future__ import annotations

import json
import threading

import pytest

from uac_desktop.pow import config as C
from uac_desktop.pow import runner as runner_module
from uac_desktop.pow.coordinator import PowCoordinator, PowEngineError
from uac_desktop.pow.psiphon import PsiphonProcess
from uac_desktop.pow.status import PowPhase, PowStatusStore
from uac_desktop.pow.store import PowStore


def test_json_to_env_mapping(tmp_path):
    payload = json.loads(C.chain_outer_json(tmp_path, "masque", C.PowSettings(), mci=True))
    env = runner_module.json_to_env(payload)
    assert env["AETHER_PROTOCOL"] == "masque"
    assert env["AETHER_SOCKS"] == f"127.0.0.1:{C.CHAIN_SOCKS_PORT}"
    assert env["AETHER_IP"] == "both"
    assert env["AETHER_MASQUE_HTTP2"] == "1"
    assert env["AETHER_API_CAMO"] == "auto"
    assert env["AETHER_DISCOVERY"] == "cache"
    assert "AETHER_MASQUE_H2_FRAGMENT" not in env

    payload = json.loads(
        C.chain_outer_json(
            tmp_path, "wireguard", C.PowSettings(link_recipe=C.RECIPE_WARP_ANY)
        )
    )
    assert runner_module.json_to_env(payload)["AETHER_PROTOCOL"] == "wg"


def test_prepare_identity_requires_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(runner_module, "find_aether_binary", lambda: None)
    with pytest.raises(RuntimeError, match="aether.exe"):
        runner_module.prepare_identity(tmp_path, C.PowSettings())


def test_psiphon_notice_parsing():
    process = PsiphonProcess()
    process._handle_notice_line('{"noticeType":"Tunnels","data":{"count":2}}')
    assert process.connected.is_set()
    process._handle_notice_line('{"noticeType":"ListeningSocksProxyPort","data":{"port":1821}}')
    assert process.socks_port == 1821
    process._handle_notice_line(
        '{"noticeType":"AvailableEgressRegions","data":{"regions":["DE","US"]}}'
    )
    assert process.available_regions == ["DE", "US"]
    process._handle_notice_line('{"noticeType":"ConnectedServerRegion","data":{"region":"DE"}}')
    assert process.server_region == "DE"
    process._handle_notice_line('{"noticeType":"BytesTransferred","data":{"sent":7,"received":9}}')
    assert (process.bytes_sent, process.bytes_received) == (7, 9)


def test_psiphon_readiness_only_accepts_notices_from_the_current_helper():
    class Process:
        def poll(self):
            return None

    psiphon = PsiphonProcess()
    stale, current = Process(), Process()
    psiphon._process = current
    notice = '{"noticeType":"Tunnels","data":{"count":1}}'
    psiphon._handle_notice_line(notice, source=stale)
    assert not psiphon.connected.is_set()
    psiphon._handle_notice_line(notice, source=current)
    assert psiphon.wait_connected(0.1, threading.Event())
    psiphon._handle_notice_line('{"noticeType":"Tunnels","data":{"count":0}}', source=current)
    assert not psiphon.connected.is_set()


class _FakeAether:
    instances: list["_FakeAether"] = []

    def __init__(self, ready_protocols: set[str], **_kwargs):
        self.ready_protocols = ready_protocols
        self.started: list[str] = []
        self.stopped = 0
        type(self).instances.append(self)

    def start(self, outer_json: str) -> None:
        self.started.append(json.loads(outer_json)["protocol"])

    def wait_ready(self, port: int, budget_ms: int, stop: threading.Event) -> bool:
        return bool(self.started) and self.started[-1] in self.ready_protocols

    def stop(self) -> None:
        self.stopped += 1

    @property
    def running(self) -> bool:
        return False


class _FakePsiphon:
    def __init__(self, succeed_on: int = 0, **_kwargs):
        self.succeed_on = succeed_on
        self.attempts = 0
        self.running_flag = False
        self.available_regions: list[str] = []
        self.server_region = ""

    def start(self, config_json: str, data_dir, meek_only: bool = False) -> None:
        self.attempts += 1
        self.running_flag = True

    def wait_connected(self, timeout_seconds: float, stop: threading.Event) -> bool:
        return self.attempts > self.succeed_on

    def stop(self) -> None:
        self.running_flag = False

    @property
    def running(self) -> bool:
        return self.running_flag


def _coordinator(tmp_path, monkeypatch, ready, psiphon_succeed_on=0):
    monkeypatch.setattr("uac_desktop.proxy_ports.busy_reason", lambda *_args: "")
    _FakeAether.instances.clear()
    store = PowStore(tmp_path)
    status = PowStatusStore()
    coordinator = PowCoordinator(tmp_path, store, status, log=lambda _message: None)
    coordinator._network_detector = lambda: ("net-a", "Test network")
    monkeypatch.setattr(coordinator, "_measure_tunnel_rtt", lambda: 0)
    aether = _FakeAether(set(ready))
    psiphon = _FakePsiphon(succeed_on=psiphon_succeed_on)
    monkeypatch.setattr(coordinator, "_aether", aether)
    monkeypatch.setattr(coordinator, "_psiphon", psiphon)
    monkeypatch.setattr(runner_module, "prepare_identity", lambda *a, **k: {"ipv4": "x"})
    monkeypatch.setattr(
        "uac_desktop.pow.coordinator.prepare_identity", lambda *a, **k: {"ipv4": "x"}
    )
    monkeypatch.setattr(
        "uac_desktop.pow.coordinator.tcp_accepts", lambda *a, **k: True
    )
    return coordinator, store, status, aether, psiphon


def test_masque_failure_stays_on_method(tmp_path, monkeypatch):
    coordinator, _store, status, aether, _psiphon = _coordinator(
        tmp_path, monkeypatch, ready=set()
    )
    monkeypatch.setattr(coordinator, "_enable_proxy", lambda: None)
    settings = C.PowSettings(
        link_recipe=C.RECIPE_AUTO, firewall_profile=C.FIREWALL_MCI, chain_psiphon=False
    )
    with pytest.raises(PowEngineError):
        coordinator.connect(settings, proxy_mode=True)
    # MASQUE attempted once; the ladder must NOT fall through to WoW/WireGuard.
    assert aether.started == ["masque"]
    assert any("Staying on this method" in step.text for step in status.snapshot().steps)


def test_warp_only_exit_is_chain_port(tmp_path, monkeypatch):
    coordinator, _store, status, _aether, _psiphon = _coordinator(
        tmp_path, monkeypatch, ready={"masque"}
    )
    ports: list[int] = []
    monkeypatch.setattr(
        coordinator, "_enable_proxy", lambda: ports.append(coordinator.exit_port)
    )
    settings = C.PowSettings(chain_psiphon=False)
    try:
        coordinator.connect(settings, proxy_mode=True)
    finally:
        # quiet=True is connect()'s internal teardown (status owned by the
        # caller); a user-facing disconnect resets the status to idle.
        coordinator.disconnect()
    assert ports == [C.CHAIN_SOCKS_PORT]
    assert status.snapshot().phase == PowPhase.IDLE


def test_chained_exit_is_psiphon_port_and_winner_remembered(tmp_path, monkeypatch):
    coordinator, store, status, _aether, psiphon = _coordinator(
        tmp_path, monkeypatch, ready={"masque"}, psiphon_succeed_on=1
    )
    ports: list[int] = []
    original_enable = PowCoordinator._enable_proxy
    monkeypatch.setattr(
        coordinator, "_enable_proxy", lambda: ports.append(coordinator.exit_port)
    )
    settings = C.PowSettings(chain_psiphon=True)
    try:
        coordinator.connect(settings, proxy_mode=True)
    finally:
        coordinator.disconnect(quiet=True)
    assert ports == [C.PSIPHON_SOCKS_PORT]
    assert psiphon.attempts == 2
    # Behind WARP: nearby-country F attempt failed, then F in any country won.
    assert store.remembered_strategy_index(2, C.strategy_signature(direct=False)) == 0
    assert store.network_strategy_index("net-a", "F,A", 2) == 0
    assert original_enable is not None


def test_remembered_outer_protocol_follows_recipe_head(tmp_path, monkeypatch):
    store = PowStore(tmp_path)
    store.save_outer_protocol("wireguard")
    status = PowStatusStore()
    coordinator = PowCoordinator(tmp_path, store, status, log=lambda _message: None)
    assert coordinator._order_ladder(["masque", "gool", "wireguard"]) == [
        "masque",
        "wireguard",
        "gool",
    ]


def test_core_log_tail_reads_only_new_clean_ip_lines(tmp_path):
    import time
    from uac_desktop.pow.runner import core_message, follow_core_log

    assert (
        core_message("20:05:14  Trying saved clean address 1.2.3.4:443")
        == "Trying saved clean address 1.2.3.4:443"
    )
    path = tmp_path / "aether-core.log"
    path.write_text("20:05:14  old line\n", encoding="utf-8")
    seen: list[str] = []
    stop = threading.Event()
    thread = threading.Thread(
        target=follow_core_log, args=(path, stop, seen.append), daemon=True
    )
    thread.start()
    time.sleep(0.3)
    with path.open("a", encoding="utf-8") as handle:
        handle.write("20:05:15  Trying saved clean address 9.9.9.9:443\n")
        handle.write("20:05:16  Saved clean address rejected 9.9.9.9:443: status 400\n")
        handle.write("20:05:17  New MASQUE certificate issued\n")
    deadline = time.time() + 2
    while time.time() < deadline and len(seen) < 3:
        time.sleep(0.05)
    stop.set()
    thread.join(timeout=1)
    assert seen[0] == "Trying saved clean address 9.9.9.9:443"
    assert "rejected" in seen[1]
    assert "certificate issued" in seen[2]
    assert all("old line" not in line for line in seen)


def test_clean_ip_and_certificate_lines_are_logged(tmp_path):
    logs: list[str] = []
    coordinator = PowCoordinator(
        tmp_path, PowStore(tmp_path), PowStatusStore(), log=logs.append
    )
    coordinator._on_native_log("Clean HTTP/2 list: 1 saved address(es)")
    coordinator._on_native_log("Trying saved clean address 162.159.199.222:443")
    coordinator._on_native_log(
        "Saved clean address rejected 162.159.199.222:443: certificate refused"
    )
    coordinator._on_native_log("Certificate 1 was refused. Requesting another.")
    coordinator._on_native_log("Scanning 162.159.199.1:443 via HTTP/2")
    assert logs == [
        "Clean HTTP/2 list: 1 saved address(es)",
        "Trying saved clean address 162.159.199.222:443",
        "Saved clean address rejected 162.159.199.222:443: certificate refused",
        "Certificate 1 was refused. Requesting another.",
        "Scan 162.159.199.1:443 trying",
    ]


def test_chained_ladder_starts_light_and_logs_nearby_region(tmp_path, monkeypatch):
    coordinator, store, _status, _aether, psiphon = _coordinator(
        tmp_path, monkeypatch, ready={"masque"}, psiphon_succeed_on=0
    )
    logs: list[str] = []
    coordinator._log = logs.append
    configs: list[dict] = []
    original_start = psiphon.start

    def _start(config_json, data_dir, meek_only=False):
        configs.append(json.loads(config_json))
        original_start(config_json, data_dir, meek_only)

    psiphon.start = _start
    monkeypatch.setattr(coordinator, "_enable_proxy", lambda: None)
    try:
        coordinator.connect(C.PowSettings(chain_psiphon=True), proxy_mode=True)
    finally:
        coordinator.disconnect(quiet=True)
    first = configs[0]
    assert first["EgressRegion"] == "DE"
    assert first["EstablishTunnelTimeoutSeconds"] == C.NEARBY_PHASE_TIMEOUT_SECONDS
    assert first["InitialLimitTunnelProtocols"] == C.FAST_DIRECT
    assert first["EstablishTunnelServerAffinityGracePeriodMilliseconds"] == 1500
    assert any(line.startswith("Psiphon strategy order (behind WARP): F ") for line in logs)
    assert any("Automatic -> nearby Germany (DE)" in line for line in logs)
    assert store.network_strategy_index("net-a", "F,A", 2) == 0


def test_lower_rtt_strategy_starts_first(tmp_path, monkeypatch):
    coordinator, store, _status, _aether, _psiphon = _coordinator(
        tmp_path, monkeypatch, ready={"masque"}
    )
    store.save_network_strategy("net-a", "F,A", 0)
    store.save_strategy_rtt("net-a", "cF", 900)
    store.save_strategy_rtt("net-a", "cA", 300)
    ladder, start, reason = coordinator._strategy_order(False, "net-a")
    assert [s.name for s in ladder] == ["F", "A"]
    assert ladder[start].name == "A"
    assert reason.startswith("lower RTT")
    # Another network keeps its own memory.
    _ladder, other_start, other_reason = coordinator._strategy_order(False, "net-b")
    assert other_start == 0 and other_reason == "default"



def test_transport_choice_is_tried_first_then_falls_back(tmp_path, monkeypatch):
    logs: list[str] = []
    coordinator, _store, _status, aether, _psiphon = _coordinator(tmp_path, monkeypatch, ready={"masque"})
    monkeypatch.setattr(coordinator, "_log", logs.append)
    monkeypatch.setattr(coordinator, "_enable_proxy", lambda: None)
    settings = C.PowSettings(firewall_profile=C.FIREWALL_MCI, outer_transport="wireguard", chain_psiphon=False)
    coordinator.connect(settings, proxy_mode=True)
    assert aether.started == ["wireguard", "masque"]
    assert coordinator.outer_label_text == "MASQUE (WireGuard failed, fell back)"
    assert any(line.startswith("Transport: WireGuard first") for line in logs)
    assert any("WireGuard did not connect; fell back to MASQUE" in line for line in logs)
    coordinator.disconnect(quiet=True)


def test_transport_choice_wins_when_it_connects(tmp_path, monkeypatch):
    coordinator, _store, _status, aether, _psiphon = _coordinator(tmp_path, monkeypatch, ready={"wireguard", "masque"})
    monkeypatch.setattr(coordinator, "_enable_proxy", lambda: None)
    settings = C.PowSettings(firewall_profile=C.FIREWALL_MCI, outer_transport="wireguard", chain_psiphon=False)
    coordinator.connect(settings, proxy_mode=True)
    assert aether.started == ["wireguard"]
    assert coordinator.outer_label_text == "WireGuard"
    coordinator.disconnect(quiet=True)


def test_auto_transport_keeps_mci_plan_unchanged(tmp_path, monkeypatch):
    coordinator, _store, _status, aether, _psiphon = _coordinator(tmp_path, monkeypatch, ready={"masque"})
    monkeypatch.setattr(coordinator, "_enable_proxy", lambda: None)
    coordinator.connect(C.PowSettings(firewall_profile=C.FIREWALL_MCI, chain_psiphon=False), proxy_mode=True)
    assert aether.started == ["masque"]
    assert coordinator.outer_label_text == "MASQUE"
    coordinator.disconnect(quiet=True)


def test_explicit_recipe_overrides_transport(tmp_path, monkeypatch):
    logs: list[str] = []
    coordinator, _store, _status, aether, _psiphon = _coordinator(tmp_path, monkeypatch, ready={"masque"})
    monkeypatch.setattr(coordinator, "_log", logs.append)
    monkeypatch.setattr(coordinator, "_enable_proxy", lambda: None)
    settings = C.PowSettings(
        firewall_profile=C.FIREWALL_MCI, outer_transport="wireguard",
        link_recipe=C.RECIPE_MASQUE_H2, chain_psiphon=False,
    )
    coordinator.connect(settings, proxy_mode=True)
    assert aether.started == ["masque"]
    assert any("Transport WireGuard not used" in line for line in logs)
    coordinator.disconnect(quiet=True)



def test_wireguard_fails_fast_on_mci_and_logs_core_lines(tmp_path, monkeypatch):
    logs: list[str] = []
    coordinator, _store, _status, aether, _psiphon = _coordinator(tmp_path, monkeypatch, ready={"masque"})
    budgets: list[int] = []
    original = aether.wait_ready

    def wait_ready(port, budget_ms, stop):
        budgets.append(budget_ms)
        if aether.started[-1] == "wireguard":
            coordinator._on_native_log("[-] scan deadline reached with no endpoint")
        return original(port, budget_ms, stop)

    monkeypatch.setattr(aether, "wait_ready", wait_ready)
    monkeypatch.setattr(coordinator, "_log", logs.append)
    monkeypatch.setattr(coordinator, "_enable_proxy", lambda: None)
    settings = C.PowSettings(firewall_profile=C.FIREWALL_MCI, outer_transport="wireguard", chain_psiphon=False)
    coordinator.connect(settings, proxy_mode=True)
    assert aether.started == ["wireguard", "masque"]
    assert budgets[0] == 20_000
    assert budgets[1] == C.outer_budget_ms("masque", scan_mode=settings.scan_mode)
    assert "WireGuard core: [-] scan deadline reached with no endpoint" in logs
    coordinator.disconnect(quiet=True)


def test_wireguard_keeps_full_budget_off_mci(tmp_path, monkeypatch):
    coordinator, _store, _status, aether, _psiphon = _coordinator(tmp_path, monkeypatch, ready={"masque"})
    budgets: list[int] = []
    original = aether.wait_ready
    monkeypatch.setattr(aether, "wait_ready", lambda p, b, s: (budgets.append(b), original(p, b, s))[1])
    monkeypatch.setattr(coordinator, "_enable_proxy", lambda: None)
    settings = C.PowSettings(firewall_profile=C.FIREWALL_IRANCELL, outer_transport="wireguard", chain_psiphon=False)
    try:
        coordinator.connect(settings, proxy_mode=True)
    except Exception:
        pass
    assert budgets and budgets[0] == C.outer_budget_ms("wireguard", scan_mode=settings.scan_mode)
    coordinator.disconnect(quiet=True)
