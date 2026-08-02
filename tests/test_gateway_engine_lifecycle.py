import threading
import os
import re
import sys

import pytest

import main as desktop_main
from uac_desktop.engine import Engine, build_singbox_tun_config


class RunningProcess:
    pid = 701

    def poll(self):
        return None


class ProxyRuntime:
    def __init__(self):
        self.has_pending_restore = True
        self.calls = []

    def suspend_for_tun(self):
        self.calls.append("suspend")

    def resume(self):
        self.calls.append("resume")

    def disable(self):
        self.calls.append("disable")
        self.has_pending_restore = False
        return True


class LeasingGateway:
    def __init__(self):
        self.active = False
        self.engine = None
        self.calls = []

    def start(self, engine, **_kwargs):
        self.calls.append("start")
        self.engine = engine
        engine.acquire_tun(owner="gateway", expected_run_id=engine.run_id)
        self.active = True

    def stop(self, reason="user", engine_stopping=False):
        self.calls.append(("stop", reason, engine_stopping))
        if self.active and not engine_stopping:
            self.engine.release_tun(
                owner="gateway",
                expected_run_id=self.engine.run_id,
            )
        self.active = False
        return True

    def before_engine_stop(self):
        return self.stop("engine-stop", True)


def test_singbox_routes_quic_through_the_proxy():
    config = build_singbox_tun_config()
    rules = config["route"]["rules"]
    assert not any(
        rule.get("network") == "udp"
        and rule.get("port") == 443
        and rule.get("action") == "reject"
        for rule in rules
    )
    assert "rules" not in config["dns"]


def test_singbox_routes_only_pattern_edge_connections_from_app_direct():
    config = build_singbox_tun_config(
        direct_edge_addresses=["104.19.229.21", "bad", "104.19.229.21"],
    )
    rules = config["route"]["rules"]
    edge_rule = next(rule for rule in rules if "ip_cidr" in rule)

    assert edge_rule["process_name"] == [os.path.basename(sys.executable)]
    assert edge_rule["ip_cidr"] == ["104.19.229.21/32"]
    assert edge_rule["outbound"] == "direct"
    assert config["inbounds"][0]["route_exclude_address"] == [
        "104.19.229.21/32",
    ]


def test_singbox_gateway_mode_only_proxies_gateway_source_network():
    config = build_singbox_tun_config(
        gateway_networks=[
            "192.168.70.151/24",
            "192.168.70.0/24",
            "invalid",
        ],
        gateway_host_addresses=["192.168.70.151"],
        gateway_interface="Wi-Fi",
    )
    rules = config["route"]["rules"]
    network = ["192.168.70.0/24"]

    assert config["route"]["final"] == "proxy"
    assert config["inbounds"][0]["strict_route"] is False
    assert not any(
        rule.get("source_ip_cidr") == ["192.168.70.151/32"]
        and rule.get("outbound") == "direct"
        for rule in rules
    )
    assert {
        "source_ip_cidr": network,
        "port": 53,
        "action": "hijack-dns",
    } in rules
    assert not any(
        rule.get("source_ip_cidr") == network
        and rule.get("network") == "udp"
        and rule.get("port") == 443
        and rule.get("action") == "reject"
        for rule in rules
    )
    assert config["dns"]["rules"] == [{
        "domain_regex": [
            r"(?i)\.(?:instagram\.com|facebook\.com|"
            r"cdninstagram\.com|fbcdn\.net|fbsbx\.com)"
            r"\.(?:home|lan|localdomain)$",
        ],
        "action": "predefined",
        "rcode": "NXDOMAIN",
    }]
    suffix_rule = config["dns"]["rules"][0]["domain_regex"][0]
    assert re.search(suffix_rule, "test-gateway.instagram.com.home")
    assert re.search(suffix_rule, "graph.facebook.com.home")
    assert not re.search(suffix_rule, "youtube.com.home")
    assert {
        "source_ip_cidr": network,
        "ip_cidr": network,
        "action": "route",
        "outbound": "direct",
    } in rules
    assert {
        "source_ip_cidr": network,
        "action": "route",
        "outbound": "proxy",
    } in rules
    assert {"port": 53, "action": "hijack-dns"} not in rules
    assert not any(rule.get("ip_is_private") is True for rule in rules)
    direct = next(
        outbound for outbound in config["outbounds"]
        if outbound["tag"] == "direct"
    )
    assert direct == {"type": "direct", "tag": "direct"}


def test_gateway_lease_restores_runtime_tun_and_proxy_without_stopping_engine():
    engine = Engine(lambda _line: None, lambda _running: None,
                    lambda _up, _down: None)
    engine._active = True
    engine.process = RunningProcess()
    engine.system_proxy = ProxyRuntime()
    engine._proxy_enabled = True
    engine.gateway = LeasingGateway()
    tun_events = []

    def enable_tun(*_args, **_kwargs):
        tun_events.append("enable")
        engine.tun_process = RunningProcess()

    def stop_tun():
        tun_events.append("disable")
        engine.tun_process = None

    engine.enable_tun = enable_tun
    engine._stop_tun_locked = stop_tun

    engine.enable_gateway(expected_run_id=engine.run_id)

    assert engine.gateway_running is True
    assert engine._gateway_owns_tun is True
    assert engine._gateway_restore_proxy is True
    assert engine._proxy_enabled is False
    assert engine.system_proxy.calls == ["suspend"]

    assert engine.disable_gateway() is True

    assert engine.running is True
    assert engine.gateway_running is False
    assert tun_events == ["enable", "disable"]
    assert engine.system_proxy.calls == ["suspend", "resume"]
    assert engine._proxy_enabled is True
    assert not engine._tun_leases


def test_gateway_split_lease_keeps_windows_proxy_active():
    engine = Engine(lambda _line: None, lambda _running: None,
                    lambda _up, _down: None)
    engine._active = True
    engine.process = RunningProcess()
    engine.system_proxy = ProxyRuntime()
    engine._proxy_enabled = True
    tun_events = []

    def enable_tun(*_args, **_kwargs):
        tun_events.append("enable")
        engine.tun_process = RunningProcess()
        engine._tun_gateway_networks = ("192.168.70.0/24",)

    def stop_tun():
        tun_events.append("disable")
        engine.tun_process = None
        engine._tun_gateway_networks = ()

    engine.enable_tun = enable_tun
    engine._stop_tun_locked = stop_tun

    engine.acquire_tun(
        owner="gateway",
        expected_run_id=engine.run_id,
        gateway_networks=["192.168.70.0/24"],
        gateway_host_addresses=["192.168.70.151"],
        gateway_interface="Wi-Fi",
    )

    assert engine._proxy_enabled is True
    assert engine._gateway_restore_proxy is False
    assert engine.system_proxy.calls == []

    engine.release_tun(owner="gateway", expected_run_id=engine.run_id)

    assert tun_events == ["enable", "disable"]
    assert engine.system_proxy.calls == []


def test_gateway_borrows_existing_tun_without_changing_runtime_modes():
    engine = Engine(lambda _line: None, lambda _running: None,
                    lambda _up, _down: None)
    engine._active = True
    engine.process = RunningProcess()
    existing_tun = RunningProcess()
    engine.tun_process = existing_tun
    engine.system_proxy = ProxyRuntime()
    engine.system_proxy.has_pending_restore = False
    engine._proxy_enabled = False
    engine.gateway = LeasingGateway()
    stopped = []
    engine._stop_tun_locked = lambda: stopped.append(True)

    engine.enable_gateway(expected_run_id=engine.run_id)
    assert engine._gateway_owns_tun is False
    assert engine._gateway_restore_proxy is False

    engine.disable_gateway(expected_run_id=engine.run_id)

    assert stopped == []
    assert engine.tun_process is existing_tun
    assert engine.system_proxy.calls == []
    assert engine._proxy_enabled is False


def test_engine_stop_runs_every_cleanup_stage_after_gateway_failure():
    calls = []
    engine = object.__new__(Engine)
    engine._lifecycle_lock = threading.RLock()
    engine._active = True
    engine._run_id = 4
    engine._tun_leases = {"gateway"}
    engine._gateway_owns_tun = True
    engine._gateway_restore_proxy = True
    engine._proxy_enabled = True
    engine._bypass_processes = ["browser.exe"]

    class Gateway:
        def before_engine_stop(self):
            calls.append("gateway")
            raise RuntimeError("gateway cleanup")

    class Process:
        pid = 811

        def poll(self):
            return None

        def terminate(self):
            calls.append("xray")

        def wait(self, timeout=None):
            calls.append(("wait", timeout))
            return 0

    class Fragment:
        def stop(self):
            calls.append("fragment")
            raise RuntimeError("fragment cleanup")

    class Proxy:
        has_pending_restore = True

        def disable(self):
            calls.append("proxy")
            self.has_pending_restore = False
            return True

    engine.gateway = Gateway()
    engine.process = Process()
    engine.fragment = Fragment()
    engine.system_proxy = Proxy()
    engine.log = lambda value: calls.append(("log", value))
    engine.state = lambda value: calls.append(("state", value))
    engine._remove_owner_record = lambda _pid: calls.append("owner")

    def stop_tun():
        calls.append("tun")
        raise RuntimeError("tun cleanup")

    engine._stop_tun_locked = stop_tun

    with pytest.raises(RuntimeError, match="gateway cleanup"):
        Engine._stop_locked(engine, notify=True)

    assert calls.index("gateway") < calls.index("tun") < calls.index("xray")
    assert "fragment" in calls
    assert "proxy" in calls
    assert ("state", False) in calls
    assert engine._active is False
    assert engine._run_id == 5
    assert engine._tun_leases == set()


def test_gateway_watchdog_cli_short_circuits_normal_start(monkeypatch):
    monkeypatch.setattr(
        desktop_main.GatewayManager,
        "watchdog_mode",
        classmethod(lambda cls, arguments: 9 if arguments == ["gateway"] else None),
    )
    monkeypatch.setattr(desktop_main.sys, "argv", ["main.py", "gateway"])
    monkeypatch.setattr(
        desktop_main,
        "relaunch_as_admin",
        lambda: (_ for _ in ()).throw(AssertionError("normal startup reached")),
    )
    assert desktop_main.main() == 9


def test_event_loop_finally_forces_gateway_recovery():
    calls = []

    class Gateway:
        def recover(self, force=False):
            calls.append(("recover", force))
            return True

    class AppEngine:
        gateway = Gateway()

        def stop(self, notify=False):
            calls.append(("stop", notify))

    class Window:
        engine = AppEngine()

        def shutdown(self):
            calls.append(("shutdown",))

    class App:
        def exec(self):
            return 0

    assert desktop_main.run_event_loop(App(), Window()) == 0
    assert ("recover", True) in calls
