from __future__ import annotations

import threading
import time
from types import SimpleNamespace

from uac_desktop.engine import build_xray_config
from uac_desktop.models import Tuning, parse_many
from uac_desktop.sni_batch import (
    LiveConfigResult,
    SniBatchTester,
    _probe_proxy,
    build_batch_xray_config,
)


VMESS_URI = (
    "vmess://11111111-1111-4111-8111-111111111111@127.0.0.1:40443"
    "?security=tls&sni=edge.example&type=ws&host=edge.example&path=/ws"
    "#VMess"
)
VLESS_URI = (
    "vless://22222222-2222-4222-8222-222222222222@127.0.0.1:40443"
    "?security=tls&sni=vless.example&type=ws&host=vless.example&path=/"
    "#VLESS"
)
TROJAN_URI = (
    "trojan://password@127.0.0.1:40443"
    "?security=tls&sni=trojan.example&type=ws&host=trojan.example&path=/"
    "#Trojan"
)


def test_vmess_uri_is_supported_by_parser_and_xray_builder():
    profile = parse_many(VMESS_URI)[0]

    config = build_xray_config(profile, tuning=Tuning(xray_mux_enabled=False))
    outbound = config["outbounds"][0]

    assert profile.protocol == "vmess"
    assert outbound["protocol"] == "vmess"
    assert outbound["settings"]["vnext"][0]["users"][0] == {
        "id": "11111111-1111-4111-8111-111111111111",
        "alterId": 0,
        "security": "auto",
    }


def test_batch_xray_config_maps_every_http_inbound_to_one_profile():
    profiles = parse_many("\n".join([VLESS_URI, TROJAN_URI, VMESS_URI]))

    config = build_batch_xray_config(
        profiles, [23001, 23002, 23003], [41443, 42443, 41443],
        Tuning(xray_mux_enabled=False),
    )

    assert [item["port"] for item in config["inbounds"]] == [23001, 23002, 23003]
    assert [item["protocol"] for item in config["outbounds"][:3]] == [
        "vless", "trojan", "vmess"
    ]
    assert config["routing"]["rules"][1] == {
        "type": "field",
        "inboundTag": ["maker-in-1"],
        "outboundTag": "maker-out-1",
    }
    for outbound, relay_port in zip(
            config["outbounds"][:3], [41443, 42443, 41443]):
        endpoint = (
            outbound["settings"].get("servers")
            or outbound["settings"].get("vnext")
        )[0]
        assert endpoint["address"] == "127.0.0.1"
        assert endpoint["port"] == relay_port


def test_batch_tester_starts_one_relay_per_remote_port_and_cleans_up(
        monkeypatch, tmp_path):
    profiles = parse_many("\n".join([VLESS_URI, TROJAN_URI, VMESS_URI]))
    profiles[0].port = 443
    profiles[1].port = 8443
    profiles[2].port = 443
    patterns = []
    strategies = []
    captured_config = {}

    class Pattern:
        def __init__(self, _log):
            self.controller = None
            self.stopped = False
            patterns.append(self)

        def start(self, controller, _tuning, strategy):
            self.controller = controller
            strategies.append(strategy)

        def stop(self):
            self.stopped = True

    class Process:
        returncode = None
        stdout = None

        def __init__(self):
            self.terminated = False

        def poll(self):
            return None if not self.terminated else 0

        def terminate(self):
            self.terminated = True
            self.returncode = 0

        def wait(self, timeout=None):
            assert timeout == 1.5
            return 0

        def kill(self):
            self.terminated = True
            self.returncode = -9

    process = Process()

    def start_xray(tester, config_path, _cancel=None):
        captured_config.update(__import__("json").loads(
            config_path.read_text(encoding="utf-8")
        ))
        tester._process = process
        return process

    def probe(profile, _port, _timeout, _cancel):
        return LiveConfigResult(
            profile=profile, ok=True, ping_ms=25.0,
            country_code="CH", country="Switzerland",
            exit_ip="203.0.113.10", source="test",
        )

    monkeypatch.setattr("uac_desktop.sni_batch.DATA_DIR", tmp_path)
    monkeypatch.setattr("uac_desktop.sni_batch.PatternSniCore", Pattern)
    monkeypatch.setattr(SniBatchTester, "_start_xray", start_xray)
    monkeypatch.setattr(SniBatchTester, "_wait_ready", staticmethod(
        lambda _process, _ports, timeout=5.0: None
    ))
    monkeypatch.setattr("uac_desktop.sni_batch._probe_proxy", probe)

    tester = SniBatchTester()
    results = tester.run(
        profiles, Tuning(carrier_mode="mci"), threading.Event(),
        workers=3, timeout=1.0
    )

    assert len(results) == 3
    assert strategies == ["tls_sni_records", "tls_sni_records"]
    assert {pattern.controller.port for pattern in patterns} == {443, 8443}
    assert len(patterns) == 2
    relay_by_remote = {
        pattern.controller.port: pattern.controller.config_port
        for pattern in patterns
    }
    outbound_ports = []
    for outbound in captured_config["outbounds"][:3]:
        endpoint = (
            outbound["settings"].get("servers")
            or outbound["settings"].get("vnext")
        )[0]
        outbound_ports.append(endpoint["port"])
    assert outbound_ports == [
        relay_by_remote[443],
        relay_by_remote[8443],
        relay_by_remote[443],
    ]
    assert all(pattern.stopped for pattern in patterns)
    assert tester._patterns == []
    assert process.terminated is True
    assert list(tmp_path.glob("sni-maker-batch-*.json")) == []


def test_batch_cancel_during_relay_start_stops_started_relays(
        monkeypatch, tmp_path):
    profiles = parse_many("\n".join([VLESS_URI, TROJAN_URI]))
    profiles[0].port = 443
    profiles[1].port = 8443
    cancel = threading.Event()
    patterns = []

    class Pattern:
        def __init__(self, _log):
            self.stopped = False
            patterns.append(self)

        def start(self, _controller, _tuning, _strategy):
            cancel.set()

        def stop(self):
            self.stopped = True

    monkeypatch.setattr("uac_desktop.sni_batch.DATA_DIR", tmp_path)
    monkeypatch.setattr("uac_desktop.sni_batch.PatternSniCore", Pattern)
    monkeypatch.setattr(
        SniBatchTester, "_start_xray",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("Xray should not start after cancellation")
        ),
    )

    tester = SniBatchTester()
    results = tester.run(
        profiles, Tuning(), cancel, workers=2, timeout=1.0
    )

    assert results == []
    assert len(patterns) == 1
    assert patterns[0].stopped is True
    assert tester._patterns == []
    assert list(tmp_path.glob("sni-maker-batch-*.json")) == []


def test_stop_interrupts_running_probes_and_remains_idempotent(
        monkeypatch, tmp_path):
    profile = parse_many(VLESS_URI)[0]
    profile.port = 8443
    probe_started = threading.Event()
    pattern_stopped = threading.Event()

    class Pattern:
        def __init__(self, _log):
            return None

        def start(self, _controller, _tuning, _strategy):
            return None

        def stop(self):
            pattern_stopped.set()

    class Process:
        returncode = None
        stdout = None

        def __init__(self):
            self.terminated = False

        def poll(self):
            return None if not self.terminated else 0

        def terminate(self):
            self.terminated = True
            self.returncode = 0

        def wait(self, timeout=None):
            return 0

        def kill(self):
            self.terminated = True
            self.returncode = -9

    process = Process()

    def start_xray(tester, _config_path, _cancel=None):
        tester._process = process
        return process

    def probe(value, _port, _timeout, cancel):
        probe_started.set()
        deadline = time.monotonic() + 1.0
        while not cancel.is_set() and time.monotonic() < deadline:
            time.sleep(0.005)
        return LiveConfigResult(profile=value, error="cancelled")

    monkeypatch.setattr("uac_desktop.sni_batch.DATA_DIR", tmp_path)
    monkeypatch.setattr("uac_desktop.sni_batch.PatternSniCore", Pattern)
    monkeypatch.setattr(SniBatchTester, "_start_xray", start_xray)
    monkeypatch.setattr(SniBatchTester, "_wait_ready", staticmethod(
        lambda _process, _ports, timeout=5.0: None
    ))
    monkeypatch.setattr("uac_desktop.sni_batch._probe_proxy", probe)

    tester = SniBatchTester()
    caller_cancel = threading.Event()
    output = []
    worker = threading.Thread(target=lambda: output.extend(tester.run(
        [profile], Tuning(), caller_cancel, workers=1, timeout=1.0
    )))
    worker.start()
    assert probe_started.wait(1.0)
    tester.stop()
    worker.join(timeout=2.0)
    tester.stop()

    assert worker.is_alive() is False
    assert len(output) == 1
    assert output[0].error == "cancelled"
    assert caller_cancel.is_set() is False
    assert pattern_stopped.is_set() is True
    assert process.terminated is True
    assert tester._patterns == []
    assert list(tmp_path.glob("sni-maker-batch-*.json")) == []


def test_live_probe_uses_observed_exit_country_and_route_elapsed(monkeypatch):
    profile = parse_many(VLESS_URI)[0]

    class Response:
        ok = True
        status_code = 200
        text = "ip=203.0.113.9\nloc=CH\n"
        elapsed = SimpleNamespace(total_seconds=lambda: 0.123)

    class Session:
        trust_env = True
        calls = 0

        def get(self, *_args, **_kwargs):
            type(self).calls += 1
            return Response()

        def close(self):
            return None

    monkeypatch.setattr("uac_desktop.sni_batch.requests.Session", Session)

    result = _probe_proxy(profile, 23001, 3.0, threading.Event())

    assert result.ok is True
    assert result.ping_ms == 123
    assert result.country_code == "CH"
    assert result.exit_ip == "203.0.113.9"
    assert result.source == "cloudflare-trace"
    assert Session.calls == 1


def test_cancelled_live_probe_does_not_open_network(monkeypatch):
    profile = parse_many(VLESS_URI)[0]
    cancel = threading.Event()
    cancel.set()

    class Session:
        trust_env = True

        def get(self, *_args, **_kwargs):
            raise AssertionError("network should not be opened")

        def close(self):
            return None

    monkeypatch.setattr("uac_desktop.sni_batch.requests.Session", Session)

    result = _probe_proxy(profile, 23001, 3.0, cancel)

    assert result.ok is False
    assert result.error == "cancelled"
