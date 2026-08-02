from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest

from uac_desktop.engine import build_xray_config
from uac_desktop.models import Tuning, parse_many
from uac_desktop.sni_batch import (
    LiveConfigResult,
    SniBatchTester,
    _probe_proxy,
    build_batch_xray_config,
)


def test_xray_tls_config_omits_removed_allow_insecure_option():
    profile = parse_many(
        "vless://00000000-0000-4000-8000-000000000001@example.com:443"
        "?security=tls&type=ws&sni=example.com&allowInsecure=1"
    )[0]

    tls = build_xray_config(profile)["outbounds"][0]["streamSettings"]["tlsSettings"]

    assert "allowInsecure" not in tls


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


@pytest.mark.parametrize(
    ("network", "settings_key"),
    [("grpc", "grpcSettings"), ("tcp", "rawSettings")],
)
def test_reality_xray_config_preserves_transport_and_credentials(
        network, settings_key):
    uri = (
        "vless://33333333-3333-4333-8333-333333333333@reality.example:443"
        f"?security=reality&type={network}&sni=cover.example&fp=firefox"
        "&pbk=xRD8N2qL8TcYKc7iQQuaqoZS_2dYsiNRmL3CdW8ZtgM&sid=01234567&spx=%2Fedge"
        "&serviceName=maker&flow=xtls-rprx-vision#Reality"
    )
    profile = parse_many(uri)[0]

    config = build_xray_config(profile, tuning=Tuning(xray_mux_enabled=True))
    outbound = config["outbounds"][0]
    stream = outbound["streamSettings"]

    assert stream["security"] == "reality"
    assert stream["network"] == ("raw" if network == "tcp" else network)
    assert stream["realitySettings"] == {
        "serverName": "cover.example",
        "fingerprint": "firefox",
        "publicKey": "xRD8N2qL8TcYKc7iQQuaqoZS_2dYsiNRmL3CdW8ZtgM",
        "shortId": "01234567",
        "spiderX": "/edge",
    }
    assert settings_key in stream
    assert outbound["settings"]["vnext"][0]["users"][0]["flow"] == (
        "xtls-rprx-vision"
    )
    assert "mux" not in outbound


@pytest.mark.parametrize(
    ("network", "settings_key"),
    [
        ("grpc", "grpcSettings"),
        ("xhttp", "xhttpSettings"),
        ("tcp", "rawSettings"),
    ],
)
def test_tls_extended_transport_xray_fields(network, settings_key):
    uri = (
        "trojan://secret@transport.example:443"
        f"?security=tls&type={network}&sni=cover.example"
        "&host=host.example&path=%2Fedge&serviceName=maker"
        "&authority=authority.example&mode=auto&headerType=none"
        f"#{network}"
    )
    profile = parse_many(uri)[0]

    config = build_xray_config(profile, tuning=Tuning(xray_mux_enabled=False))
    stream = config["outbounds"][0]["streamSettings"]

    assert stream["security"] == "tls"
    assert stream["network"] == ("raw" if network == "tcp" else network)
    assert settings_key in stream
    if network == "grpc":
        assert stream[settings_key] == {
            "serviceName": "maker",
            "authority": "authority.example",
        }
    elif network == "xhttp":
        assert stream[settings_key] == {
            "path": "/edge",
            "host": "host.example",
            "mode": "auto",
        }
    else:
        assert stream[settings_key] == {"header": {"type": "none"}}


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


def test_batch_xray_config_direct_reality_keeps_original_endpoint():
    direct = parse_many(
        "vless://33333333-3333-4333-8333-333333333333@reality.example:443"
        "?security=reality&type=grpc&sni=cover.example&fp=chrome"
        "&pbk=xRD8N2qL8TcYKc7iQQuaqoZS_2dYsiNRmL3CdW8ZtgM&sid=01234567&serviceName=maker#Reality"
    )[0]
    direct.route_mode = "reality-direct"
    converted = parse_many(VLESS_URI)[0]

    config = build_batch_xray_config(
        [direct, converted], [23001, 23002], [None, 41443],
        Tuning(xray_mux_enabled=False),
    )

    direct_endpoint = config["outbounds"][0]["settings"]["vnext"][0]
    converted_endpoint = config["outbounds"][1]["settings"]["vnext"][0]
    assert direct_endpoint["address"] == "reality.example"
    assert direct_endpoint["port"] == 443
    assert converted_endpoint["address"] == "127.0.0.1"
    assert converted_endpoint["port"] == 41443


def test_batch_tester_direct_reality_does_not_start_pattern(
        monkeypatch, tmp_path):
    direct = parse_many(
        "vless://33333333-3333-4333-8333-333333333333@reality.example:443"
        "?security=reality&type=grpc&sni=cover.example&fp=chrome"
        "&pbk=xRD8N2qL8TcYKc7iQQuaqoZS_2dYsiNRmL3CdW8ZtgM&sid=01234567&serviceName=maker#Reality"
    )[0]
    direct.route_mode = "reality-direct"
    captured_config = {}

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

    def start_xray(tester, config_path, _cancel=None):
        captured_config.update(__import__("json").loads(
            config_path.read_text(encoding="utf-8")
        ))
        tester._process = process
        return process

    monkeypatch.setattr("uac_desktop.sni_batch.DATA_DIR", tmp_path)
    monkeypatch.setattr(
        "uac_desktop.sni_batch.PatternSniCore",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("Reality direct must not start Pattern")
        ),
    )
    monkeypatch.setattr(SniBatchTester, "_start_xray", start_xray)
    monkeypatch.setattr(
        SniBatchTester, "_wait_ready",
        staticmethod(lambda _process, _ports, timeout=5.0: None),
    )
    monkeypatch.setattr(
        "uac_desktop.sni_batch._probe_proxy",
        lambda profile, _port, _timeout, _cancel: LiveConfigResult(
            profile=profile, ok=True, ping_ms=25,
            country_code="JP", country="Japan",
            exit_ip="203.0.113.8", source="test",
        ),
    )

    results = SniBatchTester().run(
        [direct], Tuning(), threading.Event(), workers=1, timeout=1
    )

    endpoint = captured_config["outbounds"][0]["settings"]["vnext"][0]
    assert endpoint["address"] == "reality.example"
    assert endpoint["port"] == 443
    assert results[0].ok is True
    assert process.terminated is True


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


def test_irancell_batch_uses_full5_and_source_edges(monkeypatch, tmp_path):
    profiles = parse_many(VLESS_URI)
    profiles[0].address = "104.16.1.1"
    captured = {}

    class Pattern:
        active_edge = "104.16.1.1"

        def __init__(self, _log):
            self._profile = None

        def start(self, controller, tuning, strategy):
            self._profile = controller
            captured["strategy"] = strategy
            captured["primary"] = tuning.pattern_connect_ip

        def stop(self):
            return None

    class Process:
        returncode = None
        stdout = None

        def poll(self): return None
        def terminate(self): self.returncode = 0
        def wait(self, timeout=None): return 0
        def kill(self): self.returncode = -9

    process = Process()
    monkeypatch.setattr("uac_desktop.sni_batch.DATA_DIR", tmp_path)
    monkeypatch.setattr("uac_desktop.sni_batch.PatternSniCore", Pattern)
    monkeypatch.setattr(
        SniBatchTester, "_start_xray",
        lambda tester, _path, _cancel=None: (
            setattr(tester, "_process", process) or process
        ),
    )
    monkeypatch.setattr(
        SniBatchTester, "_wait_ready", staticmethod(lambda *_args, **_kwargs: None)
    )
    monkeypatch.setattr(
        "uac_desktop.sni_batch._probe_proxy",
        lambda profile, *_args: LiveConfigResult(
            profile=profile, ok=True, country_code="DE", country="Germany",
            exit_ip="203.0.113.1", source="test",
        ),
    )

    results = SniBatchTester().run(
        profiles, Tuning(carrier_mode="irancell"), threading.Event(),
        workers=1, timeout=1, strategy="wrong_seq",
    )

    assert captured == {"strategy": "full5", "primary": "104.16.1.1"}
    assert results[0].profile.address == "104.16.1.1"


def test_batch_all_modes_tests_only_unresolved_and_preserves_input_tuning(
        monkeypatch):
    profiles = parse_many("\n".join([VLESS_URI, TROJAN_URI, VMESS_URI]))
    original_tuning = Tuning(
        carrier_mode="irancell",
        pattern_connect_ip="104.16.1.1",
        pattern_fallback_ips="104.18.1.1",
    )
    original_values = original_tuning.to_dict()
    calls = []

    def run_one(
            self, selected, tuning, cancel, workers=64, timeout=8.0,
            strategy=None, progress=None):
        calls.append({
            "carrier": tuning.carrier_mode,
            "strategy": strategy,
            "profile_ids": [profile.id for profile in selected],
            "tuning": tuning,
        })
        winning_index = len(calls) - 1
        return [
            LiveConfigResult(
                profile=profile,
                ok=index == winning_index,
                ping_ms=100 + winning_index if index == winning_index else 0,
                country_code="DE" if index == winning_index else "",
                country="Germany" if index == winning_index else "",
                exit_ip="203.0.113.10" if index == winning_index else "",
                source="test" if index == winning_index else "",
                error="route failed" if index != winning_index else "",
            )
            for index, profile in enumerate(profiles)
            if profile in selected
        ]

    monkeypatch.setattr(SniBatchTester, "run", run_one)

    results = SniBatchTester().run_all_modes(
        profiles,
        original_tuning,
        threading.Event(),
        workers=3,
        timeout=1.0,
    )

    assert [
        (call["carrier"], call["strategy"])
        for call in calls
    ] == [
        ("irancell", "full5"),
        ("mci", "tls_sni_records"),
        ("auto", "wrong_seq"),
    ]
    assert [call["profile_ids"] for call in calls] == [
        [profiles[0].id, profiles[1].id, profiles[2].id],
        [profiles[1].id, profiles[2].id],
        [profiles[2].id],
    ]
    assert all(call["tuning"] is not original_tuning for call in calls)
    assert original_tuning.to_dict() == original_values
    assert {result.profile.id for result in results if result.ok} == {
        profile.id for profile in profiles
    }
    assert [profile.method for profile in profiles] == [
        "full5", "tls_sni_records", "combined",
    ]
    assert {
        result.profile.id: (result.carrier_mode, result.strategy)
        for result in results
    } == {
        profiles[0].id: ("irancell", "full5"),
        profiles[1].id: ("mci", "tls_sni_records"),
        profiles[2].id: ("auto", "wrong_seq"),
    }


def test_batch_all_modes_continues_after_one_mode_startup_error(monkeypatch):
    profile = parse_many(VLESS_URI)[0]
    calls = []

    def run_one(
            self, selected, tuning, cancel, workers=64, timeout=8.0,
            strategy=None, progress=None):
        calls.append((tuning.carrier_mode, strategy))
        if len(calls) == 1:
            raise RuntimeError("first mode failed to start")
        return [LiveConfigResult(
            profile=selected[0], ok=True, ping_ms=87,
            country_code="CH", country="Switzerland",
            exit_ip="203.0.113.11", source="test",
        )]

    monkeypatch.setattr(SniBatchTester, "run", run_one)

    results = SniBatchTester().run_all_modes(
        [profile], Tuning(carrier_mode="auto"), threading.Event(),
        workers=1, timeout=1.0,
    )

    assert calls == [
        ("irancell", "full5"),
        ("mci", "tls_sni_records"),
    ]
    assert len(results) == 1
    assert results[0].ok is True
    assert results[0].ping_ms == 87


def test_batch_all_modes_reports_incremental_progress_during_each_mode(
        monkeypatch):
    profiles = parse_many("\n".join(
        VLESS_URI.replace(
            "22222222-2222-4222-8222-222222222222",
            f"22222222-2222-4222-8222-{index:012d}",
        )
        for index in range(1, 13)
    ))
    updates = []

    def run_one(
            self, selected, tuning, cancel, workers=64, timeout=8.0,
            strategy=None, progress=None):
        results = []
        for done, profile in enumerate(selected, 1):
            result = LiveConfigResult(profile=profile, error="route failed")
            results.append(result)
            if progress:
                progress([result], done, len(selected))
        return results

    monkeypatch.setattr(SniBatchTester, "run", run_one)

    SniBatchTester().run_all_modes(
        profiles,
        Tuning(),
        threading.Event(),
        progress=lambda batch, done, total: updates.append(
            (len(batch), done, total)
        ),
    )

    values = [done for _batch, done, _total in updates]
    assert values == sorted(values)
    assert values[-1] == len(profiles)
    assert any(0 < done < len(profiles) for done in values)
    assert any(not batch for batch, done, _total in updates if done < len(profiles))


def test_batch_all_modes_forwards_healthy_results_before_mode_returns(
        monkeypatch):
    profile = parse_many(VLESS_URI)[0]
    emitted = []
    seen_inside_run = []

    def on_progress(batch, _done, _total):
        emitted.extend(batch)

    def run_one(
            self, selected, tuning, cancel, workers=64, timeout=8.0,
            strategy=None, progress=None):
        result = LiveConfigResult(
            profile=selected[0], ok=True, ping_ms=42,
            country_code="DE", country="Germany",
            exit_ip="203.0.113.12", source="test",
        )
        assert progress is not None
        progress([result], 1, len(selected))
        seen_inside_run.append([
            item.profile.id for item in emitted if item.ok
        ])
        return [result]

    monkeypatch.setattr(SniBatchTester, "run", run_one)

    SniBatchTester().run_all_modes(
        [profile], Tuning(), threading.Event(), progress=on_progress,
    )

    assert seen_inside_run == [[profile.id]]


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
