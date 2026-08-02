import asyncio
import concurrent.futures
import json
import os
import socket
import struct
import sys
import threading
import time
from types import SimpleNamespace

import requests

from pydivert import WinDivert

from uac_desktop import __version__
from uac_desktop.engine import (Engine, EngineCancelled, HTTP_PORT, SOCKS_PORT,
                                USER_AGENT, XRAY_CONFIG, build_singbox_tun_config,
                                build_xray_config, resolve_xray_upstream)
from uac_desktop.models import (ProxyProfile, Tuning, default_profiles,
                                parse_many, parse_outbound)
from uac_desktop.fragment_proxy import FragmentProxy
from uac_desktop.pattern_core import PatternSniCore
from uac_desktop.pattern_core.core import PacketInjector, Quality
from uac_desktop.pattern_core.packet_templates import ClientHelloMaker
from uac_desktop.tls_tools import find_sni, fragments, make_client_hello
from uac_desktop.ui import MainWindow
from uac_desktop.storage import _write


def test_all_six_original_builtins_parse():
    profiles = default_profiles()
    assert len(profiles) == 6
    assert [profile.name for profile in profiles] == [
        f"uacSpoofer {index}" for index in range(1, 7)
    ]
    assert {x.protocol for x in profiles} == {"vless", "trojan"}
    assert not any(profile.verified_spoof for profile in profiles)
    assert not any(profile.country_code for profile in profiles)


def test_xray_has_socks_and_http_inbounds():
    config = build_xray_config(default_profiles()[0])
    ports = {x["port"] for x in config["inbounds"]}
    assert ports == {SOCKS_PORT, HTTP_PORT}
    assert config["outbounds"][0]["protocol"] == "trojan"


def test_xray_routes_quic_instead_of_blackholing_it():
    config = build_xray_config(default_profiles()[0])
    assert config["inbounds"][0]["settings"]["udp"] is True
    assert config["inbounds"][0]["settings"]["ip"] == "127.0.0.1"
    assert not any(
        rule.get("network") == "udp"
        and str(rule.get("port")) == "443"
        and rule.get("outboundTag") == "block"
        for rule in config["routing"]["rules"]
    )


def test_xray_hostname_is_resolved_before_tun_without_changing_tls_name(monkeypatch):
    profile = ProxyProfile(
        source_uri=(
            "trojan://password@edge.example:443"
            "?security=tls&type=ws&host=origin.example&sni=tls.example"
        ),
        protocol="trojan",
        config_host="edge.example",
    )
    monkeypatch.setattr(
        "uac_desktop.engine.socket.getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::7", 443, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.7", 443)),
        ],
    )

    address = resolve_xray_upstream(profile)
    config = build_xray_config(profile, upstream_address=address)
    outbound = config["outbounds"][0]

    assert address == "203.0.113.7"
    assert outbound["settings"]["servers"][0]["address"] == "203.0.113.7"
    assert outbound["streamSettings"]["tlsSettings"]["serverName"] == "tls.example"
    assert outbound["streamSettings"]["wsSettings"]["headers"]["Host"] == "origin.example"


def test_singbox_tun_config_routes_web_to_socks_and_icmp_direct():
    config = build_singbox_tun_config([
        r"C:\Program Files\Example\example.exe", "example.exe", "game.exe",
    ])
    inbound = config["inbounds"][0]
    assert inbound["type"] == "tun"
    assert inbound["auto_route"] is True
    assert inbound["strict_route"] is True
    assert inbound["stack"] == "mixed"
    assert inbound["address"] == [
        "172.19.0.1/30", "fdfe:dcba:9876::1/126",
    ]
    assert "route_exclude_address" not in inbound
    assert config["route"]["final"] == "proxy"
    assert config["route"]["auto_detect_interface"] is True
    assert config["route"]["rules"][0] == {
        "process_name": ["xray.exe"],
        "ip_cidr": ["127.0.0.0/8"],
        "action": "route",
        "outbound": "local-direct",
    }
    assert config["route"]["rules"][1] == {
        "process_name": ["xray.exe"], "action": "route", "outbound": "direct",
    }
    assert {"port": 53, "action": "hijack-dns"} in config["route"]["rules"]
    assert {
        "network": "icmp", "action": "route", "outbound": "direct",
    } in config["route"]["rules"]
    assert {
        "process_name": ["example.exe", "game.exe"],
        "action": "route",
        "outbound": "direct",
    } in config["route"]["rules"]
    assert config["outbounds"][0]["server_port"] == SOCKS_PORT
    dns = config["dns"]["servers"][0]
    assert dns["type"] == "tcp"
    assert dns["server_port"] == 53
    assert dns["detour"] == "proxy"


def test_singbox_bypass_never_excludes_the_probe_process():
    current = os.path.basename(sys.executable)
    config = build_singbox_tun_config([current, "sing-box.exe", "game.exe"])
    process_rules = [
        rule["process_name"]
        for rule in config["route"]["rules"]
        if "process_name" in rule
    ]
    assert ["game.exe"] in process_rules
    assert all(current.lower() not in {name.lower() for name in names}
               for names in process_rules)
    assert all("sing-box.exe" not in {name.lower() for name in names}
               for names in process_rules)


def test_xray_mux_defaults_are_bounded_and_can_be_disabled():
    profile = default_profiles()[0]
    config = build_xray_config(profile, tuning=Tuning(xray_mux_concurrency=999))
    assert config["outbounds"][0]["mux"] == {
        "enabled": True,
        "concurrency": 32,
        "xudpConcurrency": 32,
        "xudpProxyUDP443": "allow",
    }
    no_mux = build_xray_config(profile, tuning=Tuning(xray_mux_enabled=False))
    assert "mux" not in no_mux["outbounds"][0]
    assert build_xray_config(profile, tuning=Tuning(log_level="minimal"))["log"]["loglevel"] == "warning"
    assert USER_AGENT == f"UAC-Spoofer-Desktop/{__version__}"


def test_mci_pins_http1_alpn_without_changing_irancell():
    profile = default_profiles()[0]
    mci = build_xray_config(profile, tuning=Tuning.carrier_preset("mci"))
    irancell = build_xray_config(profile, tuning=Tuning.carrier_preset("irancell"))
    user_profile = ProxyProfile(origin="sni-maker", source_uri=profile.source_uri)
    mci_user = build_xray_config(
        user_profile, tuning=Tuning.carrier_preset("mci")
    )
    mci_tls = mci["outbounds"][0]["streamSettings"]["tlsSettings"]
    irancell_tls = irancell["outbounds"][0]["streamSettings"]["tlsSettings"]
    mci_user_tls = mci_user["outbounds"][0]["streamSettings"]["tlsSettings"]
    assert mci_tls["alpn"] == ["http/1.1"]
    assert mci_tls["fingerprint"] == "chrome"
    assert "alpn" not in irancell_tls
    assert "fingerprint" not in irancell_tls
    assert "fingerprint" not in mci_user_tls


def test_tls_fragment_preserves_payload():
    hello = make_client_hello("www.speedtest.net")
    assert find_sni(hello) == "www.speedtest.net"
    assert b"".join(fragments(hello, "sni_split")) == hello
    assert b"".join(fragments(hello, "multi", 5)) == hello
    assert fragments(hello, "plain") == [hello]


def test_httpupgrade_mapping():
    profile = default_profiles()[5]
    parsed = parse_outbound(profile)
    assert parsed["network"] == "httpupgrade"
    config = build_xray_config(profile)
    assert "httpupgradeSettings" in config["outbounds"][0]["streamSettings"]


def test_mobile_tuning_presets_match():
    fast = Tuning.preset("fast")
    assert fast.multi_fragment_size == 256
    assert fast.route_probe_timeout_ms == 1200
    assert not fast.fake_probe_enabled
    stealth = Tuning.preset("stealth")
    assert stealth.fake_probe_delay_ms == 75
    assert stealth.sni_split_delay_ms == 60


def test_speed_tuning_defaults_and_presets_are_anti_storm():
    default = Tuning()
    assert default.xray_mux_enabled
    assert default.xray_mux_concurrency == 8
    assert default.pattern_max_sessions == 12
    assert not default.background_quality_probe_enabled
    assert default.background_quality_probe_delay_s == 30
    maximum = Tuning.preset("maximum")
    assert maximum.pattern_upload_optimized
    assert maximum.pattern_max_sessions == 12
    assert maximum.xray_mux_concurrency == 8
    streaming = Tuning.preset("streaming")
    assert not streaming.xray_mux_enabled
    assert streaming.pattern_max_sessions == 10
    compatibility = Tuning.preset("compatibility")
    assert not compatibility.xray_mux_enabled
    assert compatibility.pattern_max_sessions == 4


def test_carrier_routes_match_mobile_service():
    proxy = FragmentProxy(lambda _: None)
    proxy._profile = default_profiles()[0]
    proxy._tuning = Tuning(carrier_mode="mci")
    assert proxy._routes() == [("mci", ["104.18.8.83", "104.18.9.83"])]
    proxy._tuning.carrier_mode = "irancell"
    assert proxy._routes() == [("irancell", ["104.19.229.21", "104.19.230.21", "104.18.8.83", "104.18.9.83"])]
    proxy._tuning.carrier_mode = "auto"
    assert len(proxy._routes()) == 2


def test_fast_mode_never_forces_fake_probe():
    proxy = FragmentProxy(lambda _: None)
    proxy._profile = default_profiles()[0]
    proxy._tuning = Tuning.preset("fast")
    proxy._tuning.carrier_mode = "irancell"
    proxy._forced_strategy = "half"
    probes = []
    proxy._send_fake_probe = lambda host: probes.append(host)
    proxy._attempt = lambda carrier, host, first, strategy, delay, race_stop=None: (DummySocket(), b"\x16response")
    assert proxy._connect_host("irancell", "104.19.229.21", b"hello")
    assert probes == []


def test_auto_reuses_discovered_carrier_without_racing_again():
    proxy = FragmentProxy(lambda _: None)
    proxy._profile = default_profiles()[0]
    proxy._tuning = Tuning(carrier_mode="auto")
    proxy._preferred_carrier = "irancell"
    calls = []
    proxy._connect_route = lambda carrier, hosts, first: calls.append(carrier) or (DummySocket(), b"ok", "raw", carrier, hosts[0])
    result = proxy._connect_auto(proxy._routes(), b"hello")
    assert result[3] == "irancell"
    assert calls == ["irancell"]


class DummySocket:
    def close(self):
        pass


def test_recovery_reclaims_only_owned_xray(monkeypatch):
    engine = Engine(lambda _: None, lambda _: None, lambda _up, _down: None)
    calls = {"listeners": 0, "terminated": 0}

    def listeners(_ports):
        calls["listeners"] += 1
        return {SOCKS_PORT: 4242} if calls["listeners"] == 1 else {}

    class FakeProcess:
        def terminate(self): calls["terminated"] += 1
        def wait(self, timeout=None): return 0

    monkeypatch.setattr(engine, "_listener_owners", listeners)
    monkeypatch.setattr(engine, "_is_owned_xray", lambda pid: pid == 4242)
    monkeypatch.setattr("uac_desktop.engine.psutil.Process", lambda pid: FakeProcess())
    assert engine.reclaim_stale_listeners() == [4242]
    assert calls["terminated"] == 1


def test_recovery_reports_foreign_port_owner(monkeypatch):
    engine = Engine(lambda _: None, lambda _: None, lambda _up, _down: None)
    monkeypatch.setattr(engine, "_listener_owners", lambda _ports: {HTTP_PORT: 5151})
    monkeypatch.setattr(engine, "_is_owned_xray", lambda _pid: False)
    monkeypatch.setattr("uac_desktop.engine.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("uac_desktop.engine.time.monotonic", iter((0.0, 4.0)).__next__)

    class ForeignProcess:
        def name(self): return "foreign.exe"

    monkeypatch.setattr("uac_desktop.engine.psutil.Process", lambda pid: ForeignProcess())
    try:
        engine.reclaim_stale_listeners(timeout=3)
        assert False, "foreign listener must not be terminated"
    except RuntimeError as exc:
        assert "foreign.exe" in str(exc)
        assert str(HTTP_PORT) in str(exc)


def test_engine_uses_patterniha_core():
    engine = Engine(lambda _: None, lambda _: None, lambda _up, _down: None)
    assert isinstance(engine.fragment, PatternSniCore)


def test_engine_running_requires_live_pattern_when_route_uses_it():
    engine = Engine(lambda _: None, lambda _: None, lambda _up, _down: None)
    engine._active = True
    engine.process = RunningProcess()
    engine._fragment_required = True
    engine.fragment = SimpleNamespace(running=False)

    assert engine.running is False

    engine.fragment.running = True
    assert engine.running is True

    engine._fragment_required = False
    engine.fragment.running = False
    assert engine.running is True


def test_pattern_client_hello_contains_configured_fake_sni():
    hello = ClientHelloMaker.get_client_hello_with(b"r" * 32, b"s" * 32, b"auth.vercel.com", b"k" * 32)
    assert len(hello) == 517
    _rnd, _session, sni, _key = ClientHelloMaker.parse_client_hello(hello)
    assert sni == "auth.vercel.com"


def test_pattern_filter_is_control_only_and_valid():
    core = PatternSniCore(lambda _: None)
    core._profile = default_profiles()[0]
    core._edges = ["188.114.98.0", "104.18.8.83"]
    core._interface_ip = "192.168.70.2"
    packet_filter = core._packet_filter()
    assert "tcp.PayloadLength == 0" in packet_filter
    assert "!impostor" in packet_filter
    assert "tcp.DstPort == 443" in packet_filter
    assert WinDivert.check_filter(packet_filter)[0]


def test_pattern_upload_quality_defaults_are_bounded():
    quality = Quality.from_tuning(Tuning())
    assert quality.relay_buffer_kb == 512
    assert quality.socket_buffer_kb == 4096
    assert quality.max_sessions == 12
    assert quality.edge_failure_cooldown_s == 8
    assert quality.keepalive_interval_s == 3
    assert quality.keepalive_count == 3
    assert Tuning().pattern_connect_ip == "104.18.32.47"
    assert Tuning().pattern_fake_sni == "chatgpt.com"


def test_pattern_active_edge_exposes_selected_route_read_only():
    core = PatternSniCore(lambda _: None)
    assert core.active_edge == ""
    core._preferred_edge = "104.18.8.83"
    assert core.active_edge == "104.18.8.83"
    assert isinstance(PatternSniCore.active_edge, property)
    assert PatternSniCore.active_edge.fset is None


def test_pattern_retries_cooled_edges_when_every_edge_is_temporarily_failed():
    core = PatternSniCore(lambda _: None)
    core._edges = ["104.19.229.21", "104.19.230.21"]
    core._preferred_edge = None
    core._failed_until = {
        "104.19.229.21": time.monotonic() + 5,
        "104.19.230.21": time.monotonic() + 5,
    }

    assert core._ordered_edges() == ["104.19.229.21", "104.19.230.21"]


def test_pattern_full5_running_does_not_require_packet_injector():
    core = PatternSniCore(lambda _: None)
    core._strategy_override = "full5"
    core._server_sock = object()
    core._stop.clear()

    assert core.running is True
    assert core._injector is None


def test_pattern_mci_full5_hybrid_requires_packet_injector():
    core = PatternSniCore(lambda _: None)
    core._strategy_override = "full5"
    core._hybrid_fake_fragment = True
    core._server_sock = object()
    core._stop.clear()

    assert core.running is False
    core._injector = object()
    assert core.running is True


def test_pattern_fake_injector_repeats_payload_three_times():
    injector = PacketInjector.__new__(PacketInjector)
    injector.inject_delay_ms = 0
    injector.fake_repeat = 3
    injector.stop_event = threading.Event()
    sends = []
    injector._send = lambda packet, recalculate=False: sends.append(
        (bytes(packet.tcp.payload), recalculate)
    )
    packet = SimpleNamespace(
        tcp=SimpleNamespace(psh=False, payload=b"", seq_num=100),
        ip=SimpleNamespace(packet_len=40),
        ipv4=SimpleNamespace(ident=7),
    )
    connection = SimpleNamespace(
        lock=threading.Lock(), monitor=True, fake_data=b"fake",
        syn_seq=200, fake_sent=False,
    )

    injector._fake_send(packet, connection)

    assert sends == [(b"fake", True)] * 3
    assert connection.fake_sent is True
    assert packet.ip.packet_len == 44


def test_pattern_initial_waiters_parallelize_after_one_edge_discovery():
    core = PatternSniCore(lambda _: None)

    async def scenario():
        core._edge_lock = asyncio.Lock()
        core._preferred_edge = None
        active = 0
        maximum = 0
        calls = 0

        async def fake_connect(_incoming, _edges=None):
            nonlocal active, maximum, calls
            calls += 1
            active += 1
            maximum = max(maximum, active)
            if calls == 1:
                await asyncio.sleep(0.02)
                core._preferred_edge = "104.18.8.83"
            else:
                await asyncio.sleep(0.03)
            active -= 1
            return object()

        core._connect_edge_unlocked = fake_connect
        await asyncio.gather(*(core._connect_edge(object()) for _ in range(6)))
        return calls, maximum

    calls, maximum = asyncio.run(scenario())
    assert calls == 6
    assert maximum >= 2


def test_pattern_preferred_edge_failover_is_single_flight_then_parallel():
    core = PatternSniCore(lambda _: None)

    async def scenario():
        callers = 8
        core._edge_lock = asyncio.Lock()
        core._preferred_edge = "edge-a"
        old_edge_started = asyncio.Event()
        old_edge_calls = 0
        discovery_calls = 0
        replacement_calls = 0
        replacement_active = 0
        replacement_maximum = 0

        async def fake_connect(_incoming, edges=None):
            nonlocal old_edge_calls, discovery_calls, replacement_calls
            nonlocal replacement_active, replacement_maximum
            if edges == ("edge-a",):
                old_edge_calls += 1
                if old_edge_calls == callers:
                    old_edge_started.set()
                await old_edge_started.wait()
                core._preferred_edge = None
                return None
            if edges is None:
                discovery_calls += 1
                await asyncio.sleep(0.02)
                core._preferred_edge = "edge-b"
                return object()
            assert edges == ("edge-b",)
            replacement_calls += 1
            replacement_active += 1
            replacement_maximum = max(replacement_maximum, replacement_active)
            await asyncio.sleep(0.02)
            replacement_active -= 1
            return object()

        core._connect_edge_unlocked = fake_connect
        results = await asyncio.gather(*(core._connect_edge(object()) for _ in range(callers)))
        return (results, old_edge_calls, discovery_calls,
                replacement_calls, replacement_maximum)

    results, old_calls, discoveries, replacement_calls, maximum = asyncio.run(scenario())
    assert all(result is not None for result in results)
    assert old_calls == 8
    assert discoveries == 1
    assert replacement_calls == 7
    assert maximum >= 2


def test_pattern_handshake_parallelism_remains_bounded():
    core = PatternSniCore(lambda _: None)

    async def scenario():
        core._session_sem = asyncio.Semaphore(3)
        active = 0
        maximum = 0

        async def fake_connect(_incoming):
            nonlocal active, maximum
            active += 1
            maximum = max(maximum, active)
            await asyncio.sleep(0.02)
            active -= 1
            return object()

        async def fake_relay(_incoming, _outgoing):
            return None

        core._connect_edge = fake_connect
        core._relay_pair = fake_relay
        await asyncio.gather(*(core._handle(object()) for _ in range(9)))
        return maximum

    assert asyncio.run(scenario()) == 3


def test_upload_optimization_changes_nodelay_and_send_buffer():
    class RecordingSocket:
        def __init__(self):
            self.options = []
        def setsockopt(self, level, option, value):
            self.options.append((level, option, value))

    core = PatternSniCore(lambda _: None)
    optimized = RecordingSocket()
    core._quality = Quality(socket_buffer_kb=4096, upload_optimized=True)
    core._interface_index = 23
    core._tune_socket(optimized)
    assert (socket.IPPROTO_IP, 31, struct.pack("!I", 23)) not in optimized.options
    assert (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1) in optimized.options
    assert (socket.SOL_SOCKET, socket.SO_SNDBUF, 4096 * 1024) in optimized.options

    compatible = RecordingSocket()
    core._quality = Quality(socket_buffer_kb=4096, upload_optimized=False)
    core._tune_socket(compatible, True)
    assert (socket.IPPROTO_IP, 31, struct.pack("!I", 23)) in compatible.options
    assert (socket.IPPROTO_TCP, socket.TCP_NODELAY, 0) in compatible.options
    assert (socket.SOL_SOCKET, socket.SO_SNDBUF, 256 * 1024) in compatible.options


def test_pattern_pin_refreshes_stale_physical_interface(monkeypatch):
    core = PatternSniCore(lambda _: None)
    core._interface_ip = "192.168.1.10"
    core._interface_index = 3
    calls = []

    def tune(_sock, pin):
        calls.append((core._interface_ip, core._interface_index, pin))
        if len(calls) == 1:
            raise OSError("stale interface")

    monkeypatch.setattr(core, "_tune_socket", tune)
    monkeypatch.setattr(
        "uac_desktop.pattern_core.core.default_interface_ipv4",
        lambda _edge: "192.168.70.151",
    )
    monkeypatch.setattr(
        "uac_desktop.pattern_core.core.best_interface_index",
        lambda _edge: 23,
    )

    core._tune_outgoing_socket(object(), "104.19.229.21")

    assert calls == [
        ("192.168.1.10", 3, True),
        ("192.168.70.151", 23, True),
    ]


def test_pattern_handler_closes_incoming_when_edge_setup_fails():
    class CloseSocket:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    core = PatternSniCore(lambda _: None)
    core._session_sem = asyncio.Semaphore(1)
    incoming = CloseSocket()

    async def fail(_incoming):
        raise OSError("pin failed")

    core._connect_edge = fail
    asyncio.run(core._handle(incoming))

    assert incoming.closed


def test_pattern_upload_pump_relays_multiple_large_chunks():
    core = PatternSniCore(lambda _: None)
    core._quality = Quality(relay_buffer_kb=512, socket_buffer_kb=1024)
    payload = os.urandom(3 * 1024 * 1024 + 123)

    async def scenario():
        source, source_peer = socket.socketpair()
        destination, destination_peer = socket.socketpair()
        for item in (source, source_peer, destination, destination_peer):
            item.setblocking(False)
        loop = asyncio.get_running_loop()

        async def produce():
            await loop.sock_sendall(source_peer, payload)
            source_peer.shutdown(socket.SHUT_WR)

        async def consume():
            received = bytearray()
            while True:
                chunk = await loop.sock_recv(destination_peer, 512 * 1024)
                if not chunk:
                    return bytes(received)
                received.extend(chunk)

        try:
            pump = asyncio.create_task(core._pump(source, destination, True))
            _sent, received, _pumped = await asyncio.gather(produce(), consume(), pump)
            return received
        finally:
            for item in (source, source_peer, destination, destination_peer):
                item.close()

    assert asyncio.run(scenario()) == payload
    assert core.upload == len(payload)


class RunningProcess:
    def poll(self):
        return None


class FakeResponse:
    def __init__(self, status_code, value=None):
        self.status_code = status_code
        self.value = value

    def json(self):
        if self.value is None:
            raise ValueError("no JSON")
        return self.value


def test_upload_probe_verifies_exact_remote_echo(monkeypatch):
    engine = Engine(lambda _: None, lambda _: None, lambda _up, _down: None)
    engine._active = True
    engine.process = RunningProcess()

    class Session:
        trust_env = True
        def post(self, _url, data, **_kwargs):
            while data.read(8192):
                pass
            return FakeResponse(200, {"data": {"type": "Buffer", "data": [85] * (16 * 1024)}})
        def close(self):
            pass

    monkeypatch.setattr("uac_desktop.engine.requests.Session", Session)
    ok, detail = engine.probe_upload(size=64 * 1024)
    assert ok is True
    assert engine.last_upload_state == "verified"
    assert "exact 16384B echo" in detail
    assert engine.last_upload_speed_valid is False


def test_upload_early_404_is_not_misreported_as_verified(monkeypatch):
    engine = Engine(lambda _: None, lambda _: None, lambda _up, _down: None)
    engine._active = True
    engine.process = RunningProcess()

    class Session:
        trust_env = True
        def post(self, _url, data, **kwargs):
            assert kwargs["allow_redirects"] is False
            while data.read(8192):
                pass
            return FakeResponse(404)
        def close(self):
            pass

    monkeypatch.setattr("uac_desktop.engine.requests.Session", Session)
    ok, _detail = engine.probe_upload(size=64 * 1024)
    assert ok is None
    assert engine.last_upload_state == "inconclusive"


def test_upload_endpoint_timeout_is_inconclusive_not_config_failure(monkeypatch):
    engine = Engine(lambda _: None, lambda _: None, lambda _up, _down: None)
    engine._active = True
    engine.process = RunningProcess()

    class Session:
        trust_env = True
        def post(self, _url, data, **_kwargs):
            while data.read(8192):
                pass
            raise requests.ReadTimeout("endpoint did not answer")
        def close(self):
            pass

    monkeypatch.setattr("uac_desktop.engine.requests.Session", Session)
    ok, _detail = engine.probe_upload(size=64 * 1024)
    assert ok is None
    assert engine.last_upload_ok is None
    assert engine.last_upload_state == "inconclusive"


def test_upload_endpoint_error_remains_inconclusive_when_page_engine_is_alive(monkeypatch):
    engine = Engine(lambda _: None, lambda _: None, lambda _up, _down: None)
    engine._active = True
    engine.process = RunningProcess()

    class Session:
        trust_env = True
        def post(self, _url, data, **_kwargs):
            raise requests.exceptions.ProxyError("local proxy unavailable")
        def close(self):
            pass

    monkeypatch.setattr("uac_desktop.engine.requests.Session", Session)
    ok, _detail = engine.probe_upload(size=64 * 1024)
    assert ok is None
    assert engine.last_upload_state == "inconclusive"


def test_upload_probe_marks_failed_when_local_engine_is_stopped():
    engine = Engine(lambda _: None, lambda _: None, lambda _up, _down: None)
    ok, detail = engine.probe_upload(size=16 * 1024)
    assert ok is False
    assert detail == "engine stopped"
    assert engine.last_upload_state == "failed"


def test_engine_cancel_token_aborts_lifecycle_boundary():
    cancel = threading.Event()
    cancel.set()
    try:
        Engine._check_cancel(cancel)
        assert False, "cancelled generations must abort before spawning Xray"
    except EngineCancelled:
        pass


def test_engine_starts_validated_singbox_after_xray(monkeypatch, tmp_path):
    engine = Engine(lambda _line: None, lambda _running: None,
                    lambda _up, _down: None)
    engine._active = True
    engine.process = RunningProcess()
    engine._bypass_processes = ["game.exe"]
    binary = tmp_path / "sing-box.exe"
    binary.write_bytes(b"test")
    config_path = tmp_path / "sing-box-tun.json"
    calls = []

    class TunProcess:
        pid = 8123
        stdout = []

        def __init__(self):
            self.alive = True

        def poll(self):
            return None if self.alive else 0

        def terminate(self):
            calls.append("terminate")
            self.alive = False

        def wait(self, timeout=None):
            calls.append(("wait", timeout))
            return 0

        def kill(self):
            calls.append("kill")
            self.alive = False

    class ThreadStub:
        def __init__(self, **kwargs):
            calls.append(("thread", kwargs["name"]))

        def start(self):
            calls.append("thread-start")

    tun_process = TunProcess()
    monkeypatch.setattr("uac_desktop.engine.SING_BOX_CONFIG", config_path)
    monkeypatch.setattr(engine, "ensure_tun_available", lambda: binary)
    monkeypatch.setattr(engine, "_create_tun_job", lambda: calls.append("job-create") or 91)
    monkeypatch.setattr(
        engine, "_spawn_tun_in_job",
        lambda handle, command, cwd: calls.append(
            ("atomic-spawn", handle, command, cwd)
        ) or tun_process,
    )
    monkeypatch.setattr(engine, "_resume_tun_process",
                        lambda process: calls.append(("resume", process.pid)))
    monkeypatch.setattr(engine, "_close_tun_job",
                        lambda handle: calls.append(("job-close", handle)))
    monkeypatch.setattr(engine, "_write_singbox_owner_record", lambda process: calls.append(("owner", process.pid)))
    monkeypatch.setattr("uac_desktop.engine.subprocess.run",
                        lambda command, **kwargs: calls.append(("check", command, kwargs)) or
                        SimpleNamespace(returncode=0, stdout="", stderr=""))
    monkeypatch.setattr("uac_desktop.engine.threading.Thread", ThreadStub)
    monotonic = iter((0.0, 2.0))
    monkeypatch.setattr("uac_desktop.engine.time.monotonic", lambda: next(monotonic))

    engine.enable_tun()

    written = json.loads(config_path.read_text(encoding="utf-8"))
    assert written["route"]["final"] == "proxy"
    assert "route_exclude_address" not in written["inbounds"][0]
    assert calls[0][0] == "check"
    assert calls[1] == "job-create"
    assert calls[2][0] == "atomic-spawn"
    assert calls[2][1] == 91
    assert calls[2][2] == [
        str(binary), "run", "-c", str(config_path),
    ]
    assert calls[3] == ("owner", tun_process.pid)
    assert calls[4] == ("resume", tun_process.pid)
    assert engine.tun_running is True
    engine.disable_tun()
    assert "terminate" in calls
    assert ("job-close", 91) in calls
    assert engine.tun_running is False


def test_tun_process_is_atomically_created_inside_job(tmp_path):
    if sys.platform != "win32":
        return
    job = Engine._create_tun_job()
    process = None
    try:
        process = Engine._spawn_tun_in_job(
            job,
            [
                sys.executable, "-c",
                "import time; print('atomic-job-ok', flush=True); time.sleep(30)",
            ],
            tmp_path,
        )
        assert Engine._tun_process_in_job(job, process._handle)
        assert process.poll() is None
        Engine._resume_tun_process(process)
        assert process.stdout.readline().strip() == "atomic-job-ok"
        Engine._close_tun_job(job)
        job = 0
        assert process.wait(timeout=5) is not None
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=2)
        if process is not None and process.stdout is not None:
            process.stdout.close()
        if job:
            Engine._close_tun_job(job)


def test_failed_tun_stop_preserves_process_and_owner_for_recovery(monkeypatch):
    engine = Engine(lambda _line: None, lambda _running: None,
                    lambda _up, _down: None)
    removed = []

    class StuckProcess:
        pid = 9911

        def poll(self):
            return None

        def terminate(self):
            raise PermissionError("busy")

    process = StuckProcess()
    engine.tun_process = process
    engine._tun_job_handle = 73
    monkeypatch.setattr(engine, "_close_tun_job",
                        lambda _handle: (_ for _ in ()).throw(OSError("job busy")))
    monkeypatch.setattr(engine, "_remove_singbox_owner_record",
                        lambda pid=None: removed.append(pid))

    try:
        engine.disable_tun()
        assert False, "a live TUN process must retain its recovery record"
    except RuntimeError as exc:
        assert "did not stop" in str(exc)

    assert engine.tun_process is process
    assert engine._tun_job_handle == 73
    assert removed == []


def test_minimal_log_filter_suppresses_only_routine_client_aborts():
    routine = ("[Warning] app/proxyman/inbound: connection ends > proxy/http: "
               "failed to write response > wsasend: An established connection was aborted")
    startup_error = ("[Error] transport/internet/websocket: failed to dial to 127.0.0.1:40443 "
                     "> io: read/write on closed pipe")
    assert Engine._is_client_abort_noise(routine)
    assert not Engine._is_client_abort_noise(startup_error)


def test_auto_sni_candidates_are_measured_and_score_ordered():
    dummy = SimpleNamespace(storage=SimpleNamespace(
        scan_results=[
            {"domain": "dash.cloudflare.com", "success": True, "score": 100},
            {"domain": "chatgpt.com", "success": True, "score": 300},
            {"domain": "blog.cloudflare.com", "success": True, "score": 200},
        ],
        bookmarks=[],
        settings={},
        tuning=SimpleNamespace(carrier_mode="irancell", pattern_fake_sni="www.hcaptcha.com"),
    ))
    candidates = MainWindow._sni_candidates(dummy, carrier="irancell", limit=3)
    assert candidates == ["chatgpt.com", "blog.cloudflare.com", "dash.cloudflare.com"]
    assert "www.hcaptcha.com" not in candidates


def test_auto_sni_uses_configured_fake_sni_without_scan_results():
    dummy = SimpleNamespace(storage=SimpleNamespace(
        scan_results=[], bookmarks=[], settings={},
        tuning=SimpleNamespace(carrier_mode="auto", pattern_fake_sni="chatgpt.com"),
    ))

    assert MainWindow._sni_candidates(dummy, carrier="auto", limit=3) == ["chatgpt.com"]


def test_explicit_profile_sni_pin_precedes_auto_ranking():
    profile = SimpleNamespace(id="profile-1", sni="ignored.example")
    dummy = SimpleNamespace(storage=SimpleNamespace(
        scan_results=[
            {"domain": "chatgpt.com", "success": True, "score": 300},
            {"domain": "blog.cloudflare.com", "success": True, "score": 200},
        ],
        bookmarks=[],
        settings={"pattern_profile_sni_pins": {"profile-1": "blog.cloudflare.com"}},
        tuning=SimpleNamespace(carrier_mode="irancell", pattern_fake_sni="chatgpt.com"),
    ))
    assert MainWindow._sni_candidates(dummy, profile, "irancell", 2) == ["blog.cloudflare.com", "chatgpt.com"]


def test_atomic_storage_writes_are_thread_safe(tmp_path):
    target = tmp_path / "settings.json"
    def write_one(index):
        _write(target, {"index": index, "payload": "x" * 1000})
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        list(pool.map(write_one, range(40)))
    value = json.loads(target.read_text(encoding="utf-8"))
    assert value["index"] in range(40)
    assert value["payload"] == "x" * 1000
    assert not list(tmp_path.glob("*.tmp"))


def test_legacy_orphan_from_previous_bundle_is_reclaimable(monkeypatch):
    engine = Engine(lambda _: None, lambda _: None, lambda _up, _down: None)
    class PreviousBundleProcess:
        def name(self): return "xray.exe"
        def exe(self): return r"D:\old-build\bin\xray.exe"
        def cmdline(self): return [self.exe(), "run", "-config", str(XRAY_CONFIG)]
        def ppid(self): return 424242
    monkeypatch.setattr("uac_desktop.engine.psutil.Process", lambda _pid: PreviousBundleProcess())
    monkeypatch.setattr("uac_desktop.engine.psutil.pid_exists", lambda _pid: False)
    monkeypatch.setattr(engine, "_read_owner_record", lambda: {})
    assert engine._is_owned_xray(9999)


def test_inconclusive_upload_preserves_verified_benchmark():
    profile = SimpleNamespace(id="p1")
    previous = {
        "ok": True, "page_ok": True, "score": 77, "startup_ms": 1000.0,
        "upload_ok": True, "upload_state": "verified", "upload_mbps": 5.5,
        "upload_speed_valid": True, "upload_ms": 220.0, "sample_count": 3,
        "consecutive_failures": 0, "consecutive_upload_failures": 0,
        "engine": "patterniha-wrong-seq-v1", "tested_at": 1,
    }
    class Storage:
        tuning = SimpleNamespace(carrier_mode="irancell")
        settings = {"profile_benchmarks_pattern_irancell": {"p1": previous}}
        def save_settings(self): pass
    fake_engine = SimpleNamespace(
        last_probe_ms=1000.0, last_probe_url="https://www.youtube.com/generate_204",
        last_upload_state="inconclusive", last_upload_ok=None, last_upload_mbps=0.0,
        last_upload_speed_valid=False, last_upload_ms=8000.0,
        last_upload_reason="ReadTimeout",
    )
    dummy = SimpleNamespace(storage=Storage(), engine=fake_engine)
    MainWindow._save_profile_benchmark(dummy, profile, "wrong_seq", True,
                                       "inconclusive", "chatgpt.com", False)
    value = dummy.storage.settings["profile_benchmarks_pattern_irancell"]["p1"]
    assert value["upload_state"] == "verified"
    assert value["upload_ok"] is True
    assert value["upload_mbps"] == 5.5
    assert value["upload_ms"] == 220.0
    assert value["score"] == 77
    assert value["last_upload_probe_state"] == "inconclusive"
