from dataclasses import replace
import socket
import socketserver
import struct
import threading
from types import SimpleNamespace

import dns.message
import dns.rrset
import pytest

from uac_desktop.direct import carrier, coordinator, probe
from uac_desktop.direct.coordinator import DirectCoordinator, DirectOptions
from uac_desktop.direct.output import TUN_INTERFACE, build_tun_config
from uac_desktop.direct.resolvers import MOZILLA_DOH, RESOLVERS, parse_resolver, resolver_catalog
from uac_desktop.direct.store import DirectSettings, DirectStore, read_json, write_json
from uac_desktop.direct.xray import build_config


def test_settings_round_trip_excludes_unrecognized_values(tmp_path):
    store = DirectStore(tmp_path / "direct")
    write_json(store.settings_path, {"scan_ranges_by_latency": True, "private_key": "private", "hello_lengths": "0;3 5"})
    assert store.settings().scan_mode == "thorough"
    assert store.settings().hello_lengths == "1,3,5"
    settings = store.save_settings(replace(store.settings(), exit_country_code=" us ", connection_mode="proxy"))
    target = tmp_path / "backup.json"
    store.export_settings(target)
    assert "private_key" not in read_json(target)["settings"]
    restored = DirectStore(tmp_path / "restored").import_settings(target)
    assert restored == settings and restored.exit_country_code == "us"
    target.write_text("{}")
    with pytest.raises(ValueError, match="settings backup"):
        store.import_settings(target)


def test_saved_profiles_follow_source_network_expiry_and_exclusion(tmp_path, monkeypatch):
    now = 100_000
    monkeypatch.setattr("uac_desktop.direct.store.time.time", lambda: now)
    store = DirectStore(tmp_path)
    h2 = {"masque_transport": "h2", "h2_fragmentation": False, "token": "never persisted"}
    store.save_verified("pow", "wifi", "192.0.2.7:1701", h2)
    store.save_verified("direct", "wifi", "192.0.2.8:443", h2)
    assert store.find_profile("wifi").source == "direct"
    profile = store.find_profile("wifi", "192.0.2.8")
    assert profile.source == "pow" and profile.peer == "192.0.2.7:443"
    assert profile.options == {"h2_fragmentation": False}
    assert not store.find_profile("ethernet")
    now += 86401
    assert not store.find_profile("wifi")


def test_carrier_fallback_order_only_after_carrier_failure(tmp_path, monkeypatch):
    store = DirectStore(tmp_path)
    store.save_verified("direct", "wifi", "192.0.2.7", {"masque_transport": "h2"})
    attempts = []
    current = carrier.DirectCarrier(store, tmp_path / "pow.toml", lambda: "wifi", lambda _: None)
    monkeypatch.setattr(carrier, "check_binary", lambda _: "source")

    def attempt(_settings, _cancel, *, excluded_ip=None, compatibility=False, remembered=None):
        profile = "remembered" if remembered else "compatibility" if compatibility else "primary"
        attempts.append((profile, excluded_ip))
        if profile != "compatibility" and excluded_ip is None:
            raise carrier.CarrierError("masque: CONNECT failed")
        return profile

    monkeypatch.setattr(current, "_attempt", attempt)
    assert current.start(DirectSettings(), threading.Event()) == "compatibility"
    assert [name for name, _ in attempts] == ["primary", "remembered", "compatibility"]
    attempts.clear()
    assert current.start(DirectSettings(), threading.Event(), "192.0.2.7") == "primary"
    assert attempts == [("primary", "192.0.2.7")]
    assert not carrier.permits_retry("account: certificate provisioning failed")
    assert carrier.permits_retry("Direct carrier startup budget expired")


def _dns_response(query, address):
    request = dns.message.from_wire(query)
    response = dns.message.make_response(request)
    response.answer.append(dns.rrset.from_text(request.question[0].name, 30, "IN", "A", address))
    return response.to_wire()


def test_doh_verifies_question_transaction_and_public_a_record():
    query = probe._query("www.google.com", 0)
    assert probe.answers_with_public_ipv4(query, _dns_response(query, "8.8.8.8"))
    assert not probe.answers_with_public_ipv4(query, _dns_response(query, "192.168.1.1"))
    unrelated = probe._query("www.example.com", 0)
    assert not probe.answers_with_public_ipv4(query, _dns_response(unrelated, "8.8.8.8"))
    assert not probe.answers_with_public_ipv4(query, _dns_response(query, "8.8.8.8")[:-1])


def test_dns_lab_catalog_round_trip_and_real_tcp_measurements(tmp_path):
    class DnsServer(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            size = struct.unpack("!H", probe.recv_exact(self.request, 2))[0]
            response = _dns_response(probe.recv_exact(self.request, size), "8.8.8.8")
            self.request.sendall(struct.pack("!H", len(response)) + response)

    with socketserver.TCPServer(("127.0.0.1", 0), DnsServer) as server:
        handler = threading.Thread(target=server.serve_forever, daemon=True)
        handler.start()
        try:
            chosen = parse_resolver(f"tcp://127.0.0.1:{server.server_address[1]}")
            scan = probe.scan_dns((chosen,), 0, threading.Event())
            assert scan[0].attempts == len(scan[0].samples) == 4
            assert scan[0].latency >= 1
        finally:
            server.shutdown()
            handler.join(2)
    assert parse_resolver("2001:4860:4860::8888").url == "tcp://[2001:4860:4860::8888]"
    with pytest.raises(ValueError):
        parse_resolver("https://user:secret@example.com/")
    store = DirectStore(tmp_path)
    store.save_settings(replace(store.settings(), auto_select_dns=False, custom_dns=(chosen.url, chosen.url),
                                pinned_dns=chosen.url))
    saved = store.settings()
    assert saved.pinned_dns == chosen.url and saved.custom_dns == (chosen.url,)
    assert resolver_catalog(saved.custom_dns)[-1] == chosen


def test_aetherst_dns_catalog_and_pinned_resolver(tmp_path):
    chosen = parse_resolver("udp://[2001:4860:4860::8888]:53")
    assert chosen.label == "Google" and chosen.protocol == "UDP"
    catalog = resolver_catalog((chosen.url,))
    assert len({item.url for item in catalog if item.protocol == "UDP"}) == 30
    assert parse_resolver("udp://10.202.10.10").label == "Radar"
    assert all(item.protocol == "DoH" for item in RESOLVERS)

    store = DirectStore(tmp_path)
    store.save_settings(replace(store.settings(), pinned_dns=chosen.url, custom_dns=(chosen.url,)))
    assert store.settings().pinned_dns == chosen.url
    assert store.settings().custom_dns == ()
    config = build_config(DirectSettings(iran_direct=False), 46501, exit_port=46503, session_dns=chosen)
    server = config["dns"]["servers"][0]
    assert (server["tag"], server["address"], server["port"]) == ("dns-unfiltered", chosen.host, 53)


@pytest.mark.parametrize("host", ("127.0.0.1", "::1"))
def test_dns_lab_measures_real_udp_answers(host):
    class DnsServer(socketserver.BaseRequestHandler):
        def handle(self):
            query, sock = self.request
            sock.sendto(_dns_response(query, "8.8.8.8"), self.client_address)

    class LocalServer(socketserver.UDPServer):
        address_family = socket.AF_INET6 if host == "::1" else socket.AF_INET

    try:
        server = LocalServer((host, 0), DnsServer)
    except OSError:
        if host == "::1":
            pytest.skip("IPv6 loopback unavailable")
        raise
    with server:
        handler = threading.Thread(target=server.serve_forever, daemon=True)
        handler.start()
        try:
            address = "[::1]" if host == "::1" else host
            chosen = parse_resolver(f"udp://{address}:{server.server_address[1]}")
            scan, = probe.scan_dns((chosen,), 0, threading.Event())
            assert scan.attempts == len(scan.samples) == 4
        finally:
            server.shutdown()
            handler.join(2)


def test_dns_lab_route_bypasses_interception_and_pinned_dns_reaches_tun():
    settings = DirectSettings(iran_direct=False)
    chosen = parse_resolver("https://dns.google/dns-query")
    config = build_config(settings, 46501, exit_port=46503, dns_lab_port=46504, session_dns=chosen)
    assert config["dns"]["servers"][0]["address"] == chosen.url
    assert config["dns"]["hosts"][chosen.host] == list(chosen.bootstrap)
    rules = config["routing"]["rules"]
    assert "dns-lab-in" not in rules[0]["inboundTag"]
    assert rules[1]["inboundTag"] == ["dns-lab-in"]
    assert rules[1]["outboundTag"] == rules[2]["outboundTag"] == "direct-wireguard-dns"
    assert next(o for o in config["outbounds"] if o["tag"] == "direct-wireguard")["targetStrategy"] == "UseIPv4"
    tun = build_tun_config(settings, 46501, "1.1.1.1", 1280, "all", [], "mixed")
    assert tun["dns"]["servers"][0]["detour"] == "proxy"
    assert next(o for o in tun["outbounds"] if o["tag"] == "proxy")["server_port"] == 46501


@pytest.mark.parametrize("iran_direct", (True, False))
def test_pinned_dns_is_not_repeated_as_a_fallback(iran_direct):
    config = build_config(DirectSettings(iran_direct=iran_direct), 46501, exit_port=46503,
                          session_dns=parse_resolver(MOZILLA_DOH))
    servers = config["dns"]["servers"]
    pinned, = [server for server in servers if server["address"] == MOZILLA_DOH]
    assert pinned["tag"] == "dns-unfiltered" and not pinned.get("skipFallback")
    assert ("domain:youtube.com" in pinned.get("domains", [])) is iran_direct
    assert any(server["address"] == "https://dns.google/dns-query" for server in servers)


def test_dns_apply_rebuilds_the_existing_direct_session(tmp_path, monkeypatch):
    ready = threading.Event()
    rebuilt = threading.Event()
    calls = []

    def report(status):
        if status.phase == "connected":
            (rebuilt if len(calls) > 1 else ready).set()

    def connect_route(_stack, settings, _options, _directory, socks, http, _paused, _allow):
        calls.append(settings)
        return SimpleNamespace(tun=None, carrier=None, healthy=lambda: True,
                               socks_port=socks, http_port=http, probe_port=40000,
                               dns_lab_port=40001, stats_port=40002)

    current = DirectCoordinator(tmp_path / "direct", tmp_path, status=report, log=lambda _: None)
    monkeypatch.setattr(coordinator, "_network_key", lambda: "wifi")
    monkeypatch.setattr(coordinator, "xray_traffic", lambda *_args: None)
    monkeypatch.setattr(coordinator, "NetworkNotifications", lambda _event: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(coordinator, "WindowsProxy", lambda _log: SimpleNamespace(
        bind_session=lambda *args, **kwargs: None, restore_session=lambda: None,
    ))
    monkeypatch.setattr(current, "_connect_route", connect_route)
    assert current.connect(DirectOptions(vpn=False, system_proxy=False))
    try:
        assert ready.wait(2)
        worker = current._worker
        dns_settings = replace(current.store.settings(), auto_select_dns=False, pinned_dns="tcp://9.9.9.9")
        assert current.reload_dns(dns_settings)
        assert rebuilt.wait(2)
        assert current._worker is worker
        assert calls[-1].pinned_dns == dns_settings.pinned_dns and not calls[-1].auto_select_dns
    finally:
        current.disconnect()
        assert current.wait(3)


def test_dns_verification_uses_real_socks_connect_and_tcp_framing():
    class Fixture(socketserver.BaseRequestHandler):
        def handle(self):
            sock = self.request
            sock.settimeout(2)
            assert probe.recv_exact(sock, 3) == b"\x05\x01\x00"
            sock.sendall(b"\x05\x00")
            assert probe.recv_exact(sock, 10) == b"\x05\x01\x00\x01\x01\x01\x01\x01\x00\x35"
            sock.sendall(b"\x05\x00\x00\x03\x09localhost\x00\x00")
            size = struct.unpack("!H", probe.recv_exact(sock, 2))[0]
            response = _dns_response(probe.recv_exact(sock, size), "8.8.8.8")
            sock.sendall(struct.pack("!H", len(response)) + response)

    with socketserver.TCPServer(("127.0.0.1", 0), Fixture) as server:
        handler = threading.Thread(target=server.handle_request, daemon=True)
        handler.start()
        assert probe.verify_dns(server.server_address[1], "1.1.1.1").ok
        handler.join(2)
        assert not handler.is_alive()


def test_xray_and_tun_config_keep_requested_output_policy():
    settings = DirectSettings(udp_noise=True)
    config = build_config(settings, 46501, http_port=46502, exit_port=46503, country_exit=True)
    rules = config["routing"]["rules"]
    assert rules[0]["outboundTag"] == "dns-out"
    assert any(rule.get("domain", [""])[0] == "domain:youtube.com" and rule["outboundTag"] == "direct-wireguard" for rule in rules)
    assert any(rule.get("network") == "udp" and rule["outboundTag"] == "block" for rule in rules)
    assert "burstObservatory" not in config
    plain = build_config(settings, 46501, mask_ports={"oob": 46504, "record-sni": 46505})
    tags = {outbound["tag"] for outbound in plain["outbounds"]}
    assert {"direct-hello-oob", "direct-hello-record-sni", "direct-hello-record-small", "direct-udp-noise"} <= tags
    tun = build_tun_config(settings, 46501, "1.1.1.1", 1280, "only", ["selected.exe"], "mixed")
    assert tun["inbounds"][0]["interface_name"] == TUN_INTERFACE
    assert tun["route"]["rules"][2]["invert"]
    assert "selected.exe" in tun["route"]["rules"][2]["process_name"]
    assert tun["route"]["rules"][3]["action"] == "hijack-dns"


def test_stop_waits_for_cleanup_and_suppresses_stale_connected(tmp_path, monkeypatch):
    started = threading.Event()
    cleaned = threading.Event()
    seen = []
    direct = DirectCoordinator(tmp_path / "direct", tmp_path, status=seen.append, log=lambda _: None)
    monkeypatch.setattr(coordinator, "_network_key", lambda: "wifi")

    class NoNotifications:
        def __init__(self, _changed):
            pass

        def close(self):
            pass

    def pending(stack, *args):
        stack.callback(cleaned.set)
        started.set()
        direct._stop.wait(2)
        direct._publish(phase="connected")
        carrier.ensure_active(direct._stop)

    monkeypatch.setattr(coordinator, "NetworkNotifications", NoNotifications)
    monkeypatch.setattr(direct, "_connect_route", pending)
    assert direct.connect(DirectOptions(vpn=False, system_proxy=False))
    assert started.wait(2)
    assert not direct.connect(DirectOptions(vpn=False))
    direct.disconnect()
    assert direct.wait(2) and cleaned.is_set()
    assert direct.status.phase == "idle" and all(status.phase != "connected" for status in seen)
