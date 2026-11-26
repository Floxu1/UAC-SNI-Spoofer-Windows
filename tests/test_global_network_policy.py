import json
import socket
import subprocess
import threading
import time
from dataclasses import replace
from pathlib import Path

import dns.message
import dns.rcode
import pytest

from uac_desktop.application_settings import ConnectionPreferences
from uac_desktop.direct.output import build_tun_config
from uac_desktop.direct.store import DirectSettings
from uac_desktop.direct.xray import build_config as build_direct_config
from uac_desktop.engine import build_singbox_proxy_bypass_config, build_singbox_tun_config, build_xray_config
from uac_desktop.models import Tuning, default_profiles
from uac_desktop.pow.config import PowSettings
from uac_desktop.pow.forwarder import HttpToSocks
from uac_desktop.pow.routing import add_tun_proxy_listener, apply_rules, apply_tun_filters
from uac_desktop.pow.tun_guard import harden_config
from uac_desktop.routing_data import LOCAL_IPV4_NETWORKS, is_local_ipv4


BIN = Path(__file__).resolve().parents[1] / "bin"


@pytest.mark.parametrize("engine", ["xray", "pow", "direct"])
@pytest.mark.parametrize("enabled", [False, True])
def test_native_tun_config_validates_shared_security_filters(tmp_path, engine, enabled):
    binary = BIN / "sing-box.exe"
    if not binary.is_file():
        pytest.skip("sing-box is not installed")
    prefs = ConnectionPreferences(iran_direct=False, domains_direct="example.net", ipv6_block=enabled,
                                  dns_sinkhole=enabled, webrtc_block=enabled, quic_block=enabled)
    if engine == "direct":
        config = build_tun_config(DirectSettings(ipv6=True, block_quic=False), 19080, "1.1.1.1",
                                  1400, "bypass", [], "mixed", privacy=prefs, proxy_port=19081)
    elif engine == "pow":
        config = harden_config(build_singbox_tun_config(), ipv6_block=enabled)
        apply_rules(config, prefs.for_pow(PowSettings()), [], BIN / "geosite.dat", tun=True, warp_only=True)
        add_tun_proxy_listener(config, 19081, dns_sinkhole=prefs.dns_sinkhole, ipv6_block=prefs.ipv6_block)
        assert any(rule.get("domain_suffix") == ["example.net"] and rule["outbound"] == "direct"
                   for rule in config["route"]["rules"])
    else:
        config = build_singbox_tun_config()
        apply_tun_filters(config, prefs)
    rules = config["route"]["rules"]
    assert any(rule.get("ip_version") == 6 and rule["action"] == "reject" and "inbound" not in rule
               for rule in rules) is enabled
    assert any(rule.get("protocol") == "stun" and rule["action"] == "reject" for rule in rules) is enabled
    assert any(rule.get("protocol") == "quic" and rule["action"] == "reject" for rule in rules) is enabled
    assert any(rule.get("rcode") == "NXDOMAIN" for rule in config["dns"].get("rules", [])) is enabled
    path = tmp_path / "tun.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    checked = subprocess.run([str(binary), "check", "-c", str(path)], capture_output=True, text=True, timeout=10)
    assert checked.returncode == 0, checked.stderr

    if enabled:
        # Exercise the same DNS policy through a UDP listener without installing a Windows route.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as allocate:
            allocate.bind(("127.0.0.1", 0))
            port = allocate.getsockname()[1]
        cfg = {
            "log": {"level": "debug"},
            "dns": config["dns"],
            "inbounds": [{"type": "direct", "listen": "127.0.0.1", "listen_port": port,
                          "network": "udp", "override_address": "127.0.0.1", "override_port": 53}],
            "outbounds": [{"type": "direct", "tag": "proxy"}],
            "route": {"rules": [{"port": 53, "action": "hijack-dns"}], "final": "proxy"},
        }
        # The NXDOMAIN response must come from the native filter before it would use this upstream.
        cfg["dns"]["servers"] = [{"type": "udp", "tag": "remote-dns",
                                  "server": "127.0.0.1", "server_port": 1}]
        path.write_text(json.dumps(cfg), encoding="utf-8")
        with subprocess.Popen([str(binary), "run", "-c", str(path)], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT) as helper:
            try:
                payload = dns.message.make_query("ad.doubleclick.net", "A").to_wire()
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
                    peer.settimeout(0.25)
                    for _ in range(12):
                        assert helper.poll() is None, helper.stdout.read().decode(errors="replace")
                        peer.sendto(payload, ("127.0.0.1", port))
                        try:
                            packet, _ = peer.recvfrom(4096)
                        except ConnectionResetError:
                            time.sleep(0.1)
                            continue
                        except TimeoutError:
                            continue
                        assert dns.message.from_wire(packet).rcode() == dns.rcode.NXDOMAIN
                        break
                    else:
                        helper.terminate()
                        output, _ = helper.communicate(timeout=5)
                        pytest.fail(f"No DNS response from sing-box: {output.decode(errors='replace')}")
            finally:
                helper.terminate()
                helper.wait(timeout=5)


def test_xray_domain_bypass_uses_dns_suffix_matching_without_iran_bypass():
    config = build_xray_config(default_profiles()[0], tuning=Tuning(iran_direct=False),
                               domains_direct="EXAMPLE.net, invalid://secret@example.net")
    assert {"type": "field", "domain": ["domain:example.net"], "outboundTag": "direct"} in config["routing"]["rules"]
    assert all(inbound["sniffing"]["routeOnly"] for inbound in config["inbounds"])


def test_site_ip_rules_reach_all_engines_without_displacing_protection():
    prefs = ConnectionPreferences(iran_direct=False, ips_direct="192.0.2.0/24, 2001:db8::1")
    ips = ["192.0.2.0/24", "2001:db8::1"]
    config = build_xray_config(default_profiles()[0], tuning=Tuning(iran_direct=False),
                               ips_direct=prefs.ips_direct)
    assert {"type": "field", "ip": ips, "outboundTag": "direct"} in config["routing"]["rules"]
    direct = build_direct_config(prefs.for_direct(DirectSettings(ipv6=False)), 19080, exit_port=19081)
    rules = direct["routing"]["rules"]
    v6 = next(i for i, rule in enumerate(rules) if rule.get("ip") == ["::/0"])
    bypass = next(i for i, rule in enumerate(rules) if rule.get("ip") == ips)
    assert v6 < bypass and rules[bypass]["outboundTag"] == "direct-plain"
    for guarded in (False, True):
        tun = build_singbox_tun_config()
        settings = replace(prefs, kill_switch=guarded).for_pow(PowSettings())
        apply_rules(tun, settings, [], BIN / "geosite.dat", tun=True, warp_only=True)
        rules = tun["route"]["rules"]
        user_rules = [i for i, rule in enumerate(rules) if rule.get("ip_cidr") == ips]
        if guarded:
            assert not user_rules
        else:
            ipv6_filter = next(i for i, rule in enumerate(rules) if rule.get("ip_version") == 6)
            assert len(user_rules) == 1 and ipv6_filter < user_rules[0]


@pytest.mark.parametrize("address", ["10.0.0.138", "172.23.1.1", "192.168.100.1", "169.254.1.1"])
def test_router_ip_is_always_local(address):
    assert is_local_ipv4(address)
    assert not any(is_local_ipv4(host) for host in ("172.15.0.1", "172.32.0.1", "10.example.com", "100.64.0.1", "1.1.1.1"))
    ranges = list(LOCAL_IPV4_NETWORKS)
    xray = build_xray_config(default_profiles()[0], tuning=Tuning(iran_direct=False))
    direct = build_direct_config(DirectSettings(iran_direct=False), 19080, exit_port=19081)
    mixed = build_singbox_proxy_bypass_config(listen_port=19080, socks_port=19081)
    assert {"type": "field", "ip": ranges, "outboundTag": "direct"} in xray["routing"]["rules"]
    assert any(rule.get("ip") == ranges and rule["outboundTag"] == "direct-plain"
               for rule in direct["routing"]["rules"])
    assert {"ip_cidr": ranges, "action": "route", "outbound": "direct"} in mixed["route"]["rules"]


def test_lightweight_pow_proxy_opens_router_without_using_the_exit(monkeypatch):
    forwarder = HttpToSocks(19080, "127.0.0.1", 19081)
    calls = []
    client, inbound = socket.socketpair()
    outbound, router = socket.socketpair()
    with client, inbound, outbound, router:
        monkeypatch.setattr(socket, "create_connection",
                            lambda target, timeout: calls.append(target) or outbound)
        client.settimeout(2)
        router.settimeout(2)
        worker = threading.Thread(target=forwarder._handle, args=(inbound,), daemon=True)
        worker.start()
        try:
            client.sendall(b"GET http://192.168.100.1/?status=1 HTTP/1.1\r\nHost: 192.168.100.1\r\n\r\n")
            assert router.recv(4096).startswith(b"GET /?status=1 HTTP/1.1\r\n")
            router.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            assert client.recv(4096).startswith(b"HTTP/1.1 200")
            assert calls == [("192.168.100.1", 80)]
        finally:
            router.shutdown(socket.SHUT_RDWR)
            worker.join(3)


def test_native_tun_proxy_listener_filters_explicit_requests(tmp_path):
    binary = BIN / "sing-box.exe"
    if not binary.is_file():
        pytest.skip("sing-box is not installed")
    with socket.socket() as allocation:
        allocation.bind(("127.0.0.1", 0))
        port = allocation.getsockname()[1]
    config = build_singbox_tun_config()
    config["log"] = {"level": "debug"}
    config["inbounds"].clear()  # Exercise the companion inbound without installing an adapter.
    add_tun_proxy_listener(config, port, dns_sinkhole=True, ipv6_block=True)
    path = tmp_path / "local-proxy.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    with subprocess.Popen([str(binary), "run", "-c", str(path)], stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT) as helper, socket.socket() as target:
        try:
            target.bind(("127.0.0.1", 0))
            target.listen()
            for _ in range(30):
                assert helper.poll() is None, helper.stdout.read().decode(errors="replace")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.1)
            address = f"127.0.0.1:{target.getsockname()[1]}"
            with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                client.sendall(f"CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n".encode())
                assert b"200" in client.recv(4096)
                target.settimeout(2)
                with target.accept()[0] as upstream:
                    upstream.sendall(b"verified")
                    assert client.recv(8) == b"verified"
            for address in ("ad.doubleclick.net:443", "[::1]:443"):
                with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                    client.sendall(f"CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n".encode())
                    try:
                        response = bytearray()
                        while b"\r\n\r\n" not in response:
                            chunk = client.recv(1024)
                            if not chunk:
                                break
                            response.extend(chunk)
                        assert not response.partition(b"\r\n\r\n")[2]
                        assert client.recv(1024) == b""
                    except (BrokenPipeError, ConnectionResetError):
                        pass
        finally:
            helper.terminate()
            log, _ = helper.communicate(timeout=5)
    assert log.count(b"=> reject") == 2, log.decode(errors="replace")
