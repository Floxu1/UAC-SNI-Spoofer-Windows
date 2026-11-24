"""Speed options: each off = connect unchanged; each on = intended behaviour."""

from __future__ import annotations

import json
import socket
import threading

from uac_desktop.pow import config as C
from uac_desktop.pow import speed as S
from uac_desktop.pow.store import PowStore
from test_pow_engine import _coordinator, _FakeAether


class _JsonAether(_FakeAether):
    """Fake aether that also keeps the outer JSON it was started with."""

    def __init__(self, ready_protocols, **kwargs):
        super().__init__(ready_protocols, **kwargs)
        self.payloads: list[dict] = []
        self.ready_transports: set[str] | None = None

    def start(self, outer_json: str, extra_env=None, tail_core_log=True) -> None:
        payload = json.loads(outer_json)
        self.payloads.append(payload)
        self.started.append(payload["protocol"])

    def wait_ready(self, port, budget_ms, stop):
        if not self.started or self.started[-1] not in self.ready_protocols:
            return False
        if self.ready_transports is not None:
            return self.payloads[-1]["masque_transport"] in self.ready_transports
        return True


def _setup(tmp_path, monkeypatch, ready=("masque",), psiphon_succeed_on=0):
    coordinator, store, status, _aether, psiphon = _coordinator(
        tmp_path, monkeypatch, ready=set(ready), psiphon_succeed_on=psiphon_succeed_on
    )
    aether = _JsonAether(set(ready))
    monkeypatch.setattr(coordinator, "_aether", aether)
    logs: list[str] = []
    monkeypatch.setattr(coordinator, "_log", logs.append)
    monkeypatch.setattr(coordinator, "_enable_proxy", lambda: None)
    return coordinator, store, aether, psiphon, logs


# -- defaults ------------------------------------------------------------------


def test_speed_options_default_off_and_persist(tmp_path):
    settings = C.PowSettings()
    assert not (settings.parallel_masque or settings.irancell_h3
                or settings.direct_psiphon_first or settings.lowest_rtt_ip)
    store = PowStore(tmp_path)
    assert not store.snapshot().parallel_masque
    store.save(C.PowSettings(parallel_masque=True, lowest_rtt_ip=True))
    again = PowStore(tmp_path).snapshot()
    assert again.parallel_masque and again.lowest_rtt_ip
    assert not again.irancell_h3 and not again.direct_psiphon_first


def test_all_off_mci_masque_h2_unchanged(tmp_path, monkeypatch):
    coordinator, _store, aether, psiphon, logs = _setup(tmp_path, monkeypatch)
    (tmp_path / S.CLEAN_H2_FILENAME).write_text(json.dumps({"peers": ["1.1.1.1:443", "2.2.2.2:443"]}))
    probed: list = []
    monkeypatch.setattr(S, "rank_peers", lambda *a, **k: probed.append(a) or [])
    settings = C.PowSettings(firewall_profile=C.FIREWALL_MCI, chain_psiphon=True)
    coordinator.connect(settings, proxy_mode=True)
    assert aether.started == ["masque"]
    payload = aether.payloads[0]
    # Mobile parity: the first MASQUE attempt runs the thorough scan.
    expected = json.loads(C.chain_outer_json(tmp_path, "masque", settings, scan_mode=C.attempt_scan_mode("masque", 0, settings.scan_mode), mci=True))
    assert payload == expected
    assert payload["masque_transport"] == "h2"
    assert psiphon.attempts == 1  # only the chained Psiphon, no direct pre-try
    assert coordinator._chain_port == C.CHAIN_SOCKS_PORT and coordinator._router is None
    assert probed == []
    assert json.loads((tmp_path / S.CLEAN_H2_FILENAME).read_text())["peers"] == ["1.1.1.1:443", "2.2.2.2:443"]
    assert not any(line.startswith(("Speed options", "Parallel", "Lowest", "Direct Psiphon", "HTTP/3 on")) for line in logs)
    coordinator.disconnect(quiet=True)


def test_psiphon_upstream_default_port_unchanged():
    strategy = C.STRATEGY_F
    config = json.loads(C.psiphon_config(1821, "x", None, strategy))
    assert config["UpstreamProxyURL"] == f"socks5://127.0.0.1:{C.CHAIN_SOCKS_PORT}"
    config = json.loads(C.psiphon_config(1821, "x", None, strategy, upstream_port=S.ROUTER_PORT))
    assert config["UpstreamProxyURL"] == f"socks5://127.0.0.1:{S.ROUTER_PORT}"


# -- 2. HTTP/3 on Irancell -------------------------------------------------------


def test_irancell_h3_off_keeps_single_h3_attempt(tmp_path, monkeypatch):
    coordinator, _store, aether, _psiphon, _logs = _setup(tmp_path, monkeypatch)
    settings = C.PowSettings(firewall_profile=C.FIREWALL_IRANCELL, chain_psiphon=False)
    coordinator.connect(settings, proxy_mode=True)
    assert [p["masque_transport"] for p in aether.payloads] == ["h3"]
    coordinator.disconnect(quiet=True)


def test_irancell_h3_on_falls_back_to_h2(tmp_path, monkeypatch):
    coordinator, _store, aether, _psiphon, logs = _setup(tmp_path, monkeypatch)
    aether.ready_transports = {"h2"}
    settings = C.PowSettings(firewall_profile=C.FIREWALL_IRANCELL, irancell_h3=True, chain_psiphon=False)
    coordinator.connect(settings, proxy_mode=True)
    assert [p["masque_transport"] for p in aether.payloads] == ["h3", "h2"]
    assert coordinator._won_transport == "h2"
    assert any("HTTP/2 fallback won" in line for line in logs)
    coordinator.disconnect(quiet=True)


def test_irancell_h3_on_h3_wins(tmp_path, monkeypatch):
    coordinator, _store, aether, _psiphon, logs = _setup(tmp_path, monkeypatch)
    settings = C.PowSettings(firewall_profile=C.FIREWALL_IRANCELL, irancell_h3=True, chain_psiphon=False)
    coordinator.connect(settings, proxy_mode=True)
    assert [p["masque_transport"] for p in aether.payloads] == ["h3"]
    assert any("HTTP/3 won" in line for line in logs)
    coordinator.disconnect(quiet=True)


def test_irancell_h3_never_on_mci_or_auto(tmp_path, monkeypatch):
    for firewall in (C.FIREWALL_MCI, C.FIREWALL_AUTO):
        coordinator, _store, aether, _psiphon, logs = _setup(tmp_path, monkeypatch)
        settings = C.PowSettings(firewall_profile=firewall, irancell_h3=True, chain_psiphon=False)
        coordinator.connect(settings, proxy_mode=True)
        assert [p["masque_transport"] for p in aether.payloads] == ["h2"]
        assert any("HTTP/3 on Irancell: not used" in line for line in logs)
        coordinator.disconnect(quiet=True)


# -- 3. Direct Psiphon first -----------------------------------------------------


def test_direct_psiphon_first_wins_and_skips_warp(tmp_path, monkeypatch):
    coordinator, _store, aether, psiphon, logs = _setup(tmp_path, monkeypatch, psiphon_succeed_on=0)
    settings = C.PowSettings(firewall_profile=C.FIREWALL_MCI, direct_psiphon_first=True)
    result = coordinator.connect(settings, proxy_mode=True)
    assert aether.started == []
    assert psiphon.attempts == 1
    assert coordinator._direct_psiphon
    assert coordinator.exit_port == C.PSIPHON_SOCKS_PORT
    assert any("direct Psiphon won" in line for line in logs)
    assert "ready" in result
    coordinator.disconnect(quiet=True)


def test_direct_psiphon_first_falls_back_to_warp_chain(tmp_path, monkeypatch):
    coordinator, _store, aether, psiphon, logs = _setup(tmp_path, monkeypatch, psiphon_succeed_on=1)
    settings = C.PowSettings(firewall_profile=C.FIREWALL_MCI, direct_psiphon_first=True)
    coordinator.connect(settings, proxy_mode=True)
    assert aether.started == ["masque"]
    assert psiphon.attempts == 2
    assert not coordinator._direct_psiphon
    assert any("continuing with WARP + Psiphon" in line for line in logs)
    coordinator.disconnect(quiet=True)


# -- 4. Lowest-latency clean IP --------------------------------------------------


def test_lowest_rtt_orders_clean_list(tmp_path, monkeypatch):
    coordinator, store, aether, _psiphon, logs = _setup(tmp_path, monkeypatch)
    (tmp_path / S.CLEAN_H2_FILENAME).write_text(json.dumps({"peers": ["1.1.1.1:443", "2.2.2.2:443", "3.3.3.3:443"]}))
    rtts = {"1.1.1.1:443": 300, "2.2.2.2:443": 90, "3.3.3.3:443": 0}
    monkeypatch.setattr(S, "tcp_rtt_ms", lambda peer, timeout=2.0: rtts[peer])
    monkeypatch.setattr(S, "rank_peers", lambda peers, cap_s=2.0, probe=None: sorted(
        [(p, rtts[p]) for p in peers if rtts.get(p, 0) > 0], key=lambda kv: kv[1]))
    settings = C.PowSettings(firewall_profile=C.FIREWALL_MCI, chain_psiphon=False, lowest_rtt_ip=True)
    coordinator.connect(settings, proxy_mode=True)
    peers = json.loads((tmp_path / S.CLEAN_H2_FILENAME).read_text())["peers"]
    assert peers == ["2.2.2.2:443", "1.1.1.1:443", "3.3.3.3:443"]
    assert any("2.2.2.2:443 (90 ms) goes first" in line for line in logs)
    assert store.clean_pool("net-a").get("2.2.2.2:443") == 90
    coordinator.disconnect(quiet=True)


def test_rank_peers_respects_cap():
    import time

    def probe(peer, cap):
        if peer == "slow":
            time.sleep(1.0)
            return 5
        return 40

    started = time.monotonic()
    ranked = S.rank_peers(["fast", "slow"], cap_s=0.3, probe=probe)
    assert time.monotonic() - started < 0.8
    assert ranked == [("fast", 40)]


def test_accepted_peer_parsing():
    assert S.accepted_peer("Accepted 162.159.199.213:443 (1.0491986s)") == "162.159.199.213:443"
    assert S.accepted_peer("Saved clean HTTP/2 address 162.159.199.95:443") == "162.159.199.95:443"
    assert S.accepted_peer("Accepted [2606:4700:103::1]:443 via HTTP/2") == "[2606:4700:103::1]:443"
    assert S.accepted_peer("Rejected 1.2.3.4:443: tls") == ""


# -- 1. Parallel MASQUE ----------------------------------------------------------


class _Extra:
    def __init__(self, ok=True):
        self.ok = ok
        self.env = None
        self.listen = ""
        self.stopped = 0

    def start(self, outer_json, extra_env=None, tail_core_log=True):
        self.env = extra_env
        self.listen = json.loads(outer_json)["listen"]
        assert tail_core_log is False

    def wait_ready(self, port, budget_ms, stop):
        return self.ok

    def stop(self):
        self.stopped += 1


def test_parallel_masque_off_single_session(tmp_path, monkeypatch):
    coordinator, _store, _aether, _psiphon, _logs = _setup(tmp_path, monkeypatch)
    made: list = []
    monkeypatch.setattr(coordinator, "_make_extra_aether", lambda: made.append(1) or _Extra())
    (tmp_path / S.CLEAN_H2_FILENAME).write_text(json.dumps({"peers": ["1.1.1.1:443", "2.2.2.2:443"]}))
    coordinator.connect(C.PowSettings(firewall_profile=C.FIREWALL_MCI), proxy_mode=True)
    assert made == []
    assert coordinator._router is None
    coordinator.disconnect(quiet=True)


def test_parallel_masque_on_routes_psiphon_through_router(tmp_path, monkeypatch):
    coordinator, _store, _aether, _psiphon, logs = _setup(tmp_path, monkeypatch)
    extras: list[_Extra] = []
    monkeypatch.setattr(coordinator, "_make_extra_aether", lambda: extras.append(_Extra()) or extras[-1])
    configs: list[dict] = []
    original_start = coordinator._psiphon.start
    monkeypatch.setattr(coordinator._psiphon, "start",
                        lambda cfg, d, meek_only=False: (configs.append(json.loads(cfg)), original_start(cfg, d, meek_only))[1])
    started_routers: list = []
    monkeypatch.setattr(S.StickyRouter, "start", lambda self: started_routers.append(self))
    monkeypatch.setattr(S.StickyRouter, "stop", lambda self: None)
    monkeypatch.setattr(S, "harvest_core_log", lambda *a, **k: [])
    (tmp_path / S.CLEAN_H2_FILENAME).write_text(json.dumps({"peers": ["1.1.1.1:443", "2.2.2.2:443", "3.3.3.3:443"]}))
    settings = C.PowSettings(firewall_profile=C.FIREWALL_MCI, parallel_masque=True)
    original_raise = coordinator._raise_outer_leg

    def raise_leg(*a, **k):
        result = original_raise(*a, **k)
        coordinator._won_peer = "1.1.1.1:443"
        return result

    monkeypatch.setattr(coordinator, "_raise_outer_leg", raise_leg)
    coordinator.connect(settings, proxy_mode=True)
    # Psiphon goes through the router from the start; extras join in the background.
    assert configs[-1]["UpstreamProxyURL"] == f"socks5://127.0.0.1:{S.ROUTER_PORT}"
    coordinator._parallel_thread.join(5)
    assert [e.env["AETHER_MASQUE_H2_PEER"] for e in extras] == ["2.2.2.2:443", "3.3.3.3:443"]
    assert [e.listen for e in extras] == [f"127.0.0.1:{p}" for p in S.EXTRA_PORTS]
    assert started_routers[0].upstreams == [C.CHAIN_SOCKS_PORT, *S.EXTRA_PORTS]
    assert any("3 sessions" in line for line in logs)
    assert coordinator.parallel_note == ""
    coordinator.disconnect(quiet=True)
    assert all(e.stopped for e in extras)
    assert coordinator._chain_port == C.CHAIN_SOCKS_PORT


def test_parallel_masque_first_connect_scans_for_a_second_address(tmp_path, monkeypatch):
    coordinator, _store, _aether, _psiphon, logs = _setup(tmp_path, monkeypatch)
    C.identity_path(tmp_path).write_text("key")
    monkeypatch.setattr(S.StickyRouter, "start", lambda self: None)
    monkeypatch.setattr(S.StickyRouter, "stop", lambda self: None)
    monkeypatch.setattr(S, "harvest_core_log", lambda *a, **k: [])
    extras: list[_Extra] = []

    class _Scanner(_Extra):
        def start(self, outer_json, extra_env=None, tail_core_log=True):
            self.env = extra_env
            self.payload = json.loads(outer_json)
            (tmp_path / "parallel" / S.CLEAN_H2_FILENAME).write_text(json.dumps({"peers": ["9.9.9.9:443"]}))

    monkeypatch.setattr(coordinator, "_make_extra_aether", lambda: extras.append(_Scanner()) or extras[-1])
    coordinator.connect(C.PowSettings(firewall_profile=C.FIREWALL_MCI, parallel_masque=True, chain_psiphon=False), proxy_mode=True)
    assert coordinator.exit_port == S.ROUTER_PORT
    coordinator._parallel_thread.join(5)
    assert len(extras) == 1 and extras[0].env is None
    assert extras[0].payload["config_path"].startswith(str(tmp_path / "parallel"))
    assert (tmp_path / "parallel" / "uac-pow.toml").read_text() == "key"
    assert any("scans for one" in line for line in logs)
    assert [s["peer"] for s in coordinator._sessions][1] == "9.9.9.9:443"
    # The main saved list is not touched by the scan session.
    assert not (tmp_path / S.CLEAN_H2_FILENAME).exists()
    coordinator.disconnect(quiet=True)


def test_parallel_masque_reports_reason_when_no_extra(tmp_path, monkeypatch):
    coordinator, _store, _aether, _psiphon, logs = _setup(tmp_path, monkeypatch)
    C.identity_path(tmp_path).write_text("key")
    monkeypatch.setattr(S.StickyRouter, "start", lambda self: None)
    monkeypatch.setattr(S.StickyRouter, "stop", lambda self: None)
    monkeypatch.setattr(S, "harvest_core_log", lambda *a, **k: [])
    monkeypatch.setattr(coordinator, "_make_extra_aether", lambda: _Extra(ok=False))
    coordinator.connect(C.PowSettings(firewall_profile=C.FIREWALL_MCI, parallel_masque=True, chain_psiphon=False), proxy_mode=True)
    coordinator._parallel_thread.join(5)
    assert coordinator.parallel_sessions() == []
    assert "no clean address" in coordinator.parallel_note
    coordinator.disconnect(quiet=True)
    assert coordinator.parallel_note == ""


def test_harvest_core_log(tmp_path):
    (tmp_path / "aether-core.log").write_text(
        "16:35:24  Accepted 162.159.198.130:443 (1.0s)\n"
        "16:35:25  Rejected 1.2.3.4:443: tls\n"
        "16:35:25  Accepted 162.159.199.213:443 (1.0s)\n"
        "16:35:25  Saved clean HTTP/2 address 162.159.199.213:443\n"
    )
    assert S.harvest_core_log(tmp_path) == ["162.159.199.213:443", "162.159.198.130:443"]


def test_forwarder_relay_has_no_idle_timeout():
    from uac_desktop.pow.forwarder import make_long_lived

    a, b = socket.socketpair()
    a.settimeout(10)
    make_long_lived(a, b)
    assert a.gettimeout() is None and b.gettimeout() is None
    assert a.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE)
    a.close(); b.close()


def test_sticky_index_keeps_site_together():
    a = S.sticky_index("i.instagram.com", 3)
    assert a == S.sticky_index("www.instagram.com", 3) == S.sticky_index("instagram.com", 3)
    assert S.sticky_index("x", 1) == 0


def _fake_socks_server(tag: bytes, fail: bool = False):
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(8)

    def _serve():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            try:
                conn.recv(3)
                conn.sendall(b"\x05\x00")
                head = conn.recv(4)
                length = conn.recv(1)[0]
                conn.recv(length + 2)
                if fail:
                    conn.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                    conn.close()
                    continue
                conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                conn.sendall(tag)
                conn.close()
            except OSError:
                pass

    threading.Thread(target=_serve, daemon=True).start()
    return server


def _ask(port: int, host: str) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(b"\x05\x01\x00")
        assert sock.recv(2) == b"\x05\x00"
        name = host.encode()
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + (443).to_bytes(2, "big"))
        reply = sock.recv(10)
        if reply[1] != 0:
            return b"refused"
        data = b""
        while True:
            chunk = sock.recv(64)
            if not chunk:
                return data
            data += chunk


def test_sticky_router_relays_and_fails_over():
    good_a = _fake_socks_server(b"A")
    good_b = _fake_socks_server(b"B", fail=True)
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    router = S.StickyRouter(port, [good_a.getsockname()[1], good_b.getsockname()[1]])
    router.start()
    try:
        hosts = [f"site{i}.example" for i in range(8)]
        answers = {_ask(port, h) for h in hosts}
        # B refuses, so every site ends up on A (failover), never an error.
        assert answers == {b"A"}
        first = _ask(port, "video.example")
        assert first == _ask(port, "video.example") == b"A"
    finally:
        router.stop()
        good_a.close()
        good_b.close()


# -- Home IP card data -------------------------------------------------------------


def test_parse_trace_and_colo():
    info = S.parse_trace("fl=1\nip=104.28.212.7\nts=1\ncolo=FRA\nloc=DE\nwarp=on\n")
    assert info == {"ip": "104.28.212.7", "colo": "FRA", "loc": "DE", "warp": "on"}
    assert S.colo_country("fra") == "DE"
    assert S.colo_country("ZZZ") == ""


def test_parallel_sessions_view(tmp_path, monkeypatch):
    coordinator, _store, aether, _psiphon, _logs = _setup(tmp_path, monkeypatch)
    assert coordinator.parallel_sessions() == []

    class _Proc:
        running = True

    router = S.StickyRouter(0, [C.CHAIN_SOCKS_PORT, 1830, 1831])
    router.counts = [3, 0, 1]
    import time as _t
    router._down = {2: _t.monotonic() + 30}
    coordinator._router = router
    monkeypatch.setattr(type(aether), "running", property(lambda self: True), raising=False)
    coordinator._sessions = [
        {"port": C.CHAIN_SOCKS_PORT, "peer": "a:443", "process": None, "colo": "FRA", "country": "DE"},
        {"port": 1830, "peer": "b:443", "process": _Proc(), "colo": "AMS", "country": "NL"},
        {"port": 1831, "peer": "c:443", "process": _Proc()},
    ]
    view = coordinator.parallel_sessions()
    assert [s["state"] for s in view] == ["up", "standby", "skipped"]
    assert view[0]["main"] and view[0]["country"] == "DE"
    coordinator._router = None
    coordinator._sessions = []


def test_exit_info_falls_back_to_psiphon_region(tmp_path, monkeypatch):
    coordinator, *_ = _setup(tmp_path, monkeypatch)
    coordinator._exit_region = "NL"
    assert coordinator.exit_info == {"country": "NL"}
    coordinator._exit_port = 1821
    monkeypatch.setattr(S, "cf_trace", lambda port, timeout=8.0: {"ip": "9.9.9.9", "loc": "DE", "colo": "FRA"})
    assert coordinator.refresh_exit_info()["ip"] == "9.9.9.9"
    assert coordinator.exit_info["country"] == "DE"
