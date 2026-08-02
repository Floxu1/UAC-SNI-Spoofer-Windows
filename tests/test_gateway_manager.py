import json
import threading
import time

import pytest

from uac_desktop.gateway import (
    ForwardPathHelper,
    GatewayManager,
    LanAdapter,
    ScapyArpBackend,
    TunAdapter,
    WindowsGatewayBackend,
)


class EngineStub:
    def __init__(self, tun_running=False):
        self.running = True
        self.tun_running = tun_running
        self.run_id = 17
        self.enable_calls = []
        self.disable_calls = []

    def enable_tun(self, expected_run_id=None):
        self.enable_calls.append(expected_run_id)
        self.tun_running = True

    def disable_tun(self, expected_run_id=None):
        self.disable_calls.append(expected_run_id)
        self.tun_running = False


class LeaseEngineStub:
    def __init__(self):
        self.running = True
        self.tun_running = False
        self.run_id = 23
        self.acquire_calls = []
        self.release_calls = []

    def acquire_tun(
        self,
        owner=None,
        expected_run_id=None,
        gateway_networks=None,
        gateway_host_addresses=None,
        gateway_interface=None,
    ):
        self.acquire_calls.append((
            owner,
            expected_run_id,
            gateway_networks,
            gateway_host_addresses,
            gateway_interface,
        ))
        self.tun_running = True

    def release_tun(self, owner=None, expected_run_id=None):
        self.release_calls.append((owner, expected_run_id))
        self.tun_running = False


class WindowsStub:
    def __init__(self):
        self.lan = LanAdapter(
            index=12,
            alias="Wi-Fi",
            address="192.168.70.151",
            prefix=24,
            gateway="192.168.70.1",
            mac="10:20:30:40:50:60",
            description="Wireless Adapter",
        )
        self.tun = TunAdapter(index=100, alias="UAC-Spoofer")
        self.apply_calls = []
        self.restore_calls = []
        self.apply_error = None
        self.restore_error = None

    def wait_for_tun(self, alias, timeout=12):
        assert alias == self.tun.alias
        return self.tun

    def detect_lan(self, excluded_aliases=None):
        assert self.tun.alias in set(excluded_aliases or ())
        return self.lan

    def neighbors(self, interface_index):
        assert interface_index == self.lan.index
        return {
            self.lan.gateway: "aa:bb:cc:dd:ee:01",
            "192.168.70.152": "aa:bb:cc:dd:ee:52",
        }

    def snapshot(self, lan, tun):
        assert lan == self.lan
        assert tun == self.tun
        return {
            "ip_enable_router": {"exists": True, "value": 0},
            "interfaces": {
                str(lan.index): {
                    "forwarding": False,
                    "weak_host_send": False,
                    "weak_host_receive": False,
                },
                str(tun.index): {
                    "forwarding": False,
                    "weak_host_send": False,
                    "weak_host_receive": False,
                },
            },
        }

    def apply(self, state):
        self.apply_calls.append(dict(state))
        if self.apply_error is not None:
            raise self.apply_error

    def restore(self, state):
        self.restore_calls.append(dict(state))
        if self.restore_error is not None:
            raise self.restore_error


class ArpStub:
    def __init__(self):
        self.redirect_calls = []
        self.restore_calls = []
        self.discover_calls = []

    def interface_for(self, address):
        assert address == "192.168.70.151"
        return {"name": "npcap-wifi", "mac": "10:20:30:40:50:60"}

    def resolve(self, address, interface_name):
        assert address == "192.168.70.1"
        assert interface_name == "npcap-wifi"
        return "aa:bb:cc:dd:ee:01"

    def discover(self, lan, interface_name):
        self.discover_calls.append((lan, interface_name))
        return {
            "192.168.70.152": "aa:bb:cc:dd:ee:52",
            "192.168.70.153": "aa:bb:cc:dd:ee:53",
        }

    def redirect(self, state, devices):
        self.redirect_calls.append((dict(state), dict(devices)))

    def restore(self, state):
        self.restore_calls.append(dict(state))


class ForwarderStub:
    resolver = "1.1.1.1"
    tcp_mss = 1280
    block_quic = True

    def __init__(self):
        self.start_calls = []
        self.stop_calls = 0
        self.device_calls = []

    def start(self, lan, devices):
        self.start_calls.append((lan, dict(devices)))

    def stop(self):
        self.stop_calls += 1
        return True

    def set_devices(self, devices):
        self.device_calls.append(dict(devices))


def make_manager(tmp_path, engine=None, windows=None, arp=None, **kwargs):
    forwarder = kwargs.pop("forwarder", None) or ForwarderStub()
    manager = GatewayManager(
        engine=engine or EngineStub(),
        state_file=tmp_path / "gateway-state.json",
        windows=windows or WindowsStub(),
        arp=arp or ArpStub(),
        forwarder=forwarder,
        poll_interval=60,
        discovery_interval=60,
        watchdog_launcher=kwargs.pop("watchdog_launcher", lambda _state: None),
        **kwargs,
    )
    manager._socks_ready = lambda: True
    return manager


class PacketTransport:
    def __init__(self, tcp=False, syn=False, mss=1460):
        self.syn = syn
        if tcp:
            raw = bytearray(24)
            raw[12] = 0x60
            raw[20:24] = bytes((2, 4)) + int(mss).to_bytes(2, "big")
            self.raw = memoryview(raw)
            self.header_len = 24


class PacketStub:
    def __init__(
        self,
        source,
        destination,
        source_port,
        destination_port,
        protocol="udp",
        syn=False,
        mss=1460,
    ):
        self.src_addr = source
        self.dst_addr = destination
        self.src_port = source_port
        self.dst_port = destination_port
        self.tcp = PacketTransport(True, syn, mss) if protocol == "tcp" else None
        self.udp = PacketTransport() if protocol == "udp" else None


def configured_forwarder(**kwargs):
    helper = ForwardPathHelper(**kwargs)
    helper.configure(
        LanAdapter(
            index=12,
            alias="Wi-Fi",
            address="192.168.70.151",
            prefix=24,
            gateway="192.168.70.1",
        ),
        {"192.168.70.136": "aa:bb:cc:dd:ee:01"},
    )
    return helper


def test_gateway_default_forwarder_leaves_dns_to_singbox(
        tmp_path):
    manager = GatewayManager(
        state_file=tmp_path / "gateway.json",
        watchdog_launcher=lambda _state: None,
    )

    assert manager.forwarder.rewrite_dns is False


def test_start_stop_round_trip_is_idempotent(tmp_path):
    engine = EngineStub()
    windows = WindowsStub()
    arp = ArpStub()
    launched = []
    manager = make_manager(
        tmp_path,
        engine=engine,
        windows=windows,
        arp=arp,
        watchdog_launcher=lambda state: launched.append(dict(state)),
    )

    state = manager.start()

    assert manager.active is True
    assert state["status"] == "active"
    assert state["tun_runtime"] == "owned"
    assert state["devices"] == {
        "192.168.70.152": "aa:bb:cc:dd:ee:52",
    }
    deadline = time.monotonic() + 1
    while "192.168.70.153" not in manager.devices and time.monotonic() < deadline:
        time.sleep(0.01)
    assert manager.devices["192.168.70.153"] == "aa:bb:cc:dd:ee:53"
    assert engine.enable_calls == [17]
    assert len(windows.apply_calls) == 1
    assert len(arp.redirect_calls) >= 1
    assert len(launched) == 1
    assert manager.state_file.exists()

    assert manager.stop() is True
    assert manager.active is False
    assert engine.disable_calls == [17]
    assert len(windows.restore_calls) == 1
    assert len(arp.restore_calls) == 1
    assert not manager.state_file.exists()
    assert manager.stop() is False


def test_existing_tun_is_borrowed_and_left_running(tmp_path):
    engine = EngineStub(tun_running=True)
    manager = make_manager(tmp_path, engine=engine)

    state = manager.start()
    assert state["tun_runtime"] == "borrowed"
    assert engine.enable_calls == []

    assert manager.stop() is True
    assert engine.disable_calls == []
    assert engine.tun_running is True


def test_tun_lease_is_released(tmp_path):
    engine = LeaseEngineStub()
    manager = make_manager(tmp_path, engine=engine)

    state = manager.start()
    assert state["tun_runtime"] == "lease"
    assert engine.acquire_calls == [
        (
            "gateway",
            23,
            ["192.168.70.0/24"],
            ["192.168.70.151"],
            "Wi-Fi",
        ),
    ]

    assert manager.stop() is True
    assert engine.release_calls == [("gateway", 23)]


def test_start_failure_restores_state_and_owned_tun(tmp_path):
    engine = EngineStub()
    windows = WindowsStub()
    arp = ArpStub()
    windows.apply_error = RuntimeError("apply failed")
    manager = make_manager(tmp_path, engine=engine, windows=windows, arp=arp)

    with pytest.raises(RuntimeError, match="apply failed"):
        manager.start()

    assert manager.active is False
    assert engine.disable_calls == [17]
    assert len(windows.restore_calls) == 1
    assert len(arp.restore_calls) == 1
    assert not manager.state_file.exists()


def test_recover_restores_dead_owner_once(tmp_path):
    windows = WindowsStub()
    arp = ArpStub()
    manager = make_manager(
        tmp_path,
        windows=windows,
        arp=arp,
        process_alive=lambda _pid, _created: False,
    )
    state = fixture_state(windows)
    manager.state_file.write_text(json.dumps(state), encoding="utf-8")

    assert manager.recover() is True
    assert len(windows.restore_calls) == 1
    assert len(arp.restore_calls) == 1
    assert not manager.state_file.exists()

    assert manager.recover() is True
    assert len(windows.restore_calls) == 1
    assert len(arp.restore_calls) == 1


def test_recover_does_not_touch_live_owner(tmp_path):
    windows = WindowsStub()
    arp = ArpStub()
    manager = make_manager(
        tmp_path,
        windows=windows,
        arp=arp,
        process_alive=lambda _pid, _created: True,
    )
    manager.state_file.write_text(json.dumps(fixture_state(windows)), encoding="utf-8")

    assert manager.recover() is False
    assert windows.restore_calls == []
    assert arp.restore_calls == []
    assert manager.state_file.exists()


def test_failed_recovery_keeps_atomic_restore_record(tmp_path):
    windows = WindowsStub()
    windows.restore_error = RuntimeError("restore failed")
    manager = make_manager(
        tmp_path,
        windows=windows,
        process_alive=lambda _pid, _created: False,
    )
    manager.state_file.write_text(json.dumps(fixture_state(windows)), encoding="utf-8")

    assert manager.recover() is False
    pending = json.loads(manager.state_file.read_text(encoding="utf-8"))
    assert pending["status"] == "restore-pending"
    assert pending["restore_errors"] == ["Windows restore: restore failed"]
    assert not list(tmp_path.glob("*.tmp"))


def test_recovery_treats_arp_refresh_as_best_effort(tmp_path):
    class MissingNpcapArp(ArpStub):
        def restore(self, state):
            raise RuntimeError("Npcap unavailable")

    windows = WindowsStub()
    manager = make_manager(
        tmp_path,
        windows=windows,
        arp=MissingNpcapArp(),
        process_alive=lambda _pid, _created: False,
    )
    manager.state_file.write_text(
        json.dumps(fixture_state(windows)),
        encoding="utf-8",
    )

    assert manager.recover() is True
    assert len(windows.restore_calls) == 1
    assert not manager.state_file.exists()


def test_watchdog_recovers_after_owner_exits(tmp_path):
    windows = WindowsStub()
    arp = ArpStub()
    manager = make_manager(
        tmp_path,
        windows=windows,
        arp=arp,
        process_alive=lambda _pid, _created: False,
    )
    state = fixture_state(windows)
    manager.state_file.write_text(json.dumps(state), encoding="utf-8")

    result = GatewayManager.run_watchdog(
        parent_pid=901,
        parent_create_time=123.5,
        token=state["token"],
        state_file=manager.state_file,
        process_alive=lambda _pid, _created: False,
        manager_factory=lambda: manager,
        poll_interval=0.01,
    )

    assert result == 0
    assert not manager.state_file.exists()
    assert len(windows.restore_calls) == 1
    assert len(arp.restore_calls) == 1


def test_scapy_backend_remains_lazy_until_network_action():
    backend = ScapyArpBackend()
    assert backend._api is None


def test_scapy_backend_extracts_dhcp_hostname_identity():
    class FakeDhcp:
        pass

    class FakeBootp:
        pass

    class FakeIp:
        pass

    class FakeEther:
        pass

    dhcp = FakeDhcp()
    dhcp.options = [
        ("message-type", 3),
        ("hostname", b"Rayane-Phone"),
        ("requested_addr", "192.168.70.136"),
        "end",
    ]
    bootp = FakeBootp()
    bootp.ciaddr = "0.0.0.0"
    bootp.yiaddr = "0.0.0.0"
    bootp.chaddr = bytes.fromhex("9c9ed5936383") + (b"\x00" * 10)
    ip_layer = FakeIp()
    ip_layer.src = "0.0.0.0"
    ethernet = FakeEther()
    ethernet.src = "9c:9e:d5:93:63:83"
    layers = {
        FakeDhcp: dhcp,
        FakeBootp: bootp,
        FakeIp: ip_layer,
        FakeEther: ethernet,
    }

    class FakePacket:
        def getlayer(self, layer):
            return layers.get(layer)

    identity = ScapyArpBackend._dhcp_identity(
        FakePacket(),
        {
            "DHCP": FakeDhcp,
            "BOOTP": FakeBootp,
            "IP": FakeIp,
            "Ether": FakeEther,
        },
    )

    assert identity == (
        "192.168.70.136",
        "9c:9e:d5:93:63:83",
        "Rayane-Phone",
    )


def test_scapy_responder_reports_valid_lan_device_immediately():
    captured = {}
    sent = []

    class FakeArp:
        def __init__(self, **values):
            for name, value in values.items():
                setattr(self, name, value)

    class FakeEther:
        def __init__(self, **values):
            self.values = values

        def __truediv__(self, other):
            return self, other

    class FakeSniffer:
        def __init__(self, **values):
            captured.update(values)

        def start(self):
            captured["started"] = True

        def stop(self, join=True):
            captured["stopped"] = join

    class FakePacket:
        def __init__(self, arp):
            self.arp = arp

        def getlayer(self, layer):
            return self.arp if layer is FakeArp else None

    backend = ScapyArpBackend()
    backend._api = {
        "ARP": FakeArp,
        "Ether": FakeEther,
        "AsyncSniffer": FakeSniffer,
        "sendp": lambda packet, **values: sent.append((packet, values)),
    }
    seen = []
    state = {
        "lan": {
            "address": "192.168.70.151",
            "prefix": 24,
            "gateway": "192.168.70.1",
        },
        "capture": {
            "name": "npcap-wifi",
            "mac": "10:20:30:40:50:60",
        },
    }

    backend.start_responder(
        state,
        device_seen=lambda address, mac: seen.append((address, mac)),
    )
    captured["prn"](FakePacket(FakeArp(
        op=1,
        psrc="192.168.70.136",
        pdst="192.168.70.1",
        hwsrc="aa:bb:cc:dd:ee:36",
    )))

    assert seen == [("192.168.70.136", "aa:bb:cc:dd:ee:36")]
    assert len(sent) == 1
    backend.stop_responder()


def test_start_uses_cache_and_runs_slow_scan_in_background(tmp_path):
    entered = threading.Event()
    release = threading.Event()

    class SlowArp(ArpStub):
        def discover(self, lan, interface_name):
            entered.set()
            release.wait(2)
            return {"192.168.70.153": "aa:bb:cc:dd:ee:53"}

    manager = make_manager(tmp_path, arp=SlowArp())
    started = time.monotonic()
    state = manager.start()
    elapsed = time.monotonic() - started

    assert elapsed < 0.5
    assert state["devices"] == {
        "192.168.70.152": "aa:bb:cc:dd:ee:52",
    }
    assert entered.wait(1)

    release.set()
    deadline = time.monotonic() + 1
    while "192.168.70.153" not in manager.devices and time.monotonic() < deadline:
        time.sleep(0.01)
    assert manager.devices["192.168.70.153"] == "aa:bb:cc:dd:ee:53"
    manager.stop()


def test_passive_device_event_updates_runtime_and_redirects_target(tmp_path):
    class PassiveArp(ArpStub):
        def __init__(self):
            super().__init__()
            self.device_seen = None

        def start_responder(self, state, device_seen=None):
            self.device_seen = device_seen

    arp = PassiveArp()
    forwarder = ForwarderStub()
    changed = []
    manager = make_manager(tmp_path, arp=arp, forwarder=forwarder)
    manager.devices_changed = lambda devices: changed.append(dict(devices))
    manager.start()

    assert callable(arp.device_seen)
    assert arp.device_seen(
        "192.168.70.136",
        "aa:bb:cc:dd:ee:36",
    ) is True
    assert manager.devices["192.168.70.136"] == "aa:bb:cc:dd:ee:36"
    assert forwarder.device_calls[-1] == manager.devices
    assert {
        "192.168.70.136": "aa:bb:cc:dd:ee:36",
    } in [devices for _state, devices in arp.redirect_calls]
    assert changed[-1] == manager.devices
    assert json.loads(manager.state_file.read_text(encoding="utf-8"))["devices"] == manager.devices
    manager.stop()


@pytest.mark.parametrize("protocol", ["udp", "tcp"])
def test_forward_path_rewrites_router_dns_and_restores_response_source(protocol):
    helper = configured_forwarder(rewrite_dns=True)
    query = PacketStub(
        "192.168.70.136",
        "192.168.70.1",
        53001,
        53,
        protocol,
        syn=protocol == "tcp",
    )

    assert helper.process_packet(query) is True
    assert query.dst_addr == "1.1.1.1"

    response = PacketStub(
        "1.1.1.1",
        "192.168.70.136",
        53,
        53001,
        protocol,
        syn=protocol == "tcp",
    )

    assert helper.process_packet(response) is True
    assert response.src_addr == "192.168.70.1"


def test_forward_path_leaves_public_and_local_lan_dns_unchanged():
    helper = configured_forwarder()
    public_query = PacketStub(
        "192.168.70.136",
        "8.8.8.8",
        53002,
        53,
    )
    local_query = PacketStub(
        "192.168.70.136",
        "192.168.70.10",
        53003,
        53,
    )

    assert helper.process_packet(public_query) is True
    assert helper.process_packet(local_query) is True
    assert public_query.dst_addr == "8.8.8.8"
    assert local_query.dst_addr == "192.168.70.10"


def test_forward_path_clamps_external_tcp_syn_mss():
    helper = configured_forwarder(tcp_mss=1280)
    packet = PacketStub(
        "192.168.70.136",
        "142.250.185.110",
        54000,
        443,
        "tcp",
        syn=True,
        mss=1460,
    )

    assert helper.process_packet(packet) is True
    assert int.from_bytes(packet.tcp.raw[22:24], "big") == 1280


def test_forward_path_drops_only_external_client_quic():
    helper = configured_forwarder(block_quic=True)
    external = PacketStub(
        "192.168.70.136",
        "142.250.185.110",
        55000,
        443,
    )
    local = PacketStub(
        "192.168.70.136",
        "192.168.70.10",
        55001,
        443,
    )

    assert helper.process_packet(external) is False
    assert helper.process_packet(local) is True


def test_forward_path_default_reinjects_quic_for_fast_tun_reject():
    helper = configured_forwarder()
    packet = PacketStub(
        "192.168.70.136",
        "142.250.185.110",
        55000,
        443,
    )

    assert helper.process_packet(packet) is True


def test_forward_path_default_filter_avoids_reprocessing_dns():
    filters = []
    marker = object()
    helper = ForwardPathHelper(
        divert_factory=lambda packet_filter: filters.append(packet_filter) or marker,
    )

    assert helper._new_handle() is marker
    assert filters == ["ip and !impostor and tcp and tcp.Syn"]

    filters.clear()
    helper = ForwardPathHelper(
        rewrite_dns=True,
        divert_factory=lambda packet_filter: filters.append(packet_filter) or marker,
    )

    assert helper._new_handle() is marker
    assert "udp.DstPort == 53" in filters[0]
    assert "!impostor" in filters[0]


def test_device_discovery_runs_in_background(tmp_path):
    manager = make_manager(tmp_path)
    manager.start()
    deadline = time.monotonic() + 1
    while manager._discovery_worker is not None and time.monotonic() < deadline:
        time.sleep(0.01)
    entered = threading.Event()
    release = threading.Event()

    def slow_refresh():
        entered.set()
        release.wait(2)
        return True

    manager._refresh_devices = slow_refresh

    assert manager._start_device_refresh() is True
    assert entered.wait(1)
    assert manager._start_device_refresh() is False
    assert manager.active is True

    release.set()
    worker = manager._discovery_worker
    if worker is not None:
        worker.join(1)
    assert manager._discovery_worker is None
    manager.stop()


def test_transient_empty_discovery_keeps_known_devices(tmp_path):
    windows = WindowsStub()
    arp = ArpStub()
    manager = make_manager(tmp_path, windows=windows, arp=arp)
    manager.start()
    expected = manager.devices
    windows.neighbors = lambda _index: {
        windows.lan.gateway: "aa:bb:cc:dd:ee:01",
    }
    arp.discover = lambda _lan, _interface: {}

    assert manager._refresh_devices() is True
    assert manager.devices == expected

    manager.stop()


def test_native_neighbor_discovery_fills_empty_npcap_scan(tmp_path):
    class NativeWindows(WindowsStub):
        def discover_neighbors(self, lan):
            assert lan == self.lan
            return {"192.168.70.136": "aa:bb:cc:dd:ee:36"}

    class EmptyArp(ArpStub):
        def discover(self, lan, interface_name):
            self.discover_calls.append((lan, interface_name))
            return {}

    windows = NativeWindows()
    manager = make_manager(tmp_path, windows=windows, arp=EmptyArp())

    state = manager.start()

    assert "192.168.70.136" not in state["devices"]
    deadline = time.monotonic() + 1
    while "192.168.70.136" not in manager.devices and time.monotonic() < deadline:
        time.sleep(0.01)
    assert manager.devices["192.168.70.136"] == "aa:bb:cc:dd:ee:36"
    manager.stop()


def test_forward_path_start_timeout_does_not_report_running():
    class SlowHandle:
        is_open = False

        def open(self):
            time.sleep(0.15)
            self.is_open = True

        def close(self):
            self.is_open = False

        def recv(self):
            raise StopIteration

        def send(self, _packet):
            return None

    helper = ForwardPathHelper(divert_factory=lambda _filter: SlowHandle())
    lan = LanAdapter(
        index=12,
        alias="Wi-Fi",
        address="192.168.70.151",
        prefix=24,
        gateway="192.168.70.1",
    )

    with pytest.raises(RuntimeError, match="startup timed out"):
        helper.start(lan, timeout=0.05)
    assert helper.running is False


def test_active_state_read_does_not_wait_for_lifecycle_lock(tmp_path):
    manager = make_manager(tmp_path)
    manager._active = True
    locked = threading.Event()
    release = threading.Event()
    result = []

    def hold_lock():
        with manager._lock:
            locked.set()
            release.wait(2)

    def read_active():
        result.append(manager.active)

    holder = threading.Thread(target=hold_lock)
    holder.start()
    assert locked.wait(1)
    reader = threading.Thread(target=read_active)
    reader.start()
    reader.join(0.2)
    release.set()
    holder.join(1)
    reader.join(1)

    assert result == [True]


def test_cancelled_start_releases_tun_before_windows_changes(tmp_path):
    cancel = threading.Event()

    class CancellingWindows(WindowsStub):
        def wait_for_tun(self, alias, timeout=12):
            value = super().wait_for_tun(alias, timeout)
            cancel.set()
            return value

    engine = EngineStub()
    windows = CancellingWindows()
    manager = make_manager(tmp_path, engine=engine, windows=windows)

    with pytest.raises(RuntimeError, match="cancelled"):
        manager.start(cancel_event=cancel)

    assert engine.enable_calls == [17]
    assert engine.disable_calls == [17]
    assert windows.apply_calls == []
    assert manager.active is False
    assert not manager.state_file.exists()


def test_windows_detection_parses_generic_adapter_without_windows():
    class Runner:
        def run(self, script, timeout=20):
            assert "Get-NetIPConfiguration" in script
            return json.dumps(
                {
                    "index": 31,
                    "alias": "Ethernet 7",
                    "address": "10.44.8.19",
                    "prefix": 23,
                    "gateway": "10.44.8.1",
                    "mac": "AA-BB-CC-DD-EE-FF",
                    "description": "Generic NIC",
                }
            )

    adapter = WindowsGatewayBackend(Runner()).detect_lan({"UAC-Spoofer"})

    assert adapter == LanAdapter(
        index=31,
        alias="Ethernet 7",
        address="10.44.8.19",
        prefix=23,
        gateway="10.44.8.1",
        mac="aa:bb:cc:dd:ee:ff",
        description="Generic NIC",
    )


def test_wait_for_tun_treats_missing_adapter_as_retryable():
    class Runner:
        def __init__(self):
            self.calls = 0

        def run(self, script, timeout=20):
            self.calls += 1
            assert "exit 0" in script
            if self.calls == 1:
                return ""
            return '{"index":44,"alias":"UAC-Spoofer"}'

    runner = Runner()
    tun = WindowsGatewayBackend(runner).wait_for_tun(
        "UAC-Spoofer",
        timeout=1,
    )

    assert tun == TunAdapter(index=44, alias="UAC-Spoofer")
    assert runner.calls == 2


def test_windows_gateway_apply_uses_forwarding_fallback_without_winnat():
    class Runner:
        def __init__(self):
            self.script = ""

        def run(self, script, timeout=30):
            self.script = script
            return '{"warnings":[]}'

    runner = Runner()
    backend = WindowsGatewayBackend(runner)
    backend.apply({
        "lan": {"index": 31, "alias": "Ethernet 7"},
        "tun": {"index": 44, "alias": "UAC-Spoofer"},
        "firewall_rule": "UAC Spoofer Mobile Gateway test",
    })

    assert "-Forwarding Enabled" in runner.script
    assert "netsh.exe" in runner.script
    assert "forwarding=enabled" in runner.script
    assert "weakhostsend=enabled" in runner.script
    assert "weakhostreceive=enabled" in runner.script
    assert "New-NetNat" not in runner.script
    assert "Get-NetNat" not in runner.script


def test_windows_gateway_restore_has_forwarding_fallback_without_winnat():
    class Runner:
        def __init__(self):
            self.script = ""

        def run(self, script, timeout=30):
            self.script = script
            return ""

    runner = Runner()
    backend = WindowsGatewayBackend(runner)
    backend.restore({
        "firewall_rule": "UAC Spoofer Mobile Gateway test",
        "windows": {
            "interfaces": [{
                "index": 31,
                "forwarding": "Disabled",
                "weak_send": "Disabled",
                "weak_receive": "Disabled",
            }],
            "ip_router": {"exists": True, "value": 0},
        },
    })

    assert "forwarding=$mode" in runner.script
    assert "weakhostsend=$mode" in runner.script
    assert "weakhostreceive=$mode" in runner.script
    assert "New-NetNat" not in runner.script
    assert "Get-NetNat" not in runner.script


def fixture_state(windows):
    return {
        "version": 1,
        "token": "state-token",
        "owner": {"pid": 901, "create_time": 123.5},
        "status": "active",
        "lan": {
            "index": windows.lan.index,
            "alias": windows.lan.alias,
            "address": windows.lan.address,
            "prefix": windows.lan.prefix,
            "gateway": windows.lan.gateway,
            "mac": windows.lan.mac,
            "description": windows.lan.description,
        },
        "tun": {"index": windows.tun.index, "alias": windows.tun.alias},
        "tun_runtime": "borrowed",
        "capture": {"name": "npcap-wifi", "mac": windows.lan.mac},
        "gateway_mac": "aa:bb:cc:dd:ee:01",
        "devices": {"192.168.70.152": "aa:bb:cc:dd:ee:52"},
        "firewall_rule": "UAC Spoofer Mobile Gateway state-token",
        "windows": windows.snapshot(windows.lan, windows.tun),
    }
