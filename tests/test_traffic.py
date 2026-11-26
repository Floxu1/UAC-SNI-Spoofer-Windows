import io
import json
from types import SimpleNamespace

from PySide6.QtWidgets import QApplication

from uac_desktop import traffic
from uac_desktop import network_metrics
from uac_desktop.pow.coordinator import PowCoordinator
from uac_desktop.pow.psiphon import PsiphonProcess
from uac_desktop.pow.runner import AetherProcess


def test_xray_statistics_include_each_client_inbound_once(monkeypatch):
    stats = {"socks-in": (10, 500), "http-in": (2000, 20),
             "traffic-stats": (10000, 10000), "probe-socks-in": (5000, 6000)}
    items = [{"name": f"inbound>>>{tag}>>>traffic>>>{direction}", "value": value}
             for tag, counts in stats.items()
             for direction, value in zip(("uplink", "downlink"), counts)]
    monkeypatch.setattr(traffic.subprocess, "run", lambda *_a, **_kw: SimpleNamespace(
        returncode=0, stdout=json.dumps({"stat": items}),
    ))
    assert traffic.xray_traffic("xray.exe", 49152) == (2010, 520)


def test_probe_inbound_keeps_dns_dispatch_but_is_not_a_user_inbound():
    config = {"inbounds": [{"tag": "socks-in", "protocol": "socks"}],
              "routing": {"rules": [{"inboundTag": ["socks-in"], "port": "53"}]}}
    traffic.enable_xray_traffic(config, 49152, probe_socks=49153)
    assert config["api"]["listen"] == "127.0.0.1:49152"
    assert config["inbounds"][-1] == {"tag": "probe-socks-in", "protocol": "socks", "port": 49153}
    assert config["routing"]["rules"][0]["inboundTag"] == ["socks-in", "probe-socks-in"]


def test_session_traffic_keeps_independent_deltas_across_resets_and_path_changes():
    meter = traffic.SessionTraffic()
    assert meter.update({1: (100, 50), 2: (40, 600)}) == (0, 0)
    assert meter.update({1: (110, 500), 2: (40, 600)}) == (10, 450)
    assert meter.update({1: (1, 520), 2: (70, 600)}) == (40, 470)
    assert meter.update({1: (31, 520), 3: (1000, 1000)}) == (70, 470)
    assert meter.update({3: (1000, 2000)}) == (70, 1470)
    meter.reset()
    assert meter.update({3: (1000, 2000)}) == (0, 0)


def test_hud_displays_totals_and_samples_each_direction(monkeypatch):
    app = QApplication.instance() or QApplication([])
    hud = network_metrics.SharedNetworkMetrics(lambda _fa, en: en, lambda: False)
    up, down = [], []
    monkeypatch.setattr(hud.up_bars, "add_rate", up.append)
    monkeypatch.setattr(hud.down_bars, "add_rate", down.append)
    clock = iter((0.0, 1.0, 2.0))
    monkeypatch.setattr(network_metrics, "time", SimpleNamespace(monotonic=lambda: next(clock)))
    hud.set_traffic(0, 0)
    hud.set_traffic(0, 1024)
    assert up == [0] and down == [1024]
    hud.set_traffic(4096, 1024)
    assert up == [0, 4096] and down == [1024, 0]
    assert hud.upload.value.text() == "4.0 KB"
    assert hud.download.value.text() == "1.0 KB"
    hud.deleteLater()
    app.processEvents()


def test_pow_uses_terminal_leg_and_reads_each_native_notice_in_its_own_units():
    inner = PsiphonProcess()
    psiphon = object()
    inner._process = psiphon
    for sent, received in ((10, 50), (100, 0), (0, 200)):
        inner._handle_notice_line(json.dumps({"noticeType": "BytesTransferred",
                                              "data": {"sent": sent, "received": received}}), source=psiphon)
    inner._handle_notice_line('{"noticeType":"TotalBytesTransferred","data":{"sent":110,"received":250}}')
    inner._handle_notice_line('{"noticeType":"BytesTransferred","data":{"sent":5000}}', source=object())

    outer = AetherProcess()
    class Process:
        pass

    aether = Process()
    aether.stderr = io.StringIO(
        'AETHER_EVENT {"type":"traffic","tx":170,"rx":310}\n'
        'AETHER_EVENT {"type":"traffic","tx":260,"rx":440}\n'
    )
    outer._process = aether
    outer._drain(aether)
    coordinator = SimpleNamespace(_warp_only=False, _aether=outer, _psiphon=inner,
                                  _psiphon_secondary=None, _psiphon_ghost=None)
    assert PowCoordinator.traffic_sources(coordinator) == {psiphon: (110, 250)}
    coordinator._warp_only = True
    assert PowCoordinator.traffic_sources(coordinator) == {aether: (260, 440)}
