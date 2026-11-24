import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import threading
import time
from types import SimpleNamespace

from uac_desktop import ui
from uac_desktop.models import ProxyProfile


def _p(pid, cc, ping=0.0, ok=False):
    return ProxyProfile(id=pid, name=pid, country_code=cc, last_ping_ms=ping, last_ping_ok=ok, origin="sni-maker")


def test_rank_fastest_first_region_breaks_ties():
    us, de, tr = _p("us", "US"), _p("de", "DE"), _p("tr", "TR")
    m = {"us": {"ok": True, "ms": 120}, "de": {"ok": True, "ms": 130}, "tr": {"ok": True, "ms": 450}}
    assert [p.id for p in ui.auto_latency_rank([tr, us, de], m)] == ["de", "us", "tr"]  # same 80ms bucket -> nearer wins
    m2 = {"us": {"ok": True, "ms": 90}, "de": {"ok": True, "ms": 700}}
    assert ui.auto_latency_rank([de, us], m2)[0].id == "us"  # clearly faster wins over region


def test_failures_last_untested_use_last_test_ping():
    a, b, c = _p("a", "DE", 900, True), _p("b", "NL", 300, True), _p("c", "TR")
    order = ui.auto_latency_rank([a, b, c], {"c": {"ok": False, "ms": 0}})
    assert [p.id for p in order] == ["b", "a", "c"]


def test_auto_order_probes_when_stale_and_never_touches_profiles():
    profiles = [_p("far", "JP", 1500, True), _p("near", "TR", 1600, True), _p("mid", "DE", 1700, True)]
    snapshot = [(p.last_ping_ms, p.last_ping_ok, p.method) for p in profiles]
    logs = []; saved = []
    stub = SimpleNamespace(
        storage=SimpleNamespace(settings={}, save_settings=lambda: saved.append(1)),
        engine=SimpleNamespace(running=False),
        bridge=SimpleNamespace(log=SimpleNamespace(emit=logs.append), latency=SimpleNamespace(emit=lambda *a: None)),
        _auto_probe_fn=lambda pool, cancel: {"far": (True, 900.0), "near": (True, 210.0), "mid": (False, 0.0)},
    )
    stub._auto_probe = lambda pool, cancel: ui.MainWindow._auto_probe(stub, pool, cancel)
    order = ui.MainWindow._auto_latency_order(stub, profiles, threading.Event())
    assert [p.id for p in order] == ["near", "far", "mid"]
    assert [(p.last_ping_ms, p.last_ping_ok, p.method) for p in profiles] == snapshot
    assert saved and stub.storage.settings[ui.AUTO_LATENCY_KEY]["near"]["ms"] == 210.0
    assert any("AUTO PICK #1" in line and "210 ms" in line for line in logs)
    # fresh values reused: no second probe
    stub._auto_probe_fn = lambda *a: (_ for _ in ()).throw(AssertionError("should not probe"))
    stub.storage.settings[ui.AUTO_LATENCY_KEY]["mid"] = {"ok": True, "ms": 300.0, "at": time.time()}
    assert ui.MainWindow._auto_latency_order(stub, profiles, threading.Event())[0].id == "near"
