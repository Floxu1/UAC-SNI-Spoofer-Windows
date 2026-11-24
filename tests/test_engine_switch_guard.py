import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from types import SimpleNamespace

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from uac_desktop import ui
from uac_desktop.engine_switch_guard import EngineSwitchGuard
from uac_desktop.pow_ui import ENGINE_POW, ENGINE_XRAY

APP = QApplication.instance() or QApplication([])


def test_switch_blocked_while_connected_and_toggle_snaps_back():
    synced = []
    stub = SimpleNamespace(_engine_switching=False, engine_mode=ENGINE_XRAY,
                           _engine_busy=lambda: True, _confirm_engine_switch=lambda: False,
                           _sync_engine_switch=lambda: synced.append(1),
                           _switch_engine_now=lambda *a, **k: (_ for _ in ()).throw(AssertionError("switched")))
    stub._restore_engine_switch_look = lambda: synced.append(1)
    stub._disconnect_then_switch = lambda: (_ for _ in ()).throw(AssertionError("switched"))
    stub._guarded_switch = lambda: ui.MainWindow._guarded_switch(stub)
    ui.MainWindow._switch_engine(stub)
    for _ in range(5):
        APP.processEvents()
    assert stub.engine_mode == ENGINE_XRAY and synced == [1]


def test_busy_detection():
    s = SimpleNamespace(pow_controller=SimpleNamespace(busy=False), engine=SimpleNamespace(running=False), connecting=False)
    assert not ui.MainWindow._engine_busy(s)
    s.connecting = True
    assert ui.MainWindow._engine_busy(s)
    s.connecting = False; s.pow_controller.busy = True
    assert ui.MainWindow._engine_busy(s)


def test_guard_dialog_fa_rtl_texts():
    d = EngineSwitchGuard(None, "fa")
    assert d.layoutDirection() == Qt.RightToLeft
    assert "اول اتصال رو قطع کن" in d.title.text() and d.go_btn.text() == "قطع و سوییچ" and d.cancel_btn.text() == "باشه"
    assert EngineSwitchGuard(None, "en").go_btn.text() == "Disconnect & switch"


import pytest


@pytest.fixture()
def window(tmp_path, monkeypatch):
    monkeypatch.setattr(ui, "DATA_DIR", tmp_path / "data")
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    from uac_desktop import paths, storage
    import uac_desktop.pow_ui as pow_ui
    monkeypatch.setattr(paths, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(pow_ui, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(storage, "SETTINGS_FILE", tmp_path / "data" / "settings.json")
    yield ui.MainWindow()


def test_route_card_reset_on_engine_switch_never_leaks(window):
    w = window
    w.engine_mode = ENGINE_XRAY
    w.route_card.set_secondary("old Xray endpoint")
    w.network_metrics.set_latency(6058)
    w.ip_label.setText("1.2.3.4")
    w.engine_mode = ENGINE_POW
    w._reset_engine_cards()
    assert "old Xray endpoint" not in w.route_card.toolTip()
    assert w.active_profile.text() == "—"
    assert not w.network_metrics.dns_gauge.has_latency
    assert w.ping_label.text() == "—" and w.ip_label.text() == "—"
    # Xray refreshes must not repaint the card while on PoW
    w._update_route_card(w.storage.selected())
    assert w.active_profile.text() == "—"
    assert w.ip_button.text() == "" and w.ip_button.width() <= 30
