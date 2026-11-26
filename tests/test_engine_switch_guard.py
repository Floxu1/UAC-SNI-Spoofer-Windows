import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from types import SimpleNamespace

import pytest
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QApplication, QDialog, QFrame, QLabel, QPushButton

from uac_desktop import ui
from uac_desktop.direct_ui import ENGINE_DIRECT
from uac_desktop.engine_switch_guard import SharedEngineSwitchDialog
from uac_desktop.pow_ui import ENGINE_POW, ENGINE_XRAY

APP = QApplication.instance() or QApplication([])


def test_switch_blocked_while_connected_and_toggle_snaps_back():
    synced = []
    stub = SimpleNamespace(_engine_switching=False, engine_mode=ENGINE_XRAY,
                           _protected_session=lambda: False,
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


def test_guarded_session_cannot_release_filters_via_engine_switch():
    calls = []
    stub = SimpleNamespace(
        _engine_switching=False, _engine_switch_target=ENGINE_XRAY,
        _protected_session=lambda: True, _reject_guarded_change=lambda: calls.append("blocked"),
        _restore_engine_switch_look=lambda: calls.append("restored"),
    )
    ui.MainWindow._switch_engine(stub)
    assert calls == ["blocked", "restored"]
    assert stub._engine_switch_target is None


def test_busy_detection():
    s = SimpleNamespace(pow_controller=SimpleNamespace(busy=False), engine=SimpleNamespace(running=False), connecting=False)
    assert not ui.MainWindow._engine_busy(s)
    s.connecting = True
    assert ui.MainWindow._engine_busy(s)
    s.connecting = False; s.pow_controller.busy = True
    assert ui.MainWindow._engine_busy(s)


@pytest.mark.parametrize("language", ["fa", "en"])
def test_guard_dialog_layout_and_text(language):
    fa = language == "fa"
    dialog = SharedEngineSwitchDialog(None, language, ENGINE_DIRECT, ENGINE_XRAY, "connecting")
    dialog.show()
    APP.processEvents()
    assert dialog.layoutDirection() == (Qt.RightToLeft if fa else Qt.LeftToRight)
    assert dialog.title.text() == ("تعویض موتور" if fa else "Switch engine")
    assert dialog.go_btn.text() == ("قطع اتصال و تعویض" if fa else "Disconnect and switch")
    assert dialog.cancel_btn.text() == ("انصراف" if fa else "Cancel")
    assert dialog.width() == 440 and dialog.go_btn.height() == dialog.cancel_btn.height() == 43
    assert dialog.cancel_btn.width() == 122
    assert dialog.current_card.size() == dialog.target_card.size()
    assert dialog.current_card.parentWidget().rect().contains(dialog.current_card.geometry())
    assert ("در حال اتصال" if fa else "Connecting") in dialog.current_status.text()
    dialog.set_connection_state("connected")
    assert ("اتصال فعال" if fa else "Connected") in dialog.current_status.text()
    assert set(dialog.findChildren(QPushButton)) == {dialog.go_btn, dialog.cancel_btn}
    for dismiss in (dialog.cancel_btn.click, dialog.close):
        dialog.show()
        dismiss()
        assert dialog.result() == QDialog.Rejected and not dialog.isVisible()


@pytest.mark.parametrize("engine", [ENGINE_XRAY, ENGINE_POW, ENGINE_DIRECT])
def test_disconnect_failure_keeps_current_engine(engine):
    switched = []
    logs = []
    stub = SimpleNamespace(
        engine_mode=engine, _engine_guard_pending=True, _engine_switch_target="target",
        connecting=False, engine=SimpleNamespace(running=engine == ENGINE_XRAY),
        pow_controller=SimpleNamespace(busy=engine == ENGINE_POW, disconnect=lambda: None, disconnect_failed=True),
        direct_controller=SimpleNamespace(busy=engine == ENGINE_DIRECT, stop=lambda: None,
                                          coordinator=SimpleNamespace(status=SimpleNamespace(disconnect_failed=True))),
        bridge=SimpleNamespace(log=SimpleNamespace(emit=logs.append)),
        network_metrics=SimpleNamespace(connection_state="disconnecting"),
        _engine_busy=lambda: False, _switch_engine=lambda: switched.append(True),
        _set_connection_visual=lambda _state: None, _restore_engine_switch_look=lambda: None,
        show_toast=lambda *_args: None, tr=lambda _fa, en: en,
    )

    def fail(**_kwargs):
        raise OSError("cleanup failed")

    stub._cancel_connect_attempt = fail
    ui.MainWindow._disconnect_then_switch(stub)
    assert not switched and stub.engine_mode == engine and stub._engine_switch_target is None
    assert "switch cancelled" in logs[-1]


@pytest.fixture()
def window(tmp_path, monkeypatch):
    monkeypatch.setattr(ui, "DATA_DIR", tmp_path / "data")
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    from uac_desktop import paths, process_win, storage
    import uac_desktop.pow_ui as pow_ui
    monkeypatch.setattr(paths, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(pow_ui, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(process_win, "cleanup_bin_helpers", lambda: None)
    monkeypatch.setattr(storage, "SETTINGS_FILE", tmp_path / "data" / "settings.json")
    yield ui.MainWindow()


def test_guarded_clicks_switch_between_all_six_engine_pairs(window, monkeypatch):
    w = window
    monkeypatch.setattr(w, "_navigation_animations_enabled", lambda: False)
    w.engine_buttons[ENGINE_DIRECT].click()
    names = {ENGINE_XRAY: "Xray", ENGINE_POW: "UAC PoW", ENGINE_DIRECT: "UAC Direct"}
    path = [ENGINE_DIRECT, ENGINE_XRAY, ENGINE_POW, ENGINE_DIRECT, ENGINE_POW, ENGINE_XRAY, ENGINE_DIRECT]
    seen = []
    gaps = []
    button_sizes = []
    watchdog = QTimer()
    watchdog.setSingleShot(True)
    watchdog.timeout.connect(lambda: isinstance(QApplication.activeModalWidget(), SharedEngineSwitchDialog)
                             and QApplication.activeModalWidget().reject())
    for current, target in zip(path, path[1:]):
        assert w.engine_mode == current
        w.connecting = current == ENGINE_XRAY
        w.pow_controller._connecting = current == ENGINE_POW
        direct = w.direct_controller.coordinator
        direct._worker = object() if current == ENGINE_DIRECT else None
        w._set_connection_visual("connecting")
        stop = []
        monkeypatch.setattr(w, "_cancel_connect_attempt", lambda **_: stop.append(w.engine_mode))

        def stop_pow():
            stop.append(w.engine_mode)
            w.pow_controller._connecting = False

        def stop_direct():
            stop.append(w.engine_mode)
            direct._worker = None

        monkeypatch.setattr(w.pow_controller, "disconnect", stop_pow)
        monkeypatch.setattr(w.direct_controller, "stop", stop_direct)

        def accept():
            dialog = QApplication.activeModalWidget()
            if isinstance(dialog, SharedEngineSwitchDialog):
                seen.append((dialog.current_card.property("engineKey"), dialog.target_card.property("engineKey"),
                             dialog.target_card.findChild(QLabel, "switchName").text(), w.engine_mode, len(stop)))
                warning = dialog.findChild(QFrame, "switchWarning")
                card_top = dialog.current_card.mapTo(dialog, dialog.current_card.rect().topLeft()).y()
                warning_top = warning.mapTo(dialog, warning.rect().topLeft()).y()
                gaps.append(warning_top - card_top - dialog.current_card.height())
                button_sizes.append((dialog.go_btn.height(), dialog.cancel_btn.height(), dialog.cancel_btn.width()))
                dialog.go_btn.click()

        w.engine_buttons[target].click()
        QTimer.singleShot(0, accept)
        watchdog.start(2000)
        APP.processEvents()
        watchdog.stop()
        assert stop == [current] and w.engine_mode == target
    assert seen == [(current, target, names[target], current, 0) for current, target in zip(path, path[1:])]
    assert gaps == [16] * 6
    assert button_sizes == [(43, 43, 122)] * 6


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
