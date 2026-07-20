from __future__ import annotations

import json
import os
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import Qt, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QLabel, QPushButton, QScrollArea, QToolButton

import uac_desktop.storage as storage_module
from uac_desktop.models import Tuning
from uac_desktop.network import ScanResult
from uac_desktop.storage import Storage
from uac_desktop.ui import STYLE, MainWindow, ToggleOptionFrame, ToggleSwitch, TuningDialog
from uac_desktop.update_checker import UpdateInfo


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


def _redirect_storage(monkeypatch, tmp_path):
    paths = {
        "SETTINGS_FILE": tmp_path / "settings.json",
        "PROFILES_FILE": tmp_path / "profiles.json",
        "BOOKMARKS_FILE": tmp_path / "bookmarks.json",
        "SNI_RESULTS_FILE": tmp_path / "sni-results.json",
    }
    for name, path in paths.items():
        monkeypatch.setattr(storage_module, name, path)
    return paths


def test_storage_keeps_mci_and_irancell_tuning_fully_isolated(tmp_path, monkeypatch):
    paths = _redirect_storage(monkeypatch, tmp_path)
    irancell = Tuning.carrier_preset("irancell")
    irancell.mode = "custom"
    irancell.pattern_connect_ip = "104.19.229.21"
    irancell.pattern_fallback_ips = "104.19.230.21"
    irancell.pattern_fake_sni = "irancell-only.example"
    irancell.pattern_socket_buffer_kb = 3584
    paths["SETTINGS_FILE"].write_text(json.dumps({
        "tuning": irancell.to_dict(),
        "speed_core_version": 3,
        "pattern_core_version": 1,
    }), encoding="utf-8")

    storage = Storage()
    initial_irancell = storage.tuning_for_carrier("irancell")
    initial_mci = storage.tuning_for_carrier("mci")

    assert initial_irancell.pattern_fake_sni == "irancell-only.example"
    assert initial_irancell.pattern_socket_buffer_kb == 3584
    assert initial_mci.pattern_connect_ip == "188.114.98.0"
    assert initial_mci.pattern_fake_sni != initial_irancell.pattern_fake_sni

    mci = storage.activate_carrier("mci")
    mci.mode = "custom"
    mci.pattern_connect_ip = "188.114.98.0"
    mci.pattern_fallback_ips = "188.114.99.0"
    mci.pattern_fake_sni = "mci-only.example"
    mci.pattern_ack_timeout_ms = 2711
    mci.pattern_socket_buffer_kb = 4096
    storage.set_tuning(mci)

    restored_irancell = storage.activate_carrier("irancell")
    assert restored_irancell.pattern_fake_sni == "irancell-only.example"
    assert restored_irancell.pattern_ack_timeout_ms != 2711
    assert restored_irancell.pattern_socket_buffer_kb == 3584

    restored_irancell.pattern_connect_timeout_ms = 1777
    restored_irancell.pattern_fake_sni = "irancell-edited.example"
    storage.set_tuning(restored_irancell)

    restored_mci = storage.activate_carrier("mci")
    assert restored_mci.pattern_fake_sni == "mci-only.example"
    assert restored_mci.pattern_ack_timeout_ms == 2711
    assert restored_mci.pattern_connect_timeout_ms != 1777

    reloaded = Storage()
    assert reloaded.tuning.carrier_mode == "mci"
    assert reloaded.tuning_for_carrier("mci").pattern_fake_sni == "mci-only.example"
    assert reloaded.tuning_for_carrier("mci").pattern_ack_timeout_ms == 2711
    assert reloaded.tuning_for_carrier("irancell").pattern_fake_sni == "irancell-edited.example"
    assert reloaded.tuning_for_carrier("irancell").pattern_connect_timeout_ms == 1777


def test_advanced_carrier_switch_preserves_each_draft_without_field_leak(qapp):
    irancell = Tuning.carrier_preset("irancell")
    irancell.mode = "custom"
    irancell.pattern_connect_ip = "104.19.229.21"
    irancell.pattern_fallback_ips = "104.19.230.21"
    irancell.pattern_fake_sni = "irancell.example"
    irancell.pattern_max_sessions = 13
    irancell.xray_mux_enabled = True

    mci = Tuning.carrier_preset("mci")
    mci.mode = "custom"
    mci.pattern_connect_ip = "188.114.98.0"
    mci.pattern_fallback_ips = "188.114.99.0"
    mci.pattern_fake_sni = "mci.example"
    mci.pattern_max_sessions = 9
    mci.xray_mux_enabled = False

    dialog = TuningDialog(
        None,
        irancell,
        "en",
        carrier_tunings={"irancell": irancell, "mci": mci},
    )
    try:
        dialog.connect_ip.setText("104.19.229.99")
        dialog.fake_sni.setText("irancell-edited.example")
        dialog.max_sessions.setValue(15)
        dialog.mux_enabled.setChecked(True)

        dialog.carrier.setCurrentText("mci")
        qapp.processEvents()
        assert dialog.connect_ip.text() == "188.114.98.0"
        assert dialog.fallback_ips.text() == "188.114.99.0"
        assert dialog.fake_sni.text() == "mci.example"
        assert dialog.max_sessions.value() == 9
        assert dialog.mux_enabled.isChecked() is False

        dialog.connect_ip.setText("188.114.98.77")
        dialog.fake_sni.setText("mci-edited.example")
        dialog.max_sessions.setValue(11)
        dialog.mux_enabled.setChecked(False)

        dialog.carrier.setCurrentText("irancell")
        qapp.processEvents()
        assert dialog.connect_ip.text() == "104.19.229.99"
        assert dialog.fake_sni.text() == "irancell-edited.example"
        assert dialog.max_sessions.value() == 15
        assert dialog.mux_enabled.isChecked() is True

        values = dialog.values()
        assert values["irancell"].pattern_connect_ip == "104.19.229.99"
        assert values["irancell"].pattern_fake_sni == "irancell-edited.example"
        assert values["irancell"].pattern_max_sessions == 15
        assert values["mci"].pattern_connect_ip == "188.114.98.77"
        assert values["mci"].pattern_fake_sni == "mci-edited.example"
        assert values["mci"].pattern_max_sessions == 11
        assert values["mci"].xray_mux_enabled is False
    finally:
        dialog.close()


def test_toggle_switch_center_is_clickable(qapp):
    toggle = ToggleSwitch()
    try:
        toggle.show()
        qapp.processEvents()
        center = toggle.rect().center()
        assert toggle.hitButton(center) is True
        assert toggle.isChecked() is False

        QTest.mouseClick(toggle, Qt.LeftButton, Qt.NoModifier, center)
        qapp.processEvents()
        assert toggle.isChecked() is True
    finally:
        toggle.close()


def test_proxy_option_remains_clickable_when_visual_state_is_off(qapp):
    toggle = ToggleSwitch()
    option = ToggleOptionFrame(toggle)
    option.setProperty("active", False)
    try:
        option.resize(160, 50)
        option.show()
        qapp.processEvents()
        assert option.isEnabled() is True
        assert toggle.isEnabled() is True

        QTest.mouseClick(option, Qt.LeftButton, Qt.NoModifier, option.rect().center())
        qapp.processEvents()
        assert toggle.isChecked() is True
    finally:
        option.close()


def test_home_dashboard_has_no_scroll_and_fits_minimum_window(qapp, tmp_path, monkeypatch):
    _redirect_storage(monkeypatch, tmp_path)
    monkeypatch.setattr(MainWindow, "_setup_tray", lambda self: None)
    monkeypatch.setattr(MainWindow, "refresh_processes", lambda self: None)
    monkeypatch.setattr(MainWindow, "check_for_updates", lambda self, manual=False: None)
    previous_style = qapp.styleSheet()
    qapp.setStyleSheet(STYLE)
    window = MainWindow()
    try:
        window.show()
        QTest.qWait(5)
        qapp.processEvents()
        assert window.hero_card.height() >= 300
        for width, height in ((1080, 700), (1280, 800), (1440, 900)):
            window.resize(width, height)
            qapp.processEvents()

            home = window.stack.widget(0)
            sections = [
                window.home_header,
                window.hero_card,
                window.country_card,
                *window.metric_cards,
                window.quick_controls,
            ]
            assert home is window.home_page
            assert not isinstance(home, QScrollArea)
            assert not home.findChildren(QScrollArea)
            assert all(section.isVisible() for section in sections)
            assert max(section.mapTo(home, section.rect().bottomLeft()).y() for section in sections) <= home.rect().bottom()
            assert len({card.mapTo(home, card.rect().topLeft()).y() for card in window.metric_cards}) == 1
            assert window.carrier.geometry().bottom() <= window.carrier_control.rect().bottom()
            assert window.carrier.geometry().right() <= window.carrier_control.rect().right()
            assert window.status.font().pixelSize() == 38
            assert window.connection_hint.font().pixelSize() == 15
            assert window.route_card.title.font().pixelSize() == 11
            assert window.route_card.value.font().pixelSize() == 22
    finally:
        window._force_quit = True
        window.close()
        qapp.setStyleSheet(previous_style)


def test_update_notification_is_top_centered_and_contained(qapp, tmp_path, monkeypatch):
    _redirect_storage(monkeypatch, tmp_path)
    monkeypatch.setattr(MainWindow, "_setup_tray", lambda self: None)
    monkeypatch.setattr(MainWindow, "refresh_processes", lambda self: None)
    monkeypatch.setattr(MainWindow, "check_for_updates", lambda self, manual=False: None)
    previous_style = qapp.styleSheet()
    qapp.setStyleSheet(STYLE)
    window = MainWindow()
    try:
        window.show()
        qapp.processEvents()
        info = UpdateInfo(
            repo_url="https://github.com/example/UAC-Spoofer-Desktop",
            current_version="1.0.2",
            latest_version="1.1.0",
            tag_name="v1.1.0",
            release_name="UAC Spoofer Desktop 1.1.0",
            release_url="https://github.com/example/UAC-Spoofer-Desktop/releases/tag/v1.1.0",
            published_at="",
            release_notes="",
            prerelease=False,
            is_update_available=True,
        )
        window._show_update_notification(info)
        qapp.processEvents()

        banner = window._update_notification
        button = banner.findChild(QPushButton, "updateNotificationPrimary")
        stack_origin = window.stack.mapTo(window.centralWidget(), window.stack.rect().topLeft())
        assert banner.isVisible()
        assert banner.y() == stack_origin.y() + 18
        assert banner.width() <= window.stack.width() - 36
        assert button is not None and button.isVisible()
        assert banner.findChild(QLabel, "updateNotificationVersion") is None
        assert banner.findChild(QToolButton, "updateNotificationClose") is None
        assert button.mapTo(banner, button.rect().bottomRight()).x() <= banner.rect().right()
        assert button.mapTo(banner, button.rect().bottomRight()).y() <= banner.rect().bottom()
    finally:
        window._force_quit = True
        window.close()
        qapp.setStyleSheet(previous_style)


def test_app_bypass_changes_are_debounced_and_reconnect_once(qapp):
    events = SimpleNamespace(log=[], cancelled=[], states=[], reconnects=0, activities=[])
    storage = SimpleNamespace(
        settings={},
        saves=0,
    )

    def save_settings():
        storage.saves += 1

    storage.save_settings = save_settings
    engine = SimpleNamespace(running=True)
    timer = QTimer()
    timer.setSingleShot(True)
    timer.setInterval(30)
    dummy = SimpleNamespace(
        storage=storage,
        engine=engine,
        connecting=False,
        _closing=False,
        _bypass_apply_timer=timer,
        connection_error="old error",
        selected_processes=lambda: ["Telegram.exe"],
        _update_process_count=lambda: None,
        _set_activity=lambda *args: events.activities.append(args),
        _append_log=events.log.append,
        _set_state=events.states.append,
    )

    def cancel_connect_attempt(*, notify):
        events.cancelled.append(notify)
        engine.running = False
        dummy.connecting = False

    def toggle_connection():
        events.reconnects += 1

    dummy._cancel_connect_attempt = cancel_connect_attempt
    dummy.toggle_connection = toggle_connection
    timer.timeout.connect(lambda: MainWindow._apply_bypass_changes(dummy))

    for _ in range(3):
        MainWindow._save_process_selection(dummy)
        QTest.qWait(6)

    assert timer.isActive()
    assert storage.settings["bypass_processes"] == ["Telegram.exe"]
    assert storage.saves == 3
    assert events.reconnects == 0

    QTest.qWait(260)
    qapp.processEvents()
    assert len(events.log) == 1
    assert events.cancelled == [False]
    assert events.states == [False]
    assert events.reconnects == 1
    assert dummy.connection_error == ""


def test_sni_edge_is_bound_only_when_scanner_verified_the_exact_pair():
    base = Tuning(
        carrier_mode="mci",
        pattern_connect_ip="188.114.98.0",
        pattern_fallback_ips="188.114.99.0,104.18.8.83",
        pattern_fake_sni="old.example",
    )
    unverified = ScanResult(
        domain="unverified.example",
        success=True,
        edge="172.64.155.209",
        edge_verified=False,
    )

    unchanged_route = MainWindow._bind_verified_sni_route(
        Tuning.from_dict(base.to_dict()), unverified,
    )
    assert unchanged_route.pattern_fake_sni == "unverified.example"
    assert unchanged_route.pattern_connect_ip == "188.114.98.0"
    assert unchanged_route.pattern_fallback_ips == "188.114.99.0,104.18.8.83"

    verified = ScanResult(
        domain="verified.example",
        success=True,
        edge="188.114.99.0",
        edge_verified=True,
    )
    bound = MainWindow._bind_verified_sni_route(Tuning.from_dict(base.to_dict()), verified)
    assert bound.pattern_fake_sni == "verified.example"
    assert bound.pattern_connect_ip == "188.114.99.0"
    assert bound.pattern_fallback_ips.split(",") == ["188.114.98.0", "104.18.8.83"]
