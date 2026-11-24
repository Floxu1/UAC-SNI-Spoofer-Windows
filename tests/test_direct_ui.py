import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QPoint, QRect
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication, QFileDialog, QFrame, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QTabWidget
from PySide6.QtTest import QTest

from uac_desktop import direct_ui, pow_ui, storage, ui
from uac_desktop.direct_ui import ENGINE_DIRECT
from uac_desktop.direct.coordinator import DirectStatus
from uac_desktop.pow_ui import ENGINE_POW, ENGINE_XRAY

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def window(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "SETTINGS_FILE", tmp_path / "settings.json")
    monkeypatch.setattr(direct_ui, "DATA_DIR", tmp_path)
    monkeypatch.setattr(pow_ui, "DATA_DIR", tmp_path)
    APP.setStyleSheet(ui.combined_app_style("en"))
    instance = ui.MainWindow()
    instance.language = "en"
    instance._apply_language()
    instance.resize(1080, 700)
    instance.show()
    APP.processEvents()
    yield instance
    instance.shutdown()
    instance._force_quit = True
    instance.close()


def test_direct_uses_shared_home_and_keeps_advanced_controls_in_settings(window):
    assert window.engine_mode == ENGINE_POW
    window.engine_buttons[ENGINE_DIRECT].click()
    APP.processEvents()
    assert window.engine_mode == ENGINE_DIRECT
    assert window.stack.currentWidget() is window.home_page
    assert window.engine_buttons[ENGINE_DIRECT].isChecked()
    for button in window.engine_buttons.values():
        assert button.geometry().right() <= window.engine_switch.width()
    right = window.engine_switch.mapTo(window.sidebar, window.engine_switch.rect().topRight()).x()
    assert right <= window.sidebar.width()
    assert not window.home_page.findChildren(QLineEdit)
    assert not window.home_page.findChildren(QPlainTextEdit)
    window.proxy_mode.click()
    assert window.global_settings.snapshot().connection_mode == "proxy"
    assert window.proxy_mode.isChecked() and not window.tun_mode.isChecked()
    assert window.direct_controller.store.settings().connection_mode == "vpn"
    window.show_page(window.GLOBAL_SETTINGS_PAGE)
    assert not {"connection_mode", "routing_mode"} & window.global_settings_page.controls.keys()
    window.show_page(5)
    policy = window.app_routing_mode
    assert window.stack.currentWidget().isAncestorOf(policy)
    policy.setCurrentIndex(policy.findData("only"))
    assert window.global_settings.snapshot().routing_mode == "only"

    window.show_page(0)
    window.tune_button.click()
    assert window.stack.currentWidget().objectName() == "directSettingsPage"
    assert window.nav[window.DIRECT_SETTINGS_PAGE].isChecked()
    direct = window.direct_controller
    assert "kill_switch" not in direct._toggles
    method = direct._choices["wireguard_over_direct"][0]
    method.setCurrentIndex(method.findData(False))
    assert not direct._choices["scan_mode"][0].isEnabled()
    assert direct._toggles["udp_noise"].isEnabled()
    assert not window.direct_controller.store.settings().wireguard_over_direct
    assert not window.pow_country_button.isEnabled()
    window.language = "fa"
    window._apply_language()
    assert window.pow_country_button.title_label.text() == "TLS مستقیم"
    window.engine_buttons[ENGINE_XRAY].click()
    assert window.engine_mode == ENGINE_XRAY
    assert window.stack.currentWidget() is window.home_page
    assert window.pause_button.isHidden()
    assert not window.gateway_option.isHidden()
    window.engine_buttons[ENGINE_POW].click()
    assert window.pow_country_button.isEnabled()
    assert window.pause_button.isHidden()


def test_shared_dashboard_and_sidebar_keep_pixel_geometry_when_engines_change(window):
    def rect(widget):
        return QRect(widget.mapTo(window, QPoint()), widget.size())

    def bounds():
        controls = (
            window.sidebar, window.logo_card, window.logo_mark, window.brand_label, window.version_label,
            window.engine_switch, *window.engine_buttons.values(),
            window.sidebar_footer, window.home_header, window.hero_card, window.orb, window.connect_button,
            window.country_card, *window.metric_cards, window.active_profile, window.quick_controls_slot,
            window.activity_bar,
        )
        return tuple(map(rect, controls))

    def check_row(widgets, language, gap=None, *, equal_widths=True):
        tiles = tuple(map(rect, widgets))
        assert all(tile.height() == tiles[0].height() and tile.y() == tiles[0].y() for tile in tiles)
        if equal_widths:
            assert all(tile.width() == tiles[0].width() for tile in tiles)
        ordered = tiles[::-1] if language == "fa" else tiles
        gaps = [right.left() - left.right() - 1 for left, right in zip(ordered, ordered[1:])]
        assert all(space > 0 for space in gaps)
        if gap is not None:
            assert gaps == [gap] * len(gaps)
        return tiles

    for language in ("fa", "en"):
        window.language = language
        window._apply_language()
        for size in ((1080, 700), (1440, 900)):
            window.resize(*size)
            window.engine_buttons[ENGINE_POW].click()
            QTest.qWait(75)
            scroll = window.home_page.verticalScrollBar()
            if size[1] == 700:
                assert scroll.maximum() > 0
            scroll.setValue(scroll.maximum())
            offset = scroll.value()
            reference = bounds()
            compact_nav = [window.nav[i] for i in (0, 4, 5, 9, 8)]
            nav_reference = tuple(map(rect, compact_nav))
            two_row_panel = rect(window.quick_controls)
            for engine in (ENGINE_DIRECT, ENGINE_XRAY, ENGINE_POW):
                window.engine_buttons[engine].click()
                QTest.qWait(75)
                assert window.engine_mode == engine
                assert bounds() == reference
                if engine != ENGINE_XRAY:
                    assert tuple(map(rect, compact_nav)) == nav_reference
                assert scroll.value() == offset
                assert window.quick_controls_header.isVisible()
                assert window.quick_controls_stamp.text() == f"{engine.upper()} / CONTROL"
                heading = window.quick_controls_header.findChild(QLabel, "quickControlsTitle")
                assert heading.font().pixelSize() == 13
                assert heading.font().weight() == QFont.DemiBold
                labels = [card.title for card in window.network_metrics.cards]
                labels += [window._option_label(window.auto_option), window.tune_button]
                assert all(label.font().pixelSize() == 12 and label.font().weight() == QFont.DemiBold
                           for label in labels)
                assert all(card.value.digits.weight() == QFont.DemiBold for card in window.network_metrics.cards)
                if engine == ENGINE_XRAY:
                    top = check_row((window.auto_option, window.manual_option, window.gateway_option),
                                    language, 8, equal_widths=False)
                    bottom = check_row((window.proxy_option, window.tun_option, window.carrier_control,
                                        window.tune_button), language, 8)
                    assert all(tile.height() == 45 for tile in (*top, *bottom))
                    assert bottom[0].top() - top[0].bottom() - 1 == 8
                    assert (top[0].left(), top[0].right()) == (
                        min(bottom[0].left(), bottom[1].left()), max(bottom[0].right(), bottom[1].right()),
                    )
                    assert [(tile.x(), tile.width()) for tile in top[1:]] == [
                        (tile.x(), tile.width()) for tile in bottom[2:]
                    ]
                    assert rect(window.quick_controls) == two_row_panel
                elif engine == ENGINE_DIRECT:
                    check_row((window.auto_option, window.proxy_option, window.tun_option, window.tune_button), language)
                else:
                    top = check_row((window.auto_option, window.gateway_option, window.carrier_control), language, 8)
                    bottom = check_row((window.proxy_option, window.tun_option, window.tune_button), language, 8)
                    assert all(tile.height() == 45 for tile in (*top, *bottom))
                    assert bottom[0].top() - top[0].bottom() - 1 == 8
                    assert [tile.x() for tile in top] == [tile.x() for tile in bottom]


def test_xray_quick_settings_keep_their_bindings(window, monkeypatch):
    window.engine_buttons[ENGINE_XRAY].click()
    window.auto_mode.click()
    assert window.storage.settings["auto_mode"] == window.auto_mode.isChecked()
    window.pick_best.click()
    assert window.storage.settings["pick_best"] == window.pick_best.isChecked()
    assert [window.carrier.itemText(i) for i in range(window.carrier.count())] == ["auto", "mci", "irancell"]
    for carrier in ("mci", "irancell", "auto"):
        window.carrier.setCurrentText(carrier)
        assert window.storage.tuning.carrier_mode == carrier
    window.gateway_devices_badge.click()
    assert window.gateway_devices_popup.isVisible()
    window.gateway_devices_popup.hide()
    opened = []
    monkeypatch.setattr(ui.TuningDialog, "exec", lambda dialog: opened.append(dialog) or 0)
    window.tune_button.click()
    assert len(opened) == 1


def test_pow_quick_settings_keep_their_bindings(window):
    window.engine_buttons[ENGINE_POW].click()
    store = window.pow_controller.store
    assert [window.carrier.itemText(i) for i in range(window.carrier.count())] == ["auto", "mci", "irancell"]
    for firewall in ("irancell", "mci", "auto"):
        window.carrier.setCurrentText(firewall)
        assert store.snapshot().firewall_profile == firewall
    window.auto_mode.click()
    assert (store.snapshot().exit_mode == "chain") == window.auto_mode.isChecked()
    window.gateway_mode.click()
    assert bool(window.pow_controller.h2_fragment_display()[0]) == window.gateway_mode.isChecked()
    assert all(toggle._thumb_animation.duration() == 200 for toggle in
               (window.auto_mode, window.gateway_mode, window.proxy_mode, window.tun_mode))
    window.tune_button.click()
    assert window.stack.currentWidget().objectName() == "powSettingsPage"


@pytest.mark.parametrize("engine", (ENGINE_DIRECT, ENGINE_POW))
def test_turning_off_active_output_stops_it_without_enabling_the_other(window, monkeypatch, engine):
    window.engine_buttons[engine].click()
    controller = window.direct_controller if engine == ENGINE_DIRECT else window.pow_controller
    coordinator = controller.coordinator
    calls = []
    monkeypatch.setattr(coordinator, "connect", lambda *args, **kwargs: calls.append("connect"))
    monkeypatch.setattr(window, "show_toast", lambda message, *_: calls.append(message))

    for mode, toggle in (("proxy", window.proxy_mode), ("vpn", window.tun_mode)):
        if not toggle.isChecked():
            toggle.click()
        assert window.global_settings.snapshot().connection_mode == mode
        assert window.proxy_mode.isChecked() == (mode == "proxy")
        assert window.tun_mode.isChecked() == (mode == "vpn")
        coordinator._stop.clear()
        with monkeypatch.context() as session:
            if engine == ENGINE_DIRECT:
                session.setattr(coordinator, "_worker", object())
                session.setattr(coordinator, "_session_vpn", mode == "vpn")
                session.setattr(coordinator, "_status", DirectStatus(phase="connected"))
            else:
                coordinator._path_cancel.clear()
                coordinator._proxy_mode = mode == "proxy"
                coordinator._connected.set()
                session.setattr(coordinator, "_teardown_exit", lambda: calls.append("stop"))

            toggle.click()
            assert window.global_settings.snapshot().connection_mode == "local"
            assert coordinator._stop.is_set()
            assert not window.proxy_mode.isChecked()
            assert not window.tun_mode.isChecked()
            if engine == ENGINE_POW:
                deadline = time.monotonic() + 2
                while controller.busy and time.monotonic() < deadline:
                    QTest.qWait(10)
                assert not controller.busy
                assert calls.pop() == "stop"

        if engine == ENGINE_DIRECT:
            controller.refresh()
        else:
            controller._refresh()
        assert window.connect_button.isEnabled()
        window.connect_button.click()
        assert calls.pop() == "Turn on Windows Proxy or TUN to connect."
        assert not calls

    window.engine_buttons[ENGINE_XRAY].click()
    window.engine_buttons[engine].click()
    assert not window.proxy_mode.isChecked()
    assert not window.tun_mode.isChecked()
    if engine == ENGINE_POW:
        window._change_global_settings(auto_connect=True)
        controller._auto_network = "test-network"
        controller._auto_connect()
        assert not calls


def test_direct_status_owns_metrics_and_worker_logs_reach_live_logs(window):
    window.engine_buttons[ENGINE_DIRECT].click()
    direct = window.direct_controller
    status = DirectStatus(phase="connected", detail="Verified SOCKS", carrier="192.0.2.3:443",
                          resolver="Cloudflare", dns_ms=39, tx_bytes=1024, rx_bytes=2048,
                          exit_ip="192.0.2.8", country="DE")
    direct.coordinator._status = status
    direct._status.emit(status)
    for line in ("Direct connecting: WireGuard over Direct (VPN)", "Direct IP scan 192",
                 "Direct fallback: trying saved carrier", "Direct connected", "Direct recovering: test",
                 "Direct failed: test", "Direct stopped", "Native tunnel started",
                 "route discovery (private_key=secretfixture)", "authorization: Bearer testfixture"):
        direct.coordinator._log(line)
    APP.processEvents()
    window._set_state(False)
    window._poll_windows_traffic()
    window._target_latency_finished(6058, (ENGINE_XRAY, 1080, 7), window._target_latency_generation)
    assert window.connect_button.text() == "Disconnect"
    assert window.active_profile.text() == "WireGuard"
    assert window.ping_label.text() == "39 ms"
    assert window.network_metrics.dns_gauge.has_latency
    assert window.network_metrics.route_status.state == "connected"
    assert window.ip_label.text() == "192.0.2.8"
    assert window.up_label.text() == ui.format_bytes(1024)
    window.bridge.engine_log.emit("old Xray engine detail", ENGINE_XRAY)
    window.show_page(4)
    window._render_logs()
    rendered = window.logs.toPlainText()
    for line in ("Direct scanning 192 addresses", "Direct fallback: trying saved carrier", "Direct connected",
                 "Direct recovering: test", "Direct failed: test", "Direct disconnected", "Direct: Native tunnel started"):
        assert line in rendered
    assert "old Xray engine detail" not in rendered
    assert "secretfixture" not in rendered and "testfixture" not in rendered
    assert "[redacted]" in rendered
    assert window.stack.currentWidget().objectName() == "liveLogsPage"


def test_global_destination_persists_across_switches_and_keeps_engine_settings_independent(window):
    from uac_desktop.application_settings import ApplicationSettings

    window.engine_buttons[ENGINE_DIRECT].click()
    window.nav[window.GLOBAL_SETTINGS_PAGE].click()
    page = window.stack.currentWidget()
    assert page is window.global_settings_page
    shared = window.global_settings
    domestic = page.controls["iran_direct"]
    domestic.setChecked(False)
    for engine in (ENGINE_POW, ENGINE_XRAY, ENGINE_DIRECT):
        window.engine_buttons[engine].click()
        APP.processEvents()
        assert window.engine_mode == engine
        assert window.stack.currentWidget() is page
        assert window.global_settings is shared
        assert not domestic.isChecked()
    assert not ApplicationSettings(storage.Storage()).snapshot().iran_direct

    pow_before = window.pow_controller.store.snapshot()
    window.nav[window.DIRECT_SETTINGS_PAGE].click()
    direct = window.direct_controller
    direct._toggles["auto_select_dns"].setChecked(False)
    assert not direct.store.settings().auto_select_dns
    assert window.pow_controller.store.snapshot() == pow_before
    saved_direct = direct.store.settings()
    window.engine_buttons[ENGINE_POW].click()
    window.nav[window.POW_SETTINGS_PAGE].click()
    combo = window.pow_controller.recipe_combo
    combo.setCurrentIndex(combo.findData("masque-h3-over-h2"))
    assert window.pow_controller.store.snapshot().link_recipe == "masque-h3-over-h2"
    assert direct.store.settings() == saved_direct
    assert not shared.snapshot().iran_direct


def test_global_settings_cards_keep_all_controls_and_backup_actions(window, monkeypatch, tmp_path):
    window.engine_buttons[ENGINE_XRAY].click()
    window.nav[window.GLOBAL_SETTINGS_PAGE].click()
    page = window.global_settings_page
    sections = page.findChildren(QFrame, "globalSettingsSection")
    assert not page.findChildren(QTabWidget)
    assert [section.findChild(QLabel, "globalSettingsSectionTitle").text() for section in sections] == [
        "Appearance", "Connection & routing", "Network sharing", "Security", "Tools & backup",
    ]
    toggle_names = {"iran_direct", "auto_connect", "lan_share", "kill_switch", "ipv6_block",
                    "dns_sinkhole", "webrtc_block", "quic_block"}
    assert set(page.controls) == toggle_names | {"domains_direct", "lan_share_mode", "lan_share_port"}
    settings = window.global_settings
    page.motion.setChecked(not page.motion.isChecked())
    assert settings.reduce_navigation_motion == page.motion.isChecked()
    for name in toggle_names:
        control = page.controls[name]
        control.click()
        assert getattr(settings.snapshot(), name) == control.isChecked()
    domains = page.controls["domains_direct"]
    domains.setText("example.com, cdn.example.net")
    domains.editingFinished.emit()
    assert "cdn.example.net" in settings.snapshot().domains_direct
    protocol = page.controls["lan_share_mode"]
    assert [protocol.itemData(index) for index in range(protocol.count())] == ["socks5", "ps5"]
    protocol.setCurrentIndex(protocol.findData("ps5"))
    port = page.controls["lan_share_port"]
    port.setValue(18823)
    assert (settings.snapshot().lan_share_mode, settings.snapshot().lan_share_port) == ("ps5", 18823)

    backup = tmp_path / "settings-backup.json"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *_: (str(backup), "JSON"))
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *_: (str(backup), "JSON"))
    monkeypatch.setattr(QMessageBox, "question", lambda *_: QMessageBox.Yes)
    opened_folders = []
    monkeypatch.setattr(ui.os, "startfile", opened_folders.append, raising=False)
    actions = {button.text(): button for button in page.findChildren(QPushButton, "settingsAction")}
    actions["Open"].click()
    assert opened_folders == [ui.DATA_DIR]
    actions["Export"].click()
    assert backup.is_file()
    saved = settings.snapshot()
    actions["Reset"].click()
    assert settings.snapshot().lan_share_port != saved.lan_share_port
    actions["Import"].click()
    assert settings.snapshot() == saved


def test_hero_pause_shows_for_proxy_only_and_uses_session_state(window, monkeypatch):
    window.engine_buttons[ENGINE_DIRECT].click()
    direct = window.direct_controller
    coordinator = direct.coordinator
    calls = []
    monkeypatch.setattr(coordinator, "set_paused", lambda paused, *, proxy_only: calls.append((paused, proxy_only)))
    coordinator._worker = object()
    try:
        for vpn, phase, label in ((True, "connected", None), (False, "connected", "Pause"),
                                  (False, "paused", "Resume"), (False, "recovering", None)):
            coordinator._session_vpn = vpn
            coordinator._status = DirectStatus(phase=phase)
            direct._show_status(coordinator.status)
            assert window.pause_button.isVisible() == bool(label)
            if label:
                assert window.pause_button.text() == label
                assert window.pause_button.parentWidget() is window.hero_card
                window.pause_button.click()
        assert calls == [(True, True), (False, True)]
    finally:
        coordinator._worker = None


def test_switch_waits_until_direct_releases_its_worker(window, monkeypatch):
    window.engine_buttons[ENGINE_DIRECT].click()
    direct = window.direct_controller
    pending = object()
    direct.coordinator._worker = pending
    requested = []
    monkeypatch.setattr(window, "_switch_guard_fn", lambda: True, raising=False)
    monkeypatch.setattr(direct, "stop", lambda: requested.append(True))
    try:
        window.engine_buttons[ENGINE_XRAY].click()
        window.engine_buttons[ENGINE_POW].click()
        APP.processEvents()
        assert requested and window.engine_mode == ENGINE_DIRECT
    finally:
        direct.coordinator._worker = None
    deadline = time.monotonic() + 1
    while window.engine_mode == ENGINE_DIRECT and time.monotonic() < deadline:
        APP.processEvents()
        time.sleep(0.025)
    assert window.engine_mode == ENGINE_XRAY
