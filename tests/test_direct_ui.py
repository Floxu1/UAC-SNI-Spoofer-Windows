import os
import socket
import threading
import time
import uuid
import winreg
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication, QEvent, QObject, QPoint, QRect, Qt
from PySide6.QtGui import QColor, QFont, QPalette
from PySide6.QtNetwork import QNetworkInformation
from PySide6.QtWidgets import QApplication, QFileDialog, QFrame, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QTabWidget, QToolButton, QToolTip
from PySide6.QtTest import QTest

from uac_desktop import direct_ui, pow_ui, process_win, storage, ui
from uac_desktop.app_routing_view import RunningApp
from uac_desktop import engine as engine_module
from uac_desktop.direct_ui import ENGINE_DIRECT
from uac_desktop.direct.coordinator import DirectStatus
from uac_desktop.pow_ui import ENGINE_POW, ENGINE_XRAY
from uac_desktop.pow.status import PowPhase

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def window(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "SETTINGS_FILE", tmp_path / "settings.json")
    monkeypatch.setattr(direct_ui, "DATA_DIR", tmp_path)
    monkeypatch.setattr(pow_ui, "DATA_DIR", tmp_path)
    monkeypatch.setattr(ui.MainWindow, "refresh_processes", lambda self: None)
    monkeypatch.setattr(ui.MainWindow, "check_for_updates", lambda self, manual=False: None)
    monkeypatch.setattr(process_win, "cleanup_bin_helpers", lambda: None)
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
    instance.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


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
    window.tun_mode.click()
    window.proxy_mode.click()
    assert window.global_settings.snapshot().connection_mode == "proxy"
    assert window.proxy_mode.isChecked() and not window.tun_mode.isChecked()
    assert window.direct_controller.store.settings().connection_mode == "vpn"
    window.show_page(window.GLOBAL_SETTINGS_PAGE)
    assert not {"connection_mode", "routing_mode"} & window.global_settings_page.controls.keys()
    window.show_page(5)
    policy = window.app_routing_view
    assert window.stack.currentWidget() is policy
    policy.set_apps([RunningApp("sample.exe", "Sample")])
    policy.modes["bypass"].click()
    switch = policy.table.cellWidget(0, 2).findChild(ui.ToggleSwitch)
    switch.click()
    policy.modes["all"].click()
    assert switch.isChecked() and not switch.isEnabled()
    policy.modes["only"].click()
    assert window.global_settings.snapshot().routing_mode == "only"
    policy.set_apps([])
    assert window.global_settings.processes() == ("sample.exe",)
    assert policy.table.rowCount() == 1

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
    assert not window.gateway_option.isHidden()
    window.engine_buttons[ENGINE_POW].click()
    assert window.pow_country_button.isEnabled()


def test_direct_dns_lab_import_scan_and_apply(window, tmp_path, monkeypatch):
    from uac_desktop import direct_dns_ui
    from uac_desktop.direct.probe import ResolverMeasurement

    window.engine_buttons[ENGINE_DIRECT].click()
    window.nav[window.DIRECT_DNS_PAGE].click()
    page = window.dns_lab_page
    assert window.stack.currentWidget() is page
    radar = "udp://10.202.10.10"
    assert page.table.item(page._rows[radar], 2).text() == "UDP"
    page.address.setText("1.0.0.1")
    page.address.returnPressed.emit()
    filename = tmp_path / "dns.txt"
    filename.write_text("https://dns.example/dns-query\ninvalid\n1.0.0.1\n", encoding="utf-8")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *_args: (str(filename), ""))
    page._import_file()
    endpoint = "https://dns.example/dns-query"
    settings = window.direct_controller.store.settings()
    assert settings.custom_dns == ("tcp://1.0.0.1", endpoint)

    route = window.direct_controller.coordinator
    route._status = DirectStatus(phase="connected", dns_lab_port=46540)
    page.set_route_status(route.status)
    scans, applied = [], []

    def scan(resolvers, port, cancel, *, progress):
        scans.append(port)
        for resolver in resolvers:
            progress(ResolverMeasurement(resolver, (5, 7, 9, 11) if resolver.url == endpoint else (), 4))

    monkeypatch.setattr(direct_dns_ui, "scan_dns", scan)
    monkeypatch.setattr(route, "reload_dns", lambda settings: applied.append(settings) or True)
    page.scan_all.click()
    for _ in range(50):
        if page.apply_best.isEnabled():
            break
        QTest.qWait(10)
    assert scans == [46540] and page.apply_best.isEnabled()
    row = page._rows[endpoint]
    assert page.table.item(row, 3).text() == "8 ms"
    assert page.table.item(row, 4).text() == "4 / 4"
    page.apply_best.click()
    assert applied[-1].pinned_dns == endpoint and not applied[-1].auto_select_dns
    assert applied[-1] == window.direct_controller.store.settings()
    page.auto.click()
    assert applied[-1].auto_select_dns and not applied[-1].pinned_dns
    route._status = DirectStatus(phase="connected", dns_lab_port=46540, dns_udp_supported=False)
    page.set_route_status(route.status)
    page.table.selectRow(page._rows[radar])
    assert not page.scan_row.isEnabled()
    assert page.scan_all.isEnabled()
    page._apply(radar)
    assert applied[-1].auto_select_dns
    route._status = DirectStatus()
    window.engine_buttons[ENGINE_POW].click()
    assert window.nav[window.DIRECT_DNS_PAGE].isHidden()
    assert window.stack.currentWidget() is window.home_page


def test_shared_dashboard_and_sidebar_keep_pixel_geometry_when_engines_change(window):
    def rect(widget):
        return QRect(widget.mapTo(window, QPoint()), widget.size())

    panels = (window.country_card, window.network_metrics, window.quick_controls, window.activity_bar)

    def bounds():
        controls = (
            window.sidebar, window.logo_card, window.logo_mark, window.brand_label, window.version_label,
            window.engine_badge,
            window.engine_switch, *window.engine_buttons.values(),
            window.sidebar_footer, window.home_header, window.hero_card, window.orb, window.connect_button,
            *panels, *window.metric_cards, window.active_profile,
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
            panel_bounds = tuple(map(rect, panels))
            assert len({(area.left(), area.right()) for area in panel_bounds}) == 1
            assert all(b.top() - a.bottom() - 1 == 12 for a, b in zip(panel_bounds, panel_bounds[1:]))
            compact_nav = [window.nav[i] for i in (0, 4, 5, 9, 8)]
            nav_reference = tuple(map(rect, compact_nav))
            two_row_panel = rect(window.quick_controls)
            for engine in (ENGINE_DIRECT, ENGINE_XRAY, ENGINE_POW):
                window.engine_buttons[engine].click()
                QTest.qWait(75)
                assert window.engine_mode == engine
                assert bounds() == reference
                accent = {"xray": "#27dfe9", "pow": "#37e9ac", "direct": "#ff974d"}[engine]
                assert window.engine_thumb.colors()[1].name() == accent
                assert accent in window.brand_label.text().lower()
                assert window.engine_thumb.geometry() == window.engine_buttons[engine].geometry()
                tray = window.engine_switch.rect()
                for button in window.engine_buttons.values():
                    geometry = button.geometry()
                    assert tray.contains(geometry)
                    assert geometry.top() == tray.bottom() - geometry.bottom()
                    assert button.font().pixelSize() == 11
                    assert button.fontMetrics().horizontalAdvance(button.text()) <= button.width() - 6
                if engine != ENGINE_XRAY:
                    sidebar_rows = tuple(map(rect, compact_nav))
                    assert sidebar_rows[:-1] == nav_reference[:-1]
                    extra = window.nav[window.DIRECT_DNS_PAGE]
                    offset_y = 0 if extra.isHidden() else extra.height() + window.sidebar_layout.spacing()
                    assert sidebar_rows[-1] == nav_reference[-1].translated(0, offset_y)
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

    activity = window.activity_bar
    window.show_page(window.GLOBAL_SETTINGS_PAGE)
    assert window.activity_layout.indexOf(activity) == 0
    assert activity.isVisible()
    window.show_page(0)
    assert window.home_root.indexOf(activity) == window.home_root.count() - 1
    assert rect(activity).top() - rect(window.quick_controls).bottom() - 1 == 12


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
    window.tune_button.click()
    assert window.stack.currentWidget() is window.xray_settings_page
    assert window.xray_settings_button.isChecked()


def test_verified_config_activation_and_maker_import_do_not_show_floating_labels(window):
    def profile(index):
        return ui.ProxyProfile(
            name=f"Sample {index}", source_uri=f"trojan://fixture-{index}@sample.example:443",
            verified_route=True, country_code="GB", origin=ui.USER_CONFIG_ORIGIN,
        )

    class FloatingLabels(QObject):
        def __init__(self):
            super().__init__()
            self.titles = []

        def eventFilter(self, widget, event):
            if event.type() == QEvent.Show and isinstance(widget, QLabel) and widget.isWindow():
                self.titles.append(widget.objectName())
            return False

    window.engine_buttons[ENGINE_XRAY].click()
    first, second = profile(1), profile(2)
    window.storage.profiles = [first, second]
    window.storage.selected_id = first.id
    probe = FloatingLabels()
    APP.installEventFilter(probe)
    try:
        window.refresh_profiles()
        window.show_page(1)
        table = window.user_config_list
        window.profile_tabs.setCurrentWidget(table)
        row = next(i for i in range(table.count()) if table.item(i).data(Qt.UserRole) == second.id)
        cell = table.cellWidget(row, ui.ProfileTable.ACTIONS)
        button = cell.findChild(QToolButton, "profileRowActivate")
        button.click()
        assert window.storage.selected_id == second.id
        assert table.cellWidget(row, ui.ProfileTable.ACTIONS) is cell
        assert not button.isEnabled()

        window.show_page(2)
        made = profile(3)
        window._maker_profiles["test-made"] = made
        window.maker_model.append_batch([
            {"key": "test-made", "uri": made.source_uri, "status": "healthy", "country_code": "GB"},
        ])
        window._maker_add_results("all")
        assert len(window.storage.profiles) == 3
        assert not probe.titles
    finally:
        APP.removeEventFilter(probe)


def test_repeated_toasts_reuse_the_frame_timer_and_keep_undo_working(window, monkeypatch):
    window.show_toast("First", undo=True)
    toast = window.centralWidget().findChild(QFrame, "toast")
    timer, animation = window._toast_timer, window._toast_animation
    for index in range(20):
        window.show_toast(str(index), "warning")
    assert window.centralWidget().findChildren(QFrame, "toast") == [toast]
    assert toast.findChild(QLabel, "toastText").text() == "19"
    assert window._toast_timer is timer
    assert window._toast_animation is animation

    monkeypatch.setattr(window, "undo_sni_apply", lambda: window.show_toast("Restored"))
    window.show_toast("Undo available", undo=True)
    toast.findChild(QPushButton, "toastAction").click()
    assert toast.isVisible()
    assert toast.findChild(QLabel, "toastText").text() == "Restored"
    timer.start(0)
    APP.processEvents()
    assert toast.isHidden()


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
def test_tun_turns_off_windows_proxy_without_reenabling_it_on_exit(window, engine):
    window.engine_buttons[engine].click()
    window._change_global_settings(connection_mode="proxy")
    assert window.proxy_mode.isEnabled() and window.proxy_mode.isChecked()
    window.tun_mode.click()
    assert window.tun_mode.isChecked()
    assert not window.proxy_mode.isChecked() and not window.proxy_mode.isEnabled()
    assert window.global_settings.snapshot().connection_mode == "vpn"
    window.proxy_mode.click()
    assert window.tun_mode.isChecked()
    assert not window.global_settings.snapshot().windows_proxy_enabled
    window.tun_mode.click()
    assert not window.tun_mode.isChecked()
    assert window.proxy_mode.isEnabled() and not window.proxy_mode.isChecked()
    window.proxy_mode.click()
    assert window.proxy_mode.isChecked() and not window.tun_mode.isChecked()


def test_direct_can_switch_to_tun_after_disabling_proxy_in_a_live_session(window, monkeypatch):
    window.engine_buttons[ENGINE_DIRECT].click()
    window._change_global_settings(connection_mode="local")
    controller = window.direct_controller
    coordinator = controller.coordinator
    restarts = []
    with monkeypatch.context() as session:
        session.setattr(coordinator, "_worker", object())
        session.setattr(coordinator, "_session_vpn", False)
        session.setattr(coordinator, "_status", DirectStatus(phase="connected"))
        session.setattr(controller, "restart_if_active", lambda: restarts.append("tun"))
        window.tun_mode.click()
        assert restarts == ["tun"]
        assert window.global_settings.snapshot().connection_mode == "vpn"
        assert not window.proxy_mode.isChecked() and not window.proxy_mode.isEnabled()


@pytest.mark.parametrize("engine", (ENGINE_DIRECT, ENGINE_POW))
@pytest.mark.parametrize("vpn", (False, True))
def test_live_windows_proxy_keeps_the_route_and_reflects_registry_state(window, monkeypatch, tmp_path, engine, vpn):
    window.engine_buttons[engine].click()
    controller = window.direct_controller if engine == ENGINE_DIRECT else window.pow_controller
    coordinator = controller.coordinator
    window.global_settings.change(connection_mode="vpn" if vpn else "proxy", kill_switch=vpn)
    registry_key = rf"Software\UAC-Proxy-Test-{uuid.uuid4().hex}"
    monkeypatch.setattr(engine_module, "INTERNET_SETTINGS", registry_key)
    monkeypatch.setattr(engine_module, "PROXY_STATE_FILE", tmp_path / "proxy-owner.json")
    monkeypatch.setattr(engine_module.WindowsProxy, "_refresh", staticmethod(lambda: None))
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, registry_key) as key:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "existing:8080")
    try:
        with socket.socket() as listener, monkeypatch.context() as session:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            proxy = engine_module.WindowsProxy(lambda _: None)
            proxy.bind_session(port, port, enabled=True, tun=vpn)
            session.setattr(coordinator, "_proxy", proxy)
            session.setattr(coordinator, "connect", lambda *_a, **_kw: pytest.fail("session recreated"))
            session.setattr(coordinator, "disconnect", lambda *_a, **_kw: pytest.fail("session stopped"))
            session.setattr(window, "_set_connection_visual", lambda *_a: pytest.fail("state redrawn"))
            notices = []
            session.setattr(window, "show_toast", lambda *args: notices.append(args))
            if engine == ENGINE_DIRECT:
                worker = object()
                status = DirectStatus(phase="connected", tx_bytes=1500, rx_bytes=2500, protected=vpn)
                session.setattr(coordinator, "_worker", worker)
                session.setattr(coordinator, "_session_vpn", vpn)
                session.setattr(coordinator, "_status", status)
                sync = controller.refresh_output_controls
            else:
                session.setattr(coordinator, "_proxy_mode", not vpn)
                session.setattr(coordinator, "_connected", threading.Event())
                session.setattr(coordinator, "_proxy_session", False)
                coordinator._connected.set()
                if vpn:
                    session.setattr(coordinator, "_kill_switch", SimpleNamespace(running=True))
                session.setattr(coordinator, "switch_exit_mode", lambda *_: pytest.fail("route replaced"))
                coordinator._status.update(PowPhase.CONNECTED, 100, "Verified route")
                status = coordinator._status.snapshot()
                sync = window._pow_sync_home_visuals
            sync()
            assert window.proxy_mode.isChecked() == window.proxy_mode.isEnabled() == (not vpn)
            if vpn:
                window.proxy_mode.click()
                with pytest.raises(RuntimeError, match="Turn off TUN"):
                    coordinator.set_system_proxy_enabled(True)
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_key) as key:
                    assert winreg.QueryValueEx(key, "ProxyEnable")[0] == 0
            for enabled in (() if vpn else (False, True) * 3):
                window.proxy_mode.click()
                assert window.proxy_mode.isChecked() == enabled == proxy.session_enabled
                assert window.global_settings.snapshot().windows_proxy_enabled == enabled
                assert not window.tun_mode.isChecked()
                assert coordinator._proxy is proxy
                assert not coordinator._stop.is_set()
                with socket.create_connection(("127.0.0.1", port), timeout=1), listener.accept()[0]:
                    pass
            if engine == ENGINE_DIRECT:
                assert coordinator.status is status and coordinator._worker is worker
            else:
                assert coordinator._status.snapshot() == status
                assert coordinator.session_proxy_mode == (not vpn)
            if not vpn:
                def refuse():
                    raise PermissionError("Windows rejected the write")
                with monkeypatch.context() as failure:
                    failure.setattr(proxy, "suspend", refuse)
                    window.proxy_mode.click()
                    assert window.proxy_mode.isChecked() and proxy.session_enabled
                    assert not window.tun_mode.isChecked()
                    assert len(notices) == 1
            proxy.restore_session()
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_key) as key:
            assert winreg.QueryValueEx(key, "ProxyServer")[0] == "existing:8080"
            assert winreg.QueryValueEx(key, "ProxyEnable")[0] == 1
    finally:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, registry_key)

    window.engine_buttons[ENGINE_XRAY].click()
    window.engine_buttons[engine].click()
    assert window.proxy_mode.isChecked() == window.proxy_mode.isEnabled() == (not vpn)
    assert window.tun_mode.isChecked() == vpn


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
    window._poll_traffic()
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


def test_direct_hero_uses_connection_phase_colors_and_off_title(window):
    window.engine_buttons[ENGINE_DIRECT].click()
    controller = window.direct_controller
    button = window.connect_button
    for phase, state, accent, button_text, border in (
        ("idle", "disconnected", "#ff974d", "#17110d", "#ffaa6d"),
        ("starting", "connecting", "#e9bc60", "#f3ce91", "#806039"),
        ("recovering", "connecting", "#e6a15c", "#ffd0a3", "#956238"),
        ("connected", "connected", "#65cba3", "#e1fff2", "#468f75"),
        ("stopping", "connecting", "#a1a8b0", "#c2c6cc", "#494d52"),
        ("error", "error", "#f18a98", "#ffe4e8", "#a54c5b"),
        ("idle", "disconnected", "#ff974d", "#17110d", "#ffaa6d"),
    ):
        status = DirectStatus(phase=phase)
        controller.coordinator._status = status
        controller._show_status(status)
        assert window.orb.state == state
        assert window.orb._current_color() == QColor(accent)
        assert window.status_pill.label.palette().color(QPalette.WindowText) == QColor(accent)
        assert button.palette().color(QPalette.ButtonText) == QColor(button_text)
        image = button.grab().toImage()
        assert image.pixelColor(image.width() // 2, 0) == QColor(border)
        if phase == "connected":
            assert window.status.palette().color(QPalette.WindowText) == QColor("#CFFFF9")
            assert window.status.property("i18nEn") == "VPN is ON"
            assert "color:#3CF0AF'>ON" in window.status.text()
    assert window.status.property("i18nEn") == "VPN is OFF"
    window.language = "fa"
    window._apply_language()
    assert "خاموش" in window.status.text() and "VPN" in window.status.text()
    window._set_connection_visual("connected")
    assert window.status.property("i18nFa") == f"{ui.ltr_isolate('VPN')} متصل است"
    assert "color:#3CF0AF'>متصل" in window.status.text()


def test_dashboard_status_text_fits_in_both_languages(window):
    window.engine_buttons[ENGINE_DIRECT].click()
    pill = window.status_pill
    for language in ("fa", "en"):
        window.language = language
        window._apply_language()
        for state in ("disconnected", "connecting", "connected", "paused", "error"):
            window._set_connection_visual(state)
            if state == "connected":
                pill._connected_at -= 123 * 3600
                pill._show_session_time()
            APP.processEvents()
            assert pill.label.width() >= pill.label.sizeHint().width(), pill.label.text()


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
        "Appearance", "Connection & routing", "Network sharing", "Security & privacy", "Tools & backup",
    ]
    toggle_names = {"iran_direct", "auto_connect", "lan_share", "kill_switch", "ipv6_block",
                    "dns_sinkhole", "webrtc_block", "quic_block"}
    assert set(page.controls) == toggle_names | {"lan_share_mode", "lan_share_port"}
    assert not sections[1].icon.pixmap().isNull()
    settings = window.global_settings
    window._change_global_settings(connection_mode="vpn")
    assert not page.controls["kill_switch"].isEnabled()
    assert not page.controls["lan_share"].isEnabled()
    window.engine_buttons[ENGINE_POW].click()
    monkeypatch.setattr(window._auto_connect, "configure", lambda: None)
    page.motion.setChecked(not page.motion.isChecked())
    assert settings.reduce_navigation_motion == page.motion.isChecked()
    for name in toggle_names:
        control = page.controls[name]
        assert control.isEnabled()
        control.click()
        assert getattr(settings.snapshot(), name) == control.isChecked()
    page.routing_link.click()
    routing = window.direct_routing_view
    assert window.stack.currentWidget() is routing
    routing.domains.address.setText("example.com, cdn.example.net")
    routing.domains.address.returnPressed.emit()
    routing.ips.address.setText("192.0.2.5, 192.0.2.5/32, 2001:db8:1::4/64")
    routing.ips.address.returnPressed.emit()
    assert settings.snapshot().domains_direct == ""
    routing.save.click()
    assert "cdn.example.net" in settings.snapshot().domains_direct
    assert settings.snapshot().ips_direct == "192.0.2.5, 2001:db8:1::/64"
    routing._go_back()
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


def test_disabled_global_settings_show_a_reason_at_the_pointer(window, monkeypatch):
    window.global_settings.set_navigation_motion(True)
    window.engine_buttons[ENGINE_XRAY].click()
    window.show_page(window.GLOBAL_SETTINGS_PAGE)
    page = window.global_settings_page
    tips = []
    monkeypatch.setattr(QToolTip, "showText", lambda pos, message, *_: tips.append((pos, message)))

    def click(key):
        control = page.controls[key]
        page.scroll.ensureWidgetVisible(control)
        APP.processEvents()
        center = control.rect().center()
        QTest.mouseClick(window.windowHandle(), Qt.LeftButton, Qt.NoModifier, control.mapTo(window, center))
        return control.mapToGlobal(center)

    window._change_global_settings(connection_mode="proxy")
    pos = click("ipv6_block")
    assert tips[-1] == (pos, "Turn on TUN mode to change this setting.")
    click("lan_share")
    assert tips[-1][1] == "Select PoW to configure connection sharing."
    click("kill_switch")
    assert tips[-1][1] == "Use PoW or Direct in TUN mode for the kill switch."

    window.engine_buttons[ENGINE_POW].click()
    window._change_global_settings(connection_mode="vpn")
    monkeypatch.setattr(window, "_engine_busy", lambda: True)
    page.refresh_capabilities()
    click("kill_switch")
    assert tips[-1][1] == "Disconnect first to change the kill switch."

    tip_count = len(tips)
    was_enabled = window.global_settings.snapshot().ipv6_block
    click("ipv6_block")
    assert window.global_settings.snapshot().ipv6_block != was_enabled
    assert len(tips) == tip_count


@pytest.mark.parametrize("engine", (ENGINE_XRAY, ENGINE_POW, ENGINE_DIRECT))
def test_global_auto_connect_uses_current_engine_after_network_return(window, monkeypatch, engine):
    reachability = QNetworkInformation.Reachability
    window.engine_buttons[engine].click()
    window.global_settings.change(auto_connect=True)
    calls = []
    monkeypatch.setattr(window, "toggle_connection", lambda *, automatic: calls.append((window.engine_mode, automatic)))
    window._auto_connect.observe(reachability.Online)
    window._auto_connect.user_stopped()
    window._auto_connect.observe(reachability.Local)
    window._auto_connect.observe(reachability.Online)
    window._auto_connect.observe(reachability.Disconnected)
    window._auto_connect.observe(reachability.Online)
    assert calls == [(engine, True), (engine, True)]


def test_global_settings_geometry_is_shared_in_both_languages(window):
    window.global_settings.set_navigation_motion(True)
    window.show_page(window.GLOBAL_SETTINGS_PAGE)
    page = window.global_settings_page
    sections = page.findChildren(QFrame, "globalSettingsSection")
    for language in ("en", "fa"):
        window.language = language
        window._apply_language()
        for width in (1080, 1400):
            window.resize(width, 780)
            reference = None
            for engine in (ENGINE_XRAY, ENGINE_POW, ENGINE_DIRECT):
                window.engine_buttons[engine].click()
                APP.processEvents()
                assert window.stack.currentWidget() is page
                rects = [section.geometry().getRect() for section in sections]
                if reference is None:
                    reference = rects
                assert rects == reference


def test_direct_dashboard_has_no_pause_or_resume_button(window):
    window.engine_buttons[ENGINE_DIRECT].click()
    direct = window.direct_controller
    coordinator = direct.coordinator
    coordinator._worker = object()
    try:
        for vpn, phase in ((True, "connected"), (False, "connected"), (False, "paused")):
            coordinator._session_vpn = vpn
            coordinator._status = DirectStatus(phase=phase)
            direct._show_status(coordinator.status)
            assert not hasattr(window, "pause_button")
            assert window.connect_button.text() == "Disconnect"
    finally:
        coordinator._worker = None


def test_pow_connected_dashboard_hides_pause(window, monkeypatch):
    window.engine_buttons[ENGINE_POW].click()
    controller = window.pow_controller
    monkeypatch.setattr(type(controller.coordinator), "session_proxy_mode", property(lambda _: True))
    controller.status.update(PowPhase.CONNECTED, 100, "Verified route")
    window._set_connection_visual("connected")
    assert not hasattr(window, "pause_button")
    assert window.connect_button.text() == "Disconnect"


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
