from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from PySide6.QtCore import QLocale, QObject, QSignalBlocker, Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog, QLineEdit, QSpinBox, QWidget,
)

from .direct.coordinator import DirectCoordinator, DirectOptions, DirectStatus
from .paths import DATA_DIR
from .pow.regions import BUNDLED, region_name
from .pow_ui import PowCountryPicker
from .settings_ui import SettingsCard, SettingsGrid, SettingsPage, SettingsRow, SettingsSelect, engine_backup_card

ENGINE_DIRECT = "direct"


class DirectPanel(QObject):
    _status = Signal(object)

    def __init__(self, window) -> None:
        super().__init__(window)
        self.window = window
        self.coordinator = DirectCoordinator(Path(DATA_DIR) / "direct", Path(DATA_DIR) / "pow",
                                             status=self._status.emit, log=self._forward_log)
        self.store = self.coordinator.store
        self._status.connect(self._show_status, Qt.QueuedConnection)
        self._reconnect = False
        self._phase = None
        self._choices = {}
        self._toggles = {}
        self._fields = {}

    @property
    def busy(self) -> bool:
        return self.coordinator.active

    def open_settings(self) -> None:
        self.window.show_page(self.window.DIRECT_SETTINGS_PAGE)

    def build_settings_page(self) -> QWidget:
        w = self.window
        page = SettingsPage(w, "تنظیمات Direct", "Direct Settings",
                            "روش اتصال، کشف مسیر و DNS موتور Direct را تنظیم کنید.",
                            "Configure Direct connection methods, route discovery, and DNS.",
                            categories=(("اتصال", "Connection"), ("رفتار بسته‌ها", "Packet behavior")))
        connection = SettingsCard(w, "اتصال و کشف مسیر", "Connection and discovery", icon="route")
        self._choice(connection, "wireguard_over_direct", "روش اتصال", "Connection method", (
            (True, "وایرگارد روی Direct", "WireGuard over Direct"), (False, "TLS مستقیم", "Direct TLS"),
        ))
        self._choice(connection, "scan_mode", "عمق اسکن", "Scan depth", (
            ("turbo", "سریع", "Turbo"), ("balanced", "متعادل", "Balanced"), ("thorough", "عمیق", "Deep"),
        ), hint=("برای کشف مسیر وایرگارد استفاده می‌شود.", "Used for WireGuard route discovery."))
        dns = SettingsCard(w, "سامانهٔ نام دامنه", "DNS resolvers", icon="database")
        self._toggle(dns, "auto_select_dns", "انتخاب خودکار DNS", "Automatic DNS selection")
        self._field(dns, "unfiltered_dns", "DNS جایگزین", "Fallback DNS",
                    hint=("اگر در آزمایشگاه DNS سروری انتخاب نشده باشد، از این آدرس استفاده می‌شود.",
                          "Used when no resolver is selected in DNS Lab."))
        self._field(dns, "domestic_dns", "DNS داخلی", "Domestic DNS")
        backup = engine_backup_card(w, lambda: self._export(page), lambda: self._import(page))
        page.category(0).addWidget(SettingsGrid((connection, dns, backup)))
        page.category(0).addStretch(1)

        fragments = SettingsCard(w, "قطعه‌بندی TCP", "TCP fragmentation", icon="sliders")
        self._toggle(fragments, "tcp_fragment_enabled", "تقسیم بسته‌های TCP بدون TLS", "Split non-TLS TCP packets",
                     hint=("در حالت TLS مستقیم در دسترس است.", "Available with Direct TLS."))
        for key, fa, en in (
            ("tcp_lengths", "طول قطعهٔ TCP", "TCP fragment length"),
            ("tcp_delays", "وقفهٔ قطعهٔ TCP", "TCP fragment delay"),
            ("tcp_max_split", "سقف تقسیم TCP", "TCP maximum splits"),
        ):
            self._field(fragments, key, fa, en)
        transport = SettingsCard(w, "رفتار انتقال", "Transport behavior", icon="activity")
        self._toggle(transport, "udp_noise", "نویز UDP", "UDP noise",
                     hint=("در حالت TLS مستقیم در دسترس است.", "Available with Direct TLS."))
        self._toggle(transport, "block_quic", "جلوگیری از QUIC", "Block QUIC",
                     hint=("گزینهٔ سازگاری با مرورگر.", "Browser compatibility setting."))
        self._toggle(transport, "ipv6", "فعال‌سازی IPv6 در Direct", "Enable IPv6 in Direct")
        page.category(1).addWidget(SettingsGrid((fragments, transport)))
        page.category(1).addStretch(1)
        return page

    def _choice(self, group, name, fa, en, items, *, hint=("", "")) -> None:
        combo = SettingsSelect()
        self._choices[name] = (combo, items)
        combo.currentIndexChanged.connect(lambda: self.save(name, combo.currentData()))
        group.add(SettingsRow(self.window, (fa, en), hint, combo, stacked=True))

    def _toggle(self, group, name, fa, en, *, hint=("", "")) -> None:
        from .ui import ToggleSwitch

        toggle = ToggleSwitch()
        toggle.toggled.connect(lambda value: self.save(name, value))
        self._toggles[name] = toggle
        group.add(SettingsRow(self.window, (fa, en), hint, toggle))

    def _field(self, group, name, fa, en, *, hint=("", "")):
        if name == "tcp_max_split":
            control = QSpinBox()
            control.setObjectName("settingsNumber")
            control.setLocale(QLocale.c())
            control.setRange(0, 1000)
            control.setMaximumWidth(120)
            control.valueChanged.connect(lambda value: self.save(name, value))
        else:
            control = QLineEdit()
            control.setObjectName("settingsInput")
            if name.startswith("tcp_"):
                control.setMaximumWidth(230)
            control.editingFinished.connect(lambda: self.save(name, control.text()))
        control.setProperty("technical", True)
        control.setLayoutDirection(Qt.LeftToRight)
        self._fields[name] = control
        group.add(SettingsRow(self.window, (fa, en), hint, control, stacked=True))

    def effective_settings(self):
        return self.window.global_settings.snapshot().for_direct(self.store.settings())

    def apply_dns(self, address: str) -> bool:
        settings = replace(self.store.settings(), pinned_dns=address, auto_select_dns=not address)
        saved = self.store.save_settings(settings, exclude=self.window.global_settings.direct_legacy_fields)
        reload_requested = self.coordinator.reload_dns(saved)
        self.refresh()
        return reload_requested

    def refresh(self) -> None:
        if self.window.engine_mode != ENGINE_DIRECT or not hasattr(self.window, "home_header"):
            self._phase = None
            return
        settings = self.effective_settings()
        for key, (combo, items) in self._choices.items():
            with QSignalBlocker(combo):
                combo.clear()
                for value, fa, en in items:
                    combo.addItem(self.window._ui_text(fa, en), value)
                value = getattr(settings, key)
                selected = combo.findData(value)
                if selected < 0:
                    combo.addItem(str(value).upper(), value)
                    selected = combo.count() - 1
                combo.setCurrentIndex(selected)
        for name, toggle in self._toggles.items():
            self.window._pow_set_toggle(toggle, getattr(settings, name))
        for name, edit in self._fields.items():
            with QSignalBlocker(edit):
                if isinstance(edit, QSpinBox):
                    edit.setValue(getattr(settings, name))
                elif not edit.hasFocus():
                    edit.setText(getattr(settings, name))
        if self._choices:
            self._choices["scan_mode"][0].setEnabled(settings.wireguard_over_direct)
            self._toggles["udp_noise"].setEnabled(not settings.wireguard_over_direct)
            self._toggles["tcp_fragment_enabled"].setEnabled(not settings.wireguard_over_direct)
            for key in ("tcp_lengths", "tcp_delays", "tcp_max_split"):
                self._fields[key].setEnabled(not settings.wireguard_over_direct and settings.tcp_fragment_enabled)
        self.window._pow_set_toggle(self.window.auto_mode, settings.auto_select_dns)
        self.refresh_output_controls()
        self.refresh_country(settings)
        self._show_status(self.coordinator.status, redraw=True)

    def refresh_output_controls(self) -> None:
        w = self.window
        preferences = w.global_settings.snapshot()
        actual_vpn = self.coordinator.session_vpn
        if self.coordinator.status.phase == "stopping":
            actual_vpn = None
        tun_on = preferences.connection_mode == "vpn" if actual_vpn is None else actual_vpn
        actual_proxy = self.coordinator.system_proxy_enabled
        proxy_on = preferences.windows_proxy_enabled if actual_proxy is None else actual_proxy
        w._sync_tun_proxy_controls(tun_on, proxy_on)

    def refresh_country(self, settings=None) -> None:
        from .ui import country_flag_badge, cyber_pixmap

        w = self.window
        settings = settings or self.store.settings()
        button = w.pow_country_button
        code = settings.exit_country_code.upper() if settings.wireguard_over_direct else ""
        if code:
            title = region_name(code)
            subtitle = w.tr("خروجی انتخاب‌شدهٔ سایفون", "Selected Psiphon exit")
        elif settings.wireguard_over_direct:
            title = w.tr("خودکار", "Automatic")
            subtitle = w.tr("خروجی وارپ", "WARP exit")
        else:
            title = w.tr("TLS مستقیم", "Direct TLS")
            subtitle = w.tr("خروجی شبکهٔ محلی", "Local network exit")
        button.set_value(country_flag_badge(code, 38) if code else cyber_pixmap("zap", "#ffad6e", 22), title, subtitle)
        button.setEnabled(settings.wireguard_over_direct)
        button.setAccessibleName("Direct exit country")
        button.setToolTip(w.tr("انتخاب کشور خروجی", "Choose the exit country") if settings.wireguard_over_direct else
                          w.tr("انتخاب کشور با وایرگارد در دسترس است.", "Country selection is available with WireGuard."))
        w.country_description.setText(w.tr("وایرگارد از مسیر WARP یا سایفون", "WireGuard via WARP or Psiphon") if settings.wireguard_over_direct else
                                      w.tr("خروجی شبکهٔ محلی", "Local network exit"))
        w.country_description.setToolTip(w.tr("خودکار از وارپ استفاده می‌کند. انتخاب کشور مسیر خروجی سایفون را فعال می‌کند.",
                                           "Automatic uses WARP. Selecting a country uses a Psiphon exit.") if settings.wireguard_over_direct else
                                      w.tr("TLS مستقیم از مسیر شبکهٔ فعلی استفاده می‌کند.", "Direct TLS uses the current network route."))

    def open_country_picker(self) -> None:
        settings = self.store.settings()
        if settings.wireguard_over_direct:
            code = settings.exit_country_code.upper()
            countries = {**BUNDLED, code: region_name(code)} if code else BUNDLED
            dialog = PowCountryPicker(self.window, code, countries=countries, nearby=False)
            try:
                if dialog.exec() and dialog.selected_code is not None:
                    self.save("exit_country_code", dialog.selected_code)
            finally:
                dialog.deleteLater()

    def save(self, field: str, value) -> None:
        previous = self.store.settings()
        if value == getattr(previous, field):
            return
        try:
            self.store.save_settings(replace(previous, **{field: value}),
                                     exclude=self.window.global_settings.direct_legacy_fields)
        except OSError as error:
            self.window.show_toast(str(error), "danger")
            self.refresh()
            return
        self.refresh()
        if field in ("wireguard_over_direct", "exit_country_code"):
            if self.busy:
                self.window._set_activity("در حال اتصال دوباره با مسیر Direct انتخاب‌شده…",
                                          "Reconnecting with the selected Direct route…", "running", True)
            self.restart_if_active()

    def start(self) -> None:
        if self.busy or self.window.engine_mode != ENGINE_DIRECT or self.window._closing:
            return
        preferences = self.window.global_settings.snapshot()
        settings = preferences.for_direct(self.store.settings())
        options = DirectOptions(vpn=settings.connection_mode == "vpn", kill_switch=settings.kill_switch,
                                routing_mode=settings.routing_mode, processes=self.window.global_settings.processes(),
                                privacy=preferences,
                                system_proxy=preferences.windows_proxy_enabled)
        self.coordinator.connect(options, settings=settings)

    def toggle(self) -> None:
        if self.busy:
            self.stop()
        else:
            self.start()

    def stop(self) -> None:
        self._reconnect = False
        self.coordinator.disconnect()

    def restart_if_active(self) -> None:
        if self.busy and self.window.engine_mode == ENGINE_DIRECT:
            self._reconnect = True
            self.coordinator.disconnect()

    def shutdown(self) -> bool:
        page = getattr(self.window, "dns_lab_page", None)
        if page is not None:
            page.stop_scan()
        self.stop()
        return self.coordinator.wait(12) and not self.coordinator.status.disconnect_failed

    def _show_status(self, status: DirectStatus, *, redraw=False) -> None:
        if status != self.coordinator.status:
            return
        w = self.window
        if w.engine_mode != ENGINE_DIRECT or w._closing:
            return
        page = getattr(w, "dns_lab_page", None)
        if page is not None:
            page.set_route_status(status)
        from .ui import country_flag_icon, ltr_isolate

        phase = status.phase
        active = phase in ("connected", "paused")
        if redraw or phase != self._phase:
            self._phase = phase
            if not redraw:
                self.refresh_output_controls()
            visual = {"idle": "disconnected", "stopping": "disconnecting", "error": "error",
                      "connected": "connected", "paused": "paused"}.get(phase, "connecting")
            w._set_connection_visual(visual, direct_color_state="reconnecting" if phase == "recovering" else None)
            if phase == "error" and self.busy:
                w.connect_button.setText(w.tr("قطع اتصال", "Disconnect"))
                w.connect_button.setProperty("i18nFa", "قطع اتصال")
                w.connect_button.setProperty("i18nEn", "Disconnect")
            activity = {
                "idle": ("UAC Direct آماده است.", "UAC Direct is ready.", "idle", False),
                "connected": ("مسیر Direct تأیید شد.", "The Direct route is verified.", "success", False),
                "paused": ("Direct در حالت مکث است.", "Direct is paused.", "warning", False),
                "stopping": ("در حال بستن نشست Direct…", "Closing the Direct session…", "running", True),
                "error": ("اتصال Direct ناموفق بود.", "Direct connection failed.", "error", False),
            }
            w._set_activity(*activity.get(phase, ("در حال بررسی مسیر Direct…", "Checking the Direct route…", "running", True)))
        w._refresh_app_routing_notice()
        progress = f" · {status.progress}%" if 0 < status.progress < 100 and phase != "stopping" else ""
        if phase in ("starting", "checking", "recovering"):
            hints = {"starting": ("در حال آماده‌سازی مسیر Direct", "Preparing the Direct route"),
                     "checking": ("در حال بررسی DNS و HTTPS", "Verifying DNS and HTTPS"),
                     "recovering": ("در حال بازیابی مسیر Direct", "Recovering the Direct route")}
            w.connection_hint.setText(w.tr(*hints[phase]) + progress)
        if status.protected and phase == "error":
            w.connection_hint.setText(w.tr("اتصال قطع است و کلید قطع VPN فعال است.", "Disconnected. VPN kill switch is active."))
        w.connection_hint.setToolTip(status.detail)

        route = w.tr("وایرگارد", "WireGuard") if status.carrier and phase != "paused" else w.tr("TLS مستقیم", "Direct TLS")
        w.active_profile.setText(route if active else "—")
        ports = " · ".join(port for port in (
            f"SOCKS {status.socks_port}" if status.socks_port else "", f"HTTP {status.http_port}" if status.http_port else "",
        ) if port)
        guard = w.tr("کلید قطع VPN فعال است", "VPN kill switch active") if status.protected else ""
        w.active_profile.setToolTip("\n".join(filter(None, (route if active else "", status.carrier, ports, guard))))
        w.route_card.set_secondary((status.carrier or ports) if active else "")
        w.network_metrics.set_latency(
            status.dns_ms if phase == "connected" and status.dns_ms else None,
            w.tr(f"زمان پاسخ DNS · {ltr_isolate(status.resolver)}", f"DNS response · {status.resolver}")
            if phase == "connected" and status.resolver else "",
        )
        if active:
            w._display_traffic(status.tx_bytes, status.rx_bytes, sample=phase == "connected" and not redraw)
        w.ip_label.setText(status.exit_ip if active and status.exit_ip else "—")
        code = status.country.upper() if active and status.exit_ip else ""
        w.ip_card.set_secondary(region_name(code) if code else "")
        if code:
            w.ip_flag.setPixmap(country_flag_icon(code, 22, 16).pixmap(22, 16))
            w.ip_flag.setToolTip(region_name(code))
        w.ip_flag.setVisible(bool(code))
        w.ip_button.setEnabled(active)
        w.ip_parallel.hide()
        if status.phase == "idle" and self._reconnect:
            self._reconnect = False
            self.start()

    def _forward_log(self, line: str) -> None:
        self.window.bridge.engine_log.emit(line if line.startswith("Direct ") else f"Direct: {line}", ENGINE_DIRECT)

    def _export(self, dialog: QWidget) -> None:
        filename, _ = QFileDialog.getSaveFileName(dialog, "UAC Direct", "uac-direct-settings.json", "JSON (*.json)")
        if filename:
            try:
                self.store.export_settings(Path(filename), exclude=self.window.global_settings.direct_legacy_fields)
            except OSError as error:
                self.window.show_toast(str(error), "danger")

    def _import(self, dialog: QWidget) -> None:
        filename, _ = QFileDialog.getOpenFileName(dialog, "UAC Direct", "", "JSON (*.json)")
        if filename:
            try:
                self.store.import_settings(Path(filename), exclude=self.window.global_settings.direct_legacy_fields)
                self.refresh()
            except (OSError, ValueError) as error:
                self.window.show_toast(str(error), "danger")
