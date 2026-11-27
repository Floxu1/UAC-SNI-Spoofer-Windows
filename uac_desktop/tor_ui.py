"""UAC Tor UI panel: Full Autopilot, Clean Bridge Source Selector, Manual Bridge Box & Settings."""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import threading
import webbrowser
from dataclasses import replace
from pathlib import Path

from PySide6.QtCore import QLocale, QObject, QSignalBlocker, Qt, Signal
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QMessageBox, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QSpinBox, QWidget,
)

from .paths import DATA_DIR
from .pow.regions import ALL_NAMES, region_name
from .pow_ui import PowCountryPicker
from .settings_ui import (
    SettingsCard, SettingsGrid, SettingsPage, SettingsRow, SettingsSelect,
    engine_backup_card, settings_button,
)
from .tor.bridges import (
    auto_fetch_bridges,
    extract_bridges_from_text,
    rank_reachable_bridges,
    summarize_bridge_counts,
)
from .tor.coordinator import TorCoordinator, TorOptions, TorStatus
from .tor.output import is_admin

ENGINE_TOR = "tor"

_TRANSPORT_ITEMS = (
    ("auto", "تمام‌خودکار / Autopilot (پیشنهادی)", "Full Autopilot (Recommended)"),
    ("webtunnel", "دستی: WebTunnel", "Manual: WebTunnel"),
    ("snowflake", "دستی: Snowflake", "Manual: Snowflake"),
    ("obfs4", "دستی: obfs4", "Manual: obfs4"),
    ("custom", "دستی: فقط پل‌های ذخیره‌شده من", "Manual: Saved custom bridges only"),
    ("direct", "دستی: مستقیم بدون پل", "Manual: Direct (no bridge)"),
)
_BRIDGE_SOURCE_ITEMS = (
    ("auto", "خودکار (همه مسیرها — پیشنهادی)", "Auto (All sources — Recommended)"),
    ("moat", "سرور رسمی Tor (Moat API)", "Official Tor Server (Moat API)"),
    ("mirrors", "آینه‌های رسمی (GitHub / CDN / GitLab)", "Official Mirrors (GitHub / CDN / GitLab)"),
    ("relay", "رله اختصاصی (Cloudflare Worker)", "Custom Relay (Cloudflare Worker)"),
    ("bundled", "پل‌های داخلی آفلاین بسته Tor", "Bundled Offline Tor Bridges"),
)
_BRIDGE_FETCH_TYPES = (
    ("webtunnel", "WebTunnel", "WebTunnel"),
    ("obfs4", "obfs4", "obfs4"),
    ("snowflake", "Snowflake", "Snowflake"),
)


class TorPanel(QObject):
    _status = Signal(object)
    _bridges_fetched = Signal(object)
    _bridges_tested = Signal(object)
    _core_downloaded = Signal(bool, str)

    def __init__(self, window) -> None:
        super().__init__(window)
        self.window = window
        self.coordinator = TorCoordinator(
            Path(DATA_DIR) / "tor", status=self._status.emit, log=self._forward_log
        )
        self.store = self.coordinator.store
        self._status.connect(self._show_status, Qt.QueuedConnection)
        self._bridges_fetched.connect(self._on_bridges_fetched, Qt.QueuedConnection)
        self._bridges_tested.connect(self._on_bridges_tested, Qt.QueuedConnection)
        self._core_downloaded.connect(self._on_core_downloaded, Qt.QueuedConnection)
        self._reconnect = False
        self._phase = None
        self._fetch_cancel = threading.Event()
        self._fetching = False
        self._choices = {}
        self._toggles = {}
        self._fields = {}
        self._bridges_edit = None
        self._bridge_counter = None
        self._fetch_type_combo = None
        self._bridge_status = None
        self._fetch_btn = None
        self._test_btn = None
        self._autopilot_label = None
        self._circuit_label = None
        self._newnym_btn = None
        self._clear_cache_btn = None
        self._download_core_btn = None

    @property
    def busy(self) -> bool:
        return self.coordinator.active

    def open_settings(self) -> None:
        self.window.show_page(self.window.TOR_SETTINGS_PAGE)

    def build_settings_page(self) -> QWidget:
        w = self.window
        page = SettingsPage(
            w,
            "تنظیمات Tor", "Tor Settings",
            "حالت تمام‌خودکار (Autopilot)، انتخاب منبع دریافت پل‌ها، پل‌های دستی و تنظیمات پیشرفته Tor.",
            "Full Autopilot, bridge source selection, manual bridges, relay options, and Tor identity.",
            categories=(
                ("اتصال و خودکار", "Connection & Autopilot"),
                ("پل‌ها (خودکار و دستی)", "Bridges (Auto & Manual)"),
                ("گره‌ها و امنیت مدار", "Nodes & Circuit"),
                ("پورت‌ها و هویت", "Ports & Identity"),
            ),
        )

        # ---- Tab 0: Connection & Autopilot ----
        conn = SettingsCard(w, "حالت اتصال (تمام‌خودکار یا دستی)", "Connection mode (Autopilot or Manual)", icon="route")
        self._choice(conn, "transport", "حالت ترابری Tor", "Tor transport mode", _TRANSPORT_ITEMS,
                     hint=("در حالت تمام‌خودکار، فقط اتصال را بزنید؛ ترابری و دریافت پل به‌صورت خودکار انجام می‌شود.",
                           "In Autopilot, just click Connect: transport and bridge fetching run automatically."))
        self._autopilot_label = QLabel()
        self._autopilot_label.setObjectName("settingsRowHelp")
        self._autopilot_label.setWordWrap(True)
        self._autopilot_label.setContentsMargins(6, 2, 6, 4)
        conn.body.addWidget(self._autopilot_label)
        self._toggle(conn, "auto_fetch_bridges", "دریافت خودکار پل در حالت دستی", "Auto-fetch bridges in manual mode",
                     hint=("در حالت تمام‌خودکار همیشه فعال است؛ این گزینه برای حالت‌های دستی است.",
                           "Always active in Autopilot; controls auto-fetching when a manual transport is selected."))
        self._choice(conn, "bridge_source", "منبع دریافت پل‌ها", "Bridge acquisition source", _BRIDGE_SOURCE_ITEMS,
                     hint=("انتخاب کنید پل‌ها از چه طریقی گرفته شوند؛ گزینه «خودکار» همه مسیرها را با عبور هوشمند از فیلتر امتحان می‌کند.",
                           "Choose how bridges are acquired. 'Auto' tries all sources with silent censorship bypass."))

        resilience = SettingsCard(w, "پایداری و پروکسی بالادستی", "Resilience & upstream proxy", icon="sliders")
        self._spin_field(resilience, "bootstrap_timeout_s", "مهلت اولیه بوت‌استرپ (ثانیه)", "Bootstrap timeout (seconds)",
                         25, 180,
                         hint=("پس از اتصال به پل (بالای ۱۴٪)، مهلت به‌صورت خودکار برای دریافت اجماع تمدید می‌شود.",
                               "Automatically extends once a bridge connects (>14%) to finish consensus download."))
        self._spin_field(resilience, "stall_fail_s", "تشخیص توقف سریع (ثانیه)", "Fast-fail stall threshold (seconds)",
                         12, 60,
                         hint=("اگر زیر ۱۰٪ بدون پاسخ ماند، سریع سراغ ترابری بعدی برود.",
                               "Switches quickly to the next transport if stalled below 10%."))
        self._toggle(resilience, "auto_reconnect", "اتصال مجدد خودکار هنگام قطعی", "Auto-reconnect on drop",
                     hint=("در صورت قطع ناخواسته Tor، خودکار مدار را بازسازی کند.",
                           "Automatically rebuilds the Tor session if the process exits unexpectedly."))
        self._field(resilience, "upstream_proxy", "پروکسی بالادستی (اختیاری)", "Upstream proxy (optional)",
                    hint=("زنجیره Tor روی پروکسی دیگر، مثلاً socks5://127.0.0.1:20808 یا http://127.0.0.1:20809.",
                          "Optional upstream proxy, e.g. socks5://127.0.0.1:20808 or http://127.0.0.1:20809."))

        page.category(0).addWidget(SettingsGrid((conn, resilience)))
        page.category(0).addStretch(1)

        # ---- Tab 1: Bridges (Auto Source + Manual Box) ----
        auto_card = SettingsCard(w, "دریافت خودکار پل از مسیرهای مختلف", "Automatic bridge fetcher", icon="sparkles")
        self._fetch_type_combo = SettingsSelect()
        for val, fa, en in _BRIDGE_FETCH_TYPES:
            self._fetch_type_combo.addItem(w._ui_text(fa, en), val)
        auto_card.add(SettingsRow(
            w, ("نوع پل برای دریافت", "Bridge type to fetch"),
            ("WebTunnel ترافیک Tor را شبیه HTTPS معمولی می‌کند.", "WebTunnel disguises Tor inside standard HTTPS."),
            self._fetch_type_combo, stacked=True,
        ))
        self._field(auto_card, "bridge_relay_url", "آدرس رله Worker یا فایل آینه (اختیاری)", "Worker relay or mirror URL (optional)",
                    hint=("نشانی Cloudflare Worker یا لینک خام لیست پل‌ها برای گزینه رله.",
                          "Cloudflare Worker relay or raw .txt/.json bridge mirror URL."))

        auto_actions = QHBoxLayout()
        auto_actions.setContentsMargins(6, 6, 6, 4)
        auto_actions.setSpacing(8)
        self._fetch_btn = settings_button(w, ("دریافت خودکار پل", "Auto-fetch bridges"), icon="download")
        self._fetch_btn.clicked.connect(self._fetch_bridges_now)
        self._test_btn = settings_button(w, ("تست دسترسی و مرتب‌سازی", "Test & rank reachability"), icon="activity")
        self._test_btn.clicked.connect(self._test_bridges_now)
        auto_actions.addWidget(self._fetch_btn)
        auto_actions.addWidget(self._test_btn)
        auto_actions.addStretch(1)
        auto_card.body.addLayout(auto_actions)

        self._bridge_status = QLabel()
        self._bridge_status.setObjectName("settingsRowHelp")
        self._bridge_status.setWordWrap(True)
        self._bridge_status.setContentsMargins(6, 2, 6, 4)
        auto_card.body.addWidget(self._bridge_status)

        self._bridge_counter = QLabel()
        self._bridge_counter.setObjectName("powPickerCount")
        manual_card = SettingsCard(
            w,
            "دریافت دستی، چسباندن و ذخیره پل‌ها",
            "Manual bridge input & manager",
            icon="file-cog",
            trailing=self._bridge_counter,
        )
        manual_hint = w._bind_text(
            QLabel(),
            "پل‌های WebTunnel، obfs4 یا Snowflake را اینجا پیست کنید (متن‌های اضافه خودکار حذف می‌شوند) و ذخیره بزنید.",
            "Paste WebTunnel, obfs4, or Snowflake lines here (extra prose is stripped automatically) and save.",
        )
        manual_hint.setObjectName("settingsRowHelp")
        manual_hint.setWordWrap(True)
        manual_hint.setContentsMargins(6, 4, 6, 4)
        manual_card.body.addWidget(manual_hint)

        get_row = QHBoxLayout()
        get_row.setContentsMargins(6, 2, 6, 6)
        get_row.setSpacing(6)
        paste_btn = settings_button(w, ("چسباندن از کلیپ‌بورد", "Paste clipboard"), icon="copy")
        paste_btn.clicked.connect(self._paste_bridges)
        web_btn = settings_button(w, ("سایت رسمی Tor Bridges", "Tor Bridges web"), icon="external-link")
        web_btn.clicked.connect(lambda: webbrowser.open("https://bridges.torproject.org/options"))
        tg_btn = settings_button(w, ("ربات تلگرام @GetBridgesBot", "Telegram @GetBridgesBot"), icon="external-link")
        tg_btn.clicked.connect(lambda: webbrowser.open("https://t.me/GetBridgesBot"))
        imp_btn = settings_button(w, ("ورود فایل", "Import file"), icon="folder")
        imp_btn.clicked.connect(lambda: self._import_bridges_file(page))
        exp_btn = settings_button(w, ("خروجی فایل", "Export file"), icon="download")
        exp_btn.clicked.connect(lambda: self._export_bridges_file(page))
        for btn in (paste_btn, web_btn, tg_btn, imp_btn, exp_btn):
            get_row.addWidget(btn)
        get_row.addStretch(1)
        manual_card.body.addLayout(get_row)

        self._bridges_edit = QPlainTextEdit()
        self._bridges_edit.setProperty("technical", True)
        self._bridges_edit.setLayoutDirection(Qt.LeftToRight)
        self._bridges_edit.setMinimumHeight(190)
        self._bridges_edit.setPlaceholderText(
            "webtunnel [IP]:443 <40-CHAR-FINGERPRINT> url=https://example.com/... ver=0.0.2\n"
            "obfs4 <IP>:<PORT> <40-CHAR-FINGERPRINT> cert=... iat-mode=0\n"
            "snowflake 192.0.2.3:80 <40-CHAR-FINGERPRINT> url=https://... fronts=..."
        )
        self._bridges_edit.textChanged.connect(self._update_bridge_counter)
        manual_card.body.addWidget(self._bridges_edit)

        save_row = QHBoxLayout()
        save_row.setContentsMargins(6, 6, 6, 2)
        save_row.setSpacing(8)
        save_br = settings_button(w, ("ذخیره و اعمال پل‌ها", "Save bridges"), icon="check-circle")
        save_br.clicked.connect(self._save_custom_bridges)
        copy_br = settings_button(w, ("کپی همه پل‌ها", "Copy all"), icon="copy")
        copy_br.clicked.connect(self._copy_all_bridges)
        clr_br = settings_button(w, ("پاک کردن همه", "Clear all"), icon="trash", destructive=True)
        clr_br.clicked.connect(self._clear_bridges)
        save_row.addWidget(save_br)
        save_row.addWidget(copy_br)
        save_row.addStretch(1)
        save_row.addWidget(clr_br)
        manual_card.body.addLayout(save_row)

        page.category(1).addWidget(auto_card)
        page.category(1).addWidget(manual_card)
        page.category(1).addStretch(1)

        # ---- Tab 2: Nodes, Circuit & Security ----
        nodes = SettingsCard(w, "مسیریابی گره‌ها (Entry / Exit / Exclude)", "Relay selection & exclusions", icon="globe")
        self._toggle(nodes, "strict_nodes", "قفل سخت‌گیرانه کشور خروجی (StrictNodes)", "Strict exit country",
                     hint=("در صورت نبود گره در کشور انتخابی، از کشور دیگری خارج نشود.",
                           "Never use another country if the chosen exit country is unavailable."))
        self._field(nodes, "entry_nodes", "کشورهای گره ورودی (فقط حالت مستقیم)", "Entry guard countries (Direct mode)",
                    hint=("کد دوحرفی کشورها، مثلاً de, nl (فقط در حالت مستقیم بدون پل).",
                          "2-letter country codes, e.g. de, nl (applies in Direct mode only)."))
        self._field(nodes, "exclude_nodes", "کشورهای مسدودشده در حالت مستقیم (ExcludeNodes)", "Excluded countries (Direct mode)",
                    hint=("در حالت Bridge غیرفعال است تا پل‌ها رد نشوند. پیش‌فرض: خالی.",
                          "Ignored in Bridge mode so bridges are never rejected. Default: empty."))
        self._field(nodes, "exclude_exit_nodes", "کشورهای ممنوعه برای خروجی (ExcludeExitNodes)", "Excluded exit countries",
                    hint=("کد کشورهایی که نباید IP خروجی از آن‌ها باشد (پیش‌فرض: ir).",
                          "Countries never allowed as the final Tor exit node (default: ir)."))

        circuit = SettingsCard(w, "امنیت مدار و فایروال", "Circuit isolation & firewall", icon="shield")
        self._spin_field(circuit, "max_circuit_dirtiness", "بازه نوسازی مدار (ثانیه)", "MaxCircuitDirtiness (seconds)",
                         60, 3600,
                         hint=("مدت استفاده از یک مدار برای ارتباطات جدید (پیش‌فرض ۶۰۰ ثانیه).",
                               "How long a circuit is reused for new streams (default 600s)."))
        self._toggle(circuit, "isolate_streams", "ایزوله‌سازی جریان‌ها (IsolateDestAddr/Port)", "Stream isolation per destination",
                     hint=("برای هر سایت/پورت مدار جداگانه می‌سازد.",
                           "Assigns separate Tor circuits per destination host and port."))
        self._toggle(circuit, "reachable_80_443_only", "فقط پورت‌های ۸۰ و ۴۴۳ (FascistFirewall)", "Restrict to ports 80 & 443",
                     hint=("مناسب شبکه‌هایی که فقط پورت ۸۰ و ۴۴۳ باز است.",
                           "Enables FascistFirewall so Tor only dials ports 80 and 443."))
        self._toggle(circuit, "use_ipv6", "اجازه استفاده از IPv6 در Tor", "Allow IPv6 relays (ClientUseIPv6)",
                     hint=("خاموش برای جلوگیری از خطا و نشت IPv6 روی شبکه‌های IPv4.",
                           "Keep off on IPv4-only networks to avoid timeouts and leaks."))

        page.category(2).addWidget(SettingsGrid((nodes, circuit)))
        page.category(2).addStretch(1)

        # ---- Tab 3: Ports, Identity & Maintenance ----
        ports = SettingsCard(w, "پورت‌های محلی Tor (۰ = انتخاب خودکار)", "Local Tor ports (0 = auto)", icon="network")
        for key, fa, en in (
            ("socks_port", "پورت SOCKS5", "SOCKS5 port"),
            ("http_port", "پورت HTTP Tunnel", "HTTP tunnel port"),
            ("control_port", "پورت ControlPort", "ControlPort"),
            ("dns_port", "پورت DNSPort", "DNSPort"),
        ):
            self._spin_field(ports, key, fa, en, 0, 65535)

        ident = SettingsCard(w, "هویت، مدار فعال و نگه‌داری", "Active circuit, identity & cache", icon="lock")
        self._circuit_label = QLabel()
        self._circuit_label.setObjectName("settingsRowHelp")
        self._circuit_label.setWordWrap(True)
        self._circuit_label.setContentsMargins(6, 6, 6, 6)
        ident.body.addWidget(self._circuit_label)
        ident_row = QHBoxLayout()
        ident_row.setContentsMargins(6, 4, 6, 4)
        ident_row.setSpacing(8)
        self._newnym_btn = settings_button(w, ("ساخت هویت جدید (تغییر IP)", "New Identity (NEWNYM)"), icon="refresh")
        self._newnym_btn.clicked.connect(self.new_identity)
        self._download_core_btn = settings_button(w, ("دانلود / بروزرسانی هسته Tor", "Download / Update Tor core"), icon="download")
        self._download_core_btn.clicked.connect(self._download_tor_core)
        self._clear_cache_btn = settings_button(w, ("پاک‌سازی کش مدار و پل‌ها", "Clear Tor cache"), icon="trash", destructive=True)
        self._clear_cache_btn.clicked.connect(self._clear_tor_cache)
        ident_row.addWidget(self._newnym_btn)
        ident_row.addWidget(self._download_core_btn)
        ident_row.addWidget(self._clear_cache_btn)
        ident_row.addStretch(1)
        ident.body.addLayout(ident_row)

        backup = engine_backup_card(w, lambda: self._export(page), lambda: self._import(page))
        page.category(3).addWidget(SettingsGrid((ports, ident, backup)))
        page.category(3).addStretch(1)
        return page

    def _choice(self, group, name, fa, en, items, *, hint=("", "")) -> None:
        combo = SettingsSelect()
        self._choices[name] = (combo, items)
        combo.currentIndexChanged.connect(lambda: self.save(name, combo.currentData()))
        group.add(SettingsRow(self.window, (fa, en), hint, combo, stacked=True))

    def _toggle(self, group, name, fa, en, *, hint=("", "")) -> None:
        from .ui import ToggleSwitch

        toggle = ToggleSwitch()
        toggle.toggled.connect(lambda val: self.save(name, val))
        self._toggles[name] = toggle
        group.add(SettingsRow(self.window, (fa, en), hint, toggle))

    def _field(self, group, name, fa, en, *, hint=("", "")) -> None:
        edit = QLineEdit()
        edit.setObjectName("settingsInput")
        edit.setProperty("technical", True)
        edit.setLayoutDirection(Qt.LeftToRight)
        edit.editingFinished.connect(lambda: self.save(name, edit.text().strip()))
        self._fields[name] = edit
        group.add(SettingsRow(self.window, (fa, en), hint, edit, stacked=True))

    def _spin_field(self, group, name, fa, en, minimum: int, maximum: int, *, hint=("", "")) -> None:
        spin = QSpinBox()
        spin.setObjectName("settingsNumber")
        spin.setLocale(QLocale.c())
        spin.setRange(minimum, maximum)
        spin.setMaximumWidth(140)
        spin.setProperty("technical", True)
        spin.setLayoutDirection(Qt.LeftToRight)
        spin.valueChanged.connect(lambda val: self.save(name, int(val)))
        self._fields[name] = spin
        group.add(SettingsRow(self.window, (fa, en), hint, spin, stacked=True))

    def effective_settings(self):
        return self.window.global_settings.snapshot().for_tor(self.store.settings())

    def save(self, field: str, value) -> None:
        prev = self.store.settings()
        if value == getattr(prev, field):
            return
        try:
            self.store.save_settings(
                replace(prev, **{field: value}),
                exclude=self.window.global_settings.tor_legacy_fields,
            )
        except OSError as exc:
            self.window.show_toast(str(exc), "danger")
            self.refresh()
            return
        self.refresh()
        if field in ("transport", "exit_country_code", "strict_nodes", "entry_nodes",
                     "exclude_nodes", "exclude_exit_nodes", "reachable_80_443_only",
                     "upstream_proxy", "isolate_streams"):
            if self.busy:
                self.window._set_activity(
                    "در حال اتصال دوباره با تنظیم جدید Tor…",
                    "Reconnecting Tor with updated route…", "running", True,
                )
            self.restart_if_active()

    def _update_bridge_counter(self) -> None:
        if self._bridge_counter is None or self._bridges_edit is None:
            return
        lines = extract_bridges_from_text(self._bridges_edit.toPlainText())
        counts = summarize_bridge_counts(lines)
        if not counts:
            self._bridge_counter.setText(self.window.tr("۰ پل معتبر", "0 valid"))
            return
        parts = [f"{n} {tr}" for tr, n in sorted(counts.items())]
        self._bridge_counter.setText(" · ".join(parts))

    def _paste_bridges(self) -> None:
        if self._bridges_edit is None:
            return
        clip = QApplication.clipboard().text() or ""
        new_lines = extract_bridges_from_text(clip)
        if not new_lines:
            self.window.show_toast(
                self.window.tr("خط پل معتبری در کلیپ‌بورد پیدا نشد.", "No valid Tor bridge lines found in clipboard."),
                "warning",
            )
            return
        existing = extract_bridges_from_text(self._bridges_edit.toPlainText())
        merged = list(dict.fromkeys([*new_lines, *existing]))
        self._bridges_edit.setPlainText("\n".join(merged))
        self.save("custom_bridges", "\n".join(merged))
        self.window.show_toast(
            self.window.tr(f"{len(new_lines)} پل چسبانده و ذخیره شد.", f"Pasted and saved {len(new_lines)} bridge(s)."),
            "success",
        )

    def _save_custom_bridges(self) -> None:
        if self._bridges_edit is None:
            return
        lines = extract_bridges_from_text(self._bridges_edit.toPlainText())
        self.save("custom_bridges", "\n".join(lines))
        self._update_bridge_counter()
        self.window.show_toast(
            self.window.tr(f"{len(lines)} پل معتبر ذخیره شد.", f"Saved {len(lines)} valid bridge(s)."),
            "success" if lines else "info",
        )

    def _copy_all_bridges(self) -> None:
        if self._bridges_edit is None:
            return
        lines = extract_bridges_from_text(self._bridges_edit.toPlainText())
        if not lines:
            self.window.show_toast(self.window.tr("پلی برای کپی نیست.", "No bridges to copy."), "warning")
            return
        QApplication.clipboard().setText("\n".join(lines))
        self.window.show_toast(self.window.tr(f"{len(lines)} پل کپی شد.", f"Copied {len(lines)} bridge(s)."), "success")

    def _clear_bridges(self) -> None:
        if self._bridges_edit is not None:
            self._bridges_edit.clear()
        self.save("custom_bridges", "")
        self._update_bridge_counter()

    def _import_bridges_file(self, parent: QWidget) -> None:
        filename, _ = QFileDialog.getOpenFileName(parent, "Tor Bridges", "", "Text (*.txt);;All (*.*)")
        if not filename:
            return
        try:
            raw = Path(filename).read_text(encoding="utf-8-sig", errors="replace")
            lines = extract_bridges_from_text(raw)
            if not lines:
                raise ValueError("No valid bridge lines found in file")
            existing = extract_bridges_from_text(self.store.settings().custom_bridges)
            merged = list(dict.fromkeys([*lines, *existing]))
            self.save("custom_bridges", "\n".join(merged))
            self.window.show_toast(
                self.window.tr(f"{len(lines)} پل وارد و ذخیره شد.", f"Imported {len(lines)} bridge(s)."), "success"
            )
        except (OSError, ValueError) as exc:
            self.window.show_toast(str(exc), "danger")

    def _export_bridges_file(self, parent: QWidget) -> None:
        lines = extract_bridges_from_text(
            self._bridges_edit.toPlainText() if self._bridges_edit is not None else self.store.settings().custom_bridges
        )
        if not lines:
            self.window.show_toast(self.window.tr("پلی برای ذخیره نیست.", "No bridges to export."), "warning")
            return
        filename, _ = QFileDialog.getSaveFileName(parent, "Tor Bridges", "uac-tor-bridges.txt", "Text (*.txt)")
        if filename:
            try:
                Path(filename).write_text("\n".join(lines) + "\n", encoding="utf-8")
                self.window.show_toast(self.window.tr("فایل پل‌ها ذخیره شد.", "Bridges exported."), "success")
            except OSError as exc:
                self.window.show_toast(str(exc), "danger")

    def _download_tor_core(self) -> None:
        if self.busy:
            self.window.show_toast(self.window.tr("ابتدا اتصال Tor را قطع کنید.", "Disconnect Tor first."), "warning")
            return
        if self._download_core_btn is not None:
            self._download_core_btn.setEnabled(False)
        self.window.show_toast(self.window.tr("در حال دانلود هسته Tor و ابزارها…", "Downloading Tor core & transports…"), "info")
        proxy = self.store.settings().upstream_proxy

        def work() -> None:
            try:
                from .tor.binaries import install_tor_bundle
                dest = install_tor_bundle(proxy=proxy, log=self._forward_log)
                self._core_downloaded.emit(True, str(dest))
            except Exception as exc:
                self._core_downloaded.emit(False, str(exc))

        threading.Thread(target=work, name="tor-core-dl", daemon=True).start()

    def _on_core_downloaded(self, ok: bool, detail: str) -> None:
        if self._download_core_btn is not None:
            self._download_core_btn.setEnabled(not self.busy)
        w = self.window
        if ok:
            w.show_toast(w.tr("هسته Tor و ابزارهای عبور از فیلتر با موفقیت نصب شد.", f"Tor core installed in {detail}."), "success")
        else:
            w.show_toast(w.tr(f"دانلود هسته Tor ناموفق بود: {detail}", f"Tor core download failed: {detail}"), "danger")

    def _clear_tor_cache(self) -> None:
        if self.busy:
            self.window.show_toast(
                self.window.tr("ابتدا اتصال Tor را قطع کنید.", "Disconnect Tor before clearing its cache."), "warning"
            )
            return
        self.coordinator.clear_cache()
        self.refresh()
        self.window.show_toast(
            self.window.tr("کش مدار، اجماع و پل‌های Tor پاک شد.", "Tor consensus and bridge cache cleared."), "success"
        )

    def _fetch_bridges_now(self) -> None:
        if self._fetching:
            return
        self._fetching = True
        self._fetch_cancel = threading.Event()
        transport = str(self._fetch_type_combo.currentData() or "webtunnel")
        settings = self.store.settings()
        if self._fetch_btn is not None:
            self._fetch_btn.setEnabled(False)
        if self._bridge_status is not None:
            self._bridge_status.setText(self.window.tr(
                f"در حال دریافت خودکار پل‌های {transport}…",
                f"Auto-fetching {transport} bridges…",
            ))

        def work() -> None:
            res = auto_fetch_bridges(
                transport,
                source=settings.bridge_source,
                custom_relay=settings.bridge_relay_url,
                upstream_proxy=settings.upstream_proxy,
                data_dir=self.store.directory.parent,
                last_winner=self.store.last_winner_method(),
                dns_cache=self.store.load_dns_cache(),
                save_dns_cache=self.store.save_dns_cache,
                cancel=self._fetch_cancel,
                log=self._forward_log,
            )
            self._bridges_fetched.emit(res)

        threading.Thread(target=work, name="tor-bridge-fetch", daemon=True).start()

    def _on_bridges_fetched(self, res) -> None:
        self._fetching = False
        if self._fetch_btn is not None:
            self._fetch_btn.setEnabled(True)
        w = self.window
        if not res.ok:
            msg = w.tr(f"دریافت خودکار پل ناموفق بود ({res.detail}).", f"Bridge fetch failed: {res.detail}")
            if self._bridge_status is not None:
                self._bridge_status.setText(msg)
            w.show_toast(msg, "warning")
            return
        bridges = list(res.bridges)
        self.store.save_cached_bridges(res.transport, bridges, res.method, res.source)
        existing = extract_bridges_from_text(self.store.settings().custom_bridges)
        merged = list(dict.fromkeys([*bridges[:18], *existing]))
        self.save("custom_bridges", "\n".join(merged))
        msg = w.tr(
            f"{len(bridges)} پل {res.transport} از منبع {res.source} دریافت و ذخیره شد.",
            f"Fetched {len(bridges)} {res.transport} bridge(s) from {res.source}.",
        )
        if self._bridge_status is not None:
            self._bridge_status.setText(msg)
        w.show_toast(msg, "success")

    def _test_bridges_now(self) -> None:
        if self._fetching:
            return
        lines = extract_bridges_from_text(
            self._bridges_edit.toPlainText() if self._bridges_edit is not None else self.store.settings().custom_bridges
        )
        if not lines:
            self.window.show_toast(self.window.tr("پلی برای تست وجود ندارد.", "No bridges to test."), "warning")
            return
        self._fetching = True
        if self._test_btn is not None:
            self._test_btn.setEnabled(False)
        if self._bridge_status is not None:
            self._bridge_status.setText(self.window.tr(
                f"در حال تست دسترسی {len(lines)} پل…", f"Testing reachability of {len(lines)} bridge(s)…"
            ))

        def work() -> None:
            ranked = rank_reachable_bridges(lines, timeout=2.5, cancel=self._fetch_cancel)
            self._bridges_tested.emit((len(lines), ranked))

        threading.Thread(target=work, name="tor-bridge-test", daemon=True).start()

    def _on_bridges_tested(self, payload) -> None:
        self._fetching = False
        if self._test_btn is not None:
            self._test_btn.setEnabled(True)
        total, ranked = payload
        w = self.window
        if ranked:
            ordered = [line for line, _ms in ranked]
            best_ms = ranked[0][1]
            self.save("custom_bridges", "\n".join(ordered))
            msg = w.tr(
                f"{len(ranked)} از {total} پل در دسترس است (سریع‌ترین: {best_ms} ms).",
                f"{len(ranked)} of {total} bridges reachable (fastest: {best_ms} ms).",
            )
            w.show_toast(msg, "success")
        else:
            msg = w.tr("هیچ‌کدام از پل‌ها در تست TCP پاسخ ندادند.", "No bridges responded to TCP probe.")
            w.show_toast(msg, "warning")
        if self._bridge_status is not None:
            self._bridge_status.setText(msg)

    def new_identity(self) -> None:
        w = self.window
        if self.coordinator.request_new_identity():
            w.show_toast(w.tr("درخواست هویت جدید (تغییر IP) ارسال شد.", "New Tor identity requested."), "info")
        else:
            w.show_toast(w.tr("ابتدا به Tor متصل شوید.", "Connect Tor first."), "warning")

    def refresh(self) -> None:
        w = self.window
        settings = self.effective_settings()
        for key, (combo, items) in self._choices.items():
            with QSignalBlocker(combo):
                combo.clear()
                for val, fa, en in items:
                    combo.addItem(w._ui_text(fa, en), val)
                idx = combo.findData(getattr(settings, key))
                combo.setCurrentIndex(max(0, idx))
        for name, toggle in self._toggles.items():
            w._pow_set_toggle(toggle, getattr(settings, name))
        for name, edit in self._fields.items():
            with QSignalBlocker(edit):
                if isinstance(edit, QSpinBox):
                    edit.setValue(int(getattr(settings, name)))
                elif not edit.hasFocus():
                    edit.setText(str(getattr(settings, name)))
        if self._autopilot_label is not None:
            tr, _m = self.store.autopilot_winner()
            if tr:
                self._autopilot_label.setText(w.tr(
                    f"مسیر یادگرفته‌شده Autopilot: {tr.upper()} — در اتصال بعدی اول امتحان می‌شود.",
                    f"Learned Autopilot transport: {tr.upper()} — tried first on next connect.",
                ))
            else:
                self._autopilot_label.setText(w.tr(
                    "Autopilot آماده است: با کلیک روی اتصال، خودکار بهترین ترابری و پل سالم را پیدا می‌کند.",
                    "Autopilot ready: clicking Connect automatically finds the best transport and bridges.",
                ))
        if self._bridges_edit is not None and not self._bridges_edit.hasFocus():
            with QSignalBlocker(self._bridges_edit):
                self._bridges_edit.setPlainText(settings.custom_bridges)
            self._update_bridge_counter()
        if w.engine_mode != ENGINE_TOR or not hasattr(w, "home_header"):
            self._phase = None
            return
        with QSignalBlocker(w.carrier):
            w.carrier.clear()
            w.carrier.addItems(["auto", "webtunnel", "snowflake", "obfs4", "custom", "direct"])
            idx = w.carrier.findText(settings.transport)
            w.carrier.setCurrentIndex(max(0, idx))
        self.refresh_output_controls()
        self.refresh_country(settings)
        self._show_status(self.coordinator.status, redraw=True)

    def refresh_output_controls(self) -> None:
        w = self.window
        prefs = w.global_settings.snapshot()
        actual_vpn = self.coordinator.session_vpn
        if self.coordinator.status.phase == "stopping":
            actual_vpn = None
        tun_on = (prefs.connection_mode == "vpn") if actual_vpn is None else actual_vpn
        actual_proxy = self.coordinator.system_proxy_enabled
        proxy_on = prefs.windows_proxy_enabled if actual_proxy is None else actual_proxy
        w._sync_tun_proxy_controls(tun_on, proxy_on)

    def refresh_country(self, settings=None) -> None:
        from .ui import country_flag_badge, cyber_pixmap

        w = self.window
        settings = settings or self.store.settings()
        button = w.pow_country_button
        code = settings.exit_country_code.upper()
        if code:
            title = region_name(code)
            subtitle = w.tr("کشور خروجی انتخابی Tor", "Selected Tor exit country")
        else:
            title = w.tr("خودکار", "Automatic")
            subtitle = w.tr("مدار تصادفی شبکه Tor", "Random Tor exit relay")
        button.set_value(country_flag_badge(code, 38) if code else cyber_pixmap("tor", "#c08cff", 22), title, subtitle)
        button.setEnabled(True)
        button.setAccessibleName("Tor exit country")
        button.setToolTip(w.tr("انتخاب کشور خروجی Tor", "Choose Tor exit country"))
        w.country_description.setText(w.tr(
            "حالت تمام‌خودکار (Autopilot) یا انتخاب دستی WebTunnel، Snowflake و obfs4",
            "Full Autopilot or manual WebTunnel, Snowflake, and obfs4 circuits",
        ))

    def open_country_picker(self) -> None:
        code = self.store.settings().exit_country_code.upper()
        dialog = PowCountryPicker(self.window, code, countries=ALL_NAMES, nearby=False)
        try:
            if dialog.exec() and dialog.selected_code is not None:
                self.save("exit_country_code", dialog.selected_code)
        finally:
            dialog.deleteLater()

    def ensure_admin_for_tun(self) -> bool:
        if is_admin():
            return True
        import tempfile as _tf
        import time as _tm

        w = self.window
        reply = QMessageBox.question(
            w,
            w.tr("نیاز به دسترسی مدیر (Administrator)", "Administrator access required"),
            w.tr(
                "حالت TUN (VPN سراسری) برای ساخت کارت شبکه مجازی نیاز به دسترسی مدیر (Administrator) دارد.\n"
                "آیا برنامه هم‌اکنون با دسترسی Administrator مجدداً اجرا شود؟",
                "TUN (System VPN) mode requires Administrator privileges to create the virtual adapter.\n"
                "Restart the application as Administrator now?",
            ),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes,
        )
        if reply != QMessageBox.Yes:
            return False

        marker = Path(_tf.gettempdir()) / "uac_spoofer_relaunch.pid"
        try:
            marker.write_text(f"{os.getpid()}:{_tm.time():.3f}", encoding="utf-8")
        except OSError:
            pass

        if getattr(sys, "frozen", False):
            exe = sys.executable
            params = subprocess.list2cmdline(sys.argv[1:])
            workdir = os.getcwd()
        else:
            exe = sys.executable
            script = str(Path(sys.argv[0]).resolve())
            params = subprocess.list2cmdline([script, *sys.argv[1:]])
            workdir = str(Path(script).parent)

        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, workdir, 1)
        if rc > 32:
            try:
                w.storage.settings["engine_mode"] = ENGINE_TOR
                w.storage.save_settings()
                w.global_settings.change(connection_mode="vpn")
            except Exception:
                pass
            w._force_quit = True
            w.shutdown()
            os._exit(0)
        else:
            try:
                marker.unlink(missing_ok=True)
            except OSError:
                pass
            w.show_toast(
                w.tr("دسترسی Administrator تایید نشد.", "Administrator elevation was cancelled."),
                "warning",
            )
        return False

    def start(self) -> None:
        if self.busy or self.window.engine_mode != ENGINE_TOR or self.window._closing:
            return
        prefs = self.window.global_settings.snapshot()
        settings = prefs.for_tor(self.store.settings())
        if settings.connection_mode == "vpn" and not self.ensure_admin_for_tun():
            return
        options = TorOptions(
            vpn=(settings.connection_mode == "vpn"),
            routing_mode=settings.routing_mode,
            processes=self.window.global_settings.processes(),
            system_proxy=prefs.windows_proxy_enabled,
            privacy=prefs,
        )
        self.coordinator.connect(options, settings=settings)

    def toggle(self) -> None:
        if self.busy:
            self.stop()
        else:
            self.start()

    def stop(self) -> None:
        self._reconnect = False
        self._fetch_cancel.set()
        self.coordinator.disconnect()

    def restart_if_active(self) -> None:
        if self.busy and self.window.engine_mode == ENGINE_TOR:
            self._reconnect = True
            self.coordinator.disconnect()

    def shutdown(self) -> bool:
        self.stop()
        return self.coordinator.wait(10) and not self.coordinator.status.disconnect_failed

    def _show_status(self, status: TorStatus, *, redraw: bool = False) -> None:
        if status != self.coordinator.status:
            return
        w = self.window
        if self._circuit_label is not None:
            if status.phase == "connected" and status.circuit:
                self._circuit_label.setText(
                    w.tr("مدار فعال: ", "Active circuit: ") + "  →  ".join(status.circuit)
                )
            else:
                self._circuit_label.setText(w.tr("مدار فعالی برقرار نیست.", "No active circuit."))
        if self._newnym_btn is not None:
            self._newnym_btn.setEnabled(status.phase == "connected")
        if self._clear_cache_btn is not None:
            self._clear_cache_btn.setEnabled(not self.busy)
        if w.engine_mode != ENGINE_TOR or w._closing:
            return
        from .ui import country_flag_icon

        phase = status.phase
        active = phase == "connected"
        if redraw or phase != self._phase:
            self._phase = phase
            if not redraw:
                self.refresh_output_controls()
            visual = {
                "idle": "disconnected", "stopping": "disconnecting", "error": "error", "connected": "connected",
            }.get(phase, "connecting")
            w._set_connection_visual(visual)
            activity = {
                "idle": ("UAC Tor آماده است (Autopilot).", "UAC Tor is ready (Autopilot).", "idle", False),
                "fetching": ("در حال دریافت خودکار پل‌های Tor…", "Auto-fetching Tor bridges…", "running", True),
                "connected": ("اتصال امن Tor برقرار شد.", "Tor connection verified.", "success", False),
                "stopping": ("در حال بستن نشست Tor…", "Closing Tor session…", "running", True),
                "error": ("اتصال Tor ناموفق بود.", "Tor connection failed.", "error", False),
            }
            w._set_activity(*activity.get(phase, ("در حال برقراری مدار Tor…", "Bootstrapping Tor circuit…", "running", True)))

        w._refresh_app_routing_notice()
        if phase in ("fetching", "starting", "bootstrapping", "checking"):
            pct = f" · {status.progress}%" if 0 < status.progress < 100 else ""
            w.connection_hint.setText((status.detail or w.tr("در حال اتصال Tor", "Connecting Tor")) + pct)
        elif phase == "connected":
            hops = " → ".join(status.circuit) if status.circuit else status.transport.upper()
            w.connection_hint.setText(w.tr(f"متصل از طریق {hops}", f"Connected via {hops}"))
        elif phase == "error":
            w.connection_hint.setText(status.detail or w.tr("خطا در اتصال Tor", "Tor connection error"))
        w.connection_hint.setToolTip(status.detail)

        route_name = f"Tor · {status.transport.upper()}" if status.transport else "Tor"
        w.active_profile.setText(route_name if active else "—")
        secondary = " → ".join(status.circuit) if active and status.circuit else (
            f"SOCKS {status.socks_port} · HTTP {status.http_port}" if active else ""
        )
        w.route_card.set_secondary(secondary)
        w.network_metrics.set_latency(
            status.latency_ms if active and status.latency_ms else None,
            w.tr("پینگ مدار Tor", "Tor circuit latency") if active else "",
        )
        if active:
            w._display_traffic(status.tx_bytes, status.rx_bytes, sample=not redraw)
        w.ip_label.setText(status.exit_ip if active and status.exit_ip else "—")
        code = status.country.upper() if active and status.exit_ip else ""
        w.ip_card.set_secondary(region_name(code) if code else ("Tor Exit" if active else ""))
        if code:
            w.ip_flag.setPixmap(country_flag_icon(code, 22, 16).pixmap(22, 16))
            w.ip_flag.setToolTip(region_name(code))
        w.ip_flag.setVisible(bool(code))
        w.ip_button.setEnabled(active)
        w.ip_parallel.hide()
        if phase == "idle" and self._reconnect:
            self._reconnect = False
            self.start()

    def _forward_log(self, line: str) -> None:
        self.window.bridge.engine_log.emit(line if line.startswith("Tor") else f"Tor: {line}", ENGINE_TOR)

    def _export(self, parent: QWidget) -> None:
        filename, _ = QFileDialog.getSaveFileName(parent, "UAC Tor", "uac-tor-settings.json", "JSON (*.json)")
        if filename:
            try:
                self.store.export_settings(Path(filename), exclude=self.window.global_settings.tor_legacy_fields)
            except OSError as exc:
                self.window.show_toast(str(exc), "danger")

    def _import(self, parent: QWidget) -> None:
        filename, _ = QFileDialog.getOpenFileName(parent, "UAC Tor", "", "JSON (*.json)")
        if filename:
            try:
                self.store.import_settings(Path(filename), exclude=self.window.global_settings.tor_legacy_fields)
                self.refresh()
            except (OSError, ValueError) as exc:
                self.window.show_toast(str(exc), "danger")
