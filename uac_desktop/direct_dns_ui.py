"""The Direct DNS catalog and its cancellable connection tests."""
from __future__ import annotations

import json
import threading
from dataclasses import replace
from pathlib import Path
from string import Template

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QFileDialog, QFrame, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QProgressBar, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from .direct.carrier import DirectCancelled
from .direct.probe import scan_dns
from .direct.resolvers import MOZILLA_DOH, parse_resolver, resolver_catalog
from .fonts import make_font
from .theme import APP_ROUTING_PALETTES


_UDP_COUNTRY_HINT = ("DNS نوع UDP در خروجی کشورِ سایفون پشتیبانی نمی‌شود.",
                     "UDP DNS is unavailable with a Psiphon country exit.")

_STYLE = Template("""
#directDnsPage QFrame#dnsPanel { background: $surface; border: 1px solid $border; border-radius: 9px; }
#directDnsPage QLabel#dnsHint { color: $muted; }
#directDnsPage QLabel#dnsValue { color: $accent; font-size: 14px; font-weight: 600; }
#directDnsPage QLineEdit, #directDnsPage QPushButton { min-height: 32px; padding: 0 9px; border-radius: 7px; }
#directDnsPage QLineEdit { background: $background; border: 1px solid $border; color: $text; }
#directDnsPage QLineEdit:focus, #directDnsPage QPushButton:focus { border-color: $accent; }
#directDnsPage QPushButton#dnsAction { background: $tile; color: $text; border: 1px solid $border; }
#directDnsPage QPushButton#dnsAction:hover { background: $hover; }
#directDnsPage QPushButton#dnsPrimary { background: $selected; color: $accent; border: 1px solid $selected_border; }
#directDnsPage QPushButton#dnsPrimary:hover { background: $hover; }
#directDnsPage QPushButton#dnsAction:disabled, #directDnsPage QPushButton#dnsPrimary:disabled {
    color: $muted; background: $surface; border-color: $border;
}
#directDnsPage QTableWidget {
    background: $surface; alternate-background-color: $tile; color: $text; gridline-color: $border;
    border: 1px solid $border; border-radius: 8px; selection-background-color: $selected; selection-color: $text;
}
#directDnsPage QTableWidget::item { padding: 2px 8px; }
#directDnsPage QHeaderView::section {
    background: $tile; color: $muted; border: none; border-bottom: 1px solid $border;
    padding: 5px 8px; font-weight: 600;
}
#directDnsPage QProgressBar { background: $tile; border: none; border-radius: 3px; }
#directDnsPage QProgressBar::chunk { background: $accent; border-radius: 3px; }
""")


class DirectDnsLab(QWidget):
    _measured = Signal(object, object)
    _finished = Signal(object, str)

    def __init__(self, window) -> None:
        super().__init__()
        from .ui import ElidedLabel

        self.window = window
        self.controller = window.direct_controller
        self.store = self.controller.store
        self._route = self.controller.coordinator.status
        self._cancel = None
        self._scan_port = 0
        self._results = {}
        self._rows = {}
        self._best = None
        self._message = ("برای مقایسهٔ سرورها، اسکن را شروع کنید.",
                         "Run a scan to compare these servers.")
        self.setStyleSheet(_STYLE.substitute(APP_ROUTING_PALETTES["direct"]))

        root = QVBoxLayout(self)
        root.setContentsMargins(14, 12, 14, 8)
        root.setSpacing(8)
        root.addWidget(window._page_header(
            "آزمایشگاه DNS", "DNS Lab", "سرورها را بسنجید و DNS مناسب را برای اتصال Direct انتخاب کنید.",
            "Compare resolvers and choose the DNS server for Direct.", compact_name="dnsLabHeader",
        ))

        summary = QFrame(objectName="dnsPanel")
        overview = QHBoxLayout(summary)
        overview.setContentsMargins(10, 6, 10, 6)
        self.active = ElidedLabel()
        self.active.setObjectName("dnsValue")
        overview.addWidget(self.active, 1)
        self.auto = self._button("انتخاب خودکار", "Use automatic DNS", "zap", lambda: self._apply(""))
        overview.addWidget(self.auto)
        root.addWidget(summary)

        add = QHBoxLayout()
        add.setSpacing(8)
        self.address = QLineEdit()
        self.address.setLayoutDirection(Qt.LeftToRight)
        self.address.setProperty("technical", True)
        self.address.returnPressed.connect(self._add_address)
        add.addWidget(self.address, 1)
        add.addWidget(self._button("افزودن", "Add", "plus", self._add_address))
        self.import_file = self._button("انتخاب فایل", "Import file", "folder", self._import_file)
        add.addWidget(self.import_file)
        root.addLayout(add)

        bar = QHBoxLayout()
        bar.setSpacing(8)
        self.search = QLineEdit()
        self.search.textChanged.connect(self._render_table)
        bar.addWidget(self.search, 1)
        self.scan_all = self._button("اسکن همه", "Scan all", "play", lambda: self._start_scan(False), primary=True)
        self.scan_row = self._button("تست انتخاب‌شده", "Test selected", "activity", lambda: self._start_scan(True))
        self.stop = self._button("توقف", "Stop", "x-circle", self.stop_scan)
        for button in (self.scan_all, self.scan_row, self.stop):
            bar.addWidget(button)
        root.addLayout(bar)
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(6)
        root.addWidget(self.progress)

        self.table = QTableWidget(0, 5)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setTextElideMode(Qt.ElideMiddle)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(38)
        header = self.table.horizontalHeader()
        for column, width in ((0, 142), (2, 68), (3, 94), (4, 110)):
            header.setSectionResizeMode(column, QHeaderView.Fixed)
            self.table.setColumnWidth(column, width)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.itemSelectionChanged.connect(self._sync_actions)
        root.addWidget(self.table, 1)

        footer = QHBoxLayout()
        footer.setSpacing(8)
        self.note = QLabel(objectName="dnsHint")
        self.note.setWordWrap(True)
        footer.addWidget(self.note, 1)
        self.remove = self._button("حذف از فهرست", "Remove", "trash", self._remove_address)
        self.apply_row = self._button("اعمال انتخاب‌شده", "Apply selected", "check-circle", self._apply_selected)
        self.apply_best = self._button("اعمال بهترین", "Apply best", "zap", self._apply_fastest, primary=True)
        for button in (self.remove, self.apply_row, self.apply_best):
            footer.addWidget(button)
        root.addLayout(footer)

        self._measured.connect(self._on_measurement, Qt.QueuedConnection)
        self._finished.connect(self._on_finished, Qt.QueuedConnection)
        self.refresh()

    def _tr(self, fa, en):
        return self.window._ui_text(fa, en)

    def _button(self, fa, en, glyph, action, *, primary=False):
        button = self.window._action_button(fa, en, glyph, "dnsPrimary" if primary else "dnsAction")
        button.clicked.connect(action)
        return button

    def refresh(self):
        self._settings = self.store.settings()
        self._catalog = resolver_catalog(self._settings.custom_dns,
                                         (self._settings.unfiltered_dns, MOZILLA_DOH, self._settings.pinned_dns))
        self.address.setPlaceholderText(self._tr("آدرس IP یا نشانی HTTPS سرور DNS", "DNS server IP or HTTPS URL"))
        self.address.setToolTip(self._tr("نمونه‌ها: udp://9.9.9.9 یا https://dns.google/dns-query",
                                         "Examples: udp://9.9.9.9 or https://dns.google/dns-query"))
        self.import_file.setToolTip(self._tr("فایل TXT با یک آدرس در هر خط یا آرایهٔ JSON از آدرس‌ها",
                                             "TXT with one address per line or a JSON array of addresses"))
        self.search.setPlaceholderText(self._tr("جست‌وجوی نام یا آدرس…", "Search by name or address…"))
        self.table.setHorizontalHeaderLabels([
            self._tr("سرور", "Resolver"), self._tr("آدرس", "Address"), self._tr("روش", "Protocol"),
            self._tr("زمان پاسخ", "Latency"), self._tr("پاسخ معتبر", "Valid replies"),
        ])
        self._render_table()
        self.set_route_status(self.controller.coordinator.status)
        self._show_note()

    def set_route_status(self, status):
        self._route = status
        if self._cancel is not None and self._scan_port != self._available_port():
            self.stop_scan()
        active = status.resolver_address if status.phase == "connected" else ""
        selected = self._settings.pinned_dns if not self._settings.auto_select_dns else ""
        if active:
            name = status.resolver
            self.active.setText(self._tr(f"DNS ترجیحی این اتصال: {name}", f"Preferred DNS for this connection: {name}"))
        elif status.phase == "connected":
            self.active.setText(self._tr("DNS مسیر فعال: تنظیمات جایگزین", "Active route DNS: fallback settings"))
        elif selected and not self._can_apply(selected):
            self.active.setText(self._tr(*_UDP_COUNTRY_HINT))
        elif selected:
            name = parse_resolver(selected).label
            self.active.setText(self._tr(f"اتصال بعدی با {name}", f"Next connection uses {name}"))
        else:
            self.active.setText(self._tr("انتخاب خودکار DNS", "Automatic DNS selection") if self._settings.auto_select_dns
                                else self._tr("DNS جایگزین Direct", "Direct fallback DNS"))
        self.active.setToolTip(active or selected or self._settings.unfiltered_dns)
        self._sync_actions()

    def _available_port(self):
        return self._route.dns_lab_port if self._route.phase == "connected" else 0

    def _can_apply(self, address):
        if not address.startswith("udp://"):
            return True
        if self._route.phase == "connected":
            return self._route.dns_udp_supported
        return not (self._settings.wireguard_over_direct and self._settings.exit_country_code)

    def _selected(self):
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        return item.data(Qt.UserRole) if item else None

    def _render_table(self, *_args):
        selected = self._selected()
        filter_text = self.search.text().strip().casefold()
        visible = [resolver for resolver in self._catalog if filter_text in
                   f"{resolver.label} {resolver.url} {resolver.protocol}".casefold()]
        self.table.setRowCount(len(visible))
        self._rows = {}
        font = make_font("en", 9)
        for row, resolver in enumerate(visible):
            self._rows[resolver.url] = row
            values = (resolver.label, resolver.url, resolver.protocol, "—", "—")
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                if column == 2:
                    protocol = resolver.protocol
                    if protocol == "DoH":
                        hint = self._tr("DNS رمزنگاری‌شده روی HTTPS", "Encrypted DNS over HTTPS")
                    else:
                        hint = self._tr(f"DNS بدون رمزنگاری روی {protocol}", f"Unencrypted DNS over {protocol}")
                        if protocol == "UDP":
                            hint += "\n" + self._tr(*_UDP_COUNTRY_HINT)
                    item.setToolTip(hint)
                item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter if column < 2 else Qt.AlignCenter)
                item.setFont(font)
                self.table.setItem(row, column, item)
            self.table.item(row, 0).setData(Qt.UserRole, resolver.url)
            self._render_result(resolver.url)
        if selected in self._rows:
            self.table.selectRow(self._rows[selected])
        self._sync_actions()

    def _render_result(self, address):
        row = self._rows.get(address)
        result = self._results.get(address)
        if row is None or result is None:
            return
        latency = self.table.item(row, 3)
        value = f"{result.latency} ms" if result.latency is not None else "—"
        latency.setText(f"\u2066{value}\u2069" if self.window.language == "fa" else value)
        latency.setToolTip(self._tr("میانهٔ زمان دریافت پاسخ‌های معتبر", "Median time to receive a valid reply"))
        quality = self.table.item(row, 4)
        quality.setText(f"{len(result.samples)} / {result.attempts}")
        quality.setToolTip(self._tr("تعداد پاسخ‌های معتبر از کل درخواست‌های آزمایش",
                                    "Valid DNS replies out of all test requests"))
        if address == self._best:
            color = QColor(APP_ROUTING_PALETTES["direct"]["accent"])
            quality.setForeground(color)
            self.table.item(row, 0).setForeground(color)

    def _sync_actions(self):
        if not hasattr(self, "apply_best"):
            return
        scanning = self._cancel is not None
        selected = self._selected()
        result = self._results.get(selected)
        ready = self._route.phase in ("idle", "connected", "paused", "error")
        can_scan = bool(self._available_port()) or (
            self._route.phase in ("idle", "error") and not self._route.protected
        )
        udp_scan = not self._available_port() or self._route.dns_udp_supported
        self.scan_all.setEnabled(not scanning and bool(self._catalog) and can_scan)
        self.scan_row.setEnabled(not scanning and bool(selected) and can_scan
                                 and (udp_scan or not selected.startswith("udp://")))
        self.scan_all.setToolTip(self._tr("صبر کنید اتصال آماده شود، یا اتصال را کامل قطع کنید.",
                                         "Wait for the connection to be ready, or disconnect fully.") if not can_scan
                                 else self._tr(*_UDP_COUNTRY_HINT) if not udp_scan else "")
        self.stop.setEnabled(scanning and not self._cancel.is_set())
        pinned = self._settings.pinned_dns if not self._settings.auto_select_dns else ""
        self.apply_row.setEnabled(ready and not scanning and selected != pinned
                                  and result is not None and bool(result.samples) and self._can_apply(selected))
        self.apply_best.setEnabled(ready and not scanning and bool(self._best) and self._best != pinned
                                   and self._can_apply(self._best))
        self.auto.setEnabled(ready and not scanning and not self._settings.auto_select_dns)
        self.remove.setEnabled(not scanning and selected in self._settings.custom_dns
                               and selected != self._settings.pinned_dns)

    def _show_note(self):
        self.note.setText(self._tr(*self._message))

    def _notify(self, fa, en):
        self._message = (fa, en)
        self._show_note()

    def _save_addresses(self, addresses):
        try:
            self.store.save_settings(replace(self._settings, custom_dns=tuple(addresses)),
                                     exclude=self.window.global_settings.direct_legacy_fields)
        except OSError as error:
            self.window.show_toast(str(error), "danger")
            return False
        self.refresh()
        return True

    def _add_address(self):
        self._add_addresses([self.address.text()])

    def _add_addresses(self, lines):
        addresses = list(self._settings.custom_dns)
        catalog = {resolver.url for resolver in self._catalog}
        added = invalid = 0
        for line in lines:
            if not isinstance(line, str):
                invalid += 1
                continue
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            try:
                endpoint = parse_resolver(line).url
            except ValueError:
                invalid += 1
                continue
            if endpoint not in catalog:
                addresses.append(endpoint)
                catalog.add(endpoint)
                added += 1
        if not added and not invalid:
            self._notify("آدرس جدیدی در فهرست نبود.", "There were no new addresses to add.")
        elif not added:
            self._notify("آدرس معتبر پیدا نشد. یک IP یا نشانی HTTPS وارد کنید.",
                         "No valid address was found. Enter an IP or an HTTPS URL.")
        elif self._save_addresses(addresses):
            self.address.clear()
            if invalid:
                self._notify(f"{added} سرور اضافه شد. {invalid} آدرس نامعتبر بود.",
                             f"Added {added} resolvers. Skipped {invalid} invalid addresses.")
            else:
                self._notify(f"{added} سرور به فهرست اضافه شد.", f"Added {added} resolvers.")

    def _import_file(self):
        filename, _ = QFileDialog.getOpenFileName(
            self, self._tr("انتخاب فهرست DNS", "Choose a DNS list"), "",
            self._tr("فهرست DNS (*.txt *.json)", "DNS lists (*.txt *.json)"),
        )
        if not filename:
            return
        try:
            with Path(filename).open("rb") as stream:
                data = stream.read(256 * 1024 + 1)
            if len(data) > 256 * 1024:
                raise ValueError("DNS list is larger than 256 KiB")
            content = data.decode("utf-8-sig")
            lines = json.loads(content) if Path(filename).suffix.lower() == ".json" else content.splitlines()
            if not isinstance(lines, list):
                raise ValueError("A JSON DNS list must be an array")
        except (OSError, ValueError):
            self._notify("فایل خوانده نشد. از TXT با یک آدرس در هر خط یا آرایهٔ JSON استفاده کنید.",
                         "Could not read the file. Use TXT with one address per line or a JSON array.")
            return
        self._add_addresses(lines)

    def _remove_address(self):
        selected = self._selected()
        if selected in self._settings.custom_dns and selected != self._settings.pinned_dns:
            if self._save_addresses(address for address in self._settings.custom_dns if address != selected):
                self._results.pop(selected, None)
                if selected == self._best:
                    self._best = None
                self._sync_actions()
                self._notify("سرور از فهرست حذف شد.", "Resolver removed.")

    def _start_scan(self, selected_only):
        selected = self._selected()
        port = self._available_port()
        udp_scan = not port or self._route.dns_udp_supported
        resolvers = tuple(item for item in self._catalog if (not selected_only or item.url == selected)
                          and (udp_scan or item.protocol != "UDP"))
        if self._cancel is not None or not resolvers:
            return
        cancel = self._cancel = threading.Event()
        self._scan_port = port
        self._best = None
        self._results.clear()
        self.progress.setRange(0, len(resolvers))
        self.progress.setValue(0)
        self._render_table()
        self._notify("در حال آزمایش از مسیر Direct…" if port else "در حال آزمایش روی شبکهٔ فعلی…",
                     "Testing through Direct…" if port else "Testing on the current network…")

        def work():
            outcome = "done"
            try:
                scan_dns(resolvers, port, cancel, progress=lambda result: self._measured.emit(cancel, result))
            except DirectCancelled:
                outcome = "cancelled"
            except (OSError, RuntimeError, ValueError):
                outcome = "error"
            try:
                self._finished.emit(cancel, outcome)
            except RuntimeError:
                pass

        threading.Thread(target=work, name="direct-dns-lab", daemon=True).start()

    def _on_measurement(self, cancel, result):
        if cancel is not self._cancel or cancel.is_set():
            return
        address = result.resolver.url
        self._results[address] = result
        self._render_result(address)
        self.progress.setValue(self.progress.value() + 1)

    def _on_finished(self, cancel, outcome):
        if cancel is not self._cancel:
            return
        self._cancel = None
        if cancel.is_set() or outcome == "cancelled":
            self._notify("آزمایش متوقف شد.", "Scan stopped.")
        elif outcome == "error":
            self._notify("آزمایش کامل نشد. دوباره تلاش کنید.", "The scan could not finish. Try again.")
        else:
            winner = min((result for result in self._results.values() if len(result.samples) == result.attempts),
                         key=lambda result: (result.rank, result.resolver.label), default=None)
            if winner:
                self._best = winner.resolver.url
                fa_route = "مسیر Direct" if self._scan_port else "شبکهٔ فعلی"
                en_route = "Direct route" if self._scan_port else "current network"
                self._notify(f"بهترین پاسخ روی {fa_route}: {winner.resolver.label} با {winner.latency} میلی‌ثانیه",
                             f"Best on the {en_route}: {winner.resolver.label} at {winner.latency} ms")
            else:
                self._notify("هیچ سروری به همهٔ درخواست‌ها پاسخ معتبر نداد.",
                             "No resolver answered every test request correctly.")
        self._render_table()

    def stop_scan(self):
        if self._cancel is not None and not self._cancel.is_set():
            self._cancel.set()
            self._notify("در حال توقف آزمایش…", "Stopping the scan…")
            self._sync_actions()

    def hideEvent(self, event):
        self.stop_scan()
        super().hideEvent(event)

    def _apply_selected(self):
        address = self._selected()
        if address:
            self._apply(address)

    def _apply_fastest(self):
        if self._best:
            self._apply(self._best)

    def _apply(self, address):
        if not self._can_apply(address):
            self._notify(*_UDP_COUNTRY_HINT)
            return
        phase = self._route.phase
        try:
            reload_requested = self.controller.apply_dns(address)
        except OSError as error:
            self.window.show_toast(str(error), "danger")
            return
        self.refresh()
        if reload_requested and phase == "paused":
            self._notify("ذخیره شد. پس از ادامهٔ اتصال اعمال می‌شود.", "Saved. Applies when the connection resumes.")
        elif reload_requested:
            self._notify("ذخیره شد. مسیر Direct برای اعمال DNS دوباره برقرار می‌شود.",
                         "Saved. Direct will reconnect its route to apply the DNS choice.")
        else:
            self._notify("ذخیره شد. در اتصال بعدی Direct اعمال می‌شود.", "Saved for the next Direct connection.")
