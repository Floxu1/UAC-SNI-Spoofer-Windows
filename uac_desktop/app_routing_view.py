from __future__ import annotations

import ctypes
import os
import sys
from ctypes import wintypes
from dataclasses import dataclass
from string import Template

import psutil
from PySide6.QtCore import QEvent, QFileInfo, QSignalBlocker, QSize, Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QAbstractItemView, QButtonGroup, QFileIconProvider, QFrame, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QPushButton, QTableWidget, QVBoxLayout, QWidget,
)

from .icons import pixmap
from .theme import APP_ROUTING_PALETTES


@dataclass(frozen=True)
class RunningApp:
    executable: str
    title: str
    path: str = ""


def _file_description(path, version):
    size = version.GetFileVersionInfoSizeW(path, None)
    if not size:
        return ""
    data = ctypes.create_string_buffer(size)
    if not version.GetFileVersionInfoW(path, 0, size, data):
        return ""
    address = ctypes.c_void_p()
    length = wintypes.UINT()
    if not version.VerQueryValueW(data, r"\VarFileInfo\Translation", ctypes.byref(address), ctypes.byref(length)):
        return ""
    pairs = (wintypes.WORD * (length.value // 2)).from_buffer_copy(ctypes.string_at(address, length.value))
    for language, codepage in zip(pairs[::2], pairs[1::2]):
        key = fr"\StringFileInfo\{language:04x}{codepage:04x}\FileDescription"
        if version.VerQueryValueW(data, key, ctypes.byref(address), ctypes.byref(length)) and length.value:
            description = ctypes.wstring_at(address, length.value).rstrip("\0").strip()
            if description:
                return description
    return ""


def running_apps():
    protected = {os.path.basename(sys.executable).casefold(), "xray.exe", "sing-box.exe",
                 "aether.exe", "uac-psiphon.exe", "uac_psiphon.exe"}
    processes = {}
    for process in psutil.process_iter(["name", "exe"]):
        name, path = process.info.get("name"), process.info.get("exe") or ""
        if name and name.casefold() not in protected:
            key = name.casefold()
            if key not in processes or (path and not processes[key][1]):
                processes[key] = (name, path)
    version = ctypes.windll.version if sys.platform == "win32" else None
    apps = []
    for name, path in processes.values():
        description = _file_description(path, version) if path and version else ""
        apps.append(RunningApp(name, description or os.path.splitext(name)[0], path))
    return sorted(apps, key=lambda app: (app.title.casefold(), app.executable.casefold()))


def supports_process_routing(engine, output, mode):
    if mode == "all":
        return True
    if engine == "pow":
        return True
    if engine == "xray":
        return mode == "bypass"
    return output == "vpn"


_MODES = (
    ("all", "shield", ("همه برنامه‌ها", "All apps"),
     ("همهٔ برنامه‌ها از VPN استفاده می‌کنند.", "All apps use the VPN.")),
    ("bypass", "globe", ("عبور مستقیم برنامه‌های انتخابی", "Bypass selected apps"),
     ("برنامه‌های انتخابی بدون VPN متصل می‌شوند.", "Selected apps connect without the VPN.")),
    ("only", "route", ("فقط برنامه‌های انتخابی", "Selected apps only"),
     ("فقط برنامه‌های انتخابی از VPN استفاده می‌کنند.", "Only selected apps use the VPN.")),
)

_STYLE = Template("""
QWidget#appBypassPage { background: $background; }
QFrame#routingHeader { background: transparent; border: 0; }
QFrame#routingHeader QLabel#pageTitle { color: $text; font-size: 23px; font-weight: 600; }
QFrame#routingHeader QLabel#pageSubtitle { color: $muted; font-size: 12px; font-weight: 500; }
QFrame#routingHeader QLabel#pageHeaderIcon { background: $selected; border: 1px solid $selected_border; border-radius: 8px; }
QFrame#routingPanel { background: $surface; border: 1px solid $border; border-radius: 8px; }
QFrame#routingToolbar, QFrame#routingSummary { background: transparent; border: 0; }
QFrame#routingSummary { border-top: 1px solid $border; }
QWidget#appBypassPage QLabel { color: $text; font-size: 12px; font-weight: 500; }
QWidget#appBypassPage QLabel#routingMuted { color: $muted; }
QWidget#appBypassPage QLabel#routingAppName, QWidget#appBypassPage QLabel#routingExecutable {
    font-family: "Inter", "Vazirmatn UI FD", "Segoe UI"; }
QWidget#appBypassPage QLabel#routingExecutable { color: $muted; }
QWidget#appBypassPage QLabel#routingNotice { color: $accent; }
QWidget#appBypassPage QLabel#routingCount { color: $accent; font-size: 24px; font-weight: 600; }
QWidget#appBypassPage QLabel#routingModeTitle { font-size: 13px; font-weight: 600; }
QWidget#appBypassPage QLabel#routingModeTitle[active="true"], QLabel#routingPath[route="direct"] { color: $accent; }
QWidget#appBypassPage QLabel#routingPath[route="tunnel"] { color: $vpn; }
QWidget#appBypassPage QLabel#routingPath[route="unknown"] { color: $muted; }
QLabel#routingGlyph { background: $tile; border: 1px solid $border; border-radius: 6px; }
QLabel#routingGlyph[active="true"] { background: $selected; border-color: $selected_border; }
QFrame#routingRadio { background: transparent; border: 1px solid $muted; border-radius: 7px; }
QFrame#routingRadio[active="true"] { border-color: $accent; }
QFrame#routingRadioDot { background: $accent; border-radius: 3px; }
QWidget#appBypassPage QPushButton#routingMode {
    min-height: 101px; padding: 0; background: $background; border: 1px solid $border; border-radius: 8px; }
QWidget#appBypassPage QPushButton#routingMode:hover { background: $hover; }
QWidget#appBypassPage QPushButton#routingMode:checked { background: $selected; border-color: $selected_border; }
QWidget#appBypassPage QPushButton#routingMode:focus { border-color: $accent; }
QWidget#appBypassPage QLineEdit#routingSearch, QWidget#appBypassPage QPushButton#routingAction {
    padding: 0 9px; min-height: 32px; color: $text; background: $tile; border: 1px solid $border;
    border-radius: 7px; font-size: 12px; font-weight: 500; }
QWidget#appBypassPage QLineEdit#routingSearch { background: $background; }
QWidget#appBypassPage QPushButton#routingAction:hover { background: $hover; }
QWidget#appBypassPage QPushButton#routingAction:checked { background: $selected; color: $accent; border-color: $selected_border; }
QWidget#appBypassPage QPushButton#routingAction:disabled { color: $muted; }
QWidget#appBypassPage QLineEdit#routingSearch:focus, QWidget#appBypassPage QPushButton#routingAction:focus { border-color: $accent; }
QTableWidget#processTable { background: $background; alternate-background-color: $surface; border: 0; border-radius: 0; padding: 0; }
QTableWidget#processTable QHeaderView::section {
    color: $muted; background: $tile; border: 0; border-bottom: 1px solid $border; padding: 0 10px; font-weight: 500; }
QFrame#routingCell { background: $background; border-bottom: 1px solid $border; }
QFrame#routingCell[alternate="true"] { background: $surface; }
QFrame#routingCell[marked="true"] { background: $selected; }
QFrame#routingCell[marked="true"][hovered="true"], QFrame#routingCell[hovered="true"] { background: $hover; }
QFrame#routingCell[marked="true"][leading="left"] { border-left: 3px solid $accent; }
QFrame#routingCell[marked="true"][leading="right"] { border-right: 3px solid $accent; }
""")


def app_routing_style(engine):
    return _STYLE.substitute(APP_ROUTING_PALETTES[engine])


def _flag(widget, name, value):
    if widget.property(name) != value:
        widget.setProperty(name, value)
        widget.style().unpolish(widget)
        widget.style().polish(widget)
        widget.update()


class SharedAppRoutingView(QWidget):
    def __init__(self, window, switch_type):
        super().__init__()
        self.setObjectName("appBypassPage")
        self.window = window
        self.switch_type = switch_type
        self._running = []
        self._rows = {}
        self._hovered = None
        self._icon_provider = QFileIconProvider()
        self._real_icons = {}
        self._art = {}
        self._palette = APP_ROUTING_PALETTES[window.engine_mode]
        self._switch_palette = self._switch_colors()

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 8, 12, 10)
        root.setSpacing(8)
        counts = QWidget()
        counts.setLayoutDirection(Qt.LeftToRight)
        count_layout = QHBoxLayout(counts)
        count_layout.setContentsMargins(0, 0, 0, 0)
        count_layout.setSpacing(6)
        self.selected_count = QLabel()
        self.selected_count.setObjectName("routingCount")
        count_layout.addWidget(self.selected_count)
        count_layout.addWidget(self._label("برنامهٔ انتخاب‌شده", "apps selected", "routingMuted"))
        self.header = window._page_header(
            "مسیریابی برنامه‌ها", "App routing",
            "مشخص کنید کدام برنامه‌ها از VPN استفاده کنند.",
            "Choose which apps use the VPN.", counts, compact_name="routingHeader",
        )
        root.addWidget(self.header)

        modes, mode_layout = self._panel()
        mode_layout.setContentsMargins(10, 8, 10, 10)
        mode_layout.addWidget(self._label("نحوهٔ استفاده از VPN", "VPN routing mode", "routingModeTitle"))
        cards = QHBoxLayout()
        cards.setSpacing(8)
        self.modes = {}
        self._mode_parts = {}
        group = QButtonGroup(self)
        for key, glyph, title, description in _MODES:
            card = QPushButton()
            card.setObjectName("routingMode")
            card.setCheckable(True)
            card.setCursor(Qt.PointingHandCursor)
            card.setFixedHeight(103)
            box = QVBoxLayout(card)
            box.setContentsMargins(10, 8, 10, 8)
            box.setSpacing(3)
            top = QHBoxLayout()
            tile = QLabel()
            tile.setObjectName("routingGlyph")
            tile.setAlignment(Qt.AlignCenter)
            tile.setFixedSize(30, 30)
            radio = QFrame()
            radio.setObjectName("routingRadio")
            radio.setFixedSize(14, 14)
            radio_layout = QHBoxLayout(radio)
            radio_layout.setContentsMargins(0, 0, 0, 0)
            dot = QFrame()
            dot.setObjectName("routingRadioDot")
            dot.setFixedSize(6, 6)
            radio_layout.addWidget(dot, 0, Qt.AlignCenter)
            top.addWidget(tile)
            top.addStretch(1)
            top.addWidget(radio)
            box.addLayout(top)
            box.addStretch(1)
            heading = self._label(*title, "routingModeTitle")
            help_label = self._label(*description, "routingMuted")
            help_label.setWordWrap(True)
            box.addWidget(heading)
            box.addWidget(help_label)
            for child in card.findChildren(QWidget):
                child.setAttribute(Qt.WA_TransparentForMouseEvents)
            group.addButton(card)
            card.clicked.connect(lambda _checked=False, mode=key: self._change_mode(mode))
            cards.addWidget(card, 1)
            self.modes[key] = card
            self._mode_parts[key] = (glyph, tile, radio, dot, heading, help_label)
        mode_layout.addLayout(cards)
        root.addWidget(modes)

        results, result_layout = self._panel()
        result_layout.setContentsMargins(1, 1, 1, 1)
        result_layout.setSpacing(0)
        toolbar = QFrame()
        toolbar.setObjectName("routingToolbar")
        controls = QHBoxLayout(toolbar)
        controls.setContentsMargins(10, 9, 10, 9)
        controls.setSpacing(8)
        self.search = QLineEdit()
        self.search.setObjectName("routingSearch")
        self.search.setClearButtonEnabled(True)
        self.search.setFixedHeight(34)
        self._search_icon = self.search.addAction(QIcon(), QLineEdit.LeadingPosition)
        controls.addWidget(self.search, 1)
        self.all_filter = self._button("همه برنامه‌ها", "All apps")
        self.selected_filter = self._button("انتخاب‌شده‌ها", "Selected")
        filters = QButtonGroup(self)
        for button in (self.all_filter, self.selected_filter):
            button.setCheckable(True)
            filters.addButton(button)
            controls.addWidget(button)
            button.clicked.connect(self._filter)
        self.all_filter.setChecked(True)
        self.refresh_button = self._button("به‌روزرسانی", "Refresh")
        self.refresh_button.clicked.connect(window.refresh_processes)
        controls.addWidget(self.refresh_button)
        result_layout.addWidget(toolbar)

        self.table = QTableWidget(0, 3)
        self.table.setObjectName("processTable")
        self.table.setShowGrid(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionMode(QAbstractItemView.NoSelection)
        self.table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(48)
        self.table.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)
        header = self.table.horizontalHeader()
        header.setFixedHeight(34)
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        self.table.setColumnWidth(2, 82)
        self.table.viewport().setMouseTracking(True)
        result_layout.addWidget(self.table, 1)
        self.empty = QLabel(self.table.viewport())
        self.empty.setObjectName("routingMuted")
        self.empty.setAlignment(Qt.AlignCenter)
        self.empty.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.table.viewport().installEventFilter(self)

        summary = QFrame()
        summary.setObjectName("routingSummary")
        summary.setFixedHeight(38)
        line = QHBoxLayout(summary)
        line.setContentsMargins(10, 0, 10, 0)
        self.summary = QLabel()
        self.summary.setObjectName("routingMuted")
        self.visible_count = QLabel()
        self.visible_count.setObjectName("routingMuted")
        line.addWidget(self.summary, 1)
        line.addWidget(self.visible_count)
        result_layout.addWidget(summary)
        root.addWidget(results, 1)

        footer = QFrame()
        footer.setObjectName("routingPanel")
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(10, 4, 10, 4)
        self.notice_icon = QLabel()
        self.notice_icon.setFixedWidth(14)
        footer_layout.addWidget(self.notice_icon)
        footer.setFixedHeight(48)
        self.notice = QLabel()
        self.notice.setObjectName("routingNotice")
        self.notice.setWordWrap(True)
        footer_layout.addWidget(self.notice, 1)
        root.addWidget(footer)
        self.search.textChanged.connect(self._filter)

    def _label(self, fa, en, role):
        label = self.window._bind_text(QLabel(), fa, en)
        label.setObjectName(role)
        return label

    def _button(self, fa, en):
        button = self.window._bind_text(QPushButton(), fa, en)
        button.setObjectName("routingAction")
        button.setFixedHeight(34)
        button.setCursor(Qt.PointingHandCursor)
        return button

    @staticmethod
    def _panel():
        panel = QFrame()
        panel.setObjectName("routingPanel")
        layout = QVBoxLayout(panel)
        layout.setSpacing(8)
        return panel, layout

    def _switch_colors(self):
        return {**self._palette, "track_on": self._palette["accent"],
                "thumb_off": self._palette["muted"], "icon": self._palette["accent"]}

    def _glyph(self, name, tone, size):
        key = name, tone, size
        if key not in self._art:
            self._art[key] = pixmap(name, self._palette[tone], size, lucide=True)
        return self._art[key]

    def set_engine(self, engine):
        palette = APP_ROUTING_PALETTES[engine]
        if self._palette is not palette:
            self._palette = palette
            self._switch_palette = self._switch_colors()
            self._art.clear()
        self.refresh()

    def set_language(self):
        self.search.setPlaceholderText(self.window.tr("جست‌وجوی برنامه…", "Search apps…"))
        self.table.setHorizontalHeaderLabels([
            self.window.tr("نام برنامه", "App"),
            self.window.tr("مسیر پس از اعمال", "Route after applying"),
            self.window.tr("انتخاب", "Select"),
        ])
        leading = Qt.AlignRight if self.window.language == "fa" else Qt.AlignLeft
        self.table.horizontalHeaderItem(0).setTextAlignment(leading | Qt.AlignAbsolute | Qt.AlignVCenter)
        self.refresh()

    def set_apps(self, apps):
        self._running = apps
        self.refresh()

    def _change_mode(self, mode):
        if not self.window._change_global_settings(routing_mode=mode):
            self.refresh()

    def _add_row(self, row, app):
        cells = []
        for column in range(3):
            cell = QFrame()
            cell.setObjectName("routingCell")
            cell.setProperty("alternate", row % 2 == 1)
            cell.installEventFilter(self)
            box = QHBoxLayout(cell)
            box.setContentsMargins(10, 0, 10, 0)
            box.setSpacing(7)
            self.table.setCellWidget(row, column, cell)
            cells.append(cell)
        name_cell, path_cell, choice_cell = cells
        glyph = QLabel()
        glyph.setObjectName("routingGlyph")
        glyph.setAlignment(Qt.AlignCenter)
        glyph.setFixedSize(30, 30)
        name_cell.layout().addWidget(glyph)
        titles = QVBoxLayout()
        titles.setSpacing(0)
        titles.setAlignment(Qt.AlignVCenter)
        for title, role in ((app.title, "routingAppName"), (app.executable, "routingExecutable")):
            text = QLabel(title)
            text.setTextFormat(Qt.PlainText)
            text.setObjectName(role)
            text.setLayoutDirection(Qt.LeftToRight)
            text.setToolTip(title)
            text.setMinimumWidth(0)
            titles.addWidget(text)
        name_cell.layout().addLayout(titles, 1)
        route_icon = QLabel()
        route = QLabel()
        route.setObjectName("routingPath")
        path_cell.layout().addStretch(1)
        path_cell.layout().addWidget(route_icon)
        path_cell.layout().addWidget(route)
        path_cell.layout().addStretch(1)
        switch = self.switch_type()
        switch.setLayoutDirection(Qt.LeftToRight)
        switch.set_quick_style(self._switch_palette)
        switch.toggled.connect(lambda checked, name=app.executable: self.window._save_process_selection(name, checked))
        choice_cell.layout().addWidget(switch, 0, Qt.AlignCenter)
        self._rows[app.executable.casefold()] = (app, cells, glyph, route_icon, route, switch)

    def _sync_rows(self, saved):
        apps = {app.executable.casefold(): app for app in self._running}
        for name in saved:
            key = name.casefold()
            previous = self._rows.get(key)
            apps.setdefault(key, previous[0] if previous else RunningApp(name, os.path.splitext(name)[0]))
        ordered = sorted(apps.values(), key=lambda app: (app.title.casefold(), app.executable.casefold()))
        if ordered == [row[0] for row in self._rows.values()]:
            return
        scroll = self.table.verticalScrollBar().value()
        self._hovered = None
        self._rows.clear()
        self.table.setRowCount(0)
        self.table.setRowCount(len(ordered))
        for row, app in enumerate(ordered):
            self._add_row(row, app)
        self.table.verticalScrollBar().setValue(scroll)

    def refresh(self):
        w = self.window
        preferences = w.global_settings.snapshot()
        mode, output = preferences.routing_mode, preferences.connection_mode
        saved = w.global_settings.processes()
        selected = {name.casefold() for name in saved}
        self._sync_rows(saved)
        self.selected_count.setText(str(len(selected)))
        self.modes[mode].setChecked(True)
        self.header.findChild(QLabel, "pageHeaderIcon").setPixmap(self._glyph("route", "accent", 24))
        self._search_icon.setIcon(QIcon(self._glyph("search", "muted", 15)))
        self.refresh_button.setIcon(QIcon(self._glyph("refresh", "muted", 14)))
        self.notice_icon.setPixmap(self._glyph("info", "accent", 13))
        for key, card in self.modes.items():
            glyph, tile, radio, dot, title, description = self._mode_parts[key]
            active = key == mode
            _flag(tile, "active", active)
            _flag(radio, "active", active)
            _flag(title, "active", active)
            dot.setVisible(active)
            tile.setPixmap(self._glyph(glyph, "accent" if active else "muted", 16))
            card.setAccessibleName(title.text())
            card.setAccessibleDescription(description.text())
        supported = supports_process_routing(w.engine_mode, output, mode)
        self._set_notice(preferences, supported, len(selected))
        vpn = output == "vpn"
        routed = vpn or (w.engine_mode != "direct" and supported)
        direct_labels = ("بدون VPN", "Without VPN") if vpn else ("مستقیم", "Direct")
        tunnel_labels = ("از طریق VPN", "Via VPN") if vpn else ("از طریق پروکسی", "Via proxy")
        alignment = (Qt.AlignRight if w.language == "fa" else Qt.AlignLeft) | Qt.AlignAbsolute | Qt.AlignVCenter
        leading = "right" if w.language == "fa" else "left"
        for key, (app, cells, glyph, route_icon, route, switch) in self._rows.items():
            checked = key in selected
            if app.path and app.path not in self._real_icons:
                self._real_icons[app.path] = self._icon_provider.icon(QFileInfo(app.path)).pixmap(QSize(22, 22))
            real_icon = self._real_icons.get(app.path)
            glyph.setPixmap(real_icon if real_icon is not None and not real_icon.isNull()
                            else self._glyph("app-window", "muted", 16))
            for label in cells[0].findChildren(QLabel):
                if label is not glyph:
                    label.setAlignment(alignment)
            if routed:
                direct = supported and ((mode == "bypass" and checked) or (mode == "only" and not checked))
                kind = "direct" if direct else "tunnel"
                labels = direct_labels if direct else tunnel_labels
                route_icon.setPixmap(self._glyph("globe" if direct else "shield", "accent" if direct else "vpn", 15))
            else:
                kind, labels = "unknown", ("بسته به تنظیم پروکسی برنامه", "Depends on app proxy settings")
                route_icon.setPixmap(self._glyph("globe", "muted", 15))
            route.setText(w.tr(*labels))
            _flag(route, "route", kind)
            for cell in cells:
                _flag(cell, "marked", checked and mode != "all")
            _flag(cells[0], "leading", leading)
            switch.set_quick_style(self._switch_palette)
            with QSignalBlocker(switch):
                switch.setChecked(checked)
            switch.setEnabled(mode != "all")
            switch.setAccessibleName(w.tr(f"انتخاب {app.title}", f"Select {app.title}"))
        self._filter()

    def _set_notice(self, preferences, supported, count):
        w = self.window
        mode, output = preferences.routing_mode, preferences.connection_mode
        if mode == "only" and w.engine_mode == "xray":
            summary = ("گزینهٔ «فقط برنامه‌های انتخابی» در Xray پشتیبانی نمی‌شود.",
                       "Xray does not support selected-apps-only routing.")
        elif output != "vpn":
            summary = (("مسیریابی جداگانهٔ برنامه‌ها به VPN نیاز دارد.", "Per-app routing requires VPN mode.")
                       if w.engine_mode == "direct" else
                       ("این تنظیم فقط روی ترافیکی اعمال می‌شود که برنامه‌ها به پروکسی می‌فرستند.",
                        "These rules apply only to traffic apps send through the proxy."))
        elif mode == "all":
            summary = ("همهٔ برنامه‌ها از VPN استفاده می‌کنند.", "All apps use the VPN.")
        elif mode == "bypass":
            summary = (f"{count} برنامهٔ انتخابی بدون VPN متصل می‌شوند.", f"{count} selected apps connect without the VPN.")
        else:
            summary = (f"فقط {count} برنامهٔ انتخابی از VPN استفاده می‌کنند.", f"Only {count} selected apps use the VPN.")
        if mode == "all":
            notice = ("فهرست انتخاب‌ها حفظ می‌شود. تغییر حالت در اتصال بعدی اعمال می‌شود.",
                      "Selections are kept. Mode changes apply on the next connection.")
        elif not supported:
            notice = ("این انتخاب‌ها برای موتور یا نوع اتصال سازگار ذخیره می‌شوند.",
                      "These selections are saved for a compatible engine or connection mode.")
        elif w._protected_session():
            notice = ("قطع اضطراری روشن است. برای اعمال تغییرات، اتصال را دستی دوباره برقرار کنید.",
                      "Kill Switch is active. Reconnect manually to apply changes.")
        elif w._routing_selection_reconnects(preferences):
            notice = ("تغییر حالت در اتصال بعدی اعمال می‌شود. تغییر فهرست، اتصال را دوباره برقرار می‌کند.",
                      "Mode changes apply on the next connection. Editing the app list reconnects the current session.")
        else:
            notice = ("تنظیمات ذخیره می‌شوند و در اتصال بعدی اعمال خواهند شد.",
                      "Settings are saved and will apply on the next connection.")
        self.summary.setText(w.tr(*summary))
        self.notice.setText(w.tr(*notice))

    def refresh_notice(self):
        preferences = self.window.global_settings.snapshot()
        supported = supports_process_routing(self.window.engine_mode, preferences.connection_mode, preferences.routing_mode)
        self._set_notice(preferences, supported, len({name.casefold() for name in self.window.global_settings.processes()}))

    def showEvent(self, event):
        super().showEvent(event)
        self.refresh_notice()

    def _filter(self, *_):
        query = self.search.text().strip().casefold()
        selected_only = self.selected_filter.isChecked()
        visible = 0
        for row, (app, _cells, _glyph, _path_icon, _route, switch) in enumerate(self._rows.values()):
            show = (not selected_only or switch.isChecked()) and (query in app.title.casefold() or query in app.executable.casefold())
            self.table.setRowHidden(row, not show)
            visible += int(show)
        self.visible_count.setText(self.window.tr(f"{visible} از {len(self._rows)} برنامه", f"{visible} of {len(self._rows)} apps"))
        self.empty.setText(self.window.tr("برنامه‌ای پیدا نشد.", "No apps found."))
        self.empty.setVisible(visible == 0)
        self.empty.setGeometry(self.table.viewport().rect())

    def eventFilter(self, watched, event):
        if watched is self.table.viewport():
            if event.type() == QEvent.Resize:
                self.empty.setGeometry(watched.rect())
            elif event.type() == QEvent.Leave:
                self._hover_row(-1)
            elif event.type() == QEvent.MouseMove:
                self._hover_row(self.table.rowAt(event.position().toPoint().y()))
        elif event.type() == QEvent.Enter:
            self._hover_row(self.table.rowAt(watched.y()))
        return super().eventFilter(watched, event)

    def _hover_row(self, row):
        if self._hovered == row:
            return
        for index, value in ((self._hovered, False), (row, True)):
            if index is not None and index >= 0:
                for column in range(3):
                    cell = self.table.cellWidget(index, column)
                    if cell is not None:
                        _flag(cell, "hovered", value)
        self._hovered = row
