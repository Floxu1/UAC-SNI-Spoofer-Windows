"""Shared editor for user-managed destination exceptions."""
from __future__ import annotations

import os
from string import Template

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QPlainTextEdit, QToolButton, QVBoxLayout, QWidget,
)

from .application_settings import direct_domains, direct_ips
from .icons import icon, pixmap
from .paths import BIN
from .pow.routing import iran_domains
from .routing_data import geoip_entries, geosite_entries
from .settings_ui import SettingsSelect
from .theme import APP_ROUTING_PALETTES


_STYLE = Template("""
#directRoutingPage QFrame#siteCard { background: $surface; border: 1px solid $border; border-radius: 8px; }
#directRoutingPage QLabel#siteKey { color: $text; font-weight: 600; font-size: 13px; }
#directRoutingPage QLabel#siteNote { color: $muted; font-size: 11px; }
#directRoutingPage QLabel#siteState { color: $accent; font-weight: 600; }
#directRoutingPage QFrame#siteDivider { background: $border; border: none; }
#directRoutingPage QLineEdit, #directRoutingPage QPlainTextEdit, #directRoutingPage QListWidget {
    background: $background; color: $text; border: 1px solid $border; border-radius: 6px;
}
#directRoutingPage QListWidget { background: $surface; border: none; }
#directRoutingPage QListWidget::item { border-bottom: 1px solid $border; }
#directRoutingPage QLineEdit { min-height: 32px; padding: 0 8px; }
#directRoutingPage QLineEdit:focus { border-color: $accent; }
#directRoutingPage QPushButton {
    background: $tile; color: $text; border: 1px solid $border; border-radius: 6px; padding: 0 9px;
    min-height: 33px; font-size: 12px; font-weight: 600;
}
#directRoutingPage QPushButton#sitePrimary { background: $accent; color: $background; border-color: $accent; }
#directRoutingPage QPushButton#sitePrimary:disabled { background: $tile; color: $muted; border-color: $border; }
#directRoutingPage QPushButton:hover, #directRoutingPage QPushButton:focus { border-color: $accent; }
#directRoutingPage QToolButton#siteRemove { border: 1px solid transparent; border-radius: 5px; background: transparent; }
#directRoutingPage QToolButton#siteRemove:hover, #directRoutingPage QToolButton#siteRemove:focus {
    background: $hover; border-color: $border;
}
""")


class _DestinationList(QFrame):
    def __init__(self, page, title, description, placeholder, glyph, parser):
        super().__init__()
        self.setObjectName("siteCard")
        self.page, self.glyph, self.parser = page, glyph, parser
        self.entries = []
        root = QVBoxLayout(self)
        root.setContentsMargins(1, 1, 1, 1)
        root.setSpacing(0)
        head = QHBoxLayout()
        head.setContentsMargins(10, 10, 10, 9)
        head.setSpacing(8)
        self.mark = QLabel()
        self.mark.setFixedSize(22, 22)
        head.addWidget(self.mark)
        copy = QVBoxLayout()
        copy.setSpacing(2)
        copy.addWidget(page._label(*title, name="siteKey"))
        copy.addWidget(page._label(*description))
        head.addLayout(copy, 1)
        root.addLayout(head)
        root.addWidget(page._divider())

        bar = QHBoxLayout()
        bar.setContentsMargins(9, 9, 9, 9)
        bar.setSpacing(6)
        self.address = QLineEdit()
        self.address.setProperty("technical", True)
        self.address.setLayoutDirection(Qt.LeftToRight)
        self.address.setAlignment(Qt.AlignLeft | Qt.AlignAbsolute)
        self.address.setPlaceholderText(placeholder)
        self.address.returnPressed.connect(self.add)
        bar.addWidget(self.address, 1)
        bar.addWidget(page._button("افزودن", "Add", "plus", self.add, primary=True))
        root.addLayout(bar)
        root.addWidget(page._divider())

        self.list = QListWidget()
        self.list.setSelectionMode(QListWidget.NoSelection)
        self.list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.list.setMinimumHeight(132)
        root.addWidget(self.list, 1)
        root.addWidget(page._divider())
        self.total = QLabel(objectName="siteNote")
        self.total.setContentsMargins(10, 8, 10, 8)
        root.addWidget(self.total)

    def add(self):
        try:
            entries = self.parser(self.address.text(), strict=True)
        except ValueError:
            if self.parser is direct_domains:
                self.page._message("فقط نام دامنه را وارد کنید، مثل example.com.",
                                   "Enter a domain name such as example.com.")
            else:
                self.page._message("یک IPv4، IPv6 یا محدوده مانند 192.0.2.0/24 وارد کنید.",
                                   "Enter an IPv4, IPv6 or a range such as 192.0.2.0/24.")
            return
        new = [entry for entry in entries if entry not in self.entries]
        if not new:
            if entries:
                self.page._message("این مقصد از قبل در فهرست است.", "This destination is already listed.")
            return
        self.entries.extend(new)
        self.address.clear()
        self.render()
        self.list.scrollToBottom()
        self.page._update_status()

    def remove(self, entry):
        self.entries.remove(entry)
        self.render()
        self.page._update_status()

    def render(self):
        page = self.page
        self.mark.setPixmap(pixmap(self.glyph, page.palette["accent"], 19))
        self.list.clear()
        for entry in self.entries:
            item = QListWidgetItem()
            item.setSizeHint(QSize(0, 41))
            row = QWidget()
            layout = QHBoxLayout(row)
            layout.setContentsMargins(10, 2, 10, 2)
            remove = QToolButton(objectName="siteRemove")
            remove.setFixedSize(28, 28)
            remove.setIcon(icon("trash", page.palette["muted"], 15))
            remove.setToolTip(page.window.tr(f"حذف {entry}", f"Remove {entry}"))
            remove.setAccessibleName(remove.toolTip())
            remove.clicked.connect(lambda _checked=False, value=entry: self.remove(value))
            layout.addWidget(remove)
            value = page._elided(entry)
            value.setLayoutDirection(Qt.LeftToRight)
            value.setAlignment(Qt.AlignLeft | Qt.AlignAbsolute | Qt.AlignVCenter)
            value.setProperty("technical", True)
            layout.addWidget(value, 1)
            self.list.addItem(item)
            self.list.setItemWidget(item, row)
        count = len(self.entries)
        self.total.setText(page.window.tr(f"{count} مورد در فهرست", f"{count} in the list"))


class SharedDirectRoutingView(QWidget):
    _sources = (
        ("geosite.dat", "category-ir", "دامنه‌های ایران", "Iranian domains"),
        ("geosite.dat", "category-bank-ir", "بانک‌های ایرانی", "Iranian banks"),
        ("geoip.dat", "ir", "محدوده‌های آی‌پی ایران", "Iranian IP ranges"),
    )

    def __init__(self, window):
        super().__init__()
        from .ui import ElidedLabel

        self.window = window
        self._elided = ElidedLabel
        self._saved = ((), ())
        self._engine = None
        self.palette = APP_ROUTING_PALETTES[window.engine_mode]
        root = QVBoxLayout(self)
        root.setContentsMargins(15, 8, 15, 10)
        root.setSpacing(8)
        self.back = self._button("بازگشت", "Back", "chevron-left", self._go_back)
        root.addWidget(window._page_header(
            "عبور مستقیم سایت‌ها", "Direct site routing",
            "مشخص کنید چه مقصدهایی بدون VPN باز شوند.", "Choose destinations that open outside the VPN.",
            self.back, compact_name="siteRoutingHeader",
        ))

        scroll, content = window._scroll_page()
        root.addWidget(scroll, 1)
        body = QVBoxLayout(content)
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(8)
        status = QFrame(objectName="siteCard")
        status_row = QHBoxLayout(status)
        status_row.setContentsMargins(11, 9, 11, 9)
        copy = QVBoxLayout()
        copy.setSpacing(2)
        copy.addWidget(self._label("عبور مستقیم سایت‌های ایرانی", "Bypass VPN for Iranian sites", name="siteKey"))
        copy.addWidget(self._label("فهرست پیش‌فرض سایت‌های ایرانی برنامه", "The app’s built-in Iranian site list"))
        status_row.addLayout(copy, 1)
        self.state = QLabel(objectName="siteState")
        status_row.addWidget(self.state)
        body.addWidget(status)

        lists = QHBoxLayout()
        lists.setSpacing(8)
        self.domains = _DestinationList(self, ("سایت‌های دلخواه", "Custom sites"),
                                       ("نام دامنه را وارد کنید.", "Enter a domain name."),
                                       "example.com", "globe", direct_domains)
        self.ips = _DestinationList(self, ("آی‌پی‌های دلخواه", "Custom IPs"),
                                   ("یک آی‌پی یا محدوده وارد کنید.", "Enter an IP address or range."),
                                   "192.0.2.10 / 2001:db8::/64", "server", direct_ips)
        lists.addWidget(self.domains, 1)
        lists.addWidget(self.ips, 1)
        body.addLayout(lists, 1)
        self.notice = QLabel(objectName="siteNote")
        self.notice.setWordWrap(True)
        self.notice.setContentsMargins(2, 3, 2, 3)
        body.addWidget(self.notice)
        self.advanced = self._button("تنظیمات پیشرفته و فایل‌های مسیریابی", "Advanced settings and routing files",
                                     "chevron-down", self._toggle_sources)
        self.advanced.setCheckable(True)
        body.addWidget(self.advanced)
        self.source_box = QFrame(objectName="siteCard")
        details = QVBoxLayout(self.source_box)
        details.setContentsMargins(9, 8, 9, 8)
        details.setSpacing(8)
        toolbar = QHBoxLayout()
        self.source = SettingsSelect()
        self.source.currentIndexChanged.connect(self._read_source)
        toolbar.addWidget(self.source, 1)
        toolbar.addWidget(self._button("باز کردن پوشه", "Open folder", "folder", lambda: os.startfile(BIN)))
        toolbar.addWidget(self._button("بازخوانی", "Reload lists", "refresh", self._reload_sources))
        details.addLayout(toolbar)
        self.source_note = QLabel(objectName="siteNote")
        self.source_note.setWordWrap(True)
        details.addWidget(self.source_note)
        self.preview = QPlainTextEdit(readOnly=True)
        self.preview.setProperty("technical", True)
        self.preview.setLayoutDirection(Qt.LeftToRight)
        self.preview.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.preview.setFixedHeight(150)
        details.addWidget(self.preview)
        body.addWidget(self.source_box)
        self.source_box.hide()

        footer = QHBoxLayout()
        self.footer_status = QLabel(objectName="siteNote")
        self.footer_status.setWordWrap(True)
        footer.addWidget(self.footer_status, 1)
        footer.addWidget(self._button("انصراف", "Cancel", "x-circle", self._go_back))
        self.save = self._button("ذخیره تغییرات", "Save changes", "check-circle", self._save, primary=True)
        footer.addWidget(self.save)
        root.addLayout(footer)
        self.set_engine(window.engine_mode)

    def _label(self, fa, en, *, name="siteNote"):
        label = self.window._bind_text(QLabel(), fa, en)
        label.setObjectName(name)
        label.setWordWrap(True)
        return label

    def _button(self, fa, en, glyph, action, *, primary=False):
        button = self.window._action_button(fa, en, glyph, "sitePrimary" if primary else "siteAction")
        button.clicked.connect(action)
        return button

    @staticmethod
    def _divider():
        divider = QFrame(objectName="siteDivider")
        divider.setFixedHeight(1)
        return divider

    def set_engine(self, engine):
        if engine == self._engine:
            return
        self._engine = engine
        self.palette = APP_ROUTING_PALETTES[engine]
        self.setStyleSheet(_STYLE.substitute(self.palette))
        self.refresh_labels()

    def open(self):
        settings = self.window.global_settings.snapshot()
        self._saved = direct_domains(settings.domains_direct), direct_ips(settings.ips_direct)
        self.domains.entries, self.ips.entries = map(list, self._saved)
        self.domains.address.clear()
        self.ips.address.clear()
        self.refresh_labels()

    def refresh_labels(self):
        direction = "chevron-left" if self.window.language == "en" else "chevron-right"
        self.back.setIcon(icon(direction, self.palette["muted"], 15))
        self.domains.render()
        self.ips.render()
        self._update_status()
        index = max(0, self.source.currentIndex())
        self.source.blockSignals(True)
        self.source.clear()
        for file, _, fa, en in self._sources:
            self.source.addItem(self.window._ui_text(f"{fa} · {file}", f"{en} · {file}"))
        self.source.setCurrentIndex(index)
        self.source.blockSignals(False)
        if self.advanced.isChecked():
            self._read_source()

    def _values(self):
        return tuple(self.domains.entries), tuple(self.ips.entries)

    def _message(self, fa, en):
        self.footer_status.setText(self.window._ui_text(fa, en))

    def _update_status(self):
        w = self.window
        settings = w.global_settings.snapshot()
        guarded = self._engine in ("pow", "direct") and settings.connection_mode == "vpn" and settings.kill_switch
        if guarded and settings.iran_direct:
            self.state.setText(w.tr("معلق با قطع اضطراری", "Paused by Kill Switch"))
        else:
            self.state.setText(w.tr("● فعال", "● On") if settings.iran_direct else w.tr("○ خاموش", "○ Off"))
        if guarded:
            note = w.tr("با قطع اضطراری فعال، استثناهای سایت در حالت TUN معلق می‌مانند.",
                        "Site exceptions are suspended while TUN Kill Switch is enabled.")
        elif settings.connection_mode == "vpn":
            note = w.tr("تغییرات در اتصال بعدی اعمال می‌شوند. قوانین برنامه‌ها و فیلترهای امنیتی اولویت دارند.",
                        "Changes apply on the next connection. App routing and security filters take priority.")
        else:
            note = w.tr("تغییرات در اتصال بعدی و برای برنامه‌هایی اعمال می‌شوند که از پروکسی استفاده می‌کنند.",
                        "Changes apply on the next connection, for apps using the proxy.")
        if self._engine == "direct" and not w.direct_controller.store.settings().wireguard_over_direct:
            note += " " + w.tr("Direct TLS از خروجی شبکهٔ محلی استفاده می‌کند.",
                               "Direct TLS uses the local network as its exit.")
        if self._engine == "direct" and not w.direct_controller.store.settings().ipv6:
            note += " " + w.tr("IPv6 در تنظیمات Direct خاموش است.", "IPv6 is disabled in Direct Settings.")
        elif settings.connection_mode == "vpn" and settings.ipv6_block:
            note += " " + w.tr("محافظت IPv6 همچنان اولویت دارد.", "IPv6 protection still takes priority.")
        self.notice.setText(note)
        dirty = self._saved != self._values()
        self.save.setEnabled(dirty)
        if dirty:
            self._message("تغییرات ذخیره نشده‌اند.", "Unsaved changes.")
        else:
            self._message("بدون تغییر ذخیره‌نشده", "No unsaved changes")

    def _go_back(self):
        self.window.show_page(self.window.GLOBAL_SETTINGS_PAGE)

    def _save(self):
        changes = {name: ", ".join(values) for name, before, values in
                   zip(("domains_direct", "ips_direct"), self._saved, self._values()) if before != values}
        if changes and self.window._change_global_settings(**changes):
            self._saved = self._values()
            self._update_status()
            self._message("ذخیره شد. در اتصال بعدی اعمال می‌شود.", "Saved. Changes apply on the next connection.")

    def _toggle_sources(self, expanded):
        self.source_box.setVisible(expanded)
        if expanded:
            self._read_source()

    def _reload_sources(self):
        iran_domains.cache_clear()
        self._read_source()

    def _read_source(self, *_args):
        if not self.advanced.isChecked() or self.source.currentIndex() < 0:
            return
        file, category, _, _ = self._sources[self.source.currentIndex()]
        w = self.window
        try:
            if file == "geoip.dat":
                entries = list(geoip_entries(BIN / file, category))
            else:
                kinds = ("keyword", "regexp", "domain", "full")
                entries = [f"{kinds[kind] if 0 <= kind < len(kinds) else kind}:{value}"
                           for kind, value in geosite_entries(BIN / file, category)]
        except (OSError, ValueError):
            self.preview.clear()
            self.source_note.setText(w.tr("فایل مسیریابی خوانده نشد.", "Could not read the routing file."))
            return
        self.preview.setPlainText("\n".join(entries))
        applies = (
            w.tr("PoW برای فهرست داخلی از تطبیق پسوند دامنه استفاده می‌کند.",
                 "PoW uses domain suffix matching for its built-in list.") if self._engine == "pow" else
            w.tr("دستهٔ بانک‌ها در Direct به قواعد داخلی اضافه می‌شود.",
                 "Direct adds the bank category to its built-in rules.") if category == "category-bank-ir" else ""
        )
        self.source_note.setText(f"{file} / {category} · {len(entries)}   {applies}")
