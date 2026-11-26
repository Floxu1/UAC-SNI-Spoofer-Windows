import json
from pathlib import Path
from string import Template

from PySide6.QtCore import QLocale, QSignalBlocker, Qt
from PySide6.QtGui import QPalette
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QFrame, QGridLayout,
    QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton, QSizePolicy, QSpinBox,
    QStyle, QStyledItemDelegate, QStyleOptionComboBox, QStylePainter, QTabWidget, QToolTip, QVBoxLayout, QWidget,
)

from .fonts import DASHBOARD_HEADING_QSS, DASHBOARD_LABEL_QSS, DASHBOARD_WEIGHT
from .icons import pixmap
from .quick_controls import PALETTES

GLOBAL_SETTINGS_STYLE = """
QTabWidget#settingsTabs::pane { border: 0; background: transparent; }
QTabWidget#settingsTabs QTabBar::tab { background: #0b1b2e; color: #b4c8df;
    border: 1px solid #203b53; border-radius: 9px; min-height: 25px; padding: 4px 15px; margin: 0 3px; }
QTabWidget#settingsTabs QTabBar::tab:hover { background: #162c43; color: #f1f8ff; }
QTabWidget#settingsTabs QTabBar::tab:selected { background: #0e3a45; border-color: #389693; color: #eefeff; }
QTabWidget#settingsTabs QTabBar::tab:focus { border-color: #50ebdf; }
QFrame#settingsCard { background: #0e1c2e; border: 1px solid #24415a; border-radius: 16px; }
QFrame#settingsDivider { background: #20374e; border: 0; }
QFrame#settingsRow { border-radius: 9px; }
QFrame#settingsRow:hover { background: #152b40; }
QLabel#settingsCardTitle { color: #f0f7ff; font-size: 16px; font-weight: 750; }
QLabel#settingsRowTitle { color: #e7f1fb; font-size: 14px; font-weight: 650; }
QLabel#settingsRowHelp { color: #acc1d9; font-size: 13px; }
QLabel#settingsRowIcon { color: #50ebdf; background: #102a40; border: 1px solid #26465d; border-radius: 9px; }
QComboBox#settingsSelect, QLineEdit#settingsInput, QSpinBox#settingsNumber {
    background: #081522; border: 1px solid #31506a; border-radius: 8px; min-height: 23px; padding: 4px 9px; }
QComboBox#settingsSelect:hover, QLineEdit#settingsInput:hover, QSpinBox#settingsNumber:hover { border-color: #5a819a; }
QComboBox#settingsSelect:focus, QLineEdit#settingsInput:focus, QSpinBox#settingsNumber:focus { border-color: #50ebdf; }
QComboBox#settingsSelect:disabled, QLineEdit#settingsInput:disabled, QSpinBox#settingsNumber:disabled {
    background: #0c1928; border-color: #21364b; color: #8296ad; }
QPushButton#settingsAction { background: #142b42; border: 1px solid #385570; color: #e2effc;
    border-radius: 8px; padding: 5px 12px; min-width: 54px; min-height: 23px; font-weight: 650; }
QPushButton#settingsAction:hover { background: #1e3b54; border-color: #54819a; }
QPushButton#settingsAction:focus { border-color: #50ebdf; }
QPushButton#settingsAction:pressed { background: #102033; }
QPushButton#settingsAction[destructive="true"] { color: #ffb4c0; border-color: #6b3e53; }
"""

_SHARED_GLOBAL_STYLE = Template("""
QFrame#globalSettingsSection { background: $surface; border: 1px solid $border; border-radius: 9px; }
QFrame#globalSettingsDivider { background: $border; }
QFrame#globalSettingsTile { background: $row; border: 1px solid $border; border-radius: 6px; }
QFrame#globalSettingsTile:hover { border-color: $hover_border; background: $hover; }
QPushButton#globalRoutingLink { background: $action; border: 1px solid $border; border-radius: 6px; padding: 0; }
QPushButton#globalRoutingLink:hover, QPushButton#globalRoutingLink:focus { border-color: $icon; background: $hover; }
QLabel#globalSettingsHeading { color: $text; font-size: 25px; font-weight: $weight; }
QLabel#globalSettingsSectionTitle { color: $text; $heading_font }
QLabel#globalSettingsLabel { color: $text; $label_font }
QLabel#globalSettingsHelp, QLabel#globalSettingsStamp { color: $secondary; font-size: 11px; }
QLabel#globalSettingsPageIcon { background: $row; border: 1px solid $border; border-radius: 9px; }
QWidget#globalSettingsPage QComboBox#settingsSelect,
QWidget#globalSettingsPage QLineEdit#settingsInput,
QWidget#globalSettingsPage QSpinBox#settingsNumber {
    background: $surface; color: $text; border-color: $border; border-radius: 6px; $label_font
}
QWidget#globalSettingsPage QComboBox#settingsSelect:focus,
QWidget#globalSettingsPage QLineEdit#settingsInput:focus,
QWidget#globalSettingsPage QSpinBox#settingsNumber:focus { border-color: $icon; }
QWidget#globalSettingsPage QComboBox#settingsSelect QAbstractItemView {
    background: $surface; color: $text; border-color: $border; selection-background-color: $hover;
}
QWidget#globalSettingsPage QPushButton#settingsAction {
    background: $surface; color: $text; border-color: $border; border-radius: 6px; $label_font
}
QWidget#globalSettingsPage QPushButton#settingsAction:hover,
QWidget#globalSettingsPage QPushButton#settingsAction:focus { border-color: $icon; }
QWidget#globalSettingsPage QPushButton#settingsAction[destructive="true"] {
    color: #ffb4c0; border-color: #6b3e53;
}
""")


def shared_global_settings_style(engine):
    palette = PALETTES[engine]
    return _SHARED_GLOBAL_STYLE.substitute(
        palette, row=palette["action"] if palette["tile"] == palette["surface"] else palette["tile"],
        weight=DASHBOARD_WEIGHT.value, heading_font=DASHBOARD_HEADING_QSS, label_font=DASHBOARD_LABEL_QSS,
    )

class SettingsPage(QWidget):
    def __init__(self, window, *heading, categories, compact_name=None):
        super().__init__()
        compact = bool(compact_name)
        self.window = window
        self.categories = categories
        rail = QWidget()
        if not compact:
            rail.setMaximumWidth(1000)
        root = QHBoxLayout(self)
        root.setContentsMargins(*((14, 8, 14, 10) if compact else (26, 18, 26, 6)))
        if not compact:
            root.addStretch(1)
        root.addWidget(rail, 30)
        if not compact:
            root.addStretch(1)
        body = QVBoxLayout(rail)
        self.body = body
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(8 if compact else 12)
        header = (window._page_header(*heading, compact_name=compact_name) if compact
                  else window._page_header(*heading))
        header.findChild(QLabel, "pageEyebrow").hide()
        if not compact:
            header.setMinimumHeight(94)
        body.addWidget(header)
        self.tabs = QTabWidget()
        self.tabs.setObjectName("settingsTabs")
        self.tabs.setDocumentMode(True)
        self.tabs.tabBar().setExpanding(compact)
        if compact:
            self.tabs.tabBar().setFixedHeight(48)
        body.addWidget(self.tabs, 1)
        self._category_layouts = []
        for title in categories:
            scroll, content = self.window._scroll_page()
            layout = QVBoxLayout(content)
            layout.setContentsMargins(*((0, 8, 0, 0) if compact else (4, 12, 4, 8)))
            layout.setSpacing(8 if compact else 12)
            self._category_layouts.append(layout)
            self.tabs.addTab(scroll, window.tr(*title))

    def category(self, index):
        return self._category_layouts[index]

    def refresh_labels(self):
        alignment = Qt.AlignRight if self.window.language == "fa" else Qt.AlignLeft
        alignment |= Qt.AlignAbsolute | Qt.AlignVCenter
        for index, title in enumerate(self.categories):
            self.tabs.setTabText(index, self.window.tr(*title))
        for label in self.findChildren(QLabel):
            if label.property("i18nFa") is not None:
                label.setAlignment(alignment)
        for row in self.findChildren(SettingsRow):
            control = row.label.buddy()
            control.setAccessibleName(row.label.text())
            if isinstance(control, QLineEdit):
                control.setAlignment(alignment)


class SettingsCard(QFrame):
    def __init__(self, window, fa, en, *, icon=None, trailing=None, subtitle=None):
        super().__init__()
        self.setObjectName("settingsCard")
        self.setAttribute(Qt.WA_StyledBackground)
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(15, 13, 15, 10)
        self.body.setSpacing(2)
        title = window._bind_text(QLabel(), fa, en)
        title.setObjectName("settingsCardTitle")
        title.setContentsMargins(5, 0, 5, 3)
        if icon or trailing is not None or subtitle:
            from .ui import cyber_pixmap

            header = QHBoxLayout()
            header.setContentsMargins(5, 0, 3, 3)
            header.setSpacing(8)
            if icon:
                glyph = QLabel()
                glyph.setPixmap(cyber_pixmap(icon, "#79e9e3", 17))
                header.addWidget(glyph, 0, Qt.AlignVCenter)
            title.setContentsMargins(0, 0, 0, 0)
            if subtitle:
                copy = QVBoxLayout()
                copy.setSpacing(1)
                copy.addWidget(title)
                hint = window._bind_text(QLabel(), *subtitle)
                hint.setObjectName("settingsRowHelp")
                hint.setWordWrap(True)
                copy.addWidget(hint)
                header.addLayout(copy, 1)
            else:
                header.addWidget(title, 1)
            if trailing is not None:
                header.addWidget(trailing)
            self.body.addLayout(header)
        else:
            self.body.addWidget(title)

    def add(self, row):
        if self.body.count() > 1:
            divider = QFrame()
            divider.setObjectName("settingsDivider")
            divider.setFixedHeight(1)
            self.body.addWidget(divider)
        self.body.addWidget(row)


class SettingsRow(QFrame):
    def __init__(self, window, title, help_text, control, *, icon=None, stacked=False,
                 trailing=False, help_button=None):
        from .ui import cyber_pixmap

        super().__init__()
        self.setObjectName("settingsRow")
        self.setAttribute(Qt.WA_StyledBackground)
        row = QHBoxLayout(self)
        row.setContentsMargins(6, 8, 6, 8)
        row.setSpacing(10)
        if icon:
            tile = QLabel()
            tile.setObjectName("settingsRowIcon")
            tile.setFixedSize(32, 32)
            tile.setAlignment(Qt.AlignCenter)
            tile.setPixmap(cyber_pixmap(icon, "#79e9e3", 17))
            row.addWidget(tile, 0, Qt.AlignTop)
        copy = QVBoxLayout()
        copy.setSpacing(3)
        self.label = window._bind_text(QLabel(), *title)
        self.label.setObjectName("settingsRowTitle")
        self.label.setWordWrap(stacked)
        self.label.setBuddy(control)
        if trailing:
            row.setContentsMargins(2, 5, 2, 5)
            title_row = QHBoxLayout()
            title_row.setSpacing(5)
            title_row.addWidget(self.label)
            if help_button is not None:
                title_row.addWidget(help_button)
            title_row.addStretch(1)
            copy.addLayout(title_row)
        elif stacked:
            copy.addWidget(self.label)
        else:
            title_row = QHBoxLayout()
            title_row.setSpacing(9)
            inline_switch = isinstance(control, QCheckBox)
            if inline_switch:
                title_row.addWidget(control, 0, Qt.AlignVCenter)
            title_row.addWidget(self.label)
            if not inline_switch:
                title_row.addWidget(control, 0, Qt.AlignVCenter)
            title_row.addStretch(1)
            copy.addLayout(title_row)
        if any(help_text):
            hint = window._bind_text(QLabel(), *help_text)
            hint.setObjectName("settingsRowHelp")
            hint.setWordWrap(True)
            copy.addWidget(hint)
        control.setAccessibleName(window.tr(*title))
        if stacked:
            copy.addSpacing(3)
            alignment = Qt.AlignLeading if (control.maximumWidth() < 16777215
                        or control.sizePolicy().horizontalPolicy() == QSizePolicy.Fixed) else Qt.Alignment()
            copy.addWidget(control, alignment=alignment)
        row.addLayout(copy, 1)
        if trailing:
            row.addWidget(control, 0, Qt.AlignVCenter)


class SettingsGrid(QWidget):
    """Keep the card order when the settings viewport drops to one column."""

    def __init__(self, cards, *, spacing=12, two_column_width=790, placements=None):
        super().__init__()
        self.cards = cards
        self.columns = 0
        self.two_column_width = two_column_width
        self.placements = placements
        self.grid = QHBoxLayout(self)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setSpacing(spacing)
        self.stacks = []
        for _ in range(2):
            column = QWidget()
            stack = QVBoxLayout(column)
            stack.setContentsMargins(0, 0, 0, 0)
            stack.setSpacing(spacing)
            stack.addStretch()
            self.grid.addWidget(column, 1)
            self.stacks.append(stack)
        self._reflow(1)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._reflow(2 if event.size().width() >= self.two_column_width else 1)

    def _reflow(self, columns):
        if self.columns == columns:
            return
        self.columns = columns
        for stack in self.stacks:
            for card in self.cards:
                stack.removeWidget(card)
        self.stacks[1].parentWidget().setVisible(columns == 2)
        for index, card in enumerate(self.cards):
            column = self.placements[index] if self.placements and columns == 2 else index % columns
            stack = self.stacks[column]
            stack.insertWidget(stack.count() - 1, card)
            card.show()


class _SettingsOptionDelegate(QStyledItemDelegate):
    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        if self.parent().layoutDirection() == Qt.RightToLeft:
            option.direction = Qt.RightToLeft
            option.displayAlignment = Qt.AlignRight | Qt.AlignAbsolute | Qt.AlignVCenter


class SettingsSelect(QComboBox):
    def __init__(self):
        super().__init__()
        self.setObjectName("settingsSelect")
        self.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.setMinimumContentsLength(12)
        self.setItemDelegate(_SettingsOptionDelegate(self))

    def paintEvent(self, event):
        if self.layoutDirection() != Qt.RightToLeft:
            super().paintEvent(event)
            return
        option = QStyleOptionComboBox()
        self.initStyleOption(option)
        rect = self.style().subControlRect(
            QStyle.CC_ComboBox, option, QStyle.SC_ComboBoxEditField, self,
        ).adjusted(3, 0, -5, 0)
        text = option.fontMetrics.elidedText(option.currentText, Qt.ElideLeft, max(0, rect.width()))
        option.currentText = ""
        painter = QStylePainter(self)
        painter.setLayoutDirection(Qt.RightToLeft)
        painter.drawComplexControl(QStyle.CC_ComboBox, option)
        flags = (Qt.AlignRight | Qt.AlignAbsolute | Qt.AlignVCenter).value | Qt.TextForceRightToLeft.value
        painter.drawItemText(rect, flags,
                             option.palette, self.isEnabled(), text, QPalette.ButtonText)


def settings_button(window, label, *, icon=None, destructive=False):
    if icon:
        button = window._action_button(*label, icon, "settingsAction")
    else:
        button = window._bind_text(QPushButton(), *label)
        button.setObjectName("settingsAction")
        button.setCursor(Qt.PointingHandCursor)
    button.setProperty("destructive", destructive)
    return button


def engine_backup_card(window, export, restore):
    backup = SettingsCard(window, "پشتیبان تنظیمات موتور", "Engine settings backup", icon="folder")
    actions = QHBoxLayout()
    actions.setContentsMargins(5, 5, 5, 3)
    for label, icon, handler in (
        (("خروجی تنظیمات", "Export settings"), "download", export),
        (("ورود تنظیمات", "Import settings"), "upload", restore),
    ):
        button = settings_button(window, label, icon=icon)
        button.clicked.connect(handler)
        actions.addWidget(button)
    actions.addStretch(1)
    backup.body.addLayout(actions)
    return backup


class _GlobalSettingsSection(QFrame):
    def __init__(self, window, title, subtitle):
        super().__init__()
        self.setObjectName("globalSettingsSection")
        root = QHBoxLayout(self)
        root.setContentsMargins(1, 1, 1, 1)
        root.setSpacing(0)
        heading = QWidget()
        heading.setFixedWidth(168)
        copy = QVBoxLayout(heading)
        copy.setContentsMargins(12, 10, 12, 10)
        copy.setSpacing(5)
        copy.setAlignment(Qt.AlignVCenter)
        self.icon = QLabel()
        self.icon.setFixedSize(20, 20)
        copy.addWidget(self.icon, 0, Qt.AlignLeading)
        for name, text in (("globalSettingsSectionTitle", title), ("globalSettingsHelp", subtitle)):
            label = window._bind_text(QLabel(), *text)
            label.setObjectName(name)
            label.setWordWrap(True)
            copy.addWidget(label)
        root.addWidget(heading)
        divider = QFrame()
        divider.setObjectName("globalSettingsDivider")
        divider.setFixedWidth(1)
        root.addWidget(divider)
        self.grid = QGridLayout()
        self.grid.setContentsMargins(10, 8, 10, 8)
        self.grid.setSpacing(8)
        root.addLayout(self.grid, 1)
        self._rows = ()
        self._columns = 0

    def set_rows(self, *rows):
        self._rows = rows
        self._reflow(2)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._reflow(2 if self.width() >= 650 else 1)

    def _reflow(self, columns):
        if self._columns == columns:
            return
        self._columns = columns
        while self.grid.count():
            self.grid.takeAt(0)
        self.grid.setColumnStretch(0, 1)
        self.grid.setColumnStretch(1, int(columns == 2))
        rows = self._rows if columns == 2 else ((tile,) for row in self._rows for tile in row)
        for index, row in enumerate(rows):
            for column, tile in enumerate(row):
                self.grid.addWidget(tile, index, column, 1, columns if len(row) == 1 else 1)


class _GlobalSettingsTile(QFrame):
    def __init__(self, window, title, help_text, control, *, brief=False):
        super().__init__()
        self.setObjectName("globalSettingsTile")
        self.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.control = control
        self._disabled_reason = ""
        row = QHBoxLayout(self)
        row.setContentsMargins(10, 7, 10, 7)
        row.setSpacing(10)
        copy = QVBoxLayout()
        copy.setSpacing(2)
        copy.setAlignment(Qt.AlignVCenter)
        self.label = window._bind_text(QLabel(), *title)
        self.label.setObjectName("globalSettingsLabel")
        self.label.setWordWrap(True)
        self.label.setBuddy(control)
        copy.addWidget(self.label)
        self.help = window._bind_text(QLabel(), *help_text)
        self.help.setObjectName("globalSettingsHelp")
        self.help.setWordWrap(True)
        if not brief and any(help_text):
            copy.addWidget(self.help)
        else:
            self.help.setParent(self)
            self.help.hide()
        row.addLayout(copy, 1)
        row.addWidget(control, int(isinstance(control, QLineEdit)), Qt.AlignVCenter)
        if not isinstance(control, QCheckBox):
            control.setFixedHeight(34)
        self.refresh_labels()

    def refresh_labels(self):
        self.control.setAccessibleName(self.label.text())
        self.control.setAccessibleDescription(self.help.text())
        self.control.setToolTip(self.help.text())

    def set_availability(self, enabled, note):
        self._disabled_reason = "" if enabled else note
        # Let the enabled tile receive clicks over a disabled control.
        self.control.setAttribute(Qt.WA_TransparentForMouseEvents, not enabled)
        self.control.setEnabled(enabled)
        description = " ".join(filter(None, (self.help.text(), note)))
        self.control.setAccessibleDescription(description)
        self.control.setToolTip(description)
        self.setToolTip(self._disabled_reason)

    def mouseReleaseEvent(self, event):
        if (self._disabled_reason and event.button() == Qt.LeftButton
                and self.control.geometry().contains(event.position().toPoint())):
            QToolTip.showText(event.globalPosition().toPoint(), self._disabled_reason, self, self.rect(), 3500)
            event.accept()
            return
        super().mouseReleaseEvent(event)


class SharedGlobalSettings(QWidget):
    def __init__(self, window):
        super().__init__()
        self.window = window
        self.controls = {}
        self.choices = {}
        self._icons = []
        self._engine = None
        self.scroll, body = window._scroll_page()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addWidget(self.scroll)
        self.body = QVBoxLayout(body)
        self.body.setContentsMargins(20, 12, 20, 10)
        self.body.setSpacing(8)
        self.body.addLayout(self._header())
        self._build_appearance()
        self._build_connection()
        self._build_sharing()
        self._build_security()
        self._build_tools()
        self.body.addStretch(1)
        self.refresh()
        self.set_engine(window.engine_mode)

    def _header(self):
        header = QHBoxLayout()
        header.setContentsMargins(0, 3, 0, 8)
        header.setSpacing(10)
        icon = QLabel()
        icon.setObjectName("globalSettingsPageIcon")
        icon.setFixedSize(42, 42)
        icon.setAlignment(Qt.AlignCenter)
        self._icons.append((icon, "settings", 22))
        header.addWidget(icon, 0, Qt.AlignVCenter)
        copy = QVBoxLayout()
        copy.setSpacing(2)
        for name, fa, en in (
            ("globalSettingsHeading", "تنظیمات کلی", "Global Settings"),
            ("globalSettingsHelp", "مدیریت یکپارچهٔ تنظیمات هر سه موتور",
             "Shared preferences for all three engines."),
        ):
            label = self.window._bind_text(QLabel(), fa, en)
            label.setObjectName(name)
            label.setWordWrap(True)
            copy.addWidget(label)
        header.addLayout(copy, 1)
        stamp = QLabel("GLOBAL / SETTINGS")
        stamp.setObjectName("globalSettingsStamp")
        header.addWidget(stamp, 0, Qt.AlignVCenter)
        return header

    def _section(self, title, subtitle, icon):
        section = _GlobalSettingsSection(self.window, title, subtitle)
        self._icons.append((section.icon, icon, 20))
        self.body.addWidget(section)
        return section

    def set_engine(self, engine):
        if self._engine == engine:
            return
        self._engine = engine
        palette = PALETTES[engine]
        for label, glyph, size in self._icons:
            label.setPixmap(pixmap(glyph, palette["icon"], size, lucide=True))
        for control in (self.motion, *self.controls.values()):
            if isinstance(control, QCheckBox):
                control.set_quick_style(palette)
        self.refresh_capabilities()

    def refresh_labels(self):
        for tile in self.findChildren(_GlobalSettingsTile):
            tile.refresh_labels()
        self.refresh_capabilities()

    def _build_appearance(self):
        from .ui import ToggleSwitch

        section = self._section(("ظاهر برنامه", "Appearance"), ("رابط کاربری و پویانمایی", "Interface and motion"), "monitor")
        self.motion = ToggleSwitch()
        self.motion.toggled.connect(self._motion_changed)
        section.set_rows((self._row(("کاهش انیمیشن‌ها", "Reduce animations"),
                                    ("جابه‌جایی صفحه‌ها و موتورها بدون پویانمایی.",
                                     "Skip animations when switching pages or engines."), self.motion),))

    def _build_connection(self):
        section = self._section(("اتصال و مسیریابی", "Connection & routing"),
                                ("مدیریت ارتباطات شبکه", "Network connections"), "route")
        iran = self._toggle("iran_direct", ("عبور مستقیم سایت‌های ایرانی", "Bypass VPN for Iranian sites"),
                            ("سایت‌های ایرانیِ شناسایی‌شده مستقیم باز شوند.",
                             "Open recognized Iranian sites directly."))
        startup = self._toggle("auto_connect", ("اتصال خودکار", "Auto-connect"),
                               ("با اجرای برنامه یا بازگشت اینترنت، موتور انتخاب‌شده وصل شود.",
                                "Connect the selected engine at startup or when Internet returns."))
        self.routing_link = link = QPushButton()
        link.setObjectName("globalRoutingLink")
        link.setCursor(Qt.PointingHandCursor)
        link.setFixedHeight(58)
        link.clicked.connect(lambda: self.window.show_page(self.window.DIRECT_ROUTING_PAGE))
        row = QHBoxLayout(link)
        row.setContentsMargins(10, 5, 10, 5)
        row.setSpacing(8)
        globe = QLabel()
        globe.setObjectName("globalSettingsPageIcon")
        globe.setFixedSize(34, 34)
        globe.setAlignment(Qt.AlignCenter)
        self._icons.append((globe, "globe", 19))
        row.addWidget(globe)
        copy = QVBoxLayout()
        copy.setSpacing(1)
        for name, fa, en in (
                ("globalSettingsLabel", "تنظیمات بیشتر عبور مستقیم", "More direct routing settings"),
                ("globalSettingsHelp", "مدیریت دامنه‌ها، آی‌پی‌ها و فایل‌های مسیریابی", "Manage domains, IPs and routing files")):
            label = self.window._bind_text(QLabel(), fa, en)
            label.setObjectName(name)
            label.setAttribute(Qt.WA_TransparentForMouseEvents)
            copy.addWidget(label)
        row.addLayout(copy, 1)
        arrow = QLabel("›")
        arrow.setObjectName("globalSettingsHelp")
        row.addWidget(arrow)
        link.setAccessibleName("More direct routing settings")
        section.set_rows((startup, iran), (link,))

    def _build_sharing(self):
        section = self._section(("اشتراک شبکه", "Network sharing"),
                                ("شبکهٔ محلی و پروکسی", "Local network and proxy"), "network")
        sharing = self._toggle("lan_share", ("اشتراک اتصال", "Share connection"),
                               ("دستگاه‌های شبکهٔ خصوصی از اتصال PoW استفاده کنند.",
                                "Let devices on a private network use the PoW connection."))
        protocol = self._choice("lan_share_mode", ("پروتکل اشتراک", "LAN share protocol"),
                                (("socks5", "SOCKS5", "SOCKS5"), ("ps5", "HTTP CONNECT", "HTTP CONNECT")))
        self.controls["lan_share_mode"].setProperty("technical", True)
        port = QSpinBox()
        port.setObjectName("settingsNumber")
        port.setProperty("technical", True)
        port.setLayoutDirection(Qt.LeftToRight)
        port.setLocale(QLocale.c())
        port.setRange(1, 65535)
        port.setFixedWidth(95)
        port.valueChanged.connect(lambda value: self._change("lan_share_port", value))
        self.controls["lan_share_port"] = port
        section.set_rows((sharing,), (protocol, self._row(("درگاه اشتراک", "LAN share port"), ("", ""), port)))

    def _build_security(self):
        section = self._section(("امنیت و حریم خصوصی", "Security & privacy"),
                                ("فیلترها فقط روی ترافیک TUN اعمال می‌شوند.",
                                 "Filters apply to traffic captured by TUN."), "shield")
        kill = self._toggle("kill_switch", ("قطع اضطراری اینترنت", "Internet kill switch"),
                            ("در قطع ناخواستهٔ VPN در PoW و Direct، دسترسی مستقیم قطع شود.",
                             "Block direct Internet access if the PoW or Direct VPN drops."))
        ipv6 = self._toggle("ipv6_block", ("جلوگیری از نشت IPv6", "Block IPv6 leaks"),
                            ("ترافیک IPv6 عبوری از TUN مسدود شود.", "Block IPv6 traffic captured by TUN."))
        dns = self._toggle("dns_sinkhole", ("مسدودسازی ردیاب‌ها", "Block trackers"),
                           ("درخواست‌های DNS برای ردیاب‌های شناخته‌شده مسدود شوند.",
                            "Block DNS requests for known trackers."))
        stun = self._toggle("webrtc_block", ("مسدودسازی STUN", "Block WebRTC STUN"),
                            ("احتمال افشای آی‌پی واقعی از طریق STUN کاهش یابد.",
                             "Reduce the risk of exposing your IP through STUN."))
        quic = self._toggle("quic_block", ("مسدودسازی QUIC", "Block QUIC"),
                            ("ترافیک QUIC شناسایی‌شده و UDP درگاه ۴۴۳ مسدود شود.",
                             "Block detected QUIC and UDP traffic on port 443."))
        section.set_rows((kill, ipv6), (dns, stun), (quic,))

    def _build_tools(self):
        section = self._section(("ابزارها و پشتیبان‌گیری", "Tools & backup"),
                                ("مدیریت فایل‌ها و تنظیمات", "Manage files and settings"), "server")
        export = self._action(("خروجی تنظیمات کلی", "Export Global Settings"),
                              ("تنظیمات برنامه و فهرست برنامه‌ها را در فایل JSON ذخیره کنید.",
                               "Save application preferences and the app list as JSON."),
                              ("خروجی", "Export"), lambda: self._exchange(False))
        restore = self._action(("بازیابی تنظیمات کلی", "Import Global Settings"),
                               ("تنظیمات را از فایل پشتیبان بازیابی کنید.", "Restore settings from a backup file."),
                               ("ورود", "Import"), lambda: self._exchange(True))
        data = self._action(("پوشهٔ داده‌ها", "Data folder"),
                            ("فایل‌های محلی و گزارش‌های برنامه را ببینید.", "Browse local app files and logs."),
                            ("باز کردن", "Open"), self.window.data_button.click)
        reset = self._action(("بازنشانی تنظیمات اتصال", "Reset connection settings"),
                             ("زبان و فهرست برنامه‌ها حفظ می‌شوند.", "Keeps your language and app list."),
                             ("بازنشانی", "Reset"), self._reset_connection, destructive=True)
        section.set_rows((export, restore), (data, reset))

    def _row(self, title, hint, control, *, brief=False):
        return _GlobalSettingsTile(self.window, title, hint, control, brief=brief)

    def _action(self, title, hint, label, action, *, destructive=False):
        button = settings_button(self.window, label, destructive=destructive)
        button.clicked.connect(action)
        return self._row(title, hint, button, brief=True)

    def _toggle(self, key, title, hint):
        from .ui import ToggleSwitch

        control = ToggleSwitch()
        self.controls[key] = control
        control.toggled.connect(lambda value: self._change(key, value))
        return self._row(title, hint, control)

    def _choice(self, key, title, choices):
        control = SettingsSelect()
        control.setFixedWidth(122)
        self.controls[key] = control
        self.choices[key] = choices
        control.currentIndexChanged.connect(lambda: self._change(key, control.currentData()))
        return self._row(title, ("", ""), control)

    def refresh(self):
        window = self.window
        settings = window.global_settings.snapshot()
        window._pow_set_toggle(self.motion, window.global_settings.reduce_navigation_motion)
        for key, control in self.controls.items():
            value = getattr(settings, key)
            with QSignalBlocker(control):
                if key in self.choices:
                    control.clear()
                    for data, fa, en in self.choices[key]:
                        control.addItem(window._ui_text(fa, en), data)
                    control.setCurrentIndex(control.findData(value))
                elif isinstance(control, QLineEdit):
                    control.setText(value)
                elif isinstance(control, QSpinBox):
                    control.setValue(value)
                else:
                    window._pow_set_toggle(control, value)
        self.refresh_capabilities()

    def refresh_capabilities(self):
        from .application_settings import LAN_SETTINGS, TUN_FILTERS

        window = self.window
        mode = window.global_settings.snapshot().connection_mode
        busy = window._engine_busy()
        next_connect = window.tr("در اتصال بعدی اعمال می‌شود.", "Applies on the next connection.")
        tun_only = window._ui_text("برای تغییر این گزینه، حالت TUN را روشن کنید.",
                                   "Turn on TUN mode to change this setting.")
        for key, control in self.controls.items():
            enabled = True
            note = ""
            if key in LAN_SETTINGS:
                enabled = window.engine_mode == "pow"
                if not enabled:
                    note = window._ui_text("برای تنظیم اشتراک اتصال، موتور PoW را انتخاب کنید.",
                                           "Select PoW to configure connection sharing.")
                elif key == "lan_share" and control.isChecked():
                    endpoint, error = window.pow_controller.coordinator.lan_share_status
                    if endpoint:
                        note = window.tr(f"اشتراک فعال است: {endpoint}", f"Sharing is active: {endpoint}")
                    elif error:
                        note = window.tr("اشتراک فعال نشد. لاگ زنده را ببینید.",
                                         "Sharing failed. See Live Log.")
                    else:
                        note = window.tr("اشتراک هنوز فعال نیست.", "Sharing is not active yet.")
            elif key in TUN_FILTERS or key == "kill_switch":
                enabled = mode == "vpn"
                note = (next_connect if busy else "") if enabled else tun_only
                if key == "kill_switch":
                    enabled = enabled and window.engine_mode != "xray" and not busy
                    if window.engine_mode == "xray":
                        note = window._ui_text("برای قطع اضطراری، PoW یا Direct را در حالت TUN انتخاب کنید.",
                                               "Use PoW or Direct in TUN mode for the kill switch.")
                    elif busy and mode == "vpn":
                        note = window.tr("برای تغییر قطع اضطراری، ابتدا اتصال را قطع کنید.",
                                         "Disconnect first to change the kill switch.")
                    elif busy:
                        note = window._ui_text("ابتدا اتصال را قطع کنید و حالت TUN را روشن کنید.",
                                               "Disconnect first, then turn on TUN mode.")
                elif key in ("ipv6_block", "quic_block") and window.engine_mode == "direct" and enabled:
                    note += " " + window.tr("تنظیمات اختصاصی Direct هم ممکن است این ترافیک را مسدود کنند.",
                                            "Dedicated Direct settings can also block this traffic.")
            elif busy and key in ("iran_direct", "domains_direct"):
                note = next_connect
            control.parentWidget().set_availability(enabled, note)

    def _change(self, key, value):
        self.window._change_global_settings(**{key: value})

    def _motion_changed(self, reduced):
        try:
            self.window.global_settings.set_navigation_motion(reduced)
        except OSError as error:
            self.window.show_toast(str(error), "danger")
            self.refresh()

    def _exchange(self, restore):
        window = self.window
        if restore and window._engine_busy():
            window._reject_guarded_change()
            return
        picker = QFileDialog.getOpenFileName if restore else QFileDialog.getSaveFileName
        name, _ = picker(self, window.tr("تنظیمات کلی", "Global Settings"),
                         "uac-global-settings.json", "JSON (*.json)")
        if not name:
            return
        try:
            path = Path(name)
            if restore:
                before = window.global_settings.snapshot()
                if path.stat().st_size > 1024 * 1024:
                    raise ValueError("Global Settings backup is larger than 1 MB.")
                window.global_settings.restore(json.loads(path.read_text(encoding="utf-8-sig")))
                window.language = window.storage.settings.get("language", "fa")
                window._apply_language()
                window.refresh_processes()
                window._global_settings_changed(before)
            else:
                path.write_text(json.dumps(window.global_settings.export(), ensure_ascii=False, indent=2),
                                encoding="utf-8")
        except ValueError:
            window.show_toast(window.tr("محتوای فایل پشتیبان معتبر نیست.",
                                        "The settings backup is invalid."), "danger")
        except OSError as error:
            window.show_toast(str(error), "danger")

    def _reset_connection(self):
        window = self.window
        if window._engine_busy():
            window._reject_guarded_change()
            return
        answer = QMessageBox.question(
            self, window.tr("بازنشانی ترجیحات اتصال", "Reset connection preferences"),
            window.tr("ترجیحات مشترک اتصال و امنیت به پیش‌فرض‌ها بازگردند؟",
                      "Restore the shared connection and security defaults?"),
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        before = window.global_settings.snapshot()
        try:
            window.global_settings.reset_connection()
        except OSError as error:
            window.show_toast(str(error), "danger")
            return
        window._global_settings_changed(before)
