"""UAC PoW page + controller — desktop port of mobile ``PowSettingsPanel``.

Owns the third engine (Psiphon-over-WARP) inside the Windows app:

- settings widgets bound to :class:`PowStore` (``pow_settings.json``),
  same keys and ladder semantics as mobile ``PowEngineSettings``;
- live stage list bound to :class:`PowStatusStore` snapshots;
- identity card bound to :mod:`uac_desktop.pow.identity`;
- connect runs :class:`PowCoordinator` on a worker thread and never
  touches the Xray ``Engine`` — the two engines are mutually exclusive.

The page is built with the host :class:`MainWindow` helpers so it keeps
the desktop look (cards, toggles, glow buttons, bilingual labels).
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

from PySide6.QtCore import QSize, Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from .paths import DATA_DIR
from .pow import config as C
from .pow.coordinator import PowCoordinator, PowEngineError
from .pow.identity import (
    forget_identity,
    read_clean_h2_peers,
    read_identity,
    short_id,
)
from .pow.regions import ALL_NAMES, BUNDLED
from .pow.runner import prepare_identity
from .pow.status import PowPhase, PowStatusStore
from .pow.store import PowStore

ENGINE_XRAY = "xray"
ENGINE_POW = "pow"

_SCAN_OPTIONS = (
    ("turbo", "توربو", "Turbo"),
    ("balanced", "متعادل", "Balanced"),
    ("thorough", "عمیق", "Thorough"),
)
_FIREWALL_OPTIONS = (
    ("auto", "خودکار (سخت‌گیرانه)", "Auto (strict)"),
    ("mci", "MCI (همراه اول)", "MCI"),
    ("irancell", "ایرانسل", "Irancell"),
)
_TRANSPORT_OPTIONS = (
    ("auto", "خودکار", "Auto"),
    ("masque", "MASQUE", "MASQUE"),
    ("gool", "WoW", "WoW"),
    ("wireguard", "WireGuard", "WireGuard"),
)
_SPEED_OPTIONS = (('parallel', 'parallel_masque', 'MASQUE موازی', 'Parallel MASQUE', '۲ تا ۳ اتصال MASQUE هم\u200cزمان؛ هر سایت روی یک اتصال می\u200cماند', '2–3 MASQUE sessions at once; each site stays on one session'), ('h3', 'irancell_h3', 'HTTP/3 در ایرانسل', 'HTTP/3 on Irancell', 'فقط وقتی فایروال ایرانسل است؛ اگر نشد سریع به HTTP/2 برمی\u200cگردد', 'Only when firewall is Irancell; falls back to HTTP/2 quickly'), ('direct', 'direct_psiphon_first', 'اول سایفون مستقیم', 'Direct Psiphon first', 'اول کوتاه سایفون بدون وارپ؛ اگر وصل شد وارپ لازم نیست', 'Short try of Psiphon without WARP; if it connects, WARP is skipped'), ('lowrtt', 'lowest_rtt_ip', 'کم\u200cتأخیرترین آی\u200cپی تمیز', 'Lowest-latency clean IP', 'آی\u200cپی تمیز سریع\u200cتر اول؛ هر چند دقیقه دوباره سنجیده می\u200cشود', 'Fastest saved clean IP first; re-measured every few minutes'))
_SPEED_TOGGLES = tuple(f"speed_{key}_toggle" for key, *_rest in _SPEED_OPTIONS)
_RECIPE_OPTIONS = (
    ("auto", "خودکار", "Auto"),
    ("masque-h2", "MASQUE H2", "MASQUE H2"),
    ("masque-h3", "MASQUE H3", "MASQUE H3"),
    ("masque-h2-split", "MASQUE H2 شکافته", "MASQUE H2 split"),
    ("masque-h2-saved", "MASQUE H2 ذخیره‌شده", "MASQUE H2 saved"),
    ("warp-any", "WARP هر IP", "WARP any"),
    ("warp-v6", "WARP نسخه ۶", "WARP v6"),
    ("wow-any", "WoW هر IP", "WoW any"),
    ("wow-v6", "WoW نسخه ۶", "WoW v6"),
)
_KEY_FETCH_OPTIONS = (
    ("auto", "خودکار", "Auto"),
    ("oob", "OOB", "OOB"),
    ("relay", "رله", "Relay"),
    ("ech", "ECH", "ECH"),
    ("fragment", "فرگمنت", "Fragment"),
    ("external", "خارجی", "External"),
)
_OBFUSCATION_OPTIONS = (
    ("off", "خاموش", "Off"),
    ("light", "سبک", "Light"),
    ("balanced", "متعادل", "Balanced"),
    ("aggressive", "تهاجمی", "Aggressive"),
)


def _fa_label(window, combo: QComboBox, options, value: str) -> str:
    for key, fa_text, _en_text in options:
        if key == value:
            return fa_text if window.language != "en" else _en_text
    return value


class PowSegmented(QFrame):
    """Compact segmented control with the small QComboBox API the page uses
    (addItem / count / itemData / currentData / setCurrentIndex /
    currentIndexChanged), so settings binding stays the same."""

    currentIndexChanged = Signal(int)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("powSegmented")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(3, 3, 3, 3)
        self._layout.setSpacing(2)
        self._group = QButtonGroup(self)
        self._group.setExclusive(True)
        self._data: list = []
        self._group.idClicked.connect(self._clicked)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

    def addItem(self, text: str, data=None) -> None:
        button = QPushButton(text)
        button.setObjectName("powSegment")
        button.setCheckable(True)
        button.setCursor(Qt.PointingHandCursor)
        index = len(self._data)
        self._data.append(data)
        self._group.addButton(button, index)
        self._layout.addWidget(button)
        if index == 0:
            button.setChecked(True)

    def count(self) -> int:
        return len(self._data)

    def itemData(self, index: int):
        return self._data[index] if 0 <= index < len(self._data) else None

    def currentIndex(self) -> int:
        return self._group.checkedId()

    def currentData(self):
        return self.itemData(self.currentIndex())

    def setCurrentIndex(self, index: int) -> None:
        button = self._group.button(index)
        if button is None or button.isChecked():
            return
        button.setChecked(True)
        if not self.signalsBlocked():
            self.currentIndexChanged.emit(index)

    def _clicked(self, index: int) -> None:
        if not self.signalsBlocked():
            self.currentIndexChanged.emit(index)


class PowSection(QFrame):
    """Settings group: small caps header, optional collapse chevron, rows."""

    def __init__(self, window, persian: str, english: str, icon_name: str,
                 collapsible: bool = False, expanded: bool = True,
                 trailing: QWidget | None = None) -> None:
        from uac_desktop.ui import cyber_pixmap

        super().__init__()
        self.setObjectName("powSection")
        self.setAttribute(Qt.WA_StyledBackground, True)
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(8)
        header = QHBoxLayout()
        header.setSpacing(8)
        icon = QLabel()
        icon.setPixmap(cyber_pixmap(icon_name, "#67e8f9", 15))
        icon.setFixedSize(18, 18)
        title = window._bind_text(QLabel(), persian, english.upper())
        title.setObjectName("powSectionTitle")
        header.addWidget(icon)
        header.addWidget(title)
        header.addStretch()
        if trailing is not None:
            header.addWidget(trailing)
        self._toggle = None
        if collapsible:
            self._toggle = QToolButton()
            self._toggle.setObjectName("powSectionToggle")
            self._toggle.setCursor(Qt.PointingHandCursor)
            self._toggle.setFixedSize(26, 22)
            self._toggle.clicked.connect(lambda: self.set_expanded(not self.body.isVisible()))
            header.addWidget(self._toggle)
        root.addLayout(header)
        self.body = QWidget()
        self.body.setObjectName("powSectionBody")
        self.body_layout = QVBoxLayout(self.body)
        self.body_layout.setContentsMargins(0, 4, 0, 0)
        self.body_layout.setSpacing(4)
        root.addWidget(self.body)
        self.set_expanded(expanded or not collapsible)

    def set_expanded(self, expanded: bool) -> None:
        self.body.setVisible(bool(expanded))
        if self._toggle is not None:
            self._toggle.setText("\u25be" if expanded else "\u25b8")

    def add(self, widget: QWidget) -> None:
        self.body_layout.addWidget(widget)


def _airy(label: QLabel, window) -> None:
    """Taller line height for wrapped help text (Qt labels have no QSS line-height)."""
    from uac_desktop.fonts import airy_html

    text = label.text()
    if text and "<" not in text:
        label.setTextFormat(Qt.RichText)
        label.setText(airy_html(text, getattr(window, "language", "fa") == "fa"))


def _setting_row(window, fa_title: str, en_title: str, fa_desc: str, en_desc: str,
                 control: QWidget) -> QFrame:
    row = QFrame()
    row.setObjectName("powSettingRow")
    row.setAttribute(Qt.WA_Hover, True)
    row.setAttribute(Qt.WA_StyledBackground, True)
    layout = QHBoxLayout(row)
    layout.setContentsMargins(12, 10, 12, 10)
    layout.setSpacing(18)
    copy = QVBoxLayout()
    copy.setSpacing(4)
    title = window._bind_text(QLabel(), fa_title, en_title)
    title.setObjectName("powRowTitle")
    desc = window._bind_text(QLabel(), fa_desc, en_desc)
    desc.setObjectName("powRowDesc")
    desc.setWordWrap(True)
    _airy(desc, window)
    copy.addWidget(title)
    copy.addWidget(desc)
    layout.addLayout(copy, 1)
    layout.addWidget(control, 0, Qt.AlignVCenter)
    return row


def _dialog_header(dialog: QDialog, window, fa_title: str, en_title: str,
                   fa_sub: str, en_sub: str, icon_name: str) -> QFrame:
    from uac_desktop.ui import cyber_pixmap

    header = QFrame()
    header.setObjectName("powDialogHeader")
    header.setAttribute(Qt.WA_StyledBackground, True)
    layout = QHBoxLayout(header)
    layout.setContentsMargins(20, 14, 12, 14)
    layout.setSpacing(12)
    icon = QLabel()
    icon.setObjectName("powDialogIcon")
    icon.setFixedSize(38, 38)
    icon.setAlignment(Qt.AlignCenter)
    icon.setPixmap(cyber_pixmap(icon_name, "#8efff4", 20))
    layout.addWidget(icon, 0, Qt.AlignVCenter)
    copy = QVBoxLayout()
    copy.setSpacing(4)
    title = window._bind_text(QLabel(), fa_title, en_title)
    title.setObjectName("powDialogTitle")
    subtitle = window._bind_text(QLabel(), fa_sub, en_sub)
    subtitle.setObjectName("powDialogSubtitle")
    subtitle.setWordWrap(True)
    _airy(subtitle, window)
    copy.addWidget(title)
    copy.addWidget(subtitle)
    layout.addLayout(copy, 1)
    close = QToolButton()
    close.setObjectName("powDialogClose")
    close.setText("\u2715")
    close.setFixedSize(32, 32)
    close.setCursor(Qt.PointingHandCursor)
    close.setToolTip(window.tr("بستن (Esc)", "Close (Esc)"))
    close.clicked.connect(dialog.accept)
    layout.addWidget(close, 0, Qt.AlignTop)
    return header


class PowExitSelector(QPushButton):
    """Card-like exit selector: round flag/bolt badge, two-line text, chevron."""

    def __init__(self, parent=None) -> None:
        from PySide6.QtGui import QTransform
        from uac_desktop.ui import cyber_pixmap

        super().__init__(parent)
        self.setObjectName("powExitSelector")
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumSize(300, 56)
        self.setMaximumHeight(60)
        self.setLayoutDirection(Qt.LeftToRight)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(9, 8, 12, 8)
        layout.setSpacing(11)
        self.badge = QLabel()
        self.badge.setObjectName("powExitBadge")
        self.badge.setFixedSize(38, 38)
        self.badge.setAlignment(Qt.AlignCenter)
        copy = QVBoxLayout()
        copy.setContentsMargins(0, 0, 0, 0)
        copy.setSpacing(3)
        self.title_label = QLabel()
        self.title_label.setObjectName("powExitTitle")
        self.subtitle_label = QLabel()
        self.subtitle_label.setObjectName("powExitSubtitle")
        copy.addStretch()
        copy.addWidget(self.title_label)
        copy.addWidget(self.subtitle_label)
        copy.addStretch()
        self.chevron = QLabel()
        self.chevron.setObjectName("powExitChevron")
        self.chevron.setFixedSize(26, 26)
        self.chevron.setAlignment(Qt.AlignCenter)
        self.chevron.setPixmap(cyber_pixmap("chevron-right", "#8fdcf0", 16).transformed(QTransform().rotate(90)))
        layout.addWidget(self.badge)
        layout.addLayout(copy, 1)
        layout.addWidget(self.chevron)
        for widget in (self.badge, self.title_label, self.subtitle_label, self.chevron):
            widget.setAttribute(Qt.WA_TransparentForMouseEvents, True)

    def set_value(self, pixmap, title: str, subtitle: str) -> None:
        self.badge.setPixmap(pixmap)
        self.title_label.setText(title)
        self.subtitle_label.setText(subtitle)
        self.setAccessibleDescription(f"{title}. {subtitle}")

    def text(self) -> str:  # readable summary for tests / accessibility
        return f"{self.title_label.text()} \u00b7 {self.subtitle_label.text()}"


class PowSettingsDialog(QDialog):
    """Advanced PoW options. Everyday switches (exit country, firewall,
    Psiphon over WARP, optimized, HTTP/2 fragmentation, proxy/TUN) live on
    Home only; both write the same PowStore, so there is one source of truth."""

    def __init__(self, window, controller: "PowController") -> None:
        super().__init__(window)
        self.setObjectName("powSettingsDialog")
        self.setWindowTitle(window.tr("تنظیمات UAC PoW", "UAC PoW Settings"))
        self.setMinimumSize(620, 460)
        self.resize(700, 640)
        self.setModal(True)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(_dialog_header(
            self, window,
            "تنظیمات UAC PoW", "UAC PoW Settings",
            "گزینه‌های پیشرفته. کلیدهای روزمره در صفحه اصلی هستند.",
            "Advanced options. Everyday switches live on Home.",
            "settings",
        ))
        scroll = QScrollArea()
        scroll.setObjectName("powDialogScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(16, 14, 16, 16)
        body_layout.setSpacing(12)
        # Widgets emit while they are being filled. Ignore those signals until
        # the stored settings have been applied, or the first empty control
        # overwrites pow_settings.json.
        controller._editing = False
        body_layout.addWidget(controller._build_proxy_ports_section())
        body_layout.addWidget(controller._build_tunnel_section())
        body_layout.addWidget(controller._build_speed_section())
        body_layout.addWidget(controller._build_identity_card())
        body_layout.addWidget(controller._build_learned_section())
        controller._load_settings_into_widgets()
        controller._refresh_identity()
        controller._editing = True
        body_layout.addStretch()
        scroll.setWidget(body)
        root.addWidget(scroll, 1)


class PowCountryPicker(QDialog):
    """One picker for the PoW exit: Automatic (nearby first) or a country."""

    def __init__(self, window, selected: str = "", remembered: str | None = None) -> None:
        from uac_desktop.ui import country_flag_icon, cyber_icon

        super().__init__(window)
        self.setObjectName("powCountryPicker")
        self.setWindowTitle(window.tr("کشور خروجی", "Exit country"))
        self.setModal(True)
        self.resize(430, 560)
        self.selected_code: str | None = None
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        count = len(ALL_NAMES)
        root.addWidget(_dialog_header(
            self, window, "کشور خروجی", "Exit country",
            f"{count} کشور · خودکار اول کشور نزدیک را امتحان می‌کند",
            f"{count} countries · Automatic tries a nearby country first",
            "globe",
        ))
        body = QVBoxLayout()
        body.setContentsMargins(16, 14, 16, 16)
        body.setSpacing(12)
        self.search = QLineEdit()
        self.search.setObjectName("powCountrySearch")
        self.search.setPlaceholderText(window.tr("جستجوی کشور یا کد", "Search country or code"))
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._filter)
        self.search.returnPressed.connect(self._choose_first_visible)
        body.addWidget(self.search)
        self.list = QListWidget()
        self.list.setObjectName("powCountryList")
        self.list.setIconSize(QSize(30, 20))
        self.list.setLayoutDirection(Qt.LeftToRight)
        self.list.setUniformItemSizes(False)
        remembered = (remembered or "").strip().upper()
        if remembered:
            auto_sub = window.tr(
                f"اول {ALL_NAMES.get(remembered, remembered)} ({remembered})، بعد هر کشوری",
                f"{ALL_NAMES.get(remembered, remembered)} ({remembered}) first, then any country",
            )
        else:
            auto_sub = window.tr("اول یک کشور نزدیک، بعد هر کشوری", "A nearby country first, then any country")
        auto = QListWidgetItem(
            cyber_icon("zap", "#78fff0", 18),
            window.tr("خودکار (سریع‌ترین کشور نزدیک)", "Automatic (fastest nearby)") + "\n" + auto_sub,
        )
        auto.setData(Qt.UserRole, "")
        auto.setSizeHint(QSize(0, 50))
        self.list.addItem(auto)
        wanted = (selected or "").strip().upper()
        current = auto
        for code in sorted(ALL_NAMES, key=lambda c: ALL_NAMES[c].lower()):
            item = QListWidgetItem(country_flag_icon(code), f"{ALL_NAMES[code]}   {code}")
            item.setData(Qt.UserRole, code.lower())
            item.setSizeHint(QSize(0, 38))
            self.list.addItem(item)
            if code == wanted:
                current = item
        self.list.setCurrentItem(current)
        self.list.scrollToItem(current)
        self.list.itemClicked.connect(self._choose)
        self.list.itemActivated.connect(self._choose)
        body.addWidget(self.list, 1)
        root.addLayout(body, 1)
        self.search.setFocus()

    def _filter(self, text: str) -> None:
        needle = (text or "").strip().lower()
        for index in range(self.list.count()):
            item = self.list.item(index)
            item.setHidden(bool(needle) and needle not in item.text().lower())

    def _choose_first_visible(self) -> None:
        for index in range(self.list.count()):
            item = self.list.item(index)
            if not item.isHidden():
                self._choose(item)
                return

    def _choose(self, item: QListWidgetItem) -> None:
        self.selected_code = str(item.data(Qt.UserRole) or "")
        self.accept()


class PowController:
    """Builds the PoW page and drives connect/disconnect."""

    def __init__(self, window) -> None:
        self._window = window
        self.data_dir = Path(DATA_DIR) / "pow"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.store = PowStore(self.data_dir)
        self.status = PowStatusStore()
        self.coordinator = PowCoordinator(
            self.data_dir,
            self.store,
            self.status,
            log=self._thread_log,
        )
        self._thread: threading.Thread | None = None
        self._connecting = False
        self._failed_message = ""
        # TUN by default: the whole PC goes through the tunnel; the
        # coordinator falls back to the Windows proxy when TUN cannot work.
        # The choice is saved so it survives a restart.
        try:
            self._exit_proxy_mode = bool(self.store.exit_proxy_mode())
        except Exception:
            self._exit_proxy_mode = False
        # Requested exit while a live switch runs (None when idle).
        self._switch_target: bool | None = None
        self._switch_token = None
        # The connection/identity cards live inside the settings dialog and are
        # built on demand; the page itself only needs the launcher summary.
        self.country_combo = None
        self.transport_combo = None
        self.firewall_combo = None
        self.scan_combo = None
        self.recipe_combo = None
        self.obfuscation_combo = None
        self.key_fetch_combo = None
        self.chain_toggle = None
        self.optimized_toggle = None
        for _name in _SPEED_TOGGLES:
            setattr(self, _name, None)
        self.h2_toggle = None
        self.proxy_toggle = None
        self.tun_toggle = None
        self.identity_state = None
        self.identity_detail = None
        self.settings_summary = None
        self.learned_box = None
        self.learned_count = None
        self._editing = False
        self._attempt_open = False
        self._activity_kind = ""
        self._steps_signature: tuple | None = None
        self._poll = QTimer(window)
        self._poll.setInterval(600)
        self._poll.timeout.connect(self._refresh)
        self._poll.start()

    # -- page -----------------------------------------------------------------
    def build_page(self) -> QWidget:
        window = self._window
        page = QWidget()
        root = QVBoxLayout(page)
        root.setContentsMargins(34, 28, 34, 26)
        root.setSpacing(16)
        root.addWidget(
            window._page_header(
                "موتور UAC PoW",
                "UAC PoW Engine",
                "سایفون روی وارپ؛ بدون دخالت Xray",
                "Psiphon over WARP · runs without Xray",
            )
        )
        root.addWidget(self._build_status_card())
        root.addWidget(self._build_settings_launcher())
        root.addWidget(self._build_stages_card())
        hint = window._bind_text(
            QLabel(),
            "موتور Xray و موتور PoW هرگز همزمان اجرا نمی‌شوند؛ با اتصال یکی، دیگری متوقف می‌شود.",
            "The Xray and PoW engines never run together; connecting one stops the other.",
        )
        hint.setObjectName("powHint")
        hint.setWordWrap(True)
        root.addWidget(hint)
        root.addStretch()
        self._load_settings_into_widgets()
        self._refresh_identity()
        self._refresh()
        self._update_settings_summary()
        return page

    def _build_proxy_port_card(self) -> QFrame:
        """Deprecated: ports live in PoW Settings dialog."""
        from PySide6.QtWidgets import QFrame
        frame = QFrame()
        frame.hide()
        self.proxy_port_panel = None
        return frame

    def _build_proxy_ports_section(self) -> QFrame:
        """HTTP + Psiphon SOCKS inside PowSettingsDialog (تنظیمات PoW)."""
        from .proxy_port_panel import build_pow_ports_section
        return build_pow_ports_section(self._window, self)


    def _build_settings_launcher(self) -> QFrame:
        from uac_desktop.ui import MotionFrame

        window = self._window
        card = MotionFrame()
        card.setObjectName("powCard")
        layout = QHBoxLayout(card)
        layout.setContentsMargins(22, 16, 22, 16)
        layout.setSpacing(14)
        copy_box = QVBoxLayout()
        copy_box.setSpacing(3)
        title = window._bind_text(QLabel(), "تنظیمات اتصال", "Connection Settings")
        title.setObjectName("powCardTitle")
        self.settings_summary = QLabel("")
        self.settings_summary.setObjectName("powDetail")
        self.settings_summary.setWordWrap(True)
        copy_box.addWidget(title)
        copy_box.addWidget(self.settings_summary)
        layout.addLayout(copy_box, 1)
        self.settings_button = window._action_button(
            "تنظیمات PoW", "PoW Settings", "wrench", "secondaryAction")
        self.settings_button.setMinimumWidth(170)
        self.settings_button.clicked.connect(self._open_settings)
        layout.addWidget(self.settings_button)
        return card

    def _open_settings(self) -> None:
        dialog = PowSettingsDialog(self._window, self)
        dialog.exec()
        # Drop the widgets before they are destroyed so a teardown signal
        # cannot write the unchecked defaults back over the saved settings.
        self._editing = False
        self._release_setting_widgets()
        self._refresh_identity()
        self._update_settings_summary()
        refresh_exit = getattr(self._window, "_update_pow_country_selector", None)
        if refresh_exit is not None and getattr(self._window, "engine_mode", "") == ENGINE_POW:
            try:
                refresh_exit()
            except Exception:
                pass

    def _release_setting_widgets(self) -> None:
        for name in (
            "country_combo", "transport_combo", "firewall_combo", "scan_combo",
            "recipe_combo", "obfuscation_combo", "key_fetch_combo",
            "chain_toggle", "optimized_toggle", "h2_toggle",
            "proxy_toggle", "tun_toggle", "identity_state", "identity_detail",
            "learned_box", "learned_count", *_SPEED_TOGGLES,
            "pow_http_port_input", "pow_socks_port_input", "proxy_port_editor",
        ):
            setattr(self, name, None)

    def _update_settings_summary(self) -> None:
        summary = getattr(self, "settings_summary", None)
        if summary is None:
            return
        window = self._window
        try:
            settings = self.store.snapshot()
        except Exception:
            return
        transport = _fa_label(window, self.transport_combo, _TRANSPORT_OPTIONS, settings.outer_transport)
        firewall = _fa_label(window, self.firewall_combo, _FIREWALL_OPTIONS, settings.firewall_profile)
        scan = _fa_label(window, self.scan_combo, _SCAN_OPTIONS, settings.scan_mode)
        country = _fa_label(window, self.country_combo, [], settings.exit_country_code) or window.tr("خودکار", "Automatic")
        chain = window.tr("سایفون روی وارپ", "Psiphon over WARP") if settings.chain_psiphon else window.tr("فقط وارپ", "WARP only")
        exit_mode = window.tr("پروکسی ویندوز", "Windows Proxy") if self._exit_proxy_mode else window.tr("حالت TUN", "TUN Mode")
        summary.setText(
            f"{country} · {transport} · {firewall} · {scan} · {chain} · {exit_mode}"
        )

    def _build_status_card(self) -> QFrame:
        from uac_desktop.ui import CyberProgressBar, GlowButton, MotionFrame

        window = self._window
        card = MotionFrame()
        card.setObjectName("powStatusCard")
        layout = QHBoxLayout(card)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(20)
        copy_box = QVBoxLayout()
        copy_box.setSpacing(6)
        self.state_label = window._bind_text(QLabel(), "PoW خاموش است", "PoW is OFF")
        self.state_label.setObjectName("powState")
        self.state_label.setWordWrap(True)
        self.detail_label = QLabel("")
        self.detail_label.setObjectName("powDetail")
        self.detail_label.setWordWrap(True)
        self.route_label = QLabel("")
        self.route_label.setObjectName("powRoute")
        self.route_label.setWordWrap(True)
        self.progress = CyberProgressBar()
        self.progress.setMaximum(100)
        self.progress.setValue(0)
        copy_box.addWidget(self.state_label)
        copy_box.addWidget(self.detail_label)
        copy_box.addWidget(self.route_label)
        copy_box.addWidget(self.progress)
        layout.addLayout(copy_box, 1)
        side = QVBoxLayout()
        side.setSpacing(8)
        self.connect_button = GlowButton("اتصال")
        self.connect_button.setObjectName("powConnectButton")
        self.connect_button.setProperty("state", "idle")
        self.connect_button.setMinimumSize(200, 56)
        self.connect_button.setCursor(Qt.PointingHandCursor)
        self.connect_button.clicked.connect(self.toggle)
        side.addWidget(self.connect_button)
        self.exit_label = QLabel("")
        self.exit_label.setObjectName("powExit")
        self.exit_label.setAlignment(Qt.AlignCenter)
        self.exit_label.setWordWrap(True)
        side.addWidget(self.exit_label)
        side.addStretch()
        layout.addLayout(side)
        return card

    def _segmented(self, options, attr: str) -> PowSegmented:
        window = self._window
        control = PowSegmented()
        for key, fa_option, en_option in options:
            control.addItem(fa_option if window.language != "en" else en_option, key)
        control.currentIndexChanged.connect(lambda _index, name=attr: self._field_changed(name))
        setattr(self, f"{attr}_combo", control)
        return control

    def _compact_combo(self, options, attr: str) -> QComboBox:
        window = self._window
        combo = QComboBox()
        combo.setObjectName("powComboCompact")
        combo.setCursor(Qt.PointingHandCursor)
        combo.setFixedWidth(210)
        for key, fa_option, en_option in options:
            combo.addItem(fa_option if window.language != "en" else en_option, key)
        combo.currentIndexChanged.connect(lambda _index, name=attr: self._field_changed(name))
        setattr(self, f"{attr}_combo", combo)
        return combo

    def _build_tunnel_section(self) -> QFrame:
        window = self._window
        section = PowSection(window, "تونل WARP", "WARP tunnel", "route")
        section.add(_setting_row(
            window, "انتقال", "Transport",
            "اول کدام مسیر WARP امتحان شود", "Which WARP leg is tried first",
            self._segmented(_TRANSPORT_OPTIONS, "transport")))
        section.add(_setting_row(
            window, "مسیر لینک", "Link path",
            "دستور دقیق اتصال WARP؛ خودکار برای بیشتر شبکه‌ها", "Exact WARP recipe; Auto suits most networks",
            self._compact_combo(_RECIPE_OPTIONS, "recipe")))
        section.add(_setting_row(
            window, "جستجو", "Search",
            "مدت جستجوی آدرس تمیز", "How long to hunt for a clean edge",
            self._segmented(_SCAN_OPTIONS, "scan")))
        section.add(_setting_row(
            window, "مبهم‌سازی", "Obfuscation",
            "نویز روی دست‌دهی WARP", "Noise added to the WARP handshake",
            self._segmented(_OBFUSCATION_OPTIONS, "obfuscation")))
        from uac_desktop.ui import ToggleSwitch

        self.optimized_toggle = ToggleSwitch()
        self.optimized_toggle.setCursor(Qt.PointingHandCursor)
        self.optimized_toggle.toggled.connect(lambda _on: self._field_changed("optimized"))
        section.add(_setting_row(
            window, "حالت بهینه", "Optimized mode",
            "تنظیم سایفون برای اتصال سریع‌تر و پایدارتر", "Tunes Psiphon workers and DNS for faster, steadier connects",
            self.optimized_toggle))
        return section

    def _build_speed_section(self) -> QFrame:
        from uac_desktop.ui import ToggleSwitch

        window = self._window
        section = PowSection(window, "سرعت", "Speed", "zap")
        for key, _field, fa_title, en_title, fa_hint, en_hint in _SPEED_OPTIONS:
            toggle = ToggleSwitch()
            toggle.setCursor(Qt.PointingHandCursor)
            toggle.toggled.connect(lambda _on, name=key: self._field_changed("speed_" + name))
            setattr(self, f"speed_{key}_toggle", toggle)
            section.add(_setting_row(window, fa_title, en_title, fa_hint, en_hint, toggle))
        return section

    def _build_identity_card(self) -> QFrame:
        window = self._window
        section = PowSection(window, "کلید و هویت", "Key & Identity", "lock",
                             collapsible=True, expanded=True)
        status = QFrame()
        status.setObjectName("powSettingRow")
        status.setAttribute(Qt.WA_StyledBackground, True)
        status_layout = QVBoxLayout(status)
        status_layout.setContentsMargins(10, 6, 10, 6)
        status_layout.setSpacing(2)
        self.identity_state = QLabel("")
        self.identity_state.setObjectName("powRowTitle")
        self.identity_state.setWordWrap(True)
        self.identity_detail = QLabel("")
        self.identity_detail.setObjectName("powRowDesc")
        self.identity_detail.setWordWrap(True)
        self.identity_detail.setTextInteractionFlags(Qt.TextSelectableByMouse)
        status_layout.addWidget(self.identity_state)
        status_layout.addWidget(self.identity_detail)
        section.add(status)
        section.add(_setting_row(
            window, "دریافت کلید", "Key fetch",
            "روش درخواست کلید جدید WARP", "How a new WARP key is requested",
            self._segmented(_KEY_FETCH_OPTIONS, "key_fetch")))
        buttons = QHBoxLayout()
        buttons.setContentsMargins(10, 6, 10, 2)
        buttons.setSpacing(8)
        self.key_button = self._compact_button("دریافت کلید", "Get Key", "zap")
        self.key_button.clicked.connect(self._fetch_key)
        self.cert_button = self._compact_button("گواهی تازه", "Fresh Certificate", "refresh")
        self.cert_button.clicked.connect(self._renew_cert)
        self.forget_button = self._compact_button("حذف کلید", "Forget Key", "trash")
        self.forget_button.setProperty("danger", True)
        self.forget_button.clicked.connect(self._forget_key)
        buttons.addWidget(self.key_button)
        buttons.addWidget(self.cert_button)
        buttons.addStretch()
        buttons.addWidget(self.forget_button)
        holder = QWidget()
        holder.setLayout(buttons)
        section.add(holder)
        return section

    def _compact_button(self, persian: str, english: str, icon_name: str) -> QPushButton:
        from uac_desktop.ui import cyber_icon

        window = self._window
        button = QPushButton()
        button.setObjectName("powCompactAction")
        button.setIcon(cyber_icon(icon_name, "#bfefff", 15))
        button.setIconSize(QSize(15, 15))
        button.setCursor(Qt.PointingHandCursor)
        window._bind_text(button, persian, english)
        return button

    def _build_learned_section(self) -> QFrame:
        window = self._window
        self.learned_count = QLabel("")
        self.learned_count.setObjectName("powPickerCount")
        section = PowSection(window, "مسیرهای آموخته", "Learned routes", "map-pin",
                             collapsible=True, expanded=False, trailing=self.learned_count)
        intro = window._bind_text(
            QLabel(),
            "بعد از هر اتصال موفق، روش سایفون، تأخیر و کشور نزدیک برای همان شبکه ذخیره می‌شود و دفعه بعد اول امتحان می‌شود.",
            "After each successful connect the Psiphon method, its latency and the nearby exit are saved for that network and tried first next time.",
        )
        intro.setObjectName("powRowDesc")
        intro.setWordWrap(True)
        intro.setContentsMargins(10, 0, 10, 4)
        section.add(intro)
        self.learned_box = QVBoxLayout()
        self.learned_box.setContentsMargins(10, 0, 10, 0)
        self.learned_box.setSpacing(3)
        holder = QWidget()
        holder.setLayout(self.learned_box)
        section.add(holder)
        actions = QHBoxLayout()
        actions.setContentsMargins(10, 6, 10, 2)
        actions.addStretch()
        forget = self._compact_button("فراموش کردن مسیرها", "Forget learned routes", "trash")
        forget.setProperty("danger", True)
        forget.clicked.connect(self._forget_learned)
        actions.addWidget(forget)
        action_holder = QWidget()
        action_holder.setLayout(actions)
        section.add(action_holder)
        self._refresh_learned()
        return section

    def _refresh_learned(self) -> None:
        box = getattr(self, "learned_box", None)
        if box is None:
            return
        window = self._window
        while box.count():
            item = box.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        try:
            networks = self.store.learned_networks()
        except Exception:
            networks = []
        if self.learned_count is not None:
            self.learned_count.setText(window.tr(f"{len(networks)} شبکه", f"{len(networks)} network" + ("" if len(networks) == 1 else "s")))
        if not networks:
            empty = QLabel(window.tr("هنوز چیزی آموخته نشده.", "Nothing learned yet."))
            empty.setObjectName("powLearnedLine")
            box.addWidget(empty)
            return
        names = {"F": window.tr("سبک", "light"), "A": window.tr("میک", "meek")}
        now = time.time()
        for entry in networks[:4]:
            parts = [window.tr("شبکه", "Network") + f" {entry.get('key', '')[:6]}"]
            region = str(entry.get("region") or "")
            if region:
                parts.append(f"{ALL_NAMES.get(region, region)} ({region})")
            shape = str(entry.get("strategy_shape") or "")
            try:
                index = int(entry.get("strategy_index"))
                strategy = shape.split(",")[index] if shape else ""
            except (TypeError, ValueError, IndexError):
                strategy = ""
            rtts = entry.get("rtt") if isinstance(entry.get("rtt"), dict) else {}
            if strategy:
                rtt = rtts.get("c" + strategy) or rtts.get("d" + strategy)
                label = f"{names.get(strategy, strategy)} ({strategy})"
                parts.append(label + (f" {rtt} ms" if rtt else ""))
            seen = int(entry.get("seen") or 0)
            if seen:
                minutes = max(0, int((now - seen) // 60))
                if minutes < 60:
                    ago = window.tr(f"{minutes} دقیقه پیش", f"{minutes} min ago")
                elif minutes < 60 * 48:
                    ago = window.tr(f"{minutes // 60} ساعت پیش", f"{minutes // 60} h ago")
                else:
                    ago = window.tr(f"{minutes // 1440} روز پیش", f"{minutes // 1440} d ago")
                parts.append(ago)
            line = QLabel("\u2022  " + "  \u00b7  ".join(parts))
            line.setObjectName("powLearnedLine")
            line.setLayoutDirection(Qt.LeftToRight)
            box.addWidget(line)

    def _forget_learned(self) -> None:
        try:
            self.store.forget_learned()
        except Exception as exc:
            self._window.show_toast(str(exc)[:200], "error")
            return
        self._refresh_learned()
        self._window.show_toast(
            self._window.tr("مسیرهای آموخته پاک شد", "Learned routes cleared"), "info")

    def _build_stages_card(self) -> QFrame:
        from uac_desktop.ui import MotionFrame

        window = self._window
        card = MotionFrame()
        card.setObjectName("powCard")
        root = QVBoxLayout(card)
        root.setContentsMargins(22, 18, 22, 18)
        root.setSpacing(8)
        title = window._bind_text(QLabel(), "مراحل اتصال", "Connection Stages")
        title.setObjectName("powCardTitle")
        root.addWidget(title)
        self.steps_box = QVBoxLayout()
        self.steps_box.setSpacing(4)
        root.addLayout(self.steps_box)
        return card

    # -- settings binding ------------------------------------------------------
    def _set_combo(self, combo: QComboBox, value: str) -> None:
        if combo is None:
            return
        for index in range(combo.count()):
            if str(combo.itemData(index) or "") == value:
                combo.blockSignals(True)
                combo.setCurrentIndex(index)
                combo.blockSignals(False)
                return
        combo.blockSignals(True)
        combo.setCurrentIndex(0)
        combo.blockSignals(False)

    def _load_settings_into_widgets(self) -> None:
        settings = self.store.snapshot()
        self._set_combo(self.country_combo, (settings.exit_country_code or "").lower())
        self._set_combo(self.transport_combo, settings.outer_transport)
        self._set_combo(self.firewall_combo, settings.firewall_profile)
        self._set_combo(self.scan_combo, settings.scan_mode)
        self._set_combo(self.recipe_combo, settings.link_recipe)
        self._set_combo(self.obfuscation_combo, settings.obfuscation_profile)
        self._set_combo(self.key_fetch_combo, settings.key_fetch)
        for toggle, value in (
            (self.chain_toggle, settings.chain_psiphon),
            (self.optimized_toggle, settings.optimized_mode),
            (self.h2_toggle, settings.h2_fragmentation),
            (self.proxy_toggle, self._exit_proxy_mode),
            (self.tun_toggle, not self._exit_proxy_mode),
            *(
                (getattr(self, f"speed_{key}_toggle", None), getattr(settings, field))
                for key, field, *_rest in _SPEED_OPTIONS
            ),
        ):
            if toggle is None:
                continue
            toggle.blockSignals(True)
            toggle.setChecked(bool(value))
            toggle.blockSignals(False)
            # Signals were blocked, so move the switch thumb ourselves.
            if hasattr(toggle, "_set_thumb_position"):
                toggle._set_thumb_position(1.0 if value else 0.0)

    def _collect_settings(self) -> C.PowSettings:
        """Start from the stored settings and apply only the controls that are
        on screen. Home owns country/firewall/toggles and writes them straight
        to the store, so the dialog never overwrites them."""
        from dataclasses import replace

        settings = self.store.snapshot()

        def _value(control, fallback: str) -> str:
            data = control.currentData()
            return str(data) if data else fallback

        changes = {}
        for attr, field, fallback in (
            ("transport_combo", "outer_transport", C.OUTER_AUTO),
            ("scan_combo", "scan_mode", C.SCAN_BALANCED),
            ("recipe_combo", "link_recipe", C.RECIPE_AUTO),
            ("obfuscation_combo", "obfuscation_profile", "balanced"),
            ("key_fetch_combo", "key_fetch", C.DEFAULT_KEY_FETCH),
            ("country_combo", "exit_country_code", ""),
            ("firewall_combo", "firewall_profile", C.FIREWALL_AUTO),
        ):
            control = getattr(self, attr, None)
            if control is not None:
                changes[field] = _value(control, fallback)
        for attr, field in (
            ("chain_toggle", "chain_psiphon"),
            ("optimized_toggle", "optimized_mode"),
            ("h2_toggle", "h2_fragmentation"),
            *((f"speed_{key}_toggle", field) for key, field, *_rest in _SPEED_OPTIONS),
        ):
            toggle = getattr(self, attr, None)
            if toggle is not None:
                changes[field] = bool(toggle.isChecked())
        return replace(settings, **changes) if changes else settings

    def _field_changed(self, _name: str) -> None:
        if not self._editing:
            return
        try:
            before = self.store.snapshot()
            after = self._collect_settings()
            self.store.save(after)
            logger = getattr(self._window, "_log_pow_setting_changes", None)
            if logger is not None:
                try:
                    logger(before, after)
                except Exception:
                    pass
        except Exception as exc:
            self._window.bridge.log.emit(f"PoW settings save failed: {exc}")
        try:
            self._update_settings_summary()
        except Exception:
            pass

    def _exit_mode_changed(self, proxy: bool, on: bool) -> None:
        if not on:
            # Keep one exit mode always selected.
            (self.proxy_toggle if proxy else self.tun_toggle).blockSignals(True)
            (self.proxy_toggle if proxy else self.tun_toggle).setChecked(True)
            (self.proxy_toggle if proxy else self.tun_toggle).blockSignals(False)
            return
        self._exit_proxy_mode = proxy
        other = self.tun_toggle if proxy else self.proxy_toggle
        other.blockSignals(True)
        other.setChecked(False)
        other.blockSignals(False)
        try:
            self._update_settings_summary()
        except Exception:
            pass

    # -- identity ---------------------------------------------------------------
    def _refresh_identity(self) -> None:
        window = self._window
        if self.identity_state is None or self.identity_detail is None:
            return
        try:
            identity = read_identity(self.data_dir)
        except Exception as exc:
            self.identity_state.setText(window.tr("خطا در خواندن هویت", "Identity read error"))
            self.identity_detail.setText(str(exc)[:300])
            return
        try:
            clean = read_clean_h2_peers(self.data_dir)
        except Exception:
            clean = []
        if not identity.present:
            self.identity_state.setText(
                window.tr("کلیدی ثبت نشده است", "No key enrolled"))
            self.identity_detail.setText(
                window.tr("برای شروع «دریافت کلید» را بزنید.", "Press Get Key to start."))
            return
        device = short_id(identity.device_id) if identity.device_id else "—"
        fa_state, en_state = identity.state_label
        self.identity_state.setText(
            f"{en_state if window.language == 'en' else fa_state} · {device}")
        lines = [identity.issued_label()]
        if identity.ipv4:
            lines.append(f"IPv4 {identity.ipv4}")
        if identity.ipv6:
            lines.append(f"IPv6 {identity.ipv6}")
        if clean:
            lines.append(
                window.tr(f"لیست تمیز: {len(clean)} مسیر", f"Clean list: {len(clean)} paths"))
            self.identity_detail.setText(" · ".join(line for line in lines if line))
        else:
            self.identity_detail.setText(" · ".join(line for line in lines if line))

    def _run_worker(self, label: str, func) -> None:
        window = self._window

        def _work() -> None:
            try:
                func()
            except Exception as exc:
                window.bridge.log.emit(f"{label} failed: {exc}")
                window.bridge.error.emit(f"{label} failed: {exc}")
            finally:
                window.bridge.log.emit(f"{label} finished")

        thread = threading.Thread(target=_work, name=f"pow-{label}", daemon=True)
        thread.start()

    def _key_log_line(self, line: str) -> None:
        text = (line or "").strip()
        if text.startswith(("Key:", "Cert:")):
            try:
                self._window.bridge.log.emit(text[:300])
            except Exception:
                pass

    def _fetch_key(self) -> None:
        settings = self.store.snapshot()
        self._run_worker(
            "PoW key fetch",
            lambda: prepare_identity(self.data_dir, settings, on_log=self._key_log_line),
        )
        self._window.show_toast(
            self._window.tr("درخواست کلید ارسال شد؛ نتیجه در لاگ", "Key request sent — watch Live Logs"),
            "info",
        )
        QTimer.singleShot(4000, self._refresh_identity)

    def _renew_cert(self) -> None:
        settings = self.store.snapshot()
        self._run_worker(
            "PoW certificate renew",
            lambda: prepare_identity(self.data_dir, settings, renew=True, on_log=self._key_log_line),
        )
        QTimer.singleShot(4000, self._refresh_identity)

    def _forget_key(self) -> None:
        try:
            forgotten = forget_identity(self.data_dir)
        except Exception as exc:
            self._window.show_toast(str(exc)[:200], "error")
            return
        self._window.show_toast(
            self._window.tr(
                "کلید حذف شد" if forgotten else "کلیدی برای حذف نبود",
                "Key forgotten" if forgotten else "No key to forget",
            ),
            "info",
        )
        self._refresh_identity()

    # -- connect ------------------------------------------------------------------
    @property
    def running(self) -> bool:
        try:
            return bool(self.coordinator.running)
        except Exception:
            return False

    @property
    def busy(self) -> bool:
        return self._connecting or self.running

    def toggle(self) -> None:
        if self._connecting or self.running:
            # The button turns into Disconnect as soon as the click lands.
            # Ignore that same double-click so it cannot cancel the attempt.
            started = getattr(self, "_connect_started", 0.0)
            if self._connecting and time.time() - started < 5.0:
                return
            self.disconnect()
        else:
            self.connect()

    def connect(self) -> None:
        window = self._window
        if self._connecting or self.running:
            return
        self._stop_xray_first()
        # Connect from the saved file. The settings dialog is the only writer,
        # and only while it is open.
        settings = self.store.snapshot()
        proxy_mode = self._exit_proxy_mode
        bypass = list(window.storage.settings.get("bypass_processes", []) or [])
        self._connecting = True
        self._attempt_open = True
        self._connect_started = time.time()
        self._failed_message = ""
        self._activity_kind = ""
        self.status.reset()
        self._note_activity("progress")
        token = object()
        self._connect_token = token

        def _work() -> None:
            try:
                message = self.coordinator.connect(
                    settings, proxy_mode=proxy_mode, bypass_processes=bypass
                )
                window.bridge.log.emit(message)
                if self._exit_proxy_mode != proxy_mode:
                    # The exit switch was flipped while connecting: apply it now.
                    self.coordinator.switch_exit_mode(lambda: self._exit_proxy_mode)
            except PowEngineError as exc:
                self._failed_message = "" if str(exc) == "stopped" else str(exc)
                if str(exc) != "stopped":
                    window.bridge.log.emit(f"UAC PoW failed: {exc}")
                else:
                    window.bridge.log.emit("UAC PoW cancelled")
            except Exception as exc:  # never crash the worker silently
                self._failed_message = str(exc) or repr(exc)
                window.bridge.log.emit(f"UAC PoW error: {exc}")
            finally:
                # An older attempt that unwinds late must not mark a newer
                # connect as finished.
                if getattr(self, "_connect_token", None) is token:
                    self._connecting = False

        self._thread = threading.Thread(target=_work, name="pow-connect", daemon=True)
        self._thread.start()

    def disconnect(self, quiet: bool = False) -> None:
        window = self._window
        if not self._connecting and not self.running:
            return
        self._attempt_open = False
        self._failed_message = ""
        self._window._set_activity(
            "در حال قطع UAC PoW…", "Disconnecting UAC PoW…")

        def _work() -> None:
            try:
                self.coordinator.disconnect(quiet=quiet)
            except Exception as exc:
                window.bridge.log.emit(f"UAC PoW disconnect failed: {exc}")
            finally:
                self._connecting = False

        thread = threading.Thread(target=_work, name="pow-disconnect", daemon=True)
        thread.start()

    def _stop_xray_first(self) -> None:
        """Mutual exclusion: the Xray engine must be down before PoW starts."""
        window = self._window
        try:
            xray_running = bool(window.engine.running)
        except Exception:
            xray_running = False
        try:
            xray_connecting = bool(window.connecting)
        except Exception:
            xray_connecting = False
        if not xray_running and not xray_connecting:
            return
        window.bridge.log.emit("Stopping the Xray engine before UAC PoW connects")
        try:
            cancel = getattr(window, "_cancel_connect_attempt", None)
            if callable(cancel):
                cancel(notify=False)
        except Exception:
            pass
        try:
            window.engine.stop(notify=False)
        except Exception as exc:
            window.bridge.log.emit(f"Xray stop failed: {exc}")
        try:
            window._set_state(False)
        except Exception:
            pass

    def shutdown(self) -> None:
        try:
            self._poll.stop()
        except Exception:
            pass
        try:
            self.coordinator.disconnect(quiet=True)
        except Exception:
            pass
        try:
            from .process_win import cleanup_bin_helpers
            cleanup_bin_helpers()
        except Exception:
            pass
        self._connecting = False

    def apply_language(self) -> None:
        """Refresh PoW labels that are rebuilt from the live language."""
        try:
            self._update_settings_summary()
        except Exception:
            pass
        try:
            self._refresh_identity()
        except Exception:
            pass
        try:
            self._refresh()
        except Exception:
            pass

    # -- refresh (GUI thread) ------------------------------------------------------
    # -- exit mode / HTTP/2 fragment (Home switches) ----------------------------
    def effective_exit_proxy(self) -> bool:
        """What the Home switches show: the running session's real exit, the
        requested one while a switch is applying, else the saved choice."""
        if self._switch_target is not None:
            return bool(self._switch_target)
        try:
            actual = self.coordinator.actual_proxy_mode
        except Exception:
            actual = None
        return bool(self._exit_proxy_mode if actual is None else actual)

    def set_exit_mode(self, proxy: bool) -> None:
        """Save the exit choice; when connected, really switch the running exit."""
        proxy = bool(proxy)
        self._exit_proxy_mode = proxy
        try:
            self.store.save_exit_proxy_mode(proxy)
        except Exception:
            pass
        try:
            self._update_settings_summary()
        except Exception:
            pass
        window = self._window
        if not self.coordinator.running:
            if self._connecting:
                window.bridge.log.emit(
                    "Exit mode saved; it is applied as soon as the current connect finishes")
            return
        if self.coordinator.actual_proxy_mode == proxy and self._switch_target is None:
            return
        self._switch_target = proxy
        token = object()
        self._switch_token = token

        def _work() -> None:
            try:
                self.coordinator.switch_exit_mode(lambda: self._exit_proxy_mode)
            except Exception as exc:
                window.bridge.log.emit(f"UAC PoW exit switch failed: {exc}")
            finally:
                if self._switch_token is token:
                    self._switch_target = None

        threading.Thread(target=_work, name="pow-exit-switch", daemon=True).start()

    def h2_fragment_display(self) -> tuple[bool, bool]:
        """(switch on, turned on by adaptive auto). Off = auto mode."""
        try:
            mode = self.store.snapshot().h2_fragment_mode
        except Exception:
            mode = C.H2_FRAG_AUTO
        if mode == C.H2_FRAG_ON:
            return True, False
        if mode == C.H2_FRAG_OFF:
            return False, False
        on = C.adaptive_on(self.data_dir)
        return on, on

    def set_h2_fragment(self, on: bool) -> None:
        """On = force HTTP/2 fragmentation; off = back to auto (adaptive decides
        again from scratch). Used at the next outer (re)connect, like mobile."""
        if not on:
            try:
                C.AdaptiveObfuscation(self.data_dir).reset()
            except Exception:
                pass
        changes = {"h2_fragment_mode": C.H2_FRAG_ON if on else C.H2_FRAG_AUTO,
                   "h2_fragmentation": bool(on)}
        setter = getattr(self._window, "_pow_setting", None)
        if setter is not None:
            setter(**changes)
        else:
            from dataclasses import replace
            self.store.save(replace(self.store.snapshot(), **changes))

    def _thread_log(self, message: str) -> None:
        try:
            self._window.bridge.log.emit(str(message))
        except Exception:
            pass

    def _refresh(self) -> None:
        window = self._window
        if getattr(window, "_closing", False):
            return
        try:
            snapshot = self.status.snapshot()
        except Exception:
            return
        sync = getattr(window, "_pow_sync_home_visuals", None)
        if sync is not None:
            try:
                sync()
            except Exception:
                pass
        try:
            self._render_snapshot(snapshot)
        except RuntimeError:
            # Widgets already destroyed during shutdown.
            try:
                self._poll.stop()
            except Exception:
                pass
        except Exception:
            pass

    def check_exit_ip(self) -> None:
        """Home 'Check IP' in PoW mode: one Cloudflare trace through the PoW exit."""
        window = self._window
        try:
            window.ip_button.setEnabled(False)
            window._set_activity("در حال بررسی آی‌پی خروجی…", "Checking exit IP…")
        except Exception:
            pass
        coordinator = self.coordinator

        def _work() -> None:
            info = coordinator.refresh_exit_info(background=False)
            try:
                if info.get("ip"):
                    window.bridge.log.emit(f"Public IP (PoW exit): {info['ip']} {info.get('country', '')}".strip())
                    window.bridge.activity.emit(
                        window.tr("آی‌پی خروجی دریافت شد.", "Exit IP check completed."), "success", False)
                else:
                    window.bridge.activity.emit(
                        window.tr("بررسی آی‌پی خروجی ناموفق بود.", "Exit IP check failed."), "error", False)
            except Exception:
                pass
            self._ip_signature = None

        threading.Thread(target=_work, name="pow-check-ip", daemon=True).start()

    def _sync_ip_card(self, snapshot) -> None:
        """PoW Home IP card: exit IP + flag, and the parallel MASQUE badge."""
        window = self._window
        flag = getattr(window, "ip_flag", None)
        badge = getattr(window, "ip_parallel", None)
        if flag is None or badge is None:
            return
        active = (
            getattr(window, "engine_mode", ENGINE_XRAY) == ENGINE_POW
            and snapshot.phase == PowPhase.CONNECTED
        )
        if not active:
            if getattr(self, "_ip_owned", False):
                self._ip_owned = False
                self._ip_signature = None
                flag.setVisible(False)
                badge.setVisible(False)
                badge._signature = None
                window.ip_card.set_tight(False)
                window.ip_label.setText("—")
                window.ip_card.set_secondary("")
                try:
                    window.ip_button.setEnabled(True)
                except Exception:
                    pass
                try:
                    window._schedule_ip_refresh(700)  # back to the direct IP
                except Exception:
                    pass
            return
        from uac_desktop.ui import country_flag_icon

        info = self.coordinator.exit_info
        sessions = self.coordinator.parallel_sessions()
        fa = window.language != "en"
        note = getattr(self.coordinator, "parallel_note", "") or ""
        signature = (tuple(sorted(info.items())), tuple(tuple(sorted(s.items())) for s in sessions), note, fa)
        if signature == getattr(self, "_ip_signature", None):
            return
        self._ip_signature = signature
        self._ip_owned = True
        try:
            window.ip_button.setEnabled(True)
        except Exception:
            pass
        code = str(info.get("country") or "").upper()
        window.ip_label.setText(info.get("ip") or "…")
        if code and len(code) == 2:
            flag.setPixmap(country_flag_icon(code, 22, 16).pixmap(22, 16))
            flag.setToolTip(f"{ALL_NAMES.get(code, code)} ({code})")
            flag.setVisible(True)
        else:
            flag.setVisible(False)
        if len(sessions) >= 2:
            badge.set_sessions(sessions, fa)
            badge.setVisible(True)
            window.ip_card.set_secondary("")
            window.ip_card.set_tight(True)
        elif note:
            badge.set_note(note, fa)
            badge.setVisible(True)
            window.ip_card.set_tight(True)
            window.ip_card.set_secondary("")
        else:
            window.ip_card.set_tight(False)
            badge.setVisible(False)
            badge._signature = None
            exit_kind = window.tr("خروجی سایفون", "Psiphon exit") if self.coordinator.exit_port == getattr(self.coordinator, "psiphon_socks_port", C.PSIPHON_SOCKS_PORT) else window.tr("خروجی WARP", "WARP exit")
            name = ALL_NAMES.get(code, code) if code else ""
            secondary = window.ip_card.secondary
            if fa:
                try:
                    from uac_desktop.verified_configs import COUNTRIES as _countries
                    known = _countries.get(code)
                    name = (known[2] if known and known[2] else (f"\u2068{name}\u2069" if name else ""))
                except Exception:
                    name = f"\u2068{name}\u2069" if name else ""
                text = "\u200f" + "، ".join(part for part in (name, exit_kind) if part)
                secondary.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            else:
                text = " · ".join(part for part in (name, exit_kind) if part)
                secondary.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            window.ip_card.set_secondary(text)

    def _render_snapshot(self, snapshot) -> None:
        try:
            self._sync_ip_card(snapshot)
        except RuntimeError:
            raise
        except Exception:
            pass
        window = self._window
        phase = snapshot.phase
        busy_phase = phase in (PowPhase.STARTING, PowPhase.OUTER, PowPhase.INNER)
        # The worker clears _connecting in its own finally, before this timer
        # runs. Key off the thread having exited, not off _connecting.
        if self._attempt_open and self._thread is not None and not self._thread.is_alive():
            self._thread = None
            self._attempt_open = False
            if self._failed_message == "" and not self.coordinator.running:
                self._activity_kind = ""
                self._render_idle(self.status.snapshot())
                return
            if self.coordinator.running and not self._failed_message:
                self._on_connected()
            else:
                self._on_failed(self._failed_message or "UAC PoW did not connect")
            return
        try:
            self.progress.setBusy(bool(busy_phase))
        except Exception:
            pass
        try:
            self.progress.setValue(int(snapshot.progress or 0))
        except Exception:
            pass
        if phase == PowPhase.CONNECTED and self.coordinator.running:
            self._render_connected(snapshot)
        elif phase == PowPhase.FAILED:
            self._render_failed(snapshot)
        elif self._connecting or busy_phase or phase == PowPhase.BRIDGING:
            self._render_progress(snapshot)
        else:
            self._render_idle(snapshot)
        self._render_steps(snapshot)
        self._paint_home_route(snapshot)

    def _paint_home_route(self, snapshot) -> None:
        window = self._window
        if getattr(window, "engine_mode", "") != ENGINE_POW:
            return
        label = getattr(window, "active_profile", None)
        detail = getattr(window, "route_detail", None)
        if label is None or detail is None:
            return
        if snapshot.phase == PowPhase.CONNECTED or self.running:
            label.setText(snapshot.outer_label or "UAC PoW")
            detail.setText(snapshot.detail or snapshot.exit_region or "")
        elif snapshot.phase in (PowPhase.STARTING, PowPhase.OUTER, PowPhase.INNER, PowPhase.BRIDGING):
            label.setText(snapshot.outer_label or "UAC PoW")
            detail.setText(snapshot.detail or window.tr("در حال برقراری مسیر", "Bringing the route up"))
        else:
            label.setText("—")
            detail.setText(window.tr("مسیر PoW هنوز برقرار نشده", "PoW route is not up yet"))

    def _render_steps(self, snapshot) -> None:
        signature = tuple((step.text, str(step.state)) for step in snapshot.steps)
        if signature == self._steps_signature:
            return
        self._steps_signature = signature
        while self.steps_box.count():
            item = self.steps_box.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        for step in snapshot.steps[-8:]:
            label = QLabel(f"• {step.text}")
            label.setObjectName("powStep")
            label.setWordWrap(True)
            self.steps_box.addWidget(label)

    def _render_idle(self, snapshot) -> None:
        window = self._window
        self.state_label.setText(window.tr("PoW خاموش است", "PoW is OFF"))
        self.detail_label.setText(
            snapshot.detail or window.tr("آماده اتصال", "Ready to connect"))
        self.route_label.setText("")
        self.exit_label.setText("")
        self.connect_button.setText(window.tr("اتصال", "Connect"))
        self._paint_connect_button("idle")
        self._note_activity("idle")

    def _render_progress(self, snapshot) -> None:
        window = self._window
        self.state_label.setText(window.tr("در حال اتصال PoW…", "Connecting PoW…"))
        self.detail_label.setText(snapshot.detail or "")
        outer = snapshot.outer_label or ""
        region = snapshot.exit_region or ""
        suffix = " · ".join(part for part in (outer, region) if part)
        self.route_label.setText(suffix)
        self.connect_button.setText(window.tr("قطع اتصال", "Disconnect"))
        self._paint_connect_button("cancel")
        self._note_activity("progress")
        hint = getattr(window, "connection_hint", None)
        if hint is not None and getattr(window, "engine_mode", "") == ENGINE_POW:
            latest = snapshot.steps[-1].text if snapshot.steps else snapshot.detail
            if latest:
                hint.setText(latest)

    def _render_connected(self, snapshot) -> None:
        window = self._window
        self._note_activity("connected")
        self.state_label.setText(window.tr("PoW متصل است", "PoW is ON"))
        self.detail_label.setText(snapshot.detail or "")
        try:
            self.progress.setBusy(False)
            self.progress.setValue(100)
        except Exception:
            pass
        port = self.coordinator.exit_port
        region = snapshot.exit_region or self.coordinator.exit_region
        parts = []
        if region:
            parts.append(f"region {region}")
        if port:
            parts.append(f"127.0.0.1:{port}")
        self.route_label.setText(" · ".join(parts))
        self.exit_label.setText(
            window.tr(f"خروجی: {region or '—'}", f"Exit: {region or '—'}"))
        self.connect_button.setText(window.tr("قطع اتصال", "Disconnect"))
        self._paint_connect_button("connected")
        refresh_exit = getattr(window, "_update_pow_country_selector", None)
        if refresh_exit is not None and getattr(window, "engine_mode", "") == ENGINE_POW:
            try:
                refresh_exit()
            except Exception:
                pass

    def _render_failed(self, snapshot) -> None:
        window = self._window
        self.state_label.setText(window.tr("خطای PoW", "PoW Error"))
        self.detail_label.setText(
            snapshot.detail or self._failed_message or window.tr("اتصال ناموفق بود", "Connection failed"))
        self.connect_button.setText(window.tr("تلاش دوباره", "Retry"))
        self._paint_connect_button("error")
        self._note_activity("failed")
        try:
            self.progress.setBusy(False)
        except Exception:
            pass

    def _on_connected(self) -> None:
        window = self._window
        try:
            snapshot = self.status.snapshot()
        except Exception:
            return
        self._render_connected(snapshot)
        window.show_toast(window.tr("UAC PoW متصل شد", "UAC PoW connected"), "success")

    def _on_failed(self, message: str) -> None:
        window = self._window
        self._failed_message = message
        try:
            snapshot = self.status.snapshot()
        except Exception:
            snapshot = None
        if snapshot is not None:
            self._render_failed(snapshot)
        else:
            self.state_label.setText(window.tr("خطای PoW", "PoW Error"))
            self.detail_label.setText(message[:300])
            self._note_activity("failed")
        window.show_toast(
            window.tr(f"اتصال PoW ناموفق بود: {message[:120]}", f"PoW failed: {message[:120]}"),
            "error",
        )

    def _note_activity(self, kind: str) -> None:
        """Update the shared activity bar once per phase.

        The connect worker finishes before the UI timer sees it, so the bar
        has to follow the rendered phase itself. Otherwise it stays on
        "Connecting" after the tunnel is up.
        """
        if self._activity_kind == kind:
            return
        window = self._window
        if getattr(window, "engine_mode", "") != ENGINE_POW:
            return
        self._activity_kind = kind
        if kind == "connected":
            window._set_activity(
                "اتصال امن PoW برقرار شد.",
                "Secure PoW connection established.",
                "success",
                False,
            )
            window._set_connection_visual("connected")
        elif kind == "failed":
            window._set_activity(
                "اتصال PoW ناموفق بود.", "PoW connection failed.", "warning", False)
            window._set_connection_visual("error")
        elif kind == "progress":
            window._set_activity("در حال اتصال UAC PoW…", "Connecting UAC PoW…")
            window._set_connection_visual("connecting")
        elif kind == "idle":
            window._set_activity("UAC PoW آماده است.", "UAC PoW is ready.", "success", False)
            window._set_connection_visual("disconnected")

    def _paint_connect_button(self, state: str) -> None:
        button = self.connect_button
        button.setProperty("state", state)
        button.style().unpolish(button)
        button.style().polish(button)
        button.update()

    def _sync_home_visual(self, state: str, message: str = "") -> None:
        """Kept so older callers compile. The home Connect button is the Xray
        control and must not change while UAC PoW connects."""
        return
