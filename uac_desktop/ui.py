from __future__ import annotations

import os
import ctypes
import html
import math
import subprocess
import threading
import time
import webbrowser
from dataclasses import replace

import psutil
import requests
from PySide6.QtCore import (
    QObject, Qt, QTimer, Signal, QSize, QRectF, QPointF, QPoint, QPropertyAnimation,
    QEasingCurve, Property, QParallelAnimationGroup,
)
from PySide6.QtGui import (
    QColor, QFont, QIcon, QPainter, QPen, QLinearGradient, QIntValidator,
    QRadialGradient, QPainterPath,
    QTextCursor, QTextCharFormat, QAction,
)
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog,
    QFrame, QGridLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QListWidget, QListWidgetItem, QMainWindow, QMessageBox, QPlainTextEdit,
    QPushButton, QScrollArea, QStackedWidget, QTableWidget, QTableWidgetItem,
    QTabWidget, QTextEdit, QVBoxLayout, QWidget, QSizePolicy, QGraphicsDropShadowEffect,
    QGraphicsOpacityEffect, QBoxLayout, QStyle, QStyleOptionButton, QToolButton,
    QSystemTrayIcon, QMenu,
)

from . import __version__
from .app_config import PROJECT_URL, SUGGESTED_CONFIGS_URL, UPDATE_REPOSITORY_URL
from .engine import Engine, EngineCancelled, format_bytes, mci_quality_score
from .models import ProxyProfile, Tuning, parse_many
from .network import ScanResult, current_ip, profile_ping, scan_domains, tcp_ping
from .paths import ASSETS, DATA_DIR, LOG_FILE
from .storage import Storage
from .icons import icon as cyber_icon, pixmap as cyber_pixmap
from .update_checker import SemVersion, UpdateInfo, check_latest_release, parse_github_repository


REMOTE_CONFIGS_URL = SUGGESTED_CONFIGS_URL
DEFAULT_UPDATE_REPO_URL = UPDATE_REPOSITORY_URL

FA_EN = {
    "خانه": "Home", "کانفیگ‌ها": "Configs", "آزمایشگاه SNI": "SNI Lab",
    "لاگ زنده": "Live Logs", "عبور مستقیم برنامه‌ها": "App Bypass", "ابزارها": "Tools", "پشتیبانی": "Support",
    "باز کردن پوشه داده‌ها": "Open Data Folder", "کنترل اتصال": "Connection Center",
    "نسخه دسکتاپ با استفاده از Xray، System Proxy ویندوز و هسته Patterniha Wrong-Sequence": "Desktop engine powered by Xray, Windows System Proxy and the Patterniha wrong-sequence core",
    "VPN خاموش است": "VPN is OFF", "VPN متصل است": "VPN is ON",
    "اتصال": "Connect", "قطع اتصال": "Disconnect", "در حال اتصال…": "Connecting…",
    "کانفیگ فعال": "Active Config", "مسیر فعال": "Active Route", "پینگ": "Latency",
    "آپلود": "Upload", "دانلود": "Download", "آی‌پی عمومی": "Public IP", "بررسی IP": "Check IP",
    "انتخاب بهترین کانفیگ دستی": "Pick Best Manual Config", "اپراتور:": "Carrier:",
    "تنظیمات پیشرفته": "Advanced Settings", "مدیریت کامل لینک‌های VLESS و Trojan": "Manage all VLESS and Trojan profiles",
    "+ افزودن": "+ Add", "ویرایش": "Edit", "حذف": "Delete", "ورود از Clipboard": "Import Clipboard",
    "دریافت Suggested": "Sync Suggested", "دستی": "Manual", "پیشنهادی": "Suggested",
    "اسکن همزمان، امتیازدهی پایداری و ذخیره بهترین مسیرها": "Concurrent scanning, stability scoring and route bookmarks",
    "دامنه‌ها": "Domains", "شروع اسکن": "Start Scan", "توقف اسکن": "Stop Scan",
    "نتایج": "Results", "ذخیره‌شده": "Saved", "ذخیره نتیجه": "Save Result",
    "اعمال SNI به کانفیگ فعال": "Apply SNI to Active Config", "کپی نتیجه": "Copy Result",
    "فقط رویدادهای مهم اتصال، خطا و تشخیص مسیر": "Connection, error and route diagnostics only",
    "کپی لاگ": "Copy Logs", "پاک کردن": "Clear",
    "پردازه‌هایی را انتخاب کنید که مستقیم و خارج از تونل کار کنند": "Select processes that should connect directly outside the tunnel",
    "خارج از VPN": "Bypass VPN", "به‌روزرسانی لیست پردازه‌ها": "Refresh Process List",
    "ابزارهای شبکه": "Network Tools", "قابلیت‌های بیشتر نسخه کامپیوتر": "Additional desktop network utilities",
    "اجرا": "Run", "پشتیبانی و بروزرسانی": "Support & Updates",
    "UAC Spoofer Desktop — سازگار با کانفیگ‌های نسخه موبایل": "UAC Spoofer Desktop — compatible with mobile profiles",
    "باز کردن کانال تلگرام": "Open Telegram Channel", "نام": "Name", "لینک VLESS / Trojan": "VLESS / Trojan URI",
    "IP اصلی": "Primary IP", "IP جایگزین": "Fallback IP", "پورت": "Port", "SNI جعلی": "Fake SNI",
    "روش": "Method", "پروفایل": "Preset", "اپراتور": "Carrier", "فعال": "Enabled",
    "تعداد probe": "Probe count", "اندازه fragment": "Fragment size", "تاخیر SNI split": "SNI split delay",
    "تاخیر TLS record": "TLS record delay", "مهلت route": "Route timeout", "اندازه pool": "Pool size",
    "تست IP مستقیم": "Direct IP Test", "نمایش IP بدون پروکسی": "Show IP without proxy",
    "تست IP تونل": "Tunnel IP Test", "نمایش IP از پروکسی UAC": "Show IP through UAC proxy",
    "باز کردن Log file": "Open Log File", "مشاهده فایل لاگ دائمی": "View persistent log file",
    "تست TCP و TLS مقصد": "Test target TCP and TLS", "کانال تلگرام: t.me/UacSniSpoofer": "Telegram: t.me/UacSniSpoofer",
    "کانفیگی انتخاب نشده": "No config selected", "کانفیگی موجود نیست": "No config available",
    "آماده اتصال": "Ready to connect", "در حال تست مسیرها و کانفیگ‌ها": "Testing routes and profiles",
    "ترافیک واقعی اینترنت تایید شد": "Real internet traffic verified",
    "در حال تست مسیر…": "Testing route…", "تست مسیر واقعی تونل": "Live tunnel test",
    "تست سریع لبه": "Quick edge test",
}
EN_FA = {value: key for key, value in FA_EN.items()}


class Bridge(QObject):
    log = Signal(str)
    state = Signal(bool)
    traffic = Signal(int, int)
    latency = Signal(float, str)
    scan_progress = Signal(int, int, object, int)
    scan_done = Signal(object, int)
    scan_failed = Signal(str, int)
    error = Signal(str)
    profiles_changed = Signal()
    ip = Signal(str)
    hint = Signal(str)
    activity = Signal(str, str, bool)
    processes = Signal(object)
    update_checked = Signal(object, int)
    update_failed = Signal(str, int, bool)


def _system_motion_enabled() -> bool:
    """Honor the Windows client-animation accessibility preference."""
    override = os.environ.get("UAC_REDUCED_MOTION", "").strip().lower()
    if override in {"1", "true", "yes", "on"}:
        return False
    if override in {"0", "false", "no", "off"}:
        return True
    if os.name == "nt":
        try:
            enabled = ctypes.c_int(1)
            if ctypes.windll.user32.SystemParametersInfoW(0x1042, 0, ctypes.byref(enabled), 0):
                return bool(enabled.value)
        except Exception:
            pass
    return True


MOTION_ENABLED = _system_motion_enabled()


def _animations_enabled() -> bool:
    app = QApplication.instance()
    return MOTION_ENABLED and (app is None or app.platformName() != "offscreen")


def _restyle(widget: QWidget) -> None:
    widget.style().unpolish(widget)
    widget.style().polish(widget)
    widget.update()


def ltr_isolate(value: object) -> str:
    """Keep technical tokens readable inside Persian sentences."""
    return f"\u2066{value}\u2069"


class MotionFrame(QFrame):
    """Glass panel with a GPU-light hover glow instead of an abrupt QSS jump."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._glow = 0.0
        self._glow_animation = QPropertyAnimation(self, b"glowProgress", self)
        self._glow_animation.setDuration(280)
        self._glow_animation.setEasingCurve(QEasingCurve.OutCubic)
        self.setAttribute(Qt.WA_Hover, True)

    def _get_glow(self):
        return self._glow

    def _set_glow(self, value):
        self._glow = max(0.0, min(1.0, float(value)))
        self.update()

    glowProgress = Property(float, _get_glow, _set_glow)

    def _animate_glow(self, target):
        if not _animations_enabled():
            self._set_glow(target)
            return
        self._glow_animation.stop()
        self._glow_animation.setStartValue(self._glow)
        self._glow_animation.setEndValue(float(target))
        self._glow_animation.start()

    def enterEvent(self, event):
        self._animate_glow(1.0)
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._animate_glow(0.0)
        super().leaveEvent(event)

    def paintEvent(self, event):
        super().paintEvent(event)
        if self._glow <= .001:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        radius = max(90.0, self.width() * .42)
        anchor_x = self.width() * (.82 if self.layoutDirection() == Qt.LeftToRight else .18)
        glow = QRadialGradient(QPointF(anchor_x, self.height() * .08), radius)
        glow.setColorAt(0, QColor(74, 255, 235, int(27 * self._glow)))
        glow.setColorAt(.46, QColor(44, 199, 255, int(11 * self._glow)))
        glow.setColorAt(1, QColor(44, 199, 255, 0))
        painter.setPen(Qt.NoPen)
        painter.setBrush(glow)
        painter.drawRoundedRect(QRectF(1, 1, self.width() - 2, self.height() - 2), 18, 18)
        edge = QColor(111, 255, 242, int(52 * self._glow))
        painter.setBrush(Qt.NoBrush)
        painter.setPen(QPen(edge, 1.0))
        painter.drawRoundedRect(QRectF(1.5, 1.5, self.width() - 3, self.height() - 3), 18, 18)


class GlowButton(QPushButton):
    """Standard push button with a soft, animated light sweep on hover."""

    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self._hover = 0.0
        self._hover_animation = QPropertyAnimation(self, b"hoverProgress", self)
        self._hover_animation.setDuration(230)
        self._hover_animation.setEasingCurve(QEasingCurve.OutCubic)
        self.setAttribute(Qt.WA_Hover, True)

    def _get_hover(self):
        return self._hover

    def _set_hover(self, value):
        self._hover = max(0.0, min(1.0, float(value)))
        self.update()

    hoverProgress = Property(float, _get_hover, _set_hover)

    def _animate_hover(self, target):
        if not _animations_enabled():
            self._set_hover(target)
            return
        self._hover_animation.stop()
        self._hover_animation.setStartValue(self._hover)
        self._hover_animation.setEndValue(float(target))
        self._hover_animation.start()

    def enterEvent(self, event):
        self._animate_hover(1.0)
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._animate_hover(0.0)
        super().leaveEvent(event)

    def paintEvent(self, event):
        super().paintEvent(event)
        if self._hover <= .001 or not self.isEnabled():
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        sweep_x = (-.18 + self._hover * 1.36) * self.width()
        sweep = QLinearGradient(sweep_x - 45, 0, sweep_x + 45, self.height())
        sweep.setColorAt(0, QColor(255, 255, 255, 0))
        sweep.setColorAt(.5, QColor(220, 255, 252, int(22 * self._hover)))
        sweep.setColorAt(1, QColor(255, 255, 255, 0))
        painter.setPen(Qt.NoPen)
        painter.setBrush(sweep)
        painter.drawRoundedRect(QRectF(1, 1, self.width() - 2, self.height() - 2), 11, 11)


class LuminousPageHeader(MotionFrame):
    """Readable page title surface with a restrained animated signal trace."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("pageHeader")
        self.setMinimumHeight(112)
        self._phase = 0.0
        self._signal_timer = QTimer(self)
        self._signal_timer.timeout.connect(self._tick_signal)
        if _animations_enabled():
            self._signal_timer.start(34)

    def _tick_signal(self):
        if self.isVisible():
            self._phase = (self._phase + .0065) % 1.0
            self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        y = self.height() - 2.0
        base = QLinearGradient(20, y, self.width() - 20, y)
        base.setColorAt(0, QColor(35, 245, 224, 0))
        base.setColorAt(.18, QColor(35, 245, 224, 78))
        base.setColorAt(.62, QColor(44, 199, 255, 30))
        base.setColorAt(1, QColor(124, 60, 255, 0))
        painter.setPen(QPen(base, 1.2, Qt.SolidLine, Qt.RoundCap))
        painter.drawLine(QPointF(20, y), QPointF(self.width() - 20, y))
        if MOTION_ENABLED:
            center = 20 + self._phase * max(1, self.width() - 40)
            signal = QLinearGradient(center - 74, y, center + 74, y)
            signal.setColorAt(0, QColor(35, 245, 224, 0))
            signal.setColorAt(.5, QColor(191, 255, 249, 225))
            signal.setColorAt(1, QColor(44, 199, 255, 0))
            painter.setPen(QPen(signal, 2.2, Qt.SolidLine, Qt.RoundCap))
            painter.drawLine(QPointF(max(20, center - 74), y), QPointF(min(self.width() - 20, center + 74), y))


class HelpDot(QToolButton):
    """Keyboard-accessible question mark with a localized hover guide."""

    def __init__(self, help_text: str, rtl: bool = False, parent=None):
        super().__init__(parent)
        self.setObjectName("helpDot")
        self.setText("?")
        self.setFixedSize(24, 24)
        self.setAutoRaise(True)
        self.setCursor(Qt.WhatsThisCursor)
        direction = "rtl" if rtl else "ltr"
        self.setToolTip(f"<div dir='{direction}' style='white-space:normal'>{html.escape(help_text)}</div>")
        self.setAccessibleName("راهنمای تنظیم" if rtl else "Setting help")
        self.setAccessibleDescription(help_text)


class CyberRoot(QWidget):
    """Lightweight animated grid/glow background; no particle engine."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("windowRoot")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self._phase = 0.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        # Keep the full-window grid static. Repainting the entire translucent
        # widget tree on a timer causes flicker on some Windows GPU drivers;
        # localized hero/status animations remain active and inexpensive.

    def _tick(self):
        self._phase = (self._phase + 0.45) % 48
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        width, height = self.width(), self.height()

        cyan = QRadialGradient(QPointF(width * .72, height * .12), max(280, width * .42))
        cyan.setColorAt(0, QColor(35, 245, 224, 23))
        cyan.setColorAt(.45, QColor(44, 199, 255, 10))
        cyan.setColorAt(1, QColor(5, 11, 24, 0))
        painter.fillRect(self.rect(), cyan)

        purple = QRadialGradient(QPointF(width * .94, height * .82), max(240, width * .33))
        purple.setColorAt(0, QColor(124, 60, 255, 18))
        purple.setColorAt(1, QColor(5, 11, 24, 0))
        painter.fillRect(self.rect(), purple)

        painter.setPen(QPen(QColor(44, 199, 255, 10), 1))
        offset = int(self._phase) if MOTION_ENABLED else 0
        for x in range(-48 + offset, width + 48, 48):
            painter.drawLine(x, 0, x, height)
        for y in range(-48 + offset, height + 48, 48):
            painter.drawLine(0, y, width, y)


class HeroCard(MotionFrame):
    """Cinematic hero surface with a restrained data wave and dot field."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("heroCard")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self._phase = 0.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        if _animations_enabled():
            self._timer.start(32)

    def _tick(self):
        self._phase = (self._phase + .018) % (math.pi * 2)
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        width, height = self.width(), self.height()

        glow = QRadialGradient(QPointF(width * .74, height * .47), max(130, height * .92))
        glow.setColorAt(0, QColor(35, 245, 224, 24))
        glow.setColorAt(.48, QColor(44, 199, 255, 9))
        glow.setColorAt(1, QColor(5, 11, 24, 0))
        painter.fillRect(self.rect(), glow)

        # A slow optical beam adds depth without repainting the full window.
        beam_x = width * (.12 + (.5 + .5 * math.sin(self._phase * .72)) * .76)
        beam = QLinearGradient(beam_x - 92, 0, beam_x + 92, height)
        beam.setColorAt(0, QColor(44, 199, 255, 0))
        beam.setColorAt(.48, QColor(105, 250, 239, 10))
        beam.setColorAt(.52, QColor(198, 255, 249, 23))
        beam.setColorAt(1, QColor(44, 199, 255, 0))
        painter.setPen(Qt.NoPen)
        painter.setBrush(beam)
        painter.drawRoundedRect(QRectF(1, 1, width - 2, height - 2), 26, 26)

        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(44, 199, 255, 24))
        start_x = int(width * .48)
        for x in range(start_x, width - 18, 20):
            for y in range(20, height - 14, 20):
                if ((x // 20) + (y // 20)) % 3 == 0:
                    painter.drawEllipse(QPointF(x, y), 1.15, 1.15)

        for index, alpha in enumerate((34, 20, 12)):
            path = QPainterPath()
            baseline = height * (.72 + index * .045)
            amplitude = max(7, height * (.045 - index * .008))
            path.moveTo(0, baseline)
            for x in range(0, width + 8, 8):
                wave = math.sin(x / 66 + self._phase + index * .7)
                wave += .38 * math.sin(x / 23 - self._phase * .7)
                path.lineTo(x, baseline + wave * amplitude)
            painter.setPen(QPen(QColor(44, 199, 255, alpha), 1.1))
            painter.drawPath(path)


class NavButton(QPushButton):
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self.setObjectName("navButton")
        self.setCheckable(True)
        self.setMinimumHeight(56)
        self.setCursor(Qt.PointingHandCursor)
        self.setAttribute(Qt.WA_Hover, True)

    def paintEvent(self, event):
        if self.layoutDirection() == Qt.RightToLeft:
            painter = QPainter(self)
            painter.setRenderHint(QPainter.Antialiasing)
            option = QStyleOptionButton()
            self.initStyleOption(option)
            option.text = ""
            option.icon = QIcon()
            self.style().drawControl(QStyle.CE_PushButton, option, painter, self)
            icon_size = self.iconSize()
            icon_x = self.width() - 16 - icon_size.width()
            icon_y = (self.height() - icon_size.height()) // 2
            text_rect = QRectF(34, 0, max(0, icon_x - 8 - 34), self.height())
            painter.setPen(option.palette.buttonText().color())
            painter.setFont(self.font())
            painter.drawText(text_rect, Qt.AlignRight | Qt.AlignAbsolute | Qt.AlignVCenter | Qt.TextSingleLine, self.text())
            self.icon().paint(painter, icon_x, icon_y, icon_size.width(), icon_size.height())
        else:
            super().paintEvent(event)
        if self.isChecked():
            if self.layoutDirection() != Qt.RightToLeft:
                painter = QPainter(self)
                painter.setRenderHint(QPainter.Antialiasing)
            trailing_x = 10 if self.layoutDirection() == Qt.LayoutDirection.RightToLeft else self.width() - 18
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(35, 245, 224, 45))
            painter.drawEllipse(QPointF(trailing_x, self.height() / 2), 8, 8)
            painter.setBrush(QColor("#23f5e0"))
            painter.drawEllipse(QPointF(trailing_x, self.height() / 2), 4, 4)


class ToggleSwitch(QCheckBox):
    """Keyboard-accessible custom switch without native checkbox chrome."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("toggleSwitch")
        self.setFixedSize(48, 26)
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.StrongFocus)
        self._thumb_position = 0.0
        self._thumb_animation = QPropertyAnimation(self, b"thumbPosition", self)
        self._thumb_animation.setDuration(260)
        self._thumb_animation.setEasingCurve(QEasingCurve.OutBack)
        self.toggled.connect(self._animate_thumb)

    def _get_thumb_position(self):
        return self._thumb_position

    def _set_thumb_position(self, value):
        self._thumb_position = max(0.0, min(1.0, float(value)))
        self.update()

    thumbPosition = Property(float, _get_thumb_position, _set_thumb_position)

    def _animate_thumb(self, checked):
        target = 1.0 if checked else 0.0
        if not _animations_enabled() or not self.isVisible():
            self._set_thumb_position(target)
            return
        self._thumb_animation.stop()
        self._thumb_animation.setStartValue(self._thumb_position)
        self._thumb_animation.setEndValue(target)
        self._thumb_animation.start()

    def sizeHint(self):
        return QSize(48, 26)

    def hitButton(self, pos):
        """Make the complete painted switch clickable, not only native chrome."""
        return self.rect().contains(pos)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        enabled = self.isEnabled()
        checked = self.isChecked()
        track = QColor("#0d6f76" if checked else "#12243c")
        if not enabled:
            track = QColor("#111c2d")
        painter.setPen(QPen(QColor("#41e8df" if checked else "#34506f"), 1))
        painter.setBrush(track)
        painter.drawRoundedRect(QRectF(1, 2, 46, 22), 11, 11)
        position = self._thumb_position
        if abs(position - float(checked)) > .001 and not self._thumb_animation.state():
            position = float(checked)
        thumb_x = 13 + 22 * position
        if self.layoutDirection() == Qt.RightToLeft:
            thumb_x = 35 - 22 * position
        painter.setPen(Qt.NoPen)
        glow_alpha = int(10 + 38 * position) if checked or position > .01 else 0
        painter.setBrush(QColor(35, 245, 224, glow_alpha))
        painter.drawEllipse(QPointF(thumb_x, 13), 10 + position, 10 + position)
        painter.setBrush(QColor("#eaffff" if checked else "#8da3bd"))
        painter.drawEllipse(QPointF(thumb_x, 13), 7, 7)
        if self.hasFocus():
            painter.setPen(QPen(QColor(44, 199, 255, 160), 1.4, Qt.DashLine))
            painter.setBrush(Qt.NoBrush)
            painter.drawRoundedRect(QRectF(.5, .5, 47, 25), 12, 12)


class PulseDot(QWidget):
    COLORS = {
        "disconnected": QColor("#5f7fa6"),
        "connecting": QColor("#ffd166"),
        "connected": QColor("#23f5a6"),
        "error": QColor("#ff5c7c"),
        "idle": QColor("#5f7fa6"),
        "running": QColor("#23f5e0"),
        "success": QColor("#23f5a6"),
        "warning": QColor("#ffd166"),
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(18, 18)
        self.state = "disconnected"
        self._phase = 0.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        if _animations_enabled():
            self._timer.start(40)

    def _tick(self):
        self._phase = (self._phase + .08) % (math.pi * 2)
        self.update()

    def set_state(self, state):
        self.state = state
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        color = QColor(self.COLORS.get(self.state, self.COLORS["idle"]))
        pulse = .5 + .5 * math.sin(self._phase) if MOTION_ENABLED else .4
        glow = QColor(color)
        glow.setAlpha(int(35 + pulse * 55))
        painter.setPen(Qt.NoPen)
        painter.setBrush(glow)
        painter.drawEllipse(QPointF(9, 9), 7, 7)
        painter.setBrush(color)
        painter.drawEllipse(QPointF(9, 9), 3.6, 3.6)


class StatusPill(QFrame):
    def __init__(self, language="fa", parent=None):
        super().__init__(parent)
        self.setObjectName("statusPill")
        self.language = language
        self.state = "disconnected"
        layout = QHBoxLayout(self)
        layout.setContentsMargins(13, 8, 15, 8)
        layout.setSpacing(7)
        self.dot = PulseDot()
        self.label = QLabel()
        self.label.setObjectName("statusPillText")
        layout.addWidget(self.dot)
        layout.addWidget(self.label)
        self.set_state("disconnected")

    def set_language(self, language):
        self.language = language
        self.set_state(self.state)

    def set_state(self, state):
        self.state = state
        values = {
            "disconnected": ("وضعیت: قطع", "Status: Disconnected"),
            "connecting": ("وضعیت: در حال اتصال", "Status: Connecting"),
            "connected": ("وضعیت: متصل", "Status: Connected"),
            "error": ("وضعیت: خطا", "Status: Error"),
        }
        fa, en = values.get(state, values["disconnected"])
        self.label.setText(en if self.language == "en" else fa)
        self.dot.set_state(state)
        self.setProperty("state", state)
        _restyle(self)


class ActivityIndicator(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(28, 28)
        self.state = "idle"
        self.busy = False
        self._phase = 0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        if _animations_enabled(): self._timer.start(48)

    def _tick(self):
        if self.busy and MOTION_ENABLED:
            self._phase = (self._phase + 1) % 12
            self.update()

    def set_activity(self, state, busy):
        self.state, self.busy = state, busy
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        color = QColor({"error": "#ff5c7c", "warning": "#ffd166", "success": "#23f5a6"}.get(self.state, "#23f5e0"))
        if self.busy:
            for index in range(12):
                angle = math.radians(index * 30)
                alpha = 35 + ((index - self._phase) % 12) * 18
                segment = QColor(color); segment.setAlpha(min(235, alpha))
                painter.setPen(QPen(segment, 2.3, Qt.SolidLine, Qt.RoundCap))
                inner = QPointF(14 + math.cos(angle) * 7, 14 + math.sin(angle) * 7)
                outer = QPointF(14 + math.cos(angle) * 10, 14 + math.sin(angle) * 10)
                painter.drawLine(inner, outer)
            return
        painter.setPen(QPen(color, 2.2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        painter.setBrush(QColor(color.red(), color.green(), color.blue(), 18))
        painter.drawEllipse(QPointF(14, 14), 10, 10)
        if self.state == "error":
            painter.drawLine(10, 10, 18, 18); painter.drawLine(18, 10, 10, 18)
        elif self.state == "warning":
            painter.drawLine(14, 8, 14, 15); painter.drawPoint(14, 19)
        else:
            painter.drawLine(9, 14, 12.5, 17.5); painter.drawLine(12.5, 17.5, 19, 10)


class ActivityRail(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(3)
        self.busy = False
        self._phase = 0.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        if _animations_enabled():
            self._timer.start(35)

    def _tick(self):
        if self.busy:
            self._phase = (self._phase + .018) % 1.0
            self.update()

    def set_busy(self, busy):
        self.busy = busy
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), QColor(44, 199, 255, 16))
        if not self.busy:
            return
        start = max(0.0, self._phase - .18)
        end = min(1.0, self._phase + .18)
        gradient = QLinearGradient(0, 0, self.width(), 0)
        gradient.setColorAt(0, QColor(35, 245, 224, 0))
        gradient.setColorAt(start, QColor(35, 245, 224, 0))
        gradient.setColorAt(self._phase, QColor(35, 245, 224, 230))
        gradient.setColorAt(end, QColor(44, 199, 255, 0))
        gradient.setColorAt(1, QColor(44, 199, 255, 0))
        painter.fillRect(self.rect(), gradient)


class ActivityBar(QFrame):
    def __init__(self, language="fa", parent=None):
        super().__init__(parent)
        self.setObjectName("activityBar")
        self.language = language
        self.state = "idle"
        self.busy = False
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        content = QHBoxLayout()
        content.setContentsMargins(16, 10, 16, 10)
        content.setSpacing(12)
        self.indicator = ActivityIndicator()
        text_box = QVBoxLayout(); text_box.setSpacing(1)
        self.title = QLabel(); self.title.setObjectName("activityTitle")
        self.message = QLabel(); self.message.setObjectName("activityMessage")
        self.message.setTextInteractionFlags(Qt.TextSelectableByMouse)
        text_box.addWidget(self.title); text_box.addWidget(self.message)
        content.addWidget(self.indicator); content.addLayout(text_box, 1)
        root.addLayout(content)
        self.rail = ActivityRail(); root.addWidget(self.rail)
        self.set_language(language)
        self.set_activity("", "idle", False)

    def set_language(self, language):
        self.language = language
        self.title.setText("CURRENT ACTIVITY" if language == "en" else "فعالیت فعلی")
        if self.state == "idle":
            self.message.setText("Ready. No background task is running." if language == "en" else "آماده؛ هیچ عملیات پس‌زمینه‌ای در حال اجرا نیست.")

    def set_activity(self, message, state="running", busy=True):
        self.state, self.busy = state, busy
        if message:
            self.message.setText(message)
        elif state == "idle":
            self.set_language(self.language)
        self.indicator.set_activity(state, busy)
        self.rail.set_busy(busy)
        self.setProperty("state", state)
        _restyle(self)


class MiniSparkline(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.values: list[float] = []
        self.setMinimumHeight(24)
        self.setMaximumHeight(28)

    def add_value(self, value):
        try:
            self.values.append(float(value))
        except (TypeError, ValueError):
            return
        self.values = self.values[-28:]
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        baseline = self.height() - 5
        painter.setPen(QPen(QColor(44, 199, 255, 50), 1))
        painter.drawLine(0, baseline, self.width(), baseline)
        if len(self.values) < 2:
            return
        low, high = min(self.values), max(self.values)
        span = max(1.0, high - low)
        path = QPainterPath()
        for index, value in enumerate(self.values):
            x = index * self.width() / max(1, len(self.values) - 1)
            y = baseline - 3 - ((value - low) / span) * max(7, self.height() - 11)
            if index == 0: path.moveTo(x, y)
            else: path.lineTo(x, y)
        painter.setPen(QPen(QColor("#23f5e0"), 1.4))
        painter.drawPath(path)


class MetricCard(MotionFrame):
    def __init__(self, title, icon_name, value_widget=None, parent=None):
        super().__init__(parent)
        self.setObjectName("metricCard")
        self.setAttribute(Qt.WA_Hover, True)
        self.setMinimumHeight(154)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 15, 16, 14)
        layout.setSpacing(8)
        header = QHBoxLayout(); header.setSpacing(9)
        self.icon_label = QLabel(); self.icon_label.setObjectName("metricIcon")
        self.icon_label.setFixedSize(34, 34)
        self.icon_label.setPixmap(cyber_pixmap(icon_name, "#23f5e0", 19))
        self.title = QLabel(title); self.title.setObjectName("metricLabel")
        header.addWidget(self.icon_label); header.addWidget(self.title); header.addStretch()
        layout.addLayout(header)
        self.value = value_widget or QLabel("—")
        self.value.setObjectName("metricValue")
        layout.addWidget(self.value, 1)
        self.secondary = QLabel("")
        self.secondary.setObjectName("metricSecondary")
        self.secondary.setLayoutDirection(Qt.LeftToRight)
        self.secondary.setVisible(False)
        layout.addWidget(self.secondary)
        self.sparkline = MiniSparkline()
        self.sparkline.setVisible(False)
        layout.addWidget(self.sparkline)

    def set_secondary(self, text):
        self.secondary.setText(text)
        self.secondary.setVisible(bool(text))

    def enable_sparkline(self, enabled=True):
        self.sparkline.setVisible(enabled)


class EmptyListWidget(QListWidget):
    def __init__(self, icon_name="database", parent=None):
        super().__init__(parent)
        self.empty_icon = icon_name
        self.empty_title = "No items yet"
        self.empty_subtitle = "Use the actions above to add one."

    def set_empty_text(self, title, subtitle):
        self.empty_title, self.empty_subtitle = title, subtitle
        self.viewport().update()

    def paintEvent(self, event):
        super().paintEvent(event)
        if self.count():
            return
        painter = QPainter(self.viewport())
        painter.setRenderHint(QPainter.Antialiasing)
        area = self.viewport().rect()
        pix = cyber_pixmap(self.empty_icon, "#3a7690", 38)
        painter.drawPixmap(int(area.center().x() - pix.width() / 2), int(area.center().y() - 66), pix)
        painter.setPen(QColor("#d8e9f6"))
        font = painter.font(); font.setPointSize(12); font.setWeight(QFont.DemiBold); painter.setFont(font)
        painter.drawText(QRectF(24, area.center().y() - 14, area.width() - 48, 30), Qt.AlignCenter, self.empty_title)
        painter.setPen(QColor("#7993b3"))
        font.setPointSize(9); font.setWeight(QFont.Normal); painter.setFont(font)
        painter.drawText(QRectF(30, area.center().y() + 16, area.width() - 60, 44), Qt.AlignHCenter | Qt.AlignTop | Qt.TextWordWrap, self.empty_subtitle)


class NumericInput(QFrame):
    """Compact, intentional numeric control without native spinner chrome."""
    valueChanged = Signal(int)

    def __init__(self, value=0, minimum=0, maximum=9999, suffix="", parent=None):
        super().__init__(parent)
        self.setObjectName("numericInput")
        self.setMinimumHeight(36)
        self._minimum, self._maximum, self._suffix = minimum, maximum, suffix
        layout = QHBoxLayout(self); layout.setContentsMargins(4, 3, 4, 3); layout.setSpacing(3)
        self.minus = QPushButton("−"); self.minus.setObjectName("numericStep"); self.minus.setFixedSize(30, 30)
        self.edit = QLineEdit(); self.edit.setObjectName("numericEdit"); self.edit.setAlignment(Qt.AlignCenter)
        self.edit.setValidator(QIntValidator(minimum, maximum, self)); self.edit.setFixedHeight(30)
        self.suffix_label = QLabel(suffix); self.suffix_label.setObjectName("numericSuffix"); self.suffix_label.setVisible(bool(suffix))
        self.plus = QPushButton("+"); self.plus.setObjectName("numericStep"); self.plus.setFixedSize(30, 30)
        layout.addWidget(self.minus); layout.addWidget(self.edit, 1); layout.addWidget(self.suffix_label); layout.addWidget(self.plus)
        self.minus.clicked.connect(lambda: self.setValue(self.value() - 1)); self.plus.clicked.connect(lambda: self.setValue(self.value() + 1))
        self.edit.editingFinished.connect(self._commit); self.setValue(value); self.setLayoutDirection(Qt.LeftToRight)

    def _commit(self):
        self.setValue(self.value())

    def value(self):
        try: return int(self.edit.text())
        except ValueError: return self._minimum

    def setValue(self, value):
        clean = max(self._minimum, min(self._maximum, int(value)))
        changed = clean != self.value() if self.edit.text() else True
        self.edit.setText(str(clean))
        if changed: self.valueChanged.emit(clean)

    def setRange(self, minimum, maximum):
        self._minimum, self._maximum = int(minimum), int(maximum)
        self.edit.setValidator(QIntValidator(self._minimum, self._maximum, self)); self.setValue(self.value())

    def setSuffix(self, suffix):
        self._suffix = suffix; self.suffix_label.setText(suffix); self.suffix_label.setVisible(bool(suffix))

    def sizeHint(self): return QSize(170, 36)
    def minimumSizeHint(self): return QSize(116, 36)


class CyberProgressBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent); self._value = 0; self._maximum = 100; self._phase = 0
        self.setMinimumHeight(14)
        self.timer = QTimer(self); self.timer.timeout.connect(self._animate)
        if _animations_enabled(): self.timer.start(45)

    def _animate(self):
        if 0 < self._value < self._maximum:
            self._phase = (self._phase + 2) % 100; self.update()

    def setMaximum(self, value): self._maximum = max(1, int(value)); self.update()
    def setValue(self, value): self._value = max(0, min(int(value), self._maximum)); self.update()
    def value(self): return self._value

    def paintEvent(self, event):
        painter = QPainter(self); painter.setRenderHint(QPainter.Antialiasing)
        area = QRectF(0, 1, self.width(), self.height() - 2)
        painter.setPen(QPen(QColor("#23405f"), 1)); painter.setBrush(QColor("#071423")); painter.drawRoundedRect(area, 8, 8)
        ratio = self._value / self._maximum if self._maximum else 0
        if ratio > 0:
            fill = QRectF(1, 2, max(3, (self.width() - 2) * ratio), self.height() - 4)
            gradient = QLinearGradient(fill.left(), 0, fill.right(), 0)
            shimmer = self._phase / 100
            gradient.setColorAt(0, QColor("#0ea5a8")); gradient.setColorAt(max(0.05, shimmer - .12), QColor("#14b8a6"))
            gradient.setColorAt(min(.95, shimmer), QColor("#67e8f9")); gradient.setColorAt(min(1, shimmer + .16), QColor("#22d3ee")); gradient.setColorAt(1, QColor("#0891b2"))
            painter.setPen(Qt.NoPen); painter.setBrush(gradient); painter.drawRoundedRect(fill, 7, 7)


class ScanProgressPanel(QFrame):
    def __init__(self, language="fa", parent=None):
        super().__init__(parent); self.setObjectName("scanProgressPanel")
        self.language = language
        self.setMinimumHeight(72)
        root = QVBoxLayout(self); root.setContentsMargins(14, 7, 14, 7); root.setSpacing(5)
        top = QHBoxLayout(); self.status = QLabel(); self.status.setObjectName("scanStatus")
        self.percent = QLabel("0%"); self.percent.setObjectName("scanPercent"); self.percent.setLayoutDirection(Qt.LeftToRight)
        top.addWidget(self.status); top.addStretch(); top.addWidget(self.percent); root.addLayout(top)
        self.bar = CyberProgressBar(); root.addWidget(self.bar)
        self.domain = QLabel(); self.domain.setObjectName("scanDomain"); self.domain.setLayoutDirection(Qt.LeftToRight); self.domain.setAlignment(Qt.AlignLeft)
        root.addWidget(self.domain)
        self._maximum = 100
        self.set_language(language)

    def set_language(self, language):
        self.language = language
        self.status.setText("Scanner idle" if language == "en" else "اسکنر آماده است")
        self.domain.setText("Waiting for scan" if language == "en" else "در انتظار شروع اسکن")

    def setMaximum(self, value): self._maximum = max(1, int(value)); self.bar.setMaximum(self._maximum)
    def setValue(self, value):
        self.bar.setValue(value); self.percent.setText(f"{int(value / self._maximum * 100)}%")
    def setFormat(self, text):
        self.domain.setText(text); self.domain.setToolTip(text)
    def set_status(self, text, state="idle"):
        self.status.setText(text); self.status.setProperty("state", state); self.status.style().unpolish(self.status); self.status.style().polish(self.status)


def badge(text, kind="neutral"):
    label = QLabel(text); label.setObjectName("statusBadge"); label.setProperty("kind", kind)
    label.setAlignment(Qt.AlignCenter); label.setMinimumWidth(62); label.setFixedHeight(25); label.setLayoutDirection(Qt.LeftToRight)
    return label


class ConnectionOrb(QWidget):
    COLORS = {
        "disconnected": QColor("#5f7fa6"),
        "connecting": QColor("#ffd166"),
        "connected": QColor("#23f5e0"),
        "error": QColor("#ff5c7c"),
    }

    def __init__(self):
        super().__init__()
        self.state = "disconnected"
        self._phase = 0.0
        self._transition = 1.0
        self._from_color = QColor(self.COLORS["disconnected"])
        self._color_animation = QPropertyAnimation(self, b"transitionProgress", self)
        self._color_animation.setDuration(480)
        self._color_animation.setEasingCurve(QEasingCurve.InOutCubic)
        self.setFixedSize(224, 224)
        self.setAccessibleName("Connection security core")
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        if _animations_enabled():
            self._timer.start(20)

    def _get_transition(self):
        return self._transition

    def _set_transition(self, value):
        self._transition = max(0.0, min(1.0, float(value)))
        self.update()

    transitionProgress = Property(float, _get_transition, _set_transition)

    def _current_color(self):
        target = self.COLORS.get(self.state, self.COLORS["disconnected"])
        mix = self._transition
        return QColor(
            round(self._from_color.red() + (target.red() - self._from_color.red()) * mix),
            round(self._from_color.green() + (target.green() - self._from_color.green()) * mix),
            round(self._from_color.blue() + (target.blue() - self._from_color.blue()) * mix),
        )

    @property
    def connected(self):
        return self.state == "connected"

    @connected.setter
    def connected(self, value):
        self.set_state("connected" if value else "disconnected")

    def set_state(self, state):
        if state == self.state:
            self.update()
            return
        self._from_color = self._current_color()
        self.state = state
        if not _animations_enabled():
            self._set_transition(1.0)
            return
        self._color_animation.stop()
        self._color_animation.setStartValue(0.0)
        self._color_animation.setEndValue(1.0)
        self._color_animation.start()

    def _tick(self):
        speed = {
            "connecting": .047,
            "connected": .014,
            "disconnected": .0065,
            "error": .009,
        }.get(self.state, .0065)
        self._phase = (self._phase + speed) % (math.pi * 2)
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        center = QPointF(self.width() / 2, self.height() / 2)
        color = self._current_color()
        pulse = .5 + .5 * math.sin(self._phase * 1.72) if MOTION_ENABLED else .55

        aura = QRadialGradient(center, 108)
        aura.setColorAt(0, QColor(color.red(), color.green(), color.blue(), 35 + int(pulse * 16)))
        aura.setColorAt(.52, QColor(color.red(), color.green(), color.blue(), 10))
        aura.setColorAt(1, QColor(color.red(), color.green(), color.blue(), 0))
        p.setPen(Qt.NoPen); p.setBrush(aura); p.drawEllipse(center, 108, 108)

        core_glow = QRadialGradient(center, 64)
        core_glow.setColorAt(0, QColor(225, 255, 252, 12 + int(pulse * 13)))
        core_glow.setColorAt(.6, QColor(color.red(), color.green(), color.blue(), 16))
        core_glow.setColorAt(1, QColor(5, 18, 35, 0))
        p.setPen(Qt.NoPen); p.setBrush(core_glow); p.drawEllipse(center, 65, 65)

        for radius, alpha, width in ((103, 30, 1), (94, 55, 1.2), (80, 110, 1.7), (67, 62, 1)):
            ring = QColor(color); ring.setAlpha(alpha)
            p.setBrush(Qt.NoBrush); p.setPen(QPen(ring, width)); p.drawEllipse(center, radius, radius)

        rotation = math.degrees(self._phase)
        p.setPen(QPen(QColor(color.red(), color.green(), color.blue(), 205), 2.0, Qt.SolidLine, Qt.RoundCap))
        p.drawArc(QRectF(center.x() - 94, center.y() - 94, 188, 188), int((24 + rotation) * 16), 74 * 16)
        p.drawArc(QRectF(center.x() - 80, center.y() - 80, 160, 160), int((202 - rotation * .7) * 16), 66 * 16)
        p.setPen(QPen(QColor(color.red(), color.green(), color.blue(), 92), 1.0, Qt.DashLine, Qt.RoundCap))
        p.drawArc(QRectF(center.x() - 103, center.y() - 103, 206, 206), int((126 - rotation * .34) * 16), 132 * 16)
        p.drawArc(QRectF(center.x() - 68, center.y() - 68, 136, 136), int((38 + rotation * .52) * 16), 94 * 16)
        if self.state == "connecting":
            p.setPen(QPen(QColor(255, 209, 102, 220), 3, Qt.SolidLine, Qt.RoundCap))
            p.drawArc(QRectF(center.x() - 70, center.y() - 70, 140, 140), int(rotation * 2.2 * 16), 44 * 16)

        p.setPen(Qt.NoPen)
        for index, radius in enumerate((95, 80, 70, 102, 88)):
            angle = self._phase * (1.0 + index * .08) + index * 1.31
            point = QPointF(center.x() + math.cos(angle) * radius, center.y() + math.sin(angle) * radius)
            dot = QColor(color); dot.setAlpha(120 + (index % 2) * 75)
            p.setBrush(dot); p.drawEllipse(point, 1.8 + (index % 2), 1.8 + (index % 2))

            # Short fading packet trail makes the orbital motion easy to read.
            for trail_index in range(1, 4):
                trail_angle = angle - trail_index * (.035 + index * .003)
                trail_point = QPointF(center.x() + math.cos(trail_angle) * radius, center.y() + math.sin(trail_angle) * radius)
                trail = QColor(color); trail.setAlpha(max(12, 70 - trail_index * 18))
                p.setBrush(trail); p.drawEllipse(trail_point, 1.2, 1.2)

        shield = QPainterPath()
        shield.moveTo(center.x(), center.y() - 54)
        shield.cubicTo(center.x() + 26, center.y() - 46, center.x() + 42, center.y() - 37, center.x() + 45, center.y() - 32)
        shield.lineTo(center.x() + 40, center.y() + 13)
        shield.cubicTo(center.x() + 35, center.y() + 35, center.x() + 14, center.y() + 49, center.x(), center.y() + 55)
        shield.cubicTo(center.x() - 14, center.y() + 49, center.x() - 35, center.y() + 35, center.x() - 40, center.y() + 13)
        shield.lineTo(center.x() - 45, center.y() - 32)
        shield.cubicTo(center.x() - 42, center.y() - 37, center.x() - 26, center.y() - 46, center.x(), center.y() - 54)
        shield.closeSubpath()
        shield_fill = QLinearGradient(center.x(), center.y() - 55, center.x(), center.y() + 56)
        shield_fill.setColorAt(0, QColor(color.red(), color.green(), color.blue(), 62))
        shield_fill.setColorAt(1, QColor(5, 18, 35, 210))
        p.setBrush(shield_fill)
        p.setPen(QPen(QColor(color.red(), color.green(), color.blue(), 210), 1.5))
        p.drawPath(shield)
        inner = shield.translated(0, 2)
        p.setBrush(Qt.NoBrush); p.setPen(QPen(QColor(color.red(), color.green(), color.blue(), 65), 1)); p.drawPath(inner)

        lock_color = QColor("#dffcff" if self.state != "error" else "#ffe5eb")
        p.setPen(QPen(lock_color, 5.5, Qt.SolidLine, Qt.RoundCap))
        p.setBrush(Qt.NoBrush)
        p.drawArc(QRectF(center.x() - 15, center.y() - 20, 30, 30), 0, 180 * 16)
        p.setPen(Qt.NoPen); p.setBrush(lock_color)
        p.drawRoundedRect(QRectF(center.x() - 20, center.y() - 6, 40, 31), 8, 8)
        p.setBrush(QColor("#082037")); p.drawEllipse(QPointF(center.x(), center.y() + 7), 3.6, 3.6)
        p.drawRoundedRect(QRectF(center.x() - 1.8, center.y() + 7, 3.6, 9), 1.8, 1.8)


def card() -> QFrame:
    frame = QFrame(); frame.setObjectName("card")
    return frame


def title_label(title: str, subtitle: str = "") -> QWidget:
    box = QWidget(); layout = QVBoxLayout(box); layout.setContentsMargins(0, 0, 0, 10)
    title_widget = QLabel(title); title_widget.setObjectName("pageTitle"); layout.addWidget(title_widget)
    if subtitle:
        sub = QLabel(subtitle); sub.setObjectName("muted"); sub.setWordWrap(True); layout.addWidget(sub)
    return box


class ProfileDialog(QDialog):
    def __init__(self, parent, profile: ProxyProfile | None = None, language: str = "fa"):
        super().__init__(parent); self.setObjectName("profileDialog"); self._animated = False; t = lambda fa, en: en if language == "en" else fa; self.setWindowTitle(t("ویرایش کانفیگ", "Edit Config") if profile else t("افزودن کانفیگ", "Add Config")); self.resize(700, 680); self.setMinimumSize(620, 580)
        self.setAccessibleName("Edit proxy configuration" if profile else "Add proxy configuration")
        self.setLayoutDirection(Qt.LeftToRight if language == "en" else Qt.RightToLeft)
        self.profile = profile
        layout = QVBoxLayout(self); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(0)
        header = QFrame(); header.setObjectName("modalHeader"); header_layout = QHBoxLayout(header); header_layout.setContentsMargins(26, 21, 26, 19); header_layout.setSpacing(14)
        header_icon = QLabel(); header_icon.setObjectName("modalIcon"); header_icon.setFixedSize(46, 46); header_icon.setPixmap(cyber_pixmap("file-cog", "#23f5e0", 25)); header_layout.addWidget(header_icon)
        header_copy = QVBoxLayout(); header_copy.setSpacing(4); heading = QLabel(t("ویرایش کانفیگ", "Edit Config") if profile else t("افزودن کانفیگ", "Add Config")); heading.setObjectName("modalTitle"); subtitle = QLabel(t("مشخصات مسیر و لینک اتصال را با دقت بررسی کنید.", "Review the connection URI and route details.")); subtitle.setObjectName("modalSubtitle"); subtitle.setWordWrap(True); header_copy.addWidget(heading); header_copy.addWidget(subtitle); header_layout.addLayout(header_copy, 1); layout.addWidget(header)

        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QFrame.NoFrame); scroll.setObjectName("modalScroll")
        body = QWidget(); body_layout = QVBoxLayout(body); body_layout.setContentsMargins(24, 20, 24, 20); body_layout.setSpacing(14)
        self.name = QLineEdit(profile.name if profile else "")
        self.name.setPlaceholderText(t("نام قابل تشخیص برای این مسیر", "A recognizable name for this route"))
        self.uri = QTextEdit(profile.source_uri if profile else ""); self.uri.setObjectName("configEditor"); self.uri.setMinimumHeight(112); self.uri.setPlaceholderText("vless://…  or  trojan://…")
        self.address = QLineEdit(profile.address if profile else "104.18.8.83")
        self.fallback = QLineEdit(profile.fallback_address if profile else "104.18.9.83")
        self.port = NumericInput(profile.port if profile else 443, 1, 65535)
        self.sni = QLineEdit(profile.sni if profile else "www.speedtest.net")
        self.method = QComboBox(); self.method.addItems(["combined", "fragment", "half", "multi", "sni_split"])
        self.method.setCurrentText(profile.method if profile else "combined")
        for technical in (self.uri, self.address, self.fallback, self.port, self.sni, self.method): technical.setLayoutDirection(Qt.LeftToRight)
        self.validation = QLabel(t("یک لینک معتبر VLESS یا Trojan وارد کنید.", "Enter a valid VLESS or Trojan URI.")); self.validation.setObjectName("validationError"); self.validation.setVisible(False)

        identity = self._section(t("هویت و لینک", "Identity & URI"), t("نام نمایشی و لینک اصلی کانفیگ", "Display name and original config URI"), [(t("نام", "Name"), self.name), (t("لینک VLESS / Trojan", "VLESS / Trojan URI"), self.uri)])
        identity.layout().addWidget(self.validation)
        route = self._section(t("مسیر اتصال", "Connection Route"), t("مقادیر فنی برای Edge، SNI و روش انتقال", "Technical edge, SNI and transport values"), [(t("IP اصلی", "Primary IP"), self.address), (t("IP جایگزین", "Fallback IP"), self.fallback), (t("پورت", "Port"), self.port), (t("SNI جعلی", "Fake SNI"), self.sni), (t("روش", "Method"), self.method)])
        body_layout.addWidget(identity); body_layout.addWidget(route); body_layout.addStretch(); scroll.setWidget(body); layout.addWidget(scroll, 1)

        footer = QFrame(); footer.setObjectName("modalFooter"); footer_layout = QHBoxLayout(footer); footer_layout.setContentsMargins(24, 15, 24, 18); footer_layout.addStretch()
        cancel = QPushButton(t("لغو", "Cancel")); cancel.setObjectName("modalSecondary"); cancel.setIcon(cyber_icon("x-circle", "#b7cce0", 18)); cancel.clicked.connect(self.reject)
        save = QPushButton(t("ذخیره کانفیگ", "Save Config")); save.setObjectName("modalPrimary"); save.setIcon(cyber_icon("check-circle", "#031422", 18)); save.setDefault(True); save.clicked.connect(self._validate_accept)
        footer_layout.addWidget(cancel); footer_layout.addWidget(save); layout.addWidget(footer)
        self.uri.textChanged.connect(self._clear_validation)

    def _section(self, title_text, subtitle_text, rows):
        frame = QFrame(); frame.setObjectName("settingsSection"); section = QVBoxLayout(frame); section.setContentsMargins(18, 16, 18, 17); section.setSpacing(11)
        title = QLabel(title_text); title.setObjectName("settingsTitle"); subtitle = QLabel(subtitle_text); subtitle.setObjectName("settingsSubtitle"); subtitle.setWordWrap(True); section.addWidget(title); section.addWidget(subtitle)
        form = QGridLayout(); form.setHorizontalSpacing(18); form.setVerticalSpacing(11); form.setColumnMinimumWidth(0, 170); form.setColumnStretch(1, 1)
        for row, (label_text, widget) in enumerate(rows):
            label = QLabel(label_text); label.setObjectName("fieldLabel"); label.setWordWrap(False); label.setMinimumWidth(145); form.addWidget(label, row, 0, Qt.AlignVCenter); form.addWidget(widget, row, 1)
        section.addLayout(form); return frame

    def _clear_validation(self):
        self.validation.setVisible(False); self.uri.setProperty("invalid", False); _restyle(self.uri)

    def _validate_accept(self):
        if not parse_many(self.uri.toPlainText()):
            self.validation.setVisible(True); self.uri.setProperty("invalid", True); _restyle(self.uri); self.uri.setFocus(); return
        self.accept()

    def showEvent(self, event):
        super().showEvent(event)
        if self._animated or not _animations_enabled(): return
        self._animated = True; self.setWindowOpacity(0.0); animation = QPropertyAnimation(self, b"windowOpacity", self); animation.setDuration(220); animation.setStartValue(0.0); animation.setEndValue(1.0); animation.setEasingCurve(QEasingCurve.OutCubic); self._show_animation = animation; animation.start()

    def result_profile(self) -> ProxyProfile | None:
        parsed = parse_many(self.uri.toPlainText())
        if not parsed:
            return None
        out = self.profile or parsed[0]
        source = parsed[0]
        out.name = self.name.text().strip() or source.name
        out.source_uri = source.source_uri; out.protocol = source.protocol
        out.config_host = source.config_host; out.config_port = source.config_port
        out.address = self.address.text().strip(); out.fallback_address = self.fallback.text().strip()
        out.port = self.port.value(); out.sni = self.sni.text().strip(); out.method = self.method.currentText(); out.origin = "user"
        return out


class TuningDialog(QDialog):
    def __init__(self, parent, tuning: Tuning, language: str = "fa",
                 update_repo_url: str = DEFAULT_UPDATE_REPO_URL,
                 carrier_tunings: dict[str, Tuning] | None = None):
        super().__init__(parent); self.language = language; self.t = lambda fa, en: en if language == "en" else fa; self._animated = False
        self._loading_tuning = False
        self._active_carrier = tuning.carrier_mode if tuning.carrier_mode in {"auto", "mci", "irancell"} else "auto"
        self._carrier_drafts = {
            carrier: Tuning.from_dict(value.to_dict())
            for carrier, value in (carrier_tunings or {self._active_carrier: tuning}).items()
            if carrier in {"auto", "mci", "irancell"} and isinstance(value, Tuning)
        }
        for carrier in ("auto", "mci", "irancell"):
            self._carrier_drafts.setdefault(carrier, Tuning.carrier_preset(carrier))
        self.setObjectName("advancedDialog"); self.setWindowTitle(self.t("تنظیمات پیشرفته", "Advanced Settings")); self.resize(790, 760); self.setMinimumSize(720, 640); self.tuning = tuning
        self.setAccessibleName("Advanced Settings")
        self.setLayoutDirection(Qt.LeftToRight if language == "en" else Qt.RightToLeft)
        root = QVBoxLayout(self); root.setContentsMargins(0, 0, 0, 0); root.setSpacing(0)
        header = QFrame(); header.setObjectName("modalHeader"); hl = QHBoxLayout(header); hl.setContentsMargins(28, 21, 28, 19); hl.setSpacing(14)
        header_icon = QLabel(); header_icon.setObjectName("modalIcon"); header_icon.setFixedSize(46, 46); header_icon.setPixmap(cyber_pixmap("sliders", "#23f5e0", 25)); hl.addWidget(header_icon)
        header_copy = QVBoxLayout(); header_copy.setSpacing(4)
        title = QLabel(self.t("تنظیمات پیشرفته", "Advanced Settings")); title.setObjectName("modalTitle")
        subtitle = QLabel(self.t(
            f"سرعت بارگذاری، هسته {ltr_isolate('Patterniha')} و مسیر اتصال را با مقادیر واقعی تنظیم کنید.",
            "Tune page-start latency, streaming throughput and the Patterniha route.")); subtitle.setObjectName("modalSubtitle"); subtitle.setWordWrap(True)
        header_copy.addWidget(title); header_copy.addWidget(subtitle); hl.addLayout(header_copy, 1); root.addWidget(header)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QFrame.NoFrame); scroll.setObjectName("modalScroll")
        body = QWidget(); body_layout = QVBoxLayout(body); body_layout.setContentsMargins(24, 20, 24, 20); body_layout.setSpacing(14)

        self.preset = QComboBox(); self.preset.addItems(["maximum", "balanced", "fast", "streaming", "stealth", "compatibility", "custom"]); self.preset.setCurrentText(tuning.mode if tuning.mode in [self.preset.itemText(i) for i in range(self.preset.count())] else "custom")
        self.carrier = QComboBox(); self.carrier.addItems(["auto", "mci", "irancell"]); self.carrier.setCurrentText(tuning.carrier_mode)
        body_layout.addWidget(self._section(
            self.t("پروفایل سرعت", "Performance profile"),
            self.t("Maximum برای شروع سریع؛ Streaming برای ویدئوی طولانی متعادل شده است.", "Maximum favors page start; Streaming balances long video transfers."),
            [(self.t("پروفایل", "Preset"), self.preset,
              self.t("یک مجموعه امن از مقادیر زیر را اعمال می‌کند. Custom تنظیمات دستی را نگه می‌دارد.", "Applies a safe group of the controls below. Custom preserves manual values.")),
             (self.t("اپراتور", "Carrier"), self.carrier,
              self.t("مسیر و نتیجه‌های ذخیره‌شده را برای اپراتور فعلی اولویت‌بندی می‌کند.", "Prioritizes cached routes and measurements for the selected carrier."))],
            self.t("این بخش فقط Preset و اپراتور را انتخاب می‌کند؛ تمام مقادیر قابل بازبینی هستند.", "Choose a starting preset and carrier; every resulting value remains visible and editable.")))

        self.mux_enabled = ToggleSwitch(); self.mux_enabled.setChecked(bool(getattr(tuning, "xray_mux_enabled", True)))
        self.mux_concurrency = NumericInput(getattr(tuning, "xray_mux_concurrency", 8), 1, 32)
        self.background_probe = ToggleSwitch(); self.background_probe.setChecked(bool(getattr(tuning, "background_quality_probe_enabled", False)))
        self.probe_delay = NumericInput(getattr(tuning, "background_quality_probe_delay_s", 30), 10, 300, "s")
        self.log_level = QComboBox(); self.log_level.addItems(["minimal", "normal"]); self.log_level.setCurrentText(tuning.log_level)
        body_layout.addWidget(self._section(
            self.t(f"شتاب‌دهی {ltr_isolate('Xray')}", "Xray acceleration"),
            self.t("اتصال‌های مرورگر را تجمیع می‌کند تا تعداد Handshakeهای گران کاهش یابد.", "Reduce expensive tunnel handshakes by sharing browser streams."),
            [(self.t(f"فعال‌سازی {ltr_isolate('Mux')}", "Enable Mux"), self.mux_enabled,
              self.t("شروع صفحات را سریع‌تر می‌کند. اگر سرور ناسازگار باشد تست اتصال آن را تشخیص می‌دهد.", "Usually improves page start. The real connectivity probe detects incompatible servers.")),
             (self.t("جریان در هر تونل", "Streams per tunnel"), self.mux_concurrency,
              self.t("عدد بیشتر Handshake را کم می‌کند؛ عدد بسیار زیاد ممکن است روی ویدئو Head-of-line ایجاد کند.", "Higher values reduce handshakes; excessive values can add head-of-line blocking to video.")),
             (self.t("تست کیفیت پس‌زمینه", "Background quality probe"), self.background_probe,
              self.t("یک Echo کوچک برای رتبه‌بندی آپلود اجرا می‌کند. برای بیشترین سرعت اولیه خاموش بماند.", "Runs a small upload echo for diagnostics. Keep it off for maximum initial responsiveness.")),
             (self.t("تاخیر تست پس‌زمینه", "Probe delay"), self.probe_delay,
              self.t("اگر تست فعال باشد، آن را تا بعد از بارگذاری اولیه کاربر عقب می‌اندازد.", "When enabled, postpones the probe until after the user's initial page load.")),
             (self.t("جزئیات لاگ", "Log detail"), self.log_level,
              self.t("Minimal هشدارهای تکراری قطع اتصال مرورگر را حذف می‌کند اما خطاهای اصلی حفظ می‌شوند.", "Minimal suppresses repeated browser-abort noise while preserving startup and route errors."))],
            self.t("برای ایرانسل، Mux با ۴ تا ۸ جریان معمولاً شروع چند اتصال هم‌زمان مرورگر را سبک‌تر می‌کند.", "Mux with 4–8 streams usually reduces the initial Chrome connection burst.")))

        self.core_preset = QComboBox(); self.core_preset.addItems(["maximum", "streaming", "upload", "balanced", "low_latency", "compatibility"]); self.core_preset.setCurrentText(tuning.pattern_quality_preset if tuning.pattern_quality_preset in [self.core_preset.itemText(i) for i in range(self.core_preset.count())] else "balanced")
        self.connect_ip = QLineEdit(tuning.pattern_connect_ip); self.connect_ip.setProperty("technical", True); self.connect_ip.setPlaceholderText("104.18.32.47")
        self.fallback_ips = QLineEdit(tuning.pattern_fallback_ips); self.fallback_ips.setProperty("technical", True); self.fallback_ips.setPlaceholderText("188.114.99.0,104.18.8.83")
        self.profile_edges = QCheckBox(self.t("اولویت با IPهای داخل پروفایل", "Prefer IPs stored in each profile")); self.profile_edges.setChecked(tuning.pattern_use_profile_edges)
        self.fake_sni = QLineEdit(tuning.pattern_fake_sni); self.fake_sni.setProperty("technical", True); self.fake_sni.setPlaceholderText("chatgpt.com")
        body_layout.addWidget(self._section(
            self.t(f"هسته {ltr_isolate('Patterniha')}", "Patterniha core"),
            self.t(f"تزریق {ltr_isolate('Wrong-Sequence')}؛ داده‌ی فایل در مسیر سریع Kernel باقی می‌ماند.", "Wrong-sequence injection while file payload stays in the kernel fast path."),
            [(self.t("حالت کیفیت", "Quality preset"), self.core_preset,
              self.t("مقادیر Handshake، Buffer و Keepalive را با هم تنظیم می‌کند.", "Sets handshake, buffer and keepalive values as one tested group.")),
             (self.t(f"{ltr_isolate('IP')} اصلی {ltr_isolate('Edge')}", "Primary edge IP"), self.connect_ip,
              self.t("مقصد TCP مستقل از SNI است؛ فقط Edgeای را وارد کنید که برای همین اپراتور همراه با SNI تست شده باشد.", "The TCP destination is independent from SNI; use only an edge tested with that SNI on this carrier.")),
             (self.t(f"{ltr_isolate('IP')}های جایگزین", "Fallback edge IPs"), self.fallback_ips,
              self.t("فقط بعد از شکست Edge اصلی امتحان می‌شوند؛ فهرست بلند زمان شکست را افزایش می‌دهد.", "Tried only after the primary edge fails; long lists increase worst-case failover time.")),
             (self.t(f"{ltr_isolate('SNI')} جعلی", "Fake SNI"), self.fake_sni,
              self.t("نام TLS/Host است و لازم نیست IP آن با Edge یکی باشد. SNI Lab زوج دقیق Edge + SNI را آزمایش می‌کند.", "This is the TLS/Host name and its DNS IP need not equal the edge. SNI Lab tests the exact edge + SNI pair.")),
             (self.t("مسیرهای پروفایل", "Profile edges"), self.profile_edges,
              self.t("IPهای داخل کانفیگ را قبل از Edgeهای عمومی امتحان می‌کند؛ فقط برای پروفایل‌های مطمئن فعال کنید.", "Tries profile IPs before global edges; enable only for trusted profiles."))],
            self.t("SNI خوب باید با تست واقعی صفحه تأیید شود؛ Ping تنها معیار انتخاب نیست.", "A good SNI must pass real page traffic; ping alone is not used as proof.")))

        self.inject_delay = NumericInput(tuning.pattern_inject_delay_ms, 0, 20, "ms")
        self.ack_timeout = NumericInput(tuning.pattern_ack_timeout_ms, 500, 10000, "ms")
        self.connect_timeout = NumericInput(tuning.pattern_connect_timeout_ms, 500, 10000, "ms")
        self.edge_cooldown = NumericInput(getattr(tuning, "pattern_edge_failure_cooldown_s", 8), 1, 120, "s")
        body_layout.addWidget(self._section(
            self.t(f"کیفیت {ltr_isolate('Handshake')}", "Handshake quality"),
            self.t("زمان ایجاد مسیر و سرعت عبور به Edge جایگزین را کنترل می‌کند.", "Controls route establishment and bounded edge failover."),
            [(self.t("تاخیر تزریق", "Injection delay"), self.inject_delay,
              self.t("صفر یا یک میلی‌ثانیه سریع است؛ افزایش آن فقط برای سازگاری شبکه لازم است.", "Zero or one millisecond is fastest; raise it only for network compatibility.")),
             (self.t(f"مهلت {ltr_isolate('Fake ACK')}", "Fake ACK timeout"), self.ack_timeout,
              self.t("کمتر یعنی شکست سریع‌تر؛ مقدار خیلی کم Edge سالم اما کند را حذف می‌کند.", "Lower fails over faster; too low rejects a healthy but temporarily slow edge.")),
             (self.t(f"مهلت اتصال {ltr_isolate('Edge')}", "Edge connect timeout"), self.connect_timeout,
              self.t("حداکثر انتظار برای TCP Edge پیش از رفتن به جایگزین بعدی.", "Maximum TCP edge wait before trying the next fallback.")),
             (self.t("وقفه Edge شکست‌خورده", "Failed-edge cooldown"), self.edge_cooldown,
              self.t("Edge خراب تا این مدت دوباره امتحان نمی‌شود و از Timeoutهای پیاپی جلوگیری می‌کند.", "Skips a failed edge for this period to prevent repeated timeouts."))],
            self.t("Timeout کمتر اتصال ناموفق را سریع جمع می‌کند؛ ولی روی شبکه ناپایدار بیش از حد کم نکنید.", "Shorter timeouts end bad routes sooner, but should not be too aggressive on unstable links.")))

        self.relay_buffer = NumericInput(tuning.pattern_relay_buffer_kb, 32, 1024, "KiB")
        self.socket_buffer = NumericInput(tuning.pattern_socket_buffer_kb, 64, 8192, "KiB")
        self.max_sessions = NumericInput(tuning.pattern_max_sessions, 2, 64)
        self.keepalive = NumericInput(tuning.pattern_keepalive_idle_s, 5, 120, "s")
        self.keepalive_interval = NumericInput(getattr(tuning, "pattern_keepalive_interval_s", 3), 1, 30, "s")
        self.keepalive_count = NumericInput(getattr(tuning, "pattern_keepalive_count", 3), 1, 10)
        self.upload_optimized = ToggleSwitch(); self.upload_optimized.setChecked(tuning.pattern_upload_optimized)
        body_layout.addWidget(self._section(
            self.t("توان عبوری و ویدئو", "Throughput & video"),
            self.t("Buffer، Relay و Handshakeهای موازی را بدون ایجاد Connection Storm محدود می‌کند.", "Bounds buffers, relay chunks and parallel handshakes without a connection storm."),
            [(self.t("اندازه Relay", "Relay chunk"), self.relay_buffer,
              self.t("Chunk بزرگ‌تر برای فایل و ویدئو مناسب است؛ بسیار بزرگ حافظه بیشتری مصرف می‌کند.", "Larger chunks favor files and video; excessive values consume more memory.")),
             (self.t(f"بافر {ltr_isolate('Socket')}", "Socket buffer"), self.socket_buffer,
              self.t("فضای Kernel برای Upload/Download؛ ۱ تا ۴ MiB برای اتصال سریع مناسب است.", "Kernel send/receive space; 1–4 MiB is a practical high-throughput range.")),
             (self.t(f"{ltr_isolate('Handshake')}های هم‌زمان", "Pending handshakes"), self.max_sessions,
              self.t("بالاتر شروع چند منبع صفحه را سریع می‌کند؛ برای محافظت از NAT مودم از ۱۲ تا ۱۶ بیشتر نکنید.", "Higher starts more page resources together; keep around 12–16 to protect modem NAT.")),
             (self.t(f"شروع {ltr_isolate('Keepalive')}", "Keepalive idle"), self.keepalive,
              self.t("پس از این زمان بیکاری بررسی زنده‌بودن TCP شروع می‌شود.", "Starts TCP liveness checks after this idle period.")),
             (self.t(f"فاصله {ltr_isolate('Keepalive')}", "Keepalive interval"), self.keepalive_interval,
              self.t("فاصله بین بررسی‌های Keepalive پس از بیکارشدن اتصال.", "Delay between keepalive probes after the connection becomes idle.")),
             (self.t(f"تعداد {ltr_isolate('Keepalive')}", "Keepalive retries"), self.keepalive_count,
              self.t("بعد از این تعداد پاسخ نگرفتن، اتصال خراب سریع‌تر آزاد می‌شود.", "Releases a dead connection after this many unanswered probes.")),
             (self.t("بهینه‌سازی جریان", "Stream optimization"), self.upload_optimized,
              self.t("TCP_NODELAY و بافرهای انتخاب‌شده را برای پاسخ سریع و جریان دوطرفه فعال می‌کند.", "Uses TCP_NODELAY and the selected buffers for responsive full-duplex traffic."))],
            self.t("برای ویدئو، Buffer کافی و تعداد Handshake متوسط از مقدارهای افراطی پایدارتر است.", "For video, adequate buffers and moderate handshake concurrency are more stable than extreme values.")))

        self.update_repo = QLineEdit(update_repo_url or DEFAULT_UPDATE_REPO_URL); self.update_repo.setProperty("technical", True); self.update_repo.setPlaceholderText("https://github.com/owner/repository")
        body_layout.addWidget(self._section(
            self.t("بررسی بروزرسانی", "Update checker"),
            self.t("نسخه نصب‌شده را با آخرین Release مخزن GitHub مقایسه می‌کند.", "Compares the installed version with the latest GitHub release."),
            [(self.t("مخزن بروزرسانی", "Update repository"), self.update_repo,
              self.t("لینک مخزن GitHub شما؛ فقط ریشه مخزن مانند https://github.com/owner/repo.", "Your GitHub repository root, for example https://github.com/owner/repo."))],
            self.t("برنامه فقط اطلاعات Release را در پس‌زمینه می‌خواند و دانلود با کلیک کاربر باز می‌شود.", "Release metadata is checked in the background; download opens only after the user clicks.")))
        body_layout.addStretch(); scroll.setWidget(body); root.addWidget(scroll, 1)

        footer = QFrame(); footer.setObjectName("modalFooter"); fl = QHBoxLayout(footer); fl.setContentsMargins(24, 16, 24, 18)
        reset = QPushButton(self.t("بازنشانی پیشنهادی", "Reset Recommended")); reset.setObjectName("modalSecondary"); reset.setIcon(cyber_icon("refresh", "#b7cce0", 18)); reset.clicked.connect(self._apply_recommended); fl.addWidget(reset)
        fl.addStretch(); cancel = QPushButton(self.t("لغو", "Cancel")); cancel.setObjectName("modalSecondary"); cancel.setIcon(cyber_icon("x-circle", "#b7cce0", 18)); cancel.clicked.connect(self.reject)
        save = QPushButton(self.t("ذخیره تنظیمات", "Save Settings")); save.setObjectName("modalPrimary"); save.setIcon(cyber_icon("check-circle", "#031422", 18)); save.setDefault(True); save.clicked.connect(self.accept)
        fl.addWidget(cancel); fl.addWidget(save); root.addWidget(footer)
        self.preset.currentTextChanged.connect(self._apply_preset)
        self.core_preset.currentTextChanged.connect(self._apply_core_preset)
        self.carrier.currentTextChanged.connect(self._switch_carrier_profile)

    def _section(self, title_text, subtitle_text, rows, section_help=""):
        frame = QFrame(); frame.setObjectName("settingsSection"); layout = QVBoxLayout(frame); layout.setContentsMargins(18, 16, 18, 17); layout.setSpacing(12)
        heading = QHBoxLayout(); title = QLabel(title_text); title.setObjectName("settingsTitle"); heading.addWidget(title); heading.addStretch()
        if section_help: heading.addWidget(HelpDot(section_help, self.language == "fa"))
        subtitle = QLabel(subtitle_text); subtitle.setObjectName("settingsSubtitle"); subtitle.setWordWrap(True)
        layout.addLayout(heading); layout.addWidget(subtitle)
        grid = QGridLayout(); grid.setHorizontalSpacing(18); grid.setVerticalSpacing(12); grid.setColumnMinimumWidth(0, 185); grid.setColumnStretch(1, 1)
        for row, row_data in enumerate(rows):
            label_text, widget = row_data[:2]; row_help = row_data[2] if len(row_data) > 2 else ""
            label_box = QWidget(); label_layout = QHBoxLayout(label_box); label_layout.setContentsMargins(0, 0, 0, 0); label_layout.setSpacing(7)
            label = QLabel(label_text); label.setObjectName("fieldLabel"); label.setWordWrap(False); label.setMinimumWidth(145)
            label.setAlignment((Qt.AlignRight if self.language == "fa" else Qt.AlignLeft) | Qt.AlignVCenter)
            label_layout.addWidget(label, 1)
            if row_help: label_layout.addWidget(HelpDot(row_help, self.language == "fa"))
            grid.addWidget(label_box, row, 0, Qt.AlignVCenter); grid.addWidget(widget, row, 1)
            if isinstance(widget, (QComboBox, NumericInput, QLineEdit)): widget.setLayoutDirection(Qt.LeftToRight)
        layout.addLayout(grid); return frame

    def showEvent(self, event):
        super().showEvent(event)
        if self._animated or not _animations_enabled(): return
        self._animated = True; self.setWindowOpacity(0.0); animation = QPropertyAnimation(self, b"windowOpacity", self); animation.setDuration(220); animation.setStartValue(0.0); animation.setEndValue(1.0); animation.setEasingCurve(QEasingCurve.OutCubic); self._show_animation = animation; animation.start()

    def _apply_preset(self, mode):
        if self._loading_tuning or mode == "custom": return
        # Speed presets must not overwrite the user's proven carrier/edge/SNI.
        route = (self.carrier.currentText(), self.connect_ip.text(), self.fallback_ips.text(),
                 self.profile_edges.isChecked(), self.fake_sni.text())
        candidate = Tuning.preset(mode)
        candidate.carrier_mode = route[0]
        self._load_tuning(candidate, include_identity=False)
        self.carrier.setCurrentText(route[0]); self.connect_ip.setText(route[1]); self.fallback_ips.setText(route[2]); self.profile_edges.setChecked(route[3]); self.fake_sni.setText(route[4])

    def _load_tuning(self, t, include_identity=True):
        self._loading_tuning = True
        try:
            if include_identity:
                self.carrier.setCurrentText(t.carrier_mode)
                self.preset.setCurrentText(t.mode if self.preset.findText(t.mode) >= 0 else "custom")
            self.core_preset.setCurrentText(t.pattern_quality_preset)
            self.connect_ip.setText(t.pattern_connect_ip); self.fallback_ips.setText(t.pattern_fallback_ips); self.profile_edges.setChecked(t.pattern_use_profile_edges); self.fake_sni.setText(t.pattern_fake_sni)
            self.inject_delay.setValue(t.pattern_inject_delay_ms); self.ack_timeout.setValue(t.pattern_ack_timeout_ms); self.connect_timeout.setValue(t.pattern_connect_timeout_ms)
            self.relay_buffer.setValue(t.pattern_relay_buffer_kb); self.socket_buffer.setValue(t.pattern_socket_buffer_kb); self.max_sessions.setValue(t.pattern_max_sessions); self.keepalive.setValue(t.pattern_keepalive_idle_s); self.upload_optimized.setChecked(t.pattern_upload_optimized)
            self.mux_enabled.setChecked(getattr(t, "xray_mux_enabled", True)); self.mux_concurrency.setValue(getattr(t, "xray_mux_concurrency", 8)); self.background_probe.setChecked(getattr(t, "background_quality_probe_enabled", False)); self.probe_delay.setValue(getattr(t, "background_quality_probe_delay_s", 30)); self.log_level.setCurrentText(t.log_level)
            self.edge_cooldown.setValue(getattr(t, "pattern_edge_failure_cooldown_s", 8)); self.keepalive_interval.setValue(getattr(t, "pattern_keepalive_interval_s", 3)); self.keepalive_count.setValue(getattr(t, "pattern_keepalive_count", 3))
        finally:
            self._loading_tuning = False

    def _apply_recommended(self):
        carrier = self.carrier.currentText()
        recommended = Tuning.carrier_preset(carrier)
        self._load_tuning(recommended)

    def _apply_core_preset(self, mode):
        if self._loading_tuning:
            return
        values = {
            "maximum": (0, 1800, 1600, 512, 4096, 12, 10),
            "streaming": (0, 2200, 1800, 512, 4096, 10, 11),
            "upload": (1, 3000, 2500, 512, 4096, 8, 11),
            "balanced": (1, 2200, 2200, 256, 1024, 8, 11),
            "low_latency": (0, 1600, 1600, 128, 1024, 6, 9),
            "compatibility": (2, 8000, 5000, 128, 512, 4, 15),
        }
        inject, ack, connect, relay, sock, sessions, keepalive = values.get(mode, values["upload"])
        self.inject_delay.setValue(inject); self.ack_timeout.setValue(ack); self.connect_timeout.setValue(connect)
        self.relay_buffer.setValue(relay); self.socket_buffer.setValue(sock); self.max_sessions.setValue(sessions); self.keepalive.setValue(keepalive)
        self.upload_optimized.setChecked(mode in {"maximum", "streaming", "upload"})

    def _form_value(self, carrier=None) -> Tuning:
        carrier = carrier or self.carrier.currentText()
        base = self._carrier_drafts.get(carrier, self.tuning)
        t = Tuning.from_dict(base.to_dict())
        t.mode = self.preset.currentText(); t.carrier_mode = carrier
        t.pattern_quality_preset = self.core_preset.currentText(); t.pattern_connect_ip = self.connect_ip.text().strip()
        t.pattern_fallback_ips = self.fallback_ips.text().strip(); t.pattern_use_profile_edges = self.profile_edges.isChecked()
        t.pattern_fake_sni = self.fake_sni.text().strip(); t.pattern_inject_delay_ms = self.inject_delay.value()
        t.pattern_ack_timeout_ms = self.ack_timeout.value(); t.pattern_connect_timeout_ms = self.connect_timeout.value()
        t.pattern_relay_buffer_kb = self.relay_buffer.value(); t.pattern_socket_buffer_kb = self.socket_buffer.value()
        t.pattern_max_sessions = self.max_sessions.value(); t.pattern_keepalive_idle_s = self.keepalive.value()
        t.pattern_upload_optimized = self.upload_optimized.isChecked(); t.xray_mux_enabled = self.mux_enabled.isChecked(); t.xray_mux_concurrency = self.mux_concurrency.value()
        t.background_quality_probe_enabled = self.background_probe.isChecked(); t.background_quality_probe_delay_s = self.probe_delay.value(); t.log_level = self.log_level.currentText()
        t.pattern_edge_failure_cooldown_s = self.edge_cooldown.value(); t.pattern_keepalive_interval_s = self.keepalive_interval.value(); t.pattern_keepalive_count = self.keepalive_count.value(); return t

    def _switch_carrier_profile(self, carrier):
        if self._loading_tuning or carrier == self._active_carrier:
            return
        self._carrier_drafts[self._active_carrier] = self._form_value(self._active_carrier)
        self._active_carrier = carrier
        self._load_tuning(self._carrier_drafts.get(carrier, Tuning.carrier_preset(carrier)))

    def values(self) -> dict[str, Tuning]:
        self._carrier_drafts[self._active_carrier] = self._form_value(self._active_carrier)
        return {carrier: Tuning.from_dict(value.to_dict())
                for carrier, value in self._carrier_drafts.items()}

    def value(self) -> Tuning:
        values = self.values()
        return values[self._active_carrier]

    def update_repo_url(self) -> str:
        return self.update_repo.text().strip()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__(); self.setWindowTitle("UAC Spoofer Desktop"); self.resize(1440, 900); self.setMinimumSize(1080, 700)
        self.setAccessibleName("UAC Spoofer Desktop")
        self.storage = Storage(); self.language = self.storage.settings.get("language", "fa"); self.bridge = Bridge(); self.scan_cancelled = False; self.scanning = False; self.connecting = False; self.connection_error = ""; self.last_results: list[ScanResult] = []; self.sni_undo_snapshot = None; self._toast_timer = None
        self._scan_generation = 0; self._scan_cancel_event = threading.Event(); self._scan_results_by_domain: dict[str, ScanResult] = {}; self._scan_context = {}
        self._update_generation = 0; self._update_in_progress = False; self._latest_update: UpdateInfo | None = None
        self._closing = False
        self._force_quit = False
        self._tray = None
        self._tray_hint_shown = False
        self.tray_show_action = None
        self.tray_quit_action = None
        self._connect_generation = 0
        self._connect_cancel = threading.Event()
        self._connect_thread: threading.Thread | None = None
        self._bypass_apply_timer = QTimer(self)
        self._bypass_apply_timer.setSingleShot(True)
        self._bypass_apply_timer.setInterval(550)
        self._bypass_apply_timer.timeout.connect(self._apply_bypass_changes)
        self._page_animation = None
        self._animated_page = None
        self._entrance_done = False
        self._log_paused_lines: list[str] = []
        self._all_log_lines: list[str] = []
        self._pending_file_log_lines: list[str] = []
        self._log_flush_failures = 0
        self._log_flush_timer = QTimer(self); self._log_flush_timer.setSingleShot(True); self._log_flush_timer.setInterval(180); self._log_flush_timer.timeout.connect(self._flush_log_buffer)
        self._metrics_compact = None
        self._controls_compact = None
        self.engine = Engine(self.bridge.log.emit, self.bridge.state.emit, self.bridge.traffic.emit)
        self._build(); self._setup_tray(); self._wire(); self._configure_technical_widgets(); self.refresh_profiles(); self.refresh_bookmarks(); self.refresh_processes(); self._apply_language(); self._append_log("UAC Spoofer Desktop آماده است")
        self.activity_bar.set_activity("", "idle", False)
        QTimer.singleShot(1800, lambda: self.check_for_updates(manual=False))

    def _bind_text(self, widget, persian, english):
        widget.setProperty("i18nFa", persian)
        widget.setProperty("i18nEn", english)
        widget.setText(english if self.language == "en" else persian)
        return widget

    def _action_button(self, persian, english, icon_name, object_name="secondaryAction"):
        button = GlowButton()
        button.setObjectName(object_name)
        button.setIcon(cyber_icon(icon_name, "#bfefff", 18))
        button.setIconSize(QSize(18, 18))
        button.setCursor(Qt.PointingHandCursor)
        self._bind_text(button, persian, english)
        return button

    def _page_header(self, persian_title, english_title, persian_subtitle, english_subtitle, trailing=None):
        header_meta = {
            "Connection Center": ("shield", "فرماندهی شبکه", "NETWORK COMMAND"),
            "Configs": ("file-cog", "مدیریت مسیرها", "ROUTE LIBRARY"),
            "SNI Lab": ("flask", "آزمایش و رتبه‌بندی", "SIGNAL LABORATORY"),
            "Live Logs": ("activity", "رویدادهای زنده", "LIVE TELEMETRY"),
            "App Bypass": ("route", "مسیریابی برنامه‌ها", "APPLICATION ROUTING"),
            "Network Tools": ("wrench", "ابزارهای تشخیص", "DIAGNOSTIC TOOLKIT"),
            "Support & Updates": ("headphones", "مرکز راهنما", "SUPPORT CENTER"),
        }
        icon_name, persian_kicker, english_kicker = header_meta.get(
            english_title, ("shield", "رابط دسکتاپ", "FLOXU DESKTOP")
        )
        header = LuminousPageHeader()
        layout = QHBoxLayout(header); layout.setContentsMargins(19, 14, 19, 15); layout.setSpacing(16)
        icon = QLabel(); icon.setObjectName("pageHeaderIcon"); icon.setFixedSize(54, 54)
        icon.setAlignment(Qt.AlignCenter); icon.setPixmap(cyber_pixmap(icon_name, "#8efff4", 27))
        layout.addWidget(icon, 0, Qt.AlignVCenter)
        copy = QVBoxLayout(); copy.setSpacing(3)
        kicker = self._bind_text(QLabel(), persian_kicker, english_kicker); kicker.setObjectName("pageEyebrow")
        title = self._bind_text(QLabel(), persian_title, english_title); title.setObjectName("pageTitle")
        subtitle = self._bind_text(QLabel(), persian_subtitle, english_subtitle); subtitle.setObjectName("pageSubtitle"); subtitle.setWordWrap(True)
        subtitle.setTextInteractionFlags(Qt.TextSelectableByMouse)
        copy.addWidget(kicker); copy.addWidget(title); copy.addWidget(subtitle)
        layout.addLayout(copy, 1)
        if trailing is not None:
            layout.addWidget(trailing, 0, Qt.AlignVCenter)
        return header

    def _scroll_page(self):
        scroll = QScrollArea(); scroll.setObjectName("pageScroll"); scroll.setWidgetResizable(True); scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        body = QWidget(); body.setObjectName("pageBody")
        scroll.setWidget(body)
        return scroll, body

    def _toggle_option(self, toggle, persian, english):
        wrapper = QFrame(); wrapper.setObjectName("toggleOption")
        layout = QHBoxLayout(wrapper); layout.setContentsMargins(10, 7, 10, 7); layout.setSpacing(10)
        label = self._bind_text(QLabel(), persian, english); label.setObjectName("controlLabel")
        layout.addWidget(toggle); layout.addWidget(label); layout.addStretch()
        toggle.setAccessibleName(english)
        return wrapper

    def _build(self):
        root = CyberRoot(); self.setCentralWidget(root); layout = QHBoxLayout(root); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(0)
        sidebar = QFrame(); self.sidebar = sidebar; sidebar.setObjectName("sidebar"); sidebar.setAttribute(Qt.WA_StyledBackground, True); sidebar.setFixedWidth(286); side = QVBoxLayout(sidebar); side.setContentsMargins(18, 20, 18, 18); side.setSpacing(4)
        logo = QFrame(); logo.setObjectName("logoCard"); logo.setMinimumHeight(88); logo_layout = QHBoxLayout(logo); logo_layout.setContentsMargins(14, 12, 14, 12); logo_layout.setSpacing(12)
        mark = QLabel(); mark.setObjectName("logoMark"); mark.setAlignment(Qt.AlignCenter); mark.setFixedSize(52, 52); mark.setPixmap(cyber_pixmap("shield", "#031422", 29)); logo_layout.addWidget(mark)
        logo_text = QVBoxLayout(); logo_text.setSpacing(2); brand = QLabel("UAC SPOOFER"); brand.setObjectName("brand"); logo_text.addWidget(brand); version = QLabel(f"DESKTOP  {__version__}"); version.setObjectName("version"); version.setLayoutDirection(Qt.LeftToRight); logo_text.addWidget(version); logo_layout.addLayout(logo_text, 1); side.addWidget(logo); side.addSpacing(16)
        self.nav = []
        entries = [("home", "خانه", "Home"), ("file-cog", "کانفیگ‌ها", "Configs"), ("flask", f"آزمایشگاه {ltr_isolate('SNI')}", "SNI Lab"), ("activity", "لاگ زنده", "Live Logs"), ("shield", "عبور مستقیم برنامه‌ها", "App Bypass"), ("wrench", "ابزارها", "Tools"), ("headphones", "پشتیبانی", "Support")]
        self.nav_meta = []
        for index, (icon_name, name, english) in enumerate(entries):
            button = NavButton(english if self.language == "en" else name); button.setIcon(cyber_icon(icon_name, "#9fb4d8", 22)); button.setIconSize(QSize(22, 22)); button.setProperty("iconName", icon_name); button.clicked.connect(lambda _, i=index: self.show_page(i)); side.addWidget(button); self.nav.append(button)
            self.nav_meta.append((icon_name, name, english))
        side.addStretch()
        self.rating_card = QFrame(); self.rating_card.setObjectName("ratingCard"); rating_layout = QVBoxLayout(self.rating_card); rating_layout.setContentsMargins(15, 13, 15, 13); rating_layout.setSpacing(4)
        rating_title = self._bind_text(QLabel(), "از برنامه راضی هستید؟", "Enjoying the app?"); rating_title.setObjectName("ratingTitle")
        rating_text = self._bind_text(QLabel(), "با یک ستاره از پروژه حمایت کنید.", "Support the project with a star."); rating_text.setObjectName("ratingText"); rating_text.setWordWrap(True)
        rating_button = self._action_button("ستاره در GitHub", "Star on GitHub", "external-link", "ratingButton"); rating_button.clicked.connect(lambda: webbrowser.open(PROJECT_URL))
        rating_layout.addWidget(rating_title); rating_layout.addWidget(rating_text); rating_layout.addWidget(rating_button); side.addWidget(self.rating_card); side.addSpacing(10)
        footer = QFrame(); footer.setObjectName("sidebarFooter"); footer_layout = QVBoxLayout(footer); footer_layout.setContentsMargins(7, 7, 7, 7); footer_layout.setSpacing(4)
        self.language_button = QPushButton("English"); self.language_button.setObjectName("footerAction"); self.language_button.setIcon(cyber_icon("globe", "#9fb4d8", 19)); self.language_button.setIconSize(QSize(19, 19)); self.language_button.clicked.connect(self.toggle_language); footer_layout.addWidget(self.language_button)
        self.data_button = QPushButton("باز کردن پوشه داده‌ها"); self.data_button.setObjectName("footerAction"); self.data_button.setIcon(cyber_icon("folder", "#9fb4d8", 19)); self.data_button.setIconSize(QSize(19, 19)); self.data_button.clicked.connect(lambda: os.startfile(DATA_DIR)); footer_layout.addWidget(self.data_button); side.addWidget(footer)
        layout.addWidget(sidebar)
        content_shell = QFrame(); content_shell.setObjectName("contentShell"); content_layout = QVBoxLayout(content_shell); content_layout.setContentsMargins(0, 0, 0, 0); content_layout.setSpacing(0)
        self.stack = QStackedWidget(); self.stack.setObjectName("content"); content_layout.addWidget(self.stack, 1)
        activity_wrap = QFrame(); activity_wrap.setObjectName("activityWrap"); activity_layout = QVBoxLayout(activity_wrap); activity_layout.setContentsMargins(30, 0, 30, 18)
        self.activity_bar = ActivityBar(self.language); activity_layout.addWidget(self.activity_bar); content_layout.addWidget(activity_wrap)
        layout.addWidget(content_shell, 1)
        pages = [self._home_page(), self._configs_page(), self._scanner_page(), self._logs_page(),
                 self._apps_page(), self._tools_page(), self._support_page()]
        for page in pages:
            page.setObjectName("page")
            self.stack.addWidget(page)
        self.show_page(0)

    def _home_page(self):
        page, body = self._scroll_page(); root = QVBoxLayout(body); root.setContentsMargins(34, 28, 34, 24); root.setSpacing(18)
        self.status_pill = StatusPill(self.language)
        root.addWidget(self._page_header("کنترل اتصال", "Connection Center", f"نسخه دسکتاپ با استفاده از {ltr_isolate('Xray')}، پروکسی سیستم ویندوز و هسته {ltr_isolate('Patterniha Wrong-Sequence')}", "Desktop engine powered by Xray, Windows System Proxy and native TLS fragmentation", self.status_pill))
        hero = HeroCard(); self.hero_card = hero; hero.setMinimumHeight(318); hero_layout = QHBoxLayout(hero); self.hero_layout = hero_layout; hero_layout.setContentsMargins(38, 28, 34, 28); hero_layout.setSpacing(34)
        hero_copy = QVBoxLayout(); self.hero_copy_layout = hero_copy; hero_copy.setSpacing(9)
        eyebrow = QHBoxLayout(); eyebrow.setSpacing(9); eyebrow_icon = QLabel(); eyebrow_icon.setPixmap(cyber_pixmap("lock", "#23f5e0", 18)); eyebrow_icon.setFixedSize(20, 20)
        self.hero_badge = self._bind_text(QLabel(), "تونل امن دسکتاپ", "SECURE DESKTOP TUNNEL"); self.hero_badge.setObjectName("heroBadge")
        eyebrow.addWidget(eyebrow_icon); eyebrow.addWidget(self.hero_badge); eyebrow.addStretch(); hero_copy.addLayout(eyebrow)
        self.status = QLabel(f"{ltr_isolate('VPN')} خاموش است"); self.status.setObjectName("heroStatus"); self.status.setWordWrap(True); self.status.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred); hero_copy.addWidget(self.status)
        self.connection_hint = QLabel("آماده اتصال"); self.connection_hint.setObjectName("heroHint"); self.connection_hint.setWordWrap(True); self.connection_hint.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred); hero_copy.addWidget(self.connection_hint)
        hero_copy.addStretch()
        self.connect_button = GlowButton("اتصال"); self.connect_button.setObjectName("connectButton"); self.connect_button.setProperty("state", "idle"); self.connect_button.setIcon(cyber_icon("play", "#031422", 21)); self.connect_button.setIconSize(QSize(21, 21)); self.connect_button.setMinimumSize(216, 60); self.connect_button.setMaximumWidth(260); self.connect_button.setCursor(Qt.PointingHandCursor); hero_copy.addWidget(self.connect_button)
        hero_layout.addLayout(hero_copy, 3)
        orb_shell = QFrame(); self.orb_shell = orb_shell; orb_shell.setObjectName("orbShell"); orb_shell.setMinimumWidth(284); orb_layout = QVBoxLayout(orb_shell); orb_layout.setContentsMargins(18, 8, 18, 10); orb_layout.setSpacing(2)
        self.orb = ConnectionOrb(); orb_caption = QLabel("NETWORK CORE"); orb_caption.setObjectName("orbCaption"); orb_caption.setAlignment(Qt.AlignCenter); orb_layout.addWidget(self.orb, alignment=Qt.AlignCenter); orb_layout.addWidget(orb_caption)
        hero_layout.addWidget(orb_shell, 2, Qt.AlignCenter); root.addWidget(hero)
        self._layout_hero(self.width() < 1050)

        self.metrics_layout = QGridLayout(); self.metrics_layout.setSpacing(14)
        self.active_profile = QLabel("—"); self.active_profile.setWordWrap(True); self.route_card = MetricCard(self.tr("مسیر فعال", "Active Route"), "route", self.active_profile); self.route_card.title.setProperty("i18nFa", "مسیر فعال"); self.route_card.title.setProperty("i18nEn", "Active Route"); self.route_card.setMinimumWidth(230)
        self.route_detail = self.route_card.secondary
        self.ping_label = QLabel("—"); self.latency_card = MetricCard(self.tr("پینگ", "Latency"), "gauge", self.ping_label); self.latency_card.title.setProperty("i18nFa", "پینگ"); self.latency_card.title.setProperty("i18nEn", "Latency"); self.latency_card.enable_sparkline(True)
        self.up_label = QLabel("0 B"); self.upload_card = MetricCard(self.tr("آپلود", "Upload"), "upload", self.up_label); self.upload_card.title.setProperty("i18nFa", "آپلود"); self.upload_card.title.setProperty("i18nEn", "Upload")
        self.down_label = QLabel("0 B"); self.download_card = MetricCard(self.tr("دانلود", "Download"), "download", self.down_label); self.download_card.title.setProperty("i18nFa", "دانلود"); self.download_card.title.setProperty("i18nEn", "Download")
        self.ip_label = QLabel("—"); self.ip_card = MetricCard(self.tr("آی‌پی عمومی", "Public IP"), "map-pin", self.ip_label); self.ip_card.title.setProperty("i18nFa", "آی‌پی عمومی"); self.ip_card.title.setProperty("i18nEn", "Public IP")
        self.ip_button = self._action_button("بررسی IP", "Check IP", "refresh", "metricAction"); self.ip_button.clicked.connect(self.check_ip); self.ip_card.layout().addWidget(self.ip_button)
        self.metric_cards = [self.route_card, self.latency_card, self.upload_card, self.download_card, self.ip_card]
        root.addLayout(self.metrics_layout)
        self._layout_metric_cards(self.width() < 1320)

        controls = QFrame(); controls.setObjectName("quickControls"); self.controls_layout = QGridLayout(controls); self.controls_layout.setContentsMargins(16, 12, 16, 12); self.controls_layout.setHorizontalSpacing(12); self.controls_layout.setVerticalSpacing(10)
        self.auto_mode = ToggleSwitch(); self.auto_mode.setChecked(self.storage.settings.get("auto_mode", True)); self.auto_option = self._toggle_option(self.auto_mode, "حالت خودکار", "Auto Mode")
        self.pick_best = ToggleSwitch(); self.pick_best.setChecked(self.storage.settings.get("pick_best", False)); self.manual_option = self._toggle_option(self.pick_best, "انتخاب بهترین کانفیگ دستی", "Pick Best Manual Config")
        self.close_to_tray = ToggleSwitch(); self.close_to_tray.setChecked(self.storage.settings.get("close_to_tray", False)); self.tray_option = self._toggle_option(self.close_to_tray, "بستن در System Tray", "Close to Tray")
        self.carrier = QComboBox(); self.carrier.addItems(["auto", "mci", "irancell"]); self.carrier.setCurrentText(self.storage.tuning.carrier_mode); self.carrier.setMinimumWidth(142); self.carrier.setAccessibleName("Carrier")
        self.carrier_control = QFrame(); self.carrier_control.setObjectName("carrierControl"); carrier_layout = QHBoxLayout(self.carrier_control); carrier_layout.setContentsMargins(10, 7, 10, 7); carrier_layout.setSpacing(9); self.carrier_label = self._bind_text(QLabel(), "اپراتور", "Carrier"); self.carrier_label.setObjectName("controlLabel"); carrier_layout.addWidget(self.carrier_label); carrier_layout.addWidget(self.carrier)
        self.tune_button = self._action_button("تنظیمات پیشرفته", "Advanced Settings", "settings", "advancedButton"); self.tune_button.setProperty("chevron", True); self.tune_button.setIconSize(QSize(19, 19)); self.tune_button.clicked.connect(self.open_tuning)
        root.addWidget(controls)
        self._layout_control_bar(self.width() < 1240)
        root.addStretch()
        return page

    def _layout_metric_cards(self, compact):
        if not hasattr(self, "metrics_layout") or self._metrics_compact == compact:
            return
        self._metrics_compact = compact
        while self.metrics_layout.count():
            self.metrics_layout.takeAt(0)
        for column in range(6):
            self.metrics_layout.setColumnStretch(column, 0)
        if compact:
            self.metrics_layout.addWidget(self.route_card, 0, 0, 1, 2)
            self.metrics_layout.addWidget(self.latency_card, 0, 2)
            self.metrics_layout.addWidget(self.upload_card, 1, 0)
            self.metrics_layout.addWidget(self.download_card, 1, 1)
            self.metrics_layout.addWidget(self.ip_card, 1, 2)
            for column in range(3): self.metrics_layout.setColumnStretch(column, 1)
        else:
            for column, card_widget in enumerate(self.metric_cards):
                self.metrics_layout.addWidget(card_widget, 0, column)
                self.metrics_layout.setColumnStretch(column, 2 if column == 0 else 1)

    def _layout_hero(self, compact):
        if not hasattr(self, "hero_layout"):
            return
        if compact:
            self.hero_layout.setDirection(QBoxLayout.TopToBottom)
            self.hero_card.setMinimumHeight(570)
            self.orb_shell.setMinimumWidth(250)
        else:
            self.hero_layout.setDirection(QBoxLayout.LeftToRight)
            self.hero_card.setMinimumHeight(318)
            self.orb_shell.setMinimumWidth(284)

    def _layout_control_bar(self, compact):
        if not hasattr(self, "controls_layout") or self._controls_compact == compact:
            return
        self._controls_compact = compact
        while self.controls_layout.count():
            self.controls_layout.takeAt(0)
        for column in range(6):
            self.controls_layout.setColumnStretch(column, 0)
        if compact:
            self.controls_layout.addWidget(self.auto_option, 0, 0)
            self.controls_layout.addWidget(self.manual_option, 0, 1)
            self.controls_layout.addWidget(self.tray_option, 1, 0)
            self.controls_layout.addWidget(self.carrier_control, 1, 1)
            self.controls_layout.addWidget(self.tune_button, 2, 0, 1, 2)
        else:
            self.controls_layout.addWidget(self.auto_option, 0, 0)
            self.controls_layout.addWidget(self.manual_option, 0, 1)
            self.controls_layout.addWidget(self.tray_option, 0, 2)
            self.controls_layout.addWidget(self.carrier_control, 0, 3)
            self.controls_layout.setColumnStretch(4, 1)
            self.controls_layout.addWidget(self.tune_button, 0, 5)

    def _configs_page(self):
        page = QWidget(); root = QVBoxLayout(page); root.setContentsMargins(34, 28, 34, 26); root.setSpacing(15)
        self.config_count_label = QLabel("0"); self.config_count_label.setObjectName("summaryPill"); self.config_count_label.setAlignment(Qt.AlignCenter)
        root.addWidget(self._page_header("کانفیگ‌ها", "Configs", "مدیریت کامل لینک‌های VLESS و Trojan", "Manage, rank, import and edit VLESS and Trojan profiles", self.config_count_label))
        toolbar = QFrame(); toolbar.setObjectName("pageToolbar"); bar = QHBoxLayout(toolbar); bar.setContentsMargins(12, 10, 12, 10); bar.setSpacing(9)
        self.add_btn = self._action_button("افزودن کانفیگ", "Add Config", "plus", "primaryAction")
        self.clip_btn = self._action_button("ورود از Clipboard", "Import Clipboard", "copy", "secondaryAction")
        self.sync_btn = self._action_button("دریافت پیشنهادی‌ها", "Sync Suggested", "refresh", "secondaryAction")
        self.edit_btn = self._action_button("ویرایش", "Edit", "edit", "quietButton")
        self.delete_btn = self._action_button("حذف", "Delete", "trash", "dangerButton")
        for widget in (self.add_btn, self.clip_btn, self.sync_btn): bar.addWidget(widget)
        bar.addStretch(); bar.addWidget(self.edit_btn); bar.addWidget(self.delete_btn); root.addWidget(toolbar)
        panel = QFrame(); panel.setObjectName("configPanel"); panel_layout = QVBoxLayout(panel); panel_layout.setContentsMargins(0, 0, 0, 0)
        self.profile_tabs = QTabWidget(); self.profile_tabs.setObjectName("profileTabs"); self.manual_list = EmptyListWidget("file-cog"); self.suggested_list = EmptyListWidget("server")
        self.manual_list.setObjectName("configList"); self.suggested_list.setObjectName("configList")
        for widget in (self.manual_list, self.suggested_list):
            widget.setSelectionMode(QAbstractItemView.SingleSelection); widget.setSpacing(6); widget.itemDoubleClicked.connect(lambda _: self.edit_profile()); widget.itemSelectionChanged.connect(self._update_config_actions)
        self.manual_list.set_empty_text(self.tr("هنوز کانفیگ دستی ندارید", "No manual configs yet"), self.tr("یک لینک VLESS یا Trojan اضافه یا از Clipboard وارد کنید.", "Add a VLESS or Trojan link, or import one from the clipboard."))
        self.suggested_list.set_empty_text(self.tr("هنوز پیشنهادی دریافت نشده", "No suggestions downloaded"), self.tr("برای دریافت فهرست پیشنهادی، همگام‌سازی را اجرا کنید.", "Sync the suggested repository to populate this list."))
        self.profile_tabs.addTab(self.manual_list, self.tr("دستی", "Manual")); self.profile_tabs.addTab(self.suggested_list, self.tr("پیشنهادی", "Suggested")); self.profile_tabs.currentChanged.connect(self._update_config_actions)
        panel_layout.addWidget(self.profile_tabs); root.addWidget(panel, 1)
        self._update_config_actions()
        return page

    def _scanner_page(self):
        page, body = self._scroll_page(); root = QVBoxLayout(body); root.setContentsMargins(30, 25, 30, 24); root.setSpacing(14)
        self.scan_state_badge = QLabel(); self.scan_state_badge.setObjectName("summaryPill"); self._bind_text(self.scan_state_badge, "آماده اسکن", "Scanner Ready")
        root.addWidget(self._page_header(f"آزمایشگاه {ltr_isolate('SNI')}", "SNI Lab", "اسکن همزمان، امتیازدهی پایداری و ذخیره بهترین مسیرها", "Discover, measure and rank reliable SNI routes", self.scan_state_badge))
        controls = QFrame(); controls.setObjectName("scanControlCard"); controls.setMinimumHeight(214); c = QGridLayout(controls); c.setContentsMargins(18, 16, 18, 16); c.setHorizontalSpacing(18); c.setVerticalSpacing(12)
        domain_panel = QFrame(); domain_panel.setObjectName("domainPanel"); domain_box = QVBoxLayout(domain_panel); domain_box.setContentsMargins(0, 0, 0, 0); domain_box.setSpacing(7); domain_title = self._bind_text(QLabel(), "دامنه‌های هدف", "DOMAIN TARGETS"); domain_title.setObjectName("sectionEyebrow")
        domain_help = self._bind_text(QLabel(), "در هر خط یک دامنه؛ فهرست‌ها به‌صورت همزمان بررسی می‌شوند.", "One hostname per line • long lists are scanned concurrently"); domain_help.setObjectName("helperText"); domain_help.setWordWrap(True)
        self.domains = QPlainTextEdit(); self.domains.setObjectName("domainEditor"); self.domains.setPlaceholderText("example.com\ncdn.example.net"); self.domains.setMinimumHeight(116)
        try: self.domains.setPlainText("\n".join((ASSETS / "domains.txt").read_text(encoding="utf-8").splitlines()[:80]))
        except OSError: pass
        domain_box.addWidget(domain_title); domain_box.addWidget(domain_help); domain_box.addWidget(self.domains, 1); c.addWidget(domain_panel, 0, 0)
        options = QFrame(); options.setObjectName("scanOptions"); option_layout = QVBoxLayout(options); option_layout.setContentsMargins(15, 13, 15, 13); option_layout.setSpacing(10)
        option_title = self._bind_text(QLabel(), "پروفایل اسکن", "SCAN PROFILE"); option_title.setObjectName("sectionEyebrow"); option_layout.addWidget(option_title)
        option_grid = QGridLayout(); option_grid.setHorizontalSpacing(10); option_grid.setVerticalSpacing(9)
        self.scan_threads = NumericInput(30, 1, 100); self.scan_tries = NumericInput(3, 1, 10); self.scan_timeout = NumericInput(12, 2, 60, "s")
        for row, (fa, en, widget) in enumerate((("رشته‌ها", "Threads", self.scan_threads), ("تلاش", "Attempts", self.scan_tries), ("مهلت", "Timeout", self.scan_timeout))):
            label = self._bind_text(QLabel(), fa, en); label.setObjectName("fieldLabel"); option_grid.addWidget(label, row, 0); option_grid.addWidget(widget, row, 1)
        option_layout.addLayout(option_grid); option_layout.addStretch()
        self.scan_button = self._action_button("شروع اسکن", "Start Scan", "play", "scanPrimaryButton"); self.scan_button.setMinimumHeight(48); option_layout.addWidget(self.scan_button)
        c.addWidget(options, 0, 1); c.setColumnStretch(0, 3); c.setColumnStretch(1, 2); root.addWidget(controls)

        self.scan_progress = ScanProgressPanel(self.language); self.scan_progress.setValue(0); root.addWidget(self.scan_progress)
        self.scan_tabs = QTabWidget(); self.scan_tabs.setObjectName("scannerTabs"); self.scan_tabs.setMinimumHeight(180); self.results_table = self._result_table(); self.bookmarks_table = self._result_table(); self.scan_tabs.addTab(self.results_table, "نتایج"); self.scan_tabs.addTab(self.bookmarks_table, "ذخیره‌شده"); root.addWidget(self.scan_tabs, 1)
        action_bar = QFrame(); action_bar.setObjectName("sniActionBar"); action_bar.setMinimumHeight(122); actions = QVBoxLayout(action_bar); actions.setContentsMargins(12, 10, 12, 10); actions.setSpacing(8)
        utility_row = QHBoxLayout(); apply_row = QHBoxLayout(); utility_row.setSpacing(8); apply_row.setSpacing(8)
        self.scan_selection_label = self._bind_text(QLabel(), "هیچ ردیفی انتخاب نشده", "No rows selected"); self.scan_selection_label.setObjectName("selectionText"); utility_row.addWidget(self.scan_selection_label); utility_row.addStretch()
        self.copy_result_btn = self._action_button("کپی نتیجه", "Copy Result", "copy", "quietButton")
        self.bookmark_btn = self._action_button("ذخیره نتیجه", "Save Result", "database", "quietButton")
        self.undo_apply_btn = self._action_button("بازگردانی آخرین اعمال", "Undo Last Apply", "refresh", "quietButton"); self.undo_apply_btn.setEnabled(False)
        self.apply_sni_btn = self._action_button("اعمال SNI به کانفیگ فعال", "Apply SNI to Active Config", "route", "secondaryAction")
        self.apply_all_sni_btn = self._action_button("اعمال SNI به همه پیشنهادها", "Apply SNI to All Suggested Configs", "network", "primaryAction")
        for widget in (self.copy_result_btn, self.bookmark_btn, self.undo_apply_btn): utility_row.addWidget(widget)
        apply_row.addStretch(); apply_row.addWidget(self.apply_sni_btn); apply_row.addWidget(self.apply_all_sni_btn)
        actions.addLayout(utility_row); actions.addLayout(apply_row)
        root.addWidget(action_bar)
        return page

    def _result_table(self):
        table = QTableWidget(0, 9); table.setObjectName("resultsTable"); table.setHorizontalHeaderLabels(["", "Domain", "IP", "Colo", "Ping", "Stability", "First byte", "Bytes/2s", "Score"])
        header = table.horizontalHeader(); header.setSectionsClickable(True); header.setSortIndicatorShown(True); header.setHighlightSections(False)
        header.setSectionResizeMode(0, QHeaderView.Fixed); table.setColumnWidth(0, 42)
        header.setSectionResizeMode(1, QHeaderView.Stretch); table.setColumnWidth(1, 300)
        header.setSectionResizeMode(2, QHeaderView.Interactive); table.setColumnWidth(2, 138)
        for column, width in {3: 78, 4: 104, 5: 112, 6: 118, 7: 118, 8: 92}.items():
            header.setSectionResizeMode(column, QHeaderView.Fixed); table.setColumnWidth(column, width)
        table.verticalHeader().hide(); table.verticalHeader().setDefaultSectionSize(48); table.setShowGrid(False); table.setAlternatingRowColors(True); table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        table.setSelectionBehavior(QAbstractItemView.SelectRows); table.setSelectionMode(QAbstractItemView.ExtendedSelection); table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        header.setSortIndicator(8, Qt.DescendingOrder)
        table.setSortingEnabled(True); table.itemSelectionChanged.connect(self._update_scan_selection)
        return table

    def _logs_page(self):
        page = QWidget(); root = QVBoxLayout(page); root.setContentsMargins(34, 28, 34, 26); root.setSpacing(14)
        self.log_count_label = QLabel(self.tr("۰ خط", "0 lines")); self.log_count_label.setObjectName("summaryPill")
        root.addWidget(self._page_header("لاگ زنده", "Live Logs", "فقط رویدادهای مهم اتصال، خطا و تشخیص مسیر", "Readable connection, route and error diagnostics", self.log_count_label))
        terminal = QFrame(); terminal.setObjectName("terminalCard"); terminal_layout = QVBoxLayout(terminal); terminal_layout.setContentsMargins(0, 0, 0, 0); terminal_layout.setSpacing(0)
        toolbar = QFrame(); toolbar.setObjectName("terminalToolbar"); bar = QHBoxLayout(toolbar); bar.setContentsMargins(12, 9, 12, 9); bar.setSpacing(8)
        live_dot = PulseDot(); live_dot.set_state("connected"); live_label = self._bind_text(QLabel(), "LIVE", "LIVE"); live_label.setObjectName("terminalLive")
        self.log_filter = QLineEdit(); self.log_filter.setObjectName("logFilter"); self.log_filter.setPlaceholderText(self.tr("فیلتر لاگ‌ها…", "Filter logs…")); self.log_filter.setClearButtonEnabled(True); self.log_filter.setMaximumWidth(260)
        self.log_pause = ToggleSwitch(); self.log_pause.setAccessibleName("Pause live logs"); pause_label = self._bind_text(QLabel(), "توقف نمایش", "Pause")
        self.log_autoscroll = ToggleSwitch(); self.log_autoscroll.setChecked(True); self.log_autoscroll.setAccessibleName("Auto-scroll live logs"); auto_label = self._bind_text(QLabel(), "اسکرول خودکار", "Auto-scroll")
        copy = self._action_button("کپی", "Copy", "copy", "quietButton"); clear = self._action_button("پاک کردن", "Clear", "trash", "dangerButton")
        copy.clicked.connect(lambda: QApplication.clipboard().setText(self.logs.toPlainText())); clear.clicked.connect(self.logs_clear)
        bar.addWidget(live_dot); bar.addWidget(live_label); bar.addSpacing(6); bar.addWidget(self.log_filter, 1); bar.addWidget(self.log_pause); bar.addWidget(pause_label); bar.addWidget(self.log_autoscroll); bar.addWidget(auto_label); bar.addStretch(); bar.addWidget(copy); bar.addWidget(clear)
        terminal_layout.addWidget(toolbar)
        self.logs = QTextEdit(); self.logs.setReadOnly(True); self.logs.setObjectName("logs"); self.logs.setAcceptRichText(False); terminal_layout.addWidget(self.logs, 1)
        root.addWidget(terminal, 1)
        self.log_filter.textChanged.connect(self._render_logs); self.log_pause.toggled.connect(self._toggle_log_pause)
        return page

    def _apps_page(self):
        page = QWidget(); root = QVBoxLayout(page); root.setContentsMargins(34, 28, 34, 26); root.setSpacing(14)
        self.process_count_label = QLabel("0 selected"); self.process_count_label.setObjectName("summaryPill"); self.process_count_label.setLayoutDirection(Qt.LeftToRight)
        root.addWidget(self._page_header("عبور مستقیم برنامه‌ها", "App Bypass", "پردازه‌هایی را انتخاب کنید که مستقیم و خارج از تونل کار کنند", "Choose which running apps connect directly outside the tunnel", self.process_count_label))
        toolbar = QFrame(); toolbar.setObjectName("pageToolbar"); toolbar_layout = QHBoxLayout(toolbar); toolbar_layout.setContentsMargins(12, 9, 12, 9); toolbar_layout.setSpacing(10)
        search_wrap = QFrame(); search_wrap.setObjectName("searchWrap"); search_layout = QHBoxLayout(search_wrap); search_layout.setContentsMargins(10, 0, 8, 0); search_layout.setSpacing(7); search_icon = QLabel(); search_icon.setPixmap(cyber_pixmap("search", "#7fa2c5", 18)); search_layout.addWidget(search_icon)
        self.process_search = QLineEdit(); self.process_search.setObjectName("processSearch"); self.process_search.setPlaceholderText(self.tr("جستجوی پردازه…", "Search processes…")); self.process_search.setClearButtonEnabled(True); search_layout.addWidget(self.process_search); toolbar_layout.addWidget(search_wrap, 1)
        self.process_refresh_btn = self._action_button("به‌روزرسانی فهرست", "Refresh Process List", "refresh", "secondaryAction"); self.process_refresh_btn.clicked.connect(self.refresh_processes); toolbar_layout.addWidget(self.process_refresh_btn); root.addWidget(toolbar)
        table_frame = QFrame(); table_frame.setObjectName("tableFrame"); table_layout = QVBoxLayout(table_frame); table_layout.setContentsMargins(0, 0, 0, 0)
        self.process_table = QTableWidget(0, 2); self.process_table.setObjectName("processTable"); self.process_table.setHorizontalHeaderLabels([self.tr("خارج از VPN", "Bypass VPN"), "Process"]); self.process_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed); self.process_table.setColumnWidth(0, 145); self.process_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch); self.process_table.verticalHeader().hide(); self.process_table.verticalHeader().setDefaultSectionSize(46); self.process_table.setShowGrid(False); self.process_table.setAlternatingRowColors(True); self.process_table.setEditTriggers(QAbstractItemView.NoEditTriggers); self.process_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table_layout.addWidget(self.process_table); root.addWidget(table_frame, 1)
        self.process_search.textChanged.connect(self._filter_processes)
        return page

    def _tools_page(self):
        page, body = self._scroll_page(); root = QVBoxLayout(body); root.setContentsMargins(34, 28, 34, 26); root.setSpacing(16)
        root.addWidget(self._page_header("ابزارهای شبکه", "Network Tools", "قابلیت‌های بیشتر نسخه کامپیوتر", "Focused utilities for route, IP and diagnostics"))
        self.tools_grid = QGridLayout(); self.tools_grid.setSpacing(14); self.tool_cards = []
        tool_specs = [
            ("radio", "Reality Probe", "Reality Probe", "تست TCP و TLS مقصد فعال", "Test the active target over TCP and TLS", self.reality_probe, True),
            ("globe", "تست IP مستقیم", "Direct IP Test", "نمایش IP بدون پروکسی", "Show the public IP without the tunnel", lambda: self.check_ip(False), True),
            ("shield", "تست IP تونل", "Tunnel IP Test", "نمایش IP از پروکسی UAC", "Show the public IP through UAC proxy", lambda: self.check_ip(True), True),
            ("terminal", "باز کردن فایل لاگ", "Open Log File", "مشاهده فایل لاگ دائمی", "Open the persistent diagnostic log", self._open_log_file, LOG_FILE.exists()),
        ]
        for index, (icon_name, fa_title, en_title, fa_desc, en_desc, action, available) in enumerate(tool_specs):
            box = MotionFrame(); box.setObjectName("toolCard"); l = QVBoxLayout(box); l.setContentsMargins(18, 18, 18, 17); l.setSpacing(10)
            top = QHBoxLayout(); icon_label = QLabel(); icon_label.setObjectName("toolIcon"); icon_label.setFixedSize(42, 42); icon_label.setPixmap(cyber_pixmap(icon_name, "#23f5e0", 23)); status = QLabel(); self._bind_text(status, "آماده" if available else "در دسترس نیست", "Ready" if available else "Unavailable"); status.setObjectName("toolStatus"); status.setProperty("available", available); top.addWidget(icon_label); top.addStretch(); top.addWidget(status); l.addLayout(top)
            title = self._bind_text(QLabel(), fa_title, en_title); title.setObjectName("toolTitle"); desc = self._bind_text(QLabel(), fa_desc, en_desc); desc.setObjectName("toolDescription"); desc.setWordWrap(True); desc.setTextInteractionFlags(Qt.TextSelectableByMouse); l.addWidget(title); l.addWidget(desc); l.addStretch()
            button = self._action_button("اجرا", "Run", "play", "toolAction"); button.setEnabled(available); button.clicked.connect(action); l.addWidget(button)
            self.tool_cards.append(box)
        self._layout_tool_cards(self.width() < 1180)
        root.addLayout(self.tools_grid); root.addStretch(); return page

    def _layout_tool_cards(self, compact):
        if not hasattr(self, "tools_grid"):
            return
        while self.tools_grid.count(): self.tools_grid.takeAt(0)
        columns = 1 if compact else 2
        for index, box in enumerate(self.tool_cards): self.tools_grid.addWidget(box, index // columns, index % columns)

    def _support_page(self):
        page, body = self._scroll_page(); root = QVBoxLayout(body); root.setContentsMargins(34, 28, 34, 26); root.setSpacing(16)
        root.addWidget(self._page_header("پشتیبانی و بروزرسانی", "Support & Updates", "UAC Spoofer Desktop — سازگار با کانفیگ‌های نسخه موبایل", "Help, project resources and trusted support channels"))
        hero = MotionFrame(); hero.setObjectName("supportHero"); hero_layout = QHBoxLayout(hero); hero_layout.setContentsMargins(24, 22, 24, 22); hero_layout.setSpacing(20)
        icon_box = QLabel(); icon_box.setObjectName("supportIcon"); icon_box.setFixedSize(72, 72); icon_box.setPixmap(cyber_pixmap("shield", "#23f5e0", 38)); hero_layout.addWidget(icon_box)
        copy_box = QVBoxLayout(); support_title = self._bind_text(QLabel(), "پشتیبانی رسمی UAC Spoofer", "Official UAC Spoofer Support"); support_title.setObjectName("supportTitle"); support_desc = self._bind_text(QLabel(), "برای خبرهای نسخه، راهنما و ارتباط با جامعه از کانال‌های رسمی استفاده کنید.", "Use the official channels for release news, help and community updates."); support_desc.setObjectName("supportDescription"); support_desc.setWordWrap(True); support_desc.setTextInteractionFlags(Qt.TextSelectableByMouse); copy_box.addWidget(support_title); copy_box.addWidget(support_desc); hero_layout.addLayout(copy_box, 1)
        actions = QVBoxLayout(); github = self._action_button("پروژه GitHub", "GitHub Project", "external-link", "primaryAction"); github.clicked.connect(lambda: webbrowser.open(self.storage.settings.get("update_repo_url", DEFAULT_UPDATE_REPO_URL))); telegram = self._action_button("کانال تلگرام", "Telegram Channel", "external-link", "secondaryAction"); telegram.clicked.connect(lambda: webbrowser.open("https://t.me/UacSniSpoofer")); actions.addWidget(github); actions.addWidget(telegram); hero_layout.addLayout(actions); root.addWidget(hero)

        self.update_card = MotionFrame(); self.update_card.setObjectName("updateCard"); self.update_card.setProperty("state", "idle")
        update_layout = QHBoxLayout(self.update_card); update_layout.setContentsMargins(20, 17, 20, 17); update_layout.setSpacing(16)
        update_icon = QLabel(); update_icon.setObjectName("updateIcon"); update_icon.setFixedSize(48, 48); update_icon.setPixmap(cyber_pixmap("refresh", "#23f5e0", 25)); update_layout.addWidget(update_icon)
        update_copy = QVBoxLayout(); update_copy.setSpacing(4)
        update_title = self._bind_text(QLabel(), "بروزرسانی برنامه", "Application Update"); update_title.setObjectName("updateTitle")
        self.update_status = QLabel(self.tr("برای بررسی نسخه آماده است", "Ready to check for updates")); self.update_status.setObjectName("updateStatus"); self.update_status.setWordWrap(True)
        self.update_versions = QLabel(self.tr(f"نصب‌شده: {ltr_isolate(__version__)}  •  آخرین نسخه: —", f"Installed: {__version__}  •  Latest: —")); self.update_versions.setObjectName("updateVersions")
        update_copy.addWidget(update_title); update_copy.addWidget(self.update_status); update_copy.addWidget(self.update_versions); update_layout.addLayout(update_copy, 1)
        update_actions = QVBoxLayout(); update_actions.setSpacing(7)
        self.update_check_button = self._action_button("بررسی دوباره", "Check Again", "refresh", "secondaryAction"); self.update_check_button.clicked.connect(lambda: self.check_for_updates(manual=True))
        self.update_download_button = self._action_button("دریافت بروزرسانی", "Download Update", "download", "primaryAction"); self.update_download_button.setEnabled(False); self.update_download_button.clicked.connect(self._open_latest_update)
        update_actions.addWidget(self.update_check_button); update_actions.addWidget(self.update_download_button); update_layout.addLayout(update_actions); root.addWidget(self.update_card)
        info_grid = QGridLayout(); info_grid.setSpacing(14)
        support_cards = [
            ("activity", "مشکل اتصال دارید؟", "Connection problem?", "ابتدا Activity Bar و سپس Live Logs را بررسی کنید؛ خطای واقعی مسیر همان‌جا نمایش داده می‌شود.", "Check the Activity Bar first, then Live Logs for the real route error."),
            ("database", "کانفیگ پیشنهادی", "Suggested configs", "در صفحه Configs همگام‌سازی را اجرا کنید؛ بهترین نتایج تست‌شده در بالای فهرست قرار می‌گیرند.", "Run Sync in Configs; verified, best-scored profiles are ranked first."),
            ("flask", "بهترین SNI", "Best SNI", "SNI Lab فقط نتیجه‌های واقعی اسکن را ذخیره می‌کند و برای اتصال خودکار پیشنهاد می‌دهد.", "SNI Lab stores real scan results and makes them available to Auto Mode."),
        ]
        for index, (icon_name, fa_title, en_title, fa_body, en_body) in enumerate(support_cards):
            box = MotionFrame(); box.setObjectName("helpCard"); l = QVBoxLayout(box); l.setContentsMargins(18, 17, 18, 17); l.setSpacing(9); icon_label = QLabel(); icon_label.setObjectName("helpIcon"); icon_label.setPixmap(cyber_pixmap(icon_name, "#2cc7ff", 23)); icon_label.setFixedSize(38, 38); icon_label.setAlignment(Qt.AlignCenter); title = self._bind_text(QLabel(), fa_title, en_title); title.setObjectName("helpTitle"); text = self._bind_text(QLabel(), fa_body, en_body); text.setObjectName("helpText"); text.setWordWrap(True); text.setTextInteractionFlags(Qt.TextSelectableByMouse); l.addWidget(icon_label); l.addWidget(title); l.addWidget(text); l.addStretch(); info_grid.addWidget(box, 0, index)
        root.addLayout(info_grid); credits = QLabel(f"UAC Spoofer Desktop {__version__}  •  Credits to behroozuac"); credits.setObjectName("credits"); credits.setAlignment(Qt.AlignCenter); credits.setLayoutDirection(Qt.LeftToRight); root.addWidget(credits); root.addStretch(); return page

    def _wire(self):
        self.bridge.log.connect(self._append_log); self.bridge.state.connect(self._set_state); self.bridge.traffic.connect(self._set_traffic); self.bridge.latency.connect(self._set_latency); self.bridge.scan_progress.connect(self._scan_progress); self.bridge.scan_done.connect(self._scan_done); self.bridge.scan_failed.connect(self._scan_failed); self.bridge.error.connect(self._handle_error); self.bridge.profiles_changed.connect(self.refresh_profiles); self.bridge.ip.connect(self._ip_checked); self.bridge.hint.connect(self.connection_hint.setText); self.bridge.activity.connect(self.activity_bar.set_activity); self.bridge.processes.connect(self._populate_processes); self.bridge.update_checked.connect(self._update_checked); self.bridge.update_failed.connect(self._update_failed)
        self.connect_button.clicked.connect(self.toggle_connection); self.add_btn.clicked.connect(self.add_profile); self.edit_btn.clicked.connect(self.edit_profile); self.delete_btn.clicked.connect(self.delete_profile); self.clip_btn.clicked.connect(self.import_clipboard); self.sync_btn.clicked.connect(self.sync_profiles); self.scan_button.clicked.connect(self.toggle_scan); self.bookmark_btn.clicked.connect(self.bookmark_selected); self.apply_sni_btn.clicked.connect(self.apply_selected_sni); self.apply_all_sni_btn.clicked.connect(self.apply_sni_to_all_suggested); self.undo_apply_btn.clicked.connect(self.undo_sni_apply); self.copy_result_btn.clicked.connect(self.copy_selected_result); self.carrier.currentTextChanged.connect(self._carrier_changed); self.auto_mode.toggled.connect(lambda v: self._save_flag("auto_mode", v)); self.pick_best.toggled.connect(lambda v: self._save_flag("pick_best", v)); self.close_to_tray.toggled.connect(self._set_close_to_tray)
        self.manual_list.itemClicked.connect(self._profile_clicked); self.suggested_list.itemClicked.connect(self._profile_clicked)
        self.scan_tabs.currentChanged.connect(self._update_scan_selection)

    def _setup_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        icon = QApplication.windowIcon()
        if icon.isNull():
            icon = cyber_icon("shield", "#23f5e0", 24)
        self._tray = QSystemTrayIcon(icon, self)
        self._tray_menu = QMenu()
        self.tray_show_action = QAction(self._tray_menu)
        self.tray_show_action.setIcon(cyber_icon("home", "#23f5e0", 18))
        self.tray_show_action.triggered.connect(self._restore_from_tray)
        self._tray_menu.addAction(self.tray_show_action)
        self._tray_menu.addSeparator()
        self.tray_quit_action = QAction(self._tray_menu)
        self.tray_quit_action.setIcon(cyber_icon("power", "#ff7891", 18))
        self.tray_quit_action.triggered.connect(self._quit_from_tray)
        self._tray_menu.addAction(self.tray_quit_action)
        self._tray.setContextMenu(self._tray_menu)
        self._tray.activated.connect(self._tray_activated)
        self._update_tray_text()
        self._tray.setVisible(self.close_to_tray.isChecked())

    def _update_tray_text(self):
        if self._tray is None:
            return
        if self.tray_show_action is not None:
            self.tray_show_action.setText(self.tr("نمایش برنامه", "Show App"))
        if self.tray_quit_action is not None:
            self.tray_quit_action.setText(self.tr("خروج کامل", "Quit"))
        self._tray.setToolTip(self.tr("UAC Spoofer Desktop — در حال اجرا", "UAC Spoofer Desktop — Running"))

    def _set_close_to_tray(self, enabled):
        self._save_flag("close_to_tray", bool(enabled))
        if self._tray is not None:
            self._tray.setVisible(bool(enabled))
        if not enabled and not self.isVisible():
            self._restore_from_tray()

    def _tray_activated(self, reason):
        if reason in (QSystemTrayIcon.ActivationReason.Trigger,
                      QSystemTrayIcon.ActivationReason.DoubleClick):
            self._restore_from_tray()

    def _restore_from_tray(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _quit_from_tray(self):
        self._force_quit = True
        self.close()
        app = QApplication.instance()
        if app is not None:
            app.quit()

    def show_page(self, index):
        previous_index = self.stack.currentIndex()
        if self._page_animation is not None:
            self._page_animation.stop()
        if self._animated_page is not None:
            self._animated_page.setGraphicsEffect(None)
            self._animated_page = None
        self.stack.setCurrentIndex(index)
        for i, button in enumerate(self.nav):
            active = i == index
            button.setChecked(active)
            button.setIcon(cyber_icon(button.property("iconName"), "#23f5e0" if active else "#9fb4d8", 22))
        if _animations_enabled():
            page = self.stack.currentWidget()
            effect = QGraphicsOpacityEffect(page); page.setGraphicsEffect(effect); effect.setOpacity(0.0)
            end_position = page.pos()
            direction = -1 if index < previous_index else 1
            start_position = end_position + QPoint(direction * 26, 7)
            page.move(start_position)
            group = QParallelAnimationGroup(self)
            fade = QPropertyAnimation(effect, b"opacity", group); fade.setDuration(360); fade.setStartValue(0.0); fade.setEndValue(1.0); fade.setEasingCurve(QEasingCurve.OutCubic)
            slide = QPropertyAnimation(page, b"pos", group); slide.setDuration(430); slide.setStartValue(start_position); slide.setEndValue(end_position); slide.setEasingCurve(QEasingCurve.OutExpo)
            group.addAnimation(fade); group.addAnimation(slide)

            def finish_page_transition(target=page, target_position=end_position):
                target.move(target_position)
                target.setGraphicsEffect(None)
                if self._animated_page is target:
                    self._animated_page = None

            group.finished.connect(finish_page_transition)
            self._animated_page = page
            self._page_animation = group
            group.start()

    def _update_config_actions(self, *_):
        if not hasattr(self, "profile_tabs"):
            return
        selected = self.selected_profile_item() is not None
        self.edit_btn.setEnabled(selected)
        self.delete_btn.setEnabled(selected)

    def _set_activity(self, persian, english, state="running", busy=True):
        self.activity_bar.set_activity(self.tr(persian, english), state, busy)

    def _handle_error(self, message):
        was_connecting = self.connecting
        if was_connecting:
            self.connection_error = str(message)
            self.connecting = False
            self._set_connection_visual("error")
        self.sync_btn.setEnabled(True)
        self.ip_button.setEnabled(True)
        self.process_refresh_btn.setEnabled(True)
        self.activity_bar.set_activity(str(message), "error", False)
        self.show_toast(str(message), "danger")

    def _ip_checked(self, value):
        self.ip_label.setText(value)
        self.ip_button.setEnabled(True)
        self._set_activity("آی‌پی عمومی دریافت شد.", "Public IP check completed.", "success", False)

    def _configure_technical_widgets(self):
        widgets = [self.route_detail, self.ping_label, self.up_label, self.down_label, self.ip_label,
                   self.logs, self.domains, self.carrier, self.log_filter, self.process_search]
        for widget in widgets:
            widget.setLayoutDirection(Qt.LeftToRight)
            widget.setProperty("technical", True)
            if isinstance(widget, QLabel): widget.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        # Persian tables keep their controls/header flow RTL. Only the actual
        # technical cell values are left-aligned/LTR-friendly.
        table_direction = Qt.LeftToRight if self.language == "en" else Qt.RightToLeft
        for table in (self.results_table, self.bookmarks_table, self.process_table):
            table.setLayoutDirection(table_direction)
            table.setProperty("technical", True)

    def tr(self, persian: str, english: str | None = None) -> str:
        return (english or FA_EN.get(persian, persian)) if self.language == "en" else persian

    def toggle_language(self):
        self.language = "en" if self.language == "fa" else "fa"
        self.storage.settings["language"] = self.language
        self.storage.save_settings()
        self._apply_language()

    def _apply_language(self):
        direction = Qt.LeftToRight if self.language == "en" else Qt.RightToLeft
        self.setLayoutDirection(direction)
        self.sidebar.setProperty("rtl", self.language != "en"); _restyle(self.sidebar)
        for widget_type in (QLabel, QPushButton, QCheckBox):
            for widget in self.findChildren(widget_type):
                fa = widget.property("i18nFa"); en = widget.property("i18nEn")
                if fa is not None and en is not None:
                    widget.setText(str(en) if self.language == "en" else str(fa))
        mapping = FA_EN if self.language == "en" else EN_FA
        for widget_type in (QLabel, QPushButton, QCheckBox):
            for widget in self.findChildren(widget_type):
                text = widget.text()
                if text in mapping:
                    widget.setText(mapping[text])
        for tabs in self.findChildren(QTabWidget):
            for index in range(tabs.count()):
                text = tabs.tabText(index)
                if text in mapping:
                    tabs.setTabText(index, mapping[text])
        for table in self.findChildren(QTableWidget):
            for column in range(table.columnCount()):
                item = table.horizontalHeaderItem(column)
                if item and item.text() in mapping:
                    item.setText(mapping[item.text()])
        self.profile_tabs.setTabText(0, self.tr("دستی", "Manual")); self.profile_tabs.setTabText(1, self.tr("پیشنهادی", "Suggested"))
        self.scan_tabs.setTabText(0, self.tr("نتایج", "Results")); self.scan_tabs.setTabText(1, self.tr("ذخیره‌شده", "Saved"))
        result_headers = (["", "Domain", "IP", "Colo", "Ping", "Stability", "First byte", "Bytes/2s", "Score"] if self.language == "en" else ["", "دامنه", "IP", "Colo", "پینگ", "پایداری", "اولین بایت", "بایت/۲ثانیه", "امتیاز"])
        for table in (self.results_table, self.bookmarks_table): table.setHorizontalHeaderLabels(result_headers)
        self.process_table.setHorizontalHeaderLabels([self.tr(f"خارج از {ltr_isolate('VPN')}", "Bypass VPN"), self.tr("پردازه", "Process")])
        for index, (button, (icon_name, persian, english)) in enumerate(zip(self.nav, self.nav_meta)):
            button.setText(english if self.language == "en" else persian)
            button.setProperty("rtl", self.language != "en"); _restyle(button)
            button.setIcon(cyber_icon(icon_name, "#23f5e0" if index == self.stack.currentIndex() else "#9fb4d8", 22))
        self.language_button.setText("فارسی" if self.language == "en" else "English")
        self.data_button.setText(self.tr("باز کردن پوشه داده‌ها", "Open Data Folder"))
        self._update_tray_text()
        self.status_pill.set_language(self.language); self.activity_bar.set_language(self.language)
        if not self.scanning: self.scan_progress.set_language(self.language)
        if self._latest_update:
            self._render_update_info(self._latest_update)
        elif not self._update_in_progress:
            self.update_status.setText(self.tr("برای بررسی نسخه آماده است", "Ready to check for updates"))
            self.update_versions.setText(self.tr(f"نصب‌شده: {ltr_isolate(__version__)}  •  آخرین نسخه: —", f"Installed: {__version__}  •  Latest: —"))
        self.manual_list.set_empty_text(self.tr("هنوز کانفیگ دستی ندارید", "No manual configs yet"), self.tr("یک لینک VLESS یا Trojan اضافه یا از Clipboard وارد کنید.", "Add a VLESS or Trojan link, or import one from the clipboard."))
        self.suggested_list.set_empty_text(self.tr("هنوز پیشنهادی دریافت نشده", "No suggestions downloaded"), self.tr("برای دریافت فهرست پیشنهادی، همگام‌سازی را اجرا کنید.", "Sync the suggested repository to populate this list."))
        self.log_filter.setPlaceholderText(self.tr("فیلتر لاگ‌ها…", "Filter logs…")); self.process_search.setPlaceholderText(self.tr("جستجوی پردازه…", "Search processes…"))
        self._update_process_count()
        self._set_log_count(len(self._all_log_lines))
        if not self.activity_bar.busy: self.activity_bar.set_activity("", "idle", False)
        hero_alignment = (Qt.AlignLeft | Qt.AlignAbsolute) if self.language == "en" else (Qt.AlignRight | Qt.AlignAbsolute)
        self.status.setAlignment(hero_alignment | Qt.AlignVCenter); self.connection_hint.setAlignment(hero_alignment | Qt.AlignVCenter); self.hero_badge.setAlignment(hero_alignment | Qt.AlignVCenter); self.hero_copy_layout.setAlignment(self.connect_button, hero_alignment)
        if self.connecting:
            self._set_connection_visual("connecting")
        elif self.connection_error and not self.engine.running:
            self._set_connection_visual("error")
        else:
            self._set_state(self.engine.running)
        if self.scanning:
            self.scan_button.setText(self.tr("توقف اسکن", "Stop Scan"))
        else:
            self.scan_button.setText(self.tr("شروع اسکن", "Start Scan"))
        self._configure_technical_widgets()
        self._layout_hero(self.width() < 1050)
        self.refresh_profiles()
        self._update_scan_selection()

    def _save_flag(self, key, value): self.storage.settings[key] = value; self.storage.save_settings()

    def _carrier_changed(self, carrier):
        tuning = self.storage.activate_carrier(carrier)
        self.bridge.log.emit(
            f"CARRIER PROFILE active={carrier} edge={tuning.pattern_connect_ip} "
            f"fakeSni={tuning.pattern_fake_sni} sessions={tuning.pattern_max_sessions}")
        self.refresh_profiles()

    def refresh_profiles(self):
        self.manual_list.clear(); self.suggested_list.clear()
        self.sync_btn.setEnabled(True)
        carrier = self.storage.tuning.carrier_mode
        benchmarks = self.storage.settings.get(f"profile_benchmarks_pattern_{carrier}", {})
        benchmarks = benchmarks if isinstance(benchmarks, dict) else {}
        def benchmark_rank(profile):
            value = benchmarks[profile.id]
            if carrier == "mci":
                return (value.get("download_ok") is not True,
                        -float(value.get("score", 0)),
                        float(value.get("download_first_byte_ms", 999999) or 999999),
                        -float(value.get("download_mbps", 0) or 0),
                        float(value.get("startup_ms", 999999)))
            # Keep IranCell's existing upload/startup ordering byte-for-byte.
            return (value.get("upload_ok") is not True,
                    -float(value.get("score", 0)),
                    float(value.get("startup_ms", 999999)))
        ranked_ids = [profile.id for profile in sorted(
            (p for p in self.storage.profiles if p.origin != "user"
             and benchmarks.get(p.id, {}).get("ok")
             and benchmarks.get(p.id, {}).get("engine") == "patterniha-wrong-seq-v1"),
            key=benchmark_rank)]
        profiles = sorted(self.storage.profiles, key=lambda p: (
            p.origin != "user",
            ranked_ids.index(p.id) if p.id in ranked_ids else 999,
            not p.last_ping_ok,
            p.last_ping_ms if p.last_ping_ok else 999999,
        ))
        for profile in profiles:
            benchmark = benchmarks.get(profile.id, {})
            recommendation = ""
            if profile.id in ranked_ids[:3]:
                rank = ranked_ids.index(profile.id) + 1
                startup_ms = float(benchmark.get("startup_ms", 0))
                upload_mbps = float(benchmark.get("upload_mbps", 0))
                score = int(benchmark.get("score", 0))
                tag = f"BEST #{rank}" if self.language == "en" else f"پیشنهاد برتر #{rank}"
                if carrier == "mci" and benchmark.get("download_ok") is True:
                    download_mbps = float(benchmark.get("download_mbps", 0) or 0)
                    video_start_ms = float(benchmark.get("download_first_byte_ms", 0) or 0)
                    quality_text = f"↓ {download_mbps:.2f} Mbps · Start {video_start_ms / 1000:.2f}s"
                elif carrier == "mci":
                    quality_text = self.tr("سرعت دانلود در حال ارزیابی", "download pending")
                elif benchmark.get("upload_ok") is True and benchmark.get("upload_speed_valid"):
                    quality_text = f"↑ {upload_mbps:.2f} Mbps"
                elif benchmark.get("upload_ok") is True:
                    quality_text = self.tr("آپلود تایید شد", "upload verified")
                else:
                    quality_text = self.tr("آپلود در حال ارزیابی", "upload pending")
                startup_label = "Page" if carrier == "mci" else "YouTube"
                recommendation = f"{tag}  ·  Score {score}  ·  {startup_label} {startup_ms / 1000:.2f}s  ·  {quality_text}\n"
            endpoint = f"\u2066{profile.target_label}\u2069"
            item = QListWidgetItem(f"{recommendation}{profile.name}\n{endpoint}"); item.setData(Qt.UserRole, profile.id); item.setSizeHint(item.sizeHint().expandedTo(item.sizeHint() + QSize(0, 42 if recommendation else 30)))
            item.setIcon(cyber_icon("file-cog" if profile.origin == "user" else "server", "#23f5e0" if profile.id == self.storage.selected_id else "#6f91b5", 20))
            if recommendation:
                if carrier == "mci":
                    quality_tip = (f"download {float(benchmark.get('download_mbps', 0) or 0):.2f} Mbps · "
                                   f"first-byte {float(benchmark.get('download_first_byte_ms', 0) or 0):.0f} ms · "
                                   f"state {benchmark.get('download_state', 'not tested')}")
                else:
                    quality_tip = f"upload {benchmark.get('upload_state', 'not tested')}"
                startup_label = "Page" if carrier == "mci" else "YouTube"
                item.setToolTip(f"Patterniha real test · Fake SNI {benchmark.get('fake_sni', '—')} · {startup_label} {float(benchmark.get('startup_ms', 0)):.0f} ms · {quality_tip} · strategy={benchmark.get('strategy', 'wrong_seq')}")
            target = self.manual_list if profile.origin == "user" else self.suggested_list; target.addItem(item)
            if profile.id == self.storage.selected_id: target.setCurrentItem(item)
        self.config_count_label.setText(self.tr(f"{len(self.storage.profiles)} کانفیگ", f"{len(self.storage.profiles)} configs"))
        selected = self.storage.selected(); self.active_profile.setText(selected.name if selected else self.tr("کانفیگی انتخاب نشده", "No config selected")); self.route_card.set_secondary(selected.target_label if selected else "")
        if selected:
            self.ping_label.setText(f"{selected.last_ping_ms:.0f} ms" if selected.last_ping_ok else "—")
            if selected.last_ping_ok: self.latency_card.sparkline.add_value(selected.last_ping_ms)
        else:
            self.ping_label.setText("—")
        self._update_config_actions()

    def selected_profile_item(self):
        widget = self.manual_list if self.profile_tabs.currentIndex() == 0 else self.suggested_list
        return widget.currentItem()

    def select_profile_from_list(self):
        item = self.selected_profile_item()
        if item: self.storage.selected_id = item.data(Qt.UserRole); self.refresh_profiles()

    def _profile_clicked(self, item):
        self.storage.selected_id = item.data(Qt.UserRole)
        selected = self.storage.selected()
        if selected:
            self.active_profile.setText(selected.name); self.route_card.set_secondary(selected.target_label)
            self.ping_label.setText(f"{selected.last_ping_ms:.0f} ms" if selected.last_ping_ok else "—")
            if selected.last_ping_ok: self.latency_card.sparkline.add_value(selected.last_ping_ms)
        self._update_config_actions()

    def add_profile(self):
        dialog = ProfileDialog(self, language=self.language)
        if dialog.exec():
            profile = dialog.result_profile()
            if not profile: self.show_toast(self.tr("لینک VLESS یا Trojan معتبر نیست", "The VLESS or Trojan link is invalid"), "danger"); return
            self.storage.profiles.append(profile); self.storage.selected_id = profile.id; self.storage.save_profiles(); self.refresh_profiles(); self._set_activity("کانفیگ ذخیره شد.", "Config saved.", "success", False)

    def edit_profile(self):
        item = self.selected_profile_item()
        if not item: return
        profile = next((x for x in self.storage.profiles if x.id == item.data(Qt.UserRole)), None)
        if not profile: return
        dialog = ProfileDialog(self, profile, self.language)
        if dialog.exec() and dialog.result_profile(): self.storage.selected_id = profile.id; self.storage.save_profiles(); self.refresh_profiles(); self._set_activity("تغییرات کانفیگ ذخیره شد.", "Config changes saved.", "success", False)

    def delete_profile(self):
        item = self.selected_profile_item()
        if not item or QMessageBox.question(self, self.tr("حذف کانفیگ", "Delete Config"), self.tr("این کانفیگ حذف شود؟ این عمل قابل بازگشت نیست.", "Delete this config? This action cannot be undone."), QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes: return
        self.storage.profiles = [x for x in self.storage.profiles if x.id != item.data(Qt.UserRole)]; self.storage.save_profiles(); self.refresh_profiles(); self._set_activity("کانفیگ حذف شد.", "Config deleted.", "success", False)

    def import_clipboard(self):
        self._set_activity("در حال وارد کردن کانفیگ…", "Importing config…")
        profiles = parse_many(QApplication.clipboard().text())
        if not profiles: self._handle_error(self.tr("کانفیگ معتبری در Clipboard پیدا نشد", "No valid config was found in the clipboard")); return
        existing = {x.source_uri.split("#")[0] for x in self.storage.profiles}; profiles = [x for x in profiles if x.source_uri.split("#")[0] not in existing]
        self.storage.profiles.extend(profiles); self.storage.save_profiles(); self.refresh_profiles(); self.show_toast(self.tr(f"{len(profiles)} کانفیگ اضافه شد", f"Added {len(profiles)} config(s)"), "success"); self._set_activity("ورود کانفیگ کامل شد.", "Config import completed.", "success", False)

    def sync_profiles(self):
        self.sync_btn.setEnabled(False); self._set_activity("در حال دریافت کانفیگ‌های پیشنهادی…", "Syncing suggested configs…")
        def work():
            try:
                text = requests.get(REMOTE_CONFIGS_URL, timeout=15).text; items = parse_many(text, suggested=True); existing = {x.source_uri.split('#')[0] for x in self.storage.profiles}; added = 0
                self.storage.profiles = [x for x in self.storage.profiles if x.origin != "github"]
                for item in items:
                    if item.source_uri.split('#')[0] not in existing: item.origin = "github"; item.name = "GitHub " + item.name; self.storage.profiles.append(item); added += 1
                self.storage.save_profiles(); self.bridge.profiles_changed.emit(); self.bridge.log.emit(f"Suggested configs synced: {added}"); self.bridge.activity.emit(self.tr(f"همگام‌سازی کامل شد؛ {added} کانفیگ اضافه شد.", f"Sync complete; {added} config(s) added."), "success", False)
            except Exception as exc: self.bridge.error.emit(str(exc))
        threading.Thread(target=work, daemon=True).start()

    def _begin_connect_attempt(self):
        self._connect_cancel.set()
        self._connect_generation += 1
        self._connect_cancel = threading.Event()
        return self._connect_generation, self._connect_cancel

    def _attempt_cancelled(self, generation, cancel):
        return self._closing or cancel.is_set() or generation != self._connect_generation

    def _cancel_connect_attempt(self, wait=False, notify=False):
        self._connect_generation += 1
        self._connect_cancel.set()
        self.engine.stop(notify=notify)
        worker = self._connect_thread
        if wait and worker and worker is not threading.current_thread():
            worker.join(timeout=3)

    def _profile_mux_enabled(self, profile, tuning, carrier=None) -> bool:
        """Use a fresh route-specific compatibility result without changing Advanced."""
        if not tuning.xray_mux_enabled:
            return False
        carrier = carrier or tuning.carrier_mode
        scoped = self.storage.settings.get("profile_mux_compatibility_by_carrier", {})
        bucket = scoped.get(carrier, {}) if isinstance(scoped, dict) else {}
        entry = bucket.get(profile.id, {}) if isinstance(bucket, dict) else {}
        if not isinstance(entry, dict):
            return True
        signature = profile.source_uri or f"{profile.protocol}:{profile.config_host}:{profile.config_port}"
        fresh = time.time() - float(entry.get("tested_at", 0) or 0) < 7 * 24 * 3600
        same_route = entry.get("edge") == tuning.pattern_connect_ip
        if fresh and same_route and entry.get("signature") == signature and entry.get("compatible") is False:
            return False
        return True

    def _remember_profile_mux(self, profile, compatible: bool, tuning, carrier=None) -> None:
        carrier = carrier or tuning.carrier_mode
        scoped = self.storage.settings.get("profile_mux_compatibility_by_carrier", {})
        scoped = dict(scoped) if isinstance(scoped, dict) else {}
        bucket = scoped.get(carrier, {})
        bucket = dict(bucket) if isinstance(bucket, dict) else {}
        signature = profile.source_uri or f"{profile.protocol}:{profile.config_host}:{profile.config_port}"
        live_edge = str(getattr(getattr(self, "engine", None), "fragment", None).active_edge or "").strip() \
            if getattr(getattr(self, "engine", None), "fragment", None) is not None else ""
        bucket[profile.id] = {
            "compatible": bool(compatible),
            "tested_at": time.time(),
            "signature": signature,
            "edge": live_edge or tuning.pattern_connect_ip,
        }
        scoped[carrier] = bucket
        self.storage.settings["profile_mux_compatibility_by_carrier"] = scoped

    def _sni_candidates(self, profile=None, carrier=None, limit=3):
        """Return only successful, persisted SNI-Lab measurements."""
        carrier = carrier or self.storage.tuning.carrier_mode
        merged = {}
        now = time.time()

        def carrier_rank(value):
            value = str(value or "").strip().lower()
            selected = str(carrier or "").strip().lower()
            if selected in {"", "auto"}:
                return 0 if value in {"", "auto"} else 1
            if value == selected:
                return 0
            if value in {"", "auto"}:
                return 1
            return 2

        def measurement_rank(raw):
            tested_at = float(raw.get("tested_at", 0) or 0)
            stale = now - tested_at > 7 * 24 * 3600
            return (
                carrier_rank(raw.get("carrier", "")), stale,
                -float(raw.get("score", -9999)),
                -float(raw.get("stability", 0)),
                float(raw.get("first_byte_ms", 99999)),
                float(raw.get("ping_ms", 99999)),
                -tested_at,
            )

        for raw in [*self.storage.scan_results, *self.storage.bookmarks]:
            if not isinstance(raw, dict) or not raw.get("success", True):
                continue
            domain = str(raw.get("domain", "")).strip().lower()
            try:
                encoded = domain.encode("idna")
            except UnicodeError:
                continue
            if not domain or b"." not in encoded or len(encoded) > 219:
                continue
            old = merged.get(domain)
            if old is None or measurement_rank(raw) < measurement_rank(old):
                merged[domain] = raw
        ranked = sorted(merged, key=lambda domain: (*measurement_rank(merged[domain]), domain))

        candidates = []
        def add(value):
            value = str(value or "").strip().lower()
            if value in merged and value not in candidates:
                candidates.append(value)

        scoped_pins = self.storage.settings.get("pattern_profile_sni_pins_by_carrier", {})
        pins = scoped_pins.get(carrier, {}) if isinstance(scoped_pins, dict) else {}
        if not isinstance(pins, dict):
            pins = {}
        legacy_active = str(getattr(self.storage.tuning, "carrier_mode", "auto") or "auto")
        if not pins and carrier == legacy_active:
            # Storage migrates these into only the active carrier. Keep this
            # read fallback for an already-open legacy settings object.
            legacy_pins = self.storage.settings.get("pattern_profile_sni_pins", {})
            pins = legacy_pins if isinstance(legacy_pins, dict) else {}
        scoped_globals = self.storage.settings.get("pattern_global_sni_pin_by_carrier", {})
        global_pin = scoped_globals.get(carrier) if isinstance(scoped_globals, dict) else None
        if not global_pin and carrier == legacy_active:
            global_pin = self.storage.settings.get("pattern_global_sni_pin")
        if profile is not None:
            add(pins.get(profile.id))
        else:
            add(global_pin)
        remembered = self.storage.settings.get(f"working_pattern_sni_{carrier}", "")
        remembered_at = float(self.storage.settings.get(f"working_pattern_sni_at_{carrier}", 0) or 0)
        if remembered and time.time() - remembered_at < 7 * 24 * 3600:
            add(remembered)
        # A recently verified real-page route must precede a newer lab score.
        # This avoids spending several full timeouts on unproven SNI candidates
        # every time the user reconnects.
        if ranked:
            add(ranked[0])
        for domain in ranked:
            add(domain)
        if not candidates:
            configured = str(getattr(self.storage.tuning, "pattern_fake_sni", "") or "").strip().lower()
            try:
                encoded = configured.encode("idna")
            except UnicodeError:
                encoded = b""
            if configured and b"." in encoded and len(encoded) <= 219:
                candidates.append(configured)
        return candidates[:max(1, limit)]

    def _verified_route_result(self, domain, carrier):
        candidates = []
        for raw in [*self.storage.scan_results, *self.storage.bookmarks]:
            if not isinstance(raw, dict) or not raw.get("success", True):
                continue
            if str(raw.get("domain", "")).strip().lower() != str(domain).strip().lower():
                continue
            if str(raw.get("carrier", "")) != carrier or not raw.get("edge_verified", False):
                continue
            try:
                candidates.append(ScanResult(**raw))
            except TypeError:
                continue
        return max(candidates, key=lambda result: (result.score, result.stability, -result.first_byte_ms), default=None)

    def _ordered_profiles(self, fake_sni, cancel_event, auto_enabled=True, manual_only=False):
        candidates = self.storage.profiles if auto_enabled else [self.storage.selected()]
        candidates = [x for x in candidates if x]
        if manual_only:
            candidates = [x for x in candidates if x.origin == "user"] or candidates
        if cancel_event.is_set():
            raise EngineCancelled("Connection attempt cancelled")
        tuning = self.storage.tuning
        ping_host = tuning.pattern_connect_ip or "104.18.32.47"
        # Every profile uses the same Pattern edge and port. Probe it once;
        # the old six identical concurrent TLS pings delayed connect and loaded NAT.
        ok, latency = profile_ping(ping_host, 443, fake_sni, 3.5)
        self.bridge.log.emit(f"PATTERN EDGE PING 1/1 {ping_host}:443 sni={fake_sni} => {'OK' if ok else 'FAIL'}")
        if ok and latency > 0:
            latency_signal = getattr(self.bridge, "latency", None)
            if latency_signal is not None:
                latency_signal.emit(latency, "edge")
        for profile in candidates:
            profile.last_ping_ok = ok
            profile.last_ping_ms = latency
        self.storage.save_profiles()
        if cancel_event.is_set():
            raise EngineCancelled("Connection attempt cancelled")
        carrier = tuning.carrier_mode
        remembered_id = self.storage.settings.get(f"working_profile_{carrier}")
        benchmarks = self.storage.settings.get(f"profile_benchmarks_pattern_{carrier}", {})
        benchmarks = benchmarks if isinstance(benchmarks, dict) else {}
        now = time.time()
        def quality(profile):
            result = benchmarks.get(profile.id, {})
            fresh = now - float(result.get("tested_at", 0)) < 24 * 3600
            page_ok = (bool(result.get("ok")) and result.get("engine") == "patterniha-wrong-seq-v1" and fresh)
            if carrier == "mci":
                download_fresh = now - float(result.get("download_tested_at", 0) or 0) < 6 * 3600
                download_verified = result.get("download_ok") is True and download_fresh
                download_mbps = float(result.get("download_mbps", 0) or 0)
                benchmark_known = bool(result) and result.get("engine") == "patterniha-wrong-seq-v1"
                download_failed = (result.get("download_ok") is False
                                   or result.get("download_state") == "failed")
                # This tier is intentionally global rather than nested under
                # page_ok: an untested profile gets one chance before a route
                # that was freshly measured below 1 Mbps.
                if page_ok and download_verified and download_mbps >= 1.0:
                    tier = 0
                elif page_ok and not download_verified and not download_failed:
                    tier = 1
                elif not benchmark_known or not fresh:
                    tier = 2
                elif page_ok and download_verified:
                    tier = 3
                else:
                    tier = 4
                return (tier,
                        -float(result.get("score", 0)) if page_ok else 0,
                        float(result.get("download_first_byte_ms", 999999) or 999999),
                        -download_mbps, profile.id != remembered_id,
                        not profile.last_ping_ok,
                        profile.last_ping_ms if profile.last_ping_ok else 999999)
            upload_rank = 0 if result.get("upload_ok") is True else 1 if result.get("upload_ok") is None else 2
            return (not page_ok, upload_rank if page_ok else 3,
                    -float(result.get("score", 0)) if page_ok else 0, profile.id != remembered_id,
                    not profile.last_ping_ok, profile.last_ping_ms if profile.last_ping_ok else 999999)
        return sorted(candidates, key=quality)

    def _save_profile_benchmark(self, profile, strategy, page_ok, upload_state=None,
                                fake_sni="", count_page_sample=True, carrier=None,
                                download_state=None):
        carrier = carrier or self.storage.tuning.carrier_mode
        key = f"profile_benchmarks_pattern_{carrier}"
        values = self.storage.settings.get(key, {})
        if not isinstance(values, dict): values = {}
        previous = values.get(profile.id, {}) if isinstance(values.get(profile.id, {}), dict) else {}
        elapsed = float(self.engine.last_probe_ms or previous.get("startup_ms", 99999))
        is_youtube = "youtube.com/generate_204" in self.engine.last_probe_url
        page_verified = bool(page_ok and (carrier != "irancell" or is_youtube))
        samples = int(previous.get("sample_count", 0))
        page_failures = int(previous.get("consecutive_failures", 0))
        if page_verified:
            if count_page_sample and previous.get("ok") and samples:
                elapsed = float(previous.get("startup_ms", elapsed)) * 0.65 + elapsed * 0.35
            if count_page_sample:
                samples += 1
            page_failures = 0
        else:
            page_failures += 1
            keep_previous = bool(previous.get("ok")) and page_failures < 2
            if keep_previous:
                elapsed = float(previous.get("startup_ms", elapsed))
                page_verified = True

        state = upload_state or self.engine.last_upload_state or "not_tested"
        previous_state = str(previous.get("upload_state", ""))
        previous_upload_valid = previous_state in {"verified", "failed"} or previous.get("upload_ok") is True
        previous_verified_upload = previous.get("upload_ok") is True
        upload_mbps = float(previous.get("upload_mbps", 0)) if previous_upload_valid else 0.0
        upload_ms = float(previous.get("upload_ms", 0)) if previous_upload_valid else 0.0
        upload_speed_valid = bool(previous.get("upload_speed_valid", upload_mbps > 0)) if previous_upload_valid else False
        upload_failures = int(previous.get("consecutive_upload_failures", 0))
        if state == "verified" and self.engine.last_upload_ok is True:
            measured = float(self.engine.last_upload_mbps or 0)
            measured_speed_valid = bool(self.engine.last_upload_speed_valid)
            if measured_speed_valid:
                upload_mbps = upload_mbps * 0.65 + measured * 0.35 if previous_verified_upload and upload_speed_valid else measured
                upload_speed_valid = True
            elif not previous_verified_upload:
                upload_mbps = 0.0
                upload_speed_valid = False
            upload_ms = float(self.engine.last_upload_ms or upload_ms)
            upload_ok = True
            effective_state = "verified"
            upload_failures = 0
        elif state == "failed":
            upload_failures += 1
            if upload_failures >= 2:
                upload_ok = False
                effective_state = "failed"
                upload_speed_valid = False
            else:
                upload_ok = True if previous_verified_upload else None
                effective_state = previous_state if previous_upload_valid else "inconclusive"
        else:
            # Endpoint timeout/not-tested telemetry never overwrites a verified
            # capability, speed sample, latency or failure counter.
            upload_ok = previous.get("upload_ok") if previous_upload_valid else None
            effective_state = previous_state if previous_upload_valid else state

        # Real download telemetry is carrier-scoped and only participates in
        # MCI ranking. IranCell continues through the original upload/startup
        # scoring path below without reading or writing these fields.
        measured_download_state = (download_state
                                   or getattr(self.engine, "last_download_state", "not_tested")
                                   or "not_tested")
        previous_download_state = str(previous.get("download_state", ""))
        previous_download_valid = (previous_download_state == "verified"
                                   or previous.get("download_ok") is True)
        previous_verified_download = previous.get("download_ok") is True
        download_mbps = float(previous.get("download_mbps", 0) or 0) if previous_download_valid else 0.0
        download_ms = float(previous.get("download_ms", 0) or 0) if previous_download_valid else 0.0
        download_first_byte_ms = float(previous.get("download_first_byte_ms", 0) or 0) if previous_download_valid else 0.0
        download_bytes = int(previous.get("download_bytes", 0) or 0) if previous_download_valid else 0
        download_speed_valid = bool(previous.get("download_speed_valid", download_mbps > 0)) if previous_download_valid else False
        download_failures = int(previous.get("consecutive_download_failures", 0) or 0)
        download_samples = int(previous.get("download_sample_count", 0) or 0)
        download_tested_at = float(previous.get("download_tested_at", 0) or 0)
        if carrier == "mci" and measured_download_state == "verified" \
                and getattr(self.engine, "last_download_ok", None) is True:
            measured_mbps = float(getattr(self.engine, "last_download_mbps", 0) or 0)
            measured_speed_valid = bool(getattr(self.engine, "last_download_speed_valid", measured_mbps > 0))
            if measured_speed_valid:
                download_mbps = (download_mbps * 0.65 + measured_mbps * 0.35
                                 if previous_verified_download and download_speed_valid else measured_mbps)
                download_speed_valid = True
            download_ms = float(getattr(self.engine, "last_download_ms", 0) or download_ms)
            download_first_byte_ms = float(
                getattr(self.engine, "last_download_first_byte_ms", 0) or download_first_byte_ms
            )
            download_bytes = int(getattr(self.engine, "last_download_bytes", 0) or download_bytes)
            download_ok = True
            effective_download_state = "verified"
            download_failures = 0
            download_samples += 1
            download_tested_at = time.time()
        elif carrier == "mci" and measured_download_state == "failed":
            download_failures += 1
            if download_failures >= 2:
                download_ok = False
                effective_download_state = "failed"
                download_speed_valid = False
            else:
                download_ok = True if previous_verified_download else None
                effective_download_state = previous_download_state if previous_download_valid else "inconclusive"
        else:
            # Cloudflare timeout/status/short-read is advisory. Preserve the
            # last verified speed and keep a page-verified route healthy.
            download_ok = previous.get("download_ok") if previous_download_valid else None
            effective_download_state = (previous_download_state
                                        if previous_download_valid else measured_download_state)

        if page_verified:
            if carrier == "mci":
                score = mci_quality_score(
                    elapsed,
                    download_mbps if download_ok is True and download_speed_valid else None,
                    download_first_byte_ms if download_ok is True and download_speed_valid else None,
                )
            else:
                startup_score = max(0, min(100, 100 - min(elapsed, 12000) / 120))
                upload_score = (max(0, min(100, upload_mbps * 20)) if upload_ok is True and upload_speed_valid
                                else 50 if upload_ok is not False else 0)
                if state in {"not_tested", "inconclusive", "accepted_unconfirmed"} and not count_page_sample and previous.get("ok"):
                    score = int(previous.get("score", 1))
                else:
                    score = max(1, min(100, round(startup_score * 0.75 + upload_score * 0.25)))
        else:
            score = 0
        tested_at = time.time() if page_ok else float(previous.get("tested_at", time.time()))
        value = {"ok": page_verified, "page_ok": page_verified, "score": score,
                 "startup_ms": round(elapsed, 1), "upload_ok": upload_ok,
                 "upload_state": effective_state, "upload_mbps": round(upload_mbps, 3),
                 "upload_speed_valid": upload_speed_valid, "upload_ms": round(upload_ms, 1),
                 "sample_count": samples, "consecutive_failures": page_failures,
                 "consecutive_upload_failures": upload_failures,
                 "strategy": strategy, "url": self.engine.last_probe_url,
                 "fake_sni": fake_sni or previous.get("fake_sni", ""),
                 "engine": "patterniha-wrong-seq-v1", "tested_at": tested_at}
        if carrier == "mci":
            value.update({
                "download_ok": download_ok,
                "download_state": effective_download_state,
                "download_mbps": round(download_mbps, 3),
                "download_speed_valid": download_speed_valid,
                "download_ms": round(download_ms, 1),
                "download_first_byte_ms": round(download_first_byte_ms, 1),
                "download_bytes": download_bytes,
                "download_sample_count": download_samples,
                "consecutive_download_failures": download_failures,
                "download_tested_at": download_tested_at,
            })
            if measured_download_state != "not_tested":
                value["last_download_probe_at"] = time.time()
                value["last_download_probe_state"] = measured_download_state
                value["last_download_reason"] = getattr(self.engine, "last_download_reason", "")
        if state != "not_tested":
            value["last_upload_probe_at"] = time.time()
            value["last_upload_probe_state"] = state
            value["last_upload_reason"] = self.engine.last_upload_reason
        values[profile.id] = value
        self.storage.settings[key] = values
        self.storage.save_settings()

    def _run_upload_quality(self, profile, strategy, fake_sni, carrier, generation, cancel):
        tuning = self.storage.tuning
        if not getattr(tuning, "background_quality_probe_enabled", False):
            self.bridge.log.emit("BACKGROUND QUALITY skipped (disabled for page/video startup speed)")
            return
        delay = max(10, min(300, int(getattr(tuning, "background_quality_probe_delay_s", 30))))
        if cancel.wait(delay) or self._attempt_cancelled(generation, cancel):
            return
        # The setting may have been disabled while this delayed task was
        # waiting. Never compete with the user's traffic after an opt-out.
        if not getattr(self.storage.tuning, "background_quality_probe_enabled", False):
            self.bridge.log.emit("BACKGROUND QUALITY skipped (disabled during delay)")
            return
        try:
            result, detail = self.engine.probe_upload(size=64 * 1024, timeout=8, cancel_event=cancel)
            if self._attempt_cancelled(generation, cancel):
                return
            self._save_profile_benchmark(profile, strategy, True, self.engine.last_upload_state,
                                         fake_sni, count_page_sample=False, carrier=carrier)
            self.bridge.log.emit(f"PROFILE QUALITY {profile.name} fakeSni={fake_sni} upload={self.engine.last_upload_state}: {detail}")
            self.bridge.profiles_changed.emit()
        except EngineCancelled:
            return
        except Exception as exc:
            if not self._attempt_cancelled(generation, cancel):
                self.bridge.log.emit(f"UPLOAD QUALITY skipped: {type(exc).__name__}")

    def _probe_mci_download(self, carrier, cancel):
        """Collect one short advisory sample after page traffic has passed."""
        if carrier != "mci":
            return "not_tested", "carrier skipped"
        try:
            _result, detail = self.engine.probe_download(
                size=256 * 1024, timeout=1.5, cancel_event=cancel
            )
            state = getattr(self.engine, "last_download_state", "inconclusive")
            self.bridge.log.emit(
                f"MCI DOWNLOAD {state} "
                f"{float(getattr(self.engine, 'last_download_mbps', 0) or 0):.2f}Mbps "
                f"{float(getattr(self.engine, 'last_download_ms', 0) or 0):.0f}ms: {detail}"
            )
            return state, detail
        except EngineCancelled:
            raise
        except Exception as exc:
            # The page probe remains authoritative. A telemetry endpoint or
            # parser failure must not turn a working MCI route into a failure.
            self.engine.last_download_ok = None
            self.engine.last_download_state = "inconclusive"
            self.engine.last_download_reason = type(exc).__name__
            self.bridge.log.emit(f"MCI DOWNLOAD inconclusive: {type(exc).__name__}")
            return "inconclusive", type(exc).__name__

    def _schedule_mci_warmup(self, carrier, cancel):
        """Prime one YouTube TLS path in the background for MCI only."""
        if carrier != "mci" or cancel.is_set():
            return False
        threading.Thread(
            target=self.engine.warmup,
            kwargs={"url": "https://www.youtube.com/generate_204",
                    "timeout": 2.0, "cancel_event": cancel},
            name="mci-youtube-warmup", daemon=True,
        ).start()
        return True

    def _schedule_mci_download_quality(self, profile, strategy, fake_sni,
                                       carrier, generation, cancel):
        """Rank the working MCI route after connect without delaying the UI."""
        if carrier != "mci" or cancel.is_set():
            return False
        def work():
            # Let the one-shot YouTube warmup finish first; never compete with
            # the user's initial page burst.
            if cancel.wait(2.2) or self._attempt_cancelled(generation, cancel):
                return
            try:
                state, detail = self._probe_mci_download(carrier, cancel)
                if self._attempt_cancelled(generation, cancel):
                    return
                self._save_profile_benchmark(
                    profile, strategy, True, "not_tested", fake_sni,
                    count_page_sample=False, carrier=carrier,
                    download_state=state,
                )
                self.bridge.log.emit(
                    f"MCI PROFILE QUALITY {profile.name} download={state}: {detail}"
                )
                self.bridge.profiles_changed.emit()
            except EngineCancelled:
                return
        threading.Thread(target=work, name=f"mci-quality-{generation}", daemon=True).start()
        return True

    def toggle_connection(self):
        if self.connecting:
            self.connecting = False
            self.connection_error = ""
            self._set_connection_visual("disconnecting")
            self._set_activity("در حال لغو عملیات اتصال…", "Cancelling the connection attempt…")
            self.bridge.log.emit("CONNECT CANCEL requested by user")
            self._cancel_connect_attempt(notify=True)
            self._set_state(False)
            self._set_activity("عملیات اتصال لغو شد.", "Connection attempt cancelled.", "warning", False)
            return
        if self.engine.running:
            self.connecting = False; self.connection_error = ""; self._set_connection_visual("disconnecting"); self._set_activity("در حال توقف تونل امن و بازگردانی پروکسی سیستم…", "Stopping the secure tunnel and restoring the system proxy…")
            self._cancel_connect_attempt(notify=True)
            self._set_state(False)
            return
        generation, cancel = self._begin_connect_attempt()
        base_tuning = self.storage.tuning
        carrier = base_tuning.carrier_mode
        bypass = self.selected_processes()
        auto_enabled = self.auto_mode.isChecked()
        manual_only = self.pick_best.isChecked()
        seed_snis = self._sni_candidates(carrier=carrier)
        if not seed_snis:
            message = self.tr("هیچ SNI معتبر در مخزن اسکن پیدا نشد", "No valid SNI was found in the scan repository")
            self.connection_error = message; self._set_connection_visual("error"); self._handle_error(message)
            return
        self.connecting = True; self.connection_error = ""; self._set_connection_visual("connecting"); self._set_latency(0.0, "testing")
        self._set_activity("در حال آماده‌سازی مسیر امن…", "Preparing secure route…")
        self.bridge.log.emit("SNI REPOSITORY candidates=" + ",".join(seed_snis))

        def work():
            connected = False
            last_error = ""
            # Split only MCI's first TLS ClientHello into valid records. IranCell
            # keeps its existing wrong-sequence behavior byte-for-byte.
            strategy = "tls_sni_records" if carrier == "mci" else "wrong_seq"
            try:
                self.bridge.activity.emit(self.tr(f"در حال آزمایش دسترسی {ltr_isolate('SNI')}…", "Testing SNI reachability…"), "running", True)
                profiles = self._ordered_profiles(seed_snis[0], cancel, auto_enabled, manual_only)
                if self._attempt_cancelled(generation, cancel):
                    raise EngineCancelled("Connection attempt cancelled")
                if not profiles:
                    raise ValueError(self.tr("کانفیگی موجود نیست", "No config available"))
                for index, profile in enumerate(profiles, 1):
                    profile_snis = self._sni_candidates(profile, carrier, limit=3)
                    profile_passed = False
                    profile_mux_enabled = self._profile_mux_enabled(profile, base_tuning, carrier)
                    for sni_index, fake_sni in enumerate(profile_snis, 1):
                        if self._attempt_cancelled(generation, cancel):
                            raise EngineCancelled("Connection attempt cancelled")
                        self.bridge.log.emit(f"CONFIG TRY {index}/{len(profiles)} {profile.name} SNI {sni_index}/{len(profile_snis)}={fake_sni}")
                        attempt_strategy = strategy
                        attempt_tuning = replace(base_tuning, pattern_fake_sni=fake_sni,
                                                 xray_mux_enabled=profile_mux_enabled)
                        measured_route = self._verified_route_result(fake_sni, carrier)
                        if measured_route:
                            attempt_tuning = self._bind_verified_sni_route(attempt_tuning, measured_route)
                        try:
                            self.bridge.activity.emit(self.tr(f"در حال راه‌اندازی هسته‌های {ltr_isolate('Xray')} و {ltr_isolate('Patterniha')}…", "Starting Xray and Patterniha cores…"), "running", True)
                            self.engine.start(profile, attempt_tuning, bypass, notify=False,
                                              enable_system_proxy=False, strategy_override=attempt_strategy,
                                              cancel_event=cancel)
                            if self._attempt_cancelled(generation, cancel):
                                raise EngineCancelled("Connection attempt cancelled")
                            self.bridge.activity.emit(self.tr("در حال بررسی دسترسی واقعی صفحات…", "Testing real page reachability…"), "running", True)
                            preferred_urls = {
                                "irancell": "https://www.youtube.com/generate_204",
                                # The MCI TLS-record path reaches this small page in
                                # about one second and it avoids IP-service-specific
                                # false negatives.
                                "mci": "https://www.gstatic.com/generate_204",
                            }
                            preferred_url = preferred_urls.get(carrier)
                            page_ok, detail = self.engine.probe(timeout=6, preferred_url=preferred_url,
                                                                require_preferred=(carrier in preferred_urls),
                                                                cancel_event=cancel)
                            if (not page_ok and carrier == "mci"
                                    and attempt_strategy == "tls_sni_records"):
                                # Some MCI cells still require the injected Fake
                                # SNI handshake. Retry only this MCI route; the
                                # IranCell path never enters this branch.
                                self.bridge.log.emit(
                                    f"MCI TLS FALLBACK {profile.name} fakeSni={fake_sni}"
                                )
                                self.engine.stop(notify=False)
                                attempt_strategy = "wrong_seq"
                                self.engine.start(
                                    profile, attempt_tuning, bypass, notify=False,
                                    enable_system_proxy=False, strategy_override=attempt_strategy,
                                    cancel_event=cancel,
                                )
                                page_ok, detail = self.engine.probe(
                                    timeout=6, preferred_url=preferred_url,
                                    require_preferred=True, cancel_event=cancel,
                                )
                            if not page_ok and base_tuning.xray_mux_enabled and attempt_tuning.xray_mux_enabled:
                                # Mux accelerates page bursts on compatible Xray servers. Test
                                # a bounded no-Mux fallback for each route. An earlier bad
                                # profile/SNI must not consume compatibility recovery globally.
                                self.bridge.log.emit(f"MUX FALLBACK {profile.name} fakeSni={fake_sni}")
                                self.engine.stop(notify=False)
                                fallback_tuning = replace(attempt_tuning, xray_mux_enabled=False)
                                self.engine.start(profile, fallback_tuning, bypass, notify=False,
                                                  enable_system_proxy=False, strategy_override=attempt_strategy,
                                                  cancel_event=cancel)
                                page_ok, detail = self.engine.probe(timeout=6, preferred_url=preferred_url,
                                                                    require_preferred=(carrier in preferred_urls),
                                                                    cancel_event=cancel)
                                if page_ok:
                                    attempt_tuning = fallback_tuning
                                    profile_mux_enabled = False
                                    self._remember_profile_mux(profile, False, fallback_tuning, carrier)
                                    self.bridge.log.emit("MUX FALLBACK WIN; Mux disabled for this working route")
                            if self._attempt_cancelled(generation, cancel):
                                raise EngineCancelled("Connection attempt cancelled")
                            if page_ok:
                                route_latency = float(self.engine.last_probe_ms or 0.0)
                                if route_latency > 0:
                                    profile.last_ping_ok = True
                                    profile.last_ping_ms = route_latency
                                    self.storage.save_profiles()
                                    latency_signal = getattr(self.bridge, "latency", None)
                                    if latency_signal is not None:
                                        latency_signal.emit(route_latency, "tunnel")
                                if base_tuning.xray_mux_enabled and attempt_tuning.xray_mux_enabled:
                                    self._remember_profile_mux(profile, True, attempt_tuning, carrier)
                                download_state = "not_tested"
                                download_detail = ""
                                self.bridge.activity.emit(self.tr("در حال اعمال پروکسی سیستم ویندوز…", "Applying Windows system proxy…"), "running", True)
                                self.engine.enable_system_proxy(cancel)
                                if self._attempt_cancelled(generation, cancel):
                                    raise EngineCancelled("Connection attempt cancelled")
                                self.storage.settings[f"working_strategy_{carrier}"] = attempt_strategy
                                self.storage.settings[f"working_profile_{carrier}"] = profile.id
                                self.storage.settings[f"working_pattern_sni_{carrier}"] = fake_sni
                                self.storage.settings[f"working_pattern_sni_at_{carrier}"] = time.time()
                                self.storage.settings["selected_id"] = profile.id
                                # Keep the working edge/SNI visible in Advanced for this
                                # carrier only. Do not persist a temporary no-Mux fallback
                                # over the user's carrier preset.
                                working_tuning = replace(base_tuning, pattern_fake_sni=fake_sni)
                                active_edge = str(getattr(self.engine.fragment, "active_edge", "") or "").strip()
                                if active_edge:
                                    previous_edges = [
                                        attempt_tuning.pattern_connect_ip,
                                        *str(attempt_tuning.pattern_fallback_ips or "").split(","),
                                        base_tuning.pattern_connect_ip,
                                        *str(base_tuning.pattern_fallback_ips or "").split(","),
                                    ]
                                    fallbacks = []
                                    for edge in previous_edges:
                                        edge = str(edge or "").strip()
                                        if edge and edge != active_edge and edge not in fallbacks:
                                            fallbacks.append(edge)
                                    working_tuning.pattern_connect_ip = active_edge
                                    working_tuning.pattern_fallback_ips = ",".join(fallbacks[:4])
                                self.storage.settings[f"working_pattern_edge_{carrier}"] = active_edge or working_tuning.pattern_connect_ip
                                self.storage.settings[f"working_pattern_route_{carrier}"] = {
                                    "edge": active_edge or working_tuning.pattern_connect_ip,
                                    "fake_sni": fake_sni,
                                    "tested_at": time.time(),
                                }
                                self.storage.set_tuning(working_tuning)
                                self._save_profile_benchmark(
                                    profile, attempt_strategy, True, "not_tested", fake_sni,
                                    carrier=carrier, download_state=download_state,
                                )
                                if self._attempt_cancelled(generation, cancel):
                                    raise EngineCancelled("Connection attempt cancelled")
                                connected = profile_passed = True
                                self.bridge.profiles_changed.emit()
                                quality = (f"; download={download_detail}"
                                           if carrier == "mci" and download_detail else "")
                                self.bridge.log.emit(f"CONFIG WIN {profile.name} fakeSni={fake_sni}: {detail}{quality}")
                                self.bridge.state.emit(True)
                                self.bridge.hint.emit(self.tr(f"متصل با بهترین {ltr_isolate('SNI')}: {ltr_isolate(fake_sni)}", f"Connected with best SNI: {fake_sni}"))
                                self.bridge.activity.emit(self.tr("اتصال امن برقرار شد.", "Connection established."), "success", False)
                                self._schedule_mci_warmup(carrier, cancel)
                                self._schedule_mci_download_quality(
                                    profile, attempt_strategy, fake_sni, carrier,
                                    generation, cancel,
                                )
                                if attempt_tuning.background_quality_probe_enabled:
                                    threading.Thread(target=self._run_upload_quality,
                                                     args=(profile, strategy, fake_sni, carrier, generation, cancel),
                                                     name=f"upload-quality-{generation}", daemon=True).start()
                                return
                            last_error = detail
                        except EngineCancelled:
                            raise
                        except Exception as attempt_error:
                            last_error = str(attempt_error)
                            self.bridge.log.emit(f"CONFIG FAIL {profile.name} fakeSni={fake_sni}: {last_error}")
                        self.engine.stop(notify=False)
                    if not profile_passed:
                        self._save_profile_benchmark(profile, strategy, False, "not_tested",
                                                     profile_snis[-1] if profile_snis else "",
                                                     carrier=carrier)
                raise RuntimeError("No profile passed the real YouTube/page traffic test. " + last_error)
            except EngineCancelled:
                return
            except Exception as exc:
                if not self._attempt_cancelled(generation, cancel):
                    self.bridge.error.emit(str(exc))
                    self.bridge.state.emit(False)
            finally:
                if not connected:
                    self.engine.stop(notify=False)

        self._connect_thread = threading.Thread(target=work, name=f"connect-{generation}", daemon=True)
        self._connect_thread.start()

    def _set_connection_visual(self, state):
        states = {
            "disconnected": (f"{ltr_isolate('VPN')} خاموش است", "VPN is OFF", "اتصال امن فعال نیست", "Your connection is not active", "اتصال", "Connect", "play", "idle", True),
            "connecting": ("در حال اتصال…", "Connecting…", "در حال ایجاد مسیر امن…", "Establishing secure route…", "قطع اتصال", "Disconnect", "x-circle", "cancel", True),
            "connected": (f"{ltr_isolate('VPN')} متصل است", "VPN is ON", "تونل امن فعال است", "Secure tunnel is active", "قطع اتصال", "Disconnect", "power", "connected", True),
            "disconnecting": ("در حال قطع اتصال…", "Disconnecting…", "در حال بازگردانی پروکسی سیستم…", "Restoring system proxy…", "در حال قطع…", "Disconnecting…", "loader", "loading", False),
            "error": ("خطای اتصال", "Connection Error", f"اتصال ناموفق بود؛ {ltr_isolate('Live Logs')} را بررسی کنید.", "Connection failed. Check Live Logs for details.", "تلاش دوباره", "Retry", "refresh", "error", True),
        }
        fa_status, en_status, fa_hint, en_hint, fa_button, en_button, icon_name, button_state, enabled = states[state]
        self.status.setText(self.tr(fa_status, en_status)); self.connection_hint.setText(self.tr(fa_hint, en_hint)); self.connect_button.setText(self.tr(fa_button, en_button)); self.connect_button.setEnabled(enabled)
        self.connect_button.setProperty("state", button_state); self.connect_button.setIcon(cyber_icon(icon_name, "#031422" if state == "disconnected" else "#eaffff", 20)); _restyle(self.connect_button)
        visual_state = "connecting" if state == "disconnecting" else state
        self.status_pill.set_state(visual_state); self.orb.set_state(visual_state)
        self.status.setObjectName("heroStatusOn" if state == "connected" else "heroStatusError" if state == "error" else "heroStatus")
        _restyle(self.status)

    def _set_state(self, running):
        was_running = getattr(self, "_ui_running", False)
        self._ui_running = bool(running)
        self.connecting = False
        if running:
            self.connection_error = ""; self._set_connection_visual("connected")
            self._set_activity("اتصال امن برقرار شد.", "Connection established.", "success", False)
        elif self.connection_error:
            self._set_connection_visual("error")
        else:
            self._set_connection_visual("disconnected")
            if was_running: self._set_activity("تونل متوقف و پروکسی سیستم بازگردانی شد.", "Tunnel stopped and system proxy restored.", "success", False)

    def _set_traffic(self, up, down): self.up_label.setText(format_bytes(up)); self.down_label.setText(format_bytes(down))

    def _set_latency(self, milliseconds, source="tunnel"):
        if source == "testing":
            self.ping_label.setText("…")
            self.latency_card.set_secondary(self.tr("در حال تست مسیر…", "Testing route…"))
            return
        try:
            value = float(milliseconds)
        except (TypeError, ValueError):
            return
        if value <= 0:
            return
        self.ping_label.setText(f"{value:.0f} ms")
        self.latency_card.set_secondary(self.tr(
            "تست مسیر واقعی تونل" if source == "tunnel" else "تست سریع لبه",
            "Live tunnel test" if source == "tunnel" else "Quick edge test",
        ))
        self.latency_card.sparkline.add_value(value)

    def _append_log(self, message):
        stamp = __import__('datetime').datetime.now().strftime("%H:%M:%S"); line = f"[{stamp}] {message}"; self._all_log_lines.append(line); self._all_log_lines = self._all_log_lines[-5000:]
        if self.log_pause.isChecked():
            self._log_paused_lines.append(line)
        elif not self.log_filter.text().strip() or self.log_filter.text().strip().lower() in line.lower():
            self._append_log_line(line)
        self._set_log_count(len(self._all_log_lines))
        self._pending_file_log_lines.append(line)
        if not self._log_flush_timer.isActive(): self._log_flush_timer.start()

    def _flush_log_buffer(self, final=False):
        if not self._pending_file_log_lines:
            return
        lines, self._pending_file_log_lines = self._pending_file_log_lines, []
        attempts = 2 if final else 1
        for attempt in range(attempts):
            try:
                with LOG_FILE.open("a", encoding="utf-8") as file:
                    file.write("\n".join(lines) + "\n")
                self._log_flush_failures = 0
                return
            except OSError:
                if attempt + 1 < attempts:
                    time.sleep(0.05)
        # Keep a bounded, ordered retry buffer; logging must never stall page
        # traffic. A transient failure is retried even if no new log arrives.
        self._pending_file_log_lines = (lines + self._pending_file_log_lines)[-1000:]
        self._log_flush_failures = min(5, self._log_flush_failures + 1)
        if not self._closing:
            self._log_flush_timer.start(min(3000, 200 * (2 ** (self._log_flush_failures - 1))))

    def _set_log_count(self, count):
        self.log_count_label.setText(self.tr(f"{count} خط", f"{count} line{'s' if count != 1 else ''}"))

    def _append_log_line(self, line):
        lowered = line.lower(); color = "#c7d8e8"
        if any(word in lowered for word in ("error", "fail", "exception", "fatal")): color = "#ff7891"
        elif any(word in lowered for word in ("warn", "timeout", "cancel")): color = "#ffd166"
        elif any(word in lowered for word in ("connected", "success", " win ", "completed", "verified", "=> ok")): color = "#55efae"
        elif any(word in lowered for word in ("probe", "config try", "sni", "xray")): color = "#75d9ff"
        cursor = self.logs.textCursor(); cursor.movePosition(QTextCursor.End); fmt = QTextCharFormat(); fmt.setForeground(QColor(color)); cursor.insertText(line + "\n", fmt)
        if self.log_autoscroll.isChecked(): self.logs.setTextCursor(cursor); self.logs.ensureCursorVisible()

    def _render_logs(self, *_):
        if not hasattr(self, "logs") or self.log_pause.isChecked(): return
        query = self.log_filter.text().strip().lower(); visible = [line for line in self._all_log_lines if not query or query in line.lower()][-2500:]
        self.logs.clear()
        for line in visible: self._append_log_line(line)

    def _toggle_log_pause(self, paused):
        if paused:
            self._set_activity("نمایش Live Logs متوقف شد؛ ثبت فایل ادامه دارد.", "Live Logs display paused; file logging continues.", "warning", False)
        else:
            self._log_paused_lines.clear(); self._render_logs(); self._set_activity("نمایش Live Logs از سر گرفته شد.", "Live Logs display resumed.", "success", False)

    def logs_clear(self):
        self.logs.clear(); self._all_log_lines.clear(); self._log_paused_lines.clear(); self._set_log_count(0); self._set_activity("نمایش لاگ پاک شد.", "Log view cleared.", "success", False)

    def open_tuning(self):
        self._set_activity("در حال باز کردن تنظیمات پیشرفته…", "Opening advanced settings…", "running", True)
        dialog = TuningDialog(self, self.storage.tuning, self.language,
                              self.storage.settings.get("update_repo_url", DEFAULT_UPDATE_REPO_URL),
                              self.storage.all_carrier_tunings())
        if dialog.exec():
            values = dialog.values(); value = dialog.value()
            self.storage.set_carrier_tunings(values, value.carrier_mode)
            blocked = self.carrier.blockSignals(True)
            self.carrier.setCurrentText(value.carrier_mode)
            self.carrier.blockSignals(blocked)
            repo_url = dialog.update_repo_url() or DEFAULT_UPDATE_REPO_URL
            changed_repo = repo_url != self.storage.settings.get("update_repo_url", DEFAULT_UPDATE_REPO_URL)
            self.storage.settings["update_repo_url"] = repo_url; self.storage.save_settings()
            self._set_activity("تنظیمات ذخیره شد.", "Settings saved.", "success", False)
            if changed_repo:
                # Invalidate an in-flight check for the previous repository.
                # Its generation-tagged callback will be ignored.
                self._update_generation += 1
                self._update_in_progress = False
                self._latest_update = None
                self.update_check_button.setEnabled(True)
                self.check_for_updates(manual=True)
        else: self.activity_bar.set_activity("", "idle", False)

    def check_for_updates(self, manual=False):
        if self._closing or self._update_in_progress:
            if manual and self._update_in_progress:
                self.show_toast(self.tr("بررسی بروزرسانی در حال اجراست", "An update check is already running"), "warning")
            return
        now = time.time(); last_check = float(self.storage.settings.get("last_update_checked_at", 0) or 0)
        if not manual and now - last_check < 12 * 3600 and self.storage.settings.get("latest_version"):
            if self._restore_cached_update():
                return
        self._update_generation += 1; generation = self._update_generation; self._update_in_progress = True
        self.update_check_button.setEnabled(False); self.update_status.setText(self.tr("در حال بررسی آخرین Release…", "Checking the latest release…")); self.update_card.setProperty("state", "checking"); _restyle(self.update_card)
        repo_url = self.storage.settings.get("update_repo_url", DEFAULT_UPDATE_REPO_URL)
        def work():
            try:
                info = check_latest_release(repo_url, __version__)
                self.bridge.update_checked.emit(info, generation)
            except Exception as exc:
                self.bridge.update_failed.emit(str(exc), generation, bool(manual))
        threading.Thread(target=work, name=f"update-check-{generation}", daemon=True).start()

    def _restore_cached_update(self):
        latest = str(self.storage.settings.get("latest_version", "")).strip()
        release_url = str(self.storage.settings.get("latest_release_url", "")).strip()
        repo_url = str(self.storage.settings.get("update_repo_url", DEFAULT_UPDATE_REPO_URL))
        try:
            canonical_repo = parse_github_repository(repo_url).canonical_url
        except Exception:
            return False
        if (not latest
                or self.storage.settings.get("last_update_repo_url") != canonical_repo
                or self.storage.settings.get("last_update_current_version") != __version__):
            return False
        try:
            available = SemVersion.parse(latest) > SemVersion.parse(__version__)
        except Exception:
            return False
        info = UpdateInfo(
            repo_url=canonical_repo,
            current_version=__version__, latest_version=latest,
            tag_name=str(self.storage.settings.get("latest_tag", latest)),
            release_name=str(self.storage.settings.get("latest_release_name", latest)),
            release_url=release_url, published_at="", release_notes="", prerelease=False,
            is_update_available=available,
        )
        self._latest_update = info; self._render_update_info(info)
        return True

    def _update_checked(self, info, generation):
        if generation != self._update_generation or self._closing:
            return
        current_repo = str(self.storage.settings.get("update_repo_url", DEFAULT_UPDATE_REPO_URL))
        try:
            current_repo = parse_github_repository(current_repo).canonical_url
        except Exception:
            current_repo = ""
        if info.repo_url != current_repo:
            self._update_in_progress = False; self.update_check_button.setEnabled(True)
            return
        self._update_in_progress = False; self.update_check_button.setEnabled(True); self._latest_update = info
        self.storage.settings.update({
            "last_update_checked_at": time.time(), "latest_version": info.latest_version,
            "latest_tag": info.tag_name, "latest_release_name": info.release_name,
            "latest_release_url": info.release_url, "update_available": info.is_update_available,
            "last_update_repo_url": info.repo_url,
            "last_update_current_version": __version__,
        }); self.storage.save_settings(); self._render_update_info(info)
        if info.is_update_available and self.storage.settings.get("notified_update_version") != info.latest_version:
            self.storage.settings["notified_update_version"] = info.latest_version; self.storage.save_settings()
            self.show_toast(self.tr(f"نسخه جدید {ltr_isolate(info.latest_version)} آماده است؛ از Support دانلود کنید.", f"Version {info.latest_version} is available; open Support to download."), "success")

    def _render_update_info(self, info):
        available = bool(info and info.is_update_available); latest = info.latest_version if info else "—"
        self.update_versions.setLayoutDirection(Qt.RightToLeft if self.language == "fa" else Qt.LeftToRight)
        self.update_versions.setAlignment((Qt.AlignRight if self.language == "fa" else Qt.AlignLeft) | Qt.AlignVCenter)
        self.update_versions.setText(self.tr(f"نصب‌شده: {ltr_isolate(__version__)}  •  آخرین نسخه: {ltr_isolate(latest)}", f"Installed: {__version__}  •  Latest: {latest}"))
        self.update_status.setText(self.tr("بروزرسانی جدید آماده دانلود است.", "A new update is ready to download.") if available else self.tr("شما آخرین نسخه را دارید.", "You are using the latest version."))
        self.update_download_button.setEnabled(available and bool(info.release_url)); self.update_card.setProperty("state", "available" if available else "current"); _restyle(self.update_card)

    def _update_failed(self, message, generation, manual):
        if generation != self._update_generation or self._closing:
            return
        self._update_in_progress = False; self.update_check_button.setEnabled(True); self.update_status.setText(self.tr("بررسی بروزرسانی انجام نشد", "Update check could not be completed")); self.update_card.setProperty("state", "error"); _restyle(self.update_card)
        if manual: self.show_toast(message, "danger")

    def _open_latest_update(self):
        url = self._latest_update.release_url if self._latest_update else str(self.storage.settings.get("latest_release_url", ""))
        if url.startswith("https://github.com/"):
            webbrowser.open(url); self._set_activity("صفحه دانلود بروزرسانی باز شد.", "The update download page was opened.", "success", False)
        else:
            self.show_toast(self.tr("لینک معتبر Release موجود نیست", "No valid release link is available"), "warning")

    def toggle_scan(self):
        if self.scanning:
            self.scan_cancelled = True; self._scan_cancel_event.set()
            self.scan_progress.set_status(self.tr("در حال توقف اسکن", "Stopping scan"), "warning")
            self.scan_button.setEnabled(False); self.scan_state_badge.setText(self.tr("در حال توقف", "Stopping")); self._set_activity(f"در حال توقف اسکن {ltr_isolate('SNI')}…", "Stopping SNI scan…", "warning", True)
            return
        domains = list(dict.fromkeys(x.strip().lower() for x in self.domains.toPlainText().splitlines() if x.strip() and not x.startswith("#")))
        if not domains: self.show_toast(self.tr("حداقل یک دامنه وارد کنید", "Enter at least one domain"), "warning"); return
        self._scan_generation += 1; generation = self._scan_generation
        self._scan_cancel_event = threading.Event(); self._scan_results_by_domain = {}; self.last_results = []
        self.scanning = True; self.scan_cancelled = False; self.scan_button.setEnabled(True); self.scan_button.setText(self.tr("توقف اسکن", "Stop Scan")); self.scan_button.setIcon(cyber_icon("x-circle", "#eaffff", 18)); self.scan_progress.setMaximum(len(domains)); self.scan_progress.setValue(0); self.results_table.setSortingEnabled(False); self.results_table.setRowCount(0); self.results_table.setSortingEnabled(True); self.scan_state_badge.setText(self.tr("در حال اسکن", "Scanning"))
        self.scan_progress.set_status(self.tr("در حال اسکن مسیرهای شبکه", "Scanning network routes"), "running")
        self.scan_progress.setFormat(self.tr("در انتظار اولین نتیجه…", "Waiting for the first result…"))
        self._set_activity(f"در حال آزمایش دسترسی دامنه‌های {ltr_isolate('SNI')}…", "Testing SNI domain reachability…")
        threads, tries, timeout = self.scan_threads.value(), self.scan_tries.value(), self.scan_timeout.value()
        cancel_event = self._scan_cancel_event
        scan_tuning = self.storage.tuning
        self._scan_context = {"generation": generation, "carrier": scan_tuning.carrier_mode,
                              "edge": scan_tuning.pattern_connect_ip}
        def work():
            try:
                results = scan_domains(
                    domains, threads, tries, timeout,
                    lambda done, total, result: self.bridge.scan_progress.emit(done, total, result, generation),
                    cancel_event.is_set,
                    edge_ip=scan_tuning.pattern_connect_ip,
                )
                self.bridge.scan_done.emit(results, generation)
            except Exception as exc:
                self.bridge.scan_failed.emit(str(exc), generation)
        threading.Thread(target=work, name=f"sni-scan-{generation}", daemon=True).start()

    def _scan_progress(self, done, total, result, generation):
        if generation != self._scan_generation or not self.scanning:
            return
        self.scan_progress.setValue(done)
        self.scan_progress.setFormat(f"{done}/{total}  •  {result.domain}")
        self.activity_bar.set_activity(self.tr(f"در حال اندازه‌گیری {ltr_isolate(result.domain)} ({done}/{total})", f"Measuring {result.domain} ({done}/{total})"), "running", True)
        if result.success:
            scan_context = getattr(self, "_scan_context", {})
            context = scan_context if scan_context.get("generation") == generation else {}
            result.tested_at = time.time(); result.carrier = result.carrier or context.get("carrier", "")
            self._scan_results_by_domain[result.domain.lower()] = result
            self._upsert_scan_result(result)

    def _scan_done(self, results, generation):
        if generation != self._scan_generation:
            return
        for result in results:
            if not result.success: continue
            scan_context = getattr(self, "_scan_context", {})
            context = scan_context if scan_context.get("generation") == generation else {}
            result.tested_at = result.tested_at or time.time(); result.carrier = result.carrier or context.get("carrier", "")
            self._scan_results_by_domain[result.domain.lower()] = result
            self._upsert_scan_result(result)
        self.last_results = sorted(self._scan_results_by_domain.values(), key=lambda x: (-x.score, -x.stability, x.first_byte_ms, x.ping_ms, x.domain))
        self._persist_scan_repository(self.last_results)
        self.scanning = False; self._scan_cancel_event.set(); self.scan_button.setEnabled(True); self.scan_button.setText(self.tr("شروع اسکن", "Start Scan")); self.scan_button.setIcon(cyber_icon("play", "#031422", 18))
        state = "warning" if self.scan_cancelled else "success"
        label = self.tr(f"اسکن پایان یافت • {len(self.last_results)} مسیر سالم", f"Scan complete • {len(self.last_results)} working routes")
        self.scan_progress.set_status(label, state); self.scan_state_badge.setText(self.tr("اسکن متوقف شد", "Scan Stopped") if self.scan_cancelled else self.tr("اسکن کامل شد", "Scan Complete")); self.activity_bar.set_activity(label, state, False)
        self.results_table.sortItems(8, Qt.DescendingOrder)
        self._append_log(f"SNI scan completed: {len(self.last_results)} working routes")

    def _scan_failed(self, message, generation):
        if generation != self._scan_generation:
            return
        self.last_results = sorted(self._scan_results_by_domain.values(), key=lambda x: (-x.score, -x.stability, x.first_byte_ms, x.ping_ms, x.domain))
        if self.last_results: self._persist_scan_repository(self.last_results)
        self.scanning = False; self._scan_cancel_event.set(); self.scan_button.setEnabled(True); self.scan_button.setText(self.tr("شروع اسکن", "Start Scan")); self.scan_button.setIcon(cyber_icon("play", "#031422", 18))
        self.scan_progress.set_status(self.tr("اسکن با خطا متوقف شد", "Scan stopped with an error"), "error"); self.scan_state_badge.setText(self.tr("خطای اسکن", "Scan Error"))
        self.activity_bar.set_activity(message, "error", False); self.show_toast(message, "danger")

    def _persist_scan_repository(self, results):
        # Persist every successful scan, not only manually bookmarked rows.
        # This is the measured SNI repository consumed by auto-connect.
        def repository_key(item):
            return (
                str(item.get("carrier", "") or "").strip().lower(),
                str(item.get("edge", "") or "").strip().lower(),
                str(item.get("domain", "") or "").strip().lower(),
            )

        repository = {repository_key(item): item for item in self.storage.scan_results
                      if isinstance(item, dict) and item.get("domain")}
        for result in results:
            result.tested_at = result.tested_at or time.time()
            result.carrier = result.carrier or self.storage.tuning.carrier_mode
            raw = result.to_dict()
            repository[repository_key(raw)] = raw
        self.storage.scan_results = sorted(repository.values(), key=lambda item: (
            -float(item.get("score", -9999)), -float(item.get("stability", 0)),
            float(item.get("first_byte_ms", 99999)), float(item.get("ping_ms", 99999)),
            str(item.get("domain", ""))))[:500]
        self.storage.save_scan_results()

    def _upsert_scan_result(self, result):
        table = self.results_table; sort_column = table.horizontalHeader().sortIndicatorSection(); sort_order = table.horizontalHeader().sortIndicatorOrder(); table.setSortingEnabled(False)
        row = next((index for index in range(table.rowCount()) if table.item(index, 1) and table.item(index, 1).text().lower() == result.domain.lower()), -1)
        checked = False
        if row >= 0:
            holder = table.cellWidget(row, 0); selector = holder.findChild(QCheckBox) if holder else None; checked = bool(selector and selector.isChecked())
        else:
            row = table.rowCount(); table.insertRow(row)
        self._populate_result_row(table, row, result, checked)
        table.setSortingEnabled(True); table.sortItems(sort_column, sort_order)
        self._update_scan_selection()

    def _fill_results(self, table, results):
        table.setSortingEnabled(False)
        table.setRowCount(0)
        for row, r in enumerate(results):
            table.insertRow(row); self._populate_result_row(table, row, r)
        table.setSortingEnabled(True)
        self._update_scan_selection()

    def _populate_result_row(self, table, row, r, checked=False):
            selector = QCheckBox(); selector.setObjectName("rowSelector"); selector.setToolTip(self.tr("انتخاب این نتیجه SNI", "Select this SNI result")); selector.setChecked(checked)
            selector.stateChanged.connect(self._update_scan_selection)
            holder = QWidget(); holder_layout = QHBoxLayout(holder); holder_layout.setContentsMargins(0, 0, 0, 0); holder_layout.addWidget(selector, alignment=Qt.AlignCenter)
            table.setCellWidget(row, 0, holder)

            raw = r.to_dict() if hasattr(r, "to_dict") else r
            domain = QTableWidgetItem(r.domain); domain.setData(Qt.UserRole, raw); domain.setToolTip(r.domain)
            address = r.resolved_ip
            ip_item = QTableWidgetItem(address); ip_item.setToolTip(address)
            table.setItem(row, 1, domain); table.setItem(row, 2, ip_item)

            colo_item = QTableWidgetItem(r.colo or "—"); table.setItem(row, 3, colo_item)
            ping_item = QTableWidgetItem(); ping_item.setData(Qt.DisplayRole, int(r.ping_ms)); ping_item.setToolTip(f"{r.ping_ms} ms"); table.setItem(row, 4, ping_item)
            stability_item = QTableWidgetItem(); stability_item.setData(Qt.DisplayRole, int(r.stability)); stability_item.setToolTip(f"{r.stability}%"); table.setItem(row, 5, stability_item)
            first_item = QTableWidgetItem(); first_item.setData(Qt.DisplayRole, int(r.first_byte_ms)); first_item.setText(f"{r.first_byte_ms} ms"); table.setItem(row, 6, first_item)
            bytes_item = QTableWidgetItem(); bytes_item.setData(Qt.DisplayRole, int(r.first_two_second_bytes)); bytes_item.setText(format_bytes(r.first_two_second_bytes)); table.setItem(row, 7, bytes_item)
            score_item = QTableWidgetItem(); score_item.setData(Qt.DisplayRole, int(r.score)); table.setItem(row, 8, score_item)

            ping_kind = "success" if r.ping_ms <= 100 else "warning" if r.ping_ms <= 250 else "danger"
            stability_kind = "success" if r.stability >= 80 else "warning" if r.stability >= 50 else "danger"
            score_kind = "success" if r.score >= 800 else "warning" if r.score >= 400 else "danger"
            table.setCellWidget(row, 3, badge(r.colo or "—", "info"))
            table.setCellWidget(row, 4, badge(f"{r.ping_ms} ms", ping_kind))
            table.setCellWidget(row, 5, badge(f"{r.stability}%", stability_kind))
            table.setCellWidget(row, 8, badge(str(r.score), score_kind))
            for col in range(1, 9):
                item = table.item(row, col)
                if item:
                    item.setTextAlignment(Qt.AlignVCenter | (Qt.AlignLeft if col in (1, 2) else Qt.AlignCenter))

    def _active_result_table(self):
        return self.results_table if self.scan_tabs.currentIndex() == 0 else self.bookmarks_table

    def _selected_results(self):
        table = self._active_result_table(); rows = set()
        for row in range(table.rowCount()):
            holder = table.cellWidget(row, 0)
            check = holder.findChild(QCheckBox) if holder else None
            if check and check.isChecked(): rows.add(row)
        rows.update(index.row() for index in table.selectionModel().selectedRows())
        results = []
        for row in sorted(rows):
            item = table.item(row, 1)
            if not item: continue
            raw = item.data(Qt.UserRole)
            results.append(ScanResult(**raw) if isinstance(raw, dict) else raw)
        return results

    def _selected_result(self):
        selected = self._selected_results()
        if selected: return max(selected, key=lambda result: result.score)
        table = self._active_result_table(); row = table.currentRow()
        if row < 0: return None
        item = table.item(row, 1)
        if not item: return None
        raw = item.data(Qt.UserRole); return ScanResult(**raw) if isinstance(raw, dict) else raw

    def _update_scan_selection(self, *_):
        if not hasattr(self, "scan_selection_label"): return
        count = len(self._selected_results())
        self.scan_selection_label.setText(self.tr(f"{count} ردیف انتخاب شده", f"{count} row{'s' if count != 1 else ''} selected") if count else self.tr("هیچ ردیفی انتخاب نشده", "No rows selected"))

    def bookmark_selected(self):
        results = self._selected_results() or ([self._selected_result()] if self._selected_result() else [])
        if not results: self.show_toast(self.tr("یک نتیجه SNI انتخاب کنید", "Select an SNI result"), "warning"); return
        keys = {(result.carrier, result.edge, result.domain) for result in results}
        self.storage.bookmarks = [x for x in self.storage.bookmarks
                                  if (x.get("carrier", ""), x.get("edge", ""), x.get("domain")) not in keys]
        self.storage.bookmarks.extend(result.to_dict() for result in results); self.storage.save_bookmarks(); self.refresh_bookmarks()
        self.show_toast(self.tr(f"{len(results)} نتیجه ذخیره شد", f"Saved {len(results)} result(s)"), "success"); self._set_activity("نتیجه‌های SNI ذخیره شدند.", "SNI results saved.", "success", False)

    def refresh_bookmarks(self): self._fill_results(self.bookmarks_table, [ScanResult(**x) for x in self.storage.bookmarks if isinstance(x, dict)])

    def _capture_sni_snapshot(self, profiles):
        tuning = self.storage.tuning
        carrier = tuning.carrier_mode
        scoped_pins = self.storage.settings.get("pattern_profile_sni_pins_by_carrier", {})
        scoped_globals = self.storage.settings.get("pattern_global_sni_pin_by_carrier", {})
        return {
            "carrier": carrier,
            "profile_ids": [profile.id for profile in profiles],
            "tuning": tuning.to_dict(),
            "profile_pins": dict(scoped_pins.get(carrier, {})) if isinstance(scoped_pins, dict) and isinstance(scoped_pins.get(carrier, {}), dict) else {},
            "global_pin_exists": isinstance(scoped_globals, dict) and carrier in scoped_globals,
            "global_pin": scoped_globals.get(carrier) if isinstance(scoped_globals, dict) else None,
        }

    def _restore_sni_snapshot(self, snapshot, persist=True):
        carrier = snapshot.get("carrier", self.storage.tuning.carrier_mode)
        carrier_tunings = self.storage.all_carrier_tunings()
        carrier_tunings[carrier] = Tuning.from_dict(snapshot.get("tuning", {}))
        scoped_pins = self.storage.settings.get("pattern_profile_sni_pins_by_carrier", {})
        scoped_pins = dict(scoped_pins) if isinstance(scoped_pins, dict) else {}
        scoped_pins[carrier] = dict(snapshot.get("profile_pins", {}))
        self.storage.settings["pattern_profile_sni_pins_by_carrier"] = scoped_pins
        scoped_globals = self.storage.settings.get("pattern_global_sni_pin_by_carrier", {})
        scoped_globals = dict(scoped_globals) if isinstance(scoped_globals, dict) else {}
        if snapshot.get("global_pin_exists"):
            scoped_globals[carrier] = snapshot.get("global_pin")
        else:
            scoped_globals.pop(carrier, None)
        self.storage.settings["pattern_global_sni_pin_by_carrier"] = scoped_globals
        active = self.storage.tuning.carrier_mode
        self.storage.set_carrier_tunings(carrier_tunings, active)
        if persist:
            self.storage.save_settings()

    @staticmethod
    def _bind_verified_sni_route(tuning, result):
        """Bind only an edge that the edge-aware scanner actually tested."""
        tuning.pattern_fake_sni = result.domain
        if not getattr(result, "edge_verified", False) or not result.edge:
            return tuning
        previous = [tuning.pattern_connect_ip, *str(tuning.pattern_fallback_ips or "").split(",")]
        tuning.pattern_connect_ip = result.edge
        fallbacks = []
        for value in previous:
            value = str(value or "").strip()
            if value and value != result.edge and value not in fallbacks:
                fallbacks.append(value)
        tuning.pattern_fallback_ips = ",".join(fallbacks[:4])
        return tuning

    def _apply_carrier_sni(self, assignments, best_result):
        carrier = self.storage.tuning.carrier_mode
        if any(result.carrier and result.carrier != carrier for result in assignments.values()):
            raise ValueError(self.tr("نتیجه SNI متعلق به اپراتور دیگری است؛ روی اپراتور فعلی دوباره اسکن کنید", "The SNI result belongs to another carrier; scan again on the active carrier"))
        scoped_pins = self.storage.settings.get("pattern_profile_sni_pins_by_carrier", {})
        scoped_pins = dict(scoped_pins) if isinstance(scoped_pins, dict) else {}
        bucket = scoped_pins.get(carrier, {})
        bucket = dict(bucket) if isinstance(bucket, dict) else {}
        for profile_id, result in assignments.items():
            bucket[profile_id] = result.domain
        scoped_pins[carrier] = bucket
        scoped_globals = self.storage.settings.get("pattern_global_sni_pin_by_carrier", {})
        scoped_globals = dict(scoped_globals) if isinstance(scoped_globals, dict) else {}
        scoped_globals[carrier] = best_result.domain
        tuning = self._bind_verified_sni_route(self.storage.tuning, best_result)
        self.storage.settings["pattern_profile_sni_pins_by_carrier"] = scoped_pins
        self.storage.settings["pattern_global_sni_pin_by_carrier"] = scoped_globals
        self.storage.set_tuning(tuning)

    def apply_selected_sni(self):
        result = self._selected_result(); profile = self.storage.selected()
        if not result or not profile:
            self.show_toast(self.tr("یک نتیجه SNI و کانفیگ فعال انتخاب کنید", "Select an SNI result and an active config"), "warning"); return
        if result and profile:
            self._set_activity("در حال اعمال SNI به کانفیگ فعال…", "Applying SNI to the active config…")
            snapshot = self._capture_sni_snapshot([profile])
            try:
                self._apply_carrier_sni({profile.id: result}, result)
            except Exception as exc:
                try: self._restore_sni_snapshot(snapshot)
                except Exception: pass
                self.show_toast(self.tr("اعمال SNI ناموفق بود؛ مقادیر قبلی حفظ شدند", "SNI apply failed; previous values were preserved") + f": {exc}", "danger")
                self.activity_bar.set_activity(self.tr("اعمال SNI ناموفق بود؛ مقادیر قبلی حفظ شدند.", "SNI apply failed; previous values were preserved."), "error", False)
                return
            self.sni_undo_snapshot = snapshot; self.undo_apply_btn.setEnabled(True)
            self.refresh_profiles(); self._append_log(f"Applied repository Fake SNI {result.domain} to {profile.name}")
            self.show_toast(self.tr("SNI روی کانفیگ فعال اعمال شد", "SNI applied to the active config"), "success", undo=True); self._set_activity("SNI روی کانفیگ فعال اعمال شد.", "SNI applied to the active config.", "success", False)

    def apply_sni_to_all_suggested(self):
        selected = self._selected_results()
        mode = "best"
        if len(selected) > 1:
            choice = QMessageBox(self); choice.setObjectName("cyberMessageBox"); choice.setWindowTitle("Multiple SNI results selected")
            choice.setIcon(QMessageBox.Question); choice.setWindowTitle(self.tr("چند نتیجه SNI انتخاب شده", "Multiple SNI results selected")); choice.setText(self.tr("نحوه تخصیص SNIهای انتخاب‌شده به کانفیگ‌های پیشنهادی را انتخاب کنید.", "Choose how the selected SNI results should be assigned to suggested configs."))
            best_button = choice.addButton(self.tr("استفاده از بهترین امتیاز", "Use Best-Scored"), QMessageBox.AcceptRole)
            ordered_button = choice.addButton(self.tr("اعمال به ترتیب", "Apply in Order"), QMessageBox.ActionRole)
            choice.addButton(self.tr("لغو", "Cancel"), QMessageBox.RejectRole); choice.exec()
            clicked = choice.clickedButton()
            if clicked is best_button: mode = "best"
            elif clicked is ordered_button: mode = "ordered"
            else: return
        if not selected:
            source = self.last_results or [ScanResult(**x) for x in self.storage.scan_results if isinstance(x, dict)]
            if self.scan_tabs.currentIndex() != 0:
                source = [ScanResult(**x) for x in self.storage.bookmarks if isinstance(x, dict)] or source
            carrier = self.storage.tuning.carrier_mode
            source = [result for result in source if not result.carrier or result.carrier == carrier]
            if not source:
                self.show_toast(self.tr("هیچ نتیجه SNI برای اعمال وجود ندارد", "No SNI result is available to apply"), "danger")
                return
            selected = [max(source, key=lambda result: result.score)]

        confirmation = QMessageBox(self); confirmation.setObjectName("cyberMessageBox"); confirmation.setIcon(QMessageBox.Question)
        confirmation.setWindowTitle(self.tr("SNI روی همه کانفیگ‌های پیشنهادی اعمال شود؟", "Apply SNI to all suggested configs?"))
        confirmation.setText(self.tr("این کار مقدار SNI همه کانفیگ‌های پیشنهادی را با نتیجه انتخاب‌شده/بهترین به‌روزرسانی می‌کند.", "This will update the SNI value for all suggested configs using the selected/best result."))
        cancel = confirmation.addButton(self.tr("لغو", "Cancel"), QMessageBox.RejectRole)
        apply_button = confirmation.addButton(self.tr("اعمال به همه", "Apply to All"), QMessageBox.AcceptRole)
        confirmation.exec()
        if confirmation.clickedButton() is not apply_button: return

        suggested = [profile for profile in self.storage.profiles if profile.origin != "user"]
        if not suggested:
            self.show_toast(self.tr("کانفیگ پیشنهادی پیدا نشد", "No suggested configs were found"), "warning")
            return
        snapshot = self._capture_sni_snapshot(suggested)
        self._set_activity("در حال اعمال SNI به کانفیگ‌های پیشنهادی…", "Applying SNI to suggested configs…")
        try:
            ordered = selected if mode == "ordered" else [max(selected, key=lambda result: result.score)]
            assignments = {}
            for index, profile in enumerate(suggested):
                assignments[profile.id] = ordered[index % len(ordered)]
            self._apply_carrier_sni(assignments, max(selected, key=lambda result: result.score))
        except Exception as exc:
            try: self._restore_sni_snapshot(snapshot)
            except Exception: pass
            self.show_toast(self.tr("اعمال SNI ناموفق بود؛ مقادیر قبلی حفظ شدند", "SNI apply failed; previous values were preserved") + f": {exc}", "danger")
            self.activity_bar.set_activity(self.tr("اعمال SNI ناموفق بود؛ مقادیر قبلی حفظ شدند.", "SNI apply failed; previous values were preserved."), "error", False)
            return
        self.sni_undo_snapshot = snapshot; self.undo_apply_btn.setEnabled(True); self.refresh_profiles()
        self._append_log(f"Applied SNI to {len(suggested)} suggested configs (mode={mode})")
        self.show_toast(self.tr(f"SNI روی {len(suggested)} کانفیگ پیشنهادی اعمال شد", f"Updated {len(suggested)} suggested configs"), "success", undo=True); self._set_activity(f"SNI روی {len(suggested)} کانفیگ پیشنهادی اعمال شد.", f"Updated {len(suggested)} suggested configs.", "success", False)

    def undo_sni_apply(self):
        if not self.sni_undo_snapshot: return
        snapshot = self.sni_undo_snapshot
        try:
            if isinstance(snapshot, dict):
                restored = len(snapshot.get("profile_ids", [])); self._restore_sni_snapshot(snapshot)
            else:
                old_values = dict(snapshot)
                for profile in self.storage.profiles:
                    if profile.id in old_values: profile.sni = old_values[profile.id]
                self.storage.save_profiles(); restored = len(old_values)
            self.refresh_profiles(); self.sni_undo_snapshot = None; self.undo_apply_btn.setEnabled(False)
            self.show_toast(self.tr(f"تغییرات {restored} کانفیگ برگردانده شد", f"Restored {restored} configs"), "success"); self._set_activity(f"تغییرات {restored} کانفیگ بازگردانده شد.", f"Restored {restored} configs.", "success", False)
        except Exception as exc:
            self.show_toast(self.tr("بازگردانی ناموفق بود", "Undo failed") + f": {exc}", "danger")

    def copy_selected_result(self):
        results = self._selected_results() or ([self._selected_result()] if self._selected_result() else [])
        if results:
            QApplication.clipboard().setText("\n".join(f"{result.domain} | {result.resolved_ip} | {result.ping_ms} ms | {result.stability}% | score {result.score}" for result in results))
            self._set_activity("نتیجه SNI در Clipboard کپی شد.", "SNI result copied to the clipboard.", "success", False)

    def show_toast(self, message, kind="success", undo=False):
        old = self.centralWidget().findChild(QFrame, "toast")
        if old: old.deleteLater()
        toast = QFrame(self.centralWidget()); toast.setObjectName("toast"); toast.setProperty("kind", kind)
        layout = QHBoxLayout(toast); layout.setContentsMargins(16, 12, 12, 12); layout.setSpacing(12)
        dot = QLabel(); dot.setObjectName("toastDot"); dot.setFixedSize(24, 24); icon_name = {"success": "check-circle", "warning": "alert", "danger": "x-circle"}.get(kind, "check-circle"); icon_color = {"success": "#23f5a6", "warning": "#ffd166", "danger": "#ff5c7c"}.get(kind, "#23f5e0"); dot.setPixmap(cyber_pixmap(icon_name, icon_color, 21)); text = QLabel(message); text.setObjectName("toastText"); text.setWordWrap(True)
        layout.addWidget(dot); layout.addWidget(text, 1)
        if undo:
            button = QPushButton(self.tr("بازگردانی", "Undo")); button.setObjectName("toastAction"); button.clicked.connect(self.undo_sni_apply); button.clicked.connect(toast.deleteLater); layout.addWidget(button)
        toast.setMaximumWidth(580); toast.setMinimumWidth(360); toast.adjustSize()
        shadow = QGraphicsDropShadowEffect(toast); shadow.setBlurRadius(32); shadow.setOffset(0, 8); shadow.setColor(QColor(0, 0, 0, 150)); toast.setGraphicsEffect(shadow)
        toast.show(); toast.raise_(); self._position_toast(toast)
        if _animations_enabled():
            target = toast.pos(); toast.move(target + QPoint(0, 12)); animation = QPropertyAnimation(toast, b"pos", self); animation.setDuration(240); animation.setStartValue(toast.pos()); animation.setEndValue(target); animation.setEasingCurve(QEasingCurve.OutCubic); self._toast_animation = animation; animation.start()
        if self._toast_timer: self._toast_timer.stop()
        self._toast_timer = QTimer(self); self._toast_timer.setSingleShot(True); self._toast_timer.timeout.connect(toast.deleteLater); self._toast_timer.start(6000)

    def _position_toast(self, toast=None):
        toast = toast or self.centralWidget().findChild(QFrame, "toast")
        if not toast: return
        area = self.centralWidget().rect(); x = max(18, area.center().x() - toast.width() // 2); y = max(18, area.bottom() - toast.height() - 24)
        toast.move(x, y)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        compact = self.width() < 1240
        self.sidebar.setFixedWidth(238 if compact else 286)
        self.rating_card.setVisible(self.height() >= 810 and not compact)
        self._layout_metric_cards(self.width() < 1320)
        self._layout_control_bar(self.width() < 1320)
        self._layout_hero(self.width() < 1050)
        self._layout_tool_cards(self.width() < 1180)
        self._position_toast()

    def showEvent(self, event):
        super().showEvent(event)
        if self._entrance_done or not MOTION_ENABLED or QApplication.platformName() == "offscreen":
            return
        self._entrance_done = True
        self.setWindowOpacity(0.0)
        animation = QPropertyAnimation(self, b"windowOpacity", self); animation.setDuration(520); animation.setStartValue(0.0); animation.setEndValue(1.0); animation.setEasingCurve(QEasingCurve.OutCubic)
        self._entrance_animation = animation; animation.start()

    def refresh_processes(self):
        self.process_refresh_btn.setEnabled(False); self._set_activity("در حال خواندن پردازه‌های فعال…", "Reading active processes…")
        def work():
            try:
                names = sorted({p.info.get("name") for p in psutil.process_iter(["name"]) if p.info.get("name")}, key=str.lower)
                self.bridge.processes.emit(names)
            except Exception as exc:
                self.bridge.error.emit(str(exc))
        threading.Thread(target=work, name="process-list", daemon=True).start()

    def _populate_processes(self, names):
        selected = set(self.storage.settings.get("bypass_processes", [])); self.process_table.setRowCount(len(names))
        for row, name in enumerate(names):
            toggle = ToggleSwitch(); toggle.setAccessibleName(f"Bypass VPN for {name}"); toggle.setChecked(name in selected); toggle.stateChanged.connect(self._save_process_selection); self.process_table.setCellWidget(row, 0, toggle); item = QTableWidgetItem(name); item.setIcon(cyber_icon("network", "#6689ad", 17)); item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter); self.process_table.setItem(row, 1, item)
        self.process_refresh_btn.setEnabled(True); self._filter_processes(); self._update_process_count(); self._set_activity("فهرست پردازه‌ها به‌روزرسانی شد.", "Process list refreshed.", "success", False)

    def _filter_processes(self, *_):
        if not hasattr(self, "process_table"): return
        query = self.process_search.text().strip().lower()
        for row in range(self.process_table.rowCount()):
            item = self.process_table.item(row, 1); self.process_table.setRowHidden(row, bool(query and item and query not in item.text().lower()))

    def _update_process_count(self):
        count = len(self.selected_processes()); self.process_count_label.setText(self.tr(f"{count} انتخاب", f"{count} selected"))

    def _save_process_selection(self):
        self.storage.settings["bypass_processes"] = self.selected_processes()
        self.storage.save_settings()
        self._update_process_count()
        # Xray routing rules are generated at start. Debounce rapid row changes,
        # then perform one controlled restart so the visible switch immediately
        # affects the active tunnel instead of only the next app launch.
        if self.engine.running or self.connecting:
            self._bypass_apply_timer.start()
            self._set_activity("در حال اعمال عبور مستقیم برنامه‌ها…", "Applying app bypass changes…", "running", True)

    def _apply_bypass_changes(self):
        if self._closing or not (self.engine.running or self.connecting):
            return
        self._append_log("APP BYPASS changed; restarting the tunnel with updated process rules")
        self._cancel_connect_attempt(notify=False)
        self.connection_error = ""
        self._set_state(False)

        def reconnect():
            if self._closing or self.engine.running or self.connecting:
                return
            self.toggle_connection()

        QTimer.singleShot(180, reconnect)

    def selected_processes(self):
        values = []
        for row in range(self.process_table.rowCount()):
            item, toggle = self.process_table.item(row, 1), self.process_table.cellWidget(row, 0)
            if item and toggle and toggle.isChecked(): values.append(item.text())
        return values

    def check_ip(self, proxy=None):
        use_proxy = self.engine.running if proxy is None else proxy
        self.ip_button.setEnabled(False); self._set_activity("در حال بررسی آی‌پی عمومی…", "Checking public IP…")
        def work():
            try: ip = current_ip(use_proxy); self.bridge.log.emit(f"Public IP ({'tunnel' if use_proxy else 'direct'}): {ip}"); self.bridge.ip.emit(ip)
            except Exception as exc: self.bridge.error.emit(str(exc))
        threading.Thread(target=work, daemon=True).start()

    def reality_probe(self):
        profile = self.storage.selected()
        if not profile: self.show_toast(self.tr("ابتدا یک کانفیگ انتخاب کنید", "Select a config first"), "warning"); return
        self._set_activity("در حال تست TCP و TLS مقصد…", "Testing target TCP and TLS…")
        def work():
            ok, ms = tcp_ping(profile.address, profile.port, 5); self.bridge.log.emit(f"Reality Probe {profile.address}:{profile.port} => {'OK' if ok else 'FAIL'} {ms:.0f} ms"); self.bridge.activity.emit(self.tr(f"تست مقصد {'موفق' if ok else 'ناموفق'} بود؛ {ms:.0f} ms", f"Target probe {'passed' if ok else 'failed'}; {ms:.0f} ms"), "success" if ok else "error", False)
        threading.Thread(target=work, daemon=True).start()

    def _open_log_file(self):
        if not LOG_FILE.exists():
            self._handle_error(self.tr("فایل لاگ هنوز ساخته نشده است", "The log file has not been created yet")); return
        os.startfile(LOG_FILE); self._set_activity("فایل لاگ باز شد.", "Log file opened.", "success", False)

    def shutdown(self):
        if self._closing:
            return
        self._closing = True
        if self._tray is not None:
            self._tray.hide()
        self._bypass_apply_timer.stop()
        self.scan_cancelled = True; self._scan_cancel_event.set(); self._scan_generation += 1; self._update_generation += 1
        try:
            self._cancel_connect_attempt(wait=True, notify=False)
        except Exception as exc:
            self._pending_file_log_lines.append(f"Shutdown cleanup retry: {exc}")
        try:
            # Retry independently: proxy restoration must not be skipped if
            # cancelling a worker or stopping Xray raised first.
            self.engine.stop(notify=False)
        except Exception as exc:
            self._pending_file_log_lines.append(f"Shutdown proxy restore pending: {exc}")
        finally:
            self._flush_log_buffer(final=True)

    def closeEvent(self, event):
        if (not self._force_quit and self.close_to_tray.isChecked()
                and self._tray is not None):
            event.ignore()
            self.hide()
            self._tray.show()
            if not self._tray_hint_shown:
                self._tray.showMessage(
                    "UAC Spoofer Desktop",
                    self.tr("برنامه در System Tray در حال اجراست؛ برای بازگشت روی آیکن آن کلیک کنید.",
                            "The app is still running in the system tray. Click its icon to restore it."),
                    QSystemTrayIcon.MessageIcon.Information,
                    3200,
                )
                self._tray_hint_shown = True
            return
        self.shutdown()
        event.accept()


COLOR_TOKENS = {
    "background": "#050b18", "bgsoft": "#071225", "surface": "#0a1830",
    "surface2": "#0d2340", "border": "rgba(54, 211, 255, 0.22)",
    "borderstrong": "rgba(54, 211, 255, 0.55)", "accent": "#23f5e0",
    "accent2": "#2cc7ff", "purple": "#7c3cff", "success": "#23f5a6",
    "warning": "#ffd166", "danger": "#ff5c7c", "muted": "#9fb4d8",
    "text": "#f4f8ff", "checkicon": str(ASSETS / "ui" / "check.svg").replace("\\", "/"),
    "chevronicon": str(ASSETS / "ui" / "chevron-down.svg").replace("\\", "/"),
}

STYLE = """
* { font-family: "Vazirmatn", "Segoe UI"; font-size: 13px; color: $text; outline: 0; }
QWidget { background: transparent; }
QMainWindow, QWidget#windowRoot { background: $background; }
QWidget#page, QWidget#pageBody, QStackedWidget#content, QFrame#contentShell, QFrame#activityWrap { background: transparent; }
QScrollArea#pageScroll, QScrollArea#pageScroll > QWidget, QScrollArea#pageScroll > QWidget > QWidget { background: transparent; border: 0; }
*[technical="true"] { font-family: "Cascadia Mono", "Segoe UI", "Consolas"; }
QToolTip { background: #102441; color: #eafaff; border: 1px solid #326789; border-radius: 8px; padding: 7px 10px; }
QToolButton#helpDot { background: rgba(16,52,80,0.88); color: #78eefa; border: 1px solid rgba(54,211,255,0.36); border-radius: 12px; font-size: 13px; font-weight: 900; padding: 0; }
QToolButton#helpDot:hover, QToolButton#helpDot:focus { background: rgba(22,91,110,0.95); color: #ffffff; border-color: #23f5e0; }

QFrame#sidebar { background: qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 rgba(7,23,42,248),stop:0.5 rgba(5,17,34,250),stop:1 rgba(5,12,27,252)); border-right: 1px solid $border; }
QFrame#sidebar[rtl="true"] { border-right: 0; border-left: 1px solid $border; }
QFrame#logoCard { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(13,40,58,235),stop:1 rgba(8,27,48,225)); border: 1px solid rgba(35,245,224,0.25); border-radius: 20px; }
QLabel#logoMark { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 $accent,stop:1 $accent2); border: 1px solid rgba(205,255,251,0.8); border-radius: 16px; qproperty-alignment: AlignCenter; }
QLabel#brand { font-size: 17px; font-weight: 900; color: #f7fdff; }
QLabel#version { color: #59e9f0; font-size: 10px; font-weight: 800; letter-spacing: 1.5px; }
QPushButton#navButton { text-align: left; background: transparent; border: 1px solid transparent; border-radius: 14px; padding: 12px 29px 12px 16px; color: #b3c5dc; font-size: 14px; font-weight: 650; }
QPushButton#navButton[rtl="true"] { text-align: left; padding: 12px 16px 12px 29px; }
QPushButton#navButton:hover { background: rgba(18,50,76,0.72); border-color: rgba(54,211,255,0.18); color: #f7fcff; }
QPushButton#navButton:focus { border-color: $borderstrong; }
QPushButton#navButton:pressed { background: rgba(16,67,83,0.82); }
QPushButton#navButton:checked { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(6,105,111,0.74),stop:0.55 rgba(11,76,95,0.78),stop:1 rgba(19,43,73,0.72)); color: #d8fffb; border: 1px solid rgba(35,245,224,0.45); border-left: 3px solid $accent; font-weight: 850; }
QPushButton#navButton[rtl="true"]:checked { border-left: 1px solid rgba(35,245,224,0.45); border-right: 3px solid $accent; }
QFrame#sidebarFooter { background: rgba(7,24,45,0.82); border: 1px solid rgba(54,211,255,0.18); border-radius: 15px; }
QPushButton#footerAction { background: transparent; border: 1px solid transparent; border-radius: 10px; padding: 9px 11px; color: #b3c7dc; text-align: left; font-weight: 600; }
QPushButton#footerAction:hover { background: rgba(19,53,79,0.8); border-color: rgba(54,211,255,0.18); color: #78f4eb; }
QFrame#ratingCard { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(17,26,71,0.9),stop:1 rgba(43,17,91,0.74)); border: 1px solid rgba(124,60,255,0.48); border-radius: 17px; }
QLabel#ratingTitle { font-size: 14px; font-weight: 850; color: #f7f4ff; }
QLabel#ratingText { font-size: 11px; color: #b7addc; }
QPushButton#ratingButton { min-height: 30px; background: rgba(76,42,146,0.34); border: 1px solid rgba(158,115,255,0.42); color: #e5dbff; padding: 5px 9px; }
QPushButton#ratingButton:hover { background: rgba(106,57,200,0.52); border-color: #a88aff; }

QFrame#pageHeader { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(10,30,57,0.92),stop:0.52 rgba(7,24,47,0.86),stop:1 rgba(17,26,63,0.84)); border: 1px solid rgba(54,211,255,0.22); border-radius: 21px; }
QLabel#pageHeaderIcon { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(18,91,103,0.76),stop:1 rgba(17,45,83,0.88)); border: 1px solid rgba(81,249,235,0.38); border-radius: 17px; qproperty-alignment: AlignCenter; }
QLabel#pageEyebrow { color: #6ee9ef; font-size: 9px; font-weight: 900; letter-spacing: 1.8px; }
QLabel#pageTitle { font-size: 29px; font-weight: 900; color: #f8fcff; }
QLabel#pageSubtitle { color: #b3c7df; font-size: 13px; font-weight: 520; }
QLabel#summaryPill { min-height: 24px; min-width: 92px; padding: 6px 12px; color: #c9fbff; background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(7,51,68,0.86),stop:1 rgba(15,38,76,0.88)); border: 1px solid rgba(64,229,235,0.34); border-radius: 12px; font-size: 11px; font-weight: 800; }
QFrame#statusPill { background: rgba(7,22,44,0.86); border: 1px solid rgba(54,211,255,0.22); border-radius: 16px; }
QFrame#statusPill[state="connected"] { border-color: rgba(35,245,166,0.46); background: rgba(7,43,47,0.76); }
QFrame#statusPill[state="connecting"] { border-color: rgba(255,209,102,0.45); }
QFrame#statusPill[state="error"] { border-color: rgba(255,92,124,0.55); background: rgba(55,14,37,0.66); }
QLabel#statusPillText { color: #d4e2f5; font-size: 12px; font-weight: 700; }

QFrame#heroCard { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(8,25,55,0.96),stop:0.55 rgba(6,28,59,0.92),stop:1 rgba(7,48,72,0.9)); border: 1px solid rgba(54,211,255,0.46); border-radius: 26px; }
QFrame#orbShell { background: rgba(5,22,43,0.54); border: 1px solid rgba(54,211,255,0.15); border-radius: 30px; }
QLabel#orbCaption { color: #6ea2bd; font-size: 9px; font-weight: 850; letter-spacing: 2.4px; }
QLabel#heroBadge, QLabel#sectionEyebrow { color: $accent; font-size: 10px; font-weight: 900; letter-spacing: 1.8px; }
QLabel#heroStatus, QLabel#heroStatusOn, QLabel#heroStatusError { color: #f8fbff; font-size: 38px; font-weight: 900; }
QLabel#heroStatusOn { color: #cffff9; }
QLabel#heroStatusError { color: #ffd9e2; }
QLabel#heroHint { color: #adc0dc; font-size: 15px; }

QFrame#metricCard { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(10,29,60,0.94),stop:1 rgba(8,21,44,0.92)); border: 1px solid rgba(54,211,255,0.24); border-radius: 19px; }
QFrame#metricCard:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(12,39,72,0.96),stop:1 rgba(8,29,53,0.94)); border-color: rgba(54,211,255,0.58); }
QLabel#metricIcon { background: rgba(10,57,76,0.72); border: 1px solid rgba(35,245,224,0.26); border-radius: 10px; qproperty-alignment: AlignCenter; }
QLabel#metricLabel, QLabel#fieldLabel { color: #a9bdd7; font-size: 11px; font-weight: 750; }
QLabel#metricValue { color: #f7fbff; font-size: 22px; font-weight: 850; }
QLabel#metricSecondary { color: #55e7df; font-family: "Cascadia Mono", "Segoe UI", "Consolas"; font-size: 11px; font-weight: 650; }
QFrame#quickControls, QFrame#sniActionBar { background: rgba(9,25,54,0.86); border: 1px solid rgba(54,211,255,0.24); border-radius: 18px; }
QFrame#toggleOption, QFrame#carrierControl { background: rgba(8,24,47,0.74); border: 1px solid rgba(54,211,255,0.13); border-radius: 12px; }
QFrame#toggleOption:hover, QFrame#carrierControl:hover { border-color: rgba(54,211,255,0.35); background: rgba(12,36,61,0.82); }
QLabel#controlLabel { color: #d3e0ee; font-size: 12px; font-weight: 650; }
QCheckBox#toggleSwitch { background: transparent; border: 0; padding: 0; }

QFrame#activityBar { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(8,26,53,0.96),stop:0.7 rgba(8,30,55,0.94),stop:1 rgba(10,37,66,0.92)); border: 1px solid rgba(54,211,255,0.25); border-radius: 15px; }
QFrame#activityBar[state="success"] { border-color: rgba(35,245,166,0.36); }
QFrame#activityBar[state="warning"] { border-color: rgba(255,209,102,0.42); }
QFrame#activityBar[state="error"] { border-color: rgba(255,92,124,0.52); }
QLabel#activityTitle { color: #61dce9; font-size: 9px; font-weight: 900; letter-spacing: 1.5px; }
QLabel#activityMessage { color: #d9e7f5; font-size: 12px; font-weight: 600; }

QPushButton { min-height: 38px; background: rgba(17,43,76,0.9); border: 1px solid rgba(82,134,178,0.52); border-radius: 11px; padding: 8px 14px; color: #eaf4ff; font-weight: 700; }
QPushButton:hover { background: rgba(24,59,95,0.96); border-color: rgba(35,245,224,0.72); color: #ffffff; }
QPushButton:focus { border: 1px solid $accent; }
QPushButton:pressed { background: rgba(10,91,101,0.92); padding-top: 9px; padding-bottom: 7px; }
QPushButton:disabled { background: rgba(9,20,37,0.78); border-color: rgba(65,91,121,0.34); color: #536b86; }
QPushButton#connectButton, QPushButton#primaryButton, QPushButton#scanPrimaryButton, QPushButton#primaryAction, QPushButton#modalPrimary { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 $accent,stop:1 $accent2); border: 1px solid rgba(199,255,250,0.86); color: #031422; font-size: 14px; font-weight: 900; }
QPushButton#primaryButton:disabled, QPushButton#scanPrimaryButton:disabled, QPushButton#primaryAction:disabled, QPushButton#modalPrimary:disabled { background: rgba(9,20,37,0.82); border-color: rgba(65,91,121,0.34); color: #536b86; }
QPushButton#connectButton { border-radius: 15px; font-size: 17px; }
QPushButton#connectButton:hover, QPushButton#scanPrimaryButton:hover, QPushButton#primaryAction:hover, QPushButton#modalPrimary:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #5ffbe9,stop:1 #61dcff); border-color: #e3ffff; }
QPushButton#connectButton[state="connected"] { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #0c877d,stop:1 #12b99f); color: #effffd; }
QPushButton#connectButton[state="cancel"] { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #82502f,stop:1 #9f3150); border-color: #ffc56f; color: #fffaf2; }
QPushButton#connectButton[state="cancel"]:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #9c6037,stop:1 #bd3b60); border-color: #ffe1a3; color: #ffffff; }
QPushButton#connectButton[state="loading"]:disabled { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #295168,stop:1 #1e6874); border-color: #4d9aa3; color: #d5fffb; }
QPushButton#connectButton[state="error"] { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #7f2944,stop:1 #a82f55); border-color: #ff7891; color: #fff5f7; }
QPushButton#secondaryAction, QPushButton#modalSecondary, QPushButton#advancedButton { background: rgba(13,35,64,0.94); border-color: rgba(88,135,183,0.54); }
QPushButton#advancedButton { min-height: 44px; padding: 9px 17px; }
QPushButton#quietButton, QPushButton#metricAction, QPushButton#toolAction { background: rgba(8,26,50,0.5); border-color: rgba(80,127,167,0.44); color: #c1d3e4; }
QPushButton#quietButton:hover, QPushButton#metricAction:hover, QPushButton#toolAction:hover { background: rgba(17,55,78,0.8); color: #84f8ef; border-color: rgba(35,245,224,0.52); }
QPushButton#dangerButton { background: rgba(78,20,43,0.56); border-color: rgba(255,92,124,0.42); color: #ffb7c5; }
QPushButton#dangerButton:hover { background: rgba(116,29,56,0.76); border-color: #ff718c; color: #fff1f4; }

QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QListWidget, QTableWidget { background: rgba(4,15,31,0.92); border: 1px solid rgba(66,118,161,0.55); border-radius: 11px; padding: 8px 10px; selection-background-color: #0b7c82; selection-color: #ffffff; }
QLineEdit:hover, QTextEdit:hover, QPlainTextEdit:hover, QComboBox:hover { border-color: rgba(80,164,201,0.72); }
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus, QListWidget:focus, QTableWidget:focus { border: 1px solid $accent; background: rgba(6,22,42,0.98); }
QLineEdit[invalid="true"], QTextEdit[invalid="true"] { border: 1px solid $danger; background: rgba(65,15,35,0.55); }
QComboBox { min-height: 28px; padding-left: 11px; padding-right: 34px; }
QComboBox::drop-down { border: 0; width: 30px; }
QComboBox::down-arrow { image: url("$chevronicon"); width: 14px; height: 14px; }
QComboBox QAbstractItemView { background: #0b1d35; border: 1px solid #315879; border-radius: 8px; padding: 5px; selection-background-color: #0e5966; }
QAbstractSpinBox::up-button, QAbstractSpinBox::down-button { width: 0; height: 0; border: 0; }
QCheckBox { spacing: 9px; color: #d1deec; }
QCheckBox::indicator { width: 18px; height: 18px; border: 1px solid #4d6e8e; border-radius: 5px; background: #071529; }
QCheckBox::indicator:hover { border-color: $accent; }
QCheckBox::indicator:checked { image: url("$checkicon"); background: $accent; border-color: #a9fff7; }
QCheckBox::indicator:disabled { background: #111f32; border-color: #293d53; }
QCheckBox#toggleSwitch::indicator { width: 0; height: 0; border: 0; image: none; }

QFrame#numericInput { background: #06162a; border: 1px solid rgba(66,118,161,0.56); border-radius: 10px; min-width: 112px; }
QLineEdit#numericEdit { background: transparent; border: 0; padding: 2px; font-family: "Segoe UI"; font-weight: 850; color: #eaffff; }
QPushButton#numericStep { min-height: 30px; background: rgba(17,54,82,0.9); border: 0; border-radius: 7px; padding: 0; color: #72f3e7; font-size: 16px; font-weight: 850; }
QPushButton#numericStep:hover { background: #176079; color: white; }
QLabel#numericSuffix { color: #7f98b4; font-size: 10px; }

QFrame#pageToolbar { background: rgba(9,25,51,0.88); border: 1px solid rgba(54,211,255,0.2); border-radius: 15px; }
QFrame#configPanel, QFrame#tableFrame { background: rgba(7,21,43,0.86); border: 1px solid rgba(54,211,255,0.21); border-radius: 17px; }
QTabWidget#profileTabs::pane, QTabWidget#scannerTabs::pane { background: rgba(5,17,34,0.84); border: 0; border-top: 1px solid rgba(54,211,255,0.17); border-radius: 12px; top: -1px; }
QTabBar::tab { background: rgba(9,27,51,0.82); padding: 10px 23px; border: 1px solid transparent; border-radius: 10px; margin: 4px; color: $muted; font-weight: 650; }
QTabBar::tab:hover { background: rgba(18,53,80,0.82); color: $text; }
QTabBar::tab:selected { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(9,90,94,0.8),stop:1 rgba(13,52,76,0.82)); border-color: rgba(35,245,224,0.42); color: #bcfff8; font-weight: 850; }
QTabBar::tab:focus { border-color: $accent; }
QTabBar::tab:disabled { color: #425a73; background: #081525; }
QListWidget#configList { background: transparent; border: 0; border-radius: 0; padding: 9px; }
QListWidget#configList::item { min-height: 62px; background: rgba(9,28,53,0.86); border: 1px solid rgba(62,113,154,0.34); border-radius: 13px; padding: 13px 15px; margin: 3px 5px; color: #d8e6f3; }
QListWidget#configList::item:hover { background: rgba(13,45,70,0.92); border-color: rgba(54,211,255,0.38); }
QListWidget#configList::item:selected { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(8,81,89,0.88),stop:1 rgba(12,47,75,0.9)); border: 1px solid rgba(35,245,224,0.7); color: #ffffff; }

QFrame#scanControlCard { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(10,31,62,0.94),stop:1 rgba(7,22,45,0.92)); border: 1px solid rgba(54,211,255,0.26); border-radius: 19px; }
QFrame#scanOptions { background: rgba(7,24,48,0.82); border: 1px solid rgba(54,211,255,0.18); border-radius: 14px; }
QLabel#helperText, QLabel#settingsSubtitle, QLabel#modalSubtitle { color: #aebfd5; font-size: 12px; }
QPlainTextEdit#domainEditor { font-family: "Cascadia Mono", "Consolas"; font-size: 13px; color: #d9f8f5; background: qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 rgba(3,15,31,0.98),stop:1 rgba(5,21,40,0.98)); border-radius: 12px; padding: 12px; }
QFrame#scanProgressPanel { background: rgba(8,25,49,0.9); border: 1px solid rgba(54,211,255,0.2); border-radius: 14px; }
QLabel#scanStatus { color: #a8bad0; font-size: 11px; font-weight: 800; }
QLabel#scanStatus[state="running"] { color: #71ecfa; }
QLabel#scanStatus[state="success"] { color: $success; }
QLabel#scanStatus[state="warning"] { color: $warning; }
QLabel#scanPercent { color: $accent; font-size: 15px; font-weight: 900; }
QLabel#scanDomain { color: #829bb5; font-family: "Cascadia Mono", "Consolas"; font-size: 11px; }
QTableWidget#resultsTable, QTableWidget#processTable { background: rgba(4,15,31,0.88); border: 0; border-radius: 0; padding: 0; alternate-background-color: rgba(8,24,45,0.78); gridline-color: transparent; }
QTableWidget#resultsTable::item, QTableWidget#processTable::item { padding: 9px 10px; border-bottom: 1px solid rgba(54,211,255,0.09); color: #cfdeeb; }
QTableWidget#resultsTable::item:hover, QTableWidget#processTable::item:hover { background: rgba(15,53,76,0.78); }
QTableWidget#resultsTable::item:selected, QTableWidget#processTable::item:selected { background: rgba(10,78,84,0.78); color: #f8ffff; }
QHeaderView::section { background: #0c203b; border: 0; border-bottom: 1px solid rgba(54,211,255,0.28); padding: 11px 10px; font-size: 11px; font-weight: 850; color: #a7eef4; }
QLabel#statusBadge { border-radius: 9px; padding: 3px 8px; font-size: 10px; font-weight: 850; }
QLabel#statusBadge[kind="success"] { color: #8ff8bc; background: rgba(8,59,43,0.8); border: 1px solid rgba(35,245,166,0.32); }
QLabel#statusBadge[kind="warning"] { color: #ffe09b; background: rgba(65,45,12,0.78); border: 1px solid rgba(255,209,102,0.35); }
QLabel#statusBadge[kind="danger"] { color: #ffadbc; background: rgba(66,17,37,0.78); border: 1px solid rgba(255,92,124,0.38); }
QLabel#statusBadge[kind="info"] { color: #9aebff; background: rgba(9,48,70,0.8); border: 1px solid rgba(44,199,255,0.32); }
QLabel#selectionText { color: #9bb0c8; font-size: 11px; font-weight: 700; }

QFrame#terminalCard { background: rgba(3,12,25,0.96); border: 1px solid rgba(54,211,255,0.24); border-radius: 17px; }
QFrame#terminalToolbar { background: rgba(9,27,49,0.96); border-bottom: 1px solid rgba(54,211,255,0.2); border-top-left-radius: 16px; border-top-right-radius: 16px; }
QLabel#terminalLive { color: $success; font-size: 10px; font-weight: 900; letter-spacing: 1.5px; }
QLineEdit#logFilter { min-height: 30px; background: rgba(3,14,29,0.8); }
QTextEdit#logs { font-family: "Cascadia Mono", "Consolas"; font-size: 13px; color: #d7e8f5; background: qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 rgba(2,10,22,0.99),stop:1 rgba(3,15,28,0.99)); border: 0; border-radius: 0; padding: 18px; selection-background-color: #12646b; }
QFrame#searchWrap { min-height: 42px; background: rgba(4,15,31,0.9); border: 1px solid rgba(66,118,161,0.5); border-radius: 11px; }
QFrame#searchWrap:focus { border-color: $accent; }
QLineEdit#processSearch { min-height: 30px; background: transparent; border: 0; padding: 4px; }
QLineEdit#processSearch:focus { background: transparent; border: 0; }

QFrame#toolCard, QFrame#helpCard { min-height: 180px; background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(11,32,63,0.94),stop:1 rgba(7,22,44,0.9)); border: 1px solid rgba(54,211,255,0.22); border-radius: 19px; }
QFrame#toolCard:hover, QFrame#helpCard:hover { border-color: rgba(54,211,255,0.52); background: rgba(12,39,70,0.94); }
QLabel#toolIcon, QLabel#supportIcon, QLabel#modalIcon, QLabel#helpIcon { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(12,76,87,0.82),stop:1 rgba(12,39,75,0.84)); border: 1px solid rgba(35,245,224,0.30); border-radius: 13px; qproperty-alignment: AlignCenter; }
QLabel#toolStatus { padding: 4px 8px; border-radius: 8px; color: #ffbdca; background: rgba(73,17,36,0.7); border: 1px solid rgba(255,92,124,0.3); font-size: 10px; font-weight: 800; }
QLabel#toolStatus[available="true"] { color: #8ff8bc; background: rgba(8,58,42,0.72); border-color: rgba(35,245,166,0.3); }
QLabel#toolTitle, QLabel#supportTitle, QLabel#helpTitle { color: #f7fcff; font-size: 18px; font-weight: 880; }
QLabel#toolDescription, QLabel#supportDescription, QLabel#helpText { color: #b4c7dc; font-size: 13px; font-weight: 500; }
QFrame#supportHero { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(8,42,62,0.92),stop:0.7 rgba(8,27,55,0.94),stop:1 rgba(32,18,75,0.82)); border: 1px solid rgba(54,211,255,0.32); border-radius: 21px; }
QFrame#updateCard { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(8,31,57,0.96),stop:1 rgba(9,24,52,0.94)); border: 1px solid rgba(54,211,255,0.24); border-radius: 18px; }
QFrame#updateCard[state="checking"] { border-color: rgba(44,199,255,0.56); }
QFrame#updateCard[state="available"] { border-color: rgba(35,245,166,0.68); background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(7,55,64,0.96),stop:1 rgba(15,31,68,0.95)); }
QFrame#updateCard[state="error"] { border-color: rgba(255,92,124,0.55); }
QLabel#updateIcon { background: rgba(35,245,224,0.10); border: 1px solid rgba(35,245,224,0.30); border-radius: 14px; padding: 10px; }
QLabel#updateTitle { color: #f4f8ff; font-size: 16px; font-weight: 800; }
QLabel#updateStatus { color: #b9cce2; font-size: 12px; }
QLabel#updateVersions { color: #67e8f9; font-size: 12px; font-weight: 700; }
QLabel#credits { color: #657f9c; font-size: 11px; padding: 12px; }

QDialog#advancedDialog, QDialog#profileDialog, QMessageBox, QMessageBox#cyberMessageBox { background: #071225; border: 1px solid rgba(54,211,255,0.32); }
QFrame#modalHeader { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(12,43,72,0.98),stop:0.68 rgba(8,32,59,0.98),stop:1 rgba(19,35,74,0.96)); border-bottom: 1px solid rgba(54,211,255,0.28); }
QFrame#modalFooter { background: rgba(5,18,36,0.98); border-top: 1px solid rgba(54,211,255,0.18); }
QScrollArea#modalScroll, QScrollArea#modalScroll > QWidget, QScrollArea#modalScroll > QWidget > QWidget { background: #071225; border: 0; }
QFrame#settingsSection { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(11,33,62,0.96),stop:1 rgba(7,24,48,0.95)); border: 1px solid rgba(54,211,255,0.2); border-radius: 16px; }
QLabel#modalTitle { color: #f7fcff; font-size: 24px; font-weight: 900; }
QLabel#settingsTitle { color: #edfaff; font-size: 15px; font-weight: 850; }
QTextEdit#configEditor { font-family: "Cascadia Mono", "Consolas"; font-size: 12px; }
QLabel#validationError { color: #ff9eb0; background: rgba(73,17,36,0.6); border: 1px solid rgba(255,92,124,0.3); border-radius: 9px; padding: 8px 10px; }
QDialogButtonBox QPushButton, QMessageBox QPushButton { min-width: 96px; }
QMessageBox QLabel { color: $text; min-width: 340px; font-size: 13px; }

QFrame#toast { background: rgba(10,31,57,0.98); border: 1px solid rgba(54,211,255,0.38); border-radius: 14px; }
QFrame#toast[kind="success"] { border-color: rgba(35,245,166,0.5); }
QFrame#toast[kind="warning"] { border-color: rgba(255,209,102,0.58); }
QFrame#toast[kind="danger"] { border-color: rgba(255,92,124,0.62); }
QLabel#toastText { color: #eefaff; font-weight: 700; }
QPushButton#toastAction { min-height: 28px; background: transparent; border: 0; color: #72f6ec; font-weight: 850; padding: 5px 8px; }

QScrollBar:vertical { background: rgba(5,15,30,0.72); width: 10px; margin: 2px; border-radius: 5px; }
QScrollBar::handle:vertical { background: #27516d; border-radius: 5px; min-height: 36px; }
QScrollBar::handle:vertical:hover { background: #387b93; }
QScrollBar:horizontal { background: rgba(5,15,30,0.72); height: 10px; margin: 2px; border-radius: 5px; }
QScrollBar::handle:horizontal { background: #27516d; border-radius: 5px; min-width: 36px; }
QScrollBar::handle:horizontal:hover { background: #387b93; }
QScrollBar::add-line, QScrollBar::sub-line, QScrollBar::add-page, QScrollBar::sub-page { width: 0; height: 0; background: transparent; }
"""
for _name, _value in sorted(COLOR_TOKENS.items(), key=lambda item: -len(item[0])):
    STYLE = STYLE.replace(f"${_name}", _value)
