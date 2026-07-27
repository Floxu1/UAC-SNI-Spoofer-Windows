from __future__ import annotations

import os
import concurrent.futures
import ctypes
import html
import math
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import uuid
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
    QRadialGradient, QPainterPath, QPixmap, QFontMetrics,
    QTextCursor, QTextCharFormat, QAction,
)
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog,
    QFileDialog, QFrame, QGridLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QListWidget, QListWidgetItem, QMainWindow, QMessageBox, QPlainTextEdit,
    QPushButton, QScrollArea, QStackedWidget, QTableView,
    QTableWidget, QTableWidgetItem,
    QTabBar, QTabWidget, QTextEdit, QVBoxLayout, QWidget, QSizePolicy, QGraphicsDropShadowEffect,
    QGraphicsOpacityEffect, QBoxLayout, QStyle, QStyleOptionButton, QToolButton,
    QSystemTrayIcon, QMenu,
)

from . import __version__
from .app_config import PROJECT_URL, SUGGESTED_CONFIGS_URL, UPDATE_REPOSITORY_URL
from .engine import Engine, EngineCancelled, format_bytes, mci_quality_score
from .models import ProxyProfile, Tuning, parse_many
from .network import (GeoLocation, ScanResult, current_ip, current_location,
                      profile_ping, profile_real_delay, scan_domains, tcp_ping)
from .paths import ASSETS, DATA_DIR, LOG_FILE
from .sni_batch import LiveConfigResult, SniBatchTester
from .sni_maker import (
    SniConfigMaker, SniImportResult, config_signature,
)
from .sni_maker_widgets import (
    ConfigDropEdit, CountryRail, MakerColumns, MakerFilterProxy,
    MakerResultsModel, MakerRoles, normalize_country_code,
)
from .storage import Storage
from .icons import icon as cyber_icon, pixmap as cyber_pixmap
from .update_checker import SemVersion, UpdateInfo, check_latest_release, parse_github_repository
from .verified_configs import COUNTRIES, VERIFIED_SPOOF_EDGE, VERIFIED_SPOOF_FAKE_SNI


REMOTE_CONFIGS_URL = SUGGESTED_CONFIGS_URL
DEFAULT_UPDATE_REPO_URL = UPDATE_REPOSITORY_URL
DEFAULT_SNI_MAKER_URL = "https://mifa.world/vless"
LEGACY_SNI_MAKER_URLS = frozenset({
    "https://raw.githubusercontent.com/Delta-Kronecker/Sub/refs/heads/main/config/sni/all_configs_sni.txt",
})
USER_CONFIG_ORIGIN = "sni-maker"
MANUAL_PROFILE_ORIGINS = frozenset({"user"})
USER_CONFIG_ORIGINS = frozenset({USER_CONFIG_ORIGIN})
DIRECT_PROFILE_ORIGINS = MANUAL_PROFILE_ORIGINS | USER_CONFIG_ORIGINS


def _parse_ping_latency(output: str) -> float | None:
    matches = re.findall(r"(?:time|زمان)\s*[=<]\s*(\d+(?:\.\d+)?)\s*ms", output, re.IGNORECASE)
    if not matches:
        matches = re.findall(r"(\d+(?:\.\d+)?)\s*ms", output, re.IGNORECASE)
    return max(1.0, float(matches[0])) if matches else None


def _direct_ping_8888(timeout_ms: int = 1500) -> float | None:
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    command = ["ping", "-n", "1", "-w", str(timeout_ms), "8.8.8.8"]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=max(2.0, timeout_ms / 1000 + 1.0),
            creationflags=flags,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return _parse_ping_latency(f"{result.stdout}\n{result.stderr}")


def _tun_tls_latency_8888(timeout: float = 8.0) -> float | None:
    started = time.perf_counter()
    raw_socket = None
    try:
        raw_socket = socket.create_connection(("8.8.8.8", 443), timeout=timeout)
        raw_socket.settimeout(timeout)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with context.wrap_socket(raw_socket, server_hostname="dns.google"):
            return max(1.0, (time.perf_counter() - started) * 1000)
    except (OSError, ssl.SSLError):
        if raw_socket is not None:
            try:
                raw_socket.close()
            except OSError:
                pass
        return None


def country_flag_icon(code: str, width: int = 30, height: int = 20) -> QIcon:
    """Draw crisp country flags locally so Windows does not depend on emoji flags."""
    code = str(code or "").upper()
    pixmap = QPixmap(width, height)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, True)
    rect = QRectF(0.75, 0.75, width - 1.5, height - 1.5)
    clip = QPainterPath(); clip.addRoundedRect(rect, 3.0, 3.0)
    painter.setClipPath(clip)

    def fill(color, x=0.0, y=0.0, w=float(width), h=float(height)):
        painter.fillRect(QRectF(x, y, w, h), QColor(color))

    if code in {"AT", "DE", "NL", "PL"}:
        colors = {
            "AT": ("#ed2939", "#ffffff", "#ed2939"),
            "DE": ("#181818", "#dd0000", "#ffce00"),
            "NL": ("#ae1c28", "#ffffff", "#21468b"),
            "PL": ("#ffffff", "#ffffff", "#dc143c"),
        }[code]
        band = height / 3
        for index, color in enumerate(colors): fill(color, 0, index * band, width, band + 0.5)
    elif code == "FR":
        band = width / 3
        for index, color in enumerate(("#0055a4", "#ffffff", "#ef4135")):
            fill(color, index * band, 0, band + 0.5, height)
    elif code == "FI":
        fill("#ffffff"); fill("#003580", width * 0.29, 0, width * 0.16, height); fill("#003580", 0, height * 0.42, width, height * 0.2)
    elif code == "JP":
        fill("#ffffff"); painter.setBrush(QColor("#bc002d")); painter.setPen(Qt.NoPen); painter.drawEllipse(QPointF(width / 2, height / 2), height * 0.29, height * 0.29)
    elif code == "CH":
        fill("#d52b1e")
        arm = min(width, height) * 0.2
        painter.fillRect(QRectF(width * 0.5 - arm * 0.5, height * 0.2, arm, height * 0.6), QColor("#ffffff"))
        painter.fillRect(QRectF(width * 0.3, height * 0.5 - arm * 0.5, width * 0.4, arm), QColor("#ffffff"))
    elif code == "SG":
        fill("#ffffff"); fill("#ef3340", 0, 0, width, height / 2); painter.setPen(Qt.NoPen); painter.setBrush(QColor("#ffffff")); painter.drawEllipse(QPointF(width * 0.25, height * 0.25), height * 0.19, height * 0.19); painter.setBrush(QColor("#ef3340")); painter.drawEllipse(QPointF(width * 0.29, height * 0.25), height * 0.15, height * 0.15)
    elif code == "US":
        stripe = height / 13
        for index in range(13): fill("#b22234" if index % 2 == 0 else "#ffffff", 0, index * stripe, width, stripe + 0.3)
        fill("#3c3b6e", 0, 0, width * 0.42, stripe * 7)
        painter.setPen(QPen(QColor("#ffffff"), 1.1))
        for row in range(3):
            for column in range(3): painter.drawPoint(QPointF(3 + column * 4, 3 + row * 3))
    else:
        fill("#164e63")
        painter.setPen(QColor("#ffffff"))
        painter.setFont(QFont("Segoe UI", max(7, int(height * 0.42)), QFont.Weight.DemiBold))
        painter.drawText(rect, Qt.AlignCenter, code if len(code) == 2 else "•")
    painter.setClipping(False)
    painter.setPen(QPen(QColor(255, 255, 255, 105), 1.0))
    painter.setBrush(Qt.NoBrush)
    painter.drawRoundedRect(rect, 3.0, 3.0)
    painter.end()
    return QIcon(pixmap)

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
    target_latency = Signal(float, str, int)
    maker_imported = Signal(object, object, int)
    maker_batch = Signal(object, int, int, int)
    maker_done = Signal(object, int)
    maker_failed = Signal(str, int)
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
    proxy_mode_applied = Signal(bool, bool, str, int, int)
    tun_mode_applied = Signal(bool, bool, str, int, int)
    gateway_mode_applied = Signal(bool, bool, str, int, int)
    gateway_runtime_state = Signal(str, int, str)
    gateway_devices_changed = Signal(object)
    profile_pings_done = Signal(object, str, int)


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


class ToggleOptionFrame(QFrame):
    def __init__(self, toggle, parent=None, row_click_enabled=True):
        super().__init__(parent)
        self.toggle = toggle
        self.row_click_enabled = bool(row_click_enabled)
        self.setCursor(
            Qt.PointingHandCursor if self.row_click_enabled else Qt.ArrowCursor
        )

    def mouseReleaseEvent(self, event):
        if (
            self.row_click_enabled
            and event.button() == Qt.LeftButton
            and self.isEnabled()
        ):
            self.toggle.toggle()
            event.accept()
            return
        super().mouseReleaseEvent(event)


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


class GatewayDevicesPopup(QFrame):
    def __init__(self, language="fa", parent=None):
        super().__init__(parent, Qt.Popup | Qt.FramelessWindowHint)
        self.setObjectName("gatewayDevicesPopup")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setWindowOpacity(1.0)
        self.setFixedWidth(340)
        self.language = language
        self.devices = {}
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 13, 14, 13)
        root.setSpacing(9)
        header = QHBoxLayout()
        header.setSpacing(8)
        self.icon = QLabel()
        self.icon.setObjectName("gatewayPopupIcon")
        self.icon.setFixedSize(34, 34)
        self.icon.setAlignment(Qt.AlignCenter)
        self.icon.setPixmap(cyber_pixmap("network", "#75fff0", 18))
        titles = QVBoxLayout()
        titles.setContentsMargins(0, 0, 0, 0)
        titles.setSpacing(1)
        self.title = QLabel()
        self.title.setObjectName("gatewayPopupTitle")
        self.subtitle = QLabel()
        self.subtitle.setObjectName("gatewayPopupSubtitle")
        titles.addWidget(self.title)
        titles.addWidget(self.subtitle)
        self.count = QLabel()
        self.count.setObjectName("gatewayPopupCount")
        self.count.setAlignment(Qt.AlignCenter)
        header.addWidget(self.icon)
        header.addLayout(titles, 1)
        header.addWidget(self.count)
        root.addLayout(header)
        self.scroll = QScrollArea()
        self.scroll.setObjectName("gatewayDevicesScroll")
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scroll.setFrameShape(QFrame.NoFrame)
        self.list_widget = QWidget()
        self.list_widget.setObjectName("gatewayDevicesList")
        self.list_layout = QVBoxLayout(self.list_widget)
        self.list_layout.setContentsMargins(0, 0, 0, 0)
        self.list_layout.setSpacing(6)
        self.scroll.setWidget(self.list_widget)
        root.addWidget(self.scroll)
        self.set_language(language)

    @staticmethod
    def _address_key(item):
        address = str(item[0])
        parts = address.split(".")
        if len(parts) == 4 and all(part.isdigit() for part in parts):
            return 0, tuple(int(part) for part in parts)
        return 1, address.casefold()

    def set_language(self, language):
        self.language = "en" if language == "en" else "fa"
        self.setLayoutDirection(
            Qt.LeftToRight if self.language == "en" else Qt.RightToLeft
        )
        self._render()

    def update_devices(self, devices):
        self.devices = {
            str(address): str(mac or "")
            for address, mac in dict(devices or {}).items()
        }
        self._render()

    def _clear_rows(self):
        while self.list_layout.count():
            item = self.list_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def _render(self):
        if not hasattr(self, "list_layout"):
            return
        self._clear_rows()
        count = len(self.devices)
        if self.language == "en":
            self.title.setText("Connected devices")
            self.subtitle.setText("Mobile Gateway live list")
            self.count.setText(f"{count} online")
        else:
            self.title.setText("دستگاه‌های متصل")
            self.subtitle.setText("فهرست زنده درگاه موبایل")
            self.count.setText(f"{count} متصل")
        if not self.devices:
            empty = QFrame()
            empty.setObjectName("gatewayDeviceEmpty")
            empty_layout = QVBoxLayout(empty)
            empty_layout.setContentsMargins(12, 13, 12, 13)
            empty_layout.setSpacing(5)
            empty_icon = QLabel()
            empty_icon.setAlignment(Qt.AlignCenter)
            empty_icon.setPixmap(cyber_pixmap("wifi", "#6f91b5", 23))
            empty_text = QLabel(
                "No device detected yet"
                if self.language == "en"
                else "هنوز دستگاهی شناسایی نشده است"
            )
            empty_text.setObjectName("gatewayDeviceEmptyText")
            empty_text.setAlignment(Qt.AlignCenter)
            empty_text.setWordWrap(True)
            empty_layout.addWidget(empty_icon)
            empty_layout.addWidget(empty_text)
            self.list_layout.addWidget(empty)
            body_height = 86
        else:
            for address, mac in sorted(
                    self.devices.items(), key=self._address_key):
                row = QFrame()
                row.setObjectName("gatewayDeviceRow")
                row_layout = QHBoxLayout(row)
                row_layout.setContentsMargins(10, 7, 10, 7)
                row_layout.setSpacing(9)
                check = QLabel()
                check.setObjectName("gatewayDeviceCheck")
                check.setFixedSize(25, 25)
                check.setAlignment(Qt.AlignCenter)
                check.setPixmap(cyber_pixmap("check-circle", "#23f5a6", 20))
                details = QVBoxLayout()
                details.setContentsMargins(0, 0, 0, 0)
                details.setSpacing(1)
                ip_label = QLabel(address)
                ip_label.setObjectName("gatewayDeviceIp")
                ip_label.setProperty("technical", True)
                ip_label.setLayoutDirection(Qt.LeftToRight)
                ip_label.setAlignment(
                    Qt.AlignLeft | Qt.AlignAbsolute | Qt.AlignVCenter
                )
                mac_label = QLabel(mac or "—")
                mac_label.setObjectName("gatewayDeviceMac")
                mac_label.setProperty("technical", True)
                mac_label.setLayoutDirection(Qt.LeftToRight)
                mac_label.setAlignment(
                    Qt.AlignLeft | Qt.AlignAbsolute | Qt.AlignVCenter
                )
                details.addWidget(ip_label)
                details.addWidget(mac_label)
                state = QLabel("Connected" if self.language == "en" else "متصل")
                state.setObjectName("gatewayDeviceState")
                row_layout.addWidget(check)
                row_layout.addLayout(details, 1)
                row_layout.addWidget(state)
                self.list_layout.addWidget(row)
            body_height = min(270, count * 56)
        self.list_layout.addStretch()
        self.scroll.setFixedHeight(body_height)
        self.setFixedHeight(81 + body_height)


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


class ElidedLabel(QLabel):
    def __init__(self, text="", parent=None):
        super().__init__(parent)
        self._full_text = ""
        self.setTextFormat(Qt.PlainText)
        self.setWordWrap(False)
        self.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.setText(text)

    def setText(self, text):
        self._full_text = str(text or "")
        self._sync_text()

    def _sync_text(self):
        width = self.contentsRect().width()
        shown = self._full_text
        if width > 0:
            shown = QFontMetrics(self.font()).elidedText(
                self._full_text, Qt.ElideRight, width
            )
        super().setText(shown)
        self.setToolTip(self._full_text if shown != self._full_text else "")

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._sync_text()


class MetricCard(MotionFrame):
    def __init__(self, title, icon_name, value_widget=None, parent=None):
        super().__init__(parent)
        self.setObjectName("metricCard")
        self.setAttribute(Qt.WA_Hover, True)
        self.setMinimumHeight(154)
        self.card_layout = QVBoxLayout(self)
        self.card_layout.setContentsMargins(16, 15, 16, 14)
        self.card_layout.setSpacing(8)
        header = QHBoxLayout(); header.setSpacing(9)
        self.icon_label = QLabel(); self.icon_label.setObjectName("metricIcon")
        self.icon_label.setFixedSize(34, 34)
        self.icon_label.setPixmap(cyber_pixmap(icon_name, "#23f5e0", 19))
        self.title = QLabel(title); self.title.setObjectName("metricLabel")
        header.addWidget(self.icon_label); header.addWidget(self.title); header.addStretch()
        self.card_layout.addLayout(header)
        self.value = value_widget or QLabel("—")
        self.value.setObjectName("metricValue")
        self.card_layout.addWidget(self.value, 1)
        self.secondary = QLabel("")
        self.secondary.setObjectName("metricSecondary")
        self.secondary.setLayoutDirection(Qt.LeftToRight)
        self.secondary.setVisible(False)
        self.card_layout.addWidget(self.secondary)
        self.sparkline = MiniSparkline()
        self.sparkline.setVisible(False)
        self.card_layout.addWidget(self.sparkline)

    def set_compact(self, compact):
        compact = bool(compact)
        self.setProperty("compact", compact)
        self.setMinimumHeight(104 if compact else 132)
        self.setMaximumHeight(112 if compact else 160)
        self.card_layout.setContentsMargins(*(10, 8, 10, 8) if compact else (16, 12, 16, 11))
        self.card_layout.setSpacing(3 if compact else 7)
        self.icon_label.setFixedSize(*(27, 27) if compact else (34, 34))
        self.sparkline.setMaximumHeight(19 if compact else 28)
        _restyle(self)

    def set_secondary(self, text):
        self.secondary.setText(text)
        self.secondary.setVisible(bool(text))

    def enable_sparkline(self, enabled=True):
        self.sparkline.setVisible(enabled)


class ProfileListRow(QFrame):
    activated = Signal(str, object)
    activateRequested = Signal(str)
    editRequested = Signal(str)
    deleteRequested = Signal(str)

    def __init__(
            self, profile_id, text, icon, activate_text, active=False,
            ping_text="—", ping_state="unknown", parent=None):
        super().__init__(parent)
        self.profile_id = str(profile_id)
        self.setObjectName("profileListRow")
        self.setFocusPolicy(Qt.NoFocus)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 4, 7, 4)
        layout.setSpacing(8)
        icon_label = QLabel()
        icon_label.setObjectName("profileRowIcon")
        icon_label.setFixedSize(30, 24)
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setPixmap(icon.pixmap(24, 20))
        raw_lines = [line.strip() for line in str(text).splitlines() if line.strip()]
        if len(raw_lines) >= 4:
            shown_lines = [raw_lines[0], raw_lines[1], "  ·  ".join(raw_lines[2:])]
        elif len(raw_lines) == 3:
            shown_lines = [raw_lines[0], "  ·  ".join(raw_lines[1:])]
        else:
            shown_lines = raw_lines or ["—"]
        text_box = QVBoxLayout()
        text_box.setContentsMargins(0, 0, 0, 0)
        text_box.setSpacing(0)
        self.text_labels = []
        for index, line in enumerate(shown_lines):
            label = ElidedLabel(line)
            label.setObjectName(
                "profileRowRecommendation"
                if len(shown_lines) == 3 and index == 0
                else "profileRowTitle" if index == len(shown_lines) - 2
                else "profileRowDetail"
            )
            label.setLayoutDirection(Qt.LeftToRight)
            label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            text_box.addWidget(label, 1)
            self.text_labels.append(label)
        self.activate_button = QToolButton()
        self.activate_button.setObjectName("profileRowActivate")
        self.activate_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.activate_button.setText(str(activate_text))
        self.activate_button.setIcon(cyber_icon("check-circle" if active else "play", "#081a26", 15))
        self.activate_button.setIconSize(QSize(15, 15))
        self.activate_button.setProperty("active", bool(active))
        self.activate_button.setMinimumWidth(88)
        self.activate_button.setMaximumWidth(112)
        self.activate_button.setFixedHeight(30)
        self.activate_button.setFocusPolicy(Qt.NoFocus)
        self.activate_button.setEnabled(not active)
        self.ping_badge = QLabel(str(ping_text))
        self.ping_badge.setObjectName("profileRowPing")
        self.ping_badge.setProperty("state", str(ping_state))
        self.ping_badge.setAlignment(Qt.AlignCenter)
        self.ping_badge.setFixedSize(84, 30)
        self.ping_badge.setLayoutDirection(Qt.LeftToRight)
        self.edit_button = QToolButton()
        self.edit_button.setObjectName("profileRowEdit")
        self.edit_button.setIcon(cyber_icon("edit", "#79dfff", 16))
        self.edit_button.setIconSize(QSize(16, 16))
        self.edit_button.setFixedSize(28, 28)
        self.edit_button.setFocusPolicy(Qt.NoFocus)
        self.delete_button = QToolButton()
        self.delete_button.setObjectName("profileRowDelete")
        self.delete_button.setIcon(cyber_icon("x-circle", "#ff8798", 16))
        self.delete_button.setIconSize(QSize(16, 16))
        self.delete_button.setFixedSize(28, 28)
        self.delete_button.setFocusPolicy(Qt.NoFocus)
        layout.addWidget(icon_label)
        layout.addLayout(text_box, 1)
        layout.addWidget(self.ping_badge)
        layout.addWidget(self.activate_button)
        layout.addWidget(self.edit_button)
        layout.addWidget(self.delete_button)
        self.activate_button.clicked.connect(
            lambda: self.activateRequested.emit(self.profile_id)
        )
        self.edit_button.clicked.connect(
            lambda: self.editRequested.emit(self.profile_id)
        )
        self.delete_button.clicked.connect(
            lambda: self.deleteRequested.emit(self.profile_id)
        )

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.activated.emit(self.profile_id, event.modifiers())
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.editRequested.emit(self.profile_id)
            event.accept()
            return
        super().mouseDoubleClickEvent(event)


class EmptyListWidget(QListWidget):
    deleteRequested = Signal()
    resized = Signal()

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

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Delete:
            self.deleteRequested.emit()
            event.accept()
            return
        super().keyPressEvent(event)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.resized.emit()


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
        scale = min(self.width(), self.height()) / 224.0
        p.scale(scale, scale)
        center = QPointF(self.width() / (2 * scale), self.height() / (2 * scale))
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


class CloseChoiceDialog(QDialog):
    def __init__(self, parent, language="fa", tray_available=True):
        super().__init__(parent)
        self.action = "cancel"
        self.setObjectName("closeChoiceDialog")
        self.setWindowTitle("بستن برنامه" if language == "fa" else "Close UAC Spoofer")
        self.setLayoutDirection(Qt.RightToLeft if language == "fa" else Qt.LeftToRight)
        self.setFixedSize(456, 214)
        self.setSizeGripEnabled(False)
        t = lambda fa, en: fa if language == "fa" else en
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 17, 20, 17)
        layout.setSpacing(13)
        header = QHBoxLayout()
        header.setSpacing(12)
        icon = QLabel()
        icon.setObjectName("closeChoiceIcon")
        icon.setFixedSize(42, 42)
        icon.setAlignment(Qt.AlignCenter)
        icon.setPixmap(cyber_pixmap("shield", "#23f5e0", 29))
        copy = QVBoxLayout()
        copy.setSpacing(2)
        title = QLabel(t("بستن برنامه", "Close UAC Spoofer"))
        title.setObjectName("closeChoiceTitle")
        body = QLabel(t(
            "برنامه به System Tray برود یا کاملاً خارج شود؟",
            "Keep the app in System Tray or quit completely?",
        ))
        body.setObjectName("closeChoiceText")
        body.setWordWrap(True)
        copy.addWidget(title)
        copy.addWidget(body)
        header.addWidget(icon)
        header.addLayout(copy, 1)
        layout.addLayout(header)
        detail = QLabel(t(
            "در Tray، اتصال و هسته اسپوف فعال می‌مانند.",
            "Tray mode keeps the connection and spoof core active.",
        ))
        detail.setObjectName("closeChoiceDetail")
        detail.setWordWrap(True)
        layout.addWidget(detail)
        actions = QHBoxLayout()
        actions.setSpacing(8)
        cancel = QPushButton(t("لغو", "Cancel"))
        cancel.setObjectName("quietButton")
        cancel.setIcon(cyber_icon("x-circle", "#b7cce0", 16))
        cancel.clicked.connect(self.reject)
        quit_button = QPushButton(t("خروج کامل", "Quit"))
        quit_button.setObjectName("dangerButton")
        quit_button.setIcon(cyber_icon("power", "#ffb7c5", 17))
        quit_button.clicked.connect(lambda: self._finish("quit"))
        actions.addWidget(cancel)
        actions.addWidget(quit_button)
        if tray_available:
            tray_button = QPushButton(t("رفتن به Tray", "System Tray"))
            tray_button.setObjectName("trayChoiceButton")
            tray_button.setIcon(cyber_icon("network", "#031422", 17))
            tray_button.clicked.connect(lambda: self._finish("tray"))
            tray_button.setDefault(True)
            actions.addWidget(tray_button)
        layout.addLayout(actions)

    def _finish(self, action):
        self.action = action
        self.accept()


class ProfileDialog(QDialog):
    def __init__(self, parent, profile: ProxyProfile | None = None, language: str = "fa",
                 fake_sni: str = ""):
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
        self.fake_sni = QLineEdit(fake_sni or (profile.spoof_fake_sni if profile else ""))
        self.fake_sni.setReadOnly(True)
        self.fake_sni.setPlaceholderText(t("خودکار از SNI Lab", "Automatic from SNI Lab"))
        self.method = QComboBox(); self.method.addItems(["combined", "fragment", "half", "multi", "sni_split"])
        self.method.setCurrentText(profile.method if profile else "combined")
        for technical in (self.uri, self.address, self.fallback, self.port, self.sni, self.fake_sni, self.method): technical.setLayoutDirection(Qt.LeftToRight)
        self.validation = QLabel(t("یک لینک معتبر VLESS یا Trojan وارد کنید.", "Enter a valid VLESS or Trojan URI.")); self.validation.setObjectName("validationError"); self.validation.setVisible(False)

        identity = self._section(t("هویت و لینک", "Identity & URI"), t("نام نمایشی و لینک اصلی کانفیگ", "Display name and original config URI"), [(t("نام", "Name"), self.name), (t("لینک VLESS / Trojan", "VLESS / Trojan URI"), self.uri)])
        identity.layout().addWidget(self.validation)
        route = self._section(t("مسیر اتصال", "Connection Route"), t("مقادیر فنی برای Edge، SNI و روش انتقال", "Technical edge, SNI and transport values"), [(t("IP اصلی", "Primary IP"), self.address), (t("IP جایگزین", "Fallback IP"), self.fallback), (t("پورت", "Port"), self.port), (t("SNI سرور کانفیگ", "Config Server SNI"), self.sni), (t("SNI جعلی فعال", "Active Fake SNI"), self.fake_sni), (t("روش", "Method"), self.method)])
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
        address = self.address.text().strip()
        fallback_address = self.fallback.text().strip()
        port = self.port.value()
        sni = self.sni.text().strip()
        method = self.method.currentText()
        previous_route = None
        if self.profile is not None:
            previous_route = (
                out.source_uri, out.protocol, out.config_host, out.config_port,
                out.address, out.fallback_address, out.port, out.sni, out.method,
            )
        current_route = (
            source.source_uri, source.protocol, source.config_host, source.config_port,
            address, fallback_address, port, sni, method,
        )
        out.name = self.name.text().strip() or source.name
        out.source_uri = source.source_uri; out.protocol = source.protocol
        out.config_host = source.config_host; out.config_port = source.config_port
        out.route_mode = source.route_mode
        out.address = address; out.fallback_address = fallback_address
        out.port = port; out.sni = sni; out.method = method
        out.origin = self.profile.origin if self.profile else "user"
        if previous_route is not None and previous_route != current_route:
            out.last_ping_ok = False
            out.last_ping_ms = 0.0
            out.country_code = ""
            out.country_latency_ms = 0
            out.verified_spoof = False
            out.verified_route = False
            out.rotating_exit = False
            out.observed_exit_ip = ""
            out.observed_country_code = ""
            out.observed_country_name = ""
            out.country_verified_at = 0.0
            out.country_source = ""
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
        self._update_notification = None; self._update_notification_timer = None; self._update_notification_animation = None; self._pending_update_notification = None
        self._closing = False
        self._force_quit = False
        self._tray = None
        self._tray_hint_shown = False
        self.tray_show_action = None
        self.tray_quit_action = None
        self._connect_generation = 0
        self._proxy_mode_apply_lock = threading.Lock()
        self._mode_apply_generation = 0
        self._mode_apply_cancel = threading.Event()
        self._gateway_requested = False
        self._gateway_apply_lock = threading.Lock()
        self._gateway_apply_generation = 0
        self._gateway_apply_cancel = threading.Event()
        self._gateway_apply_target = None
        self._gateway_apply_reasons = {}
        self._gateway_devices = {}
        self._gateway_runtime_state = "inactive"
        self._connect_cancel = threading.Event()
        self._connect_thread: threading.Thread | None = None
        self._forced_profile_id = ""
        self._pending_profile_switch_id = ""
        self._profile_switch_waiting = False
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
        self._target_latency_generation = 0
        self._target_latency_busy = False
        self._target_latency_pending = False
        self._maker_generation = 0
        self._maker_import_generation = 0
        self._maker_running = False
        self._maker_cancel_event = threading.Event()
        self._maker_tester = None
        self._maker_profiles = {}
        self._maker_base_names = {}
        self._maker_country_labels = {}
        self._maker_last_country_summary = None
        self._maker_import_meta = {}
        self._maker_import_in_progress = False
        self._maker_last_loaded_url = ""
        self._maker_last_converted_editor_text = ""
        self._maker_guide_button = None
        self._maker_guide_effect = None
        self._maker_guide_animation = None
        self._profile_ping_generation = 0
        self._profile_ping_busy = False
        self._profile_ping_cancel = threading.Event()
        self._maker = SniConfigMaker(
            fake_sni=self.storage.tuning.pattern_fake_sni,
        )
        self.engine = Engine(self.bridge.log.emit, self.bridge.state.emit, self.bridge.traffic.emit)
        gateway = getattr(self.engine, "gateway", None)
        if gateway is not None:
            gateway.state_changed = (
                lambda state, count, detail:
                self.bridge.gateway_runtime_state.emit(
                    str(state), int(count), str(detail)
                )
            )
            gateway.devices_changed = (
                lambda devices:
                self.bridge.gateway_devices_changed.emit(dict(devices))
            )
        try:
            self.engine.recover_stale_tun()
        except Exception as exc:
            self._pending_file_log_lines.append(f"sing-box recovery pending: {exc}")
        self._build(); self._setup_tray(); self._wire(); self._configure_technical_widgets(); self.refresh_profiles(); self.refresh_bookmarks(); self.refresh_processes(); self._apply_language(); self._append_log("UAC Spoofer Desktop آماده است")
        self.activity_bar.set_activity("", "idle", False)
        self._target_latency_timer = QTimer(self); self._target_latency_timer.setInterval(10000); self._target_latency_timer.timeout.connect(self._queue_target_latency_probe); self._target_latency_timer.start()
        QTimer.singleShot(300, self._queue_target_latency_probe)
        QTimer.singleShot(1800, lambda: self.check_for_updates(manual=False))
        self._update_poll_timer = QTimer(self); self._update_poll_timer.setInterval(12 * 3600 * 1000); self._update_poll_timer.timeout.connect(lambda: self.check_for_updates(manual=False)); self._update_poll_timer.start()

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
            "SNI Config Maker": ("sparkles", "ساخت و اعتبارسنجی", "CONFIG FACTORY"),
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

    def _toggle_option(self, toggle, persian, english, row_click_enabled=True):
        wrapper = ToggleOptionFrame(
            toggle, row_click_enabled=row_click_enabled
        ); wrapper.setObjectName("toggleOption")
        layout = QHBoxLayout(wrapper); layout.setContentsMargins(10, 7, 10, 7); layout.setSpacing(10)
        label = self._bind_text(QLabel(), persian, english); label.setObjectName("controlLabel")
        label.setAttribute(Qt.WA_TransparentForMouseEvents)
        layout.addWidget(toggle); layout.addWidget(label); layout.addStretch()
        toggle.setAccessibleName(english)
        return wrapper

    def _build(self):
        root = CyberRoot(); self.setCentralWidget(root); layout = QHBoxLayout(root); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(0)
        sidebar = QFrame(); self.sidebar = sidebar; sidebar.setObjectName("sidebar"); sidebar.setAttribute(Qt.WA_StyledBackground, True); sidebar.setFixedWidth(286); side = QVBoxLayout(sidebar); self.sidebar_layout = side; side.setContentsMargins(18, 20, 18, 18); side.setSpacing(4)
        logo = QFrame(); self.logo_card = logo; logo.setObjectName("logoCard"); logo.setMinimumHeight(88); logo_layout = QHBoxLayout(logo); logo_layout.setContentsMargins(14, 12, 14, 12); logo_layout.setSpacing(12)
        mark = QLabel(); mark.setObjectName("logoMark"); mark.setAlignment(Qt.AlignCenter); mark.setFixedSize(52, 52); mark.setPixmap(cyber_pixmap("shield", "#031422", 29)); logo_layout.addWidget(mark)
        logo_text = QVBoxLayout(); logo_text.setSpacing(2); brand = QLabel("UAC SPOOFER"); brand.setObjectName("brand"); logo_text.addWidget(brand); version = QLabel(f"DESKTOP  {__version__}"); version.setObjectName("version"); version.setLayoutDirection(Qt.LeftToRight); logo_text.addWidget(version); logo_layout.addLayout(logo_text, 1); side.addWidget(logo); side.addSpacing(16)
        self.nav = []
        entries = [("home", "خانه", "Home"), ("file-cog", "کانفیگ‌ها", "Configs"), ("sparkles", "سازنده کانفیگ اس‌ان‌آی", "SNI Maker"), ("flask", "آزمایشگاه اس‌ان‌آی", "SNI Lab"), ("activity", "لاگ زنده", "Live Logs"), ("shield", "عبور مستقیم برنامه‌ها", "App Bypass"), ("wrench", "ابزارها", "Tools"), ("headphones", "پشتیبانی", "Support")]
        self.nav_meta = []
        for index, (icon_name, name, english) in enumerate(entries):
            button = NavButton(english if self.language == "en" else name); button.setIcon(cyber_icon(icon_name, "#9fb4d8", 22)); button.setIconSize(QSize(22, 22)); button.setProperty("iconName", icon_name); button.clicked.connect(lambda _, i=index: self.show_page(i)); side.addWidget(button); self.nav.append(button)
            self.nav_meta.append((icon_name, name, english))
        side.addStretch()
        self.rating_card = QFrame(); self.rating_card.setObjectName("ratingCard"); self.rating_card.setMinimumHeight(136); rating_layout = QVBoxLayout(self.rating_card); rating_layout.setContentsMargins(15, 13, 15, 13); rating_layout.setSpacing(4)
        self.rating_title = self._bind_text(QLabel(), "از برنامه راضی هستید؟", "Enjoying the app?"); self.rating_title.setObjectName("ratingTitle")
        self.rating_text = self._bind_text(QLabel(), "با یک ستاره از پروژه حمایت کنید.", "Support the project with a star."); self.rating_text.setObjectName("ratingText"); self.rating_text.setWordWrap(True)
        self.rating_button = self._action_button("ستاره در گیت‌هاب", "Star on GitHub", "external-link", "ratingButton"); self.rating_button.setMinimumHeight(40); self.rating_button.clicked.connect(lambda: webbrowser.open(PROJECT_URL))
        rating_layout.addWidget(self.rating_title); rating_layout.addWidget(self.rating_text); rating_layout.addWidget(self.rating_button); side.addWidget(self.rating_card); side.addSpacing(10)
        footer = QFrame(); self.sidebar_footer = footer; footer.setObjectName("sidebarFooter"); footer_layout = QVBoxLayout(footer); footer_layout.setContentsMargins(7, 7, 7, 7); footer_layout.setSpacing(4)
        self.language_button = QPushButton("English"); self.language_button.setObjectName("footerAction"); self.language_button.setMinimumHeight(44); self.language_button.setIcon(cyber_icon("globe", "#9fb4d8", 19)); self.language_button.setIconSize(QSize(19, 19)); self.language_button.clicked.connect(self.toggle_language); footer_layout.addWidget(self.language_button)
        self.data_button = QPushButton("باز کردن پوشه داده‌ها"); self.data_button.setObjectName("footerAction"); self.data_button.setMinimumHeight(44); self.data_button.setIcon(cyber_icon("folder", "#9fb4d8", 19)); self.data_button.setIconSize(QSize(19, 19)); self.data_button.clicked.connect(lambda: os.startfile(DATA_DIR)); footer_layout.addWidget(self.data_button); side.addWidget(footer)
        layout.addWidget(sidebar)
        content_shell = QFrame(); content_shell.setObjectName("contentShell"); content_layout = QVBoxLayout(content_shell); content_layout.setContentsMargins(0, 0, 0, 0); content_layout.setSpacing(0)
        self.stack = QStackedWidget(); self.stack.setObjectName("content"); content_layout.addWidget(self.stack, 1)
        activity_wrap = QFrame(); self.activity_wrap = activity_wrap; activity_wrap.setObjectName("activityWrap"); activity_layout = QVBoxLayout(activity_wrap); self.activity_layout = activity_layout; activity_layout.setContentsMargins(30, 0, 30, 18)
        self.activity_bar = ActivityBar(self.language); activity_layout.addWidget(self.activity_bar); content_layout.addWidget(activity_wrap)
        layout.addWidget(content_shell, 1)
        pages = [self._home_page(), self._configs_page(), self._sni_maker_page(), self._scanner_page(), self._logs_page(),
                 self._apps_page(), self._tools_page(), self._support_page()]
        for page in pages:
            page.setObjectName("page")
            self.stack.addWidget(page)
        self.show_page(0)

    def _home_page(self):
        page = QWidget(); self.home_page = page; root = QVBoxLayout(page); self.home_root = root; root.setContentsMargins(26, 18, 26, 14); root.setSpacing(12)
        self.status_pill = StatusPill(self.language)
        self.home_header = self._page_header("کنترل اتصال", "Connection Center", f"نسخه دسکتاپ با استفاده از {ltr_isolate('Xray')}، پروکسی سیستم ویندوز و هسته {ltr_isolate('Patterniha Wrong-Sequence')}", "Desktop engine powered by Xray, Windows System Proxy and native TLS fragmentation", self.status_pill); root.addWidget(self.home_header)
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

        self.country_card = QFrame(); self.country_card.setObjectName("countrySelectorCard"); self.country_card.setMinimumHeight(104)
        country_layout = QHBoxLayout(self.country_card); self.country_layout = country_layout; country_layout.setContentsMargins(16, 10, 16, 10); country_layout.setSpacing(12)
        country_icon = QLabel(); self.country_icon = country_icon; country_icon.setObjectName("countryIcon"); country_icon.setFixedSize(46, 46); country_icon.setAlignment(Qt.AlignCenter); country_icon.setPixmap(cyber_pixmap("globe", "#78fff0", 24)); country_layout.addWidget(country_icon, 0, Qt.AlignVCenter)
        country_copy = QVBoxLayout(); country_copy.setSpacing(3)
        self.country_eyebrow = self._bind_text(QLabel(), "انتخاب هوشمند مسیر", "SMART ROUTE SELECTION"); self.country_eyebrow.setObjectName("countryEyebrow")
        self.country_title = self._bind_text(QLabel(), "کشور خروجی", "Exit country"); self.country_title.setObjectName("countryTitle")
        self.country_description = self._bind_text(QLabel(), "با انتخاب کشور، فقط کانفیگ‌های سالم همان کشور دوباره تست می‌شوند و بهترین مورد متصل می‌شود.", "Choose a country to retest its verified configs and connect the best route."); self.country_description.setObjectName("countryDescription"); self.country_description.setWordWrap(True)
        country_copy.addWidget(self.country_eyebrow); country_copy.addWidget(self.country_title); country_copy.addWidget(self.country_description); country_layout.addLayout(country_copy, 1)
        country_actions = QVBoxLayout(); self.country_actions = country_actions; country_actions.setSpacing(5)
        self.country_count = QLabel(); self.country_count.setObjectName("countryCount"); self.country_count.setAlignment(Qt.AlignCenter)
        self.route_source_tabs = QTabBar(); self.route_source_tabs.setObjectName("routeSourceTabs"); self.route_source_tabs.setExpanding(True); self.route_source_tabs.setDrawBase(False)
        self.route_source_tabs.addTab(self.tr("پیشنهادی", "Suggested")); self.route_source_tabs.addTab("User Config")
        route_source = str(self.storage.settings.get("route_source", "suggested") or "suggested").lower()
        self.route_source_tabs.setCurrentIndex(1 if route_source == "user-config" else 0)
        self.route_source_tabs.setAccessibleName("Connection config source")
        source_row = QHBoxLayout(); source_row.setSpacing(7); source_row.addWidget(self.route_source_tabs, 1); source_row.addWidget(self.country_count)
        self.country_combo = QComboBox(); self.country_combo.setObjectName("countryCombo"); self.country_combo.setMinimumWidth(300); self.country_combo.setMinimumHeight(48); self.country_combo.setAccessibleName("Exit country"); self.country_combo.setCursor(Qt.PointingHandCursor); self.country_combo.setIconSize(QSize(30, 20))
        country_actions.addLayout(source_row); country_actions.addWidget(self.country_combo); country_layout.addLayout(country_actions)
        self._refresh_country_selector()
        root.addWidget(self.country_card)

        self.metrics_layout = QGridLayout(); self.metrics_layout.setSpacing(14)
        self.active_profile = ElidedLabel("—"); self.route_card = MetricCard(self.tr("مسیر فعال", "Active Route"), "route", self.active_profile); self.route_card.title.setProperty("i18nFa", "مسیر فعال"); self.route_card.title.setProperty("i18nEn", "Active Route"); self.route_card.setMinimumWidth(230)
        self.route_detail = self.route_card.secondary; self.route_detail.setWordWrap(True)
        self.ping_label = QLabel("—"); self.latency_card = MetricCard(self.tr("پینگ", "Latency"), "gauge", self.ping_label); self.latency_card.title.setProperty("i18nFa", "پینگ"); self.latency_card.title.setProperty("i18nEn", "Latency"); self.latency_card.enable_sparkline(True)
        self.up_label = QLabel("0 B"); self.upload_card = MetricCard(self.tr("آپلود", "Upload"), "upload", self.up_label); self.upload_card.title.setProperty("i18nFa", "آپلود"); self.upload_card.title.setProperty("i18nEn", "Upload")
        self.down_label = QLabel("0 B"); self.download_card = MetricCard(self.tr("دانلود", "Download"), "download", self.down_label); self.download_card.title.setProperty("i18nFa", "دانلود"); self.download_card.title.setProperty("i18nEn", "Download")
        self.ip_label = QLabel("—"); self.ip_card = MetricCard(self.tr("آی‌پی عمومی", "Public IP"), "map-pin", self.ip_label); self.ip_card.title.setProperty("i18nFa", "آی‌پی عمومی"); self.ip_card.title.setProperty("i18nEn", "Public IP")
        self.ip_button = self._action_button("بررسی IP", "Check IP", "refresh", "metricAction"); self.ip_button.clicked.connect(self.check_ip); self.ip_card.layout().addWidget(self.ip_button)
        self.metric_cards = [self.route_card, self.latency_card, self.upload_card, self.download_card, self.ip_card]
        root.addLayout(self.metrics_layout)

        controls = QFrame(); self.quick_controls = controls; controls.setObjectName("quickControls"); self.controls_layout = QGridLayout(controls); self.controls_layout.setContentsMargins(13, 9, 13, 9); self.controls_layout.setHorizontalSpacing(9); self.controls_layout.setVerticalSpacing(7)
        self.auto_mode = ToggleSwitch(); self.auto_mode.setChecked(self.storage.settings.get("auto_mode", True)); self.auto_option = self._toggle_option(self.auto_mode, "حالت خودکار", "Auto Mode")
        self.pick_best = ToggleSwitch(); self.pick_best.setChecked(self.storage.settings.get("pick_best", False)); self.manual_option = self._toggle_option(self.pick_best, "انتخاب بهترین کانفیگ از لیست", "Pick Best in List")
        self.proxy_mode = ToggleSwitch(); self.proxy_mode.setChecked(self.storage.settings.get("proxy_mode", True)); self.proxy_option = self._toggle_option(self.proxy_mode, "پروکسی ویندوز", "Windows Proxy")
        self.proxy_option.setObjectName("proxyModeOption"); self.proxy_option.setProperty("active", self.proxy_mode.isChecked())
        self.proxy_mode.setToolTip(self.tr(
            "خاموش: هسته اسپوف فعال می‌ماند و فقط پروکسی سیستم ویندوز اعمال نمی‌شود.",
            "Off: the spoof core stays active; only Windows System Proxy is skipped.",
        ))
        self.tun_mode = ToggleSwitch(); self.tun_mode.setChecked(self.storage.settings.get("tun_mode", False)); self.tun_option = self._toggle_option(self.tun_mode, "حالت TUN", "TUN Mode")
        self.tun_option.setObjectName("tunModeOption"); self.tun_option.setProperty("active", self.tun_mode.isChecked())
        self.tun_mode.setToolTip(self.tr(
            "تمام ترافیک TCP و UDP ویندوز را از sing-box و هسته اسپوف عبور می‌دهد؛ پینگ CMD مستقیم و واقعی می‌ماند.",
            "Routes Windows TCP and UDP through sing-box and the spoof core; CMD ping remains direct and real.",
        ))
        self.gateway_mode = ToggleSwitch(); self.gateway_mode.setChecked(False); self.gateway_option = self._toggle_option(self.gateway_mode, "درگاه موبایل", "Mobile Gateway", row_click_enabled=False)
        self.gateway_option.setObjectName("gatewayModeOption"); self.gateway_option.setProperty("state", "off")
        self.gateway_devices_badge = QToolButton()
        self.gateway_devices_badge.setObjectName("gatewayDevicesBadge")
        self.gateway_devices_badge.setText("0")
        self.gateway_devices_badge.setIcon(cyber_icon("wifi", "#72eee7", 14))
        self.gateway_devices_badge.setIconSize(QSize(14, 14))
        self.gateway_devices_badge.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.gateway_devices_badge.setCursor(Qt.PointingHandCursor)
        self.gateway_devices_badge.setFixedHeight(26)
        self.gateway_devices_badge.setMinimumWidth(50)
        self.gateway_devices_badge.setMaximumWidth(76)
        self.gateway_devices_badge.setAccessibleName("Mobile Gateway connected devices")
        self.gateway_option.layout().addWidget(
            self.gateway_devices_badge, 0, Qt.AlignVCenter
        )
        self.gateway_devices_popup = GatewayDevicesPopup(self.language, self)
        self.gateway_devices_badge.clicked.connect(
            self._toggle_gateway_devices_popup
        )
        self.gateway_mode.setToolTip(self.tr(
            "با یک کلیک، اینترنت موبایل را از درگاه شبکه این رایانه به تونل تأییدشده هدایت می‌کند.",
            "One click routes mobile internet through this computer and the verified tunnel.",
        ))
        self.proxy_option.setEnabled(not self.tun_mode.isChecked())
        self.carrier = QComboBox(); self.carrier.setObjectName("carrierModeCombo"); self.carrier.addItems(["auto", "mci", "irancell"]); self.carrier.setCurrentText(self.storage.tuning.carrier_mode); self.carrier.setMinimumWidth(100); self.carrier.setMaximumWidth(120); self.carrier.setAccessibleName("Carrier")
        self.carrier_control = QFrame(); self.carrier_control.setObjectName("carrierControl"); self.carrier_control.setMinimumWidth(190); self.carrier_control.setMaximumWidth(220); carrier_layout = QHBoxLayout(self.carrier_control); self.carrier_layout = carrier_layout; carrier_layout.setContentsMargins(7, 3, 7, 3); carrier_layout.setSpacing(6); self.carrier_label = self._bind_text(QLabel(), "اپراتور", "Carrier"); self.carrier_label.setObjectName("controlLabel"); carrier_layout.addWidget(self.carrier_label); carrier_layout.addWidget(self.carrier)
        self.tune_button = self._action_button("تنظیمات پیشرفته", "Advanced Settings", "settings", "advancedButton"); self.tune_button.setProperty("chevron", True); self.tune_button.setIconSize(QSize(19, 19)); self.tune_button.clicked.connect(self.open_tuning)
        root.addWidget(controls)
        self._layout_home_dashboard()
        return page

    def _layout_metric_cards(self, compact):
        if not hasattr(self, "metrics_layout") or self._metrics_compact == compact:
            return
        self._metrics_compact = compact
        while self.metrics_layout.count():
            self.metrics_layout.takeAt(0)
        for column in range(6):
            self.metrics_layout.setColumnStretch(column, 0)
        self.metrics_layout.setSpacing(8 if compact else 12)
        for column, card_widget in enumerate(self.metric_cards):
            card_widget.set_compact(compact)
            card_widget.setMinimumWidth(180 if column == 0 and compact else 220 if column == 0 else 96)
            self.metrics_layout.addWidget(card_widget, 0, column)
            self.metrics_layout.setColumnStretch(column, 2 if column == 0 else 1)

    def _layout_hero(self, compact):
        if not hasattr(self, "hero_layout"):
            return
        self.hero_layout.setDirection(QBoxLayout.LeftToRight)
        self.hero_card.setProperty("compact", bool(compact))
        self.hero_layout.setContentsMargins(*(18, 12, 18, 12) if compact else (32, 22, 28, 22))
        self.hero_layout.setSpacing(18 if compact else 30)
        self.hero_copy_layout.setSpacing(5 if compact else 9)
        self.orb.setFixedSize(*(128, 128) if compact else (224, 224))
        self.orb_shell.setMinimumWidth(160 if compact else 270)
        self.orb_shell.setMaximumWidth(190 if compact else 330)
        self.connect_button.setMinimumSize(176 if compact else 216, 46 if compact else 56)
        self.connect_button.setMaximumHeight(46 if compact else 56)
        _restyle(self.hero_card)

    def _layout_control_bar(self, compact):
        if not hasattr(self, "controls_layout") or self._controls_compact == compact:
            return
        self._controls_compact = compact
        while self.controls_layout.count():
            self.controls_layout.takeAt(0)
        for column in range(8):
            self.controls_layout.setColumnStretch(column, 0)
        for option in (self.auto_option, self.manual_option, self.proxy_option, self.tun_option, self.gateway_option):
            option.layout().setContentsMargins(7, 5, 7, 5)
            option.layout().setSpacing(7)
        if compact:
            self.controls_layout.addWidget(self.auto_option, 0, 0)
            self.controls_layout.addWidget(self.manual_option, 0, 1, 1, 2)
            self.controls_layout.addWidget(self.gateway_option, 0, 3)
            self.controls_layout.addWidget(self.proxy_option, 1, 0)
            self.controls_layout.addWidget(self.tun_option, 1, 1)
            self.controls_layout.addWidget(self.carrier_control, 1, 2)
            self.controls_layout.addWidget(self.tune_button, 1, 3)
            self.controls_layout.setColumnStretch(0, 1)
            self.controls_layout.setColumnStretch(1, 1)
            self.controls_layout.setColumnStretch(2, 1)
            self.controls_layout.setColumnStretch(3, 1)
            self.tune_button.setMaximumWidth(16777215)
        else:
            self.controls_layout.addWidget(self.auto_option, 0, 0)
            self.controls_layout.addWidget(self.manual_option, 0, 1)
            self.controls_layout.addWidget(self.proxy_option, 0, 2)
            self.controls_layout.addWidget(self.tun_option, 0, 3)
            self.controls_layout.addWidget(self.gateway_option, 0, 4)
            self.controls_layout.addWidget(self.carrier_control, 0, 5)
            self.controls_layout.setColumnStretch(6, 1)
            self.controls_layout.addWidget(self.tune_button, 0, 7)
            self.tune_button.setMaximumWidth(230)

    def _layout_home_dashboard(self, narrow=None, dense=None):
        if not hasattr(self, "home_root"):
            return
        narrow = self.width() < 1320 if narrow is None else bool(narrow)
        stack_height = self.stack.height() if hasattr(self, "stack") and self.stack.height() > 100 else self.height() - 76
        dense = stack_height < 760 if dense is None else bool(dense)
        margins = (14, 8, 14, 8) if dense else (26, 18, 26, 14)
        spacing = 7 if dense else 12
        self.home_root.setContentsMargins(*margins)
        self.home_root.setSpacing(spacing)
        self.home_root.setAlignment(Qt.AlignTop)
        header_height = 88 if dense else 100
        country_height = 104
        metric_height = 116 if dense or narrow else 142
        controls_height = 106
        fixed = header_height + country_height + metric_height + controls_height + margins[1] + margins[3] + spacing * 4
        hero_height = max(178, min(318, stack_height - fixed))
        compact_hero = dense or hero_height < 250
        self.home_header.setFixedHeight(header_height)
        self.home_header.setProperty("compact", dense)
        self.home_header.layout().setContentsMargins(*(13, 8, 13, 8) if dense else (19, 12, 19, 12))
        header_icon = self.home_header.findChild(QLabel, "pageHeaderIcon")
        if header_icon is not None:
            header_icon.setFixedSize(*(42, 42) if dense else (54, 54))
        self.hero_card.setFixedHeight(hero_height)
        self._layout_hero(compact_hero)
        self.country_card.setFixedHeight(country_height)
        self.country_card.setProperty("compact", dense)
        self.country_layout.setContentsMargins(*(12, 7, 12, 7) if dense else (16, 10, 16, 10))
        self.country_layout.setSpacing(9 if dense else 12)
        self.country_icon.setFixedSize(*(40, 40) if dense else (46, 46))
        self.country_actions.setDirection(QBoxLayout.TopToBottom)
        self.country_combo.setMinimumWidth(210 if dense else 280)
        self.country_combo.setMaximumWidth(255 if dense else 340)
        self.country_combo.setFixedHeight(38 if dense else 42)
        self.country_count.setMaximumHeight(38 if dense else 28)
        _restyle(self.country_card)
        self._layout_metric_cards(dense or narrow)
        for card_widget in self.metric_cards:
            card_widget.setFixedHeight(metric_height)
        self.ip_button.setFixedHeight(30 if dense or narrow else 38)
        self._layout_control_bar(True)
        self.quick_controls.setFixedHeight(controls_height)
        self.controls_layout.setContentsMargins(10, 5, 10, 5)
        for option in (self.auto_option, self.manual_option, self.proxy_option, self.tun_option, self.gateway_option):
            option.setFixedHeight(40)
        self.carrier_layout.setContentsMargins(4, 3, 4, 3)
        self.carrier_layout.setSpacing(4)
        self.carrier.setFixedHeight(34)
        self.carrier_control.setFixedHeight(42)
        self.tune_button.setFixedHeight(42)
        self.activity_layout.setContentsMargins(18 if dense else 30, 0, 18 if dense else 30, 8 if dense else 14)

    def _layout_sni_maker(self):
        if not hasattr(self, "maker_root"):
            return
        dense = self.height() < 790
        narrow_actions = self.maker_page.width() < 1080
        self.maker_root.setContentsMargins(
            *(12, 8, 12, 8) if dense else (24, 16, 24, 14)
        )
        self.maker_root.setSpacing(6 if dense else 10)
        self.maker_header.setFixedHeight(82 if dense else 94)
        header_layout = self.maker_header.layout()
        header_layout.setContentsMargins(
            *(10, 5, 10, 5) if dense else (15, 8, 15, 8)
        )
        header_icon = self.maker_header.findChild(QLabel, "pageHeaderIcon")
        if header_icon is not None:
            header_icon.setFixedSize(*(40, 40) if dense else (46, 46))
        maker_title = self.maker_header.findChild(QLabel, "pageTitle")
        maker_subtitle = self.maker_header.findChild(QLabel, "pageSubtitle")
        if maker_title is not None:
            maker_title.setMinimumHeight(35)
            maker_title.setAlignment(Qt.AlignVCenter)
        if maker_subtitle is not None:
            maker_subtitle.setMinimumHeight(20)
            maker_subtitle.setWordWrap(False)
        self.maker_source_card.setFixedHeight(128 if dense else 146)
        self.maker_source_editor.setFixedHeight(70 if dense else 86)
        self.maker_control.setFixedHeight(60 if dense else 62)
        self.maker_progress.setFixedHeight(46 if dense else 48)
        self._layout_maker_actions(narrow_actions)
        self.maker_actions.setFixedHeight(
            92 if narrow_actions else 60 if dense else 62
        )
        self.maker_table.verticalHeader().setDefaultSectionSize(42 if dense else 45)
        self.maker_country_rail.setMinimumWidth(0)
        self.maker_country_rail.setMaximumWidth(16777215)
        self._position_maker_select_all()
        _restyle(self.maker_header)

    def _layout_maker_actions(self, compact):
        compact = bool(compact)
        if getattr(self, "_maker_actions_compact", None) == compact:
            return
        self._maker_actions_compact = compact
        layout = self.maker_action_layout
        while layout.count():
            layout.takeAt(0)
        for column in range(7):
            layout.setColumnStretch(column, 0)
        if compact:
            layout.addWidget(self.maker_destination_label, 0, 0)
            layout.addWidget(self.maker_add_selected_btn, 0, 1)
            layout.addWidget(self.maker_add_country_btn, 0, 2)
            layout.setColumnStretch(3, 1)
            layout.addWidget(self.maker_add_all_btn, 1, 0, 1, 2)
            layout.setColumnStretch(2, 1)
            layout.addWidget(self.maker_copy_btn, 1, 3)
            layout.addWidget(self.maker_export_btn, 1, 4)
            return
        layout.addWidget(self.maker_destination_label, 0, 0)
        layout.addWidget(self.maker_add_selected_btn, 0, 1)
        layout.addWidget(self.maker_add_country_btn, 0, 2)
        layout.addWidget(self.maker_add_all_btn, 0, 3)
        layout.setColumnStretch(4, 1)
        layout.addWidget(self.maker_copy_btn, 0, 5)
        layout.addWidget(self.maker_export_btn, 0, 6)

    def _configs_page(self):
        page = QWidget(); root = QVBoxLayout(page); root.setContentsMargins(34, 28, 34, 26); root.setSpacing(15)
        self.config_count_label = QLabel("0"); self.config_count_label.setObjectName("summaryPill"); self.config_count_label.setAlignment(Qt.AlignCenter)
        root.addWidget(self._page_header("کانفیگ‌ها", "Configs", "مدیریت کامل لینک‌های VLESS و Trojan", "Manage, rank, import and edit VLESS and Trojan profiles", self.config_count_label))
        toolbar = QFrame(); toolbar.setObjectName("pageToolbar"); bar = QHBoxLayout(toolbar); bar.setContentsMargins(12, 10, 12, 10); bar.setSpacing(9)
        self.add_btn = self._action_button("افزودن کانفیگ", "Add Config", "plus", "primaryAction")
        self.clip_btn = self._action_button("ورود از Clipboard", "Import Clipboard", "copy", "secondaryAction")
        self.sync_btn = self._action_button("دریافت پیشنهادی‌ها", "Sync Suggested", "refresh", "secondaryAction")
        self.clear_user_btn = self._action_button("حذف همه", "Delete All", "trash", "dangerButton")
        self.clear_user_btn.setMaximumWidth(108)
        self.clear_user_btn.setToolTip(self.tr("حذف همه کانفیگ‌های User Config", "Delete every User Config entry"))
        for widget in (self.add_btn, self.clip_btn, self.sync_btn): bar.addWidget(widget)
        bar.addStretch(); bar.addWidget(self.clear_user_btn); root.addWidget(toolbar)
        panel = QFrame(); panel.setObjectName("configPanel"); panel_layout = QVBoxLayout(panel); panel_layout.setContentsMargins(0, 0, 0, 0)
        self.profile_tabs = QTabWidget(); self.profile_tabs.setObjectName("profileTabs"); self.manual_list = EmptyListWidget("file-cog"); self.user_config_list = EmptyListWidget("sparkles"); self.suggested_list = EmptyListWidget("server")
        self.manual_list.setObjectName("manualConfigList"); self.user_config_list.setObjectName("userConfigList"); self.suggested_list.setObjectName("suggestedConfigList")
        for widget in (self.manual_list, self.user_config_list, self.suggested_list):
            widget.setSelectionMode(QAbstractItemView.ExtendedSelection); widget.setSpacing(4); widget.itemSelectionChanged.connect(self._update_config_actions); widget.deleteRequested.connect(self.delete_profile)
        self.user_config_list.setSpacing(2); self.suggested_list.setSpacing(2)
        self.manual_list.set_empty_text(self.tr("هنوز کانفیگ دستی ندارید", "No manual configs yet"), self.tr("یک لینک VLESS یا Trojan اضافه یا از Clipboard وارد کنید.", "Add a VLESS or Trojan link, or import one from the clipboard."))
        self.user_config_list.set_empty_text(self.tr("هنوز User Config ندارید", "No User Configs yet"), self.tr("کانفیگ‌های سالم را از SNI Config Maker به این بخش اضافه کنید.", "Add healthy routes from SNI Config Maker to this library."))
        self.suggested_list.set_empty_text(self.tr("هنوز پیشنهادی دریافت نشده", "No suggestions downloaded"), self.tr("برای دریافت فهرست پیشنهادی، همگام‌سازی را اجرا کنید.", "Sync the suggested repository to populate this list."))
        self.profile_pages = []
        self.profile_page_layouts = []
        for widget in (
                self.user_config_list, self.manual_list,
                self.suggested_list):
            tab_page = QWidget()
            tab_layout = QVBoxLayout(tab_page)
            tab_layout.setContentsMargins(5, 4, 5, 5)
            tab_layout.setSpacing(5)
            tab_layout.addWidget(widget, 1)
            self.profile_pages.append(tab_page)
            self.profile_page_layouts.append(tab_layout)
        self.profile_selection_bar = QFrame()
        self.profile_selection_bar.setObjectName("profileSelectionBar")
        self.profile_selection_bar.setFixedHeight(38)
        selection_layout = QHBoxLayout(self.profile_selection_bar)
        selection_layout.setContentsMargins(10, 4, 10, 4)
        selection_layout.setSpacing(7)
        self.profile_select_all_checkbox = QCheckBox()
        self.profile_select_all_checkbox.setObjectName("profileSelectAll")
        self.profile_select_all_checkbox.setLayoutDirection(Qt.LeftToRight)
        self.profile_select_all_checkbox.setFixedSize(22, 22)
        self.profile_select_all_label = self._bind_text(
            QLabel(), "انتخاب همه کانفیگ‌ها", "Select all configs"
        )
        self.profile_select_all_label.setObjectName("profileSelectionLabel")
        selection_layout.addWidget(self.profile_select_all_checkbox)
        selection_layout.addWidget(self.profile_select_all_label)
        selection_layout.addStretch()
        self.profile_ping_all_btn = self._action_button(
            "پینگ کل لیست", "Ping All", "gauge", "secondaryAction"
        )
        self.profile_ping_all_btn.setMinimumWidth(112)
        self.profile_ping_all_btn.setMaximumWidth(142)
        self.profile_sort_combo = QComboBox()
        self.profile_sort_combo.setObjectName("profileSortCombo")
        self.profile_sort_combo.setMinimumHeight(46)
        self.profile_sort_combo.setMaximumHeight(52)
        self.profile_sort_combo.setMinimumWidth(145)
        self.profile_sort_combo.setMaximumWidth(190)
        self.profile_sort_combo.addItem(
            self.tr("مرتب‌سازی: کشور", "Sort: Country"), "country"
        )
        self.profile_sort_combo.addItem(
            self.tr("مرتب‌سازی: کمترین پینگ", "Sort: Lowest ping"), "ping"
        )
        bar.insertWidget(3, self.profile_ping_all_btn)
        bar.insertWidget(4, self.profile_sort_combo)
        self.profile_select_all_checkbox.setAccessibleName("Select all configurations in the active list")
        self.profile_select_all_checkbox.setToolTip(self.tr(
            "انتخاب یا لغو انتخاب همه کانفیگ‌های لیست فعال",
            "Select or clear every configuration in the active list",
        ))
        self.profile_select_all_checkbox.clicked.connect(
            self._set_current_profile_list_selection
        )
        self.profile_page_layouts[0].insertWidget(
            0, self.profile_selection_bar
        )
        self.profile_tabs.addTab(
            self.profile_pages[0], "User Config"
        )
        self.profile_tabs.addTab(
            self.profile_pages[1], self.tr("دستی", "Manual")
        )
        self.profile_tabs.addTab(
            self.profile_pages[2],
            self.tr("پیشنهادی", "Suggested")
        )
        self.profile_tabs.currentChanged.connect(
            self._update_config_actions
        )
        self.profile_tabs.currentChanged.connect(
            self._profile_tab_changed
        )
        self.profile_ping_all_btn.clicked.connect(
            self._ping_current_profile_list
        )
        self.profile_sort_combo.currentIndexChanged.connect(
            self._profile_sort_changed
        )
        panel_layout.addWidget(self.profile_tabs)
        root.addWidget(panel, 1)
        self._update_config_actions()
        return page

    def _sni_maker_page(self):
        page = QWidget(); self.maker_page = page; root = QVBoxLayout(page); self.maker_root = root; root.setContentsMargins(24, 16, 24, 14); root.setSpacing(10)
        self.maker_summary_badge = QLabel(self.tr("۰ سالم از ۰", "0 healthy of 0")); self.maker_summary_badge.setObjectName("summaryPill"); self.maker_summary_badge.setAlignment(Qt.AlignCenter)
        self.maker_header = self._page_header(
            "سازنده کانفیگ اس‌ان‌آی", "SNI Config Maker",
            "تبدیل گروهی، تست زنده مسیر واقعی و مرتب‌سازی دقیق بر اساس کشور خروجی",
            "Bulk conversion, live end-to-end testing and verified exit-country sorting",
            self.maker_summary_badge,
        )
        root.addWidget(self.maker_header)

        self.maker_source_card = QFrame(); self.maker_source_card.setObjectName("makerSourceCard")
        source_layout = QVBoxLayout(self.maker_source_card); source_layout.setContentsMargins(10, 6, 10, 6); source_layout.setSpacing(5)
        repository_row = QHBoxLayout(); repository_row.setSpacing(6)
        self.maker_source_title = self._bind_text(QLabel(), "افزودن کانفیگ", "1 · Add configs"); self.maker_source_title.setObjectName("makerStepTitle")
        saved_maker_url = str(self.storage.settings.get("sni_maker_url", "") or "").strip()
        if not saved_maker_url or saved_maker_url in LEGACY_SNI_MAKER_URLS:
            saved_maker_url = DEFAULT_SNI_MAKER_URL
        self.maker_repo_url = QLineEdit(saved_maker_url); self.maker_repo_url.setObjectName("makerRepoUrl"); self.maker_repo_url.setLayoutDirection(Qt.LeftToRight); self.maker_repo_url.setClearButtonEnabled(True)
        self.maker_repo_btn = self._action_button("دریافت", "Load", "download", "primaryAction")
        self.maker_repo_reset_btn = self._action_button("پیش‌فرض", "Default", "refresh", "quietButton")
        self.maker_repo_btn.setMaximumWidth(105); self.maker_repo_reset_btn.setMaximumWidth(100)
        repository_row.addWidget(self.maker_source_title); repository_row.addWidget(self.maker_repo_url, 1); repository_row.addWidget(self.maker_repo_btn); repository_row.addWidget(self.maker_repo_reset_btn)
        source_layout.addLayout(repository_row)

        import_row = QHBoxLayout(); import_row.setSpacing(6)
        self.maker_import_badge = QLabel(self.tr("آماده دریافت", "Ready")); self.maker_import_badge.setObjectName("selectionText"); self.maker_import_badge.setMinimumWidth(105); self.maker_import_badge.setMaximumWidth(155)
        self.maker_source_editor = ConfigDropEdit()
        self.maker_source_editor.textChanged.connect(self._sync_maker_editor_direction)
        self.maker_source_editor.setPlaceholderText(self.tr(
            "لینک‌ها را اینجا وارد کنید یا فایل را رها کنید",
            "Paste links or drop files here",
        ))
        self.maker_file_btn = self._action_button("فایل", "File", "folder", "secondaryAction")
        self.maker_clip_btn = self._action_button("کلیپ‌بورد", "Clipboard", "copy", "secondaryAction")
        self.maker_text_btn = self._action_button("تبدیل", "Convert", "sparkles", "secondaryAction")
        self.maker_clear_btn = self._action_button("پاک‌کردن", "Clear", "trash", "dangerButton")
        for button, width in (
                (self.maker_file_btn, 90), (self.maker_clip_btn, 105),
                (self.maker_text_btn, 95), (self.maker_clear_btn, 90)):
            button.setMaximumWidth(width)
        import_row.addWidget(self.maker_import_badge); import_row.addWidget(self.maker_source_editor, 1)
        import_row.addWidget(self.maker_file_btn); import_row.addWidget(self.maker_clip_btn)
        import_row.addWidget(self.maker_text_btn); import_row.addWidget(self.maker_clear_btn)
        source_layout.addLayout(import_row)
        root.addWidget(self.maker_source_card)

        control = QFrame(); self.maker_control = control; control.setObjectName("makerTestBar"); control_layout = QHBoxLayout(control); control_layout.setContentsMargins(8, 6, 8, 6); control_layout.setSpacing(6)
        threads_label = self._bind_text(QLabel(), "همزمانی", "Workers"); threads_label.setObjectName("fieldLabel")
        timeout_label = self._bind_text(QLabel(), "مهلت", "Timeout"); timeout_label.setObjectName("fieldLabel")
        self.maker_threads = NumericInput(48, 4, 64)
        self.maker_timeout = NumericInput(8, 3, 20, "s")
        self.maker_threads.setMaximumWidth(120); self.maker_timeout.setMaximumWidth(120)
        self.maker_start_btn = self._action_button("تست همه کانفیگ‌ها", "2 · Test All", "play", "primaryAction")
        self.maker_stop_btn = self._action_button("توقف", "Stop", "x-circle", "dangerButton"); self.maker_stop_btn.setEnabled(False)
        self.maker_start_btn.setMinimumWidth(180); self.maker_start_btn.setMaximumWidth(230); self.maker_stop_btn.setMaximumWidth(85)
        self.maker_progress = ScanProgressPanel(self.language); self.maker_progress.setMaximum(100); self.maker_progress.setValue(0)
        self.maker_progress.set_status(self.tr("آماده تست", "Tester ready"), "idle")
        self.maker_progress.setFormat(self.tr("منتظر کانفیگ", "Waiting for configs"))
        self.maker_progress.domain.setVisible(False); self.maker_progress.setMinimumWidth(145)
        self.maker_progress.layout().setContentsMargins(8, 3, 8, 3); self.maker_progress.layout().setSpacing(2)
        control_layout.addWidget(threads_label); control_layout.addWidget(self.maker_threads)
        control_layout.addWidget(timeout_label); control_layout.addWidget(self.maker_timeout)
        control_layout.addWidget(self.maker_progress, 1); control_layout.addWidget(self.maker_start_btn); control_layout.addWidget(self.maker_stop_btn)
        root.addWidget(control)

        results_panel = QFrame(); self.maker_results_panel = results_panel; results_panel.setObjectName("makerResultsPanel"); results_layout = QVBoxLayout(results_panel); results_layout.setContentsMargins(0, 0, 0, 0); results_layout.setSpacing(0)
        result_toolbar = QFrame(); result_toolbar.setObjectName("makerResultToolbar"); result_bar = QHBoxLayout(result_toolbar); result_bar.setContentsMargins(10, 7, 10, 7); result_bar.setSpacing(8)
        self.maker_results_title = self._bind_text(QLabel(), "نتایج تست", "3 · Test results"); self.maker_results_title.setObjectName("makerStepTitle")
        self.maker_search = QLineEdit(); self.maker_search.setObjectName("makerSearch"); self.maker_search.setPlaceholderText(self.tr("جستجو در نتایج…", "Search results…")); self.maker_search.setClearButtonEnabled(True)
        self.maker_status_filter = QComboBox(); self.maker_status_filter.setObjectName("makerStatusFilter")
        self.maker_status_filter.addItem(self.tr("همه وضعیت‌ها", "All statuses"), "")
        self.maker_status_filter.addItem(self.tr("سالم", "Healthy"), "healthy")
        self.maker_status_filter.addItem(self.tr("ناموفق", "Failed"), "failed")
        self.maker_status_filter.addItem(self.tr("در حال تست", "Testing"), "testing")
        result_bar.addWidget(self.maker_results_title); result_bar.addWidget(self.maker_search, 1); result_bar.addWidget(self.maker_status_filter)
        results_layout.addWidget(result_toolbar)

        self.maker_country_rail = CountryRail(); self.maker_country_rail.setLayoutDirection(Qt.LeftToRight); self.maker_country_rail.set_country_counts({}, all_label=self.tr("همه کشورها", "All countries"))
        results_layout.addWidget(self.maker_country_rail)
        self.maker_model = MakerResultsModel(parent=self)
        self.maker_proxy = MakerFilterProxy(self); self.maker_proxy.setSourceModel(self.maker_model)
        self.maker_table = QTableView(); self.maker_table.setObjectName("makerResultsTable"); self.maker_table.setModel(self.maker_proxy)
        self.maker_table.setSortingEnabled(True); self.maker_table.sortByColumn(MakerColumns.STATUS, Qt.AscendingOrder)
        self.maker_table.setSelectionBehavior(QAbstractItemView.SelectRows); self.maker_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.maker_table.setEditTriggers(QAbstractItemView.NoEditTriggers); self.maker_table.setAlternatingRowColors(True); self.maker_table.setShowGrid(False)
        self.maker_table.verticalHeader().hide(); self.maker_table.verticalHeader().setDefaultSectionSize(43)
        maker_header = self.maker_table.horizontalHeader(); maker_header.setHighlightSections(False); maker_header.setStretchLastSection(True)
        maker_header.setSectionResizeMode(MakerColumns.MARK, QHeaderView.Fixed); self.maker_table.setColumnWidth(MakerColumns.MARK, 42)
        for column, width in ((MakerColumns.COUNTRY, 90), (MakerColumns.STATUS, 100), (MakerColumns.PING, 90)):
            maker_header.setSectionResizeMode(column, QHeaderView.Fixed); self.maker_table.setColumnWidth(column, width)
        maker_header.setSectionResizeMode(MakerColumns.URI, QHeaderView.Stretch)
        self.maker_select_all_checkbox = QCheckBox(maker_header)
        self.maker_select_all_checkbox.setObjectName("makerSelectAll")
        self.maker_select_all_checkbox.setLayoutDirection(Qt.LeftToRight)
        self.maker_select_all_checkbox.setFixedSize(22, 22)
        self.maker_select_all_checkbox.setEnabled(False)
        self.maker_select_all_checkbox.setAccessibleName("Select all configurations")
        self.maker_select_all_checkbox.setToolTip(self.tr("انتخاب یا لغو انتخاب همه کانفیگ‌ها", "Select or clear all configurations"))
        maker_header.geometriesChanged.connect(self._position_maker_select_all)
        maker_header.sectionResized.connect(lambda *_args: self._position_maker_select_all())
        QTimer.singleShot(0, self._position_maker_select_all)
        results_layout.addWidget(self.maker_table, 1); root.addWidget(results_panel, 1)

        actions = QFrame(); self.maker_actions = actions; actions.setObjectName("makerActionBar"); action_layout = QGridLayout(actions); self.maker_action_layout = action_layout; action_layout.setContentsMargins(10, 7, 10, 7); action_layout.setSpacing(8)
        self.maker_destination_label = self._bind_text(QLabel(), "← کانفیگ کاربر", "→ User Config"); self.maker_destination_label.setObjectName("makerDestination"); self.maker_destination_label.setMaximumWidth(125)
        self.maker_add_selected_btn = self._action_button("افزودن", "Add", "plus", "primaryAction")
        self.maker_add_country_btn = self._action_button("افزودن کانفیگ‌های سالم کشور انتخاب‌شده", "Add Healthy Configs from Selected Country", "database", "secondaryAction")
        self.maker_add_all_btn = self._action_button("افزودن همه کانفیگ‌های سالم", "Add All Healthy Configs", "download", "secondaryAction")
        self.maker_copy_btn = self._action_button("کپی", "Copy", "copy", "quietButton")
        self.maker_export_btn = self._action_button("خروجی", "Export", "upload", "quietButton")
        for button, width in (
                (self.maker_add_selected_btn, 95), (self.maker_add_country_btn, 255),
                (self.maker_add_all_btn, 210), (self.maker_copy_btn, 85),
                (self.maker_export_btn, 90)):
            button.setMinimumWidth(width)
            button.setMaximumWidth(16777215)
            button.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Fixed)
        self.maker_add_selected_btn.setToolTip(self.tr("افزودن انتخاب‌ها به کانفیگ کاربر", "Add marked configs to User Config"))
        self.maker_add_country_btn.setToolTip(self.tr("افزودن سالم‌های کشور انتخاب‌شده", "Add healthy configs from the selected country"))
        self.maker_add_all_btn.setToolTip(self.tr("افزودن همه کانفیگ‌های سالم", "Add every healthy config"))
        self._maker_actions_compact = None
        self._layout_maker_actions(False)
        for button in (self.maker_add_selected_btn, self.maker_add_country_btn, self.maker_add_all_btn, self.maker_copy_btn, self.maker_export_btn):
            button.setEnabled(False)
        root.addWidget(actions)
        return page

    def _scanner_page(self):
        page, body = self._scroll_page(); root = QVBoxLayout(body); root.setContentsMargins(30, 25, 30, 24); root.setSpacing(14)
        self.scan_state_badge = QLabel(); self.scan_state_badge.setObjectName("summaryPill"); self._bind_text(self.scan_state_badge, "آماده اسکن", "Scanner Ready")
        root.addWidget(self._page_header("آزمایشگاه اس‌ان‌آی", "SNI Lab", "اسکن همزمان، امتیازدهی پایداری و ذخیره بهترین مسیرها", "Discover, measure and rank reliable SNI routes", self.scan_state_badge))
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
        self.bridge.log.connect(self._append_log); self.bridge.state.connect(self._set_state); self.bridge.traffic.connect(self._set_traffic); self.bridge.latency.connect(self._set_latency); self.bridge.target_latency.connect(self._target_latency_finished); self.bridge.maker_imported.connect(self._maker_import_finished); self.bridge.maker_batch.connect(self._maker_test_batch); self.bridge.maker_done.connect(self._maker_test_done); self.bridge.maker_failed.connect(self._maker_failed); self.bridge.scan_progress.connect(self._scan_progress); self.bridge.scan_done.connect(self._scan_done); self.bridge.scan_failed.connect(self._scan_failed); self.bridge.error.connect(self._handle_error); self.bridge.profiles_changed.connect(self.refresh_profiles); self.bridge.profile_pings_done.connect(self._profile_pings_finished); self.bridge.ip.connect(self._ip_checked); self.bridge.hint.connect(self.connection_hint.setText); self.bridge.activity.connect(self.activity_bar.set_activity); self.bridge.processes.connect(self._populate_processes); self.bridge.update_checked.connect(self._update_checked); self.bridge.update_failed.connect(self._update_failed); self.bridge.proxy_mode_applied.connect(self._proxy_mode_apply_finished); self.bridge.tun_mode_applied.connect(self._tun_mode_apply_finished); self.bridge.gateway_mode_applied.connect(self._gateway_mode_apply_finished); self.bridge.gateway_runtime_state.connect(self._gateway_runtime_state_changed); self.bridge.gateway_devices_changed.connect(self._gateway_devices_updated)
        self.connect_button.clicked.connect(self.toggle_connection); self.add_btn.clicked.connect(self.add_profile); self.clear_user_btn.clicked.connect(self.delete_all_user_configs); self.clip_btn.clicked.connect(self.import_clipboard); self.sync_btn.clicked.connect(self.sync_profiles); self.scan_button.clicked.connect(self.toggle_scan); self.bookmark_btn.clicked.connect(self.bookmark_selected); self.apply_sni_btn.clicked.connect(self.apply_selected_sni); self.apply_all_sni_btn.clicked.connect(self.apply_sni_to_all_suggested); self.undo_apply_btn.clicked.connect(self.undo_sni_apply); self.copy_result_btn.clicked.connect(self.copy_selected_result); self.carrier.currentTextChanged.connect(self._carrier_changed); self.country_combo.activated.connect(self._country_activated); self.auto_mode.toggled.connect(self._auto_mode_changed); self.pick_best.toggled.connect(lambda v: self._save_flag("pick_best", v)); self.proxy_mode.toggled.connect(self._proxy_mode_changed); self.tun_mode.toggled.connect(self._tun_mode_changed); self.gateway_mode.toggled.connect(self._gateway_mode_changed)
        self.scan_tabs.currentChanged.connect(self._update_scan_selection)
        self.route_source_tabs.currentChanged.connect(self._route_source_changed)
        self.maker_repo_btn.clicked.connect(self._maker_fetch_repository); self.maker_repo_reset_btn.clicked.connect(lambda: self.maker_repo_url.setText(DEFAULT_SNI_MAKER_URL)); self.maker_repo_url.textChanged.connect(self._maker_repo_url_changed)
        self.maker_file_btn.clicked.connect(self._maker_import_files); self.maker_clip_btn.clicked.connect(self.maker_source_editor.paste_from_clipboard); self.maker_text_btn.clicked.connect(lambda: self._maker_import_text(self.maker_source_editor.toPlainText(), "editor")); self.maker_clear_btn.clicked.connect(self._maker_clear)
        self.maker_source_editor.textChanged.connect(self._maker_editor_changed)
        self.maker_source_editor.payloadAdded.connect(lambda *_args: self._update_maker_guide())
        self.maker_start_btn.clicked.connect(self._maker_start_test); self.maker_stop_btn.clicked.connect(self._maker_stop_test)
        self.maker_search.textChanged.connect(self.maker_proxy.set_search); self.maker_status_filter.currentIndexChanged.connect(lambda _index: self.maker_proxy.set_statuses(self.maker_status_filter.currentData()))
        self.maker_country_rail.countrySelected.connect(self.maker_proxy.set_country); self.maker_model.summaryChanged.connect(self._maker_summary_changed)
        self.maker_select_all_checkbox.clicked.connect(self.maker_model.set_all_checked)
        self.maker_add_selected_btn.clicked.connect(lambda: self._maker_add_results("selected")); self.maker_add_country_btn.clicked.connect(lambda: self._maker_add_results("country")); self.maker_add_all_btn.clicked.connect(lambda: self._maker_add_results("all"))
        self.maker_copy_btn.clicked.connect(self._maker_copy_marked); self.maker_export_btn.clicked.connect(self._maker_export_healthy)

    def _setup_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        icon = QApplication.windowIcon()
        if icon.isNull():
            icon = cyber_icon("shield", "#23f5e0", 24)
        self._tray = QSystemTrayIcon(icon, self)
        self._tray_menu = QMenu(self)
        self._tray_menu.setObjectName("trayMenu")
        self._tray_menu.setMinimumWidth(220)
        self._tray_menu.setFont(QFont("Vazirmatn", 10))
        self._tray_menu.setStyleSheet("""
            QMenu#trayMenu {
                background-color: #07172c;
                color: #e8f5ff;
                border: 1px solid #245877;
                border-radius: 11px;
                padding: 8px;
            }
            QMenu#trayMenu::item {
                min-height: 32px;
                padding: 7px 38px 7px 16px;
                margin: 2px 3px;
                border-radius: 8px;
                background: transparent;
            }
            QMenu#trayMenu::item:selected {
                background-color: #0d5260;
                color: #ffffff;
            }
            QMenu#trayMenu::item:disabled {
                color: #67839d;
            }
            QMenu#trayMenu::icon {
                padding-left: 9px;
                padding-right: 9px;
            }
            QMenu#trayMenu::separator {
                height: 1px;
                background: #1d425d;
                margin: 6px 10px;
            }
        """)
        self.tray_show_action = QAction(self._tray_menu)
        self.tray_show_action.setIcon(cyber_icon("home", "#23f5e0", 18))
        self.tray_show_action.setIconVisibleInMenu(True)
        self.tray_show_action.triggered.connect(self._restore_from_tray)
        self._tray_menu.addAction(self.tray_show_action)
        self._tray_menu.addSeparator()
        self.tray_quit_action = QAction(self._tray_menu)
        self.tray_quit_action.setIcon(cyber_icon("power", "#ff7891", 18))
        self.tray_quit_action.setIconVisibleInMenu(True)
        self.tray_quit_action.triggered.connect(self._quit_from_tray)
        self._tray_menu.addAction(self.tray_quit_action)
        self._tray.setContextMenu(self._tray_menu)
        self._tray.activated.connect(self._tray_activated)
        self._update_tray_text()
        self._tray.setVisible(False)

    def _update_tray_text(self):
        if self._tray is None:
            return
        if self.tray_show_action is not None:
            self.tray_show_action.setText(self.tr("نمایش برنامه", "Show App"))
        if self.tray_quit_action is not None:
            self.tray_quit_action.setText(self.tr("خروج کامل", "Quit"))
        if self._tray_menu is not None:
            self._tray_menu.setLayoutDirection(
                Qt.LeftToRight if self.language == "en" else Qt.RightToLeft
            )
            self._tray_menu.setMinimumWidth(220)
            self._tray_menu.ensurePolished()
        self._tray.setToolTip(self.tr("UAC Spoofer Desktop — در حال اجرا", "UAC Spoofer Desktop — Running"))

    def _tray_activated(self, reason):
        if reason in (QSystemTrayIcon.ActivationReason.Trigger,
                      QSystemTrayIcon.ActivationReason.DoubleClick):
            self._restore_from_tray()

    def _restore_from_tray(self):
        if self._tray is not None:
            self._tray.hide()
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _quit_from_tray(self):
        self._force_quit = True
        self.close()
        app = QApplication.instance()
        if app is not None:
            app.quit()

    def _ask_close_action(self) -> str:
        choice = CloseChoiceDialog(
            self, language=self.language, tray_available=self._tray is not None
        )
        choice.exec()
        return choice.action

    def _hide_to_tray(self) -> bool:
        if self._tray is None:
            return False
        self.hide()
        self._tray.show()
        if not self._tray_hint_shown:
            self._tray.showMessage(
                "UAC Spoofer Desktop",
                self.tr(
                    "برنامه در System Tray در حال اجراست؛ برای بازگشت روی آیکن آن کلیک کنید.",
                    "The app is still running in the system tray. Click its icon to restore it.",
                ),
                QSystemTrayIcon.MessageIcon.Information,
                3200,
            )
            self._tray_hint_shown = True
        return True

    def show_page(self, index):
        previous_index = self.stack.currentIndex()
        if self._page_animation is not None:
            self._page_animation.stop()
        if self._animated_page is not None:
            self._animated_page.setGraphicsEffect(None)
            self._animated_page = None
        self.stack.setCurrentIndex(index)
        if index == 2:
            self._layout_sni_maker()
            QTimer.singleShot(0, self._layout_sni_maker)
            QTimer.singleShot(120, self._layout_sni_maker)
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
        widget = self._current_profile_list()
        self._sync_profile_select_all(widget)
        self._position_profile_select_all()
        user_active = widget is self.user_config_list
        self.clear_user_btn.setVisible(user_active)
        self.clear_user_btn.setEnabled(
            user_active and any(
                profile.origin == USER_CONFIG_ORIGIN
                for profile in self.storage.profiles
            )
        )

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
                   self.logs, self.domains, self.carrier, self.log_filter, self.process_search,
                   self.maker_repo_url, self.maker_search]
        for widget in widgets:
            widget.setLayoutDirection(Qt.LeftToRight)
            widget.setProperty("technical", True)
            if isinstance(widget, QLabel): widget.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)


        table_direction = Qt.LeftToRight if self.language == "en" else Qt.RightToLeft
        for table in (self.results_table, self.bookmarks_table, self.process_table):
            table.setLayoutDirection(table_direction)
            table.setProperty("technical", True)
        self.maker_table.setLayoutDirection(Qt.LeftToRight)
        self.maker_table.setProperty("technical", True)

    def _sync_maker_editor_direction(self):
        persian_placeholder = self.language == "fa" and not self.maker_source_editor.toPlainText().strip()
        self.maker_source_editor.setLayoutDirection(
            Qt.RightToLeft if persian_placeholder else Qt.LeftToRight
        )

    def _sync_sidebar_language_layout(self):
        rtl = self.language == "fa"
        direction = Qt.RightToLeft if rtl else Qt.LeftToRight
        alignment = (Qt.AlignRight if rtl else Qt.AlignLeft) | Qt.AlignVCenter
        compact = self.width() < 1240
        nav_height = 44 if self.height() < 790 else 54 if self.height() < 930 else 56
        self.rating_card.setVisible(self.height() >= 890 and not compact)
        for button in self.nav:
            button.setFixedHeight(nav_height)
        self.rating_card.setLayoutDirection(direction)
        for label in (self.rating_title, self.rating_text):
            label.setLayoutDirection(direction)
            label.setAlignment(alignment)
        self.rating_button.setLayoutDirection(direction)
        self.rating_button.setProperty("rtl", rtl)
        self.language_button.setLayoutDirection(Qt.RightToLeft if self.language == "en" else Qt.LeftToRight)
        self.language_button.setProperty("rtl", self.language == "en")
        self.data_button.setLayoutDirection(direction)
        self.data_button.setProperty("rtl", rtl)
        for widget in (self.rating_button, self.language_button, self.data_button):
            _restyle(widget)
        for layout in (self.rating_card.layout(), self.sidebar_footer.layout(), self.sidebar_layout):
            layout.invalidate()
            layout.activate()
        self.rating_card.updateGeometry()
        self.sidebar_footer.updateGeometry()
        self.sidebar.updateGeometry()

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
        self.profile_tabs.setTabText(0, "User Config"); self.profile_tabs.setTabText(1, self.tr("دستی", "Manual")); self.profile_tabs.setTabText(2, self.tr("پیشنهادی", "Suggested"))
        self.profile_select_all_checkbox.setToolTip(self.tr(
            "انتخاب یا لغو انتخاب همه کانفیگ‌های لیست فعال",
            "Select or clear every configuration in the active list",
        ))
        self._sync_profile_sort_control()
        self._position_profile_select_all()
        self.route_source_tabs.setTabText(0, self.tr("پیشنهادی", "Suggested")); self.route_source_tabs.setTabText(1, "User Config")
        self.scan_tabs.setTabText(0, self.tr("نتایج", "Results")); self.scan_tabs.setTabText(1, self.tr("ذخیره‌شده", "Saved"))
        result_headers = (["", "Domain", "IP", "Colo", "Ping", "Stability", "First byte", "Bytes/2s", "Score"] if self.language == "en" else ["", "دامنه", "IP", "Colo", "پینگ", "پایداری", "اولین بایت", "بایت/۲ثانیه", "امتیاز"])
        for table in (self.results_table, self.bookmarks_table): table.setHorizontalHeaderLabels(result_headers)
        self.process_table.setHorizontalHeaderLabels([self.tr(f"خارج از {ltr_isolate('VPN')}", "Bypass VPN"), self.tr("پردازه", "Process")])
        self.maker_model.set_headers(
            ["", "Country", "Status", "Real ping", "Configuration"]
            if self.language == "en"
            else ["", "کشور", "وضعیت", "پینگ واقعی", "کانفیگ"]
        )
        self.maker_model.set_status_labels(
            {} if self.language == "en" else {
                "queued": "در صف",
                "ready": "آماده",
                "converted": "تبدیل‌شده",
                "converting": "در حال تبدیل",
                "testing": "در حال تست",
                "healthy": "سالم",
                "failed": "ناموفق",
                "invalid": "نامعتبر",
                "skipped": "ناسازگار",
                "cancelled": "متوقف‌شده",
            }
        )
        self.maker_source_editor.setPlaceholderText(self.tr(
            "لینک‌ها را اینجا وارد کنید یا فایل را رها کنید",
            "Paste links or drop files here",
        ))
        self._sync_maker_editor_direction()
        if self.maker_model.rowCount() == 0:
            self.maker_import_badge.setText(self.tr("آماده دریافت", "Ready"))
            self.maker_progress.set_status(self.tr("آماده تست", "Tester ready"), "idle")
            self.maker_progress.setFormat(self.tr("منتظر کانفیگ", "Waiting for configs"))
        self.maker_search.setPlaceholderText(self.tr("جستجو در نتایج…", "Search results…"))
        self.maker_select_all_checkbox.setToolTip(self.tr(
            "انتخاب یا لغو انتخاب همه کانفیگ‌ها",
            "Select or clear all configurations",
        ))
        for index, (persian, english) in enumerate((
                ("همه وضعیت‌ها", "All statuses"),
                ("سالم", "Healthy"),
                ("ناموفق", "Failed"),
                ("در حال تست", "Testing"))):
            self.maker_status_filter.setItemText(
                index, english if self.language == "en" else persian
            )
        self.maker_country_rail.set_metric_labels(
            self.tr("سالم", "healthy"),
            self.tr("کل", "total"),
            self.tr("زنده", "live"),
        )
        self._maker_last_country_summary = None
        self._maker_summary_changed({
            "total": self.maker_model.rowCount(),
            "statuses": self.maker_model.status_counts(),
            "countries": self.maker_model.country_summary(),
        })
        for index, (button, (icon_name, persian, english)) in enumerate(zip(self.nav, self.nav_meta)):
            button.setText(english if self.language == "en" else persian)
            button.setProperty("rtl", self.language != "en"); _restyle(button)
            button.setIcon(cyber_icon(icon_name, "#23f5e0" if index == self.stack.currentIndex() else "#9fb4d8", 22))
        self.language_button.setText("فارسی" if self.language == "en" else "English")
        self.data_button.setText(self.tr("باز کردن پوشه داده‌ها", "Open Data Folder"))
        self._sync_sidebar_language_layout()
        QTimer.singleShot(0, self._sync_sidebar_language_layout)
        self._update_tray_text()
        self.status_pill.set_language(self.language); self.activity_bar.set_language(self.language)
        if not self.scanning: self.scan_progress.set_language(self.language)
        if self._latest_update:
            self._render_update_info(self._latest_update)
        elif not self._update_in_progress:
            self.update_status.setText(self.tr("برای بررسی نسخه آماده است", "Ready to check for updates"))
            self.update_versions.setText(self.tr(f"نصب‌شده: {ltr_isolate(__version__)}  •  آخرین نسخه: —", f"Installed: {__version__}  •  Latest: —"))
        self.manual_list.set_empty_text(self.tr("هنوز کانفیگ دستی ندارید", "No manual configs yet"), self.tr("یک لینک VLESS یا Trojan اضافه یا از Clipboard وارد کنید.", "Add a VLESS or Trojan link, or import one from the clipboard."))
        self.user_config_list.set_empty_text(self.tr("هنوز User Config ندارید", "No User Configs yet"), self.tr("کانفیگ‌های سالم را از SNI Config Maker به این بخش اضافه کنید.", "Add healthy routes from SNI Config Maker to this library."))
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
        self._refresh_country_selector()
        self._sync_auto_mode_ui(select_profile=True)
        self.proxy_mode.setToolTip(self.tr(
            "خاموش: هسته اسپوف فعال می‌ماند و فقط پروکسی سیستم ویندوز اعمال نمی‌شود.",
            "Off: the spoof core stays active; only Windows System Proxy is skipped.",
        ))
        self.tun_mode.setToolTip(self.tr(
            "تمام ترافیک TCP و UDP ویندوز را از sing-box و هسته اسپوف عبور می‌دهد؛ پینگ CMD مستقیم و واقعی می‌ماند.",
            "Routes Windows TCP and UDP through sing-box and the spoof core; CMD ping remains direct and real.",
        ))
        self.gateway_mode.setToolTip(self.tr(
            "با یک کلیک، اینترنت موبایل را از درگاه شبکه این رایانه به تونل تأییدشده هدایت می‌کند.",
            "One click routes mobile internet through this computer and the verified tunnel.",
        ))
        self._gateway_devices_updated(self._gateway_devices)
        self.proxy_option.setEnabled(not self._tun_mode_enabled())
        self._sync_gateway_controls()
        self._configure_technical_widgets()
        self._layout_home_dashboard()
        self._layout_sni_maker()
        if self._update_notification is not None and self._latest_update is not None:
            self._show_update_notification(self._latest_update)
        self.refresh_profiles()
        self._update_scan_selection()
        self._maker_repo_url_changed()

    def _save_flag(self, key, value): self.storage.settings[key] = value; self.storage.save_settings()

    def _proxy_mode_enabled(self) -> bool:
        return bool(self.storage.settings.get("proxy_mode", True))

    def _tun_mode_enabled(self) -> bool:
        return bool(self.storage.settings.get("tun_mode", False))

    def _proxy_mode_changed(self, enabled):
        enabled = bool(enabled)
        self._save_flag("proxy_mode", enabled)
        self.proxy_option.setProperty("active", enabled)
        _restyle(self.proxy_option)
        if (self.connecting and hasattr(self, "_ui_running")
                and not self._ui_running):
            self._set_activity(
                "تنظیم پروکسی ذخیره شد و پس از پایان تست اعمال می‌شود.",
                "Proxy preference saved; it will apply after testing finishes.",
            )
            return
        if not self.engine.running:
            self._set_activity(
                "پروکسی ویندوز برای اتصال بعدی فعال است." if enabled else
                "پروکسی ویندوز خاموش است؛ اتصال بعدی فقط هسته اسپوف را فعال می‌کند.",
                "Windows Proxy will be enabled on the next connection." if enabled else
                "Windows Proxy is off; the next connection will run only the spoof core.",
                "success", False,
            )
            return
        self._queue_proxy_mode_apply()

    def _cancel_mode_apply(self):
        event = getattr(self, "_mode_apply_cancel", None)
        if event is not None:
            event.set()
        self._mode_apply_generation = int(
            getattr(self, "_mode_apply_generation", 0)
        ) + 1

    def _begin_mode_apply(self):
        self._cancel_mode_apply()
        self._mode_apply_cancel = threading.Event()
        return (
            self._mode_apply_generation,
            self._connect_generation,
            self._mode_apply_cancel,
            int(self.engine.run_id),
        )

    def _set_current_profile_list_selection(self, checked):
        self._set_profile_list_selection(
            self._current_profile_list(), checked
        )

    def _set_profile_list_selection(self, widget, checked):
        if widget not in (
                self.user_config_list, self.manual_list,
                self.suggested_list):
            return
        widget.blockSignals(True)
        try:
            widget.clearSelection()
            if checked:
                for row in range(widget.count()):
                    item = widget.item(row)
                    if item.data(Qt.UserRole):
                        item.setSelected(True)
        finally:
            widget.blockSignals(False)
        self._sync_profile_select_all(widget)
        self._update_config_actions()

    def _sync_profile_select_all(self, widget):
        checkbox = getattr(self, "profile_select_all_checkbox", None)
        if checkbox is None or widget is not self._current_profile_list():
            return
        selectable = [
            widget.item(row)
            for row in range(widget.count())
            if widget.item(row).data(Qt.UserRole)
        ]
        selected = sum(item.isSelected() for item in selectable)
        checkbox.setEnabled(bool(selectable))
        checkbox.setChecked(bool(selectable) and selected == len(selectable))

    def _current_profile_list(self):
        index = self.profile_tabs.currentIndex()
        widgets = (
            self.user_config_list, self.manual_list,
            self.suggested_list,
        )
        return widgets[index] if 0 <= index < len(widgets) else None

    def _profile_tab_index(self, widget):
        widgets = (
            self.user_config_list, self.manual_list,
            self.suggested_list,
        )
        try:
            return widgets.index(widget)
        except ValueError:
            return -1

    def _current_profile_list_key(self):
        widget = self._current_profile_list()
        if widget is self.user_config_list:
            return "user-config"
        if widget is self.manual_list:
            return "manual"
        if widget is self.suggested_list:
            return "suggested"
        return ""

    def _profiles_for_list_key(self, key):
        if key == "user-config":
            return [
                profile for profile in self.storage.profiles
                if profile.origin == USER_CONFIG_ORIGIN
            ]
        if key == "manual":
            return [
                profile for profile in self.storage.profiles
                if profile.origin == "user"
            ]
        if key == "suggested":
            return [
                profile for profile in self.storage.profiles
                if profile.origin not in DIRECT_PROFILE_ORIGINS
            ]
        return []

    def _profile_sort_mode(self, key):
        value = str(self.storage.settings.get(
            f"config_sort_{key}", "country"
        ) or "country").lower()
        return value if value in {"country", "ping"} else "country"

    def _sync_profile_sort_control(self):
        combo = getattr(self, "profile_sort_combo", None)
        if combo is None:
            return
        combo.blockSignals(True)
        combo.setItemText(
            0, self.tr("مرتب‌سازی: کشور", "Sort: Country")
        )
        combo.setItemText(
            1, self.tr("مرتب‌سازی: کمترین پینگ", "Sort: Lowest ping")
        )
        mode = self._profile_sort_mode(self._current_profile_list_key())
        index = combo.findData(mode)
        combo.setCurrentIndex(max(0, index))
        combo.blockSignals(False)

    def _profile_sort_changed(self, _index):
        key = self._current_profile_list_key()
        mode = self.profile_sort_combo.currentData()
        if not key or mode not in {"country", "ping"}:
            return
        self.storage.settings[f"config_sort_{key}"] = mode
        self.storage.save_settings()
        self.refresh_profiles()

    def _ping_current_profile_list(self):
        if self._profile_ping_busy:
            return
        key = self._current_profile_list_key()
        profiles = self._profiles_for_list_key(key)
        if not profiles:
            self.show_toast(
                self.tr("این لیست کانفیگی ندارد", "This list has no configs"),
                "warning",
            )
            return
        self._profile_ping_generation += 1
        generation = self._profile_ping_generation
        self._profile_ping_busy = True
        self._profile_ping_cancel = threading.Event()
        cancel = self._profile_ping_cancel
        self.profile_ping_all_btn.setEnabled(False)
        self.profile_ping_all_btn.setText(
            self.tr("در حال پینگ…", "Pinging…")
        )
        self._set_activity(
            f"در حال پینگ گرفتن از {len(profiles)} کانفیگ…",
            f"Pinging {len(profiles)} configs…",
        )
        targets = [
            (
                profile.id,
                profile.address,
                int(profile.port or 443),
                self._effective_profile_fake_sni(profile),
            )
            for profile in profiles
        ]

        def probe(target):
            profile_id, address, port, sni = target
            if cancel.is_set():
                return profile_id, False, 0.0
            samples = []
            for _sample in range(2):
                if cancel.is_set():
                    break
                ok, latency = profile_real_delay(
                    address, port, sni, 2.5
                )
                if ok and latency > 0:
                    samples.append(float(latency))
            return (
                profile_id, bool(samples),
                min(samples) if samples else 0.0,
            )

        def work():
            results = []
            workers = min(8, max(1, len(targets)))
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=workers,
                    thread_name_prefix="config-ping") as pool:
                futures = [pool.submit(probe, target) for target in targets]
                for future in concurrent.futures.as_completed(futures):
                    if cancel.is_set():
                        break
                    try:
                        results.append(future.result())
                    except Exception:
                        pass
            self.bridge.profile_pings_done.emit(results, key, generation)

        threading.Thread(
            target=work, name="config-list-ping", daemon=True
        ).start()

    def _profile_pings_finished(self, results, key, generation):
        if generation != self._profile_ping_generation:
            return
        by_id = {
            str(profile_id): (bool(ok), float(latency or 0.0))
            for profile_id, ok, latency in results
        }
        successful = 0
        for profile in self._profiles_for_list_key(key):
            if profile.id not in by_id:
                continue
            ok, latency = by_id[profile.id]
            profile.last_ping_ok = ok
            profile.last_ping_ms = latency if ok else 0.0
            profile.country_latency_ms = (
                int(round(latency)) if ok else 0
            )
            successful += int(ok)
        self.storage.save_profiles()
        self._profile_ping_busy = False
        self.profile_ping_all_btn.setEnabled(True)
        self.profile_ping_all_btn.setText(
            self.tr("پینگ کل لیست", "Ping All")
        )
        self.refresh_profiles()
        self._set_activity(
            f"پینگ کامل شد؛ {successful} از {len(by_id)} کانفیگ پاسخ داد.",
            f"Ping completed; {successful} of {len(by_id)} configs responded.",
            "success", False,
        )

    def _position_profile_select_all(self):
        checkbox = getattr(self, "profile_select_all_checkbox", None)
        bar = getattr(self, "profile_selection_bar", None)
        if checkbox is None or bar is None:
            return
        widget = self._current_profile_list()
        if widget not in (
                self.user_config_list, self.manual_list,
                self.suggested_list):
            bar.hide()
            return
        index = self.profile_tabs.currentIndex()
        layout = self.profile_page_layouts[index]
        if layout.indexOf(bar) != 0:
            layout.insertWidget(0, bar)
        bar.setLayoutDirection(
            Qt.LeftToRight if self.language == "en" else Qt.RightToLeft
        )
        self._sync_profile_sort_control()
        bar.show()

    def _mode_apply_current(self, mode_generation, connect_generation,
                            cancel, run_id):
        return (
            not self._closing
            and not cancel.is_set()
            and mode_generation == self._mode_apply_generation
            and connect_generation == self._connect_generation
            and run_id == self.engine.run_id
            and self.engine.running
        )

    def _apply_proxy_mode_live(self, expected_run_id=None, current=None) -> bool:
        if current is not None and not current():
            raise EngineCancelled("Connection mode apply cancelled")
        if bool(getattr(self, "_tun_mode_enabled", lambda: False)()):
            if expected_run_id is None:
                self.engine.disable_system_proxy()
            else:
                self.engine.disable_system_proxy(expected_run_id=expected_run_id)
            return False
        enabled = self._proxy_mode_enabled()
        if current is not None and not current():
            raise EngineCancelled("Connection mode apply cancelled")
        if enabled:
            if expected_run_id is None:
                self.engine.enable_system_proxy()
            else:
                self.engine.enable_system_proxy(expected_run_id=expected_run_id)
        else:
            if expected_run_id is None:
                self.engine.disable_system_proxy()
            else:
                self.engine.disable_system_proxy(expected_run_id=expected_run_id)
        return enabled

    def _queue_proxy_mode_apply(self):
        if not self.engine.running:
            return
        mode_generation, connect_generation, cancel, run_id = self._begin_mode_apply()

        def current():
            return self._mode_apply_current(
                mode_generation, connect_generation, cancel, run_id
            )

        def work():
            enabled = self._proxy_mode_enabled()
            try:
                with self._proxy_mode_apply_lock:
                    if not current():
                        raise EngineCancelled("Connection mode apply cancelled")
                    enabled = self._apply_proxy_mode_live(run_id, current)
                if current():
                    self.bridge.proxy_mode_applied.emit(
                        enabled, True, "", mode_generation, run_id
                    )
            except EngineCancelled:
                return
            except Exception as exc:
                if current():
                    self.bridge.proxy_mode_applied.emit(
                        enabled, False, str(exc), mode_generation, run_id
                    )

        threading.Thread(target=work, name="proxy-mode", daemon=True).start()

    def _proxy_mode_apply_finished(self, enabled, success, error,
                                   mode_generation=None, run_id=None):
        if (mode_generation is not None
                and mode_generation != self._mode_apply_generation):
            return
        if run_id is not None and run_id != self.engine.run_id:
            return
        if enabled != self._proxy_mode_enabled():
            return
        if not success:
            fallback = not enabled
            self.proxy_mode.blockSignals(True)
            self.proxy_mode.setChecked(fallback)
            self.proxy_mode.blockSignals(False)
            self._save_flag("proxy_mode", fallback)
            self.proxy_option.setProperty("active", fallback)
            _restyle(self.proxy_option)
            self._handle_error(error)
            QTimer.singleShot(0, self._queue_target_latency_probe)
            return
        self._set_activity(
            "پروکسی ویندوز فعال شد؛ هسته اسپوف همچنان متصل است." if enabled else
            "فقط پروکسی ویندوز خاموش شد؛ هسته اسپوف همچنان فعال است.",
            "Windows Proxy enabled; the spoof core remains connected." if enabled else
            "Only Windows Proxy was disabled; the spoof core remains active.",
            "success", False,
        )
        QTimer.singleShot(0, self._queue_target_latency_probe)

    def _apply_proxy_mode_after_probe(self, cancel=None,
                                      expected_run_id=None) -> bool:
        if not self._proxy_mode_enabled():
            self.bridge.log.emit(
                "Windows system proxy skipped by Proxy Mode; "
                "Xray and Patterniha remain active"
            )
            return False
        self.bridge.activity.emit(self.tr(
            "در حال اعمال پروکسی سیستم ویندوز…",
            "Applying Windows system proxy…",
        ), "running", True)
        if expected_run_id is None:
            self.engine.enable_system_proxy(cancel)
        else:
            self.engine.enable_system_proxy(
                cancel, expected_run_id=expected_run_id
            )
        if not self._proxy_mode_enabled():
            if expected_run_id is None:
                self.engine.disable_system_proxy()
            else:
                self.engine.disable_system_proxy(
                    expected_run_id=expected_run_id
                )
            return False
        return True

    def _tun_mode_changed(self, enabled):
        enabled = bool(enabled)
        availability_error = ""
        if enabled:
            try:
                self.engine.ensure_tun_available()
            except Exception as exc:
                self.tun_mode.blockSignals(True)
                self.tun_mode.setChecked(False)
                self.tun_mode.blockSignals(False)
                enabled = False
                availability_error = str(exc)
        self._save_flag("tun_mode", enabled)
        self.tun_option.setProperty("active", enabled)
        self.proxy_option.setEnabled(not enabled)
        _restyle(self.tun_option)
        _restyle(self.proxy_option)
        if availability_error:
            self._handle_error(availability_error)
            return
        if (self.connecting and hasattr(self, "_ui_running")
                and not self._ui_running):
            self._set_activity(
                "تنظیم TUN ذخیره شد و پس از پایان تست مسیر اعمال می‌شود.",
                "TUN preference saved; it will apply after route testing.",
            )
            return
        if not self.engine.running:
            self._set_activity(
                "حالت TUN برای اتصال بعدی فعال است." if enabled else
                "حالت TUN خاموش است؛ اتصال بعدی از تنظیم پروکسی ویندوز استفاده می‌کند.",
                "TUN Mode will be enabled on the next connection." if enabled else
                "TUN Mode is off; the next connection will use the Windows Proxy preference.",
                "success", False,
            )
            return
        self._queue_tun_mode_apply()

    def _apply_tun_mode_live(self, expected_run_id=None, cancel=None,
                             current=None) -> bool:
        def ensure_current():
            if current is not None and not current():
                raise EngineCancelled("Connection mode apply cancelled")

        def ensure_preference(value):
            if self._tun_mode_enabled() != value:
                raise EngineCancelled("TUN preference changed")

        lock = getattr(self, "_proxy_mode_apply_lock", None)
        if lock is None:
            lock = threading.Lock()
        enabled = self._tun_mode_enabled()
        ensure_current()
        if enabled:
            try:
                with lock:
                    ensure_current()
                    ensure_preference(True)
                    if expected_run_id is None:
                        self.engine.enable_tun()
                    else:
                        self.engine.enable_tun(
                            cancel, expected_run_id=expected_run_id
                        )
                ensure_current()
                ensure_preference(True)
                if expected_run_id is None:
                    ok, detail = self.engine.probe_tun(timeout=10)
                else:
                    ok, detail = self.engine.probe_tun(
                        timeout=10,
                        cancel_event=cancel,
                        expected_run_id=expected_run_id,
                    )
                ensure_current()
                if not ok:
                    raise RuntimeError(f"TUN traffic check failed: {detail}")
                with lock:
                    ensure_current()
                    ensure_preference(True)
                    if expected_run_id is None:
                        self.engine.suspend_system_proxy_for_tun()
                    else:
                        self.engine.suspend_system_proxy_for_tun(
                            expected_run_id=expected_run_id
                        )
            except EngineCancelled:
                raise
            except Exception:
                with lock:
                    ensure_current()
                    ensure_preference(True)
                    try:
                        if expected_run_id is None:
                            self.engine.disable_tun()
                        else:
                            self.engine.disable_tun(
                                expected_run_id=expected_run_id
                            )
                    except Exception:
                        if self.engine.tun_running:
                            if expected_run_id is None:
                                self.engine.suspend_system_proxy_for_tun()
                            else:
                                self.engine.suspend_system_proxy_for_tun(
                                    expected_run_id=expected_run_id
                                )
                        raise
                    if self._proxy_mode_enabled():
                        if expected_run_id is None:
                            self.engine.enable_system_proxy()
                        else:
                            self.engine.enable_system_proxy(
                                expected_run_id=expected_run_id
                            )
                raise
            return True
        with lock:
            ensure_current()
            ensure_preference(False)
            if self._proxy_mode_enabled():
                if expected_run_id is None:
                    self.engine.enable_system_proxy()
                else:
                    self.engine.enable_system_proxy(expected_run_id=expected_run_id)
            else:
                if expected_run_id is None:
                    self.engine.disable_system_proxy()
                else:
                    self.engine.disable_system_proxy(expected_run_id=expected_run_id)
            ensure_current()
            ensure_preference(False)
            try:
                if expected_run_id is None:
                    self.engine.disable_tun()
                else:
                    self.engine.disable_tun(expected_run_id=expected_run_id)
            except Exception:
                if self.engine.tun_running:
                    if expected_run_id is None:
                        self.engine.suspend_system_proxy_for_tun()
                    else:
                        self.engine.suspend_system_proxy_for_tun(
                            expected_run_id=expected_run_id
                        )
                raise
        return False

    def _queue_tun_mode_apply(self):
        if not self.engine.running:
            return
        mode_generation, connect_generation, cancel, run_id = self._begin_mode_apply()

        def current():
            return self._mode_apply_current(
                mode_generation, connect_generation, cancel, run_id
            )

        def work():
            enabled = self._tun_mode_enabled()
            try:
                if not current():
                    raise EngineCancelled("Connection mode apply cancelled")
                enabled = self._apply_tun_mode_live(run_id, cancel, current)
                if current():
                    self.bridge.tun_mode_applied.emit(
                        enabled, True, "", mode_generation, run_id
                    )
            except EngineCancelled:
                return
            except Exception as exc:
                if current():
                    self.bridge.tun_mode_applied.emit(
                        enabled, False, str(exc), mode_generation, run_id
                    )

        threading.Thread(target=work, name="tun-mode", daemon=True).start()

    def _tun_mode_apply_finished(self, enabled, success, error,
                                 mode_generation=None, run_id=None):
        if (mode_generation is not None
                and mode_generation != self._mode_apply_generation):
            return
        if run_id is not None and run_id != self.engine.run_id:
            return
        if enabled != self._tun_mode_enabled():
            return
        if not success:
            runtime_enabled = bool(self.engine.tun_running)
            self.tun_mode.blockSignals(True)
            self.tun_mode.setChecked(runtime_enabled)
            self.tun_mode.blockSignals(False)
            self._save_flag("tun_mode", runtime_enabled)
            self.tun_option.setProperty("active", runtime_enabled)
            self.proxy_option.setEnabled(not runtime_enabled)
            _restyle(self.tun_option)
            _restyle(self.proxy_option)
            self._handle_error(error)
            if hasattr(self, "_queue_target_latency_probe"):
                QTimer.singleShot(0, self._queue_target_latency_probe)
            return
        proxy_enabled = self._proxy_mode_enabled()
        self._set_activity(
            "حالت TUN فعال شد؛ وب و ویدئو از تونل عبور می‌کنند و پینگ CMD مستقیم است."
            if enabled else
            "حالت TUN خاموش و پروکسی ویندوز دوباره فعال شد."
            if proxy_enabled else
            "حالت TUN خاموش شد؛ فقط هسته اسپوف فعال مانده است.",
            "TUN Mode enabled; web and video use the tunnel while CMD ping stays direct."
            if enabled else
            "TUN Mode disabled and Windows Proxy restored."
            if proxy_enabled else
            "TUN Mode disabled; only the spoof core remains active.",
            "success", False,
        )
        if hasattr(self, "_queue_target_latency_probe"):
            QTimer.singleShot(0, self._queue_target_latency_probe)

    def _gateway_runtime_active(self) -> bool:
        value = getattr(self.engine, "gateway_running", False)
        try:
            return bool(value() if callable(value) else value)
        except Exception:
            return False

    def _position_gateway_devices_popup(self):
        popup = getattr(self, "gateway_devices_popup", None)
        badge = getattr(self, "gateway_devices_badge", None)
        if popup is None or badge is None or not popup.isVisible():
            return
        below = badge.mapToGlobal(QPoint(0, badge.height() + 7))
        trailing = badge.mapToGlobal(QPoint(badge.width(), badge.height() + 7))
        screen = QApplication.screenAt(below)
        if screen is None:
            screen = QApplication.primaryScreen()
        available = screen.availableGeometry() if screen is not None else None
        window_origin = self.mapToGlobal(QPoint(0, 0))
        window_left = window_origin.x() + 8
        window_top = window_origin.y() + 8
        window_right = window_origin.x() + self.width() - 9
        window_bottom = window_origin.y() + self.height() - 9
        x = (
            below.x()
            if self.language == "en"
            else trailing.x() - popup.width()
        )
        y = below.y()
        if available is not None:
            left = max(available.left() + 6, window_left)
            top = max(available.top() + 6, window_top)
            right = min(available.right() - 5, window_right)
            bottom = min(available.bottom() - 5, window_bottom)
            if y + popup.height() > bottom:
                y = badge.mapToGlobal(QPoint(
                    0, -popup.height() - 7
                )).y()
            x = max(
                left,
                min(x, right - popup.width()),
            )
            y = max(
                top,
                min(y, bottom - popup.height()),
            )
        popup.move(x, y)

    def _toggle_gateway_devices_popup(self):
        popup = getattr(self, "gateway_devices_popup", None)
        if popup is None:
            return
        if popup.isVisible():
            popup.hide()
            return
        popup.set_language(self.language)
        popup.update_devices(self._gateway_devices)
        popup.show()
        self._position_gateway_devices_popup()
        popup.raise_()

    def _gateway_devices_updated(self, devices):
        self._gateway_devices = dict(devices or {})
        toggle = getattr(self, "gateway_mode", None)
        if toggle is None:
            return
        count = len(self._gateway_devices)
        active = self._gateway_runtime_active()
        badge = getattr(self, "gateway_devices_badge", None)
        if badge is not None:
            badge.setText(str(count))
            badge.setProperty("hasDevices", bool(count))
            badge.setProperty("gatewayActive", active)
            badge.setAccessibleName(self.tr(
                f"{count} دستگاه متصل به درگاه موبایل",
                f"{count} devices connected to Mobile Gateway",
            ))
            badge.setToolTip(self.tr(
                "نمایش دستگاه‌های متصل",
                "Show connected devices",
            ))
            _restyle(badge)
        popup = getattr(self, "gateway_devices_popup", None)
        if popup is not None:
            popup.set_language(self.language)
            popup.update_devices(self._gateway_devices)
            if popup.isVisible():
                self._position_gateway_devices_popup()
        detail = self.tr(
            f" دستگاه شناسایی‌شده: {count}." if count else "",
            f" Detected devices: {count}." if count else "",
        )
        toggle.setToolTip(self.tr(
            "با یک کلیک، اینترنت موبایل را از درگاه شبکه این رایانه به تونل تأییدشده هدایت می‌کند.",
            "One click routes mobile internet through this computer and the verified tunnel.",
        ) + detail)

    def _gateway_runtime_state_changed(self, state, device_count=0, detail=""):
        state = str(state or "").strip().lower()
        self._gateway_runtime_state = state
        if state == "active" and self._gateway_requested:
            self._set_gateway_toggle(True)
        elif (state in {"inactive", "error", "restore-pending"}
              and self._gateway_apply_target is None):
            self._gateway_requested = False
            self._cancel_gateway_apply()
            self._set_gateway_toggle(False)
            popup = getattr(self, "gateway_devices_popup", None)
            if popup is not None:
                popup.hide()
        self._sync_gateway_controls()
        if state in {"error", "restore-pending"} and detail:
            self._append_log(
                f"Mobile Gateway {state}: {detail}"
            )

    def _set_gateway_toggle(self, checked):
        toggle = getattr(self, "gateway_mode", None)
        if toggle is None:
            return
        checked = bool(checked)
        toggle.blockSignals(True)
        toggle.setChecked(checked)
        toggle.blockSignals(False)
        animation = getattr(toggle, "_thumb_animation", None)
        if animation is not None:
            animation.stop()
        set_position = getattr(toggle, "_set_thumb_position", None)
        if callable(set_position):
            set_position(1.0 if checked else 0.0)

    def _sync_gateway_controls(self):
        requested = bool(getattr(self, "_gateway_requested", False))
        active = self._gateway_runtime_active()
        target = getattr(self, "_gateway_apply_target", None)
        transitioning = target is not None
        state = (
            "starting" if target is True else
            "stopping" if target is False else
            "active" if active else
            "requested" if requested else
            "off"
        )
        option = getattr(self, "gateway_option", None)
        if option is not None:
            option.setProperty("state", state)
            option.setProperty("active", active)
            option.setProperty("busy", transitioning)
            _restyle(option)
        gateway_mode = getattr(self, "gateway_mode", None)
        if gateway_mode is not None:
            gateway_mode.setEnabled(not transitioning)
        badge = getattr(self, "gateway_devices_badge", None)
        if badge is not None:
            badge.setProperty("gatewayActive", active)
            badge.setProperty(
                "hasDevices", bool(getattr(self, "_gateway_devices", {}))
            )
            _restyle(badge)
        locked = requested or active or transitioning
        tun_mode = getattr(self, "tun_mode", None)
        tun_option = getattr(self, "tun_option", None)
        if tun_mode is not None:
            tun_mode.setEnabled(not locked)
        if tun_option is not None:
            tun_option.setEnabled(not locked)

    def _cancel_gateway_apply(self):
        event = getattr(self, "_gateway_apply_cancel", None)
        if event is not None:
            event.set()
        self._gateway_apply_generation = int(
            getattr(self, "_gateway_apply_generation", 0)
        ) + 1
        self._gateway_apply_target = None
        reasons = getattr(self, "_gateway_apply_reasons", None)
        if isinstance(reasons, dict):
            reasons.clear()

    def _begin_gateway_apply(self, enabled, reason):
        self._cancel_gateway_apply()
        self._gateway_apply_cancel = threading.Event()
        self._gateway_apply_target = bool(enabled)
        generation = self._gateway_apply_generation
        self._gateway_apply_reasons[generation] = str(reason or "user")
        return (
            generation,
            self._connect_generation,
            self._gateway_apply_cancel,
            int(getattr(self.engine, "run_id", 0)),
        )

    def _gateway_apply_current(self, enabled, generation, connect_generation,
                               cancel, run_id):
        current = (
            not cancel.is_set()
            and generation == self._gateway_apply_generation
        )
        if not current or not enabled:
            return current
        return (
            not self._closing
            and connect_generation == self._connect_generation
            and run_id == int(getattr(self.engine, "run_id", 0))
            and bool(self.engine.running)
            and bool(getattr(self, "_ui_running", False))
            and not self.connecting
            and bool(self._gateway_requested)
        )

    def _queue_gateway_mode_apply(self, enabled, reason="user", force=False):
        enabled = bool(enabled)
        active = self._gateway_runtime_active()
        if enabled:
            if (not self._gateway_requested or not self.engine.running
                    or not getattr(self, "_ui_running", False)
                    or self.connecting):
                return
            if active:
                self._sync_gateway_controls()
                return
        elif not force and not active and self._gateway_apply_target is not True:
            self._sync_gateway_controls()
            return
        if self._gateway_apply_target is enabled:
            return
        generation, connect_generation, cancel, run_id = (
            self._begin_gateway_apply(enabled, reason)
        )
        self._set_gateway_toggle(enabled)
        self._sync_gateway_controls()

        def current():
            return self._gateway_apply_current(
                enabled, generation, connect_generation, cancel, run_id
            )

        if reason == "user":
            self._set_activity(
                "در حال فعال‌سازی درگاه موبایل…" if enabled else
                "در حال خاموش کردن درگاه موبایل…",
                "Activating Mobile Gateway…" if enabled else
                "Disabling Mobile Gateway…",
            )

        def work():
            success = False
            error = ""
            try:
                with self._gateway_apply_lock:
                    if not current():
                        return
                    if enabled:
                        self.engine.enable_gateway(
                            expected_run_id=run_id,
                            cancel_event=cancel,
                        )
                        if not current():
                            try:
                                self.engine.disable_gateway(
                                    reason="cancelled",
                                    expected_run_id=run_id,
                                )
                            except Exception:
                                pass
                            return
                        success = self._gateway_runtime_active()
                        if not success:
                            error = "Mobile Gateway did not enter the running state"
                    else:
                        expected_run_id = run_id if reason == "user" else None
                        self.engine.disable_gateway(
                            reason=str(reason or "user"),
                            expected_run_id=expected_run_id,
                        )
                        if not current():
                            return
                        success = not self._gateway_runtime_active()
                        if not success:
                            error = "Mobile Gateway is still running"
            except Exception as exc:
                error = str(exc)
                active_now = self._gateway_runtime_active()
                success = active_now if enabled else not active_now
                if success:
                    error = ""
            if current():
                self.bridge.gateway_mode_applied.emit(
                    enabled, success, error, generation, run_id
                )

        threading.Thread(
            target=work, name=f"gateway-mode-{generation}", daemon=True
        ).start()

    def _reset_gateway_mode(self, reason="disconnect", stop=True):
        requested = bool(getattr(self, "_gateway_requested", False))
        active = self._gateway_runtime_active()
        pending_enable = self._gateway_apply_target is True
        self._gateway_requested = False
        self._cancel_gateway_apply()
        self._set_gateway_toggle(False)
        self._sync_gateway_controls()
        if stop and (requested or active or pending_enable):
            self._queue_gateway_mode_apply(False, reason=reason, force=True)
        return requested or active or pending_enable

    def _gateway_mode_changed(self, enabled):
        enabled = bool(enabled)
        if not enabled:
            self._reset_gateway_mode(reason="user", stop=True)
            return
        self._gateway_requested = True
        self._cancel_gateway_apply()
        self._sync_gateway_controls()
        if (self.engine.running and getattr(self, "_ui_running", False)
                and not self.connecting):
            self._queue_gateway_mode_apply(True, reason="user")
            return
        self._set_activity(
            "درگاه موبایل درخواست شد؛ ابتدا اتصال امن بررسی می‌شود…",
            "Mobile Gateway requested; verifying the secure connection first…",
        )
        if not self.connecting:
            self.toggle_connection()
            if (not self.connecting
                    and not getattr(self, "_ui_running", False)):
                self._reset_gateway_mode(
                    reason="connection-failed", stop=True
                )

    def _gateway_mode_apply_finished(self, enabled, success, error,
                                     generation=None, run_id=None):
        if (generation is not None
                and generation != self._gateway_apply_generation):
            return
        reason = self._gateway_apply_reasons.pop(
            generation, "user"
        ) if generation is not None else "user"
        self._gateway_apply_target = None
        active = self._gateway_runtime_active()
        if enabled:
            if success and active and self._gateway_requested:
                self._sync_gateway_controls()
                self._set_activity(
                    "درگاه موبایل فعال شد؛ ترافیک دستگاه از تونل عبور می‌کند.",
                    "Mobile Gateway is active; device traffic is using the tunnel.",
                    "success", False,
                )
                return
            message = error or self.tr(
                "فعال‌سازی درگاه موبایل کامل نشد",
                "Mobile Gateway activation did not complete",
            )
            self._gateway_requested = False
            self._cancel_gateway_apply()
            self._set_gateway_toggle(False)
            self._sync_gateway_controls()
            if active:
                self._queue_gateway_mode_apply(
                    False, reason="activation-failed", force=True
                )
            self._handle_error(message)
            return
        if success or not active:
            self._sync_gateway_controls()
            if reason == "user" and getattr(self, "_ui_running", False):
                self._set_activity(
                    "درگاه موبایل خاموش شد؛ اتصال ویندوز فعال ماند.",
                    "Mobile Gateway disabled; the Windows connection stayed active.",
                    "success", False,
                )
            return
        if reason == "user":
            self._gateway_requested = True
            self._set_gateway_toggle(True)
        self._sync_gateway_controls()
        message = error or self.tr(
            "خاموش کردن درگاه موبایل کامل نشد",
            "Mobile Gateway did not stop cleanly",
        )
        if reason == "user":
            self._handle_error(message)
        else:
            self._append_log(f"Mobile Gateway cleanup pending: {message}")

    def _apply_connection_mode_after_probe(self, cancel=None) -> str:
        expected_run_id = getattr(self.engine, "run_id", None)

        def check_current():
            is_set = getattr(cancel, "is_set", None)
            if callable(is_set) and is_set():
                raise EngineCancelled("Connection mode apply cancelled")
            if (expected_run_id is not None
                    and expected_run_id != self.engine.run_id):
                raise EngineCancelled("Connection generation changed")

        def enable_proxy():
            if expected_run_id is None:
                self.engine.enable_system_proxy(cancel)
            else:
                self.engine.enable_system_proxy(
                    cancel, expected_run_id=expected_run_id
                )

        def disable_tun():
            if expected_run_id is None:
                self.engine.disable_tun()
            else:
                self.engine.disable_tun(expected_run_id=expected_run_id)

        for _attempt in range(4):
            check_current()
            if self._tun_mode_enabled():
                self.bridge.activity.emit(self.tr(
                    "در حال ساخت رابط TUN و بررسی یوتیوب…",
                    "Starting the TUN interface and checking YouTube…",
                ), "running", True)
                if expected_run_id is None:
                    self.engine.enable_tun(cancel)
                else:
                    self.engine.enable_tun(
                        cancel, expected_run_id=expected_run_id
                    )
                check_current()
                if not self._tun_mode_enabled():
                    if self._proxy_mode_enabled():
                        enable_proxy()
                    check_current()
                    disable_tun()
                    continue
                probe_arguments = {
                    "timeout": 10,
                    "preferred_url": "https://www.youtube.com/generate_204",
                    "require_preferred": True,
                    "cancel_event": cancel,
                }
                if expected_run_id is not None:
                    probe_arguments["expected_run_id"] = expected_run_id
                ok, detail = self.engine.probe_tun(
                    **probe_arguments,
                )
                check_current()
                if not ok:
                    raise RuntimeError(f"TUN YouTube traffic check failed: {detail}")
                if not self._tun_mode_enabled():
                    if self._proxy_mode_enabled():
                        enable_proxy()
                    check_current()
                    disable_tun()
                    continue
                if expected_run_id is None:
                    self.engine.suspend_system_proxy_for_tun()
                else:
                    self.engine.suspend_system_proxy_for_tun(
                        expected_run_id=expected_run_id
                    )
                return "tun"
            if self.engine.tun_running:
                if self._proxy_mode_enabled():
                    enable_proxy()
                check_current()
                disable_tun()
            if expected_run_id is None:
                proxy_active = self._apply_proxy_mode_after_probe(cancel)
            else:
                proxy_active = self._apply_proxy_mode_after_probe(
                    cancel, expected_run_id
                )
            check_current()
            if not self._tun_mode_enabled():
                return "proxy" if proxy_active else "core"
        raise RuntimeError("Connection mode changed repeatedly during activation")

    def _selected_country_code(self) -> str:
        combo = getattr(self, "country_combo", None)
        value = combo.currentData() if combo is not None else self.storage.settings.get("selected_country", "ALL")
        value = str(value or "ALL").strip().upper()
        available = {
            str(profile.country_code or "").upper()
            for profile in self.storage.profiles
            if len(str(profile.country_code or "")) == 2
        }
        known = {
            str(code).upper()
            for code in self.storage.settings.get("known_country_codes", [])
            if len(str(code)) == 2
        }
        return value if value in COUNTRIES or value in available or value in known else ""

    def _selected_route_source(self) -> str:
        tabs = getattr(self, "route_source_tabs", None)
        if tabs is not None:
            return "user-config" if tabs.currentIndex() == 1 else "suggested"
        value = str(self.storage.settings.get("route_source", "suggested") or "suggested").lower()
        return "user-config" if value == "user-config" else "suggested"

    def _route_source_profiles(self, verified_only=False):
        source = self._selected_route_source()
        profiles = [
            profile for profile in self.storage.profiles
            if (
                profile.origin == USER_CONFIG_ORIGIN
                if source == "user-config"
                else profile.origin not in DIRECT_PROFILE_ORIGINS
            )
        ]
        if verified_only:
            profiles = [
                profile for profile in profiles
                if profile.route_is_verified
            ]
        return profiles

    def _country_metadata(self, code):
        code = str(code or "").upper()
        known = COUNTRIES.get(code)
        if known:
            return known
        observed = next((
            str(profile.observed_country_name or "").strip()
            for profile in self.storage.profiles
            if str(profile.country_code or profile.observed_country_code).upper() == code
            and str(profile.observed_country_name or "").strip()
        ), code)
        return ("", observed or code, observed or code)

    def _country_profiles(self, country_code=None):
        country_code = (country_code or self._selected_country_code()).upper()
        now = time.time()
        profiles = []
        for profile in self._route_source_profiles(verified_only=True):
            if profile.country_code.upper() != country_code:
                continue
            if profile.rotating_exit:
                fresh = now - float(profile.country_verified_at or 0) < 30 * 60
                if not fresh or profile.observed_country_code.upper() != country_code:
                    continue
            profiles.append(profile)
        return profiles

    def _record_profile_location(self, profile, location: GeoLocation) -> bool:
        """Persist the country actually observed through this live tunnel."""
        code = str(location.country_code or "").upper()
        if len(code) != 2:
            return False
        previous = profile.country_code.upper()
        profile.observed_exit_ip = str(location.ip or "")
        profile.observed_country_code = code
        profile.observed_country_name = str(location.country or "")
        profile.country_verified_at = time.time()
        profile.country_source = str(location.source or "")
        profile.country_code = code
        if profile.origin not in DIRECT_PROFILE_ORIGINS:
            try:
                fragment = profile.source_uri.rsplit("#", 1)[1]
                sequence = int(fragment.split("-", 2)[1])
            except (IndexError, TypeError, ValueError):
                sequence = 0
            _flag, english, _persian = COUNTRIES.get(
                code, ("🌐", location.country or code, location.country or code)
            )
            suffix = f"Spoof {sequence:03d}" if sequence else "Spoof"
            profile.name = f"{english} · {suffix}"
        known_codes = {
            str(value).upper()
            for value in self.storage.settings.get("known_country_codes", [])
            if len(str(value)) == 2
        }
        known_codes.add(code)
        self.storage.settings["known_country_codes"] = sorted(known_codes)
        self.storage.save_profiles()
        self.storage.save_settings()
        self.bridge.log.emit(
            f"EXIT COUNTRY profile={profile.id} ip={location.ip} "
            f"country={code} source={location.source} previous={previous or '-'}"
        )
        return previous != code

    def _refresh_country_selector(self):
        if not hasattr(self, "country_combo"):
            return
        source = self._selected_route_source()
        selected = str(self.storage.settings.get(
            f"selected_country_{source}",
            self.storage.settings.get("selected_country", "ALL"),
        ) or "ALL").upper()
        observed_meta = {}
        for profile in self.storage.profiles:
            code = str(profile.country_code or profile.observed_country_code or "").upper()
            if len(code) != 2:
                continue
            name = str(getattr(profile, "observed_country_name", "") or "").strip()
            if name:
                observed_meta[code] = name
        country_codes = sorted(
            set(COUNTRIES) | {
                str(profile.country_code or "").upper()
                for profile in self.storage.profiles
                if len(str(profile.country_code or "")) == 2
            } | {
                str(code).upper()
                for code in self.storage.settings.get("known_country_codes", [])
                if len(str(code)) == 2
            },
            key=lambda code: (
                COUNTRIES.get(code, ("", observed_meta.get(code, code), ""))[1].lower(),
                code,
            ),
        )
        if selected not in country_codes:
            selected = "ALL"
        self.country_combo.blockSignals(True)
        self.country_combo.clear()



        self.country_combo.setLayoutDirection(Qt.LeftToRight)
        self.country_combo.view().setLayoutDirection(Qt.LeftToRight)
        self.country_combo.view().setMinimumWidth(360)
        self.country_combo.view().setIconSize(QSize(30, 20))
        self.country_combo.view().setTextElideMode(Qt.ElideNone)
        if hasattr(self.country_combo.view(), "setSpacing"):
            self.country_combo.view().setSpacing(3)
        all_text = self.tr("همه کشورها", "All countries")
        self.country_combo.addItem(cyber_icon("globe", "#78fff0", 19), all_text, "ALL")
        for code in country_codes:
            _flag, english, persian = self._country_metadata(code)
            count = len(self._country_profiles(code))
            name = (f"{english}  ({count})" if self.language == "en" else
                    f"{persian} · {ltr_isolate(f'{english} ({count})')}")
            self.country_combo.addItem(country_flag_icon(code), name, code)
        index = self.country_combo.findData(selected)
        self.country_combo.setCurrentIndex(max(0, index))
        self.country_combo.blockSignals(False)
        active_code = self._selected_country_code()
        active_count = len(self._country_profiles(active_code)) if active_code else sum(
            1 for profile in self._route_source_profiles(verified_only=True)
        )
        self.country_count.setText(self.tr(f"{active_count} کانفیگ سالم", f"{active_count} verified configs"))

    def _country_activated(self, _index):
        code = self._selected_country_code()
        source = self._selected_route_source()
        self.storage.settings["selected_country"] = code or "ALL"
        self.storage.settings[f"selected_country_{source}"] = code or "ALL"
        self.storage.save_settings()
        self._refresh_country_selector()
        self.refresh_profiles()
        if not self.auto_mode.isChecked():
            self._set_activity(
                "حالت دستی فعال است؛ برای استفاده از کشورها حالت خودکار را روشن کنید.",
                "Manual mode is active; enable Auto Mode to use country routes.",
                "warning", False,
            )
            return
        if not code:
            self._set_activity("فیلتر کشور برداشته شد.", "Country filter cleared.", "success", False)
            return
        _flag, english, persian = self._country_metadata(code)
        country_name = english if self.language == "en" else persian
        self.bridge.log.emit(f"COUNTRY SELECT {code} profiles={len(self._country_profiles(code))}")
        self._set_activity(
            f"در حال آماده‌سازی کانفیگ‌های {country_name}…",
            f"Preparing {country_name} configs…",
        )
        if self.connecting or self.engine.running:
            self._cancel_connect_attempt(notify=True)
            self._set_state(False)
        QTimer.singleShot(120, self._start_selected_country)

    def _route_source_changed(self, _index):
        source = self._selected_route_source()
        self.storage.settings["route_source"] = source
        self.storage.save_settings()
        self._refresh_country_selector()
        self._sync_auto_mode_ui(select_profile=True)
        title = "User Config" if source == "user-config" else self.tr("پیشنهادی", "Suggested")
        self._set_activity(
            f"منبع اتصال خودکار روی {title} تنظیم شد.",
            f"Auto connection source set to {title}.",
            "success", False,
        )

    def _start_selected_country(self):
        if (not self._closing and self.auto_mode.isChecked()
                and self._selected_country_code() and not self.connecting
                and not self.engine.running):
            self.toggle_connection()

    def _direct_source_origin(self):
        value = str(self.storage.settings.get("direct_source", "") or "").lower()
        if value == "user-config":
            return USER_CONFIG_ORIGIN
        if value == "manual":
            return "user"
        selected = self.storage.selected()
        if selected is not None and selected.origin in DIRECT_PROFILE_ORIGINS:
            return selected.origin
        return (
            "user" if any(profile.origin == "user" for profile in self.storage.profiles)
            else USER_CONFIG_ORIGIN
        )

    def _remember_direct_profile(self, profile):
        if profile is None or profile.origin not in DIRECT_PROFILE_ORIGINS:
            return
        source = "user-config" if profile.origin == USER_CONFIG_ORIGIN else "manual"
        self.storage.settings["direct_source"] = source
        self.storage.settings[
            "last_user_config_profile_id"
            if profile.origin == USER_CONFIG_ORIGIN else
            "last_manual_profile_id"
        ] = profile.id
        save = getattr(self.storage, "save_settings", None)
        if callable(save):
            save()

    def _profile_tab_changed(self, index):
        widget = (
            self.user_config_list, self.manual_list,
            self.suggested_list,
        )[index]
        self._sync_profile_sort_control()
        self._position_profile_select_all()
        if widget is not self.user_config_list and widget is not self.manual_list:
            return
        auto_mode = getattr(self, "auto_mode", None)
        if auto_mode is not None and auto_mode.isChecked():
            return
        source = "user-config" if widget is self.user_config_list else "manual"
        self.storage.settings["direct_source"] = source
        item = widget.currentItem()
        if item is not None:
            profile_id = item.data(Qt.UserRole)
            profile = next((
                value for value in self.storage.profiles
                if value.id == profile_id and value.origin in DIRECT_PROFILE_ORIGINS
            ), None)
            if profile is not None:
                self.storage.selected_id = profile.id
                self._remember_direct_profile(profile)
                return
        save = getattr(self.storage, "save_settings", None)
        if callable(save):
            save()

    def _select_manual_profile(self) -> ProxyProfile | None:
        origin = MainWindow._direct_source_origin(self)
        widget = self.user_config_list if origin == USER_CONFIG_ORIGIN else self.manual_list
        setting_key = (
            "last_user_config_profile_id"
            if origin == USER_CONFIG_ORIGIN else
            "last_manual_profile_id"
        )
        preferred_id = str(self.storage.settings.get(setting_key, "") or "")
        item = widget.currentItem()
        item_id = item.data(Qt.UserRole) if item is not None else ""
        candidate_ids = [preferred_id, item_id, self.storage.selected_id]
        selected = next((
            profile for profile_id in candidate_ids if profile_id
            for profile in self.storage.profiles
            if profile.id == profile_id and profile.origin == origin
        ), None)
        if selected is None:
            selected = next((
                profile for profile in self.storage.profiles
                if profile.origin == origin
            ), None)
        if selected is None:
            fallback_origin = "user" if origin == USER_CONFIG_ORIGIN else USER_CONFIG_ORIGIN
            selected = next((
                profile for profile in self.storage.profiles
                if profile.origin == fallback_origin
            ), None)
        if selected is not None:
            self.storage.selected_id = selected.id
            MainWindow._remember_direct_profile(self, selected)
            widget = (
                self.user_config_list
                if selected.origin == USER_CONFIG_ORIGIN else self.manual_list
            )
            if hasattr(widget, "item"):
                for row in range(widget.count()):
                    current = widget.item(row)
                    if current.data(Qt.UserRole) == selected.id:
                        widget.setCurrentItem(current)
                        break
        return selected

    def _sync_auto_mode_ui(self, select_profile=False):
        enabled = self.auto_mode.isChecked()
        self.country_combo.setEnabled(enabled)
        self.route_source_tabs.setEnabled(enabled)
        self.manual_option.setEnabled(not enabled)
        self.country_card.setProperty("mode", "auto" if enabled else "manual")
        _restyle(self.country_card)
        self.country_description.setText(self.tr(
            "منبع کانفیگ و کشور را انتخاب کنید؛ سالم‌ترین مسیر همان بخش به‌صورت خودکار متصل می‌شود."
            if enabled else "حالت دستی فعال است؛ کانفیگ انتخاب‌شده از Manual یا User Config متصل می‌شود.",
            "Choose a config source and country; Auto Mode connects its best verified route."
            if enabled else "Manual mode uses the selected Manual or User Config entry.",
        ))
        if select_profile:
            if enabled:
                self.profile_tabs.setCurrentIndex(
                    self._profile_tab_index(
                        self.user_config_list
                        if self._selected_route_source() == "user-config"
                        else self.suggested_list
                    )
                )
            else:
                direct_index = self._profile_tab_index(
                    self.user_config_list
                    if MainWindow._direct_source_origin(self) == USER_CONFIG_ORIGIN
                    else self.manual_list
                )
                self.profile_tabs.setCurrentIndex(direct_index)
                self._select_manual_profile()

    def _auto_mode_changed(self, enabled):
        if enabled:
            self._remember_direct_profile(self.storage.selected())
        self._save_flag("auto_mode", enabled)
        self._sync_auto_mode_ui(select_profile=True)
        self.refresh_profiles()
        self._set_activity(
            "حالت خودکار فعال شد؛ منبع و کشور انتخاب‌شده تست می‌شوند."
            if enabled else "حالت دستی فعال شد؛ از Manual یا User Config یک کانفیگ انتخاب کنید.",
            "Auto Mode enabled; the selected source and country will be tested."
            if enabled else "Manual mode enabled; select an entry from Manual or User Config.",
            "success", False,
        )

    def _carrier_changed(self, carrier):
        tuning = self.storage.activate_carrier(carrier)
        self.bridge.log.emit(
            f"CARRIER PROFILE active={carrier} edge={tuning.pattern_connect_ip} "
            f"fakeSni={tuning.pattern_fake_sni} sessions={tuning.pattern_max_sessions}")
        self.refresh_profiles()

    def _effective_profile_fake_sni(self, profile, carrier=None):
        if profile.route_mode == "reality-direct":
            return str(profile.sni or "").strip()
        carrier = carrier or self.storage.tuning.carrier_mode
        settings = self.storage.settings
        scoped_pins = settings.get("pattern_profile_sni_pins_by_carrier", {})
        bucket = scoped_pins.get(carrier, {}) if isinstance(scoped_pins, dict) else {}
        bucket = bucket if isinstance(bucket, dict) else {}
        value = bucket.get(profile.id, "")
        if not value and carrier == self.storage.tuning.carrier_mode:
            legacy = settings.get("pattern_profile_sni_pins", {})
            if isinstance(legacy, dict):
                value = legacy.get(profile.id, "")
        scoped_globals = settings.get("pattern_global_sni_pin_by_carrier", {})
        if not value and isinstance(scoped_globals, dict):
            value = scoped_globals.get(carrier, "")
        if not value and carrier == self.storage.tuning.carrier_mode:
            value = settings.get("pattern_global_sni_pin", "")
        return str(value or profile.spoof_fake_sni
                   or self.storage.tuning.pattern_fake_sni or profile.sni).strip()

    def _profile_route_label(self, profile, carrier=None, include_ping=True):
        if profile is None:
            return ""
        fake_sni = self._effective_profile_fake_sni(profile, carrier)
        label = (
            "Reality SNI"
            if profile.route_mode == "reality-direct" else "Fake SNI"
        )
        target = (
            profile.target_label
            if include_ping else
            f"{profile.address}:{profile.port} / {profile.sni}"
        )
        return f"{target}\n{label} {fake_sni}"

    def _attach_profile_row(self, widget, item, profile, text, icon):
        active = profile.id == self.storage.selected_id
        row = ProfileListRow(
            profile.id, text, icon,
            self.tr("فعال است", "Active") if active
            else self.tr("فعال‌سازی", "Activate"),
            active=active,
            ping_text=(
                f"{profile.last_ping_ms:.0f} ms"
                if profile.last_ping_ok else "—"
            ),
            ping_state=(
                "fast" if profile.last_ping_ok
                and profile.last_ping_ms <= 180 else
                "medium" if profile.last_ping_ok
                and profile.last_ping_ms <= 500 else
                "slow" if profile.last_ping_ok else "unknown"
            ),
        )
        row.setToolTip(item.toolTip() or text)
        row.activate_button.setToolTip(self.tr(
            "فعال‌کردن این کانفیگ",
            "Activate this configuration",
        ))
        row.edit_button.setToolTip(self.tr("ویرایش کانفیگ", "Edit config"))
        row.delete_button.setToolTip(self.tr("حذف کانفیگ", "Delete config"))
        row.activated.connect(
            lambda profile_id, modifiers, target=widget, target_item=item:
            self._profile_row_activated(
                target, target_item, profile_id, modifiers
            )
        )
        row.activateRequested.connect(self._activate_profile_by_id)
        row.editRequested.connect(self._edit_profile_by_id)
        row.deleteRequested.connect(
            lambda profile_id: self.delete_profile({profile_id})
        )
        widget.setItemWidget(item, row)
        item.setText("")
        item.setIcon(QIcon())

    def _profile_row_activated(
            self, widget, item, profile_id, modifiers):
        widget.setFocus()
        if modifiers & Qt.ControlModifier:
            item.setSelected(not item.isSelected())
            self._update_config_actions()
            return
        widget.clearSelection()
        widget.setCurrentItem(item)
        self._update_config_actions()

    def _activate_profile_by_id(self, profile_id):
        wanted = str(profile_id)
        profile = next(
            (value for value in self.storage.profiles
             if str(value.id) == wanted),
            None,
        )
        if profile is None:
            return
        worker = getattr(self, "_connect_thread", None)
        worker_active = bool(
            worker is not None
            and callable(getattr(worker, "is_alive", None))
            and worker.is_alive()
        )
        switch_active = bool(
            self.connecting or self.engine.running
            or self._profile_switch_waiting or worker_active
        )
        self.storage.selected_id = profile.id
        if profile.origin in DIRECT_PROFILE_ORIGINS:
            self._forced_profile_id = profile.id
            MainWindow._remember_direct_profile(self, profile)
        if switch_active:
            self._queue_profile_switch(profile.id)
        route_tabs = getattr(self, "route_source_tabs", None)
        route_index = None
        if profile.origin == USER_CONFIG_ORIGIN:
            self.storage.settings["route_source"] = "user-config"
            route_index = 1
        elif profile.origin not in DIRECT_PROFILE_ORIGINS:
            self.storage.settings["route_source"] = "suggested"
            route_index = 0
        if route_tabs is not None and route_index is not None:
            blocked = route_tabs.blockSignals(True)
            route_tabs.setCurrentIndex(route_index)
            route_tabs.blockSignals(blocked)
        save_settings = getattr(self.storage, "save_settings", None)
        if callable(save_settings):
            save_settings()
        widget = (
            self.manual_list if profile.origin == "user"
            else self.user_config_list
            if profile.origin == USER_CONFIG_ORIGIN
            else self.suggested_list
        )
        self.profile_tabs.setCurrentIndex(self._profile_tab_index(widget))
        self.refresh_profiles()
        for row in range(widget.count()):
            item = widget.item(row)
            if str(item.data(Qt.UserRole) or "") == wanted:
                widget.clearSelection()
                widget.setCurrentItem(item)
                break

    def _edit_profile_by_id(self, profile_id):
        profile = next(
            (value for value in self.storage.profiles
             if value.id == str(profile_id)),
            None,
        )
        if profile is None:
            return
        self.edit_profile(profile.id)

    def refresh_profiles(self):
        self.manual_list.clear(); self.user_config_list.clear(); self.suggested_list.clear()
        self._refresh_country_selector()
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

            return (value.get("upload_ok") is not True,
                    -float(value.get("score", 0)),
                    float(value.get("startup_ms", 999999)))
        ranked_ids = [profile.id for profile in sorted(
            (p for p in self.storage.profiles if p.origin not in DIRECT_PROFILE_ORIGINS
             and benchmarks.get(p.id, {}).get("ok")
             and benchmarks.get(p.id, {}).get("engine") == "patterniha-wrong-seq-v1"),
            key=benchmark_rank)]
        def profile_sort_key(profile):
            if profile.origin == "user":
                group, source = 0, "manual"
            elif profile.origin == USER_CONFIG_ORIGIN:
                group, source = 1, "user-config"
            else:
                group, source = 2, "suggested"
            code = str(
                profile.observed_country_code
                or profile.country_code or "ZZ"
            ).upper()
            _flag, english, _persian = self._country_metadata(code)
            country = f"{english.casefold()}:{code}"
            ping = (
                profile.last_ping_ms
                if profile.last_ping_ok else 999999
            )
            if MainWindow._profile_sort_mode(self, source) == "ping":
                return (
                    group, not profile.last_ping_ok, ping,
                    country, profile.name.casefold(),
                )
            return (
                group, country, not profile.last_ping_ok,
                ping, profile.name.casefold(),
            )
        profiles = sorted(self.storage.profiles, key=profile_sort_key)
        user_country_counts = {}
        for profile in profiles:
            if (
                    profile.origin == USER_CONFIG_ORIGIN
                    and MainWindow._profile_sort_mode(
                        self, "user-config") == "country"):
                code = str(profile.country_code or "XX").upper()
                user_country_counts[code] = user_country_counts.get(code, 0) + 1
        current_user_country = None
        for profile in profiles:
            if (
                    profile.origin == USER_CONFIG_ORIGIN
                    and MainWindow._profile_sort_mode(
                        self, "user-config") == "country"):
                code = str(profile.country_code or "XX").upper()
                if code != current_user_country:
                    current_user_country = code
                    _flag, english, persian = self._country_metadata(code)
                    title = english if self.language == "en" else persian
                    count = user_country_counts.get(code, 0)
                    header = QListWidgetItem(self.tr(
                        f"{title}  ·  {count} کانفیگ",
                        f"{title}  ·  {count} configs",
                    ))
                    header.setData(Qt.UserRole, None)
                    header.setData(Qt.UserRole + 1, "country-header")
                    header.setFlags(Qt.NoItemFlags)
                    header.setIcon(country_flag_icon(code, 30, 20))
                    header.setForeground(QColor("#79efe7"))
                    header.setBackground(QColor(8, 47, 66, 185))
                    font = header.font(); font.setBold(True); header.setFont(font)
                    header.setSizeHint(QSize(0, 32))
                    self.user_config_list.addItem(header)
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
            endpoint = f"\u2066{self._profile_route_label(profile, carrier)}\u2069"
            item_text = f"{recommendation}{profile.name}\n{endpoint}"
            item = QListWidgetItem(item_text); item.setData(Qt.UserRole, profile.id)
            item.setSizeHint(QSize(
                0,
                70 if recommendation else (
                    50 if profile.origin != "user" else 58
                ),
            ))
            item_icon = (
                country_flag_icon(profile.country_code, 30, 20)
                if profile.route_is_verified else
                cyber_icon("file-cog" if profile.origin == "user" else "server", "#23f5e0" if profile.id == self.storage.selected_id else "#6f91b5", 20)
            )
            item.setIcon(item_icon)
            if recommendation:
                if carrier == "mci":
                    quality_tip = (f"download {float(benchmark.get('download_mbps', 0) or 0):.2f} Mbps · "
                                   f"first-byte {float(benchmark.get('download_first_byte_ms', 0) or 0):.0f} ms · "
                                   f"state {benchmark.get('download_state', 'not tested')}")
                else:
                    quality_tip = f"upload {benchmark.get('upload_state', 'not tested')}"
                startup_label = "Page" if carrier == "mci" else "YouTube"
                item.setToolTip(f"Patterniha real test · Fake SNI {benchmark.get('fake_sni', '—')} · {startup_label} {float(benchmark.get('startup_ms', 0)):.0f} ms · {quality_tip} · strategy={benchmark.get('strategy', 'wrong_seq')}")
            target = (
                self.manual_list if profile.origin == "user"
                else self.user_config_list if profile.origin == USER_CONFIG_ORIGIN
                else self.suggested_list
            ); target.addItem(item)
            attach_row = getattr(self, "_attach_profile_row", None)
            if callable(attach_row):
                attach_row(target, item, profile, item_text, item_icon)
            if profile.id == self.storage.selected_id: target.setCurrentItem(item)
        self.config_count_label.setText(self.tr(f"{len(self.storage.profiles)} کانفیگ", f"{len(self.storage.profiles)} configs"))
        selected = self.storage.selected(); self.active_profile.setText(selected.name if selected else self.tr("کانفیگی انتخاب نشده", "No config selected")); self.route_card.set_secondary(self._profile_route_label(selected, carrier))
        self._update_config_actions()

    def _maker_repo_url_changed(self, *_args):
        current = self.maker_repo_url.text().strip()
        self.maker_repo_btn.setEnabled(
            bool(current)
            and not self._maker_import_in_progress
            and current != self._maker_last_loaded_url
        )
        self._update_maker_guide()

    def _maker_editor_changed(self):
        self._sync_maker_editor_direction()
        self._update_maker_guide()

    def _set_maker_guide_button(self, button):
        if self._maker_guide_button is button:
            return
        if self._maker_guide_animation is not None:
            self._maker_guide_animation.stop()
        if self._maker_guide_button is not None:
            self._maker_guide_button.setProperty("guided", False)
            self._maker_guide_button.setGraphicsEffect(None)
            _restyle(self._maker_guide_button)
        self._maker_guide_button = button
        self._maker_guide_effect = None
        self._maker_guide_animation = None
        if button is None:
            return
        button.setProperty("guided", True)
        _restyle(button)
        if not _animations_enabled():
            return
        effect = QGraphicsDropShadowEffect(button)
        effect.setOffset(0, 0)
        effect.setColor(QColor(35, 245, 224, 205))
        effect.setBlurRadius(9)
        button.setGraphicsEffect(effect)
        animation = QPropertyAnimation(effect, b"blurRadius", self)
        animation.setDuration(1450)
        animation.setStartValue(9.0)
        animation.setKeyValueAt(0.48, 30.0)
        animation.setEndValue(9.0)
        animation.setEasingCurve(QEasingCurve.InOutSine)
        animation.setLoopCount(-1)
        self._maker_guide_effect = effect
        self._maker_guide_animation = animation
        animation.start()

    def _update_maker_guide(self):
        if (
                not hasattr(self, "maker_repo_btn")
                or self._maker_running
                or self._maker_import_in_progress):
            self._set_maker_guide_button(None)
            return
        editor_text = self.maker_source_editor.toPlainText().strip()
        editor_dirty = (
            bool(editor_text)
            and editor_text != self._maker_last_converted_editor_text
        )
        if editor_dirty and self.maker_text_btn.isEnabled():
            self._set_maker_guide_button(self.maker_text_btn)
            return
        if (
                self.maker_repo_btn.isEnabled()
                and (
                    not self._maker_profiles
                    or bool(self._maker_last_loaded_url)
                )):
            self._set_maker_guide_button(self.maker_repo_btn)
            return
        statuses = self.maker_model.status_counts()
        if int(statuses.get("healthy", 0)) > 0:
            self._set_maker_guide_button(self.maker_add_all_btn)
            return
        if self._maker_profiles and self.maker_start_btn.isEnabled():
            self._set_maker_guide_button(self.maker_start_btn)
            return
        self._set_maker_guide_button(None)

    def _maker_import_worker(
            self, loader, source, replace=False, editor_text=""):
        self._maker_import_generation += 1
        generation = self._maker_import_generation
        self._maker_import_in_progress = True
        self._maker_repo_url_changed()
        self.maker_import_badge.setText(self.tr("در حال پردازش…", "Processing…"))

        def work():
            try:
                maker = SniConfigMaker(
                    fake_sni=self.storage.tuning.pattern_fake_sni,
                )
                imported = loader(maker)
                converted = maker.convert_many(imported.profiles)
                self.bridge.maker_imported.emit(
                    {"imported": imported, "converted": converted},
                    {
                        "source": source,
                        "replace": bool(replace),
                        "editor_text": str(editor_text or ""),
                    },
                    generation,
                )
            except Exception as exc:
                self.bridge.maker_imported.emit(
                    {"error": str(exc)},
                    {
                        "source": source,
                        "replace": bool(replace),
                        "editor_text": str(editor_text or ""),
                    },
                    generation,
                )

        threading.Thread(target=work, name="sni-maker-import", daemon=True).start()

    def _maker_import_text(self, text, source="text"):
        payload = str(text or "").strip()
        if not payload:
            self.show_toast(self.tr("متنی برای تبدیل وجود ندارد", "No configuration text to convert"), "warning")
            return
        self._maker_import_worker(
            lambda maker: maker.import_text(payload, source=source),
            source,
            editor_text=payload if source == "editor" else "",
        )

    def _maker_import_files(self):
        paths, _filter = QFileDialog.getOpenFileNames(
            self,
            self.tr("انتخاب فایل کانفیگ", "Select configuration files"),
            "",
            "Config files (*.txt *.conf *.json *.yaml *.yml);;All files (*.*)",
        )
        if not paths:
            return

        try:
            chunks = []
            for value in paths:
                path = __import__("pathlib").Path(value)
                if path.stat().st_size > 64 * 1024 * 1024:
                    raise ValueError(f"File is too large: {path.name}")
                chunks.append(path.read_text(encoding="utf-8-sig", errors="replace"))
            self.maker_source_editor.append_payload("\n".join(chunks), paths)
            self.show_toast(
                self.tr(
                    "فایل آماده است؛ اکنون تبدیل را بزنید.",
                    "File ready; press Convert next.",
                ),
                "success",
            )
            self._update_maker_guide()
        except (OSError, ValueError) as exc:
            self.show_toast(str(exc), "danger")

    def _maker_fetch_repository(self):
        url = self.maker_repo_url.text().strip() or DEFAULT_SNI_MAKER_URL
        self.maker_repo_btn.setEnabled(False)
        self._maker_import_worker(
            lambda maker: maker.import_url(url, timeout=20.0),
            url,
            replace=True,
        )

    def _maker_import_finished(self, payload, meta, generation):
        if generation != self._maker_import_generation:
            return
        self._maker_import_in_progress = False
        error = str(payload.get("error", "") if isinstance(payload, dict) else "")
        if error:
            self.maker_import_badge.setText(self.tr("خطا در دریافت یا پردازش", "Import failed"))
            self.show_toast(error, "danger")
            self._maker_repo_url_changed()
            return
        imported = payload.get("imported")
        converted = payload.get("converted")
        if not isinstance(imported, SniImportResult) or converted is None:
            self._maker_repo_url_changed()
            return
        loaded_source = str(meta.get("source", "") or "").strip()
        if bool(meta.get("replace", False)):
            self._maker_last_loaded_url = loaded_source
        editor_text = str(meta.get("editor_text", "") or "")
        if editor_text:
            self._maker_last_converted_editor_text = editor_text.strip()
        if bool(meta.get("replace", False)):
            self._maker.clear()
            self._maker_profiles.clear()
            self._maker_base_names.clear()
            self._maker_country_labels.clear()
            self._maker_last_country_summary = None
            self.maker_model.clear()
            self.maker_country_rail.set_country_counts(
                {},
                all_label=self.tr("همه کشورها", "All countries"),
            )
            self.maker_progress.setMaximum(100)
            self.maker_progress.setValue(0)
            self.maker_progress.set_status(
                self.tr("آماده تست", "Tester ready"), "idle"
            )
        if imported.input_format == "base64":
            self.show_toast(
                f"Base64 subscription decoded: {imported.detected_count} configs found.",
                "success",
            )
        elif imported.input_format == "direct":
            self.show_toast(
                f"Direct configs detected: {imported.detected_count} configs found.",
                "success",
            )
        rows = []
        added_profiles = []
        duplicate_existing = 0
        for result in converted.results:
            profile = result.profile
            if profile is None:
                continue
            key = config_signature(profile)
            if key in self._maker_profiles:
                duplicate_existing += 1
                continue
            if result.direct:
                profile.origin = USER_CONFIG_ORIGIN
                profile.spoof_fake_sni = ""
            else:
                profile.address = VERIFIED_SPOOF_EDGE
                profile.config_host = "127.0.0.1"
                profile.config_port = 40443
                profile.origin = USER_CONFIG_ORIGIN
                profile.spoof_fake_sni = (
                    profile.spoof_fake_sni
                    or self.storage.tuning.pattern_fake_sni
                )
            profile.verified_spoof = False
            profile.verified_route = False
            self._maker_profiles[key] = profile
            base_name = profile.name
            if base_name.endswith(" · SNI"):
                base_name = base_name[:-6].rstrip()
            self._maker_base_names[key] = base_name
            added_profiles.append(profile)
            rows.append({
                "key": key,
                "uri": profile.source_uri,
                "source_uri": result.source_profile.source_uri,
                "status": "ready" if (
                    result.already_sni or result.direct
                ) else "converted",
                "country_code": "XX",
                "label": profile.name,
            })
        self._maker.add_profiles(added_profiles, source=str(meta.get("source", "")))
        self.maker_model.append_batch(rows, deduplicate=True)
        duplicate_count = imported.duplicate_count + duplicate_existing
        details = [
            self.tr(f"{len(added_profiles)} آماده تست", f"{len(added_profiles)} testable"),
            self.tr(f"{duplicate_count} تکراری", f"{duplicate_count} duplicates"),
        ]
        if imported.unsupported_count:
            protocols = ", ".join(f"{name}:{count}" for name, count in imported.unsupported_by_protocol.items())
            details.append(self.tr(
                f"{imported.unsupported_count} ناسازگار ({ltr_isolate(protocols)})",
                f"{imported.unsupported_count} unsupported ({protocols})",
            ))
        if converted.incompatible_count:
            details.append(self.tr(
                f"{converted.incompatible_count} ناسازگار با متد",
                f"{converted.incompatible_count} incompatible with SNI mode",
            ))
        if imported.invalid_count:
            details.append(self.tr(
                f"{imported.invalid_count} نامعتبر",
                f"{imported.invalid_count} invalid",
            ))
        issue_count = (
            imported.unsupported_count + converted.incompatible_count
            + imported.invalid_count
        )
        compact = [self.tr(
            f"{len(added_profiles)} آماده",
            f"{len(added_profiles)} ready",
        )]
        if issue_count:
            compact.append(self.tr(f"{issue_count} مشکل", f"{issue_count} issues"))
        elif duplicate_count:
            compact.append(self.tr(
                f"{duplicate_count} تکراری",
                f"{duplicate_count} duplicates",
            ))
        self.maker_import_badge.setText(" · ".join(compact))
        self.maker_import_badge.setToolTip("  •  ".join(details))
        source = str(meta.get("source", ""))
        if source.startswith("http"):
            self.storage.settings["sni_maker_url"] = source
            self.storage.save_settings()
        self.maker_progress.setFormat(self.tr(
            f"{len(self._maker_profiles)} کانفیگ آماده تست زنده",
            f"{len(self._maker_profiles)} configs ready for live testing",
        ))
        self._set_activity(
            "کانفیگ‌ها تبدیل و برای تست آماده شدند.",
            "Configurations converted and queued for testing.",
            "success", False,
        )
        self._maker_repo_url_changed()
        self._update_maker_guide()
    def _maker_start_test(self):
        if self._maker_running:
            return
        if self.engine.running or self.connecting:
            self.show_toast(self.tr(
                "برای تست همزمان کانفیگ‌ها ابتدا اتصال فعلی را قطع کنید",
                "Disconnect the active tunnel before batch testing",
            ), "warning")
            return
        profiles = list(self._maker_profiles.values())
        if not profiles:
            self.show_toast(self.tr("ابتدا کانفیگ اضافه کنید", "Add configurations first"), "warning")
            return
        self._maker_generation += 1
        generation = self._maker_generation
        self._maker_running = True
        self._update_maker_guide()
        self._maker_cancel_event = threading.Event()
        self._maker_tester = SniBatchTester(self.bridge.log.emit)
        self.maker_start_btn.setEnabled(False); self.maker_stop_btn.setEnabled(True)
        for widget in (
                self.maker_clear_btn,
                self.maker_repo_btn, self.maker_repo_reset_btn,
                self.maker_file_btn, self.maker_clip_btn, self.maker_text_btn,
                self.maker_repo_url, self.maker_source_editor):
            widget.setEnabled(False)
        self.maker_model.update_batch([
            {"key": key, "status": "testing", "error": ""}
            for key in self._maker_profiles
        ])
        self.maker_progress.setMaximum(len(profiles)); self.maker_progress.setValue(0)
        self.maker_progress.set_status(self.tr("تست زنده مسیرها", "Live route testing"), "running")
        self.maker_progress.setFormat(self.tr(
            f"۰ از {len(profiles)} کانفیگ",
            f"0 of {len(profiles)} configs",
        ))
        workers = self.maker_threads.value()
        timeout = float(self.maker_timeout.value())
        tuning = self.storage.tuning
        carrier = tuning.carrier_mode
        strategy = str(self.storage.settings.get(
            f"working_strategy_{carrier}",
            "tls_sni_records" if carrier == "mci" else "wrong_seq",
        ) or "").strip().lower()
        tester = self._maker_tester
        cancel = self._maker_cancel_event

        def progress(batch, done, total):
            self.bridge.maker_batch.emit(batch, done, total, generation)

        def work():
            try:
                results = tester.run(
                    profiles, tuning, cancel,
                    workers=workers, timeout=timeout, strategy=strategy,
                    progress=progress,
                )
                self.bridge.maker_done.emit(
                    {"count": len(results), "cancelled": cancel.is_set()},
                    generation,
                )
            except Exception as exc:
                self.bridge.maker_failed.emit(str(exc), generation)

        threading.Thread(target=work, name="sni-maker-live", daemon=True).start()

    def _maker_test_batch(self, batch, done, total, generation):
        if generation != self._maker_generation:
            return
        updates = []
        now = time.time()
        for result in batch:
            if not isinstance(result, LiveConfigResult):
                continue
            key = config_signature(result.profile)
            profile = self._maker_profiles.get(key)
            if profile is None:
                continue
            verified_code = normalize_country_code(result.country_code)
            if result.ok and verified_code != "XX":
                profile.last_ping_ok = True
                profile.last_ping_ms = float(result.ping_ms)
                profile.country_latency_ms = int(round(result.ping_ms))
                profile.country_code = verified_code
                profile.observed_country_code = verified_code
                profile.observed_country_name = result.country
                profile.observed_exit_ip = result.exit_ip
                profile.country_verified_at = now
                profile.country_source = result.source
                direct = profile.route_mode == "reality-direct"
                profile.verified_route = direct
                profile.verified_spoof = not direct
                profile.origin = (
                    USER_CONFIG_ORIGIN
                )
                profile.spoof_fake_sni = (
                    "" if direct else (
                        profile.spoof_fake_sni
                        or self.storage.tuning.pattern_fake_sni
                    )
                )
                country = result.country or verified_code
                base_name = self._maker_base_names.get(key, profile.name)
                route_label = "Reality" if direct else "SNI"
                profile.name = f"{country} · {base_name} · {route_label}"
                self._maker_country_labels[verified_code] = country
                updates.append({
                    "key": key,
                    "status": "healthy",
                    "country_code": verified_code,
                    "ping_ms": result.ping_ms,
                    "label": profile.name,
                    "error": f"{result.exit_ip} · {result.source}",
                })
            else:
                profile.last_ping_ok = False
                profile.last_ping_ms = 0.0
                profile.verified_spoof = False
                profile.verified_route = False
                profile.country_code = ""
                profile.observed_country_code = ""
                profile.observed_country_name = ""
                profile.observed_exit_ip = ""
                profile.country_verified_at = 0.0
                profile.country_source = ""
                route_label = (
                    "Reality"
                    if profile.route_mode == "reality-direct" else "SNI"
                )
                profile.name = (
                    f"{self._maker_base_names.get(key, profile.name)}"
                    f" · {route_label}"
                )
                updates.append({
                    "key": key,
                    "status": "failed",
                    "country_code": "XX",
                    "ping_ms": None,
                    "error": result.error or "Live route test failed",
                })
        self.maker_model.update_batch(updates)
        self.maker_progress.setValue(done)
        self.maker_progress.setFormat(self.tr(
            f"{done} از {total} کانفیگ تست شد",
            f"{done} of {total} configs tested",
        ))

    def _maker_finish_test_ui(self):
        self._maker_running = False
        self.maker_start_btn.setEnabled(True); self.maker_stop_btn.setEnabled(False)
        self.maker_source_card.setVisible(True)
        for widget in (
                self.maker_clear_btn,
                self.maker_repo_btn, self.maker_repo_reset_btn,
                self.maker_file_btn, self.maker_clip_btn, self.maker_text_btn,
                self.maker_repo_url, self.maker_source_editor):
            widget.setEnabled(True)
        self._maker_tester = None
        self._maker_repo_url_changed()
        self._update_maker_guide()

    def _maker_test_done(self, payload, generation):
        if generation != self._maker_generation:
            return
        cancelled = bool(payload.get("cancelled", False)) if isinstance(payload, dict) else False
        if cancelled:
            updates = []
            for key, profile in self._maker_profiles.items():
                row = self.maker_model.row_for_key(key)
                result = self.maker_model.result_at(row)
                if result is None or result.status != "testing":
                    continue
                updates.append({
                    "key": key,
                    "status": "healthy" if profile.route_is_verified else "ready",
                    "country_code": profile.observed_country_code or "XX",
                    "ping_ms": profile.last_ping_ms if profile.last_ping_ok else None,
                    "error": "",
                })
            self.maker_model.update_batch(updates)
        self._maker_finish_test_ui()
        healthy = len(self.maker_model.healthy_results())
        total = self.maker_model.rowCount()
        self.maker_progress.set_status(
            self.tr("تست متوقف شد", "Testing stopped") if cancelled else
            self.tr("تست زنده کامل شد", "Live testing completed"),
            "warning" if cancelled else "success",
        )
        self.maker_progress.setFormat(self.tr(
            f"{healthy} کانفیگ سالم در {len(self._maker_country_labels)} کشور",
            f"{healthy} healthy configs across {len(self._maker_country_labels)} countries",
        ))
        self._set_activity(
            f"تست کانفیگ‌ها پایان یافت؛ {healthy} کانفیگ سالم است.",
            f"Config testing finished; {healthy} configs are healthy.",
            "warning" if cancelled else "success", False,
        )

    def _maker_failed(self, message, generation):
        if generation != self._maker_generation:
            return
        self._maker_finish_test_ui()
        self.maker_model.update_batch([
            {"key": key, "status": "ready", "error": str(message)}
            for key in self._maker_profiles
            if self.maker_model.result_at(self.maker_model.row_for_key(key))
            and self.maker_model.result_at(self.maker_model.row_for_key(key)).status == "testing"
        ])
        self.maker_progress.set_status(self.tr("خطای تست زنده", "Live test error"), "warning")
        self.maker_progress.setFormat(str(message))
        self.show_toast(str(message), "danger")

    def _maker_stop_test(self):
        if not self._maker_running:
            return
        self._maker_cancel_event.set()
        self.maker_stop_btn.setEnabled(False)
        self.maker_progress.set_status(self.tr("در حال توقف…", "Stopping…"), "warning")
        tester = self._maker_tester
        if tester is not None:
            threading.Thread(target=tester.stop, name="sni-maker-stop", daemon=True).start()

    def _maker_clear(self):
        self._maker_stop_test()
        self._maker_generation += 1
        self._maker_import_generation += 1
        self._maker_finish_test_ui()
        self._maker_import_in_progress = False
        self._maker_last_loaded_url = ""
        self._maker_last_converted_editor_text = ""
        self._maker.clear()
        self._maker_profiles.clear()
        self._maker_base_names.clear()
        self._maker_country_labels.clear()
        self._maker_last_country_summary = None
        self.maker_model.clear()
        self.maker_source_editor.clear()
        self.maker_country_rail.set_country_counts({}, all_label=self.tr("همه کشورها", "All countries"))
        self.maker_import_badge.setText(self.tr("آماده دریافت", "Ready"))
        self.maker_import_badge.setToolTip("")
        self.maker_progress.setMaximum(100); self.maker_progress.setValue(0)
        self.maker_progress.set_status(self.tr("آماده تست", "Tester ready"), "idle")
        self.maker_progress.setFormat(self.tr("منتظر کانفیگ", "Waiting for configs"))
        self._maker_repo_url_changed()
        self._update_maker_guide()

    def _maker_summary_changed(self, summary):
        total = int(summary.get("total", 0))
        checked = int(summary.get(
            "checked", len(self.maker_model.checked_results())
        ))
        healthy = int(summary.get("statuses", {}).get("healthy", 0))
        countries = {
            code: values
            for code, values in summary.get("countries", {}).items()
            if code != "XX" and (
                values.get("healthy", 0) or values.get("testing", 0)
            )
        }
        if countries != self._maker_last_country_summary:
            selected = self.maker_country_rail.selected_country()
            labels = {}
            for code in countries:
                known = COUNTRIES.get(code)
                if known:
                    labels[code] = known[1] if self.language == "en" else known[2]
                else:
                    labels[code] = self._maker_country_labels.get(code, code)
            self.maker_country_rail.set_country_counts(
                countries,
                labels=labels,
                selected=selected,
                all_label=self.tr("همه کشورها", "All countries"),
            )
            self._maker_last_country_summary = {
                code: dict(values) for code, values in countries.items()
            }
        self.maker_summary_badge.setText(self.tr(
            f"{healthy} سالم از {total}",
            f"{healthy} healthy of {total}",
        ))
        self.maker_select_all_checkbox.setEnabled(total > 0)
        self.maker_select_all_checkbox.setChecked(total > 0 and checked == total)
        enabled = healthy > 0
        for button in (
                self.maker_add_selected_btn, self.maker_add_country_btn,
                self.maker_add_all_btn, self.maker_copy_btn,
                self.maker_export_btn):
            button.setEnabled(enabled)
        if not self._maker_running:
            self.maker_start_btn.setEnabled(bool(self._maker_profiles))
        self._update_maker_guide()

    def _position_maker_select_all(self):
        if not hasattr(self, "maker_select_all_checkbox"):
            return
        header = self.maker_table.horizontalHeader()
        section_x = header.sectionViewportPosition(MakerColumns.MARK)
        section_width = header.sectionSize(MakerColumns.MARK)
        box = self.maker_select_all_checkbox
        box.move(
            section_x + max(0, (section_width - box.width()) // 2),
            max(0, (header.height() - box.height()) // 2),
        )
        box.raise_()

    def _maker_add_results(self, mode):
        if mode == "selected":
            results = [
                result for result in self.maker_model.checked_results()
                if result.status == "healthy"
            ]
        elif mode == "country":
            code = self.maker_country_rail.selected_country()
            results = self.maker_model.healthy_results("" if code == "*" else code)
        else:
            results = self.maker_model.healthy_results()
        existing = {
            config_signature(profile)
            for profile in self.storage.profiles
            if profile.source_uri and profile.origin in USER_CONFIG_ORIGINS
        }
        added = []
        duplicate_count = 0
        for result in results:
            profile = self._maker_profiles.get(result.key)
            if profile is None or not profile.route_is_verified:
                continue
            signature = config_signature(profile)
            if signature in existing:
                duplicate_count += 1
                continue
            existing.add(signature)
            value = replace(profile)
            value.id = str(uuid.uuid4())
            value.origin = USER_CONFIG_ORIGIN
            added.append(value)
        if not added:
            if results and duplicate_count == len(results):
                self.show_toast(self.tr(
                    "کانفیگ‌های سالم انتخاب‌شده از قبل در User Config هستند",
                    "Selected healthy configs are already in User Config",
                ), "warning")
                return
            self.show_toast(self.tr(
                "کانفیگ سالم جدیدی برای افزودن وجود ندارد",
                "No new healthy configs to add",
            ), "warning")
            return
        connection_active = bool(
            self.connecting or self.engine.running or self._profile_switch_waiting
        )
        self.storage.profiles.extend(added)
        self.storage.settings["route_source"] = "user-config"
        self.route_source_tabs.setCurrentIndex(1)
        if not connection_active and len(added) == 1:
            self.storage.selected_id = added[0].id
            self._forced_profile_id = added[0].id
            self._remember_direct_profile(added[0])
        known_codes = {
            str(code).upper()
            for code in self.storage.settings.get("known_country_codes", [])
            if len(str(code)) == 2
        }
        known_codes.update(
            profile.country_code.upper()
            for profile in added if len(profile.country_code) == 2
        )
        self.storage.settings["known_country_codes"] = sorted(known_codes)
        self.storage.save_profiles()
        self.storage.save_settings()
        self.refresh_profiles()
        self.profile_tabs.setCurrentIndex(
            self._profile_tab_index(self.user_config_list)
        )
        for row in range(self.user_config_list.count()):
            item = self.user_config_list.item(row)
            if item.data(Qt.UserRole) == added[0].id:
                self.user_config_list.setCurrentItem(item)
                break
        self.show_toast(self.tr(
            f"{len(added)} کانفیگ سالم به User Config افزوده شد",
            f"{len(added)} healthy configs added to User Config",
        ), "success")
        self._set_activity(
            f"{len(added)} کانفیگ سازنده SNI در User Config ذخیره شد.",
            f"{len(added)} SNI Maker configs saved in User Config.",
            "success", False,
        )

    def _maker_copy_marked(self):
        results = [
            result for result in self.maker_model.checked_results()
            if result.status == "healthy"
        ]
        if not results:
            self.show_toast(self.tr("کانفیگی علامت نخورده است", "No healthy configs are marked"), "warning")
            return
        QApplication.clipboard().setText("\n".join(result.uri for result in results))
        self.show_toast(self.tr("کانفیگ‌ها کپی شدند", "Configurations copied"), "success")

    def _maker_export_healthy(self):
        results = self.maker_model.healthy_results()
        if not results:
            self.show_toast(self.tr("هنوز کانفیگ سالمی وجود ندارد", "No healthy configs yet"), "warning")
            return
        path, _filter = QFileDialog.getSaveFileName(
            self,
            self.tr("ذخیره کانفیگ‌های سالم", "Export healthy configurations"),
            str(DATA_DIR / "sni-maker-healthy.txt"),
            "Text files (*.txt)",
        )
        if not path:
            return
        __import__("pathlib").Path(path).write_text(
            "\n".join(result.uri for result in results) + "\n",
            encoding="utf-8",
        )
        self.show_toast(self.tr("فایل خروجی ذخیره شد", "Export file saved"), "success")

    def selected_profile_items(self):
        widget = self._current_profile_list()
        if (
                widget is not self.user_config_list
                and widget is not self.manual_list
                and widget is not self.suggested_list):
            return []
        return [
            item for item in widget.selectedItems()
            if item.data(Qt.UserRole)
        ]

    def selected_profile_item(self):
        items = self.selected_profile_items()
        if not items:
            return None
        widget = self._current_profile_list()
        current = widget.currentItem()
        return current if current in items else items[0]

    def select_profile_from_list(self):
        item = self.selected_profile_item()
        if item:
            self._profile_clicked(item)
            self.refresh_profiles()

    def _profile_clicked(self, item):
        profile_id = item.data(Qt.UserRole)
        if not profile_id:
            return
        self.storage.selected_id = profile_id
        selected = self.storage.selected()
        if selected:
            MainWindow._remember_direct_profile(self, selected)
            if selected.origin in DIRECT_PROFILE_ORIGINS:
                self._forced_profile_id = selected.id
            route_tabs = getattr(self, "route_source_tabs", None)
            if selected.origin == USER_CONFIG_ORIGIN:
                self.storage.settings["route_source"] = "user-config"
                if route_tabs is not None:
                    route_tabs.setCurrentIndex(1)
            elif selected.origin not in DIRECT_PROFILE_ORIGINS:
                self.storage.settings["route_source"] = "suggested"
                if route_tabs is not None:
                    route_tabs.setCurrentIndex(0)
            save_settings = getattr(self.storage, "save_settings", None)
            if callable(save_settings):
                save_settings()
            self.active_profile.setText(selected.name); self.route_card.set_secondary(self._profile_route_label(selected))
        self._update_config_actions()
        worker = getattr(self, "_connect_thread", None)
        worker_active = bool(
            worker is not None
            and callable(getattr(worker, "is_alive", None))
            and worker.is_alive()
        )
        if selected and (
                self.connecting or self.engine.running
                or self._profile_switch_waiting or worker_active):
            self._queue_profile_switch(profile_id)

    def add_profile(self):
        dialog = ProfileDialog(self, language=self.language,
                               fake_sni=self.storage.tuning.pattern_fake_sni)
        if dialog.exec():
            profile = dialog.result_profile()
            if not profile: self.show_toast(self.tr("لینک VLESS یا Trojan معتبر نیست", "The VLESS or Trojan link is invalid"), "danger"); return
            self.storage.profiles.append(profile); self.storage.selected_id = profile.id; self._remember_direct_profile(profile); self.storage.save_profiles(); self.refresh_profiles(); self._set_activity("کانفیگ ذخیره شد.", "Config saved.", "success", False)

    def edit_profile(self, profile_id=None):
        item = self.selected_profile_item()
        if profile_id is None and not item:
            return
        wanted_id = str(profile_id) if profile_id is not None else item.data(Qt.UserRole)
        profile = next((x for x in self.storage.profiles if x.id == wanted_id), None)
        if not profile: return
        dialog = ProfileDialog(self, profile, self.language,
                               self._effective_profile_fake_sni(profile))
        if dialog.exec() and dialog.result_profile(): self.storage.selected_id = profile.id; self.storage.save_profiles(); self.refresh_profiles(); self._set_activity("تغییرات کانفیگ ذخیره شد.", "Config changes saved.", "success", False)

    def delete_profile(self, profile_ids=None):
        if profile_ids is None or isinstance(profile_ids, bool):
            profile_ids = {
                item.data(Qt.UserRole)
                for item in self.selected_profile_items()
                if item.data(Qt.UserRole)
            }
        else:
            profile_ids = {str(profile_id) for profile_id in profile_ids}
        count = len(profile_ids)
        if not count:
            return
        if QMessageBox.question(
                self,
                self.tr("حذف کانفیگ‌ها", "Delete Configs"),
                self.tr(
                    f"{count} کانفیگ انتخاب‌شده حذف شوند؟",
                    f"Delete {count} selected configs?",
                ),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
                ) != QMessageBox.Yes:
            return
        self.storage.profiles = [
            profile for profile in self.storage.profiles
            if profile.id not in profile_ids
        ]
        if self.storage.selected_id in profile_ids:
            self.storage.selected_id = ""
        self.storage.save_profiles()
        self.refresh_profiles()
        self._set_activity(
            f"{count} کانفیگ حذف شد.",
            f"{count} configs deleted.",
            "success", False,
        )

    def delete_all_user_configs(self):
        count = sum(
            profile.origin == USER_CONFIG_ORIGIN
            for profile in self.storage.profiles
        )
        if not count:
            return
        if QMessageBox.question(
                self,
                self.tr("حذف User Config", "Delete User Configs"),
                self.tr(
                    f"هر {count} کانفیگ User Config حذف شوند؟",
                    f"Delete all {count} User Config entries?",
                ),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
                ) != QMessageBox.Yes:
            return
        removed_ids = {
            profile.id for profile in self.storage.profiles
            if profile.origin == USER_CONFIG_ORIGIN
        }
        self.storage.profiles = [
            profile for profile in self.storage.profiles
            if profile.origin != USER_CONFIG_ORIGIN
        ]
        if self.storage.selected_id in removed_ids:
            selected = next((
                profile for profile in self.storage.profiles
                if profile.origin in DIRECT_PROFILE_ORIGINS
            ), None)
            self.storage.selected_id = selected.id if selected else ""
        self.storage.settings.pop("last_user_config_profile_id", None)
        self.storage.save_profiles()
        self.storage.save_settings()
        self.refresh_profiles()
        self._set_activity(
            f"{count} کانفیگ User Config حذف شد.",
            f"{count} User Config entries deleted.",
            "success", False,
        )

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
        self._cancel_mode_apply()
        self._connect_cancel.set()
        self._connect_generation += 1
        self._connect_cancel = threading.Event()
        return self._connect_generation, self._connect_cancel

    def _attempt_cancelled(self, generation, cancel):
        return self._closing or cancel.is_set() or generation != self._connect_generation

    def _cancel_connect_attempt(self, wait=False, notify=False):
        self._cancel_mode_apply()
        self._connect_generation += 1
        self._connect_cancel.set()
        self.engine.stop(notify=notify)
        worker = self._connect_thread
        if wait and worker and worker is not threading.current_thread():
            worker.join(timeout=3)

    def _queue_profile_switch(self, profile_id):
        self._pending_profile_switch_id = profile_id
        if self._profile_switch_waiting:
            return
        self._profile_switch_waiting = True
        selected = next((profile for profile in self.storage.profiles
                         if profile.id == profile_id), None)
        self.connecting = False
        self.connection_error = ""
        self._cancel_connect_attempt(notify=False)
        self._set_state(False)
        self._set_connection_visual("disconnecting")
        if selected:
            self._set_activity(
                f"در حال فعال‌سازی کانفیگ {ltr_isolate(selected.name)}…",
                f"Switching to config: {selected.name}…",
            )
        QTimer.singleShot(50, self._resume_profile_switch)

    def _resume_profile_switch(self):
        if self._closing:
            self._pending_profile_switch_id = ""
            self._profile_switch_waiting = False
            return
        worker = self._connect_thread
        if worker and worker.is_alive():
            QTimer.singleShot(75, self._resume_profile_switch)
            return
        profile_id = self._pending_profile_switch_id
        self._pending_profile_switch_id = ""
        self._profile_switch_waiting = False
        profile = next((candidate for candidate in self.storage.profiles
                        if candidate.id == profile_id), None)
        if profile is None:
            self._set_state(False)
            return
        self.storage.selected_id = profile.id
        self._forced_profile_id = profile.id
        self.toggle_connection()

    @staticmethod
    def _attempt_tuning_for_profile(profile, base_tuning, fake_sni, mux_enabled):
        tuning = replace(base_tuning, pattern_fake_sni=fake_sni,
                         xray_mux_enabled=mux_enabled)
        if profile.verified_spoof:
            tuning = replace(
                tuning,
                pattern_connect_ip=profile.address or VERIFIED_SPOOF_EDGE,
                pattern_fallback_ips=profile.fallback_address,
                pattern_use_profile_edges=False,
            )
        return tuning

    @staticmethod
    def _initial_connection_strategy(carrier, country_code=""):
        if country_code:
            return "wrong_seq"
        return "tls_sni_records" if carrier == "mci" else "wrong_seq"

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
        live_edge = str(getattr(getattr(self, "engine", None), "fragment", None).active_edge or "").strip()\
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


            legacy_pins = self.storage.settings.get("pattern_profile_sni_pins", {})
            pins = legacy_pins if isinstance(legacy_pins, dict) else {}
        scoped_globals = self.storage.settings.get("pattern_global_sni_pin_by_carrier", {})
        global_pin = scoped_globals.get(carrier) if isinstance(scoped_globals, dict) else None
        if not global_pin and carrier == legacy_active:
            global_pin = self.storage.settings.get("pattern_global_sni_pin")
        profile_pin = pins.get(profile.id) if profile is not None else None
        if profile_pin:
            add(profile_pin)
        else:
            add(global_pin)
        remembered = self.storage.settings.get(f"working_pattern_sni_{carrier}", "")
        remembered_at = float(self.storage.settings.get(f"working_pattern_sni_at_{carrier}", 0) or 0)
        if remembered and time.time() - remembered_at < 7 * 24 * 3600:
            add(remembered)



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

    def _profile_sni_candidates(self, profile, carrier=None, limit=3):
        carrier = carrier or self.storage.tuning.carrier_mode
        if profile.route_mode == "reality-direct":
            reality_sni = str(profile.sni or "").strip().lower()
            return [reality_sni] if reality_sni else []
        candidates = self._sni_candidates(profile, carrier, limit)
        fallback = str(getattr(profile, "spoof_fake_sni", "") or "").strip().lower()
        if fallback:
            if (
                    profile.origin == USER_CONFIG_ORIGIN
                    and profile.route_is_verified):
                candidates = [
                    fallback,
                    *(value for value in candidates if value != fallback),
                ]
            elif fallback not in candidates:
                candidates.append(fallback)
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

    def _ordered_profiles(self, fake_sni, cancel_event, auto_enabled=True, manual_only=False,
                          forced_profile=None):
        country_code = (MainWindow._selected_country_code(self)
                        if auto_enabled and forced_profile is None else "")
        if forced_profile is not None:
            candidates = [forced_profile]
        elif not auto_enabled:
            if manual_only:
                origin = MainWindow._direct_source_origin(self)
                candidates = [
                    profile for profile in self.storage.profiles
                    if profile.origin == origin
                ]
            else:
                selected = self.storage.selected()
                candidates = ([selected] if selected is not None
                              and selected.origin in DIRECT_PROFILE_ORIGINS else [])
        elif country_code:
            candidates = MainWindow._country_profiles(self, country_code)
        else:
            source_profiles = self._route_source_profiles()
            verified = [
                profile for profile in source_profiles
                if profile.route_is_verified
            ]
            candidates = (
                verified
                if self._selected_route_source() == "user-config"
                else verified or source_profiles
            )
        if cancel_event.is_set():
            raise EngineCancelled("Connection attempt cancelled")
        tuning = self.storage.tuning
        ping_host = (candidates[0].address if country_code and candidates else "")\
            or tuning.pattern_connect_ip or "104.18.32.47"


        ok, latency = profile_ping(ping_host, 443, fake_sni, 3.5)
        self.bridge.log.emit(f"PATTERN EDGE PING 1/1 {ping_host}:443 sni={fake_sni} => {'OK' if ok else 'FAIL'}")
        if ok and latency > 0:
            latency_signal = getattr(self.bridge, "latency", None)
            if latency_signal is not None:
                latency_signal.emit(latency, "edge")
        for profile in candidates:
            if not (
                    profile.origin == USER_CONFIG_ORIGIN
                    and profile.route_is_verified and profile.last_ping_ok):
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


            upload_ok = previous.get("upload_ok") if previous_upload_valid else None
            effective_state = previous_state if previous_upload_valid else state




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
        if carrier == "mci" and measured_download_state == "verified"\
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
        if getattr(self, "_maker_running", False) and not self.engine.running and not self.connecting:
            self.show_toast(self.tr(
                "ابتدا تست زنده سازنده SNI را متوقف کنید",
                "Stop the SNI Maker live test before connecting",
            ), "warning")
            return
        if self.connecting:
            self.connecting = False
            self.connection_error = ""
            self._set_connection_visual("disconnecting")
            self._set_activity("در حال لغو عملیات اتصال…", "Cancelling the connection attempt…")
            self.bridge.log.emit("CONNECT CANCEL requested by user")
            reset_gateway = getattr(self, "_reset_gateway_mode", None)
            if callable(reset_gateway):
                reset_gateway(reason="disconnect", stop=True)
            self._cancel_connect_attempt(notify=True)
            self._set_state(False)
            self._set_activity("عملیات اتصال لغو شد.", "Connection attempt cancelled.", "warning", False)
            return
        if self.engine.running:
            self.connecting = False; self.connection_error = ""; self._set_connection_visual("disconnecting")
            self._set_activity(
                "در حال توقف رابط TUN و هسته اسپوف…" if self._tun_mode_enabled()
                else "در حال توقف تونل و بازگردانی پروکسی سیستم…" if self._proxy_mode_enabled()
                else "در حال توقف هسته اسپوف…",
                "Stopping the TUN interface and spoof core…" if self._tun_mode_enabled()
                else "Stopping the tunnel and restoring the system proxy…" if self._proxy_mode_enabled()
                else "Stopping the spoof core…",
            )
            reset_gateway = getattr(self, "_reset_gateway_mode", None)
            if callable(reset_gateway):
                reset_gateway(reason="disconnect", stop=True)
            self._cancel_connect_attempt(notify=True)
            self._set_state(False)
            return
        if self._tun_mode_enabled():
            try:
                self.engine.ensure_tun_available()
            except Exception as exc:
                message = str(exc)
                self.connection_error = message
                self._set_connection_visual("error")
                self._handle_error(message)
                return
        generation, cancel = self._begin_connect_attempt()
        base_tuning = self.storage.tuning
        carrier = base_tuning.carrier_mode
        bypass = self.selected_processes()
        auto_enabled = self.auto_mode.isChecked()
        manual_only = self.pick_best.isChecked()
        forced_profile_id = self._forced_profile_id
        self._forced_profile_id = ""
        forced_profile = next((profile for profile in self.storage.profiles
                               if profile.id == forced_profile_id), None)
        country_code = self._selected_country_code() if auto_enabled and forced_profile is None else ""
        country_profiles = self._country_profiles(country_code) if country_code else []
        manual_profile = forced_profile or (self.storage.selected() if not auto_enabled else None)
        if not auto_enabled and forced_profile is None and (
                manual_profile is None
                or manual_profile.origin not in DIRECT_PROFILE_ORIGINS):
            manual_profile = self._select_manual_profile()
        if not auto_enabled and forced_profile is None and manual_profile is None:
            message = self.tr(
                "در حالت دستی ابتدا یک کانفیگ از Manual یا User Config انتخاب کنید",
                "Select a Manual or User Config entry before connecting",
            )
            self.connection_error = message; self._set_connection_visual("error"); self._handle_error(message)
            return
        if country_code and not country_profiles:
            message = self.tr("برای کشور انتخاب‌شده کانفیگ سالمی وجود ندارد", "No verified config is available for the selected country")
            self.connection_error = message; self._set_connection_visual("error"); self._handle_error(message)
            return
        if (auto_enabled and forced_profile is None and not country_code
                and self._selected_route_source() == "user-config"
                and not self._route_source_profiles(verified_only=True)):
            message = self.tr(
                "در User Config هنوز کانفیگ سالمی برای اتصال خودکار وجود ندارد",
                "User Config has no verified route for Auto Mode yet",
            )
            self.connection_error = message; self._set_connection_visual("error"); self._handle_error(message)
            return
        seed_profile = forced_profile or (manual_profile if not auto_enabled else None)
        seed_snis = (self._profile_sni_candidates(seed_profile, carrier)
                     if seed_profile is not None else
                     self._sni_candidates(None, carrier=carrier))
        if not seed_snis and country_profiles:
            seed_snis = [next((
                profile.sni
                if profile.route_mode == "reality-direct"
                else profile.spoof_fake_sni
                for profile in country_profiles
                if (
                    profile.sni
                    if profile.route_mode == "reality-direct"
                    else profile.spoof_fake_sni
                )
            ), VERIFIED_SPOOF_FAKE_SNI)]
        if not seed_snis:
            direct_seed = next((
                profile.sni
                for profile in self._route_source_profiles(verified_only=True)
                if profile.route_mode == "reality-direct" and profile.sni
            ), "")
            if direct_seed:
                seed_snis = [direct_seed]
        if not seed_snis:
            message = self.tr("هیچ SNI معتبر در مخزن اسکن پیدا نشد", "No valid SNI was found in the scan repository")
            self.connection_error = message; self._set_connection_visual("error"); self._handle_error(message)
            return
        self.connecting = True; self.connection_error = ""; self._set_connection_visual("connecting"); self._set_latency(0.0, "testing")
        if forced_profile is not None:
            self._set_activity(
                f"در حال فعال‌سازی کانفیگ {ltr_isolate(forced_profile.name)}…",
                f"Activating selected config: {forced_profile.name}…",
            )
        elif country_code:
            _flag, english, persian = self._country_metadata(country_code)
            self._set_activity(
                f"در حال تست {len(country_profiles)} کانفیگ {persian}…",
                f"Testing {len(country_profiles)} {english} configs…",
            )
        elif not auto_enabled:
            self._set_activity(
                f"در حال اتصال کانفیگ انتخاب‌شده {ltr_isolate(manual_profile.name)}…",
                f"Connecting selected config: {manual_profile.name}…",
            )
        else:
            self._set_activity("در حال آماده‌سازی مسیر امن…", "Preparing secure route…")
        self.bridge.log.emit("SNI REPOSITORY candidates=" + ",".join(seed_snis))

        def work():
            connected = False
            last_error = ""


            strategy = MainWindow._initial_connection_strategy(
                carrier, country_code
            )
            try:
                self.bridge.activity.emit(self.tr(f"در حال آزمایش دسترسی {ltr_isolate('SNI')}…", "Testing SNI reachability…"), "running", True)
                profiles = self._ordered_profiles(
                    seed_snis[0], cancel, auto_enabled, manual_only, forced_profile
                )
                if self._attempt_cancelled(generation, cancel):
                    raise EngineCancelled("Connection attempt cancelled")
                if not profiles:
                    raise ValueError(self.tr("کانفیگی موجود نیست", "No config available"))
                for index, profile in enumerate(profiles, 1):
                    profile_snis = self._profile_sni_candidates(profile, carrier, limit=3)
                    profile_passed = False
                    profile_mux_enabled = self._profile_mux_enabled(profile, base_tuning, carrier)
                    for sni_index, fake_sni in enumerate(profile_snis, 1):
                        if self._attempt_cancelled(generation, cancel):
                            raise EngineCancelled("Connection attempt cancelled")
                        self.bridge.log.emit(f"CONFIG TRY {index}/{len(profiles)} {profile.name} SNI {sni_index}/{len(profile_snis)}={fake_sni}")
                        attempt_strategy = strategy
                        attempt_tuning = self._attempt_tuning_for_profile(
                            profile, base_tuning, fake_sni, profile_mux_enabled
                        )
                        if not profile.verified_spoof:
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



                                "mci": "https://www.gstatic.com/generate_204",
                            }
                            preferred_url = preferred_urls.get(carrier)
                            page_ok, detail = self.engine.probe(timeout=6, preferred_url=preferred_url,
                                                                require_preferred=(carrier in preferred_urls),
                                                                cancel_event=cancel)
                            if (not page_ok and carrier == "mci"
                                    and attempt_strategy == "tls_sni_records"):



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
                            if page_ok and profile.route_is_verified:
                                self.bridge.activity.emit(self.tr(
                                    "در حال بررسی کشور واقعی آی‌پی خروجی…",
                                    "Verifying the real exit-IP country…",
                                ), "running", True)
                                location = current_location(proxy=True, timeout=5.0)
                                if location is not None:
                                    changed_country = self._record_profile_location(profile, location)
                                    if changed_country or profile.rotating_exit:
                                        self.bridge.profiles_changed.emit()
                                    if country_code and location.country_code.upper() != country_code:
                                        page_ok = False
                                        detail = (
                                            f"exit country mismatch: requested={country_code} "
                                            f"observed={location.country_code} ip={location.ip}"
                                        )
                                        self.bridge.log.emit(f"COUNTRY REJECT {profile.name}: {detail}")
                                elif country_code:
                                    page_ok = False
                                    detail = "exit country could not be verified"
                                    self.bridge.log.emit(f"COUNTRY REJECT {profile.name}: {detail}")
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
                                with self._proxy_mode_apply_lock:
                                    connection_mode = self._apply_connection_mode_after_probe(cancel)
                                if self._attempt_cancelled(generation, cancel):
                                    raise EngineCancelled("Connection attempt cancelled")
                                self.storage.settings[f"working_strategy_{carrier}"] = attempt_strategy
                                self.storage.settings[f"working_profile_{carrier}"] = profile.id
                                self.storage.settings[f"working_pattern_sni_{carrier}"] = fake_sni
                                self.storage.settings[f"working_pattern_sni_at_{carrier}"] = time.time()
                                self.storage.settings["selected_id"] = profile.id



                                working_tuning = replace(base_tuning, pattern_fake_sni=fake_sni)
                                if profile.verified_spoof:
                                    working_tuning.pattern_connect_ip = profile.address or VERIFIED_SPOOF_EDGE
                                    working_tuning.pattern_fallback_ips = profile.fallback_address
                                    working_tuning.pattern_use_profile_edges = False
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
                                if (not self.engine.running
                                        or (connection_mode == "tun"
                                            and not self.engine.tun_running)):
                                    raise RuntimeError(
                                        "Connection engine stopped before activation completed"
                                    )
                                connected = profile_passed = True
                                self.bridge.profiles_changed.emit()
                                quality = (f"; download={download_detail}"
                                           if carrier == "mci" and download_detail else "")
                                self.bridge.log.emit(f"CONFIG WIN {profile.name} fakeSni={fake_sni}: {detail}{quality}")
                                self.bridge.state.emit(True)
                                self.bridge.hint.emit(self.tr(f"متصل با بهترین {ltr_isolate('SNI')}: {ltr_isolate(fake_sni)}", f"Connected with best SNI: {fake_sni}"))
                                self.bridge.activity.emit(self.tr(
                                    "حالت TUN فعال است؛ وب و یوتیوب از تونل عبور می‌کنند."
                                    if connection_mode == "tun" else
                                    "اتصال برقرار شد و پروکسی ویندوز فعال است."
                                    if connection_mode == "proxy" else
                                    "هسته اسپوف فعال است؛ پروکسی ویندوز خاموش است.",
                                    "TUN Mode is active; web and YouTube use the tunnel."
                                    if connection_mode == "tun" else
                                    "Connected with Windows Proxy enabled."
                                    if connection_mode == "proxy" else
                                    "Spoof core is active; Windows Proxy is off.",
                                ), "success", False)
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
        if running and not self.engine.running:
            running = False
        if (running and self._tun_mode_enabled()
                and not bool(getattr(self.engine, "tun_running", False))):
            running = False
        was_running = getattr(self, "_ui_running", False)
        if not running:
            reset_gateway = getattr(self, "_reset_gateway_mode", None)
            if callable(reset_gateway):
                reset_gateway(reason="disconnect", stop=True)
        self._ui_running = bool(running)
        self.connecting = False
        self.proxy_mode.setEnabled(True)
        self.tun_mode.setEnabled(True)
        self.tun_option.setEnabled(True)
        self.proxy_option.setEnabled(not self._tun_mode_enabled())
        sync_gateway = getattr(self, "_sync_gateway_controls", None)
        if callable(sync_gateway):
            sync_gateway()
        if running:
            self.connection_error = ""; self._set_connection_visual("connected")
            self._set_activity("اتصال امن برقرار شد.", "Connection established.", "success", False)
            if self._tun_mode_enabled() and not self.engine.tun_running:
                QTimer.singleShot(0, self._queue_tun_mode_apply)
            elif not self._tun_mode_enabled():
                QTimer.singleShot(0, self._queue_proxy_mode_apply)
            gateway_runtime = getattr(self, "_gateway_runtime_active", None)
            if (getattr(self, "_gateway_requested", False)
                    and callable(gateway_runtime)
                    and not gateway_runtime()):
                QTimer.singleShot(
                    0, lambda: self._queue_gateway_mode_apply(
                        True, reason="user"
                    )
                )
        elif self.connection_error:
            self._set_connection_visual("error")
        else:
            self._set_connection_visual("disconnected")
            if was_running: self._set_activity("تونل متوقف و پروکسی سیستم بازگردانی شد.", "Tunnel stopped and system proxy restored.", "success", False)
        QTimer.singleShot(0, self._queue_target_latency_probe)

    def _set_traffic(self, up, down): self.up_label.setText(format_bytes(up)); self.down_label.setText(format_bytes(down))

    def _set_latency(self, milliseconds, source="tunnel"):
        if source == "testing":
            self.ping_label.setText("…")
            self.latency_card.set_secondary("8.8.8.8 • Checking…")
            return

    def _queue_target_latency_probe(self):
        if self._closing:
            return
        if self._target_latency_busy:
            self._target_latency_pending = True
            return
        self._target_latency_busy = True
        self._target_latency_pending = False
        self._target_latency_generation += 1
        generation = self._target_latency_generation
        use_tun = bool(getattr(self.engine, "tun_running", False))
        proxy_active = bool(
            not use_tun
            and getattr(self.engine, "running", False)
            and getattr(self.engine, "_proxy_enabled", False)
        )
        run_id = int(getattr(self.engine, "run_id", 0) or 0)

        def work():
            if use_tun:
                mode = "tun"
                value = _tun_tls_latency_8888()
            elif proxy_active:
                mode = f"proxy|{run_id}"
                value = self.engine.measure_proxy_latency(timeout=5.0)
            else:
                mode = "direct"
                value = _direct_ping_8888()
            if value is None and mode == "tun":
                value = _direct_ping_8888()
                mode = "direct-fallback"
            self.bridge.target_latency.emit(float(value or 0.0), mode, generation)

        thread_name = "latency-8.8.8.8" if use_tun else "latency-active-config"
        threading.Thread(target=work, name=thread_name, daemon=True).start()

    def _target_latency_finished(self, milliseconds, mode, generation):
        if generation != self._target_latency_generation:
            return
        self._target_latency_busy = False
        base_mode = str(mode).split("|", 1)[0]
        current_tun = bool(getattr(self.engine, "tun_running", False))
        current_proxy = bool(
            not current_tun
            and getattr(self.engine, "running", False)
            and getattr(self.engine, "_proxy_enabled", False)
        )
        stale_mode = (
            (base_mode == "tun" and not current_tun)
            or (base_mode == "direct-fallback" and not current_tun)
            or (base_mode == "direct" and (current_tun or current_proxy))
            or (
                base_mode == "proxy"
                and (
                    not current_proxy
                    or str(getattr(self.engine, "run_id", 0))
                    != str(mode).partition("|")[2]
                )
            )
        )
        if not stale_mode:
            value = max(0.0, float(milliseconds))
            self.ping_label.setText(f"{value:.0f} ms" if value > 0 else "Timeout")
            if base_mode == "proxy":
                secondary = self.tr(
                    "کانفیگ فعال • تأخیر زنده",
                    "Active config • Live delay",
                )
            else:
                secondary = {
                    "tun": "8.8.8.8 • TUN TLS",
                    "direct": "8.8.8.8 • Direct ICMP",
                    "direct-fallback": "8.8.8.8 • Direct fallback",
                }.get(base_mode, "8.8.8.8")
            self.latency_card.set_secondary(secondary)
            if value > 0:
                self.latency_card.sparkline.add_value(value)
        if stale_mode or self._target_latency_pending:
            QTimer.singleShot(0, self._queue_target_latency_probe)

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
        announce = getattr(self, "_announce_update", None)
        if callable(announce): announce(info)
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
        self._announce_update(info)

    def _announce_update(self, info):
        if not info or not info.is_update_available:
            return False
        if self.storage.settings.get("notified_update_version") == info.latest_version:
            return False
        self.storage.settings["notified_update_version"] = info.latest_version
        self.storage.save_settings()
        self._show_update_notification(info)
        return True

    def _show_update_notification(self, info):
        if not self.isVisible():
            self._pending_update_notification = info
            return
        old = self._update_notification
        if old is not None:
            old.deleteLater()
        banner = QFrame(self.centralWidget()); banner.setObjectName("updateNotification"); banner.setProperty("rtl", self.language == "fa"); banner.setAccessibleName(self.tr("بروزرسانی جدید برنامه", "New application update"))
        banner.setFixedHeight(108)
        root = QHBoxLayout(banner); root.setContentsMargins(13, 11, 13, 11); root.setSpacing(12)
        accent = QFrame(); accent.setObjectName("updateNotificationAccent"); accent.setFixedSize(4, 70); root.addWidget(accent, 0, Qt.AlignVCenter)
        icon = QLabel(); icon.setObjectName("updateNotificationIcon"); icon.setFixedSize(56, 56); icon.setAlignment(Qt.AlignCenter); icon.setPixmap(cyber_pixmap("download", "#bafff7", 28)); root.addWidget(icon, 0, Qt.AlignVCenter)
        copy = QVBoxLayout(); copy.setSpacing(2)
        eyebrow = QLabel(self.tr("بروزرسانی جدید UAC SPOOFER", "UAC SPOOFER UPDATE")); eyebrow.setObjectName("updateNotificationEyebrow")
        title = QLabel(self.tr("نسخه جدید آماده دریافت است", "A new version is ready")); title.setObjectName("updateNotificationTitle")
        detail = QLabel(self.tr(f"نسخه نصب‌شده {ltr_isolate(info.current_version)}  ←  نسخه جدید {ltr_isolate(info.latest_version)}", f"Installed {info.current_version}  →  New {info.latest_version}")); detail.setObjectName("updateNotificationDetail"); detail.setWordWrap(True)
        copy.addWidget(eyebrow); copy.addWidget(title); copy.addWidget(detail); root.addLayout(copy, 1)
        download = QPushButton(self.tr("دریافت بروزرسانی", "Download Update")); download.setObjectName("updateNotificationPrimary"); download.setIcon(cyber_icon("download", "#031422", 18)); download.setIconSize(QSize(18, 18)); download.setCursor(Qt.PointingHandCursor); download.setFixedSize(176, 40)
        download.clicked.connect(self._open_latest_update); download.clicked.connect(self._dismiss_update_notification); root.addWidget(download, 0, Qt.AlignVCenter)
        available_width = max(620, self.stack.width() - 36)
        banner.setFixedWidth(min(820, available_width))
        shadow = QGraphicsDropShadowEffect(banner); shadow.setBlurRadius(38); shadow.setOffset(0, 10); shadow.setColor(QColor(0, 0, 0, 175)); banner.setGraphicsEffect(shadow)
        self._update_notification = banner
        banner.show(); banner.raise_()
        target = self._update_notification_target(banner)
        if _animations_enabled():
            banner.move(target.x(), -banner.height() - 12)
            group = QParallelAnimationGroup(self)
            slide = QPropertyAnimation(banner, b"pos", group); slide.setDuration(520); slide.setStartValue(banner.pos()); slide.setEndValue(target); slide.setEasingCurve(QEasingCurve.OutBack)
            group.addAnimation(slide); self._update_notification_animation = group; group.start()
        else:
            banner.move(target)
        if self._update_notification_timer is not None:
            self._update_notification_timer.stop()
        self._update_notification_timer = QTimer(self); self._update_notification_timer.setSingleShot(True); self._update_notification_timer.timeout.connect(self._dismiss_update_notification); self._update_notification_timer.start(14000)

    def _update_notification_target(self, banner):
        stack_origin = self.stack.mapTo(self.centralWidget(), QPoint(0, 0))
        width = min(820, max(620, self.stack.width() - 36))
        banner.setFixedWidth(width)
        return QPoint(stack_origin.x() + max(18, (self.stack.width() - width) // 2), stack_origin.y() + 18)

    def _position_update_notification(self):
        banner = self._update_notification
        if banner is not None and banner.isVisible():
            banner.move(self._update_notification_target(banner))
            banner.raise_()

    def _dismiss_update_notification(self):
        banner = self._update_notification
        if banner is None:
            return
        if self._update_notification_timer is not None:
            self._update_notification_timer.stop()
        if self._update_notification_animation is not None:
            self._update_notification_animation.stop()
        self._update_notification = None
        if not _animations_enabled():
            banner.deleteLater()
            return
        group = QParallelAnimationGroup(self)
        slide = QPropertyAnimation(banner, b"pos", group); slide.setDuration(260); slide.setStartValue(banner.pos()); slide.setEndValue(banner.pos() - QPoint(0, banner.height() + 24)); slide.setEasingCurve(QEasingCurve.InCubic)
        group.addAnimation(slide); group.finished.connect(banner.deleteLater); self._update_notification_animation = group; group.start()

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

        suggested = [
            profile for profile in self.storage.profiles
            if profile.origin not in DIRECT_PROFILE_ORIGINS
        ]
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
        dense_sidebar = self.height() < 790
        self.sidebar.setFixedWidth(238 if compact else 286)
        self.rating_card.setVisible(self.height() >= 890 and not compact)
        self.sidebar_layout.setContentsMargins(
            *(14, 10, 14, 10) if dense_sidebar else (18, 20, 18, 18)
        )
        self.logo_card.setFixedHeight(76 if dense_sidebar else 88)
        nav_height = 44 if dense_sidebar else 54 if self.height() < 930 else 56
        for button in self.nav:
            button.setFixedHeight(nav_height)
        self._layout_home_dashboard()
        self._layout_sni_maker()
        self._position_profile_select_all()
        self._layout_tool_cards(self.width() < 1180)
        self._position_toast()
        self._position_update_notification()
        self._position_gateway_devices_popup()

    def showEvent(self, event):
        super().showEvent(event)
        self._layout_home_dashboard()
        self._layout_sni_maker()
        QTimer.singleShot(0, self._layout_home_dashboard)
        QTimer.singleShot(0, self._layout_sni_maker)
        if self._pending_update_notification is not None:
            info = self._pending_update_notification; self._pending_update_notification = None
            QTimer.singleShot(0, lambda value=info: self._show_update_notification(value))
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
        protected = {
            os.path.basename(sys.executable).lower(),
            "xray.exe",
            "sing-box.exe",
        }
        names = [name for name in names if str(name).lower() not in protected]
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
        self._gateway_requested = False
        self._cancel_gateway_apply()
        self._set_gateway_toggle(False)
        self._sync_gateway_controls()
        try:
            disable_gateway = getattr(self.engine, "disable_gateway", None)
            if callable(disable_gateway):
                disable_gateway(reason="shutdown")
        except Exception as exc:
            self._pending_file_log_lines.append(
                f"Shutdown gateway cleanup pending: {exc}"
            )
        self._target_latency_generation += 1
        self._target_latency_timer.stop()
        self._bypass_apply_timer.stop()
        self.scan_cancelled = True; self._scan_cancel_event.set(); self._scan_generation += 1; self._update_generation += 1
        self._maker_cancel_event.set()
        self._maker_generation += 1
        self._maker_import_generation += 1
        self._profile_ping_cancel.set()
        self._profile_ping_generation += 1
        maker_tester, self._maker_tester = self._maker_tester, None
        if maker_tester is not None:
            try:
                maker_tester.stop()
            except Exception as exc:
                self._pending_file_log_lines.append(f"SNI Maker cleanup pending: {exc}")
        try:
            self._cancel_connect_attempt(wait=True, notify=False)
        except Exception as exc:
            self._pending_file_log_lines.append(f"Shutdown cleanup retry: {exc}")
        try:


            self.engine.stop(notify=False)
        except Exception as exc:
            self._pending_file_log_lines.append(f"Shutdown proxy restore pending: {exc}")
        finally:
            self._flush_log_buffer(final=True)

    def closeEvent(self, event):
        popup = getattr(self, "gateway_devices_popup", None)
        if popup is not None:
            popup.hide()
        if not self._force_quit:
            action = self._ask_close_action()
            if action == "tray" and self._hide_to_tray():
                event.ignore()
                return
            if action != "quit":
                event.ignore()
                return
            self._force_quit = True
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
QPushButton#footerAction[rtl="true"] { text-align: right; }
QPushButton#footerAction[rtl="false"] { text-align: left; }
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

QFrame#countrySelectorCard { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(7,48,67,0.92),stop:0.48 rgba(8,31,61,0.94),stop:1 rgba(26,24,72,0.91)); border: 1px solid rgba(65,240,226,0.38); border-radius: 20px; }
QFrame#countrySelectorCard:hover { border-color: rgba(91,255,239,0.68); background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(8,60,77,0.95),stop:0.48 rgba(9,38,70,0.96),stop:1 rgba(33,29,86,0.94)); }
QFrame#countrySelectorCard[mode="manual"] { border-color: rgba(111,145,181,0.3); background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(13,34,52,0.9),stop:1 rgba(25,25,58,0.9)); }
QLabel#countryIcon { background: qradialgradient(cx:0.42,cy:0.35,radius:0.8,stop:0 rgba(45,222,218,0.4),stop:1 rgba(11,63,83,0.78)); border: 1px solid rgba(105,255,241,0.42); border-radius: 16px; }
QLabel#countryEyebrow { color: #63eee7; font-size: 9px; font-weight: 900; letter-spacing: 1.5px; }
QLabel#countryTitle { color: #f5ffff; font-size: 17px; font-weight: 900; }
QLabel#countryDescription { color: #a9bfd7; font-size: 11px; }
QLabel#countryCount { color: #9ffdf5; background: rgba(8,69,78,0.56); border: 1px solid rgba(72,236,225,0.25); border-radius: 9px; padding: 4px 9px; font-size: 10px; font-weight: 800; }
QComboBox#countryCombo { background: rgba(4,20,43,0.96); border: 1px solid rgba(82,244,230,0.55); border-radius: 13px; padding: 7px 15px; color: #f4ffff; font-size: 13px; font-weight: 750; }
QComboBox#countryCombo:hover, QComboBox#countryCombo:focus { border-color: #67fff0; background: rgba(6,34,55,0.98); }
QComboBox#countryCombo:disabled { color: #7890aa; border-color: rgba(111,145,181,0.28); background: rgba(8,20,38,0.72); }
QComboBox#countryCombo QAbstractItemView { min-width: 350px; background: #091c35; border: 1px solid rgba(82,244,230,0.6); border-radius: 12px; padding: 7px; outline: 0; show-decoration-selected: 1; }
QComboBox#countryCombo QAbstractItemView::item { min-height: 38px; padding: 6px 12px; margin: 2px; border-radius: 8px; color: #eafcff; }
QComboBox#countryCombo QAbstractItemView::item:hover { background: rgba(22,83,102,0.86); }
QComboBox#countryCombo QAbstractItemView::item:selected { background: rgba(14,105,111,0.92); color: #ffffff; }

QFrame#metricCard { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(10,29,60,0.94),stop:1 rgba(8,21,44,0.92)); border: 1px solid rgba(54,211,255,0.24); border-radius: 19px; }
QFrame#metricCard:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(12,39,72,0.96),stop:1 rgba(8,29,53,0.94)); border-color: rgba(54,211,255,0.58); }
QLabel#metricIcon { background: rgba(10,57,76,0.72); border: 1px solid rgba(35,245,224,0.26); border-radius: 10px; qproperty-alignment: AlignCenter; }
QLabel#metricLabel, QLabel#fieldLabel { color: #a9bdd7; font-size: 11px; font-weight: 750; }
QLabel#metricValue { color: #f7fbff; font-size: 22px; font-weight: 850; }
QLabel#metricSecondary { color: #55e7df; font-family: "Cascadia Mono", "Segoe UI", "Consolas"; font-size: 11px; font-weight: 650; }
QFrame#quickControls, QFrame#sniActionBar { background: rgba(9,25,54,0.86); border: 1px solid rgba(54,211,255,0.24); border-radius: 18px; }
QFrame#toggleOption, QFrame#proxyModeOption, QFrame#tunModeOption, QFrame#gatewayModeOption, QFrame#carrierControl { background: rgba(8,24,47,0.74); border: 1px solid rgba(54,211,255,0.13); border-radius: 12px; }
QFrame#toggleOption:hover, QFrame#proxyModeOption:hover, QFrame#tunModeOption:hover, QFrame#gatewayModeOption:hover, QFrame#carrierControl:hover { border-color: rgba(54,211,255,0.35); background: rgba(12,36,61,0.82); }
QFrame#proxyModeOption[active="true"] { border-color: rgba(35,245,224,0.38); background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(8,55,64,0.84),stop:1 rgba(10,35,63,0.82)); }
QFrame#proxyModeOption[active="false"] { border-color: rgba(111,145,181,0.24); background: rgba(8,21,40,0.72); }
QFrame#tunModeOption[active="true"] { border-color: rgba(97,220,255,0.62); background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(8,60,78,0.92),stop:1 rgba(28,39,91,0.88)); }
QFrame#tunModeOption[active="false"] { border-color: rgba(111,145,181,0.24); background: rgba(8,21,40,0.72); }
QFrame#gatewayModeOption[state="requested"], QFrame#gatewayModeOption[state="starting"] { border-color: rgba(255,209,102,0.64); background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(74,56,24,0.9),stop:1 rgba(16,46,68,0.9)); }
QFrame#gatewayModeOption[state="stopping"] { border-color: rgba(255,118,145,0.58); background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(69,26,48,0.9),stop:1 rgba(16,39,65,0.9)); }
QFrame#gatewayModeOption[state="active"] { border-color: rgba(102,255,231,0.78); background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(8,78,74,0.94),stop:0.55 rgba(11,55,78,0.94),stop:1 rgba(55,35,104,0.92)); }
QFrame#gatewayModeOption[state="off"] { border-color: rgba(111,145,181,0.24); background: rgba(8,21,40,0.72); }
QToolButton#gatewayDevicesBadge { min-width: 48px; max-width: 76px; min-height: 24px; max-height: 24px; padding: 0 8px; color: #a9bdd4; background: #0a2038; border: 1px solid rgba(91,143,183,0.48); border-radius: 10px; font-size: 10px; font-weight: 850; }
QToolButton#gatewayDevicesBadge:hover, QToolButton#gatewayDevicesBadge:focus { color: #f2ffff; background: rgba(12,61,75,0.94); border-color: rgba(91,255,239,0.76); }
QToolButton#gatewayDevicesBadge[gatewayActive="true"] { color: #dffffa; border-color: rgba(35,245,224,0.54); background: rgba(7,68,71,0.86); }
QToolButton#gatewayDevicesBadge[hasDevices="true"] { color: #edfff8; border-color: rgba(35,245,166,0.72); background: rgba(6,78,63,0.92); }
QFrame#gatewayDevicesPopup { background-color: #081b33; border: 1px solid #278c9f; border-radius: 17px; }
QLabel#gatewayPopupIcon { background: rgba(11,74,82,0.76); border: 1px solid rgba(73,246,231,0.38); border-radius: 11px; }
QLabel#gatewayPopupTitle { color: #f5ffff; font-size: 14px; font-weight: 900; }
QLabel#gatewayPopupSubtitle { color: #87a8c5; font-size: 10px; font-weight: 600; }
QLabel#gatewayPopupCount { color: #aaffee; background: rgba(7,67,69,0.66); border: 1px solid rgba(35,245,224,0.3); border-radius: 9px; padding: 4px 8px; font-size: 10px; font-weight: 850; }
QScrollArea#gatewayDevicesScroll, QScrollArea#gatewayDevicesScroll > QWidget, QWidget#gatewayDevicesList { background: transparent; border: 0; }
QFrame#gatewayDeviceRow { background: rgba(8,30,54,0.88); border: 1px solid rgba(69,151,190,0.3); border-radius: 11px; }
QFrame#gatewayDeviceRow:hover { background: rgba(10,46,65,0.94); border-color: rgba(35,245,224,0.5); }
QLabel#gatewayDeviceCheck { background: rgba(9,78,61,0.48); border: 1px solid rgba(35,245,166,0.34); border-radius: 9px; }
QLabel#gatewayDeviceIp { color: #f2fbff; font-size: 12px; font-weight: 800; }
QLabel#gatewayDeviceMac { color: #7999b9; font-size: 9px; font-weight: 600; }
QLabel#gatewayDeviceState { color: #55f5b4; font-size: 10px; font-weight: 850; }
QFrame#gatewayDeviceEmpty { background: rgba(7,21,42,0.62); border: 1px dashed rgba(86,137,177,0.35); border-radius: 12px; }
QLabel#gatewayDeviceEmptyText { color: #8da6bf; font-size: 11px; font-weight: 650; }
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
QPushButton#advancedButton { min-height: 20px; padding: 5px 12px; }
QPushButton#quietButton, QPushButton#metricAction, QPushButton#toolAction { background: rgba(8,26,50,0.5); border-color: rgba(80,127,167,0.44); color: #c1d3e4; }
QPushButton#quietButton:hover, QPushButton#metricAction:hover, QPushButton#toolAction:hover { background: rgba(17,55,78,0.8); color: #84f8ef; border-color: rgba(35,245,224,0.52); }
QPushButton#dangerButton { background: rgba(78,20,43,0.56); border-color: rgba(255,92,124,0.42); color: #ffb7c5; }
QPushButton#dangerButton:hover { background: rgba(116,29,56,0.76); border-color: #ff718c; color: #fff1f4; }

QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QListWidget, QTableWidget, QTableView { background: rgba(4,15,31,0.92); border: 1px solid rgba(66,118,161,0.55); border-radius: 11px; padding: 8px 10px; selection-background-color: #0b7c82; selection-color: #ffffff; }
QLineEdit:hover, QTextEdit:hover, QPlainTextEdit:hover, QComboBox:hover { border-color: rgba(80,164,201,0.72); }
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus, QListWidget:focus, QTableWidget:focus, QTableView:focus { border: 1px solid $accent; background: rgba(6,22,42,0.98); }
QLineEdit[invalid="true"], QTextEdit[invalid="true"] { border: 1px solid $danger; background: rgba(65,15,35,0.55); }
QComboBox { min-height: 28px; padding-left: 11px; padding-right: 34px; }
QComboBox#countryCombo { min-height: 20px; }
QComboBox#carrierModeCombo { min-height: 20px; padding: 4px 28px 4px 9px; }
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

QFrame#pageToolbar, QFrame#makerTestBar { background: rgba(9,25,51,0.88); border: 1px solid rgba(54,211,255,0.2); border-radius: 15px; }
QFrame#configPanel, QFrame#tableFrame { background: rgba(7,21,43,0.86); border: 1px solid rgba(54,211,255,0.21); border-radius: 17px; }
QFrame#makerSourceCard { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(8,32,57,0.96),stop:1 rgba(8,23,48,0.94)); border: 1px solid rgba(54,211,255,0.27); border-radius: 17px; }
QFrame#makerResultsPanel { background: rgba(5,18,37,0.94); border: 1px solid rgba(54,211,255,0.24); border-radius: 17px; }
QFrame#makerResultToolbar { background: rgba(10,29,54,0.96); border: 0; border-bottom: 1px solid rgba(54,211,255,0.19); border-top-left-radius: 16px; border-top-right-radius: 16px; }
QFrame#makerActionBar { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(8,38,58,0.93),stop:1 rgba(18,25,65,0.92)); border: 1px solid rgba(54,211,255,0.27); border-radius: 15px; }
QLabel#makerStepTitle { color: #b9fff8; font-size: 12px; font-weight: 850; }
QLabel#makerDestination { color: #78f5e8; background: rgba(7,62,67,0.65); border: 1px solid rgba(35,245,224,0.28); border-radius: 9px; padding: 7px 10px; font-size: 11px; font-weight: 800; }
QTabBar#routeSourceTabs::tab { min-height: 20px; padding: 4px 12px; margin: 0 2px; border-radius: 8px; font-size: 10px; }
QFrame#makerSourceCard QPushButton, QFrame#makerTestBar QPushButton, QFrame#makerResultToolbar QPushButton, QFrame#makerActionBar QPushButton { min-height: 26px; padding: 4px 9px; border-radius: 9px; }
QFrame#makerSourceCard QPushButton[guided="true"], QFrame#makerTestBar QPushButton[guided="true"], QFrame#makerActionBar QPushButton[guided="true"] { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(20,190,181,0.96),stop:0.52 rgba(35,245,224,0.98),stop:1 rgba(44,199,255,0.96)); border: 2px solid #c5fff9; color: #031823; font-weight: 900; }
QLineEdit#makerRepoUrl { min-height: 22px; padding: 4px 8px; }
QLineEdit#makerSearch { min-height: 30px; }
QComboBox#makerStatusFilter { min-width: 132px; }
QTableView#makerResultsTable { background: rgba(3,14,29,0.9); border: 0; border-radius: 0; padding: 0; alternate-background-color: rgba(8,25,46,0.82); gridline-color: transparent; }
QTableView#makerResultsTable::item { padding: 9px 10px; border-bottom: 1px solid rgba(54,211,255,0.09); color: #d3e5f2; }
QTableView#makerResultsTable::item:hover { background: rgba(15,53,76,0.78); }
QTableView#makerResultsTable::item:selected { background: rgba(9,83,88,0.82); color: #f8ffff; }
QTabWidget#profileTabs::pane, QTabWidget#scannerTabs::pane { background: rgba(5,17,34,0.84); border: 0; border-top: 1px solid rgba(54,211,255,0.17); border-radius: 12px; top: -1px; }
QTabBar::tab { background: rgba(9,27,51,0.82); padding: 10px 23px; border: 1px solid transparent; border-radius: 10px; margin: 4px; color: $muted; font-weight: 650; }
QTabBar::tab:hover { background: rgba(18,53,80,0.82); color: $text; }
QTabBar::tab:selected { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(9,90,94,0.8),stop:1 rgba(13,52,76,0.82)); border-color: rgba(35,245,224,0.42); color: #bcfff8; font-weight: 850; }
QTabBar::tab:focus { border-color: $accent; }
QTabBar::tab:disabled { color: #425a73; background: #081525; }
QListWidget#manualConfigList, QListWidget#userConfigList, QListWidget#suggestedConfigList { background: transparent; border: 0; border-radius: 0; padding: 4px; }
QListWidget#manualConfigList::item { min-height: 54px; background: rgba(9,28,53,0.86); border: 1px solid rgba(62,113,154,0.34); border-radius: 11px; padding: 9px 12px; margin: 2px 4px; color: #d8e6f3; }
QListWidget#userConfigList::item, QListWidget#suggestedConfigList::item { min-height: 44px; background: rgba(9,28,53,0.86); border: 1px solid rgba(62,113,154,0.34); border-radius: 9px; padding: 6px 10px; margin: 1px 3px; color: #d8e6f3; }
QListWidget#manualConfigList::item:hover, QListWidget#userConfigList::item:hover, QListWidget#suggestedConfigList::item:hover { background: rgba(13,45,70,0.92); border-color: rgba(54,211,255,0.38); }
QListWidget#manualConfigList::item:selected, QListWidget#userConfigList::item:selected, QListWidget#suggestedConfigList::item:selected { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(8,81,89,0.88),stop:1 rgba(12,47,75,0.9)); border: 1px solid rgba(35,245,224,0.7); color: #ffffff; }
QListWidget#userConfigList::item:disabled { min-height: 24px; background: rgba(8,47,66,0.88); border: 1px solid rgba(35,245,224,0.24); border-radius: 8px; padding: 4px 10px; margin: 5px 3px 1px 3px; color: #79efe7; }
QFrame#profileListRow { background: transparent; border: 0; }
QLabel#profileRowIcon { background: transparent; border: 0; }
QLabel#profileRowTitle { background: transparent; border: 0; color: #eef8ff; font-size: 12px; font-weight: 750; }
QLabel#profileRowDetail { background: transparent; border: 0; color: #9fdcf0; font-size: 11px; }
QLabel#profileRowRecommendation { background: transparent; border: 0; color: #8ff9eb; font-size: 10px; font-weight: 750; }
QToolButton#profileRowActivate { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #21e5cf,stop:1 #34bdf5); border: 1px solid rgba(168,255,247,0.72); border-radius: 8px; padding: 0 9px; color: #061923; font-size: 11px; font-weight: 850; }
QToolButton#profileRowActivate:hover { background: #7bfff1; border-color: #ffffff; }
QToolButton#profileRowActivate[active="true"] { background: rgba(25,111,111,0.72); border-color: rgba(87,235,218,0.5); color: #c8fff9; }
QToolButton#profileRowEdit, QToolButton#profileRowDelete { background: rgba(9,31,55,0.88); border: 1px solid rgba(74,130,168,0.42); border-radius: 8px; padding: 0; }
QToolButton#profileRowEdit:hover { background: rgba(21,73,98,0.94); border-color: rgba(98,220,255,0.78); }
QToolButton#profileRowDelete:hover { background: rgba(91,25,45,0.94); border-color: rgba(255,98,125,0.86); }
QLabel#profileRowPing { background: rgba(10,31,54,0.98); border: 1px solid rgba(86,135,173,0.55); border-radius: 9px; color: #8faac1; font-family: "Cascadia Mono", "Segoe UI"; font-size: 12px; font-weight: 900; }
QLabel#profileRowPing[state="fast"] { background: rgba(10,82,75,0.92); border-color: rgba(35,245,166,0.72); color: #b9ffeb; }
QLabel#profileRowPing[state="medium"] { background: rgba(88,67,18,0.9); border-color: rgba(255,209,102,0.7); color: #ffe8a8; }
QLabel#profileRowPing[state="slow"] { background: rgba(89,29,49,0.92); border-color: rgba(255,92,124,0.72); color: #ffc0ce; }
QFrame#profileSelectionBar { background: rgba(7,27,49,0.98); border: 1px solid rgba(54,211,255,0.22); border-radius: 9px; }
QLabel#profileSelectionLabel { background: transparent; border: 0; color: #a9c7dc; font-size: 11px; font-weight: 700; }
QCheckBox#profileSelectAll { background: transparent; border: 0; padding: 0; }
QComboBox#profileSortCombo { background: rgba(5,22,40,0.98); border: 1px solid rgba(82,148,188,0.52); border-radius: 8px; padding: 3px 9px; font-size: 11px; font-weight: 700; }

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

QDialog#advancedDialog, QDialog#profileDialog, QDialog#closeChoiceDialog, QMessageBox, QMessageBox#cyberMessageBox { background: #071225; border: 1px solid rgba(54,211,255,0.32); }
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
QDialog#closeChoiceDialog { border: 1px solid rgba(35,245,224,0.52); }
QLabel#closeChoiceIcon { background: rgba(11,62,77,0.78); border: 1px solid rgba(35,245,224,0.38); border-radius: 12px; }
QLabel#closeChoiceTitle { color: #f7fcff; font-size: 17px; font-weight: 900; }
QLabel#closeChoiceText { color: #c4d7e9; font-size: 12px; }
QLabel#closeChoiceDetail { color: #7fa2bd; font-size: 11px; padding: 3px 2px; }
QDialog#closeChoiceDialog QPushButton { min-height: 36px; padding: 6px 10px; }
QPushButton#trayChoiceButton { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 $accent,stop:1 $accent2); border: 1px solid rgba(199,255,250,0.86); color: #031422; font-weight: 900; }
QPushButton#trayChoiceButton:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #5ffbe9,stop:1 #61dcff); border-color: #e3ffff; }

QFrame#updateNotification { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(7,57,66,0.99),stop:0.5 rgba(8,32,61,0.99),stop:1 rgba(31,24,79,0.99)); border: 1px solid rgba(94,255,235,0.72); border-radius: 20px; }
QFrame#updateNotificationAccent { background: qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #a7fff6,stop:0.5 #23f5e0,stop:1 #2cc7ff); border: 0; border-radius: 2px; }
QLabel#updateNotificationIcon { background: qradialgradient(cx:0.4,cy:0.32,radius:0.8,stop:0 rgba(77,255,235,0.38),stop:1 rgba(9,69,88,0.82)); border: 1px solid rgba(131,255,243,0.48); border-radius: 17px; qproperty-alignment: AlignCenter; }
QLabel#updateNotificationEyebrow { color: #71fff0; font-size: 9px; font-weight: 900; letter-spacing: 1.7px; }
QLabel#updateNotificationTitle { color: #ffffff; font-size: 19px; font-weight: 900; }
QLabel#updateNotificationDetail { color: #c1d8e9; font-size: 12px; font-weight: 600; }
QPushButton#updateNotificationPrimary { min-height: 20px; padding: 4px 12px; color: #031422; background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #23f5e0,stop:1 #36c8ff); border: 1px solid rgba(220,255,252,0.92); border-radius: 12px; font-size: 12px; font-weight: 900; }
QPushButton#updateNotificationPrimary:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #76ffef,stop:1 #78dcff); border-color: #ffffff; }

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
