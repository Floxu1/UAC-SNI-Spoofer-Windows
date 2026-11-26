from __future__ import annotations

import os
import concurrent.futures
import ctypes
import html
import ipaddress
import math
import re
import socket
import sys
import threading
import time
import uuid
import webbrowser
from dataclasses import replace

import psutil
import requests
from PySide6.QtCore import (
    QEvent, QObject, Qt, QTimer, Signal, QSize, QRect, QRectF, QPointF, QPoint, QPropertyAnimation,
    QEasingCurve, Property, QParallelAnimationGroup, QSignalBlocker, QItemSelectionModel, QVariantAnimation,
)
from PySide6.QtGui import (
    QColor, QFont, QIcon, QImage, QPainter, QPen, QLinearGradient, QIntValidator,
    QRadialGradient, QPainterPath, QPixmap, QFontMetrics,
    QTextCursor, QTextCharFormat, QAction,
)
from PySide6.QtWidgets import (
    QAbstractButton, QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog,
    QFileDialog, QFrame, QGridLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QListWidget, QListWidgetItem, QMainWindow, QMessageBox, QPlainTextEdit,
    QPushButton, QScrollArea, QStackedWidget, QTableView,
    QTableWidget, QTableWidgetItem, QTableWidgetSelectionRange,
    QTabBar, QTabWidget, QTextEdit, QVBoxLayout, QWidget, QSizePolicy, QGraphicsDropShadowEffect,
    QGraphicsOpacityEffect, QBoxLayout, QStyle, QStyleOptionButton, QStyleOptionComboBox, QToolButton,
    QSystemTrayIcon, QMenu, QToolTip, QScrollBar,
)

from . import __version__
from .app_config import PROJECT_URL, UPDATE_REPOSITORY_URL
ASSISTANT_FEATURE_ENABLED = False
if ASSISTANT_FEATURE_ENABLED:
    try:
        from .assistant import AssistantController
        _ASSISTANT_IMPORT_ERROR = ""
    except Exception as exc:
        AssistantController = None
        _ASSISTANT_IMPORT_ERROR = str(exc)
else:
    AssistantController = None
    _ASSISTANT_IMPORT_ERROR = ""
from .device_names import DeviceNameResolver, DeviceNameResult
from .engine import Engine, EngineCancelled, format_bytes, mci_quality_score
from . import gene_pool
from .connect_summary import gene_label as _cs_gene_label
from . import clean_ip as _clean_ip
from .gene_import import display_label as gene_display_label, gene_edge_ips, load_strategies_file
from .models import (
    MCI_PROTECTED_FAKE_REPEAT as MCI_BUILTIN_FAKE_REPEAT,
    MCI_PROTECTED_FAKE_SNI as MCI_BUILTIN_FAKE_SNI,
    MCI_PROTECTED_FALLBACK_EDGES as MCI_BUILTIN_FALLBACK_EDGES,
    MCI_PROTECTED_INJECT_DELAY_MS as MCI_BUILTIN_INJECT_DELAY_MS,
    MCI_PROTECTED_PRIMARY_EDGE as MCI_BUILTIN_PRIMARY_EDGE,
    MCI_PROTECTED_ROUTE_PLANS as MCI_BUILTIN_ROUTE_PLANS,
    ProxyProfile, Tuning, parse_many, parse_outbound,
)
from .network import (GeoLocation, ScanResult, current_ip, current_location,
                      profile_ping, profile_real_delay, scan_domains, tcp_ping)
from .paths import ASSETS, DATA_DIR, LOG_FILE
from .network_metrics import SharedNetworkMetrics
from .traffic import SessionTraffic
from .profile_dialog import ProfileDialog
from .sni_lab_ui import MetricSortItem, NumberedDomainEdit, result_metric
from .direct_dns_ui import DirectDnsLab
from .direct_routing_view import SharedDirectRoutingView
from .sni_batch import LiveConfigResult, SniBatchTester
from .models import is_direct_route as _is_direct_route, route_label as _route_label, is_ech_route as _is_ech_route
from .sni_maker import (
    DEFAULT_REPOSITORY_URL as DEFAULT_SNI_MAKER_URL, SniConfigMaker, SniImportResult, config_signature,
)
from .sni_maker_widgets import (
    ConfigDropEdit, CountryRail, MakerColumns, MakerFilterProxy,
    MakerResultsModel, MakerRoles, normalize_country_code,
)
from .storage import Storage
from .velocity_flow import VelocityFlow
from . import direct_theme as _direct_theme
from . import desktop_layout as _layout
from . import quick_controls as _quick_controls
from .application_settings import ApplicationSettings
from .app_routing_view import SharedAppRoutingView, app_routing_style, running_apps, supports_process_routing
from .auto_connect import AutoConnect
from .settings_ui import (
    GLOBAL_SETTINGS_STYLE, SettingsCard, SettingsGrid, SettingsPage, SettingsRow, SettingsSelect, SharedGlobalSettings,
    shared_global_settings_style,
)
from .pow_ui import ENGINE_POW, ENGINE_XRAY, PowController
from .direct_ui import ENGINE_DIRECT, DirectPanel
from .icons import icon as _raw_cyber_icon, pixmap as _raw_cyber_pixmap
from . import theme as _theme
from . import fonts as _fonts

_BaseQColor = QColor


def QColor(*args):
    """QColor that follows the active engine theme (UAC PoW = mint on
    green-black). Painted widgets build their colours at paint time, so they
    switch with the engine without per-widget code. A factory (not a
    subclass) so Qt overload resolution stays exact."""
    color = _BaseQColor(*args)
    if (_theme.is_pow() or _theme.is_direct()) and color.isValid():
        mapper = _theme.direct_rgba if _theme.is_direct() else _theme.map_rgba
        r, g, b = mapper(color.red(), color.green(), color.blue(), color.alpha())
        color.setRgb(r, g, b, color.alpha())
    return color


# (kind, cacheKey) -> (name, original colour, size) so artwork can be
# regenerated when the engine theme changes.
_THEMED_ART: dict = {}


# Rendered icon art per (kind, name, colour, theme colour, size, palette).
# Engine switches re-theme ~200 icons; re-rendering the SVGs each time cost
# ~20 ms of frozen UI, so both themes' art is kept once rendered.
_ART_CACHE: dict = {}


def _cyber_art(kind, name, color, size, themed_color=None):
    themed_color = _theme.themed(color) if themed_color is None else themed_color
    lucide = _theme.is_direct()
    key = (kind, name, color, themed_color, size, _theme.palette_version(), lucide)
    try:
        art = _ART_CACHE.get(key)
    except TypeError:  # unhashable colour object: render uncached
        key, art = None, None
    if art is None:
        render = _raw_cyber_pixmap if kind == "p" else _raw_cyber_icon
        art = render(name, themed_color, size, lucide=lucide)
        if key is not None:
            _ART_CACHE[key] = art
        _THEMED_ART[(kind, art.cacheKey())] = (name, color, size)
    return art


def cyber_pixmap(name, color="#9fb4d8", size=22):
    return _cyber_art("p", name, color, size)


def cyber_icon(name, color="#9fb4d8", size=22):
    return _cyber_art("i", name, color, size)


def prewarm_themed_art(limit=None) -> int:
    """Render both themes' variants of known icon art (idle-time helper).

    Returns how many variants were rendered; call again until it returns 0.
    """
    rendered = 0
    for kind, _key in list(_THEMED_ART):
        name, color, size = _THEMED_ART[(kind, _key)]
        for themed_color in (color, _theme.map_hex(color) if isinstance(color, str) else color):
            cache_key = (kind, name, color, themed_color, size, _theme.palette_version(), False)
            try:
                if cache_key in _ART_CACHE:
                    continue
            except TypeError:
                continue
            _cyber_art(kind, name, color, size, themed_color)
            rendered += 1
            if limit is not None and rendered >= limit:
                return rendered
    return rendered


def _cube_pixmap(size: int = 46) -> QPixmap:
    """Isometric cube mark used by the UAC PoW brand."""
    ratio = 2.0
    art = QPixmap(int(size * ratio), int(size * ratio))
    art.setDevicePixelRatio(ratio)
    art.fill(Qt.transparent)
    painter = QPainter(art)
    painter.setRenderHint(QPainter.Antialiasing, True)
    cx, top, w = size / 2.0, size * 0.06, size * 0.44
    h = w * 0.58
    bottom = size * 0.94
    p_top = QPointF(cx, top); p_l = QPointF(cx - w, top + h); p_r = QPointF(cx + w, top + h)
    p_c = QPointF(cx, top + 2 * h); p_lb = QPointF(cx - w, bottom - h); p_rb = QPointF(cx + w, bottom - h)
    p_b = QPointF(cx, bottom)

    def face(points, color):
        path = QPainterPath(points[0])
        for point in points[1:]:
            path.lineTo(point)
        path.closeSubpath()
        painter.fillPath(path, _BaseQColor(color))

    pal = _theme.POW_PALETTE
    face([p_top, p_r, p_c, p_l], pal["cube_top"])
    face([p_l, p_c, p_b, p_lb], pal["cube_left"])
    face([p_c, p_r, p_rb, p_b], pal["cube_right"])
    inner = 0.42
    i_top = QPointF(cx, top + h * (1 - inner)); i_l = QPointF(cx - w * inner, top + h)
    i_r = QPointF(cx + w * inner, top + h); i_c = QPointF(cx, top + h * (1 + inner))
    face([i_top, i_r, i_c, i_l], pal["cube_hole"])
    painter.setPen(QPen(_BaseQColor(255, 255, 255, 70), 1.0))
    painter.drawLine(p_c, p_b)
    painter.end()
    return art


def _engine_mark(engine, size, accent):
    if engine == ENGINE_POW:
        return _cube_pixmap(size)
    return _raw_cyber_pixmap("zap" if engine == ENGINE_DIRECT else "shield", accent, size, lucide=True)


def _accent_state_word(text: str) -> str:
    """Highlight OFF/ON (or the Persian words) in the hero title."""
    import re as _re
    plain = _re.sub(r"<[^>]+>", "", text or "")
    if _theme.is_pow():
        accent = _theme.accent()
        words = ("OFF", "ON", "خاموش", "روشن", "متصل")
    elif _theme.is_direct():
        connected = plain == "VPN is ON" or "متصل" in plain
        accent = _direct_theme.HERO_CONNECTED_WORD if connected else _direct_theme.CONNECTION_ACCENTS["disconnected"]
        words = ("ON", "متصل") if connected else ("OFF", "خاموش")
    else:
        return plain
    for word in words:
        if word in plain:
            marked = plain.replace(word, f"<span style='color:{accent}'>{word}</span>", 1)
            if any("\u0600" <= ch <= "\u06ff" for ch in plain):
                # Rich text picks direction from the first strong letter
                # ("VPN"); keep the Persian sentence right-to-left.
                return f"<p dir='rtl'>{marked}</p>"
            return marked
    return plain
from .update_checker import SemVersion, UpdateInfo, check_latest_release, parse_github_repository
from .verified_configs import COUNTRIES, VERIFIED_SPOOF_EDGE, VERIFIED_SPOOF_FAKE_SNI


DEFAULT_UPDATE_REPO_URL = UPDATE_REPOSITORY_URL
PREVIOUS_SNI_MAKER_URL = "https://gitverse.ru/api/repos/flaafix/AetrisVPN_Black_list/raw/branch/master/configs.txt"
LEGACY_SNI_MAKER_URLS = frozenset({
    "https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt",
    "https://raw.githubusercontent.com/patterniha/Free-Configs/refs/heads/main/configs.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/Sub/refs/heads/main/config/sni/all_configs_sni.txt",
})
USER_CONFIG_ORIGIN = "sni-maker"
AUTO_LATENCY_KEY = "auto_latency"
AUTO_LATENCY_FRESH_SECONDS = 20 * 60
# Lower = nearer to Iran (tie-breaker only; measured latency always wins).
REGION_RANK = {code: 0 for code in ("TR", "AE", "AM", "GE", "AZ", "QA", "BH", "OM", "KW", "IQ")}
REGION_RANK.update({code: 1 for code in ("DE", "NL", "FI", "SE", "AT", "CH", "PL", "CZ", "BG", "RO", "HU", "FR", "GB",
                                         "IT", "GR", "CY", "LT", "LV", "EE", "NO", "DK", "BE", "LU", "SA", "IL")})
REGION_RANK.update({code: 2 for code in ("RU", "UA", "ES", "PT", "IE", "KZ", "IN", "PK", "EG", "RS", "MD")})
AUTO_LATENCY_BUCKET_MS = 150


def region_rank(code: str) -> int:
    return REGION_RANK.get(str(code or "").upper(), 3)


AUTO_QUALITY_POOL = 8


def auto_quality_score(quality: dict) -> tuple[float, dict]:
    """Lower is better. Median 204 latency + half the median page load, with
    heavy penalties for failed/503 samples (a dropped request hurts more than
    a slow one)."""
    import statistics as _st
    s204 = list((quality or {}).get("s204") or [])
    pages = list((quality or {}).get("pages") or [])
    ok204 = [float(x) for x in s204 if x]
    okpg = [float(x) for x in pages if x]
    n204, npg = max(1, len(s204)), max(1, len(pages))
    med204 = _st.median(ok204) if ok204 else 3000.0
    medpg = _st.median(okpg) if okpg else 8000.0
    fail204 = (n204 - len(ok204)) / n204
    failpg = (npg - len(okpg)) / npg
    score = med204 + 0.5 * medpg + 3000.0 * fail204 + 4000.0 * failpg
    return round(score, 1), {"med204": round(med204), "ok204": f"{len(ok204)}/{n204}",
                             "page": round(medpg), "okpage": f"{len(okpg)}/{npg}"}


def auto_latency_rank(profiles, measured: dict):
    """measured: {profile_id: {'ok','ms'}} fresh results. Order: fresh OK by
    latency bucket -> region -> ms; then untested by last-test ping/region;
    fresh failures last. Stable for equal keys."""
    def key(item):
        index, profile = item
        code = profile.observed_country_code or profile.country_code
        value = measured.get(profile.id)
        if value and value.get("ok") and float(value.get("ms", 0) or 0) > 0:
            ms = float(value["ms"])
            return (0, int(ms // AUTO_LATENCY_BUCKET_MS), region_rank(code), ms, index)
        if value:
            return (2, 0, region_rank(code), 0.0, index)
        ms = float(profile.last_ping_ms or 0) if profile.last_ping_ok and profile.last_ping_ms > 0 else 999999.0
        return (1, int(ms // AUTO_LATENCY_BUCKET_MS), region_rank(code), ms, index)
    return [profile for _i, profile in sorted(enumerate(profiles), key=key)]
MANUAL_PROFILE_ORIGINS = frozenset({"user"})
USER_CONFIG_ORIGINS = frozenset({USER_CONFIG_ORIGIN})
DIRECT_PROFILE_ORIGINS = MANUAL_PROFILE_ORIGINS | USER_CONFIG_ORIGINS
BUILTIN_PROFILE_SNI_HINTS = {
    "www.calmlunch.com": ("chatgpt.com", "support.cloudflare.com"),
    "www.ignitelimit.com": ("support.cloudflare.com", "chatgpt.com"),
    "www.gossipglove.com": ("support.cloudflare.com", "chatgpt.com"),
    "www.multiplydose.com": ("support.cloudflare.com", "chatgpt.com"),
    "cdn.veilvpn.fans": ("chatgpt.com", "support.cloudflare.com"),
}
BUILTIN_ROUTE_CACHE_TTL_S = 7 * 24 * 3600
MCI_BUILTIN_WEB_GATE = "Google + YouTube web check v2"
MCI_BUILTIN_WEB_GATE_MIN_BYTES = 1024


HIGH_QUALITY_RENDER_HINTS = (
    QPainter.RenderHint.Antialiasing
    | QPainter.RenderHint.TextAntialiasing
    | QPainter.RenderHint.SmoothPixmapTransform
    | QPainter.RenderHint.LosslessImageRendering
    | QPainter.RenderHint.VerticalSubpixelPositioning
)


def _set_high_quality_rendering(painter):
    painter.setRenderHints(HIGH_QUALITY_RENDER_HINTS, True)


_FLAG_CACHE: dict = {}


def _flag_png(code: str, kind: str = "4x3"):
    """Bundled flag-icons PNG (assets/flags/<kind>/<cc>.png) or None."""
    code = str(code or "").strip().lower()
    key = (code, kind)
    if key not in _FLAG_CACHE:
        pixmap = None
        if len(code) == 2 and code.isalpha():
            path = ASSETS / "flags" / kind / f"{code}.png"
            if path.exists():
                loaded = QPixmap(str(path))
                pixmap = loaded if not loaded.isNull() else None
        _FLAG_CACHE[key] = pixmap
    return _FLAG_CACHE[key]


def country_flag_badge(code: str, size: int = 38) -> QPixmap:
    """Round flag badge (square flag art clipped to a circle with a soft ring)."""
    ratio = 2.0
    pixmap = QPixmap(int(size * ratio), int(size * ratio))
    pixmap.setDevicePixelRatio(ratio)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    _set_high_quality_rendering(painter)
    rect = QRectF(1.0, 1.0, size - 2.0, size - 2.0)
    clip = QPainterPath(); clip.addEllipse(rect)
    flag = _flag_png(code, "1x1")
    if flag is not None:
        painter.setClipPath(clip)
        painter.drawPixmap(rect, flag, QRectF(0, 0, flag.width(), flag.height()))
        painter.setClipping(False)
    else:
        painter.setPen(Qt.NoPen); painter.setBrush(QColor("#164e63")); painter.drawEllipse(rect)
        painter.setPen(QColor("#ffffff"))
        painter.setFont(QFont(_fonts.LATIN, max(7, int(size * 0.3)), QFont.Weight.Medium))
        painter.drawText(rect, Qt.AlignCenter, str(code or "").upper()[:2])
    painter.setBrush(Qt.NoBrush)
    painter.setPen(QPen(QColor(255, 255, 255, 120), 1.2))
    painter.drawEllipse(rect)
    painter.end()
    return pixmap


def bolt_badge(size: int = 38) -> QPixmap:
    """Round 'Automatic' badge matching the flag badge."""
    ratio = 2.0
    pixmap = QPixmap(int(size * ratio), int(size * ratio))
    pixmap.setDevicePixelRatio(ratio)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    _set_high_quality_rendering(painter)
    rect = QRectF(1.0, 1.0, size - 2.0, size - 2.0)
    gradient = QLinearGradient(rect.topLeft(), rect.bottomRight())
    gradient.setColorAt(0.0, QColor("#35f0dc")); gradient.setColorAt(1.0, QColor("#2f8fff"))
    painter.setPen(QPen(QColor(205, 255, 251, 170), 1.2)); painter.setBrush(gradient); painter.drawEllipse(rect)
    icon_size = int(size * 0.5)
    bolt = cyber_pixmap("zap", "#031422", icon_size)
    painter.drawPixmap(int((size - icon_size) / 2), int((size - icon_size) / 2), icon_size, icon_size, bolt)
    painter.end()
    return pixmap


def country_flag_icon(code: str, width: int = 30, height: int = 20) -> QIcon:
    """Country flag from the bundled flag-icons set; drawn fallback otherwise
    (Qt on Windows renders emoji flags as letters)."""
    code = str(code or "").upper()
    flag = _flag_png(code, "4x3")
    if flag is not None:
        ratio = 2.0
        pixmap = QPixmap(int(width * ratio), int(height * ratio))
        pixmap.setDevicePixelRatio(ratio)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        _set_high_quality_rendering(painter)
        rect = QRectF(0.75, 0.75, width - 1.5, height - 1.5)
        clip = QPainterPath(); clip.addRoundedRect(rect, 3.0, 3.0)
        painter.setClipPath(clip)
        # Cover-crop the 4:3 art into the requested box.
        scale = max(width / flag.width(), height / flag.height())
        src_w, src_h = width / scale, height / scale
        source = QRectF((flag.width() - src_w) / 2, (flag.height() - src_h) / 2, src_w, src_h)
        painter.drawPixmap(QRectF(0, 0, width, height), flag, source)
        painter.setClipping(False)
        painter.setPen(QPen(QColor(255, 255, 255, 80), 1.0))
        painter.setBrush(Qt.NoBrush)
        painter.drawRoundedRect(rect, 3.0, 3.0)
        painter.end()
        return QIcon(pixmap)
    pixmap = QPixmap(width, height)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    _set_high_quality_rendering(painter)
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
        painter.setFont(QFont(_fonts.LATIN, max(7, int(height * 0.42)), QFont.Weight.Medium))
        painter.drawText(rect, Qt.AlignCenter, code if len(code) == 2 else "•")
    painter.setClipping(False)
    painter.setPen(QPen(QColor(255, 255, 255, 105), 1.0))
    painter.setBrush(Qt.NoBrush)
    painter.drawRoundedRect(rect, 3.0, 3.0)
    painter.end()
    return QIcon(pixmap)

FA_EN = {
    "خانه": "Home", "کانفیگ‌ها": "Configs", "آزمایشگاه SNI": "SNI Lab",
    "لاگ زنده": "Live Logs", "عبور مستقیم برنامه‌ها": "App Bypass", "ابزارها": "Tools", "یو‌ای‌سی پاو": "UAC PoW", "پشتیبانی": "Support",
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
    engine_log = Signal(str, str)
    state = Signal(bool)
    traffic = Signal(object)
    target_latency = Signal(object, object, int)
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
    processes_failed = Signal(str)
    update_checked = Signal(object, int)
    update_failed = Signal(str, int, bool)
    proxy_mode_applied = Signal(bool, bool, str, int, int)
    tun_mode_applied = Signal(bool, bool, str, int, int)
    gateway_mode_applied = Signal(bool, bool, str, int, int)
    gateway_runtime_state = Signal(str, int, str)
    gateway_devices_changed = Signal(object)
    gateway_device_names_changed = Signal(object)
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
        _set_high_quality_rendering(painter)
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
        _set_high_quality_rendering(painter)
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
        if self.objectName() == "xraySettingsHeader":
            return
        painter = QPainter(self)
        _set_high_quality_rendering(painter)
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
        self.set_help(help_text, rtl)

    def set_help(self, help_text, rtl):
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
        if _theme.is_direct():
            return
        painter = QPainter(self)
        _set_high_quality_rendering(painter)
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
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("heroCard")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self._wave_state = "disconnected"
        self._direct = _theme.is_direct()
        self._engine = ENGINE_DIRECT if self._direct else ENGINE_POW if _theme.is_pow() else ENGINE_XRAY
        self._velocity_flow = None
        self._edge_colors = self._edge_start = self._edge_target = _direct_theme.connection_edge_colors("disconnected")
        self._edge_transition = QVariantAnimation(self)
        self._edge_transition.setStartValue(0.0)
        self._edge_transition.setEndValue(1.0)
        self._edge_transition.setDuration(_direct_theme.CONNECTION_BORDER_MS)
        self._edge_transition.setEasingCurve(QEasingCurve.InOutCubic)
        self._edge_transition.valueChanged.connect(self._update_edge_colors)
        self.orb = None

    def set_atmosphere(self, engine):
        direct = engine == ENGINE_DIRECT
        if direct != self._direct:
            self._edge_transition.stop()
            self._edge_colors = self._edge_start = self._edge_target = _direct_theme.connection_edge_colors("disconnected")
        self._direct = direct
        self._engine = engine
        if self._velocity_flow is not None:
            self._velocity_flow.set_engine(engine)
        self._sync_atmosphere_motion(self.isVisible())
        self.update()

    def _sync_atmosphere_motion(self, visible):
        running = bool(visible and _animations_enabled() and not self.window().isMinimized())
        if self._direct and self.orb is not None:
            self.orb.set_direct_motion(running)
        if visible and self._velocity_flow is None and QApplication.platformName() == "windows":
            QTimer.singleShot(0, self, self._start_velocity_flow)
        if self._velocity_flow is not None:
            self._velocity_flow.set_active(visible, running)

    def _start_velocity_flow(self):
        if self._velocity_flow is not None or not self.isVisible():
            return
        self._velocity_flow = VelocityFlow(self, self.orb, self._engine)
        self.window().installEventFilter(self)
        self._velocity_flow.set_connection_state(self._wave_state)
        self._sync_atmosphere_motion(True)

    def eventFilter(self, watched, event):
        if event.type() == QEvent.WindowStateChange and watched is self.window():
            self._sync_atmosphere_motion(self.isVisible())
        return super().eventFilter(watched, event)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._velocity_flow is not None:
            self._velocity_flow.fit_card()

    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() == QEvent.LayoutDirectionChange:
            self.update()

    def showEvent(self, event):
        super().showEvent(event)
        self._sync_atmosphere_motion(True)

    def hideEvent(self, event):
        self._sync_atmosphere_motion(False)
        super().hideEvent(event)

    def set_wave_state(self, state, *, direct_color_state=None):
        if self._direct:
            target = _direct_theme.connection_edge_colors(direct_color_state or state)
            if target != self._edge_target:
                self._edge_transition.stop()
                self._edge_start, self._edge_target = self._edge_colors, target
                if _animations_enabled() and self.isVisible():
                    self._edge_transition.start()
                else:
                    self._update_edge_colors(1.0)
        self._wave_state = state
        if self._velocity_flow is not None:
            self._velocity_flow.set_connection_state(state)

    def _update_edge_colors(self, progress):
        self._edge_colors = tuple(
            _BaseQColor.fromRgbF(*(start + (end - start) * progress
                                  for start, end in zip(a.getRgbF()[:3], b.getRgbF()[:3])))
            for a, b in zip(self._edge_start, self._edge_target)
        )
        self.update()

    def set_wave_traffic(self, sent, received):
        if self._velocity_flow is not None:
            self._velocity_flow.set_traffic_counters(sent, received)

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        _set_high_quality_rendering(painter)
        if self._direct:
            painter.save()
            _direct_theme.paint_card_wash(painter, QRectF(self.rect()))
            if self._velocity_flow is not None:
                self._velocity_flow.paint(painter)
            painter.restore()
            _direct_theme.paint_connection_edge(painter, QRectF(self.rect()), *self._edge_colors)
            return
        width, height = self.width(), self.height()

        glow = QRadialGradient(QPointF(width * .74, height * .47), max(130, height * .92))
        glow.setColorAt(0, QColor(35, 245, 224, 24))
        glow.setColorAt(.48, QColor(44, 199, 255, 9))
        glow.setColorAt(1, QColor(5, 11, 24, 0))
        painter.fillRect(self.rect(), glow)
        if self._velocity_flow is not None:
            self._velocity_flow.paint(painter)


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
            _set_high_quality_rendering(painter)
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
        if self.isChecked() and not _theme.is_direct():
            if self.layoutDirection() != Qt.RightToLeft:
                painter = QPainter(self)
                _set_high_quality_rendering(painter)
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


class QuickControlsGrid(QGridLayout):
    equal_columns = 0

    def setGeometry(self, rect):
        if self.equal_columns:
            margins = self.contentsMargins()
            gaps = (self.equal_columns - 1) * self.horizontalSpacing()
            available = rect.width() - margins.left() - margins.right() - gaps
            remainder = max(available, 0) % self.equal_columns
            rect = rect.adjusted(remainder // 2, 0, -(remainder - remainder // 2), 0)
        super().setGeometry(rect)


class QuickCarrierCombo(QComboBox):
    arrow_color = None

    def paintEvent(self, event):
        super().paintEvent(event)
        if self.arrow_color:
            option = QStyleOptionComboBox()
            self.initStyleOption(option)
            rect = self.style().subControlRect(QStyle.CC_ComboBox, option, QStyle.SC_ComboBoxArrow, self)
            arrow = _raw_cyber_pixmap("chevron-down", self.arrow_color, 11, lucide=True)
            bounds = QStyle.alignedRect(option.direction, Qt.AlignCenter, QSize(11, 11), rect)
            painter = QPainter(self)
            painter.drawPixmap(bounds.topLeft(), arrow)


class QuickSettingsButton(GlowButton):
    quick_palette = None

    def paintEvent(self, event):
        if self.quick_palette is None:
            super().paintEvent(event)
            return
        painter = QPainter(self)
        _set_high_quality_rendering(painter)
        option = QStyleOptionButton()
        self.initStyleOption(option)
        option.text = ""
        option.icon = QIcon()
        self.style().drawControl(QStyle.CE_PushButton, option, painter, self)

        direction = self.layoutDirection()
        rtl = direction == Qt.RightToLeft
        bounds = self.rect()
        content = bounds.adjusted(11, 0, -11, 0)
        icon = QRect(content.left(), (bounds.height() - 16) // 2, 16, 16)
        chevron = QRect(content.right() - 12, (bounds.height() - 13) // 2, 13, 13)
        label = content.adjusted(23, 0, -19, 0)
        self.icon().paint(painter, QStyle.visualRect(direction, bounds, icon))
        arrow = _raw_cyber_pixmap("chevron-left" if rtl else "chevron-right",
                                 self.quick_palette["icon"], 13, lucide=True)
        painter.drawPixmap(QStyle.visualRect(direction, bounds, chevron), arrow)
        painter.setPen(option.palette.buttonText().color())
        painter.setFont(self.font())
        alignment = Qt.AlignRight if rtl else Qt.AlignLeft
        text = self.fontMetrics().elidedText(self.text(), Qt.ElideRight, label.width())
        painter.drawText(QStyle.visualRect(direction, bounds, label),
                         alignment | Qt.AlignAbsolute | Qt.AlignVCenter | Qt.TextSingleLine, text)


#: PoW Home HTTP/2 fragment switch label (Persian from the Home page) + auto tag.
_POW_H2_FA = 'فرگمنت HTTP/2'
_POW_AUTO_FA = 'خودکار'


class ToggleSwitch(QCheckBox):
    """Keyboard-accessible custom switch without native checkbox chrome."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("toggleSwitch")
        self.setFixedSize(48, 26)
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.StrongFocus)
        self._thumb_position = 0.0
        self._quick_palette = None
        self._thumb_animation = QPropertyAnimation(self, b"thumbPosition", self)
        self._thumb_animation.setDuration(260)
        self._thumb_animation.setEasingCurve(QEasingCurve.OutBack)
        self.toggled.connect(self._animate_thumb)

    def set_quick_style(self, palette):
        if palette is self._quick_palette:
            return
        self._quick_palette = palette
        self.setFixedSize(*(_layout.QUICK_SWITCH_TARGET if palette else (48, 26)))
        self._thumb_animation.stop()
        self._thumb_animation.setDuration(_quick_controls.SWITCH_MS if palette else 260)
        self._thumb_animation.setEasingCurve(QEasingCurve.InOutCubic if palette else QEasingCurve.OutBack)
        self._set_thumb_position(float(self.isChecked()))

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
        return QSize(*(_layout.QUICK_SWITCH_TARGET if self._quick_palette else (48, 26)))

    def hitButton(self, pos):
        """Make the complete painted switch clickable, not only native chrome."""
        return self.rect().contains(pos)

    def paintEvent(self, event):
        painter = QPainter(self)
        _set_high_quality_rendering(painter)
        enabled = self.isEnabled()
        checked = self.isChecked()
        palette = self._quick_palette
        if palette or _theme.is_direct():
            running = self._thumb_animation.state() == QPropertyAnimation.Running
            position = self._thumb_position if running else float(checked)
            w, h = self.width(), self.height()
            track = QRectF(1, 2, w - 2, h - 4)
            track_color = _BaseQColor("#ee935a" if checked and enabled else "#36383c")
            thumb_color = _BaseQColor("#fff2e9" if checked and enabled else "#95979e")
            if palette:
                width, height = _layout.QUICK_SWITCH
                track = QRectF((w - width) / 2, (h - height) / 2, width, height)
                off = _BaseQColor(palette["track_off"])
                on = _BaseQColor(palette["track_on"])
                progress = position if enabled else 0.0
                track_color = _BaseQColor.fromRgbF(*(start + (end - start) * progress
                                                    for start, end in zip(off.getRgbF()[:3], on.getRgbF()[:3])))
                thumb_color = _BaseQColor(palette["thumb_on" if checked and enabled else "thumb_off"])
            painter.setPen(Qt.NoPen)
            painter.setBrush(track_color)
            radius = track.height() / 2
            painter.drawRoundedRect(track, radius, radius)
            painter.setBrush(thumb_color)
            if self.layoutDirection() == Qt.RightToLeft:
                position = 1 - position
            travel = track.width() - track.height() if palette else w - h
            start_x = track.left() + radius if palette else h / 2
            painter.drawEllipse(QPointF(start_x + travel * position, h / 2), 7, 7)
            if self.hasFocus() and self.focusPolicy() != Qt.NoFocus:
                painter.setBrush(Qt.NoBrush)
                painter.setPen(QPen(_BaseQColor(palette["icon"] if palette else "#ffad6e"), 1, Qt.DotLine))
                painter.drawRoundedRect(QRectF(.5, .5, w - 1, h - 1), (h - 1) / 2, (h - 1) / 2)
            return
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
        self.names = {}
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

    def update_devices(self, devices, names=None):
        self.devices = {
            str(address): str(mac or "")
            for address, mac in dict(devices or {}).items()
        }
        if names is not None:
            self.names = {
                str(address): str(name or "")
                for address, name in dict(names or {}).items()
                if str(name or "").strip()
            }
        self.names = {
            address: name
            for address, name in self.names.items()
            if address in self.devices
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
                name = self.names.get(address, "")
                if name:
                    name_label = QLabel()
                    name_label.setObjectName("gatewayDeviceName")
                    name_label.setToolTip(name)
                    name_label.setText(
                        name_label.fontMetrics().elidedText(
                            name,
                            Qt.ElideRight,
                            185,
                        )
                    )
                    details.addWidget(name_label)
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
            body_height = min(300, count * 68)
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
        _set_high_quality_rendering(painter)
        if _theme.is_direct():
            painter.setPen(Qt.NoPen)
            accent = _direct_theme.CONNECTION_ACCENTS
            painter.setBrush(_BaseQColor(accent.get(self.state, accent["disconnected"])))
            painter.drawEllipse(QPointF(self.width() / 2, self.height() / 2), 3.5, 3.5)
            return
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
        self._connected_at = None
        self._session_tick = QTimer(self, interval=1000)
        self._session_tick.timeout.connect(self._show_session_time)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(6, 8, 6, 8)
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
            "paused": ("وضعیت: مکث", "Status: Paused"),
            "error": ("وضعیت: خطا", "Status: Error"),
        }
        fa, en = values.get(state, values["disconnected"])
        if _theme.is_direct() and state == "connected":
            if self._connected_at is None:
                self._connected_at = time.monotonic()
                self._session_tick.start()
            self._show_session_time()
        else:
            self._session_tick.stop()
            self._connected_at = None
            self.label.setText(en if self.language == "en" else fa)
        self.dot.set_state(self.property("directState") or state)
        self.setProperty("state", state)
        _restyle(self)
        if _theme.is_direct():
            _restyle(self.label)

    def _show_session_time(self):
        if self._connected_at is None or not _theme.is_direct():
            self._session_tick.stop()
            self._connected_at = None
            return
        hours, remainder = divmod(int(time.monotonic() - self._connected_at), 3600)
        minutes, seconds = divmod(remainder, 60)
        duration = f"{hours:02}:{minutes:02}:{seconds:02}" if hours else f"{minutes:02}:{seconds:02}"
        self.label.setText(f"Connected · {duration}" if self.language == "en" else f"متصل · {ltr_isolate(duration)}")


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
        _set_high_quality_rendering(painter)
        if _theme.is_direct():
            painter.setPen(Qt.NoPen)
            painter.setBrush(_BaseQColor("#ed796a" if self.state == "error" else "#ffad6e"))
            painter.drawEllipse(QRectF(self.width() / 2 - 3.5, self.height() / 2 - 3.5, 7, 7))
            return
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
        _set_high_quality_rendering(painter)
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
        self.updated_at = 0.0
        self.revision = 0
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        content = QHBoxLayout()
        content.setContentsMargins(16, 8, 16, 8)
        content.setSpacing(12)
        self.indicator = ActivityIndicator()
        text_box = QVBoxLayout(); text_box.setSpacing(1)
        self.title = QLabel(); self.title.setObjectName("activityTitle")
        self.message = ElidedLabel(); self.message.setObjectName("activityMessage")
        self.message.setTextInteractionFlags(Qt.TextSelectableByMouse)
        text_box.addWidget(self.title); text_box.addWidget(self.message)
        content.addWidget(self.indicator); content.addLayout(text_box, 1)
        root.addLayout(content)
        self.rail = ActivityRail(); root.addWidget(self.rail)
        self.set_language(language)
        self.set_activity("", "idle", False)

    def set_language(self, language):
        self.language = language
        alignment = Qt.AlignLeft if language == "en" else Qt.AlignRight
        for label in (self.title, self.message):
            label.setAlignment(alignment | Qt.AlignAbsolute | Qt.AlignVCenter)
        self.title.setText("CURRENT ACTIVITY" if language == "en" else "فعالیت فعلی")
        if self.state == "idle":
            self.message.setText("Ready. No background task is running." if language == "en" else "آماده؛ هیچ عملیات پس‌زمینه‌ای در حال اجرا نیست.")

    def set_activity(self, message, state="running", busy=True):
        self.state, self.busy = state, busy
        self.updated_at = time.time()
        self.revision += 1
        if message:
            self.message.setText(_fonts.persian_ui_text(message) if self.language == "fa" else message)
        elif state == "idle":
            self.set_language(self.language)
        self.indicator.set_activity(state, busy)
        self.rail.set_busy(busy)
        self.setProperty("state", state)
        _restyle(self)


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
        width = max(0, self.contentsRect().width() - 2 * self.margin())
        line = " ".join(self._full_text.splitlines())
        shown = self.fontMetrics().elidedText(line, Qt.ElideRight, width)
        super().setText(shown)
        self.setToolTip(self._full_text if shown != self._full_text else "")

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._sync_text()


_SESSION_STATE_COLORS = {"up": "#35f0dc", "standby": "#9fb4d8", "skipped": "#f5a524", "down": "#ff5c7a"}
_SESSION_STATE_NAMES = {
    "up": ("فعال", "up"), "standby": ("آماده", "standby"),
    "skipped": ("رد شده", "skipped"), "down": ("قطع", "down"),
}


def session_flag_pixmap(code, state, width=16, height=11):
    """Small flag with a status dot (parallel MASQUE session)."""
    ratio = 2.0
    pixmap = QPixmap(int((width + 3) * ratio), int((height + 3) * ratio))
    pixmap.setDevicePixelRatio(ratio)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    _set_high_quality_rendering(painter)
    if code:
        painter.drawPixmap(0, 0, country_flag_icon(code, width, height).pixmap(width, height))
    else:
        painter.setPen(QPen(QColor(159, 180, 216, 150), 1.0)); painter.setBrush(Qt.NoBrush)
        painter.drawRoundedRect(QRectF(0.5, 0.5, width - 1, height - 1), 2.5, 2.5)
    dot = QRectF(width - 3.5, height - 3.5, 6.0, 6.0)
    painter.setPen(QPen(QColor("#0b1220"), 1.2))
    painter.setBrush(QColor(_SESSION_STATE_COLORS.get(state, "#9fb4d8")))
    painter.drawEllipse(dot)
    painter.end()
    return pixmap


class ParallelBadge(QFrame):
    """'Parallel · 3' + one flag per MASQUE session; details in the tooltip."""

    MAX_FLAGS = 3

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ipParallelBadge")
        self.setLayoutDirection(Qt.LeftToRight)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)
        self.text = QLabel("")
        self.text.setObjectName("hudLegend")
        layout.addWidget(self.text)
        self.flags = []
        for _ in range(self.MAX_FLAGS):
            flag = QLabel()
            flag.setFixedSize(19, 14)
            flag.setVisible(False)
            layout.addWidget(flag)
            self.flags.append(flag)
        layout.addStretch(1)
        self.setVisible(False)
        self._signature = None

    def set_sessions(self, sessions, fa=False):
        signature = (tuple((s.get("peer"), s.get("country"), s.get("colo"), s.get("state"), s.get("connections")) for s in sessions), fa)
        if signature == self._signature:
            return
        self._signature = signature
        count = len(sessions)
        self.text.setText(("موازی · " if fa else "Parallel · ") + str(count))
        for index, flag in enumerate(self.flags):
            if index < count:
                session = sessions[index]
                flag.setPixmap(session_flag_pixmap(session.get("country", ""), session.get("state", "")))
                flag.setVisible(True)
            else:
                flag.setVisible(False)
        rows = []
        for index, session in enumerate(sessions):
            code = str(session.get("country") or "").lower()
            path = ASSETS / "flags" / "4x3" / f"{code}.png"
            image = f"<img src='{path.as_posix()}' width='18' height='13'> " if code and path.exists() else ""
            state = _SESSION_STATE_NAMES.get(session.get("state", ""), (session.get("state", ""),) * 2)[0 if fa else 1]
            label = ("اصلی" if fa else "main") if session.get("main") else (f"#{index + 1}")
            where = " · ".join(part for part in (session.get("colo", ""), session.get("country", "")) if part)
            conns = session.get("connections", 0)
            rows.append(
                f"<tr><td>{image}</td><td>{html.escape(label)}</td>"
                f"<td style='font-family:Consolas'>{html.escape(session.get('peer') or '—')}</td>"
                f"<td>{html.escape(where or '—')}</td><td>{html.escape(state)}</td>"
                f"<td>{conns} {'اتصال' if fa else 'conn'}</td></tr>"
            )
        title = "MASQUE موازی" if fa else "Parallel MASQUE"
        self.setToolTip(f"<b>{title}</b><table cellspacing='4'>{''.join(rows)}</table>")

    def set_note(self, note, fa=False):
        """Parallel is on but not running: one muted line, reason in the tooltip."""
        signature = ("note", note, fa)
        if signature == self._signature:
            return
        self._signature = signature
        self.text.setText(("موازی · ۱ (فقط یک نشست)" if fa else "Parallel · 1 (single session)"))
        for flag in self.flags:
            flag.setVisible(False)
        title = "MASQUE موازی فعال نشد" if fa else "Parallel MASQUE not running"
        self.setToolTip(f"<b>{title}</b><br>{html.escape(note)}")


class ProfileTable(QTableWidget):
    deleteRequested = Signal()
    editRequested = Signal(str)

    MARK, NAME, SERVER, SNI, PING, ACTIONS = range(6)

    def __init__(self):
        super().__init__(0, 6)
        self.setObjectName("profileTable")
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.setAlternatingRowColors(True)
        self.setShowGrid(False)
        self.verticalHeader().hide()
        self.verticalHeader().setDefaultSectionSize(53)
        header = self.horizontalHeader()
        header.setHighlightSections(False)
        header.setMinimumSectionSize(1)
        header.setFixedHeight(33)
        for column, width in ((self.MARK, 31), (self.SNI, 130), (self.PING, 74), (self.ACTIONS, 142)):
            header.setSectionResizeMode(column, QHeaderView.Fixed)
            self.setColumnWidth(column, width)
        for column in (self.NAME, self.SERVER):
            header.setSectionResizeMode(column, QHeaderView.Stretch)
        self.empty_title = ""
        self.empty_subtitle = ""
        self.no_matches = ""
        self._filtered = False
        self._updating_marks = False
        self.itemSelectionChanged.connect(self.update_marks)
        self.itemChanged.connect(self._apply_mark)
        self.cellDoubleClicked.connect(self._edit_row)

    def count(self):
        return self.rowCount()

    def item(self, row, column=MARK):
        return super().item(row, column)

    def currentItem(self):
        return self.item(self.currentRow())

    def selectedItems(self):
        return [self.item(index.row()) for index in self.selectionModel().selectedRows()]

    def clear(self):
        self.clearSpans()
        self.setRowCount(0)

    def addItem(self, item):
        row = self.rowCount()
        self.insertRow(row)
        self.setItem(row, self.MARK, item)
        if item.data(Qt.UserRole) is None:
            self.setSpan(row, self.MARK, 1, self.columnCount())
            self.setRowHeight(row, 29)
        else:
            with QSignalBlocker(self):
                item.setText("")
                item.setIcon(QIcon())
                item.setCheckState(Qt.Unchecked)

    def update_marks(self):
        self._updating_marks = True
        try:
            for row in range(self.rowCount()):
                item = self.item(row)
                if item is not None and item.data(Qt.UserRole):
                    mark = Qt.Checked if item.isSelected() else Qt.Unchecked
                    if item.checkState() != mark:
                        item.setCheckState(mark)
        finally:
            self._updating_marks = False

    def _apply_mark(self, item):
        if self._updating_marks or item.column() != self.MARK or not item.data(Qt.UserRole):
            return
        selection = QItemSelectionModel.Select if item.checkState() == Qt.Checked else QItemSelectionModel.Deselect
        self.selectionModel().select(self.indexFromItem(item), selection | QItemSelectionModel.Rows)

    def show_current_profile(self, item):
        self.setCurrentItem(item, QItemSelectionModel.NoUpdate)

    def selectionCommand(self, index, event=None):
        if index.isValid() and index.column() == self.MARK and event is not None:
            if event.type() in (QEvent.MouseButtonPress, QEvent.MouseButtonRelease):
                return QItemSelectionModel.NoUpdate
        return super().selectionCommand(index, event)

    def filter_rows(self, query):
        self._filtered = bool(query)
        group = None
        with QSignalBlocker(self):
            for row in range(self.rowCount()):
                item = self.item(row)
                if item.data(Qt.UserRole) is None:
                    group = row
                    self.setRowHidden(row, True)
                    continue
                visible = query in str(item.data(Qt.UserRole + 2) or "")
                self.setRowHidden(row, not visible)
                if visible and group is not None:
                    self.setRowHidden(group, False)
                if not visible and item.isSelected():
                    self.selectionModel().select(self.indexFromItem(item),
                                                 QItemSelectionModel.Deselect | QItemSelectionModel.Rows)
            self.update_marks()
        self.viewport().update()

    def _edit_row(self, row, column):
        item = self.item(row)
        if column != self.MARK and item is not None and item.data(Qt.UserRole):
            self.editRequested.emit(item.data(Qt.UserRole))

    def set_empty_text(self, title, subtitle):
        self.empty_title, self.empty_subtitle = title, subtitle
        self.viewport().update()

    def paintEvent(self, event):
        super().paintEvent(event)
        if self.rowCount() and any(not self.isRowHidden(row) for row in range(self.rowCount())):
            return
        painter = QPainter(self.viewport())
        area = self.viewport().rect().adjusted(16, 0, -16, 0)
        text = self.no_matches if self._filtered else self.empty_title + "\n" + self.empty_subtitle
        painter.setPen(QColor("#9bb6c9"))
        painter.drawText(area, Qt.AlignCenter | Qt.TextWordWrap, text)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Delete:
            self.deleteRequested.emit()
            event.accept()
            return
        super().keyPressEvent(event)


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
        self.suffix_label = QLabel(suffix, self); self.suffix_label.setObjectName("numericSuffix"); self.suffix_label.setVisible(bool(suffix))
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
        super().__init__(parent); self._value = 0; self._maximum = 100; self._phase = 0; self._busy = False
        self.setMinimumHeight(14)
        self.timer = QTimer(self); self.timer.timeout.connect(self._animate)
        if _animations_enabled(): self.timer.start(45)

    def _animate(self):
        if self._busy or 0 < self._value < self._maximum:
            self._phase = (self._phase + 2) % 100; self.update()

    def setMaximum(self, value): self._maximum = max(1, int(value)); self.update()
    def setValue(self, value): self._value = max(0, min(int(value), self._maximum)); self.update()
    def setBusy(self, busy): self._busy = bool(busy); self.update()
    def value(self): return self._value

    def paintEvent(self, event):
        painter = QPainter(self); _set_high_quality_rendering(painter)
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
        elif self._busy:
            track = max(1.0, self.width() - 2.0)
            chunk = max(28.0, track * 0.18)
            x = 1.0 + (track + chunk) * (self._phase / 100.0) - chunk
            fill = QRectF(x, 2, chunk, self.height() - 4).intersected(
                QRectF(1, 2, track, self.height() - 4)
            )
            painter.setPen(Qt.NoPen); painter.setBrush(QColor("#4deee2")); painter.drawRoundedRect(fill, 7, 7)


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

    def set_compact(self, heading, detail_name):
        self.setFixedHeight(37)
        heading.addStretch(1)
        heading.addWidget(self.status)
        layout = self.layout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        self.domain.setObjectName(detail_name)
        self.domain.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.domain.setAlignment(Qt.AlignLeading | Qt.AlignVCenter)
        layout.itemAt(0).layout().insertWidget(0, self.domain, 1)
        self.bar.setFixedHeight(8)

    def setMaximum(self, value): self._maximum = max(1, int(value)); self.bar.setMaximum(self._maximum)
    def setValue(self, value):
        self.bar.setValue(value); self.percent.setText(f"{int(value / self._maximum * 100)}%")
    def setFormat(self, text):
        self.domain.setText(text); self.domain.setToolTip(text)
    def set_status(self, text, state="idle"):
        self.status.setText(text); self.status.setProperty("state", state); self.bar.setBusy(state == "running"); self.status.style().unpolish(self.status); self.status.style().polish(self.status)


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
        self._direct_color_state = None
        self._phase = 0.0
        self._transition = 1.0
        self._direct_appearance = False
        self._direct_frame = None
        self._direct_speed = _direct_theme.ORBIT_SPEEDS["disconnected"]
        self._direct_last_tick = 0.0
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

    def set_direct_appearance(self, active):
        if active == self._direct_appearance:
            return
        self._direct_appearance = active
        self._color_animation.stop()
        self._transition = 1.0
        if active:
            self._timer.stop()
            self._direct_speed = _direct_theme.ORBIT_SPEEDS["disconnected"]
            self._direct_frame = QImage(str(ASSETS / "ui" / "velocity-energy-flow" / "core-idle.png"))
        elif _animations_enabled():
            self._timer.start(20)
        self.update()

    def set_direct_motion(self, active):
        if active and not self._timer.isActive():
            self._direct_last_tick = time.monotonic()
            self._timer.start(25)
        elif not active:
            self._timer.stop()

    def set_direct_frame(self, frame):
        if not frame.isNull():
            self._direct_frame = frame
            self.update()

    def _get_transition(self):
        return self._transition

    def _set_transition(self, value):
        self._transition = max(0.0, min(1.0, float(value)))
        self.update()

    transitionProgress = Property(float, _get_transition, _set_transition)

    def _current_color(self):
        if self._direct_appearance:
            accents = _direct_theme.CONNECTION_ACCENTS
            target = _BaseQColor(accents.get(self._direct_color_state or self.state, accents["disconnected"]))
        else:
            target = self.COLORS.get(self.state, self.COLORS["disconnected"])
        mix = self._transition
        color = _BaseQColor if self._direct_appearance else QColor
        return color(
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

    def set_state(self, state, *, direct_color_state=None):
        if state == self.state and direct_color_state == self._direct_color_state:
            self.update()
            return
        self._from_color = self._current_color()
        self.state = state
        self._direct_color_state = direct_color_state
        if not _animations_enabled() or (self._direct_appearance and not self._timer.isActive()):
            self._set_transition(1.0)
            return
        self._color_animation.stop()
        self._color_animation.setStartValue(0.0)
        self._color_animation.setEndValue(1.0)
        self._color_animation.start()

    def _tick(self):
        if self._direct_appearance:
            now = time.monotonic()
            elapsed = min(now - self._direct_last_tick, .06)
            self._direct_last_tick = now
            speeds = _direct_theme.ORBIT_SPEEDS
            target = speeds.get(self.state, speeds["disconnected"])
            self._direct_speed += (target - self._direct_speed) * (1 - math.exp(-elapsed / .18))
            speed = self._direct_speed * elapsed
        else:
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
        _set_high_quality_rendering(p)
        if self._direct_appearance:
            if self._direct_frame is not None:
                p.drawImage(self.rect(), self._direct_frame)
            _direct_theme.paint_orbit(p, QRectF(self.rect()), self._current_color(),
                                     math.degrees(self._phase), self.state)
            return
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


ENGINE_DEFAULT_MARKER = "engine_default_migrated_v2"


def resolve_startup_engine(settings) -> tuple:
    """Engine shown at start-up -> (engine, migrated).

    Fresh installs and settings saved by older versions (no marker) open on
    engine 2 (UAC PoW) once; the marker is then set so the user's own later
    engine choice (settings["engine_mode"]) is respected. Only the
    "engine_mode" and marker keys are touched.
    """
    if not isinstance(settings, dict):
        return ENGINE_POW, False
    if not settings.get(ENGINE_DEFAULT_MARKER):
        settings["engine_mode"] = ENGINE_POW
        settings[ENGINE_DEFAULT_MARKER] = True
        return ENGINE_POW, True
    mode = str(settings.get("engine_mode", ENGINE_POW) or ENGINE_POW)
    return (mode if mode in (ENGINE_XRAY, ENGINE_POW, ENGINE_DIRECT) else ENGINE_POW), False


class XraySettingsPage(SettingsPage):
    accepted = Signal()
    rejected = Signal()

    def t(self, fa, en):
        return self._ui_text(fa, en)

    def tr(self, fa, en):
        return self.t(fa, en)

    def _ui_text(self, fa, en):
        return en if self.language == "en" else _fonts.persian_ui_text(fa)

    def _bind_text(self, widget, fa, en):
        return MainWindow._bind_text(self, widget, fa, en)

    def _page_header(self, *args, **kwargs):
        return MainWindow._page_header(self, *args, **kwargs)

    def _scroll_page(self):
        return MainWindow._scroll_page(self)

    def _button(self, fa, en, glyph=None):
        button = self._bind_text(QPushButton(), fa, en)
        button.setObjectName("settingsAction")
        button.setFixedHeight(34)
        button.setCursor(Qt.PointingHandCursor)
        if glyph:
            button.setIcon(cyber_icon(glyph, "#91dfe7", 16))
        return button

    def _build_footer(self):
        tip = self._bind_text(QLabel(),
                              "اگر با تنظیمات فنی آشنا نیستید، مقادیر پیش‌فرض را تغییر ندهید.",
                              "Keep the defaults if you are unfamiliar with these options.")
        tip.setObjectName("xraySettingsTip")
        tip.setWordWrap(True)
        self.body.addWidget(tip)
        footer = QFrame()
        footer.setObjectName("xraySettingsFooter")
        actions = QHBoxLayout(footer)
        actions.setContentsMargins(0, 8, 0, 0)
        actions.setSpacing(8)
        self.reset_button = self._button("بازنشانی پیشنهادی", "Reset recommended", "refresh")
        self.cancel_button = self._button("انصراف", "Cancel")
        self.save_button = self._button("ذخیره تنظیمات", "Save settings")
        self.save_button.setObjectName("xraySettingsSave")
        self.save_button.setIcon(cyber_icon("save", "#081d29", 16))
        self.reset_button.clicked.connect(self._apply_recommended)
        self.cancel_button.clicked.connect(self.rejected)
        self.save_button.clicked.connect(self.accepted)
        actions.addWidget(self.reset_button)
        actions.addStretch(1)
        actions.addWidget(self.cancel_button)
        actions.addWidget(self.save_button)
        self.body.addWidget(footer)

    def _help_dot(self, text, control=None):
        if not text:
            return None
        help_dot = HelpDot(self.t(*text), self.language == "fa")
        help_dot.setFixedSize(17, 17)
        self._help_entries.append((help_dot, text, control))
        return help_dot

    def _section(self, title, subtitle, rows, section_help=None, *, icon=None, short_hints=()):
        card = SettingsCard(self, *title, icon=icon, trailing=self._help_dot(section_help),
                            subtitle=subtitle)
        card.body.setContentsMargins(11, 10, 11, 8)
        for index, (label, control, help_text) in enumerate(rows):
            if isinstance(control, NumericInput):
                control.setFixedSize(126, 34)
                control.minus.setFixedSize(22, 22)
                control.plus.setFixedSize(22, 22)
                control.edit.setFixedHeight(24)
            elif isinstance(control, ToggleSwitch):
                control.set_quick_style(_quick_controls.PALETTES[ENGINE_XRAY])
            elif isinstance(control, QComboBox):
                control.setFixedHeight(34)
                control.setMinimumContentsLength(9)
                control.setMaximumWidth(178)
            elif isinstance(control, QLineEdit):
                control.setFixedSize(156, 34)
            short = short_hints[index] if index < len(short_hints) else ("", "")
            card.add(SettingsRow(self, label, short, control, trailing=True,
                                 help_button=self._help_dot(help_text, control)))
        return card

    def refresh_labels(self):
        if self.window is not self:
            self.language = self.window.language
        rtl = self.language == "fa"
        self.setLayoutDirection(Qt.RightToLeft if rtl else Qt.LeftToRight)
        for widget in (*self.findChildren(QLabel), *self.findChildren(QPushButton)):
            fa, en = widget.property("i18nFa"), widget.property("i18nEn")
            if fa is not None and en is not None:
                widget.setText(self.t(fa, en))
        super().refresh_labels()
        for button, text, control in self._help_entries:
            help_text = self.t(*text)
            button.set_help(help_text, rtl)
            if control is not None:
                control.setToolTip(button.toolTip())
                if isinstance(control, QLineEdit) and control.property("technical"):
                    control.setLayoutDirection(Qt.LeftToRight)
                    control.setAlignment(Qt.AlignLeft | Qt.AlignAbsolute)
        selected = self.gene_combo.currentData()
        self._selected_gene_strategy_id = str(selected or "")
        self._reload_gene_combo()
        if self.window is not self:
            self._multi_gene_status = self.window._multi_gene_status_text()
            self.multi_gene_status.setText(self._multi_gene_status)
        self._sync_strategy_state()

    def __init__(self, parent, tuning: Tuning, language: str = "fa",
                 update_repo_url: str = DEFAULT_UPDATE_REPO_URL,
                 carrier_tunings: dict[str, Tuning] | None = None,
                 gene_strategies: list | None = None,
                 selected_gene_strategy_id: str = "",
                 strategy_locked: bool = False,
                 multi_gene_enabled: bool = False,
                 multi_gene_status: str = "",
                 auto_clean_ip: bool = True,
                 clean_ip_launcher=None,
                 ech_via_pattern: bool = False):
        self.language = language
        super().__init__(
            parent if parent is not None else self,
            "تنظیمات Xray", "Xray Settings",
            "مسیر اتصال، سرعت و عملکرد موتور را تنظیم کنید.",
            "Adjust connection routes, speed and engine performance.",
            categories=(
                ("اتصال و مسیریابی", "Connection and routing"),
                ("سرعت و پایداری", "Speed and stability"),
                ("ابزارهای پیشرفته", "Advanced tools"),
            ),
            compact_name="xraySettingsHeader",
        )
        self.setObjectName("xraySettingsView")
        self.setAccessibleName(self.t("تنظیمات Xray", "Xray Settings"))
        self.tuning = tuning
        self._help_entries = []
        self.setLayoutDirection(Qt.LeftToRight if language == "en" else Qt.RightToLeft)
        self._gene_strategies = list(gene_strategies or [])
        self._selected_gene_strategy_id = str(selected_gene_strategy_id or "")
        self._strategy_locked = bool(strategy_locked)
        self._multi_gene_enabled = bool(multi_gene_enabled)
        self._multi_gene_status = str(multi_gene_status or "")
        self._auto_clean_ip = bool(auto_clean_ip)
        self._clean_ip_launcher = clean_ip_launcher
        self._ech_via_pattern = bool(ech_via_pattern)
        self._loading_tuning = False
        self._active_carrier = tuning.carrier_mode if tuning.carrier_mode in {"auto", "mci", "irancell"} else "auto"
        self._carrier_drafts = {
            carrier: Tuning.from_dict(value.to_dict())
            for carrier, value in (carrier_tunings or {self._active_carrier: tuning}).items()
            if carrier in {"auto", "mci", "irancell"} and isinstance(value, Tuning)
        }
        for carrier in ("auto", "mci", "irancell"):
            self._carrier_drafts.setdefault(carrier, Tuning.carrier_preset(carrier))
        self.preset = SettingsSelect(); self.preset.addItems(["maximum", "balanced", "fast", "streaming", "stealth", "compatibility", "custom"]); self.preset.setCurrentText(tuning.mode if tuning.mode in [self.preset.itemText(i) for i in range(self.preset.count())] else "custom")
        self.carrier = SettingsSelect(); self.carrier.addItems(["auto", "mci", "irancell"]); self.carrier.setCurrentText(tuning.carrier_mode)
        performance = self._section(
            ("پروفایل سرعت", "Performance profile"),
            ("Maximum برای شروع سریع؛ Streaming برای ویدئوی طولانی متعادل شده است.", "Maximum favors page start; Streaming balances long video transfers."),
            [(("پروفایل", "Preset"), self.preset,
              ("یک مجموعه امن از مقادیر زیر را اعمال می‌کند. Custom تنظیمات دستی را نگه می‌دارد.", "Applies a safe group of the controls below. Custom preserves manual values."))],
            ("این بخش فقط Preset و اپراتور را انتخاب می‌کند؛ تمام مقادیر قابل بازبینی هستند.", "Choose a starting preset and carrier; every resulting value remains visible and editable."), icon="gauge")

        self.mux_enabled = ToggleSwitch(); self.mux_enabled.setChecked(bool(getattr(tuning, "xray_mux_enabled", True)))
        self.mux_concurrency = NumericInput(getattr(tuning, "xray_mux_concurrency", 8), 1, 32)
        self.background_probe = ToggleSwitch(); self.background_probe.setChecked(bool(getattr(tuning, "background_quality_probe_enabled", False)))
        self.probe_delay = NumericInput(getattr(tuning, "background_quality_probe_delay_s", 30), 10, 300, "s")
        self.log_level = SettingsSelect(); self.log_level.addItems(["minimal", "normal"]); self.log_level.setCurrentText(tuning.log_level)
        acceleration = self._section(
            (f"شتاب‌دهی {ltr_isolate('Xray')}", "Xray acceleration"),
            ("اتصال‌های مرورگر را تجمیع می‌کند تا تعداد Handshakeهای گران کاهش یابد.", "Reduce expensive tunnel handshakes by sharing browser streams."),
            [((f"فعال‌سازی {ltr_isolate('Mux')}", "Enable Mux"), self.mux_enabled,
              ("شروع صفحات را سریع‌تر می‌کند. اگر سرور ناسازگار باشد تست اتصال آن را تشخیص می‌دهد.", "Usually improves page start. The real connectivity probe detects incompatible servers.")),
             (("جریان در هر تونل", "Streams per tunnel"), self.mux_concurrency,
              ("عدد بیشتر Handshake را کم می‌کند؛ عدد بسیار زیاد ممکن است روی ویدئو Head-of-line ایجاد کند.", "Higher values reduce handshakes; excessive values can add head-of-line blocking to video.")),
             (("تست کیفیت پس‌زمینه", "Background quality probe"), self.background_probe,
              ("یک Echo کوچک برای رتبه‌بندی آپلود اجرا می‌کند. برای بیشترین سرعت اولیه خاموش بماند.", "Runs a small upload echo for diagnostics. Keep it off for maximum initial responsiveness.")),
             (("تاخیر تست پس‌زمینه", "Probe delay"), self.probe_delay,
              ("اگر تست فعال باشد، آن را تا بعد از بارگذاری اولیه کاربر عقب می‌اندازد.", "When enabled, postpones the probe until after the user's initial page load.")),
             (("جزئیات لاگ", "Log detail"), self.log_level,
              ("Minimal هشدارهای تکراری قطع اتصال مرورگر را حذف می‌کند اما خطاهای اصلی حفظ می‌شوند.", "Minimal suppresses repeated browser-abort noise while preserving startup and route errors."))],
            ("برای ایرانسل، Mux با ۴ تا ۸ جریان معمولاً شروع چند اتصال هم‌زمان مرورگر را سبک‌تر می‌کند.", "Mux with 4–8 streams usually reduces the initial Chrome connection burst."), icon="zap")

        self.core_preset = SettingsSelect(); self.core_preset.addItems(["maximum", "streaming", "upload", "balanced", "low_latency", "compatibility"]); self.core_preset.setCurrentText(tuning.pattern_quality_preset if tuning.pattern_quality_preset in [self.core_preset.itemText(i) for i in range(self.core_preset.count())] else "balanced")
        self.connect_ip = QLineEdit(tuning.pattern_connect_ip); self.connect_ip.setProperty("technical", True); self.connect_ip.setPlaceholderText("104.18.32.47")
        self.fallback_ips = QLineEdit(tuning.pattern_fallback_ips); self.fallback_ips.setProperty("technical", True); self.fallback_ips.setPlaceholderText("188.114.99.0,104.18.8.83")
        self.profile_edges = ToggleSwitch(); self.profile_edges.setChecked(tuning.pattern_use_profile_edges)
        self.fake_sni = QLineEdit(tuning.pattern_fake_sni); self.fake_sni.setProperty("technical", True); self.fake_sni.setPlaceholderText("chatgpt.com")
        pattern = self._section(
            (f"هسته {ltr_isolate('Patterniha')}", "Patterniha core"),
            (f"تزریق {ltr_isolate('Wrong-Sequence')}؛ داده‌ی فایل در مسیر سریع Kernel باقی می‌ماند.", "Wrong-sequence injection while file payload stays in the kernel fast path."),
            [(("حالت کیفیت", "Quality preset"), self.core_preset,
              ("مقادیر Handshake، Buffer و Keepalive را با هم تنظیم می‌کند.", "Sets handshake, buffer and keepalive values as one tested group.")),
             ((f"{ltr_isolate('IP')} اصلی {ltr_isolate('Edge')}", "Primary edge IP"), self.connect_ip,
              ("مقصد TCP مستقل از SNI است؛ فقط Edgeای را وارد کنید که برای همین اپراتور همراه با SNI تست شده باشد.", "The TCP destination is independent from SNI; use only an edge tested with that SNI on this carrier.")),
             ((f"{ltr_isolate('IP')}های جایگزین", "Fallback edge IPs"), self.fallback_ips,
              ("فقط بعد از شکست Edge اصلی امتحان می‌شوند؛ فهرست بلند زمان شکست را افزایش می‌دهد.", "Tried only after the primary edge fails; long lists increase worst-case failover time.")),
             ((f"{ltr_isolate('SNI')} جعلی", "Fake SNI"), self.fake_sni,
              ("نام TLS/Host است و لازم نیست IP آن با Edge یکی باشد. SNI Lab زوج دقیق Edge + SNI را آزمایش می‌کند.", "This is the TLS/Host name and its DNS IP need not equal the edge. SNI Lab tests the exact edge + SNI pair.")),
             (("مسیرهای پروفایل", "Profile edges"), self.profile_edges,
              ("IPهای داخل کانفیگ را قبل از Edgeهای عمومی امتحان می‌کند؛ فقط برای پروفایل‌های مطمئن فعال کنید.", "Tries profile IPs before global edges; enable only for trusted profiles."))],
            ("SNI خوب باید با تست واقعی صفحه تأیید شود؛ Ping تنها معیار انتخاب نیست.", "A good SNI must pass real page traffic; ping alone is not used as proof."), icon="route")

        self.inject_delay = NumericInput(tuning.pattern_inject_delay_ms, 0, 20, "ms")
        self.ack_timeout = NumericInput(tuning.pattern_ack_timeout_ms, 500, 10000, "ms")
        self.connect_timeout = NumericInput(tuning.pattern_connect_timeout_ms, 500, 10000, "ms")
        self.edge_cooldown = NumericInput(getattr(tuning, "pattern_edge_failure_cooldown_s", 8), 1, 120, "s")
        handshake = self._section(
            (f"کیفیت {ltr_isolate('Handshake')}", "Handshake quality"),
            ("زمان ایجاد مسیر و سرعت عبور به Edge جایگزین را کنترل می‌کند.", "Controls route establishment and bounded edge failover."),
            [(("تاخیر تزریق", "Injection delay"), self.inject_delay,
              ("صفر یا یک میلی‌ثانیه سریع است؛ افزایش آن فقط برای سازگاری شبکه لازم است.", "Zero or one millisecond is fastest; raise it only for network compatibility.")),
             ((f"مهلت {ltr_isolate('Fake ACK')}", "Fake ACK timeout"), self.ack_timeout,
              ("کمتر یعنی شکست سریع‌تر؛ مقدار خیلی کم Edge سالم اما کند را حذف می‌کند.", "Lower fails over faster; too low rejects a healthy but temporarily slow edge.")),
             ((f"مهلت اتصال {ltr_isolate('Edge')}", "Edge connect timeout"), self.connect_timeout,
              ("حداکثر انتظار برای TCP Edge پیش از رفتن به جایگزین بعدی.", "Maximum TCP edge wait before trying the next fallback.")),
             (("وقفه Edge شکست‌خورده", "Failed-edge cooldown"), self.edge_cooldown,
              ("Edge خراب تا این مدت دوباره امتحان نمی‌شود و از Timeoutهای پیاپی جلوگیری می‌کند.", "Skips a failed edge for this period to prevent repeated timeouts."))],
            ("Timeout کمتر اتصال ناموفق را سریع جمع می‌کند؛ ولی روی شبکه ناپایدار بیش از حد کم نکنید.", "Shorter timeouts end bad routes sooner, but should not be too aggressive on unstable links."), icon="clock")

        self.relay_buffer = NumericInput(tuning.pattern_relay_buffer_kb, 32, 1024, "KiB")
        self.socket_buffer = NumericInput(tuning.pattern_socket_buffer_kb, 64, 8192, "KiB")
        self.max_sessions = NumericInput(tuning.pattern_max_sessions, 2, 64)
        self.keepalive = NumericInput(tuning.pattern_keepalive_idle_s, 5, 120, "s")
        self.keepalive_interval = NumericInput(getattr(tuning, "pattern_keepalive_interval_s", 3), 1, 30, "s")
        self.keepalive_count = NumericInput(getattr(tuning, "pattern_keepalive_count", 3), 1, 10)
        self.upload_optimized = ToggleSwitch(); self.upload_optimized.setChecked(tuning.pattern_upload_optimized)
        throughput = self._section(
            ("توان عبوری و ویدئو", "Throughput & video"),
            ("Buffer، Relay و Handshakeهای موازی را بدون ایجاد Connection Storm محدود می‌کند.", "Bounds buffers, relay chunks and parallel handshakes without a connection storm."),
            [(("اندازه Relay", "Relay chunk"), self.relay_buffer,
              ("Chunk بزرگ‌تر برای فایل و ویدئو مناسب است؛ بسیار بزرگ حافظه بیشتری مصرف می‌کند.", "Larger chunks favor files and video; excessive values consume more memory.")),
             ((f"بافر {ltr_isolate('Socket')}", "Socket buffer"), self.socket_buffer,
              ("فضای Kernel برای Upload/Download؛ ۱ تا ۴ MiB برای اتصال سریع مناسب است.", "Kernel send/receive space; 1–4 MiB is a practical high-throughput range.")),
             ((f"{ltr_isolate('Handshake')}های هم‌زمان", "Pending handshakes"), self.max_sessions,
              ("بالاتر شروع چند منبع صفحه را سریع می‌کند؛ برای محافظت از NAT مودم از ۱۲ تا ۱۶ بیشتر نکنید.", "Higher starts more page resources together; keep around 12–16 to protect modem NAT.")),
             ((f"شروع {ltr_isolate('Keepalive')}", "Keepalive idle"), self.keepalive,
              ("پس از این زمان بیکاری بررسی زنده‌بودن TCP شروع می‌شود.", "Starts TCP liveness checks after this idle period.")),
             ((f"فاصله {ltr_isolate('Keepalive')}", "Keepalive interval"), self.keepalive_interval,
              ("فاصله بین بررسی‌های Keepalive پس از بیکارشدن اتصال.", "Delay between keepalive probes after the connection becomes idle.")),
             ((f"تعداد {ltr_isolate('Keepalive')}", "Keepalive retries"), self.keepalive_count,
              ("بعد از این تعداد پاسخ نگرفتن، اتصال خراب سریع‌تر آزاد می‌شود.", "Releases a dead connection after this many unanswered probes.")),
             (("بهینه‌سازی جریان", "Stream optimization"), self.upload_optimized,
              ("TCP_NODELAY و بافرهای انتخاب‌شده را برای پاسخ سریع و جریان دوطرفه فعال می‌کند.", "Uses TCP_NODELAY and the selected buffers for responsive full-duplex traffic."))],
            ("برای ویدئو، Buffer کافی و تعداد Handshake متوسط از مقدارهای افراطی پایدارتر است.", "For video, adequate buffers and moderate handshake concurrency are more stable than extreme values."), icon="activity")


        self.gene_combo = SettingsSelect(); self.gene_combo.setProperty("technical", True)
        self.gene_combo.setMinimumWidth(174)
        self._reload_gene_combo()
        self.gene_import_btn = self._button("ورود استراتژی", "Import strategy")
        self.gene_clear_btn = self._button("پاک کردن ژن‌ها", "Clear imported genes")
        self.gene_import_btn.clicked.connect(self._import_gene_strategies)
        self.gene_clear_btn.clicked.connect(self._clear_gene_selection)
        self.strategy_lock = ToggleSwitch(); self.strategy_lock.setChecked(self._strategy_locked)
        self.strategy_lock.setAccessibleName("Strategy lock")
        self.strategy_lock_hint = self._bind_text(QLabel(self),
            "قفل روشن است: اگر اتصال با این استراتژی برقرار نشود، روش دیگری امتحان نمی‌شود.",
            "Locked: if this strategy fails to connect, no other method is tried.")
        self.strategy_lock_hint.setObjectName("settingsSubtitle"); self.strategy_lock_hint.setWordWrap(True)
        self.strategy_lock_hint.setVisible(self._strategy_locked)
        self.strategy_lock.toggled.connect(self.strategy_lock_hint.setVisible)
        self.multi_gene = ToggleSwitch(); self.multi_gene.setChecked(self._multi_gene_enabled)
        self.multi_gene.setAccessibleName("Smart multi-gene")
        self.multi_gene_hint = self._bind_text(QLabel(self),
            "همه ژن‌های تأییدشده به ترتیب امتیاز امتحان می‌شوند؛ ژن برنده دفعه بعد اول است.",
            "All confirmed genes are tried by score; the winner goes first next time.")
        self.multi_gene_hint.setObjectName("settingsSubtitle"); self.multi_gene_hint.setWordWrap(True)
        self.multi_gene_status = QLabel(self._multi_gene_status, self)
        self.multi_gene_status.setObjectName("settingsSubtitle"); self.multi_gene_status.setWordWrap(True)
        self.multi_gene_hint.setVisible(self._multi_gene_enabled)
        self.multi_gene_status.setVisible(self._multi_gene_enabled and bool(self._multi_gene_status))
        self.multi_gene.toggled.connect(self.multi_gene_hint.setVisible)
        self.multi_gene.toggled.connect(
            lambda on: self.multi_gene_status.setVisible(bool(on) and bool(self._multi_gene_status)))
        genes = self._section(
            ("آزمایشگاه ژن", "Gene Lab strategies"),
            ("ترکیب‌های پیدا شده توسط Gene Lab را بدون تغییر پیش‌فرض MCI وارد کنید.",
                   "Import Gene Lab combinations without changing MCI defaults."),
            [(("فایل استراتژی‌ها", "Strategy file"), self.gene_import_btn,
              ("فایل strategies.json را Import کنید؛ Clear همهٔ ایمپورت‌ها را پاک می‌کند و با Import دوباره برمی‌گردند.",
                     "Import strategies.json; Clear removes all imported genes, and Import brings them back.")),
             (("ژن‌های واردشده", "Imported genes"), self.gene_clear_btn,
              ("همهٔ ژن‌های واردشده را از فهرست حذف می‌کند.", "Removes all imported genes from the list.")),
             (("قفل استراتژی", "Strategy lock"), self.strategy_lock,
              ("روشن: Connect فقط با همین استراتژی (ژن انتخاب‌شده یا روش فعلی) وصل می‌شود و در صورت خطا سراغ متد دیگری نمی‌رود. تعویض IP لبه برای همان متد ادامه دارد.",
                     "On: Connect uses only this strategy (selected gene or current method) and never rotates to another method on failure. Edge IP failover for the same method still runs."))],
            ("خروجی پیش‌فرض: E:\\desktop\\Generic project\\data\\strategies.json",
                   "Default output: E:\\desktop\\Generic project\\data\\strategies.json"), icon="flask")

        genes.body.addWidget(self.strategy_lock_hint)

        self.auto_clean_ip = ToggleSwitch(); self.auto_clean_ip.setChecked(self._auto_clean_ip)
        self.auto_clean_ip.setAccessibleName("Auto find clean IP")
        self.clean_ip_scan_btn = self._button("شروع اسکن", "Start scan")
        self.clean_ip_scan_btn.setEnabled(callable(self._clean_ip_launcher))
        self.clean_ip_scan_btn.clicked.connect(
            lambda: self._clean_ip_launcher(self) if callable(self._clean_ip_launcher) else None)
        # ECH via Pattern core (Engine 1, default off).
        self.ech_via_pattern = ToggleSwitch(); self.ech_via_pattern.setChecked(self._ech_via_pattern)
        self.ech_via_pattern.setAccessibleName("ECH via Pattern core")

        self.update_repo = QLineEdit(update_repo_url or DEFAULT_UPDATE_REPO_URL); self.update_repo.setProperty("technical", True); self.update_repo.setPlaceholderText("https://github.com/owner/repository")
        updates = self._section(
            ("بررسی بروزرسانی", "Update checker"),
            ("نسخه نصب‌شده را با آخرین Release مخزن GitHub مقایسه می‌کند.", "Compares the installed version with the latest GitHub release."),
            [(("مخزن بروزرسانی", "Update repository"), self.update_repo,
              ("لینک مخزن GitHub شما؛ فقط ریشه مخزن مانند https://github.com/owner/repo.", "Your GitHub repository root, for example https://github.com/owner/repo."))],
            ("برنامه فقط اطلاعات Release را در پس‌زمینه می‌خواند و دانلود با کلیک کاربر باز می‌شود.", "Release metadata is checked in the background; download opens only after the user clicks."), icon="refresh")
        connection, strategy = self._connection_cards(
                                  ("فقط برای auto/Irancell اعمال می‌شود؛ MCI دست‌نخورده می‌ماند.", "Applied for auto/Irancell only; MCI routes stay protected."),
                                  ("فقط Auto و Irancell. برای هر کانفیگ تا ۳ ژن تأییدشده (حداکثر ۹ تلاش در هر اتصال) امتحان می‌شود. ژنی که ۳ بار پشت‌سرهم شکست بخورد ۳ ساعت کنار می‌رود. با قفل استراتژی فقط بین ژن‌ها می‌چرخد؛ بدون قفل، بعد از ژن‌ها روش‌های داخلی برنامه امتحان می‌شوند.", "Auto/Irancell only. Up to 3 confirmed genes per config (max 9 tries per Connect). A gene failing 3 times in a row cools down for 3 hours. With Strategy lock it rotates only among genes; without it, built-in methods follow after the genes."))
        from .proxy_port_panel import install_xray_ports_into_settings
        routes = [connection, strategy]
        if parent is not None and hasattr(parent, "storage"):
            routes.append(install_xray_ports_into_settings(self, parent))
        self.category(0).addWidget(SettingsGrid(routes, spacing=8, two_column_width=600,
                                                placements=(0, 1, 1)))
        self.category(1).addWidget(SettingsGrid(
            [performance, acceleration, handshake, throughput], spacing=8, two_column_width=600,
            placements=(0, 1, 1, 0),
        ))
        self.category(2).addWidget(SettingsGrid([pattern, genes, updates], spacing=8, two_column_width=600,
                                                placements=(0, 1, 1)))
        for index in range(self.tabs.count()):
            self.category(index).addStretch()
        for index, glyph in enumerate(("route", "gauge", "flask")):
            self.tabs.setTabIcon(index, cyber_icon(glyph, "#78d9e3", 17))
        self._build_footer()
        self._mci_locked_controls = (
            self.preset,
            self.mux_enabled,
            self.mux_concurrency,
            self.background_probe,
            self.probe_delay,
            self.core_preset,
            self.connect_ip,
            self.fallback_ips,
            self.profile_edges,
            self.fake_sni,
            self.inject_delay,
            self.ack_timeout,
            self.connect_timeout,
            self.edge_cooldown,
            self.relay_buffer,
            self.socket_buffer,
            self.max_sessions,
            self.keepalive,
            self.keepalive_interval,
            self.keepalive_count,
            self.upload_optimized,
            self.gene_combo,
            self.gene_import_btn,
            self.gene_clear_btn,
            self.multi_gene,
        )
        self.preset.currentTextChanged.connect(self._apply_preset)
        self.core_preset.currentTextChanged.connect(self._apply_core_preset)
        self.carrier.currentTextChanged.connect(self._switch_carrier_profile)
        self._sync_carrier_lock()


        self.refresh_labels()

    def _connection_cards(self, gene_help, multi_help):
        auto_fa = "\u067e\u06cc\u062f\u0627 \u06a9\u0631\u062f\u0646 \u062e\u0648\u062f\u06a9\u0627\u0631 IP \u062a\u0645\u06cc\u0632"
        connection = self._section(
            ("تنظیمات اتصال", "Connection settings"),
            ("\u0627\u067e\u0631\u0627\u062a\u0648\u0631 \u0648 \u067e\u06cc\u062f\u0627 \u06a9\u0631\u062f\u0646 IP \u0633\u0627\u0644\u0645 \u067e\u06cc\u0634 \u0627\u0632 \u0627\u062a\u0635\u0627\u0644.",
                   "Carrier and finding a clean IP before Connect."),
            [(("\u0627\u067e\u0631\u0627\u062a\u0648\u0631", "Carrier"), self.carrier,
              ("\u0627\u067e\u0631\u0627\u062a\u0648\u0631\u06cc \u06a9\u0647 \u0628\u0627 \u0622\u0646 \u0648\u0635\u0644 \u0645\u06cc\u200c\u0634\u0648\u06cc\u062f.", "The carrier you connect with (auto / MCI / Irancell).")),
             ((auto_fa, "Auto find clean IP"), self.auto_clean_ip,
              ("IP \u062a\u0645\u06cc\u0632 \u0631\u0627 \u0642\u0628\u0644 \u0627\u0632 \u0627\u062a\u0635\u0627\u0644 \u062e\u0648\u062f\u06a9\u0627\u0631 \u067e\u06cc\u062f\u0627 \u0645\u06cc\u200c\u06a9\u0646\u062f.",
                     "Tests cached and sampled Cloudflare IPs before Connect (max ~5 s).")),
             (("\u0627\u0633\u06a9\u0646 \u06a9\u0627\u0645\u0644", "Full scan"), self.clean_ip_scan_btn,
              ("\u0627\u0633\u06a9\u0646 \u062f\u0633\u062a\u06cc \u0648 \u0627\u0646\u062a\u062e\u0627\u0628 \u06cc\u06a9 IP \u0628\u0631\u0627\u06cc \u0647\u0645\u06cc\u0646 \u0646\u0634\u0633\u062a.",
                     "Scan manually and pick one IP for this session.")),
             (("\u0639\u0628\u0648\u0631 ECH \u0627\u0632 \u0647\u0633\u062a\u0647 Pattern", "ECH via Pattern core"), self.ech_via_pattern,
              ("\u067e\u06cc\u0634\u200c\u0641\u0631\u0636 \u062e\u0627\u0645\u0648\u0634. \u06a9\u0627\u0646\u0641\u06cc\u06af\u200c\u0647\u0627\u06cc ECH \u0628\u0647\u200c\u062c\u0627\u06cc \u0627\u062a\u0635\u0627\u0644 \u0645\u0633\u062a\u0642\u06cc\u0645 \u0627\u0632 \u0647\u0633\u062a\u0647 \u0645\u062d\u0644\u06cc Pattern (wrong-seq) \u0631\u062f \u0645\u06cc\u200c\u0634\u0648\u0646\u062f\u061b ClientHello \u062e\u0648\u062f ECH \u062f\u0633\u062a \u0646\u0645\u06cc\u200c\u062e\u0648\u0631\u062f.",
                     "Off by default. ECH configs go through the local Pattern core (wrong-seq) instead of dialing directly; the ECH ClientHello itself is not changed."))], icon="route", short_hints=(
                ("تشخیص خودکار یا انتخاب دستی", "Detect or select manually"),
                ("پیدا کردن مسیر مناسب پیش از اتصال", "Find a reachable address before connecting"),
                ("بررسی دوبارهٔ مسیرهای اتصال", "Check connection routes again"),
                ("تنظیم روش عبور ECH", "Choose how ECH is routed"),
            ))
        strategy = self._section(
            ("استراتژی اتصال", "Connection strategy"),
            ("\u0631\u0648\u0634 \u0627\u062a\u0635\u0627\u0644: \u0628\u062f\u0648\u0646 \u0698\u0646 (\u0631\u0648\u0634 \u062f\u0627\u062e\u0644\u06cc) \u06cc\u0627 \u06cc\u06a9 \u0698\u0646 Gene Lab.",
                   "How to connect: no gene (built-in method) or a Gene Lab gene."),
            [(("\u0627\u0633\u062a\u0631\u0627\u062a\u0698\u06cc \u0698\u0646", "Gene strategy"), self.gene_combo,
              gene_help),
             (("\u0698\u0646 \u0686\u0646\u062f\u06af\u0627\u0646\u0647", "Smart multi-gene"), self.multi_gene,
              multi_help)], icon="zap")
        self.strategy_state = QLabel(); self.strategy_state.setObjectName("settingsSubtitle")
        self.strategy_state.setWordWrap(True); self.strategy_state.setAlignment(Qt.AlignLeading | Qt.AlignTop)
        strategy.body.addWidget(self.multi_gene_hint)
        strategy.body.addWidget(self.multi_gene_status)
        strategy.body.addWidget(self.strategy_state)
        self.gene_combo.currentIndexChanged.connect(self._sync_strategy_state)
        self.multi_gene.toggled.connect(self._sync_strategy_state)
        self.carrier.currentTextChanged.connect(self._sync_strategy_state)
        self._sync_strategy_state()
        return connection, strategy

    def _strategy_state_text(self):
        """(text, warning) for the one-line strategy status under Strategy."""
        carrier = self.carrier.currentText()
        gene_id = str(self.gene_combo.currentData() or "")
        multi = bool(self.multi_gene.isChecked())
        has_genes = bool(self._gene_strategies)
        if carrier == "mci":
            return self.t("\u0648\u0636\u0639\u06cc\u062a: \u0631\u0648\u06cc \u0647\u0645\u0631\u0627\u0647 \u0627\u0648\u0644 \u0698\u0646\u200c\u0647\u0627 \u0627\u0633\u062a\u0641\u0627\u062f\u0647 \u0646\u0645\u06cc\u200c\u0634\u0648\u0646\u062f\u061b \u0645\u0633\u06cc\u0631\u0647\u0627\u06cc \u062f\u0627\u062e\u0644\u06cc \u0645\u062d\u0627\u0641\u0638\u062a \u0645\u06cc\u200c\u0634\u0648\u0646\u062f.",
                          "Status: on MCI genes are not used; built-in routes stay protected."), False
        if multi and not has_genes:
            return self.t("\u0648\u0636\u0639\u06cc\u062a: \u0686\u0646\u062f \u0698\u0646\u0647 \u0631\u0648\u0634\u0646 \u0627\u0633\u062a \u0648\u0644\u06cc \u0698\u0646\u06cc \u0627\u06cc\u0645\u067e\u0648\u0631\u062a \u0646\u0634\u062f\u0647\u061b \u0631\u0648\u0634 \u062f\u0627\u062e\u0644\u06cc \u0627\u0633\u062a\u0641\u0627\u062f\u0647 \u0645\u06cc\u200c\u0634\u0648\u062f.",
                          "Status: Multi-gene is on but no genes are imported; the built-in method is used."), False
        if multi and not gene_id:
            return self.t("\u0648\u0636\u0639\u06cc\u062a: \xab\u0628\u062f\u0648\u0646 \u0698\u0646\xbb \u0627\u0646\u062a\u062e\u0627\u0628 \u0634\u062f\u0647\u060c \u0648\u0644\u06cc \u0686\u0646\u062f \u0698\u0646\u0647 \u0631\u0648\u0634\u0646 \u0627\u0633\u062a\u061b \u0698\u0646\u200c\u0647\u0627\u06cc \u0627\u06cc\u0645\u067e\u0648\u0631\u062a\u200c\u0634\u062f\u0647 \u0628\u0627\u0632 \u0647\u0645 \u0627\u0645\u062a\u062d\u0627\u0646 \u0645\u06cc\u200c\u0634\u0648\u0646\u062f. \u0628\u0631\u0627\u06cc \u0641\u0642\u0637 \u0631\u0648\u0634 \u062f\u0627\u062e\u0644\u06cc\u060c \u0686\u0646\u062f \u0698\u0646\u0647 \u0631\u0627 \u062e\u0627\u0645\u0648\u0634 \u06a9\u0646\u06cc\u062f.",
                          "Status: 'No gene' is selected but Multi-gene is ON, so imported genes are still tried. Turn Multi-gene off to use only the built-in method."), True
        if multi:
            return self.t("\u0648\u0636\u0639\u06cc\u062a: \u0698\u0646\u200c\u0647\u0627\u06cc \u062a\u0623\u06cc\u06cc\u062f\u0634\u062f\u0647 \u0628\u0647 \u062a\u0631\u062a\u06cc\u0628 \u0627\u0645\u062a\u06cc\u0627\u0632 \u0627\u0645\u062a\u062d\u0627\u0646 \u0645\u06cc\u200c\u0634\u0648\u0646\u062f.",
                          "Status: confirmed genes are tried in score order."), False
        if gene_id:
            return self.t("\u0648\u0636\u0639\u06cc\u062a: \u0641\u0642\u0637 \u0698\u0646 \u0627\u0646\u062a\u062e\u0627\u0628\u200c\u0634\u062f\u0647 \u0627\u0633\u062a\u0641\u0627\u062f\u0647 \u0645\u06cc\u200c\u0634\u0648\u062f.",
                          "Status: only the selected gene is used."), False
        return self.t("\u0648\u0636\u0639\u06cc\u062a: \u0641\u0642\u0637 \u0631\u0648\u0634 \u062f\u0627\u062e\u0644\u06cc \u0627\u067e\u0631\u0627\u062a\u0648\u0631 \u0627\u0633\u062a\u0641\u0627\u062f\u0647 \u0645\u06cc\u200c\u0634\u0648\u062f.",
                      "Status: only the carrier's built-in method is used."), False

    def _sync_strategy_state(self):
        label = getattr(self, "strategy_state", None)
        if label is None:
            return
        try:
            text, warning = self._strategy_state_text()
        except Exception:
            return
        label.setText(text)
        label.setStyleSheet("color: #f5b94a;" if warning else "")
        hint = getattr(self, "multi_gene_hint", None)
        if hint is not None:
            hint.setEnabled(not warning)


    def _reload_gene_combo(self):
        current = str(getattr(self, "_selected_gene_strategy_id", "") or "")
        self.gene_combo.blockSignals(True)
        self.gene_combo.clear()
        self.gene_combo.addItem(self.t("بدون استراتژی ژن", "No gene strategy"), "")
        for strategy in getattr(self, "_gene_strategies", []) or []:
            if not isinstance(strategy, dict):
                continue
            label = gene_display_label(strategy, self.language)
            self.gene_combo.addItem(label, strategy.get("id", ""))
        index = self.gene_combo.findData(current)
        self.gene_combo.setCurrentIndex(index if index >= 0 else 0)
        self.gene_combo.blockSignals(False)
        self._sync_strategy_state()

    def _import_gene_strategies(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            self.t("انتخاب strategies.json", "Select strategies.json"),
            r"E:\desktop\Generic project updated\data\strategies.json",
            "JSON (*.json)",
        )
        if not path:
            return
        try:
            imported = load_strategies_file(path)
        except Exception as exc:
            QMessageBox.warning(self, "Gene Lab", str(exc))
            return
        if not imported:
            QMessageBox.information(self, "Gene Lab", self.t("استراتژی معتبری پیدا نشد", "No valid strategies found"))
            return
        by_id = {str(s.get("id")): s for s in self._gene_strategies if isinstance(s, dict)}
        for item in imported:
            by_id[str(item["id"])] = item
        self._gene_strategies = sorted(
            by_id.values(),
            key=lambda s: (float(s.get("score", 0) or 0), float(s.get("success_rate", 0) or 0)),
            reverse=True,
        )
        if not self._selected_gene_strategy_id and self._gene_strategies:
            self._selected_gene_strategy_id = str(self._gene_strategies[0].get("id", ""))
        self._reload_gene_combo()
        QMessageBox.information(
            self, "Gene Lab",
            self.t(f"{len(imported)} استراتژی وارد شد", f"Imported {len(imported)} strategies"),
        )

    def _clear_gene_selection(self):
        """Drop imported Gene Lab strategies from the list; Import brings them back."""
        self._gene_strategies = []
        self._selected_gene_strategy_id = ""
        self._reload_gene_combo()

    def auto_clean_ip_value(self) -> bool:
        return bool(self.auto_clean_ip.isChecked())

    def ech_via_pattern_value(self) -> bool:
        toggle = getattr(self, "ech_via_pattern", None)
        if toggle is None:
            return bool(getattr(self, "_ech_via_pattern", False))
        return bool(toggle.isChecked())

    def multi_gene_enabled_value(self) -> bool:
        return bool(self.multi_gene.isChecked())

    def strategy_lock_enabled(self) -> bool:
        return bool(self.strategy_lock.isChecked())

    def gene_selection(self):
        self._selected_gene_strategy_id = str(self.gene_combo.currentData() or "")
        return list(self._gene_strategies), self._selected_gene_strategy_id

    def _sync_carrier_lock(self):
        locked = self.carrier.currentText() == "mci"
        if locked:
            source = self._carrier_drafts.get("mci", Tuning.carrier_preset("mci"))
            protected = Tuning.enforce_carrier(source, "mci")
            self._carrier_drafts["mci"] = protected
            self._load_tuning(protected)
        for widget in self._mci_locked_controls:
            widget.setEnabled(not locked)

    def _apply_preset(self, mode):
        if self._loading_tuning or mode == "custom" or self.carrier.currentText() == "mci": return

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
        self._sync_carrier_lock()

    def _apply_core_preset(self, mode):
        if self._loading_tuning or self.carrier.currentText() == "mci":
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
        t.pattern_edge_failure_cooldown_s = self.edge_cooldown.value(); t.pattern_keepalive_interval_s = self.keepalive_interval.value(); t.pattern_keepalive_count = self.keepalive_count.value()
        return Tuning.enforce_carrier(t, carrier)

    def _switch_carrier_profile(self, carrier):
        if self._loading_tuning or carrier == self._active_carrier:
            return
        self._carrier_drafts[self._active_carrier] = self._form_value(self._active_carrier)
        self._active_carrier = carrier
        target = Tuning.enforce_carrier(
            self._carrier_drafts.get(carrier, Tuning.carrier_preset(carrier)), carrier
        )
        self._carrier_drafts[carrier] = target
        self._load_tuning(target)
        self._sync_carrier_lock()

    def values(self) -> dict[str, Tuning]:
        self._carrier_drafts[self._active_carrier] = self._form_value(self._active_carrier)
        return {carrier: Tuning.from_dict(value.to_dict())
                for carrier, value in self._carrier_drafts.items()}

    def value(self) -> Tuning:
        values = self.values()
        return values[self._active_carrier]

    def update_repo_url(self) -> str:
        return self.update_repo.text().strip()


from .log_panel import LogsPageMixin
from . import engine_switch as _eswitch

class _OverlayHint(QLabel):
    """Centered hint that fills its parent (used as the empty state of a table)."""

    def __init__(self, parent):
        super().__init__(parent)
        self.setAlignment(Qt.AlignCenter)
        self.setWordWrap(True)
        self.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        parent.installEventFilter(self)
        self.setGeometry(parent.rect())

    def eventFilter(self, obj, event):
        from PySide6.QtCore import QEvent
        if obj is self.parent() and event.type() in (QEvent.Resize, QEvent.Show):
            self.setGeometry(obj.rect())
        return False


class MainWindow(LogsPageMixin, QMainWindow):
    GLOBAL_SETTINGS_PAGE = 9
    POW_SETTINGS_PAGE = 10
    DIRECT_SETTINGS_PAGE = 11
    XRAY_SETTINGS_PAGE = 12
    DIRECT_DNS_PAGE = 13
    DIRECT_ROUTING_PAGE = 14

    def __init__(self):
        super().__init__(); self.setWindowTitle("UAC Spoofer Desktop"); self.resize(1440, 900); self.setMinimumSize(*_layout.MIN_WINDOW_SIZE)
        self.setAccessibleName("UAC Spoofer Desktop")
        self.storage = Storage(); self.language = self.storage.settings.get("language", "fa"); self.bridge = Bridge(); self.scan_cancelled = False; self.scanning = False; self.connecting = False; self.connection_error = ""; self.last_results: list[ScanResult] = []; self.sni_undo_snapshot = None
        self._toast = None
        if self.storage.settings.get("assistant_enabled", False):
            self.storage.settings["assistant_enabled"] = False
            self.storage.save_settings()
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
        self._gateway_device_names = {}
        self._gateway_device_name_priorities = {}
        self._gateway_device_name_pending = set()
        self._gateway_device_name_generation = 0
        self._gateway_device_name_resolver = DeviceNameResolver()
        self._gateway_runtime_state = "inactive"
        self._connect_cancel = threading.Event()
        self._connect_thread: threading.Thread | None = None
        self._connection_retry_pending = False
        self._forced_profile_id = ""
        self._pending_profile_switch_id = ""
        self._profile_switch_waiting = False
        self._bypass_apply_timer = QTimer(self)
        self._bypass_apply_timer.setSingleShot(True)
        self._bypass_apply_timer.setInterval(550)
        self._bypass_apply_timer.timeout.connect(self._apply_bypass_changes)
        self._page_animation = None
        self._animated_page = None
        self._engine_switching = False
        self._engine_switch_anim = None
        self._engine_checked_override = None
        self._suppress_page_motion = False
        self._stale_pages = set()
        self._engine_switch_stats = {}
        self._entrance_done = False
        self._log_paused_lines: list[str] = []
        self._all_log_lines: list[str] = []
        self._pending_file_log_lines: list[str] = []
        self._log_flush_failures = 0
        self._log_flush_timer = QTimer(self); self._log_flush_timer.setSingleShot(True); self._log_flush_timer.setInterval(180); self._log_flush_timer.timeout.connect(self._flush_log_buffer)
        self._controls_compact = None
        self._target_latency_generation = 0
        self._target_latency_busy = False
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
        self._assistant_maker_test_completed_at = 0.0
        self._assistant_maker_next_action = ""
        self._profile_ping_generation = 0
        self._profile_ping_busy = False
        self._profile_ping_cancel = threading.Event()
        self._maker = SniConfigMaker(
            fake_sni=self.storage.tuning.pattern_fake_sni,
        )
        self.assistant_controller = None
        self._traffic_totals = SessionTraffic()
        self._traffic_busy = False
        self.engine = Engine(lambda text: self.bridge.engine_log.emit(text, ENGINE_XRAY),
                             self.bridge.state.emit, lambda _up, _down: None)
        self.engine.ech_via_pattern = bool(self.storage.settings.get("ech_via_pattern", False))
        self._apply_xray_port_setting()
        self.engine_mode, _engine_migrated = resolve_startup_engine(self.storage.settings)
        if _engine_migrated:
            try:
                self.storage.save_settings()
            except Exception:
                pass
        # Install the combined (both engines) stylesheet before any widget
        # exists, so start-up pays for one cheap install and a later engine
        # switch never has to replace the application stylesheet.
        self.global_settings = ApplicationSettings(self.storage)
        self.setProperty(_eswitch.ENGINE_PROPERTY, ENGINE_POW if self.engine_mode == ENGINE_DIRECT else self.engine_mode)
        try:
            _startup_app = QApplication.instance()
            if _startup_app is not None and is_app_style(_startup_app.styleSheet()):
                _startup_app.setStyleSheet(combined_app_style(self.language if self.language in ("fa", "en") else "fa"))
        except Exception:
            pass
        self.pow_controller = PowController(self)
        self.direct_controller = DirectPanel(self)
        self.global_settings.migrate(self.engine_mode, self.pow_controller.store, self.direct_controller.store)
        self._xray_session_mode = None
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
            gateway.device_names_changed = self._gateway_runtime_names_received
        try:
            self.engine.recover_stale_tun()
        except Exception as exc:
            self._pending_file_log_lines.append(f"sing-box recovery pending: {exc}")
        _theme.set_engine(self.engine_mode); self._build(); self._sync_engine_ui(); self._setup_tray(); self._wire(); self._configure_technical_widgets(); self.refresh_profiles(); self.refresh_bookmarks(); self.refresh_processes(); self._apply_language(); self._append_log("UAC Spoofer Desktop آماده است")
        QTimer.singleShot(2500, self._prewarm_art_step)
        self.activity_bar.set_activity("", "idle", False)
        self._auto_connect = AutoConnect(self)
        self._auto_connect.configure()
        if ASSISTANT_FEATURE_ENABLED and AssistantController is not None:
            try:
                self.assistant_controller = AssistantController(
                    self, reduced_motion=not _animations_enabled()
                )
            except Exception as exc:
                self.bridge.log.emit(f"Assistant initialization failed: {exc}")
        if self.assistant_controller is None:
            self.assistant_toggle.blockSignals(True)
            self.assistant_toggle.setChecked(False)
            self.assistant_toggle.blockSignals(False)
            self.assistant_toggle.setEnabled(False)
            self.assistant_replay_button.setEnabled(False)
            self.assistant_guides_toggle.setEnabled(False)
            self.assistant_warnings_toggle.setEnabled(False)
            if _ASSISTANT_IMPORT_ERROR:
                self.bridge.log.emit(f"Assistant module unavailable: {_ASSISTANT_IMPORT_ERROR}")
        elif self.assistant_toggle.isChecked():
            QTimer.singleShot(0, self.assistant_controller.enable)
        self._target_latency_timer = QTimer(self); self._target_latency_timer.setInterval(10000); self._target_latency_timer.timeout.connect(self._queue_target_latency_probe); self._target_latency_timer.start()
        QTimer.singleShot(300, self._queue_target_latency_probe)
        QTimer.singleShot(1800, lambda: self.check_for_updates(manual=False))
        self._update_poll_timer = QTimer(self); self._update_poll_timer.setInterval(12 * 3600 * 1000); self._update_poll_timer.timeout.connect(lambda: self.check_for_updates(manual=False)); self._update_poll_timer.start()

    def _bind_text(self, widget, persian, english):
        widget.setProperty("i18nFa", persian)
        widget.setProperty("i18nEn", english)
        widget.setText(self._ui_text(persian, english))
        return widget

    def _action_button(self, persian, english, icon_name, object_name="secondaryAction", *, button_type=GlowButton):
        button = button_type()
        button.setObjectName(object_name)
        if icon_name:
            button.setIcon(cyber_icon(icon_name, "#bfefff", 18))
            button.setIconSize(QSize(18, 18))
        button.setCursor(Qt.PointingHandCursor)
        self._bind_text(button, persian, english)
        return button

    def _page_header(self, persian_title, english_title, persian_subtitle, english_subtitle, trailing=None,
                     *, compact_name=None):
        header_meta = {
            "Connection Center": ("shield", "فرماندهی شبکه", "NETWORK COMMAND"),
            "Manage configs": ("file-cog", "مدیریت مسیرها", "ROUTE LIBRARY"),
            "SNI Config Maker": ("sparkles", "ساخت و اعتبارسنجی", "CONFIG FACTORY"),
            "SNI Lab": ("flask", "آزمایش و رتبه‌بندی", "SIGNAL LABORATORY"),
            "Live Logs": ("activity", "رویدادهای زنده", "LIVE TELEMETRY"),
            "App routing": ("route", "مسیریابی برنامه‌ها", "APPLICATION ROUTING"),
            "Network Tools": ("wrench", "ابزارهای تشخیص", "DIAGNOSTIC TOOLKIT"),
            "Support & Updates": ("headphones", "مرکز راهنما", "SUPPORT CENTER"),
            "Global Settings": ("settings", "ترجیحات برنامه", "APPLICATION PREFERENCES"),
            "PoW Settings": ("zap", "موتور PoW", "POW ENGINE"),
            "Xray Settings": ("sliders", "تنظیم مسیر", "XRAY / SETTINGS"),
            "Direct Settings": ("route", "موتور Direct", "DIRECT ENGINE"),
            "DNS Lab": ("flask", "", ""),
            "Direct site routing": ("globe", "", ""),
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
        dashboard = english_title == "Connection Center"
        subtitle = self._bind_text(ElidedLabel() if dashboard else QLabel(), persian_subtitle, english_subtitle)
        subtitle.setObjectName("pageSubtitle"); subtitle.setWordWrap(not dashboard)
        if dashboard:
            copy.setAlignment(Qt.AlignVCenter)
        subtitle.setTextInteractionFlags(Qt.TextSelectableByMouse)
        copy.addWidget(kicker); copy.addWidget(title); copy.addWidget(subtitle)
        layout.addLayout(copy, 1)
        if trailing is not None:
            layout.addWidget(trailing, 0, Qt.AlignVCenter)
        if compact_name:
            header.setObjectName(compact_name)
            header.setFixedHeight(72)
            layout.setContentsMargins(6, 4, 6, 4)
            layout.setSpacing(12)
            kicker.hide()
            icon.setFixedSize(40, 40)
        return header

    def _scroll_page(self):
        scroll = QScrollArea(); scroll.setObjectName("pageScroll"); scroll.setWidgetResizable(True); scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        body = QWidget(); body.setObjectName("pageBody")
        scroll.setWidget(body)
        return scroll, body

    def _toggle_option(self, toggle, persian, english, row_click_enabled=True, *, word_wrap=False):
        wrapper = ToggleOptionFrame(
            toggle, row_click_enabled=row_click_enabled
        ); wrapper.setObjectName("toggleOption")
        layout = QHBoxLayout(wrapper); layout.setContentsMargins(10, 7, 10, 7); layout.setSpacing(10)
        label = QLabel() if word_wrap else ElidedLabel()
        if word_wrap:
            label.setWordWrap(True)
            label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self._bind_text(label, persian, english)
        label.setObjectName("controlLabel")
        label.setAttribute(Qt.WA_TransparentForMouseEvents)
        layout.addWidget(toggle); layout.addWidget(label, 1)
        toggle.setAccessibleName(english)
        return wrapper

    def _build(self):
        root = CyberRoot(); self.setCentralWidget(root); layout = QHBoxLayout(root); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(0)
        sidebar = QFrame(); self.sidebar = sidebar; sidebar.setObjectName("sidebar"); sidebar.setAttribute(Qt.WA_StyledBackground, True); sidebar.setFixedWidth(286); side = QVBoxLayout(sidebar); self.sidebar_layout = side; side.setContentsMargins(18, 20, 18, 18); side.setSpacing(4)
        logo = _eswitch.EngineBrandCard(); self.logo_card = logo
        logo.setLayoutDirection(Qt.RightToLeft)
        logo.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed); logo_root = QVBoxLayout(logo); self.logo_root = logo_root; logo_root.setContentsMargins(12, 10, 12, 10); logo_root.setSpacing(9); logo_root.setSizeConstraint(QBoxLayout.SizeConstraint.SetMinimumSize)
        brand_row = QHBoxLayout(); brand_row.setSpacing(12)
        mark = QLabel(); self.logo_mark = mark; mark.setObjectName("logoMark"); mark.setAlignment(Qt.AlignCenter); mark.setFixedSize(_layout.BRAND_ICON, _layout.BRAND_ICON); brand_row.addWidget(mark, 0, Qt.AlignVCenter)
        logo_text = QVBoxLayout(); logo_text.setSpacing(1)
        brand = QLabel("UAC Spoofer"); self.brand_label = brand; brand.setObjectName("brand"); brand.setTextFormat(Qt.RichText); logo_text.addWidget(brand)
        version = QLabel(f"DESKTOP  \u00b7  v{__version__}"); self.version_label = version; version.setObjectName("brandEdition"); logo_text.addWidget(version)
        self.engine_badge = QLabel(); self.engine_badge.setObjectName("engineBadge"); self.engine_badge.setTextFormat(Qt.RichText); logo_text.addWidget(self.engine_badge)
        for label in (brand, version, self.engine_badge):
            label.setLayoutDirection(Qt.LeftToRight)
            label.setAlignment(Qt.AlignLeft | Qt.AlignAbsolute | Qt.AlignVCenter)
        brand_row.addLayout(logo_text, 1); logo_root.addLayout(brand_row)
        switch = QFrame(); self.engine_switch = switch; switch.setObjectName("engineSwitch"); switch.setLayoutDirection(Qt.LeftToRight); switch_layout = QHBoxLayout(switch); switch_layout.setContentsMargins(2, 3, 2, 3); switch_layout.setSpacing(2); switch.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        switch.setFixedHeight(_layout.ENGINE_SWITCH_HEIGHT)
        from PySide6.QtWidgets import QButtonGroup
        self.engine_group = QButtonGroup(self); self.engine_group.setExclusive(True); self.engine_buttons = {}
        modes = ((ENGINE_XRAY, "Xray"), (ENGINE_POW, "UAC\u00a0PoW"), (ENGINE_DIRECT, "UAC\u00a0Direct"))
        for (engine_key, engine_label), stretch in zip(modes, _layout.ENGINE_SWITCH_STRETCH):
            option = QPushButton(engine_label); option.setObjectName("engineOption"); option.setCheckable(True); option.setCursor(Qt.PointingHandCursor); option.setProperty("engine", engine_key)
            option.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Fixed)
            option.setFixedHeight(_layout.ENGINE_OPTION_HEIGHT)
            option.clicked.connect(lambda _checked=False, key=engine_key: self._engine_option_clicked(key))
            self.engine_group.addButton(option); self.engine_buttons[engine_key] = option
            switch_layout.addWidget(option, stretch, Qt.AlignVCenter)
        self.engine_thumb = _eswitch.EngineThumb(switch); self.engine_thumb.lower(); switch.installEventFilter(self)
        logo_root.addWidget(switch); side.addWidget(logo); side.addSpacing(14)
        def navigation_button(icon_name, persian, english):
            button = self._bind_text(NavButton(parent=sidebar), persian, english)
            button.setIcon(cyber_icon(self._nav_icon(icon_name), "#9fb4d8", _layout.NAV_ICON))
            button.setIconSize(QSize(_layout.NAV_ICON, _layout.NAV_ICON))
            button.setProperty("iconName", icon_name)
            button.hide()
            return button

        self.nav = []
        entries = (
            ("home", "خانه", "Home"),
            ("file-cog", "کانفیگ‌ها", "Configs"),
            ("sparkles", "سازنده SNI", "SNI Maker"),
            ("flask", "آزمایشگاه SNI", "SNI Lab"),
            ("activity", "لاگ زنده", "Live Logs"),
            ("shield", "عبور مستقیم برنامه‌ها", "App Bypass"),
            ("wrench", "ابزارها", "Tools"),
            ("zap", "یو‌ای‌سی پاو", "UAC PoW"),
            ("headphones", "پشتیبانی", "Support"),
            ("settings", "تنظیمات کلی", "Global Settings"),
            ("pow-settings", "تنظیمات PoW", "PoW Settings"),
            ("direct-settings", "تنظیمات Direct", "Direct Settings"),
            ("xray-settings", "تنظیمات Xray", "Xray Settings"),
            ("direct-dns", "آزمایشگاه DNS", "DNS Lab"),
        )
        for index, (icon_name, name, english) in enumerate(entries):
            button = navigation_button(icon_name, name, english)
            button.clicked.connect(lambda _, i=index: self.show_page(i))
            self.nav.append(button)
        self.xray_settings_button = self.nav[self.XRAY_SETTINGS_PAGE]
        ordered_nav = (*self.nav[:7], self.nav[self.GLOBAL_SETTINGS_PAGE],
                       self.nav[self.POW_SETTINGS_PAGE], self.nav[self.DIRECT_SETTINGS_PAGE],
                       self.nav[self.DIRECT_DNS_PAGE], self.xray_settings_button, self.nav[8])
        for button in ordered_nav:
            side.addWidget(button)
        for first, second in zip(ordered_nav, ordered_nav[1:]):
            self.setTabOrder(first, second)
        self.sidebar_compact_spacer = QWidget(sidebar)
        self.sidebar_compact_spacer.setFixedHeight(_layout.COMPACT_NAV_SPACER)
        side.addWidget(self.sidebar_compact_spacer)
        side.addStretch()
        self.rating_card = QFrame(); self.rating_card.setObjectName("ratingCard"); self.rating_card.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed); rating_layout = QVBoxLayout(self.rating_card); rating_layout.setContentsMargins(15, 13, 15, 13); rating_layout.setSpacing(4)
        self.rating_title = self._bind_text(QLabel(), "از برنامه راضی هستید؟", "Enjoying the app?"); self.rating_title.setObjectName("ratingTitle")
        self.rating_text = self._bind_text(QLabel(), "با یک ستاره از پروژه حمایت کنید.", "Support the project with a star."); self.rating_text.setObjectName("ratingText"); self.rating_text.setWordWrap(True)
        self.rating_button = self._action_button("ستاره در گیت‌هاب", "Star on GitHub", "external-link", "ratingButton"); self.rating_button.setMinimumHeight(40); self.rating_button.clicked.connect(lambda: webbrowser.open(PROJECT_URL))
        rating_layout.addWidget(self.rating_title); rating_layout.addWidget(self.rating_text); rating_layout.addWidget(self.rating_button); side.addWidget(self.rating_card); side.addSpacing(10)
        footer = QFrame(); self.sidebar_footer = footer; footer.setObjectName("sidebarFooter"); footer.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed); footer_layout = QVBoxLayout(footer); footer_layout.setContentsMargins(7, 7, 7, 7); footer_layout.setSpacing(4)
        self.assistant_toggle = ToggleSwitch(); self.assistant_toggle.setObjectName("assistantToggle"); self.assistant_toggle.setChecked(False); self.assistant_toggle.setEnabled(False)
        self.assistant_option = self._toggle_option(self.assistant_toggle, "فعال‌سازی دستیار کمکی", "Enable Assistant Guide", row_click_enabled=False); self.assistant_option.setObjectName("assistantToggleOption"); self.assistant_option.setMinimumHeight(44); self.assistant_option.findChild(QLabel, "controlLabel").setWordWrap(True)
        # Assistant guide is retired: the switch stays as a hidden, disabled
        # object (old code paths reference it) but takes no sidebar space.
        self.assistant_option.setParent(footer); self.assistant_option.setVisible(False)
        self.language_button = QPushButton("English"); self.language_button.setObjectName("footerAction"); self.language_button.setFixedHeight(40); self.language_button.setIcon(cyber_icon("globe", "#9fb4d8", 19)); self.language_button.setIconSize(QSize(19, 19)); self.language_button.clicked.connect(self.toggle_language); footer_layout.addWidget(self.language_button)
        self.data_button = QPushButton(); self.data_button.setObjectName("footerAction"); self._bind_text(self.data_button, "باز کردن پوشه داده‌ها", "Open Data Folder"); self.data_button.setFixedHeight(40); self.data_button.setIcon(cyber_icon("folder", "#9fb4d8", 19)); self.data_button.setIconSize(QSize(19, 19)); self.data_button.clicked.connect(lambda: os.startfile(DATA_DIR)); footer_layout.addWidget(self.data_button); side.addWidget(footer)
        layout.addWidget(sidebar)
        content_shell = QFrame(); self.content_shell = content_shell; content_shell.setObjectName("contentShell"); content_layout = QVBoxLayout(content_shell); content_layout.setContentsMargins(0, 0, 0, 0); content_layout.setSpacing(0)
        self.stack = QStackedWidget(); self.stack.setObjectName("content"); content_layout.addWidget(self.stack, 1)
        activity_wrap = QFrame(); self.activity_wrap = activity_wrap; activity_wrap.setObjectName("activityWrap"); activity_layout = QVBoxLayout(activity_wrap); self.activity_layout = activity_layout; activity_layout.setContentsMargins(30, 0, 30, 18)
        self.activity_bar = ActivityBar(self.language)
        activity_wrap.hide()
        content_layout.addWidget(activity_wrap)
        layout.addWidget(content_shell, 1)
        pages = [self._home_page(), self._configs_page(), self._sni_maker_page(), self._scanner_page(), self._logs_page(),
                 self._apps_page(), self._tools_page(), self._pow_page(), self._support_page()]
        self.global_settings_page = SharedGlobalSettings(self)
        self.xray_settings_page = QWidget()
        self.xray_settings_page.setLayout(QVBoxLayout())
        self.xray_settings_page.layout().setContentsMargins(0, 0, 0, 0)
        self._xray_settings_form = None
        self.dns_lab_page = DirectDnsLab(self)
        self.direct_routing_view = SharedDirectRoutingView(self)
        pages.extend((self.global_settings_page, self.pow_controller.build_settings_page(),
                      self.direct_controller.build_settings_page(), self.xray_settings_page,
                      self.dns_lab_page, self.direct_routing_view))
        for page, object_name in zip(pages, (
                "homePage", "configsPage", "sniMakerPage", "sniLabPage",
                "liveLogsPage", "appBypassPage", "toolsPage", "powPage", "supportPage",
                "globalSettingsPage", "powSettingsPage", "directSettingsPage", "xraySettingsPage",
                "directDnsPage", "directRoutingPage")):
            page.setObjectName(object_name)
            self.stack.addWidget(page)
        self.stack.currentChanged.connect(self._place_activity_bar)
        for widget, object_name in (
                (self.add_btn, "addConfigButton"),
                (self.clip_btn, "importClipboardButton"),
                (self.sync_btn, "restoreOriginalsButton"),
                (self.clear_user_btn, "deleteAllUserConfigsButton"),
                (self.profile_ping_all_btn, "pingAllConfigsButton"),
                (self.maker_repo_btn, "makerLoadButton"),
                (self.maker_repo_reset_btn, "makerDefaultButton"),
                (self.maker_file_btn, "makerFileButton"),
                (self.maker_clip_btn, "makerClipboardButton"),
                (self.maker_text_btn, "makerConvertButton"),
                (self.maker_clear_btn, "makerClearButton"),
                (self.maker_start_btn, "makerTestAllButton"),
                (self.maker_stop_btn, "makerStopButton"),
                (self.maker_add_selected_btn, "makerAddSelectedButton"),
                (self.maker_add_country_btn, "makerAddCountryButton"),
                (self.maker_add_all_btn, "makerAddAllButton")):
            widget.setObjectName(object_name)
        self.show_page(0)

    def _home_page(self):
        page, body = self._scroll_page()
        self.home_page = page
        root = QVBoxLayout(body)
        self.home_root = root
        root.setSpacing(_layout.DASHBOARD_GAP)
        root.setAlignment(Qt.AlignTop)
        self.status_pill = StatusPill(self.language)
        self.wizard_restart_btn = None
        self.home_header = self._page_header("کنترل اتصال", "Connection Center", f"{ltr_isolate('Xray')}، پروکسی ویندوز و فرگمنت {ltr_isolate('TLS')}", "Xray with Windows proxy and TLS fragmentation", self.status_pill); root.addWidget(self.home_header)
        self._install_wizard_restart_button()
        hero = HeroCard(); self.hero_card = hero; hero.setMinimumHeight(318); hero_layout = QHBoxLayout(hero); self.hero_layout = hero_layout; hero_layout.setContentsMargins(38, 28, 34, 28); hero_layout.setSpacing(34)
        hero_copy = QVBoxLayout(); self.hero_copy_layout = hero_copy; hero_copy.setSpacing(9)
        eyebrow = QHBoxLayout(); eyebrow.setSpacing(9); eyebrow_icon = QLabel(); eyebrow_icon.setPixmap(cyber_pixmap("lock", "#23f5e0", 18)); eyebrow_icon.setFixedSize(20, 20)
        self.hero_badge = self._bind_text(QLabel(), "تونل امن دسکتاپ", "SECURE DESKTOP TUNNEL"); self.hero_badge.setObjectName("heroBadge")
        eyebrow.addWidget(eyebrow_icon); eyebrow.addWidget(self.hero_badge, 1); hero_copy.addLayout(eyebrow)
        self.status = QLabel(f"{ltr_isolate('VPN')} خاموش است"); self.status.setObjectName("heroStatus"); self.status.setWordWrap(True); self.status.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred); hero_copy.addWidget(self.status)
        self.connection_hint = QLabel("آماده اتصال"); self.connection_hint.setObjectName("heroHint"); self.connection_hint.setWordWrap(True); self.connection_hint.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred); hero_copy.addWidget(self.connection_hint)
        hero_copy.addStretch()
        self.connect_button = GlowButton("اتصال"); self.connect_button.setObjectName("connectButton"); self.connect_button.setProperty("i18nFa", "اتصال"); self.connect_button.setProperty("i18nEn", "Connect"); self.connect_button.setProperty("state", "idle"); self.connect_button.setIcon(cyber_icon("play", "#031422", 21)); self.connect_button.setIconSize(QSize(21, 21)); self.connect_button.setMinimumSize(216, 60); self.connect_button.setMaximumWidth(260); self.connect_button.setCursor(Qt.PointingHandCursor)
        actions = QHBoxLayout()
        actions.addWidget(self.connect_button)
        actions.addStretch(1)
        hero_copy.addLayout(actions)
        hero_layout.addLayout(hero_copy, 3)
        orb_shell = QFrame(); self.orb_shell = orb_shell; orb_shell.setObjectName("orbShell"); orb_shell.setMinimumWidth(284); orb_layout = QVBoxLayout(orb_shell); orb_layout.setContentsMargins(18, 8, 18, 10); orb_layout.setSpacing(2)
        self.orb = ConnectionOrb(); orb_caption = QLabel("NETWORK CORE"); self.orb_caption = orb_caption; orb_caption.setObjectName("orbCaption"); orb_caption.setAlignment(Qt.AlignCenter); orb_layout.addWidget(self.orb, alignment=Qt.AlignCenter); orb_layout.addWidget(orb_caption)
        self.hero_card.orb = self.orb
        hero_layout.addWidget(orb_shell, 2, Qt.AlignCenter); root.addWidget(hero)

        self.country_card = QFrame(); self.country_card.setObjectName("countrySelectorCard"); self.country_card.setMinimumHeight(104)
        country_layout = QHBoxLayout(self.country_card); self.country_layout = country_layout; country_layout.setContentsMargins(16, 10, 16, 10); country_layout.setSpacing(12)
        country_icon = QLabel(); self.country_icon = country_icon; country_icon.setObjectName("countryIcon"); country_icon.setFixedSize(46, 46); country_icon.setAlignment(Qt.AlignCenter); country_icon.setPixmap(cyber_pixmap("globe", "#78fff0", 24)); country_layout.addWidget(country_icon, 0, Qt.AlignVCenter)
        country_copy = QVBoxLayout(); country_copy.setSpacing(3); country_copy.setAlignment(Qt.AlignVCenter)
        self.country_eyebrow = self._bind_text(QLabel(), "انتخاب هوشمند مسیر", "SMART ROUTE SELECTION"); self.country_eyebrow.setObjectName("countryEyebrow")
        self.country_title = self._bind_text(QLabel(), "کشور خروجی", "Exit country"); self.country_title.setObjectName("countryTitle")
        self.country_description = self._bind_text(QLabel(), "با انتخاب کشور، فقط کانفیگ‌های سالم همان کشور دوباره تست می‌شوند و بهترین مورد متصل می‌شود.", "Choose a country to retest its verified configs and connect the best route."); self.country_description.setObjectName("countryDescription"); self.country_description.setWordWrap(True)
        for label, height in zip((self.country_eyebrow, self.country_title, self.country_description), _layout.COUNTRY_TEXT_HEIGHTS):
            label.setFixedHeight(height)
        country_copy.addWidget(self.country_eyebrow); country_copy.addWidget(self.country_title); country_copy.addWidget(self.country_description); country_layout.addLayout(country_copy, 1)
        self.country_actions_widget = QWidget(self.country_card)
        country_actions = QVBoxLayout(self.country_actions_widget); self.country_actions = country_actions; country_actions.setContentsMargins(0, 0, 0, 0); country_actions.setSpacing(5)
        self.country_count = QLabel(); self.country_count.setObjectName("countryCount"); self.country_count.setAlignment(Qt.AlignCenter)
        self.route_source_tabs = QTabBar(); self.route_source_tabs.setObjectName("routeSourceTabs"); self.route_source_tabs.setExpanding(True); self.route_source_tabs.setDrawBase(False)
        self.route_source_tabs.addTab(self.tr("پیشنهادی", "Suggested")); self.route_source_tabs.addTab("User Config")
        route_source = str(self.storage.settings.get("route_source", "suggested") or "suggested").lower()
        self.route_source_tabs.setCurrentIndex(1 if route_source == "user-config" else 0)
        self.route_source_tabs.setAccessibleName("Connection config source")
        source_row = QHBoxLayout(); source_row.setSpacing(7); source_row.addWidget(self.route_source_tabs, 1); source_row.addWidget(self.country_count)
        self.country_combo = QComboBox(); self.country_combo.setObjectName("countryCombo"); self.country_combo.setMinimumWidth(300); self.country_combo.setMinimumHeight(48); self.country_combo.setAccessibleName("Exit country"); self.country_combo.setCursor(Qt.PointingHandCursor); self.country_combo.setIconSize(QSize(30, 20))
        self.original_configs_label = QLabel("UAC Spoof Original Configs"); self.original_configs_label.setObjectName("originalConfigsLabel"); self.original_configs_label.setMinimumWidth(300); self.original_configs_label.setMinimumHeight(48); self.original_configs_label.setAlignment(Qt.AlignCenter); self.original_configs_label.setLayoutDirection(Qt.LeftToRight)
        country_actions.addLayout(source_row); country_actions.addWidget(self.country_combo); country_actions.addWidget(self.original_configs_label)
        from .pow_ui import PowExitSelector; self.pow_country_button = PowExitSelector(); self.pow_country_button.setAccessibleName("PoW exit country"); self.pow_country_button.clicked.connect(self._open_pow_country_picker); self.pow_country_button.setVisible(False)
        country_actions.addWidget(self.pow_country_button); country_layout.addWidget(self.country_actions_widget)
        self._refresh_country_selector()
        root.addWidget(self.country_card)

        self.network_metrics = SharedNetworkMetrics(self.tr, _animations_enabled)
        self.metric_cards = self.network_metrics.cards
        self.route_card, self.latency_card, self.upload_card, self.download_card, self.ip_card = self.metric_cards
        self.active_profile, self.ping_label, self.up_label, self.down_label, self.ip_label = (
            card.value for card in self.metric_cards
        )
        self.ip_flag = QLabel()
        self.ip_flag.setFixedSize(22, 16)
        policy = self.ip_flag.sizePolicy()
        policy.setRetainSizeWhenHidden(True)
        self.ip_flag.setSizePolicy(policy)
        self.ip_flag.hide()
        self.ip_card.readout.addWidget(self.ip_flag)
        self.ip_parallel = ParallelBadge()
        self.ip_card.caption.addWidget(self.ip_parallel)
        self.ip_button = self.network_metrics.ip_refresh
        self.ip_button.setToolTip(self.tr("بررسی IP", "Check IP"))
        self.ip_button.clicked.connect(self.check_ip)
        from .ip_info import ClickableCard
        self._ip_click = ClickableCard(self.ip_card, self._open_ip_details)
        root.addWidget(self.network_metrics)

        controls = QFrame(); self.quick_controls = controls; controls.setObjectName("quickControls")
        self.controls_layout = QuickControlsGrid(controls)
        self.auto_mode = ToggleSwitch(); self.auto_mode.setChecked(self.storage.settings.get("auto_mode", True)); self.auto_option = self._toggle_option(self.auto_mode, "حالت خودکار", "Auto Mode")
        self.pick_best = ToggleSwitch(); self.pick_best.setChecked(self.storage.settings.get("pick_best", False))
        self.manual_option = self._toggle_option(
            self.pick_best, "انتخاب بهترین کانفیگ از لیست", "Pick Best in List", word_wrap=True,
        )
        self.proxy_mode = ToggleSwitch(); self.proxy_mode.setChecked(self._proxy_mode_enabled()); self.proxy_option = self._toggle_option(self.proxy_mode, "پروکسی ویندوز", "Windows Proxy")
        self.proxy_option.setObjectName("proxyModeOption"); self.proxy_option.setProperty("active", self.proxy_mode.isChecked())
        self.proxy_mode.setToolTip(self.tr(
            "خاموش: هسته اسپوف فعال می‌ماند و فقط پروکسی سیستم ویندوز اعمال نمی‌شود.",
            "Off: the spoof core stays active; only Windows System Proxy is skipped.",
        ))
        self.tun_mode = ToggleSwitch(); self.tun_mode.setChecked(self._tun_mode_enabled()); self.tun_option = self._toggle_option(self.tun_mode, "حالت TUN", "TUN Mode")
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
        self.gateway_devices_badge.setIcon(QIcon(_raw_cyber_pixmap(
            "wifi", _quick_controls.PALETTES[ENGINE_XRAY]["muted_icon"], 16, lucide=True,
        )))
        self.gateway_devices_badge.setIconSize(QSize(16, 16))
        self.gateway_devices_badge.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.gateway_devices_badge.setCursor(Qt.PointingHandCursor)
        self.gateway_devices_badge.setFixedHeight(26)
        self.gateway_devices_badge.setAccessibleName("Mobile Gateway connected devices")
        self.gateway_option.layout().insertWidget(
            0, self.gateway_devices_badge, 0, Qt.AlignVCenter
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
        self.carrier = QuickCarrierCombo(); self.carrier.setObjectName("carrierModeCombo"); self.carrier.addItems(["auto", "mci", "irancell"]); self.carrier.setCurrentText(self.storage.tuning.carrier_mode); self.carrier.setMinimumWidth(100); self.carrier.setMaximumWidth(120); self.carrier.setAccessibleName("Carrier")
        self.carrier_control = QFrame(); self.carrier_control.setObjectName("carrierControl"); self.carrier_control.setMinimumWidth(190); self.carrier_control.setMaximumWidth(220); carrier_layout = QHBoxLayout(self.carrier_control); self.carrier_layout = carrier_layout; carrier_layout.setContentsMargins(7, 3, 7, 3); carrier_layout.setSpacing(6); self.carrier_label = self._bind_text(QLabel(), "اپراتور", "Carrier"); self.carrier_label.setObjectName("controlLabel"); carrier_layout.addWidget(self.carrier_label); carrier_layout.addWidget(self.carrier)
        self.tune_button = self._action_button("تنظیمات پیشرفته", "Advanced Settings", "settings", "advancedButton",
                                               button_type=QuickSettingsButton)
        self.tune_button.setProperty("chevron", True)
        self.tune_button.setIconSize(QSize(19, 19))
        self.tune_button.clicked.connect(self.open_tuning)
        self.quick_controls_header = QWidget(controls)
        self.quick_controls_header.setFixedHeight(_layout.QUICK_HEADER_HEIGHT)
        heading = QHBoxLayout(self.quick_controls_header)
        heading.setContentsMargins(0, 0, 0, 0)
        heading.setSpacing(7)
        self.quick_controls_icon = QLabel()
        heading.addWidget(self.quick_controls_icon)
        title = self._bind_text(QLabel(), "تنظیمات سریع", "Quick settings")
        title.setObjectName("quickControlsTitle")
        heading.addWidget(title)
        heading.addStretch()
        stamp = self.quick_controls_stamp = QLabel()
        stamp.setObjectName("quickControlsStamp")
        stamp_font = stamp.font()
        stamp_font.setLetterSpacing(QFont.AbsoluteSpacing, 1.1)
        stamp.setFont(stamp_font)
        heading.addWidget(stamp)
        self._quick_tiles = []
        for option, toggle, names, color in (
            (self.auto_option, self.auto_mode, {ENGINE_XRAY: "zap", ENGINE_POW: "shield", ENGINE_DIRECT: "globe"}, "icon"),
            (self.manual_option, self.pick_best, {ENGINE_XRAY: "trending-up"}, "muted_icon"),
            (self.proxy_option, self.proxy_mode, dict.fromkeys(_quick_controls.PALETTES, "layout-grid"), "icon"),
            (self.tun_option, self.tun_mode, {ENGINE_XRAY: "shield", ENGINE_POW: "square-arrow-right", ENGINE_DIRECT: "shield"}, "muted_icon"),
            (self.gateway_option, self.gateway_mode, {ENGINE_POW: "layout-grid"}, "muted_icon"),
            (self.carrier_control, None, {ENGINE_XRAY: "signal", ENGINE_POW: "brick-wall"}, "icon"),
        ):
            icon = QLabel(option)
            icon.setAttribute(Qt.WA_TransparentForMouseEvents)
            icon.setFixedSize(16, 16)
            option.layout().insertWidget(0, icon)
            self._quick_tiles.append((option, toggle, icon, names, color))
        for option in (self.auto_option, self.manual_option, self.proxy_option, self.tun_option,
                       self.gateway_option, self.carrier_control, self.tune_button):
            option.setParent(controls)
            option.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Fixed)
        self.carrier_control.setMinimumWidth(0)
        self.carrier_control.setMaximumWidth(16777215)
        controls.setFixedHeight(_layout.QUICK_PANEL_HEIGHT)
        root.addWidget(controls)
        root.addWidget(self.activity_bar)
        self._layout_home_dashboard()
        return page

    def _place_activity_bar(self, index):
        home = index == 0
        target = self.home_root if home else self.activity_layout
        if target.indexOf(self.activity_bar) == -1:
            target.addWidget(self.activity_bar)
        self.activity_wrap.setVisible(not home and index not in (self.XRAY_SETTINGS_PAGE, self.DIRECT_ROUTING_PAGE)
                                      and self.stack.currentWidget() is not self.app_routing_view)
        self.activity_bar.show()

    def _layout_hero(self, compact):
        if not hasattr(self, "hero_layout"):
            return
        self.hero_layout.setDirection(QBoxLayout.LeftToRight)
        self.hero_card.setProperty("compact", bool(compact))
        margins = (18, 12, 18, 12) if compact else (32, 22, 28, 22)
        self.hero_layout.setContentsMargins(*margins)
        self.hero_layout.setSpacing(18 if compact else 30)
        self.hero_copy_layout.setSpacing(5 if compact else 9)
        self.orb_shell.setMinimumWidth(160 if compact else 270)
        self.orb_shell.setMaximumWidth(190 if compact else 330)
        self._fit_orb(compact)
        self.connect_button.setFixedSize(176 if compact else 216, _layout.CONNECT_HEIGHT)
        _restyle(self.hero_card)

    def _fit_orb(self, compact):
        """Size the NETWORK CORE animation from the space the hero card
        really has, so the outer ring and the caption are never clipped."""
        hero_margins = self.hero_layout.contentsMargins()
        hero_height = self.hero_card.maximumHeight()
        if hero_height >= 16777215 or hero_height <= 0:
            hero_height = max(self.hero_card.height(), 178)
        shell_layout = self.orb_shell.layout()
        shell_margins = shell_layout.contentsMargins()
        caption_height = self.orb_caption.minimumHeight()
        available_height = (
            hero_height - hero_margins.top() - hero_margins.bottom()
            - shell_margins.top() - shell_margins.bottom()
            - caption_height - shell_layout.spacing() - 6
        )
        available_width = (190 if compact else 330) - shell_margins.left() - shell_margins.right()
        size = int(max(84, min(224, available_height, available_width)))
        self.orb.setFixedSize(size, size)

    def _relayout_control_bar(self):
        if not hasattr(self, "controls_layout"):
            return
        compact = getattr(self, "_controls_compact", None)
        self._controls_compact = None
        try:
            self._layout_control_bar(True if compact is None else compact)
        except Exception:
            pass

    def _layout_control_bar(self, compact):
        if not hasattr(self, "controls_layout") or self._controls_compact == compact:
            return
        self._controls_compact = compact
        grid = self.controls_layout
        mode = self.engine_mode
        direct = mode == ENGINE_DIRECT
        palette = _quick_controls.PALETTES[mode]
        while grid.count():
            grid.takeAt(0)
        if direct:
            rows = ((self.auto_option, self.proxy_option, self.tun_option, self.tune_button),)
        elif mode == ENGINE_POW:
            rows = ((self.auto_option, self.gateway_option, self.carrier_control),
                    (self.proxy_option, self.tun_option, self.tune_button))
        else:
            rows = ((self.auto_option, self.manual_option, self.gateway_option),
                    (self.proxy_option, self.tun_option, self.carrier_control, self.tune_button))
        margins = _layout.DIRECT_QUICK_MARGINS if direct else _layout.QUICK_GRID_MARGINS
        tile_height = _layout.DIRECT_QUICK_TILE_HEIGHT if direct else _layout.QUICK_TILE_HEIGHT
        grid.equal_columns = len(rows[-1])
        grid.setContentsMargins(*margins)
        grid.setHorizontalSpacing(9 if direct else _layout.QUICK_GRID_GAP)
        grid.setVerticalSpacing(7 if direct else _layout.QUICK_GRID_GAP)
        grid.setAlignment(Qt.AlignVCenter)
        for column in range(4):
            grid.setColumnStretch(column, int(column < grid.equal_columns))
        for option, toggle, icon, names, color in self._quick_tiles:
            option.setFixedHeight(tile_height)
            row = option.layout()
            vertical = 2 if option is self.manual_option else 5
            row.setContentsMargins(9, vertical, 9, vertical)
            row.setSpacing(6)
            if toggle is not None:
                row.removeWidget(toggle)
                row.addWidget(toggle)
                toggle.set_quick_style(palette)
            name = names.get(mode)
            icon.setVisible(bool(name))
            if name:
                icon.setPixmap(_raw_cyber_pixmap(name, palette[color], 16, lucide=True))
        self.carrier_layout.setStretch(self.carrier_layout.indexOf(self.carrier_label), 1)
        self.carrier.setFixedSize(*_layout.QUICK_DROPDOWN_SIZE)
        self.carrier.arrow_color = palette["icon"] if mode == ENGINE_XRAY else None
        self.tune_button.setFixedHeight(tile_height)
        self.tune_button.quick_palette = palette
        self.quick_controls_stamp.setText(f"{mode.upper()} / CONTROL")
        self.quick_controls_icon.setPixmap(_raw_cyber_pixmap("sliders", palette["icon"], 17, lucide=True))
        self.tune_button.setIcon(QIcon(_raw_cyber_pixmap("settings", palette["icon"], 18, lucide=True)))
        grid.addWidget(self.quick_controls_header, 0, 0, 1, grid.equal_columns)
        for row, tiles in enumerate(rows, start=1):
            column = 0
            for tile in tiles:
                span = 2 if mode == ENGINE_XRAY and tile is self.auto_option else 1
                grid.addWidget(tile, row, column, 1, span)
                column += span

    def _layout_home_dashboard(self, narrow=None, dense=None):
        if not hasattr(self, "home_root"):
            return
        narrow = self.width() < 1320 if narrow is None else bool(narrow)
        language = "en" if self.language == "en" else "fa"
        stack_height = self.height() - _layout.ACTIVITY_HEIGHT[language] - 8
        dense = stack_height < 760 if dense is None else bool(dense)
        layout = _layout.dashboard_layout(stack_height, narrow, dense)
        self.home_root.setContentsMargins(*layout.margin)
        self.home_header.setFixedHeight(layout.header)
        self.home_header.setProperty("compact", dense)
        self.home_header.layout().setContentsMargins(*(13, 8, 13, 8) if dense else (19, 12, 19, 12))
        self.home_header.findChild(QLabel, "pageHeaderIcon").setFixedSize(*(42, 42) if dense else (54, 54))
        for name, height in zip(("pageEyebrow", "pageTitle", "pageSubtitle"), _layout.HEADER_TEXT_HEIGHTS[language][not dense]):
            self.home_header.findChild(QLabel, name).setFixedHeight(height)
        self.status_pill.setFixedSize(*_layout.STATUS_PILL_SIZE[language])
        hint, caption = _layout.HERO_TEXT_HEIGHTS[language]
        self.connection_hint.setFixedHeight(hint)
        self.orb_caption.setFixedHeight(caption)
        self.hero_card.setFixedHeight(layout.hero)
        self._layout_hero(dense or layout.hero < 250)
        self.country_card.setVisible(True)
        self.country_card.setFixedHeight(layout.country)
        self.country_card.setProperty("compact", dense)
        self.country_layout.setContentsMargins(*(12, 7, 12, 7) if dense else (16, 10, 16, 10))
        self.country_layout.setSpacing(9 if dense else 12)
        self.country_icon.setFixedSize(*(40, 40) if dense else (46, 46))
        self.country_actions_widget.setFixedWidth(340)
        self.country_combo.setMinimumWidth(210 if dense else 280)
        self.country_combo.setMaximumWidth(255 if dense else 340)
        self.country_combo.setFixedHeight(38 if dense else 42)
        self.country_count.setMaximumHeight(38 if dense else 28)
        _restyle(self.country_card)
        self._layout_control_bar(True)
        margin = 18 if dense else 30
        self.activity_layout.setContentsMargins(margin, 0, margin, 8)
        self.activity_bar.setFixedHeight(_layout.ACTIVITY_HEIGHT[language])

    def _configs_page(self):
        page = QWidget()
        page.setObjectName("configsPage")
        root = QVBoxLayout(page)
        root.setContentsMargins(12, 8, 12, 10)
        root.setSpacing(8)
        self.config_count_label = QLabel()
        self.config_count_label.setObjectName("configCount")
        root.addWidget(self._page_header(
            "مدیریت کانفیگ‌ها", "Manage configs",
            "کانفیگ‌های خود را اضافه، بررسی و فعال کنید.",
            "Add, check and activate your configs.", self.config_count_label,
            compact_name="configsHeader",
        ))

        toolbar = QFrame()
        toolbar.setObjectName("configToolbar")
        bar = QHBoxLayout(toolbar)
        bar.setContentsMargins(8, 7, 8, 7)
        bar.setSpacing(8)
        self.add_btn = self._action_button("افزودن کانفیگ", "Add config", "plus")
        self.clip_btn = self._action_button("چسباندن لینک", "Paste link", "copy")
        self.profile_ping_all_btn = self._action_button("تست پینگ همه", "Ping all", "gauge")
        self.sync_btn = self._action_button("بازیابی لیست اصلی", "Restore original list", "refresh")
        for button in (self.add_btn, self.clip_btn, self.profile_ping_all_btn, self.sync_btn):
            button.setFixedHeight(34)
            button.setIconSize(QSize(14, 14))
            bar.addWidget(button)
        self.add_btn.setIcon(cyber_icon("plus", "#071f2a", 14))
        self.config_search = QLineEdit()
        self.config_search.setObjectName("configSearch")
        self.config_search.setClearButtonEnabled(True)
        self.config_search.setMinimumWidth(105)
        self.config_search.setFixedHeight(34)
        self.config_search.addAction(cyber_icon("search", "#91adc4", 14), QLineEdit.LeadingPosition)
        self.config_search.textChanged.connect(self._filter_config_rows)
        bar.addWidget(self.config_search, 1)
        root.addWidget(toolbar)

        panel = QFrame()
        panel.setObjectName("configPanel")
        content = QVBoxLayout(panel)
        content.setContentsMargins(1, 1, 1, 1)
        content.setSpacing(0)
        controls = QFrame()
        controls.setObjectName("configTabsRow")
        controls_layout = QHBoxLayout(controls)
        controls_layout.setContentsMargins(8, 7, 8, 7)
        controls_layout.setSpacing(8)
        self.config_segments = QTabBar()
        self.config_segments.setObjectName("configSegments")
        self.config_segments.setDrawBase(False)
        self.config_segments.setExpanding(False)
        self.config_segments.setUsesScrollButtons(False)
        for _ in range(3):
            self.config_segments.addTab("")
        controls_layout.addWidget(self.config_segments)
        controls_layout.addStretch(1)
        self.profile_sort_combo = QComboBox()
        self.profile_sort_combo.setObjectName("profileSortCombo")
        self.profile_sort_combo.setFixedHeight(34)
        self.profile_sort_combo.addItem("", "country")
        self.profile_sort_combo.addItem("", "ping")
        controls_layout.addWidget(self.profile_sort_combo)
        content.addWidget(controls)

        self.profile_tabs = QStackedWidget()
        self.profile_tabs.setObjectName("profileTabs")
        self.user_config_list, self.manual_list, self.suggested_list = (ProfileTable() for _ in range(3))
        self.profile_pages = [self.user_config_list, self.manual_list, self.suggested_list]
        for table in self.profile_pages:
            self.profile_tabs.addWidget(table)
            table.itemSelectionChanged.connect(self._update_config_actions)
            table.deleteRequested.connect(self.delete_profile)
            table.editRequested.connect(self._edit_profile_by_id)
            table.horizontalHeader().geometriesChanged.connect(self._position_profile_select_all)
        self.config_segments.currentChanged.connect(lambda index: self.profile_tabs.setCurrentIndex(2 - index))
        self.profile_tabs.currentChanged.connect(self._profile_tab_changed)
        self.profile_tabs.currentChanged.connect(self._update_config_actions)
        self.profile_tabs.setCurrentIndex(2)
        content.addWidget(self.profile_tabs, 1)

        self.profile_select_all_checkbox = QCheckBox()
        self.profile_select_all_checkbox.setObjectName("profileSelectAll")
        self.profile_select_all_checkbox.setLayoutDirection(Qt.LeftToRight)
        self.profile_select_all_checkbox.setFixedSize(16, 16)
        self.profile_select_all_checkbox.clicked.connect(self._set_current_profile_list_selection)

        footer = QFrame()
        footer.setObjectName("configTableFooter")
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(10, 4, 10, 4)
        footer_layout.setSpacing(8)
        self.config_collection_label = QLabel()
        self.config_selection_count = QLabel()
        self.config_delete_selected = self._action_button("حذف انتخاب‌شده‌ها", "Delete selected", "trash")
        self.clear_user_btn = self._action_button("حذف همه", "Delete all", "trash")
        for button in (self.config_delete_selected, self.clear_user_btn):
            button.setIconSize(QSize(13, 13))
            button.setFixedHeight(26)
        self.config_delete_selected.clicked.connect(self.delete_profile)
        self.clear_user_btn.setToolTip(self.tr("حذف همه کانفیگ‌های من", "Delete all my configs"))
        footer_layout.addWidget(self.config_collection_label)
        footer_layout.addStretch(1)
        footer_layout.addWidget(self.config_delete_selected)
        footer_layout.addWidget(self.clear_user_btn)
        footer_layout.addWidget(self.config_selection_count)
        footer.setFixedHeight(38)
        content.addWidget(footer)
        root.addWidget(panel, 1)

        self.profile_ping_all_btn.clicked.connect(self._ping_current_profile_list)
        self.profile_sort_combo.currentIndexChanged.connect(self._profile_sort_changed)
        self._update_config_actions()
        return page

    def _sni_maker_page(self):
        page = QWidget()
        page.setObjectName("sniMakerPage")
        self.maker_page = page
        root = QVBoxLayout(page)
        root.setContentsMargins(12, 8, 12, 10)
        root.setSpacing(8)

        def heading(fa, en):
            label = self._bind_text(QLabel(), fa, en)
            label.setObjectName("makerStepTitle")
            return label

        def action(fa, en, icon=None, style="secondaryAction"):
            button = self._action_button(fa, en, icon, style)
            button.setFixedHeight(34)
            button.setIconSize(QSize(14, 14))
            if style == "primaryAction":
                button.setProperty("makerPrimary", True)
                if icon:
                    button.setIcon(cyber_icon(icon, "#062331", 14))
            return button

        def panel(name):
            frame = QFrame()
            frame.setObjectName(name)
            frame.setFixedHeight(202)
            box = QVBoxLayout(frame)
            box.setContentsMargins(12, 10, 12, 10)
            box.setSpacing(6)
            return frame, box

        def row(parent, *widgets):
            layout = QHBoxLayout()
            layout.setSpacing(6)
            for widget in widgets:
                layout.addWidget(widget)
            parent.addLayout(layout)
            return layout

        self.maker_header = self._page_header(
            "سازنده کانفیگ اس‌ان‌آی", "SNI Config Maker",
            "کانفیگ بسازید، اتصال آن را بررسی کنید و موارد سالم را ذخیره کنید.",
            "Build configs, check their connections and save the healthy ones.",
            compact_name="makerHeader",
        )
        root.addWidget(self.maker_header)

        top = QHBoxLayout()
        top.setSpacing(8)
        self.maker_source_card, source = panel("makerSourceCard")
        self.maker_import_badge = self._bind_text(ElidedLabel(), "آماده دریافت", "Ready to import")
        self.maker_import_badge.setObjectName("makerDetail")
        source_heading = row(source, heading("۱. افزودن کانفیگ‌ها", "1. Add configs"), self.maker_import_badge)
        source_heading.setStretch(1, 1)
        self.maker_import_badge.setAlignment(Qt.AlignTrailing | Qt.AlignVCenter)
        saved_url = str(self.storage.settings.get("sni_maker_url", "") or "").strip()
        if not saved_url or saved_url in LEGACY_SNI_MAKER_URLS:
            saved_url = DEFAULT_SNI_MAKER_URL
        self.maker_repo_url = QLineEdit(saved_url)
        self.maker_repo_url.setObjectName("makerRepoUrl")
        self.maker_repo_url.setAlignment(Qt.AlignLeft | Qt.AlignAbsolute)
        self.maker_repo_url.setFixedHeight(34)
        self.maker_repo_url.setMinimumWidth(80)
        self.maker_repo_url.setClearButtonEnabled(True)
        self.maker_repo_url.setCursorPosition(0)
        self.maker_repo_btn = action("دریافت", "Load", "download")
        self.maker_repo_reset_btn = action("لینک پیش‌فرض", "Default link", style="quietButton")
        repository_row = row(source, self.maker_repo_url, self.maker_repo_btn, self.maker_repo_reset_btn)
        repository_row.setStretch(0, 1)

        self.maker_source_editor = ConfigDropEdit()
        self.maker_source_editor.setObjectName("makerSourceEditor")
        self.maker_source_editor.setMinimumHeight(50)
        self.maker_source_editor.textChanged.connect(self._sync_maker_editor_direction)
        source.addWidget(self.maker_source_editor, 1)
        self.maker_text_btn = action("ساخت کانفیگ SNI", "Build SNI configs", "sparkles", "primaryAction")
        self.maker_file_btn = action("انتخاب فایل", "Choose file")
        self.maker_clip_btn = action("چسباندن متن", "Paste text")
        self.maker_clear_btn = action("پاک کردن", "Clear", style="dangerButton")
        import_row = row(source, self.maker_text_btn, self.maker_file_btn, self.maker_clip_btn, self.maker_clear_btn)
        import_row.setStretch(0, 2)
        import_row.setStretch(1, 1)
        import_row.setStretch(2, 1)
        top.addWidget(self.maker_source_card, 3)

        self.maker_control, control = panel("makerTestBar")
        self.maker_progress = ScanProgressPanel(self.language)
        self.maker_progress.setObjectName("makerProgress")
        self._set_maker_progress_status("آماده بررسی", "Ready to check")
        self._set_maker_progress_detail("منتظر کانفیگ", "Waiting for configs")
        test_heading = row(control, heading("۲. بررسی اتصال", "2. Check connection"))
        self.maker_progress.set_compact(test_heading, "makerDetail")

        input_grid = QGridLayout()
        input_grid.setContentsMargins(0, 0, 0, 0)
        input_grid.setHorizontalSpacing(8)
        input_grid.setVerticalSpacing(4)
        self.maker_threads = NumericInput(48, 4, 64)
        self.maker_timeout = NumericInput(8, 3, 20)
        for column, field, fa, en in (
            (0, self.maker_threads, "تعداد تست هم‌زمان", "Concurrent tests"),
            (1, self.maker_timeout, "مهلت هر تست (ثانیه)", "Test timeout (seconds)"),
        ):
            label = self._bind_text(QLabel(), fa, en)
            label.setObjectName("makerDetail")
            label.setBuddy(field.edit)
            field.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            field.minus.setFixedSize(24, 24)
            field.plus.setFixedSize(24, 24)
            field.edit.setFixedHeight(26)
            input_grid.addWidget(label, 0, column)
            input_grid.addWidget(field, 1, column)
            input_grid.setColumnStretch(column, 1)
        control.addLayout(input_grid)
        control.addWidget(self.maker_progress)
        control.addStretch(1)
        self.maker_start_btn = action("بررسی همه کانفیگ‌ها", "Check all configs", "play", "primaryAction")
        self.maker_start_btn.setEnabled(False)
        self.maker_stop_btn = action("توقف بررسی", "Stop checking", style="quietButton")
        self.maker_stop_btn.setEnabled(False)
        test_actions = row(control, self.maker_start_btn, self.maker_stop_btn)
        test_actions.setStretch(0, 1)
        top.addWidget(self.maker_control, 2)
        root.addLayout(top)

        self.maker_results_panel = QFrame()
        self.maker_results_panel.setObjectName("makerResultsPanel")
        results = QVBoxLayout(self.maker_results_panel)
        results.setContentsMargins(1, 1, 1, 1)
        results.setSpacing(0)

        toolbar = QFrame()
        toolbar.setObjectName("makerResultToolbar")
        title_row = QHBoxLayout(toolbar)
        title_row.setContentsMargins(12, 6, 12, 6)
        title_row.setSpacing(8)
        title_row.addWidget(heading("۳. نتایج بررسی", "3. Check results"))
        title_row.addStretch(1)
        self.maker_chip_total = QLabel()
        self.maker_chip_healthy = QLabel()
        self.maker_chip_failed = QLabel()
        self.maker_chip_ech = QLabel()
        for chip, tone in ((self.maker_chip_total, "total"), (self.maker_chip_healthy, "ok"),
                           (self.maker_chip_failed, "bad"), (self.maker_chip_ech, "ech")):
            chip.setObjectName("makerChip")
            chip.setProperty("tone", tone)
            title_row.addWidget(chip)
        results.addWidget(toolbar)

        filters = QFrame()
        filters.setObjectName("makerFilters")
        filters_row = QHBoxLayout(filters)
        filters_row.setContentsMargins(10, 3, 10, 3)
        filters_row.setSpacing(8)
        self.maker_country_rail = CountryRail()
        self.maker_country_rail.set_country_counts({}, all_label=self.tr("همه کشورها", "All countries"))
        filters_row.addWidget(self.maker_country_rail, 2)
        self.maker_search = QLineEdit()
        self.maker_search.setObjectName("makerSearch")
        self.maker_search.setFixedHeight(32)
        self.maker_search.setClearButtonEnabled(True)
        filters_row.addWidget(self.maker_search, 1)
        self.maker_status_filter = QComboBox()
        self.maker_status_filter.setObjectName("makerStatusFilter")
        self.maker_status_filter.setFixedHeight(32)
        for status in ("", "healthy", "failed", "testing"):
            self.maker_status_filter.addItem("", status)
        filters_row.addWidget(self.maker_status_filter)
        results.addWidget(filters)

        self.maker_model = MakerResultsModel(parent=self)
        self.maker_proxy = MakerFilterProxy(self)
        self.maker_proxy.setSourceModel(self.maker_model)
        self.maker_table = QTableView()
        self.maker_table.setObjectName("makerResultsTable")
        self.maker_table.setModel(self.maker_proxy)
        self.maker_table.setSortingEnabled(True)
        self.maker_table.sortByColumn(MakerColumns.STATUS, Qt.AscendingOrder)
        self.maker_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.maker_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.maker_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.maker_table.setAlternatingRowColors(True)
        self.maker_table.setShowGrid(False)
        self.maker_table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.maker_table.verticalHeader().hide()
        self.maker_table.verticalHeader().setDefaultSectionSize(40)
        table_header = self.maker_table.horizontalHeader()
        table_header.setFixedHeight(36)
        table_header.setHighlightSections(False)
        for column, width in ((MakerColumns.MARK, 38), (MakerColumns.COUNTRY, 98),
                              (MakerColumns.STATUS, 146), (MakerColumns.PING, 96)):
            table_header.setSectionResizeMode(column, QHeaderView.Fixed)
            self.maker_table.setColumnWidth(column, width)
        table_header.setSectionResizeMode(MakerColumns.URI, QHeaderView.Stretch)
        self.maker_select_all_checkbox = QCheckBox(table_header)
        self.maker_select_all_checkbox.setObjectName("makerSelectAll")
        self.maker_select_all_checkbox.setLayoutDirection(Qt.LeftToRight)
        self.maker_select_all_checkbox.setFixedSize(22, 22)
        self.maker_select_all_checkbox.setEnabled(False)
        self.maker_select_all_checkbox.setAccessibleName(self.tr("انتخاب همه کانفیگ‌ها", "Select all configs"))
        table_header.geometriesChanged.connect(self._position_maker_select_all)
        table_header.sectionResized.connect(lambda *_args: self._position_maker_select_all())
        QTimer.singleShot(0, self._position_maker_select_all)
        self.maker_empty_hint = _OverlayHint(self.maker_table.viewport())
        self.maker_empty_hint.setObjectName("makerEmptyHint")
        results.addWidget(self.maker_table, 1)

        self.maker_actions = QFrame()
        self.maker_actions.setObjectName("makerActionBar")
        actions = QHBoxLayout(self.maker_actions)
        actions.setContentsMargins(10, 7, 10, 7)
        actions.setSpacing(6)
        self.maker_add_all_btn = action("افزودن همه کانفیگ‌های سالم", "Add all healthy configs", "plus", "primaryAction")
        self.maker_add_country_btn = action("افزودن سالم‌های این کشور", "Add healthy from this country")
        self.maker_add_selected_btn = action("افزودن موارد انتخابی", "Add selected")
        self.maker_copy_btn = action("کپی", "Copy", style="quietButton")
        self.maker_export_btn = action("ذخیره در فایل", "Save to file", style="quietButton")
        for button in (self.maker_add_all_btn, self.maker_add_country_btn, self.maker_add_selected_btn,
                       self.maker_copy_btn, self.maker_export_btn):
            if button is self.maker_copy_btn:
                actions.addStretch(1)
            button.setEnabled(False)
            actions.addWidget(button)
        results.addWidget(self.maker_actions)
        root.addWidget(self.maker_results_panel, 1)

        footer = QFrame()
        footer.setObjectName("makerFooter")
        footer_row = QHBoxLayout(footer)
        footer_row.setContentsMargins(10, 3, 10, 3)
        self.maker_summary_badge = QLabel()
        self.maker_summary_badge.setObjectName("makerFooterSummary")
        self.maker_view_configs_btn = action("مشاهده کانفیگ‌های من", "View my configs", "external-link", "quietButton")
        footer_row.addWidget(self.maker_summary_badge)
        footer_row.addStretch(1)
        footer_row.addWidget(self.maker_view_configs_btn)
        root.addWidget(footer)
        return page

    def _scanner_page(self):
        page = QWidget()
        page.setObjectName("sniLabPage")
        root = QVBoxLayout(page)
        root.setContentsMargins(12, 8, 12, 10)
        root.setSpacing(8)

        self.scan_state_badge = QLabel()
        self.scan_state_badge.setObjectName("labState")
        root.addWidget(self._page_header(
            "آزمایشگاه اس‌ان‌آی", "SNI Lab",
            "دامنه‌ها را آزمایش کنید و بهترین مسیر اتصال را پیدا کنید.",
            "Test domains and find the best route.", self.scan_state_badge, compact_name="labHeader",
        ))

        def panel(name, fa, en):
            frame = QFrame()
            frame.setObjectName(name)
            box = QVBoxLayout(frame)
            box.setContentsMargins(12, 9, 12, 9)
            box.setSpacing(6)
            title = self._bind_text(QLabel(), fa, en)
            title.setObjectName("labStep")
            head = QHBoxLayout()
            head.addWidget(title)
            box.addLayout(head)
            return frame, box, head

        def action(fa, en, glyph=None):
            button = self._action_button(fa, en, glyph)
            button.setFixedHeight(34)
            button.setIconSize(QSize(14, 14))
            return button

        top = QHBoxLayout()
        top.setSpacing(8)
        domains, domain_box, domain_head = panel("domainPanel", "۱. دامنه‌های مورد آزمایش", "1. Domains to test")
        self.scan_domain_count = QLabel()
        self.scan_domain_count.setObjectName("labDetail")
        domain_head.addStretch(1)
        domain_head.addWidget(self.scan_domain_count)
        domain_help = self._bind_text(QLabel(), "در هر خط یک آدرس دامنه وارد کنید.", "Enter one domain per line.")
        domain_help.setObjectName("labDetail")
        domain_box.addWidget(domain_help)
        self.domains = NumberedDomainEdit()
        self.domains.setPlaceholderText("example.com\ncdn.example.net")
        self.domains.setMinimumHeight(118)
        self.domains.textChanged.connect(self._update_scan_domain_count)
        try:
            self.domains.setPlainText("\n".join((ASSETS / "domains.txt").read_text(encoding="utf-8").splitlines()[:80]))
        except OSError:
            pass
        self._update_scan_domain_count()
        domain_box.addWidget(self.domains, 1)
        top.addWidget(domains, 3)

        options, option_box, option_head = panel("scanOptions", "۲. تنظیمات آزمایش", "2. Test settings")
        option_grid = QGridLayout()
        option_grid.setHorizontalSpacing(8)
        option_grid.setVerticalSpacing(5)
        option_grid.setColumnStretch(0, 1)
        self.scan_threads = NumericInput(30, 1, 100)
        self.scan_tries = NumericInput(3, 1, 10)
        self.scan_timeout = NumericInput(12, 2, 60)
        for row, (fa, en, field) in enumerate((
            ("تعداد تست هم‌زمان", "Concurrent tests", self.scan_threads),
            ("تعداد تلاش برای هر دامنه", "Attempts per domain", self.scan_tries),
            ("مهلت هر تست (ثانیه)", "Timeout (seconds)", self.scan_timeout),
        )):
            label = self._bind_text(QLabel(), fa, en)
            label.setObjectName("labDetail")
            label.setBuddy(field.edit)
            field.setFixedHeight(34)
            field.setMaximumWidth(126)
            field.minus.setFixedSize(22, 22)
            field.plus.setFixedSize(22, 22)
            field.edit.setFixedHeight(24)
            option_grid.addWidget(label, row, 0)
            option_grid.addWidget(field, row, 1)
        option_box.addLayout(option_grid)
        self.scan_progress = ScanProgressPanel(self.language)
        self.scan_progress.setObjectName("labProgress")
        self.scan_progress.set_compact(option_head, "labProgressDetail")
        self.scan_progress.setValue(0)
        self._set_scan_status("آمادهٔ آزمایش", "Ready to test")
        self._set_scan_detail("منتظر شروع آزمایش", "Waiting to start")
        option_box.addStretch(1)
        option_box.addWidget(self.scan_progress)
        test_actions = QHBoxLayout()
        test_actions.setSpacing(6)
        self.scan_button = action("شروع آزمایش", "Start test", "play")
        self.scan_button.setObjectName("labPrimary")
        self.scan_button.setIcon(cyber_icon("play", "#071f2a", 14))
        self.scan_stop_btn = action("توقف آزمایش", "Stop test")
        self.scan_stop_btn.setEnabled(False)
        test_actions.addWidget(self.scan_button, 1)
        test_actions.addWidget(self.scan_stop_btn)
        option_box.addLayout(test_actions)
        top.addWidget(options, 2)
        root.addLayout(top)

        results = QFrame()
        results.setObjectName("labResults")
        result_box = QVBoxLayout(results)
        result_box.setContentsMargins(1, 1, 1, 1)
        result_box.setSpacing(0)
        toolbar = QFrame()
        toolbar.setObjectName("labToolbar")
        tools = QHBoxLayout(toolbar)
        tools.setContentsMargins(9, 6, 9, 6)
        tools.setSpacing(8)
        self.scan_tabs = QTabBar()
        self.scan_tabs.setObjectName("configSegments")
        self.scan_tabs.setDrawBase(False)
        self.scan_tabs.setExpanding(False)
        self.scan_tabs.setUsesScrollButtons(False)
        self.scan_tabs.addTab(self.tr("نتایج آزمایش", "Test results"))
        self.scan_tabs.addTab(self.tr("ذخیره‌شده‌ها", "Saved"))
        tools.addWidget(self.scan_tabs)
        self.scan_search = QLineEdit()
        self.scan_search.setObjectName("labSearch")
        self.scan_search.setClearButtonEnabled(True)
        self.scan_search.setFixedHeight(34)
        self.scan_search.addAction(cyber_icon("search", "#91adc4", 14), QLineEdit.LeadingPosition)
        tools.addWidget(self.scan_search, 1)
        self.scan_good = QLabel()
        self.scan_good.setObjectName("labCount")
        self.scan_good.setProperty("tone", "success")
        self.scan_bad = QLabel()
        self.scan_bad.setObjectName("labCount")
        self.scan_bad.setProperty("tone", "danger")
        tools.addWidget(self.scan_good)
        tools.addWidget(self.scan_bad)
        result_box.addWidget(toolbar)

        self.results_table = self._result_table()
        self.bookmarks_table = self._result_table()
        tables = QStackedWidget()
        tables.addWidget(self.results_table)
        tables.addWidget(self.bookmarks_table)
        self.scan_tabs.currentChanged.connect(tables.setCurrentIndex)
        result_box.addWidget(tables, 1)

        selection_bar = QFrame()
        selection_bar.setObjectName("labSelection")
        selection = QHBoxLayout(selection_bar)
        selection.setContentsMargins(10, 3, 10, 3)
        selection.addWidget(self._bind_text(QLabel(), "دامنهٔ انتخاب‌شده", "Selected domain"))
        self.scan_selection_label = ElidedLabel("—")
        self.scan_selection_label.setObjectName("labSelectedDomain")
        self.scan_selection_label.setLayoutDirection(Qt.LeftToRight)
        self.scan_selection_label.setAlignment(Qt.AlignLeft if self.language == "fa" else Qt.AlignRight)
        selection.addWidget(self.scan_selection_label, 1)
        selection_bar.setFixedHeight(32)
        result_box.addWidget(selection_bar)

        action_bar = QFrame()
        action_bar.setObjectName("sniActionBar")
        actions = QHBoxLayout(action_bar)
        actions.setContentsMargins(8, 7, 8, 7)
        actions.setSpacing(6)
        self.apply_all_sni_btn = action("اعمال SNI روی همه کانفیگ‌های پیشنهادی", "Apply SNI to all suggested configs")
        self.apply_all_sni_btn.setObjectName("labPrimary")
        self.apply_sni_btn = action("اعمال SNI روی کانفیگ فعال", "Apply SNI to active config")
        self.bookmark_btn = action("ذخیره نتیجه", "Save result", "save")
        self.copy_result_btn = action("کپی نتیجه", "Copy result", "copy")
        self.undo_apply_btn = action("بازگرداندن آخرین تغییر", "Undo last change", "refresh")
        self.undo_apply_btn.setEnabled(False)
        actions.addWidget(self.apply_all_sni_btn)
        actions.addWidget(self.apply_sni_btn)
        actions.addStretch(1)
        actions.addWidget(self.bookmark_btn)
        actions.addWidget(self.copy_result_btn)
        actions.addWidget(self.undo_apply_btn)
        result_box.addWidget(action_bar)
        root.addWidget(results, 1)
        self.scan_search.textChanged.connect(self._filter_scan_results)
        return page

    def _result_table(self):
        table = QTableWidget(0, 9)
        table.setObjectName("resultsTable")
        table.setLayoutDirection(Qt.LeftToRight)
        table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)
        table.verticalHeader().hide()
        table.verticalHeader().setDefaultSectionSize(42)
        header = table.horizontalHeader()
        header.setMinimumSectionSize(1)
        header.setFixedHeight(34)
        header.setHighlightSections(False)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        for col, width in ((0, 30), (2, 122), (3, 72), (4, 70), (5, 100), (6, 90), (7, 90), (8, 60)):
            header.setSectionResizeMode(col, QHeaderView.Fixed)
            table.setColumnWidth(col, width)
        header.setSortIndicator(8, Qt.DescendingOrder)
        table.setSortingEnabled(True)
        table.itemSelectionChanged.connect(self._update_scan_selection)
        return table

    def _apps_page(self):
        self.app_routing_view = SharedAppRoutingView(self, ToggleSwitch)
        self.process_table = self.app_routing_view.table
        return self.app_routing_view

    def _apply_xray_port_setting(self):
        """Hand the saved engine-1 SOCKS/HTTP pair to the engine (next start)."""
        try:
            from .proxy_ports import xray_ports_from_settings
            self.engine.preferred_ports = xray_ports_from_settings(self.storage.settings)
        except Exception:
            pass

    def _sync_proxy_port_panels(self, except_panel=None):
        """Ports live in settings dialogs now; nothing to sync on Home."""
        return


    def _refresh_proxy_port_panels_for_engine(self):
        """No Home port panels."""
        return


    def _open_proxy_port_dialog(self):
        """Ports are in Advanced / PoW Settings; open Advanced for Xray."""
        try:
            self.open_tuning()
        except Exception:
            pass


    def _tools_page(self):
        page, body = self._scroll_page(); root = QVBoxLayout(body); root.setContentsMargins(34, 28, 34, 26); root.setSpacing(16)
        root.addWidget(self._page_header("ابزارهای شبکه", "Network Tools", "قابلیت‌های بیشتر نسخه کامپیوتر", "Focused utilities for route, IP and diagnostics"))
        self.tools_grid = QGridLayout(); self.tools_grid.setSpacing(14); self.tool_cards = []
        tool_specs = [
            ("radio", "Reality Probe", "Reality Probe", "تست TCP و TLS مقصد فعال", "Test the active target over TCP and TLS", self.reality_probe, True),
            ("globe", "تست IP مستقیم", "Direct IP Test", "نمایش IP بدون پروکسی", "Show the public IP without the tunnel", lambda: self.check_ip(False), True),
            ("shield", "تست IP تونل", "Tunnel IP Test", "نمایش IP از پروکسی UAC", "Show the public IP through UAC proxy", lambda: self.check_ip(True), True),
            ("sparkles", "شروع سریع", "Quick Start", "تشخیص خط و راه‌اندازی خودکار با یه دکمه", "Detect your line and set everything up in one tap", lambda: self._open_wizard(), True),
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

        self.assistant_help_card = MotionFrame(); self.assistant_help_card.setObjectName("assistantHelpCard")
        assistant_layout = QHBoxLayout(self.assistant_help_card); assistant_layout.setContentsMargins(20, 16, 20, 16); assistant_layout.setSpacing(14)
        assistant_icon = QLabel(); assistant_icon.setFixedSize(46, 46); assistant_icon.setAlignment(Qt.AlignCenter); assistant_icon.setPixmap(cyber_pixmap("sparkles", "#23f5e0", 25)); assistant_layout.addWidget(assistant_icon)
        assistant_copy = QVBoxLayout(); assistant_copy.setSpacing(3)
        assistant_title = self._bind_text(QLabel(), "دستیار کمکی برنامه", "Assistant Guide"); assistant_title.setObjectName("supportTitle")
        assistant_description = self._bind_text(QLabel(), "راهنمای مرحله‌به‌مرحله را دوباره اجرا کن؛ دستیار از وضعیت فعلی برنامه باخبر می‌ماند.", "Replay the step-by-step guide; the assistant remains aware of the current app state."); assistant_description.setObjectName("supportDescription"); assistant_description.setWordWrap(True)
        assistant_copy.addWidget(assistant_title); assistant_copy.addWidget(assistant_description)
        assistant_preferences = QHBoxLayout(); assistant_preferences.setSpacing(8)
        self.assistant_guides_toggle = ToggleSwitch(); self.assistant_guides_toggle.setChecked(bool(self.storage.settings.get("assistant_guides_enabled", True)))
        self.assistant_guides_option = self._toggle_option(self.assistant_guides_toggle, "راهنماهای آموزشی", "Educational Guides"); self.assistant_guides_option.setObjectName("assistantPreferenceOption")
        self.assistant_warnings_toggle = ToggleSwitch(); self.assistant_warnings_toggle.setChecked(bool(self.storage.settings.get("assistant_warnings_enabled", True)))
        self.assistant_warnings_option = self._toggle_option(self.assistant_warnings_toggle, "هشدارهای دستیار", "Assistant Alerts"); self.assistant_warnings_option.setObjectName("assistantPreferenceOption")
        assistant_preferences.addWidget(self.assistant_guides_option); assistant_preferences.addWidget(self.assistant_warnings_option); assistant_copy.addLayout(assistant_preferences)
        assistant_layout.addLayout(assistant_copy, 1)
        self.assistant_replay_button = self._action_button("اجرای دوباره راهنمای برنامه", "Replay App Guide", "refresh", "secondaryAction"); self.assistant_replay_button.setObjectName("assistantReplayButton"); self.assistant_replay_button.setMinimumWidth(210); assistant_layout.addWidget(self.assistant_replay_button)
        # Retired with the sidebar switch: kept hidden, not laid out.
        self.assistant_help_card.setParent(body); self.assistant_help_card.setVisible(False)

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
        self.assistant_toggle.toggled.connect(self._assistant_enabled_changed)
        self.assistant_guides_toggle.toggled.connect(self._assistant_guides_changed)
        self.assistant_warnings_toggle.toggled.connect(self._assistant_warnings_changed)
        self.assistant_replay_button.clicked.connect(self._replay_assistant_guide)
        self.bridge.engine_log.connect(self._append_log)
        self.bridge.log.connect(self._append_log); self.bridge.state.connect(self._set_state); self.bridge.traffic.connect(self._set_traffic); self.bridge.target_latency.connect(self._target_latency_finished); self.bridge.maker_imported.connect(self._maker_import_finished); self.bridge.maker_batch.connect(self._maker_test_batch); self.bridge.maker_done.connect(self._maker_test_done); self.bridge.maker_failed.connect(self._maker_failed); self.bridge.scan_progress.connect(self._scan_progress); self.bridge.scan_done.connect(self._scan_done); self.bridge.scan_failed.connect(self._scan_failed); self.bridge.error.connect(self._handle_error); self.bridge.profiles_changed.connect(self.refresh_profiles); self.bridge.profile_pings_done.connect(self._profile_pings_finished); self.bridge.ip.connect(self._ip_checked); self.bridge.hint.connect(self._set_xray_hint); self.bridge.activity.connect(self.activity_bar.set_activity); self.bridge.processes.connect(self._populate_processes); self.bridge.processes_failed.connect(self._process_refresh_failed); self.bridge.update_checked.connect(self._update_checked); self.bridge.update_failed.connect(self._update_failed); self.bridge.proxy_mode_applied.connect(self._proxy_mode_apply_finished); self.bridge.tun_mode_applied.connect(self._tun_mode_apply_finished); self.bridge.gateway_mode_applied.connect(self._gateway_mode_apply_finished); self.bridge.gateway_runtime_state.connect(self._gateway_runtime_state_changed); self.bridge.gateway_devices_changed.connect(self._gateway_devices_updated); self.bridge.gateway_device_names_changed.connect(self._gateway_device_names_updated)
        self._traffic_timer = QTimer(self)
        self._traffic_timer.setInterval(1000)
        self._traffic_timer.timeout.connect(self._poll_traffic)
        self._traffic_timer.start()   
        self.connect_button.clicked.connect(self.toggle_connection); self.add_btn.clicked.connect(self.add_profile); self.clear_user_btn.clicked.connect(self.delete_all_user_configs); self.clip_btn.clicked.connect(self.import_clipboard); self.sync_btn.clicked.connect(self.sync_profiles); self.scan_button.clicked.connect(self.toggle_scan); self.bookmark_btn.clicked.connect(self.bookmark_selected); self.apply_sni_btn.clicked.connect(self.apply_selected_sni); self.apply_all_sni_btn.clicked.connect(self.apply_sni_to_all_suggested); self.undo_apply_btn.clicked.connect(self.undo_sni_apply); self.copy_result_btn.clicked.connect(self.copy_selected_result); self.carrier.currentTextChanged.connect(self._carrier_changed); self.country_combo.activated.connect(self._country_activated); self.auto_mode.toggled.connect(self._auto_mode_changed); self.pick_best.toggled.connect(self._pick_best_changed); self.proxy_mode.toggled.connect(self._proxy_mode_changed); self.tun_mode.toggled.connect(self._tun_mode_changed); self.gateway_mode.toggled.connect(self._gateway_mode_changed)
        self.scan_stop_btn.clicked.connect(self.toggle_scan)
        self.scan_tabs.currentChanged.connect(self._filter_scan_results)
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
        self.maker_view_configs_btn.clicked.connect(self._maker_open_configs)

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
        self._tray_menu.setFont(_fonts.make_font(self.language))
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

    def eventFilter(self, watched, event):
        try:
            from PySide6.QtCore import QEvent as _QEvent
            if watched is getattr(self, "logo_card", None) and event.type() == _QEvent.Type.MouseButtonRelease:
                self._switch_engine()
                return True
            if watched is getattr(self, "engine_switch", None) and event.type() in (_QEvent.Type.Resize, _QEvent.Type.LayoutRequest, _QEvent.Type.Show):
                if not self._engine_switching:
                    QTimer.singleShot(0, self, self._place_engine_thumb)
        except Exception:
            pass
        return super().eventFilter(watched, event)

    def _pow_page(self):
        return self.pow_controller.build_page()

    def _pow_busy(self) -> bool:
        try:
            controller = getattr(self, "pow_controller", None)
            return bool(controller is not None and controller.busy)
        except Exception:
            return False

    def _sync_engine_ui(self):
        self._sync_engine_ui_theme()
        self._sync_engine_ui_layout()

    def _sync_engine_ui_theme(self):
        pow_active = getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_POW
        badge = getattr(self, "engine_badge", None)
        if badge is not None:
            try:
                badge.setText(self.tr("⚡ موتور UAC POW", "⚡ UAC POW ENGINE") if pow_active else self.tr("موتور XRAY", "XRAY ENGINE"))
            except Exception:
                pass
        logo = getattr(self, "logo_card", None)
        if logo is not None:
            try:
                logo.setToolTip("")
            except Exception:
                pass
        self._apply_engine_theme()

    def _sync_engine_ui_layout(self):
        self._layout_sidebar_chrome()
        self._sync_engine_nav()
        self._sync_engine_switch()
        self._apply_engine_home()
        self._ensure_engine_page()

    def _apply_app_style(self):
        """Fonts (Inter / Vazirmatn UI FD / JetBrains Mono) + themed stylesheet."""
        app = QApplication.instance()
        if app is None:
            return
        language = getattr(self, "language", "fa")
        _fonts.apply_app_font(app, language)
        engine = getattr(self, "engine_mode", ENGINE_XRAY)
        current = app.styleSheet()
        wanted = combined_app_style(language)
        if is_app_style(current) and current != wanted:
            # Language change / first start: one full (slow) stylesheet install.
            self.setProperty(_eswitch.ENGINE_PROPERTY, engine)
            app.setStyleSheet(wanted)
            self._stale_pages = set()
        elif self.property(_eswitch.ENGINE_PROPERTY) != engine:
            self._flip_engine_property(engine)

    def _flip_engine_property(self, engine):
        """Engine theme switch: flip the scoped property, repolish what is visible.

        Pages that are not on screen are only marked stale; they are
        repolished right before they are shown or on idle ticks later.
        """
        self.setProperty(_eswitch.ENGINE_PROPERTY, engine)
        stack = getattr(self, "stack", None)
        stale = set()
        if stack is not None:
            current = stack.currentWidget()
            for index in range(stack.count()):
                page = stack.widget(index)
                if page is not None and page is not current:
                    stale.add(page)
        skip = set()
        for page in stale:
            skip.add(page)
            skip.update(page.findChildren(QWidget))
        style = self.style()
        for widget in [self] + self.findChildren(QWidget):
            if widget not in skip:
                style.unpolish(widget)
                style.polish(widget)
        self._stale_pages = stale
        self._stale_pending = None
        self.update()
        if not self._engine_switching:
            self._schedule_stale_restyle(60)

    def _freshen_page(self, page):
        """Bring a stale page up to the current engine theme (before showing it)."""
        if page is None or page not in self._stale_pages:
            return
        self._stale_pages.discard(page)
        pending = getattr(self, "_stale_pending", None)
        if pending is not None and pending[0] is page:
            widgets = pending[1]
            self._stale_pending = None
        else:
            widgets = [page] + page.findChildren(QWidget)
        style = self.style()
        for widget in widgets:
            try:
                style.unpolish(widget)
                style.polish(widget)
            except RuntimeError:
                pass
        page.update()

    def _schedule_stale_restyle(self, delay=30):
        if not self._stale_pages:
            return
        timer = getattr(self, "_stale_timer", None)
        if timer is None:
            timer = QTimer(self); timer.setSingleShot(True); timer.timeout.connect(self._restyle_next_stale_page)
            self._stale_timer = timer
        timer.start(delay)

    STALE_RESTYLE_BATCH = 90   # widgets per idle tick (~8-10 ms)

    def _restyle_next_stale_page(self):
        """Idle-time restyle of hidden pages, in small batches."""
        if self._engine_switching or not self._stale_pages:
            return
        pending = getattr(self, "_stale_pending", None)
        if pending is None or pending[0] not in self._stale_pages:
            page = next(iter(self._stale_pages))
            pending = (page, [page] + page.findChildren(QWidget))
            self._stale_pending = pending
        page, widgets = pending
        style = self.style()
        batch, rest = widgets[:self.STALE_RESTYLE_BATCH], widgets[self.STALE_RESTYLE_BATCH:]
        for widget in batch:
            try:
                style.unpolish(widget)
                style.polish(widget)
            except RuntimeError:  # widget deleted since the batch was listed
                pass
        if rest:
            self._stale_pending = (page, rest)
        else:
            self._stale_pending = None
            self._stale_pages.discard(page)
            page.update()
        self._schedule_stale_restyle(15)

    def _apply_engine_theme(self):
        engine = getattr(self, "engine_mode", ENGINE_XRAY)
        changed = self.property(_eswitch.ENGINE_PROPERTY) != engine
        _theme.set_engine(engine)
        self._apply_app_style()
        if changed or not getattr(self, "_theme_applied", False):
            self._theme_applied = True
            self._retheme_art()
        if hasattr(self, "global_settings_page"):
            self.global_settings_page.set_engine(engine)
        if hasattr(self, "app_routing_view"):
            self.app_routing_view.set_engine(engine)
        if hasattr(self, "direct_routing_view"):
            self.direct_routing_view.set_engine(engine)
        self._sync_brand()
        status = getattr(self, "status", None)
        if status is not None:
            status.setText(_accent_state_word(status.text()))
        self.update()

    def _retheme_art(self):
        """Regenerate theme-coloured icon art that was set before a switch."""
        for label in self.findChildren(QLabel):
            art = label.pixmap()
            if art is None or art.isNull():
                continue
            meta = _THEMED_ART.get(("p", art.cacheKey()))
            if meta is not None:
                label.setPixmap(cyber_pixmap(*meta))
        for button in self.findChildren(QAbstractButton):
            meta = _THEMED_ART.get(("i", button.icon().cacheKey()))
            if meta is not None:
                button.setIcon(cyber_icon(*meta))

    def _sync_brand(self):
        brand = getattr(self, "brand_label", None)
        if brand is None:
            return
        mode = getattr(self, "engine_mode", ENGINE_XRAY)
        accent = _theme.ENGINE_BRAND_PALETTES[mode]["accent"]
        name, badge = {
            ENGINE_XRAY: ("Spoofer", "XRAY ENGINE"),
            ENGINE_POW: ("PoW", "PoW ENGINE"),
            ENGINE_DIRECT: ("Direct", "DIRECT ENGINE"),
        }[mode]
        brand.setText(f"UAC <span style='color:{accent}'>{name}</span>")
        self.engine_badge.setText(f"<span style='color:{accent}'>\u25cf</span>&nbsp;&nbsp;{badge}")
        self.logo_card.set_engine(mode)
        self.logo_mark.setPixmap(_engine_mark(mode, 28 if mode == ENGINE_POW else 26, accent))
        self.rating_button.setIcon(cyber_icon("star" if mode == ENGINE_DIRECT else "external-link", "#bfefff", 18))

    def _sync_engine_switch(self):
        buttons = getattr(self, "engine_buttons", None)
        if not buttons:
            return
        mode = getattr(self, "engine_mode", ENGINE_XRAY)
        checked = self._engine_checked_override or mode
        tips = {
            ENGINE_XRAY: self.tr("موتور Xray: کانفیگ‌های VLESS/Trojan با اسپوف SNI", "Xray engine: VLESS/Trojan configs with SNI spoofing"),
            ENGINE_POW: self.tr("موتور UAC PoW: سایفون روی WARP", "UAC PoW engine: Psiphon over WARP"),
            ENGINE_DIRECT: self.tr("وایرگارد روی HTTP/2 یا TLS مستقیم", "WireGuard over HTTP/2 or direct TLS"),
        }
        for key, button in buttons.items():
            button.blockSignals(True)
            button.setChecked(key == checked)
            button.blockSignals(False)
            active = self.tr("موتور فعال", "Active engine") if key == mode else self.tr("کلیک برای تعویض موتور", "Click to switch engine")
            button.setToolTip(f"{tips.get(key, '')}\n{active}")
        if not self._engine_switching:
            self._place_engine_thumb()

    def _engine_thumb_rect(self, engine):
        button = (getattr(self, "engine_buttons", None) or {}).get(engine)
        return QRect(button.geometry()) if button is not None else QRect()

    def _place_engine_thumb(self):
        thumb = getattr(self, "engine_thumb", None)
        if thumb is None or self._engine_switching:
            return
        engine = getattr(self, "engine_mode", ENGINE_XRAY)
        thumb.setGeometry(self._engine_thumb_rect(engine))
        thumb.set_engine(engine)
        thumb.lower()
        thumb.show()

    def _engine_option_clicked(self, key):
        if self._engine_switching or getattr(self, "_engine_guard_pending", False):
            self._sync_engine_switch()
            return
        if key != getattr(self, "engine_mode", ENGINE_XRAY):
            self._engine_switch_target = key
            self._switch_engine()
        self._sync_engine_switch()

    def _option_label(self, option):
        return option.findChild(QLabel, "controlLabel") if option is not None else None

    def _set_bilingual(self, widget, persian, english):
        if widget is None:
            return
        if widget.property("xrayFa") is None:
            widget.setProperty("xrayFa", widget.property("i18nFa"))
            widget.setProperty("xrayEn", widget.property("i18nEn"))
        widget.setProperty("i18nFa", persian)
        widget.setProperty("i18nEn", english)
        widget.setText(self._ui_text(persian, english))

    def _restore_bilingual(self, widget):
        if widget is None or widget.property("xrayFa") is None:
            return
        persian = str(widget.property("xrayFa"))
        english = str(widget.property("xrayEn") or "")
        widget.setProperty("i18nFa", persian)
        widget.setProperty("i18nEn", english)
        widget.setText(self._ui_text(persian, english))

    def _pow_setting(self, **changes):
        from dataclasses import replace
        controller = getattr(self, "pow_controller", None)
        if controller is None:
            return
        before = controller.store.snapshot()
        after = replace(before, **changes)
        controller.store.save(after, exclude=self.global_settings.pow_legacy_fields)
        try:
            self._log_pow_setting_changes(before, after)
        except Exception:
            pass

    def _apply_engine_home(self):
        """Same Connection Center layout; the slots follow the active engine."""
        if not hasattr(self, "home_header"):
            return
        mode = getattr(self, "engine_mode", ENGINE_XRAY)
        pow_on = mode == ENGINE_POW
        direct_on = mode == ENGINE_DIRECT
        subtitle = self.home_header.findChild(QLabel, "pageSubtitle")
        self.orb.set_direct_appearance(direct_on)
        self.hero_card.set_atmosphere(mode)
        self.orb_caption.setText("DIRECT CORE" if direct_on else "NETWORK CORE")
        self.pow_country_button.refresh_chevron(direct_on)
        self.network_metrics.set_engine(mode)
        self._refresh_app_routing_notice()
        self.gateway_option.setVisible(not direct_on)
        self.carrier_control.setVisible(not direct_on)
        self.manual_option.setVisible(mode == ENGINE_XRAY)
        if direct_on:
            self._set_bilingual(subtitle, "مدیریت هوشمند ارتباطات شبکه", "Intelligent network management")
            self._set_bilingual(self.hero_badge, "موتور ارتباط مستقیم", "Direct connection engine")
            self._set_bilingual(self._option_label(self.auto_option), "DNS خودکار", "Automatic DNS")
            self._set_bilingual(self.tune_button, "تنظیمات Direct", "Direct Settings")
            self.route_source_tabs.hide()
            self.country_count.hide()
            self.country_combo.hide()
            self.original_configs_label.hide()
            self.pow_country_button.show()
            self._relayout_control_bar()
            self.direct_controller.refresh()
            return
        self._restore_bilingual(self.hero_badge)
        self.country_description.setToolTip("")
        if pow_on:
            self.pow_country_button.setEnabled(True)
            self.pow_country_button.setAccessibleName("PoW exit country")
            self._set_bilingual(subtitle, "سایفون روی وارپ، با پروکسی ویندوز یا حالت TUN", "Psiphon over WARP, with Windows proxy or TUN mode")
            self._set_bilingual(self.country_description, "کشور خروجی سایفون. خودکار یعنی بدون قفل منطقه.", "Psiphon exit country. Automatic means no region pin.")
            self._set_bilingual(self._option_label(self.auto_option), "سایفون روی وارپ", "Psiphon over WARP")
            self._set_bilingual(self._option_label(self.manual_option), "حالت بهینه", "Optimized")
            self._set_bilingual(self._option_label(self.gateway_option), "فرگمنت HTTP/2", "HTTP/2 fragmentation")
            self._set_bilingual(self.carrier_label, "فایروال", "Firewall")
            self._set_bilingual(self.tune_button, "تنظیمات PoW", "PoW Settings")
            self.route_source_tabs.setTabText(0, self.tr("خودکار", "Automatic"))
            self.route_source_tabs.setTabText(1, self.tr("کشور", "Country"))
            self.gateway_devices_badge.setVisible(False)
            self.connect_button.setVisible(True)
            # One exit control on PoW: the selector button (no tabs/count).
            self.route_source_tabs.setVisible(False)
            self.country_count.setVisible(False)
            # Optimized lives in PoW Settings; Home keeps the everyday switches.
            self.manual_option.setVisible(False)
            self._relayout_control_bar()
            self._load_pow_home_controls()
            self._refresh_proxy_port_panels_for_engine()
        else:
            self._restore_bilingual(subtitle)
            self._restore_bilingual(self.country_description)
            self._restore_bilingual(self._option_label(self.auto_option))
            self._restore_bilingual(self._option_label(self.manual_option))
            self._set_bilingual(self._option_label(self.gateway_option), "درگاه موبایل", "Gateway")
            self._restore_bilingual(self.carrier_label)
            self._restore_bilingual(self.tune_button)
            self.route_source_tabs.setTabText(0, self.tr("پیشنهادی", "Suggested"))
            self.route_source_tabs.setTabText(1, "User Config")
            self.gateway_devices_badge.setVisible(True)
            self.connect_button.setVisible(True)
            self.route_source_tabs.setVisible(True)
            self.country_count.setVisible(True)
            self.pow_country_button.setVisible(False)
            self.manual_option.setVisible(True)
            self._relayout_control_bar()
            self.original_configs_label.setText("UAC Spoof Original Configs")
            self._restore_xray_home_controls()
            self._refresh_proxy_port_panels_for_engine()

    def _load_pow_home_controls(self):
        controller = getattr(self, "pow_controller", None)
        if controller is None:
            return
        settings = controller.store.snapshot()
        self._pow_home_loading = True
        widgets = (
            self.auto_mode, self.pick_best, self.proxy_mode, self.tun_mode,
            self.gateway_mode, self.carrier, self.route_source_tabs, self.country_combo,
        )
        for widget in widgets:
            widget.blockSignals(True)
        try:
            self.auto_mode.setChecked(settings.exit_mode == "chain")
            self.pick_best.setChecked(bool(settings.optimized_mode))
            self.gateway_mode.setChecked(bool(controller.h2_fragment_display()[0]))
            firewall = settings.firewall_profile if settings.firewall_profile in ("auto", "mci", "irancell") else "auto"
            self.carrier.setCurrentText(firewall)
            automatic = not (settings.exit_country_code or "").strip()
            self.route_source_tabs.setCurrentIndex(0 if automatic else 1)
            self._fill_pow_country_combo(settings.exit_country_code, automatic)
        finally:
            for widget in widgets:
                widget.blockSignals(False)
            self._pow_home_loading = False
        self._pow_h2_label_state = None
        self._pow_sync_home_visuals()

    @staticmethod
    def _pow_set_toggle(toggle, value):
        """Set a switch without firing its handler, and move the thumb too
        (the thumb animation hangs off the blocked toggled signal)."""
        value = bool(value)
        if toggle.isChecked() != value:
            toggle.blockSignals(True)
            toggle.setChecked(value)
            toggle.blockSignals(False)
        if hasattr(toggle, "_set_thumb_position") and getattr(toggle, "_thumb_position", None) != (1.0 if value else 0.0):
            toggle._set_thumb_position(1.0 if value else 0.0)

    def _pow_sync_home_visuals(self):
        """Show the selected output and effective HTTP/2 fragmentation."""
        controller = getattr(self, "pow_controller", None)
        if controller is None or getattr(self, "engine_mode", ENGINE_XRAY) != ENGINE_POW:
            return
        if not hasattr(self, "proxy_mode") or getattr(self, "_pow_home_loading", False):
            return
        self._sync_tun_proxy_controls(controller.effective_exit_proxy() is False,
                                      controller.system_proxy_enabled)
        checked, auto_on = controller.h2_fragment_display()
        self._pow_set_toggle(self.gateway_mode, checked)
        if not self.gateway_mode.isEnabled():
            self.gateway_mode.setEnabled(True)
        state = bool(auto_on)
        if getattr(self, "_pow_h2_label_state", None) != state:
            self._pow_h2_label_state = state
            fa, en = _POW_H2_FA, "HTTP/2 fragmentation"
            if state:
                fa, en = f"{fa} \u00b7 {_POW_AUTO_FA}", f"{en} \u00b7 auto"
            self._set_bilingual(self._option_label(self.gateway_option), fa, en)
            self.gateway_mode.setToolTip(self.tr(
                "\u0631\u0648\u0634\u0646: \u0647\u0645\u06cc\u0634\u0647 \u0631\u0648\u0634\u0646. \u062e\u0627\u0645\u0648\u0634: \u062e\u0648\u062f\u06a9\u0627\u0631 (\u0627\u06af\u0631 DPI \u062f\u06cc\u062f\u0647 \u0634\u0648\u062f \u0631\u0648\u0634\u0646 \u0645\u06cc\u200c\u0634\u0648\u062f).",
                "On: always fragment. Off: automatic (turns on by itself when DPI is suspected).",
            ))

    def _sync_tun_proxy_controls(self, tun_on, proxy_on):
        self.tun_option.setEnabled(True)
        self.tun_mode.setEnabled(True)
        self.proxy_option.setEnabled(not tun_on and self.global_settings.snapshot().connection_mode != "vpn")
        for option, toggle, active in ((self.proxy_option, self.proxy_mode, proxy_on and not tun_on),
                                      (self.tun_option, self.tun_mode, tun_on)):
            self._pow_set_toggle(toggle, active)
            if option.property("active") != active:
                option.setProperty("active", active)
                _restyle(option)

    def _fill_pow_country_combo(self, selected: str, automatic: bool):
        """PoW keeps a single exit control: the selector button."""
        self.country_combo.setVisible(False)
        self.original_configs_label.setVisible(False)
        self.route_source_tabs.setVisible(False)
        self.country_count.setVisible(False)
        self.pow_country_button.setVisible(True)
        self._update_pow_country_selector(selected)

    def _update_pow_country_selector(self, selected=None):
        from .pow.config import NEARBY_PHASE_TIMEOUT_SECONDS, REGION_PHASE_TIMEOUT_SECONDS
        from .pow.regions import ALL_NAMES
        controller = getattr(self, "pow_controller", None)
        button = getattr(self, "pow_country_button", None)
        if controller is None or button is None:
            return
        if selected is None:
            selected = controller.store.snapshot().exit_country_code
        code = (selected or "").strip().upper()
        try:
            remembered = controller.store.last_learned_region()
        except Exception:
            remembered = None
        if code:
            name = ALL_NAMES.get(code, code)
            button.set_value(
                country_flag_badge(code, 38), name,
                self.tr(f"کشور خروجی · {code}", f"Exit country · {code}"),
            )
            self._set_bilingual(
                self.country_description,
                f"خروج سایفون از {name}. اگر در {REGION_PHASE_TIMEOUT_SECONDS} ثانیه وصل نشود، هر کشوری استفاده می‌شود.",
                f"Psiphon exits in {name}. If it cannot connect in {REGION_PHASE_TIMEOUT_SECONDS}s, any country is used.",
            )
        else:
            if remembered:
                subtitle = self.tr(f"اول نزدیک‌ترین ({remembered})، بعد هر کشوری", f"Nearest {remembered} first, then any")
            else:
                subtitle = self.tr("اول کشور نزدیک، بعد هر کشوری", "Nearby country first, then any")
            button.set_value(bolt_badge(38), self.tr("خودکار", "Automatic"), subtitle)
            fa = f"خودکار اول یک کشور نزدیک را {NEARBY_PHASE_TIMEOUT_SECONDS} ثانیه امتحان می‌کند، بعد هر کشوری."
            en = f"Automatic tries a nearby country first ({NEARBY_PHASE_TIMEOUT_SECONDS}s), then any country."
            if remembered:
                rname = ALL_NAMES.get(remembered, remembered)
                fa += f" آخرین خروجی نزدیک: {rname} ({remembered})."
                en += f" Last nearby exit: {rname} ({remembered})."
            self._set_bilingual(self.country_description, fa, en)
        button.setToolTip(self.tr("انتخاب کشور خروجی", "Choose the exit country"))

    def _open_pow_country_picker(self):
        if getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_DIRECT:
            self.direct_controller.open_country_picker()
            return
        from .pow_ui import PowCountryPicker
        controller = getattr(self, "pow_controller", None)
        if controller is None:
            return
        try:
            remembered = controller.store.last_learned_region()
        except Exception:
            remembered = None
        current = controller.store.snapshot().exit_country_code
        dialog = PowCountryPicker(self, current, remembered)
        if dialog.exec() and dialog.selected_code is not None:
            code = dialog.selected_code
            self._pow_setting(exit_country_code=code)
            self._update_pow_country_selector()
            if code:
                self.bridge.log.emit(f"PoW exit country set to {code.upper()}")
            else:
                self.bridge.log.emit("PoW exit country set to Automatic (nearby first)")

    def _restore_xray_home_controls(self):
        self._pow_home_loading = True
        widgets = (
            self.auto_mode, self.pick_best, self.proxy_mode, self.tun_mode,
            self.gateway_mode, self.carrier, self.route_source_tabs,
        )
        for widget in widgets:
            widget.blockSignals(True)
        try:
            self.auto_mode.setChecked(bool(self.storage.settings.get("auto_mode", True)))
            self.pick_best.setChecked(bool(self.storage.settings.get("pick_best", False)))
            self.proxy_mode.setChecked(bool(self._proxy_mode_enabled()))
            self.tun_mode.setChecked(bool(self._tun_mode_enabled()))
            self.gateway_mode.setChecked(False)
            self.carrier.setCurrentText(self.storage.tuning.carrier_mode)
            route_source = str(self.storage.settings.get("route_source", "suggested") or "suggested").lower()
            self.route_source_tabs.setCurrentIndex(1 if route_source == "user-config" else 0)
        finally:
            for widget in widgets:
                widget.blockSignals(False)
            self._pow_home_loading = False
        # Undo what the PoW Home changed on the shared switches (thumbs, active
        # look, enabled rows) so Xray shows its own saved state again.
        try:
            for toggle in (self.auto_mode, self.pick_best, self.proxy_mode, self.tun_mode, self.gateway_mode):
                self._pow_set_toggle(toggle, toggle.isChecked())
            self.proxy_option.setProperty("active", self.proxy_mode.isChecked())
            self.tun_option.setProperty("active", self.tun_mode.isChecked())
            self.proxy_option.setEnabled(not self._tun_mode_enabled())
            _restyle(self.proxy_option)
            _restyle(self.tun_option)
            self._sync_gateway_controls()
        except Exception:
            pass
        self._pow_h2_label_state = None
        try:
            self._refresh_country_selector()
            self.refresh_profiles()
        except Exception:
            pass

    @staticmethod
    def _nav_icon(name):
        if name == "direct-dns":
            return "database"
        return "settings" if name in ("xray-settings", "pow-settings", "direct-settings") else name

    def _nav_visible(self, icon: str) -> bool:
        engine = getattr(self, "engine_mode", ENGINE_XRAY)
        if icon in ("home", "activity", "headphones", "shield", "settings"):
            return True
        if icon == "zap":
            return False
        if icon == "pow-settings":
            return engine == ENGINE_POW
        if icon in ("direct-settings", "direct-dns"):
            return engine == ENGINE_DIRECT
        return engine == ENGINE_XRAY

    def _sync_engine_nav(self):
        for button in self.nav:
            icon = button.property("iconName")
            button.setVisible(self._nav_visible(icon))
        self.sidebar_compact_spacer.setVisible(self.engine_mode == ENGINE_POW)
        self._sync_nav_selection(self.stack.currentIndex())
        try:
            self._fit_sidebar()
        except Exception:
            pass

    def _sync_nav_selection(self, page_index):
        if page_index == self.DIRECT_ROUTING_PAGE:
            page_index = self.GLOBAL_SETTINGS_PAGE
        for index, button in enumerate(self.nav):
            active = index == page_index and not button.isHidden()
            button.setChecked(active)
            icon = self._nav_icon(button.property("iconName"))
            button.setIcon(cyber_icon(icon, "#23f5e0" if active else "#9fb4d8", _layout.NAV_ICON))

    def _pow_stack_index(self) -> int:
        for index, button in enumerate(self.nav):
            if button.property("iconName") == "zap":
                return index
        return 0

    def _ensure_engine_page(self):
        if not getattr(self, "nav", None) or not hasattr(self, "stack"):
            return
        index = self.stack.currentIndex()
        icon = self.nav[index].property("iconName") if 0 <= index < len(self.nav) else ""
        widget = self.stack.currentWidget()
        name = widget.objectName() if widget is not None else ""
        pow_active = getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_POW
        if pow_active and name == "powPage":
            self.show_page(0)
        elif (not pow_active) and icon == "zap":
            self.show_page(0)
        elif icon and not self._nav_visible(icon) and icon != "zap":
            self.show_page(0)

    def _switch_engine(self):
        """Switch the selected engine and animate the transition when enabled.

        Disconnect rules are unchanged (see _switch_engine_now); this wrapper
        only adds the snapshot cross-fade, the sliding pill and the
        re-entrancy guard (the switch ignores clicks while animating).
        """
        if self._engine_switching:
            return
        QToolTip.hideText()
        if self._protected_session():
            self._reject_guarded_change()
            self._engine_switch_target = None
            self._restore_engine_switch_look()
            return
        if self._engine_busy():
            # Ask after the click handler returns (a modal loop inside the
            # click left the switch buttons stuck in a pressed/dark state).
            if not getattr(self, "_engine_guard_pending", False):
                self._engine_guard_pending = True
                QTimer.singleShot(0, self._guarded_switch)
            return
        started = time.perf_counter()
        previous = getattr(self, "engine_mode", ENGINE_XRAY)
        animate = (self._navigation_animations_enabled() and self.isVisible()
                   and getattr(self, "engine_thumb", None) is not None)
        self._engine_switch_stats = {"started": started, "animated": animate}
        if not animate:
            self._switch_engine_now()
            self._engine_switch_stats["blocking_ms"] = (time.perf_counter() - started) * 1000.0
            self._engine_switch_finished()
            return
        self._engine_switching = True
        self._engine_checked_override = previous
        overlay = None
        try:
            snapshot = self.grab()
            content = getattr(self, "stack", None)
            content_rect = QRect(content.mapTo(self, QPoint(0, 0)), content.size()) if content is not None else QRect()
            hole = QRect(self.engine_switch.mapTo(self, QPoint(0, 0)), self.engine_switch.size())
            overlay = _eswitch.SwitchOverlay(self, snapshot, content_rect, hole)
            overlay.show(); overlay.raise_()
        except Exception:
            overlay = None
        central = self.centralWidget()
        frozen = central is not None and overlay is not None
        if frozen:
            central.setUpdatesEnabled(False)   # the overlay shows the old frame meanwhile
        stats = self._engine_switch_stats
        state = {"done": False}

        def finish_ui(rest):
            def run():
                part = time.perf_counter()
                try:
                    self._suppress_page_motion = True
                    rest()
                except Exception:
                    pass
                finally:
                    self._suppress_page_motion = False
                    if frozen:
                        central.setUpdatesEnabled(True)
                    stats["second_ms"] = (time.perf_counter() - part) * 1000.0
                    state["done"] = True
                    try:
                        self._animate_engine_switch(previous, overlay)
                    except Exception:
                        if overlay is not None:
                            overlay.hide(); overlay.deleteLater()
                        self._engine_switch_finished()
            QTimer.singleShot(0, run)

        try:
            self._switch_engine_now(defer=finish_ui)
        except Exception:
            if not state["done"]:
                if frozen:
                    central.setUpdatesEnabled(True)
                if overlay is not None:
                    overlay.hide(); overlay.deleteLater()
                self._engine_switch_finished()
            raise
        finally:
            stats["first_ms"] = (time.perf_counter() - started) * 1000.0

    def _animate_engine_switch(self, previous, overlay):
        stats = self._engine_switch_stats
        stats["blocking_ms"] = max(stats.get("first_ms", 0.0), stats.get("second_ms", 0.0))
        target = getattr(self, "engine_mode", ENGINE_XRAY)
        thumb = self.engine_thumb
        thumb.setGeometry(self._engine_thumb_rect(previous)); thumb.lower(); thumb.show()
        thumb.blend_to(target)
        group = QParallelAnimationGroup(self)
        slide = _eswitch.make_animation(thumb, b"geometry", self._engine_thumb_rect(previous), self._engine_thumb_rect(target), parent=group)
        tint = _eswitch.make_animation(thumb, b"mix", 0.0, 1.0, _eswitch.FADE_MS, parent=group)
        group.addAnimation(slide); group.addAnimation(tint)
        if overlay is not None:
            fade = _eswitch.make_animation(overlay, b"progress", 0.0, 1.0, _eswitch.FADE_MS, parent=group)
            group.addAnimation(fade)

        def flip_label(value):
            if self._engine_checked_override is not None and float(value) >= 0.45:
                self._engine_checked_override = None
                self._sync_engine_switch()

        tint.valueChanged.connect(flip_label)

        def done():
            if overlay is not None:
                overlay.hide(); overlay.deleteLater()
            self._engine_switch_finished()

        group.finished.connect(done)
        self._engine_switch_anim = group
        group.start()

    def _prewarm_art_step(self):
        """Render the other engine's icon art in small idle slices."""
        if self._engine_switching:
            QTimer.singleShot(300, self._prewarm_art_step)
            return
        try:
            if prewarm_themed_art(limit=24):
                QTimer.singleShot(40, self._prewarm_art_step)
        except Exception:
            pass

    def _engine_switch_finished(self):
        self._engine_switching = False
        self._engine_checked_override = None
        self._engine_switch_anim = None
        stats = self._engine_switch_stats
        if stats.get("started"):
            stats["total_ms"] = (time.perf_counter() - stats["started"]) * 1000.0
        self._sync_engine_switch()
        self._schedule_stale_restyle(60)

    def _switch_engine_now(self, defer=None):
        target = getattr(self, "_engine_switch_target", None)
        if target is None:
            target = ENGINE_XRAY if getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_POW else ENGINE_POW
        self._engine_switch_target = None
        if self._engine_busy():
            self.show_toast(self.tr("اتصال هنوز فعال است؛ تعویض انجام نشد.",
                                    "The connection is still active. The engine was not switched."), "warning")
            if defer is not None:
                defer(self._sync_engine_switch)
            return
        current_page = self.stack.currentWidget() if hasattr(self, "stack") else None
        following_log = (current_page is not None and current_page.objectName() == "liveLogsPage"
                         and self._log_follow and self.log_autoscroll.isChecked())
        self._engine_page_scroll = (current_page, tuple(
            (bar, bar.value()) for bar in current_page.findChildren(QScrollBar)
            if bar.orientation() == Qt.Vertical
            and not (following_log and bar is self.logs.verticalScrollBar())
        )) if current_page is not None else (None, ())
        self.engine_mode = target
        try:
            self.storage.settings["engine_mode"] = target
            self.storage.save_settings()
        except Exception:
            pass
        try:
            self.bridge.log.emit(f"Engine switched to {target}")
        except Exception:
            pass
        self._sync_engine_ui_theme()
        if defer is not None:
            # Animated switch: the rest runs on the next event-loop turn (under
            # the snapshot overlay) so no single frame blocks for long.
            defer(self._finish_engine_switch_ui)
        else:
            self._finish_engine_switch_ui()

    def _engine_busy(self):
        controller = getattr(self, "pow_controller", None)
        try:
            busy_pow = bool(controller is not None and controller.busy)
        except Exception:
            busy_pow = False
        engine = getattr(self, "engine", None)
        direct = getattr(self, "direct_controller", None)
        worker = getattr(self, "_connect_thread", None)
        return bool(busy_pow or (direct is not None and direct.busy) or getattr(engine, "running", False)
                    or getattr(self, "connecting", False) or (worker is not None and worker.is_alive()))

    def _confirm_engine_switch(self):
        """True = disconnect and switch. Tests may inject _switch_guard_fn."""
        guard = getattr(self, "_switch_guard_fn", None)
        if callable(guard):
            return bool(guard())
        from .engine_switch_guard import SharedEngineSwitchDialog
        target = getattr(self, "_engine_switch_target", None)
        if target is None:
            return False
        state = self.connect_button.property("directState") or self.network_metrics.connection_state
        dialog = SharedEngineSwitchDialog(self, self.language, self.engine_mode, target, state)
        self._engine_switch_dialog = dialog
        try:
            return dialog.exec() == QDialog.Accepted
        finally:
            self._engine_switch_dialog = None
            dialog.deleteLater()

    def _guarded_switch(self):
        if self._protected_session():
            self._reject_guarded_change()
            self._engine_guard_pending = False
            self._engine_switch_target = None
            self._restore_engine_switch_look()
            return
        ok = self._confirm_engine_switch()
        self._restore_engine_switch_look()
        if ok and not self._protected_session():
            self._disconnect_then_switch()
        else:
            if ok:
                self._reject_guarded_change()
            self._engine_guard_pending = False
            self._engine_switch_target = None

    def _restore_engine_switch_look(self):
        self._engine_checked_override = None
        for button in (getattr(self, "engine_buttons", None) or {}).values():
            try:
                button.setDown(False); button.setEnabled(True)
                button.style().unpolish(button); button.style().polish(button); button.update()
            except Exception:
                pass
        switch = getattr(self, "engine_switch", None)
        if switch is not None:
            switch.setEnabled(True)
            switch.style().unpolish(switch); switch.style().polish(switch); switch.update()
        self._sync_engine_switch()

    def _disconnect_then_switch(self, timeout=25.0):
        """Fully stop the active engine (await it), then switch."""
        self.bridge.log.emit("ENGINE SWITCH: disconnecting before switch")
        self._set_connection_visual("disconnecting")
        direct = getattr(self, "direct_controller", None)
        controller = getattr(self, "pow_controller", None)
        stopping_direct = direct is not None and direct.busy
        stopping_pow = controller is not None and controller.busy

        def fail(reason):
            self.bridge.log.emit(f"ENGINE SWITCH: {reason}; switch cancelled")
            self._engine_guard_pending = False
            self._engine_switch_target = None
            self._restore_engine_switch_look()
            if self.network_metrics.connection_state == "disconnecting":
                self._set_connection_visual("error")
            self.show_toast(self.tr("قطع اتصال کامل نشد؛ موتور تغییر نکرد.",
                                    "Could not disconnect fully. The engine was not switched."), "warning")

        try:
            if stopping_direct and direct.stop() is False:
                return fail("Direct could not stop")
            if stopping_pow and controller.disconnect() is False:
                return fail("PoW could not stop")
            if self.engine.running or self.connecting:
                self._cancel_connect_attempt(notify=False)
                self.connecting = False
        except Exception as exc:
            return fail(f"disconnect failed: {exc}")
        deadline = time.monotonic() + float(timeout)

        def poll():
            if self._engine_busy():
                if time.monotonic() >= deadline:
                    fail("engine did not stop in time")
                else:
                    QTimer.singleShot(200, poll)
                return
            if ((stopping_direct and direct.coordinator.status.disconnect_failed)
                    or (stopping_pow and controller.disconnect_failed)):
                fail("connection cleanup failed")
                return
            self.bridge.log.emit("ENGINE SWITCH: previous engine fully stopped; switching")
            self._engine_guard_pending = False
            self._switch_engine()
        poll()

    def _reset_connection_ui(self):
        """Both engines start disconnected after a switch (no fake 'connected')."""
        if self._engine_busy():
            return
        self.connection_error = ""; self._ui_running = False; self.connecting = False
        controller = getattr(self, "pow_controller", None)
        if controller is not None:
            try:
                controller._activity_kind = ""
            except Exception:
                pass
        self._set_connection_visual("disconnected")
        self._set_activity("", "", "idle", False)

    def _coach(self):
        queue = getattr(self, "_coach_queue", None)
        if queue is None:
            from .coach_mark import CoachQueue
            queue = CoachQueue(self, self.storage.settings, self.storage.save_settings, lambda: self.language,
                               is_blocked=lambda: (getattr(self, "_wizard", None) is not None
                                                   or QApplication.activeModalWidget() is not None))
            self._coach_queue = queue
        return queue

    def _queue_engine_coach(self):
        self._coach().enqueue(
            "engine_switch", lambda: getattr(self, "engine_switch", None),
            "از اینجا می‌توانید بین موتورهای Xray، UAC PoW و UAC Direct جابه‌جا شوید.",
            "Switch between Xray, UAC PoW and UAC Direct here.",
            "فهمیدم", "Got it")

    def _queue_restart_coach(self):
        self._coach().enqueue(
            "restart_guide", lambda: getattr(self, "wizard_restart_btn", None),
            "💡 هر وقت خواستی دوباره راهنما رو ببینی یا کانفیگ تازه بگیری، از همین دکمه شروع کن.",
            "💡 Whenever you want the guide again or fresh configs, start from this button.",
            "باشه", "OK")

    def _reset_engine_cards(self):
        self._traffic_totals.reset()
        self._target_latency_generation += 1
        self._target_latency_busy = False
        """Never show the other engine's route/ping/IP/traffic after a switch."""
        dialog = getattr(self, "_ip_dialog", None)
        if dialog is not None:
            try:
                dialog.close()
            except RuntimeError:
                pass
            self._ip_dialog = None
        try:
            self.network_metrics.set_connection_state("disconnected")
            self.network_metrics.set_latency(None)
            self.network_metrics.reset_traffic()
            self.upload_card.set_secondary(""); self.download_card.set_secondary("")
            self.ip_label.setText("—"); self.ip_flag.setVisible(False); self.ip_card.set_secondary("")
            self.ip_button.setEnabled(True)
            self.ip_parallel.setVisible(False)
            if getattr(self, "engine_mode", ENGINE_XRAY) != ENGINE_XRAY:
                self.active_profile.setText("—"); self.active_profile.setToolTip("")
                self.route_card.set_secondary(self.tr("هنوز وصل نشدی؛ دکمه اتصال رو بزن", "Not connected yet; tap Connect"))
            else:
                self._update_route_card(self.storage.selected())
        except Exception as exc:
            try:
                self._append_log(f"ENGINE SWITCH: card reset skipped ({exc})")
            except Exception:
                pass

    def _finish_engine_switch_ui(self):
        page, scroll = getattr(self, "_engine_page_scroll", (None, ()))
        self._engine_page_scroll = (None, ())
        self._sync_engine_ui_layout()
        self._reset_engine_cards()
        self._reset_connection_ui()
        if self.engine_mode == ENGINE_DIRECT:
            self.direct_controller.refresh()
        self._sync_wizard_restart_button()
        if (getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_XRAY
                and QApplication.platformName() != "offscreen"):
            QTimer.singleShot(500, self._maybe_open_wizard)
        try:
            self._layout_home_dashboard()
        except Exception:
            pass
        if self.stack.currentWidget() is page:
            if page is not None and page.objectName() == "liveLogsPage":
                self._render_logs()
                self._update_log_summary()
            if scroll:
                def restore_scroll():
                    if self.stack.currentWidget() is page:
                        for bar, value in scroll:
                            bar.setValue(value)

                restore_scroll()
                QTimer.singleShot(0, restore_scroll)

    def show_page(self, index):
        requested = self.nav[index].property("iconName") if 0 <= index < len(self.nav) else "home"
        if index == self.DIRECT_ROUTING_PAGE:
            requested = "settings"
        if requested in ("home", "zap") or not self._nav_visible(requested):
            index = 0
        previous_index = self.stack.currentIndex()
        if index == self.XRAY_SETTINGS_PAGE and previous_index != index:
            self._open_xray_settings_form(previous_index)
        if self._page_animation is not None:
            self._page_animation.stop()
        if self._animated_page is not None:
            self._animated_page.setGraphicsEffect(None)
            self._animated_page = None
        self._freshen_page(self.stack.widget(index))
        self.stack.setCurrentIndex(index)
        if requested == "activity":
            self._render_logs()
            self._update_log_summary()
        if index == self.GLOBAL_SETTINGS_PAGE:
            self.global_settings_page.refresh()
        elif index == self.POW_SETTINGS_PAGE:
            self.pow_controller.refresh_settings_page()
        elif index == self.DIRECT_SETTINGS_PAGE:
            self.direct_controller.refresh()
        elif index == self.DIRECT_DNS_PAGE:
            self.dns_lab_page.refresh()
        elif index == self.DIRECT_ROUTING_PAGE and previous_index != index:
            self.direct_routing_view.open()
        self._sync_nav_selection(index)
        if self._navigation_animations_enabled() and not self._suppress_page_motion:
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
        if self.assistant_controller is not None:
            self.assistant_controller.on_navigation(index)

    def _update_config_actions(self, *_):
        if not hasattr(self, "config_selection_count"):
            return
        widget = self._current_profile_list()
        if widget is None:
            return
        self._sync_profile_select_all(widget)
        self._position_profile_select_all()
        count = len(self.selected_profile_items())
        self.config_selection_count.setText(self._ui_text(f"{count} مورد انتخاب شده", f"{count} selected"))
        self.config_delete_selected.setVisible(count > 0)
        self.config_collection_label.setText(self.config_segments.tabText(self.config_segments.currentIndex()))
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
            self._append_log(f"Connection failed: {message}", engine=self.engine_mode)
            self._set_connection_visual("error")
        self.sync_btn.setEnabled(True)
        self.ip_button.setEnabled(True)
        self.activity_bar.set_activity(str(message), "error", False)
        self.show_toast(str(message), "danger")

    def _ip_checked(self, value):
        if getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_DIRECT:
            return
        self.ip_button.setEnabled(True)
        if not str(value).startswith("{"):
            self.ip_label.setText(value)
            self._set_activity("آی‌پی عمومی دریافت شد.", "Public IP check completed.", "success", False)
            return
        import json as _json
        from .ip_info import card_subtitle, country_name
        info = _json.loads(value)
        if info.get("gen") != getattr(self, "_ip_gen", 0) or info.get("mode") != self._ip_mode():
            return  # stale (engine/connection changed meanwhile)
        controller = getattr(self, "pow_controller", None)
        if controller is not None and getattr(controller, "_ip_owned", False):
            return
        self._ip_info = info
        if not info.get("ip"):
            self.ip_label.setText("—"); self.ip_flag.setVisible(False); self.ip_card.set_secondary("")
            self._ip_failures = getattr(self, "_ip_failures", 0) + 1
            if self._ip_failures <= 1:  # one retry only
                self._schedule_ip_refresh(4000 * self._ip_failures)  # transient network hiccup
            return
        self._ip_failures = 0
        fa = self.language != "en"
        self.ip_parallel.setVisible(False)
        self.ip_label.setText(info["ip"])
        code = str(info.get("country") or "").upper()
        if len(code) == 2:
            self.ip_flag.setPixmap(country_flag_icon(code, 22, 16).pixmap(22, 16))
            self.ip_flag.setToolTip(f"{country_name(code, fa)} ({code})"); self.ip_flag.setVisible(True)
        else:
            self.ip_flag.setVisible(False)
        kind = ("\u200fتونل \u2068Xray\u2069" if fa else "Xray tunnel")
        self.ip_card.set_secondary(card_subtitle(info, fa, kind))
        if info.get("force"):
            self._set_activity("آی‌پی عمومی دریافت شد.", "Public IP check completed.", "success", False)

    def _ip_mode(self):
        controller = getattr(self, "pow_controller", None)
        if getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_POW:
            try:
                if controller is not None and controller.coordinator.running:
                    return "pow"
            except Exception:
                pass
            return "direct"
        if getattr(self.engine, "running", False) and not self.connecting:
            return "xray"
        return "direct"

    def _schedule_ip_refresh(self, delay=1200):
        timer = getattr(self, "_ip_timer", None)
        if timer is None:
            timer = self._ip_timer = QTimer(self); timer.setSingleShot(True)
            timer.timeout.connect(self._refresh_ip_card)
        timer.start(int(delay))

    def _refresh_ip_card(self, force=False):
        """Direct IP when disconnected, Xray exit IP when connected (PoW owns its own)."""
        if getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_DIRECT:
            return
        mode = self._ip_mode()
        controller = getattr(self, "pow_controller", None)
        if mode == "pow":
            if force and controller is not None:
                controller.check_exit_ip()
            return
        if self.connecting or (controller is not None and getattr(controller, "busy", False)):
            return  # mid connect/disconnect: the state change reschedules us
        self._ip_gen = gen = getattr(self, "_ip_gen", 0) + 1
        port = getattr(self.engine, "probe_http_port", getattr(self.engine, "http_port", None)) if mode == "xray" else None
        engine_exit = MainWindow._engine_exit_info(self) if mode == "xray" else None
        if force:
            self.ip_button.setEnabled(False)
        bridge = self.bridge

        def work():
            import json as _json
            from .ip_info import cache_get, cache_put, direct_identity, fetch_fast
            try:
                info = None
                if mode == "xray":
                    known = engine_exit
                    if known:
                        info = cache_get(("ip", known["ip"])) or dict(known)
                    if not info:
                        info = fetch_fast(port)
                        cache_put(("ip", info.get("ip", "")), info)
                else:
                    info = cache_get(("direct",))
                    if not info:
                        info = direct_identity()
                        if info.get("ip"):
                            cache_put(("direct",), info)
                if not info.get("ip"):
                    raise RuntimeError(info.get("error") or "no IP")
                info.update(mode=mode, gen=gen, force=bool(force))
                bridge.log.emit(f"Public IP ({'Xray tunnel' if mode == 'xray' else 'direct'}): {info['ip']} {info.get('country', '')} via {info.get('source', '')}".strip())
            except Exception as exc:
                bridge.log.emit(f"Public IP check failed ({mode}): {exc}")
                info = {"gen": gen, "mode": mode, "ip": ""}
            bridge.ip.emit(_json.dumps(info))
        threading.Thread(target=work, name="ip-card", daemon=True).start()

    def _engine_exit_info(self, max_age=600):
        """Exit IP/country the engine already verified at connect (no new request)."""
        try:
            fresh = [p for p in self.storage.profiles
                     if getattr(p, "observed_exit_ip", "") and time.time() - float(getattr(p, "country_verified_at", 0) or 0) < max_age]
        except Exception:
            return None
        if not fresh:
            return None
        p = max(fresh, key=lambda x: float(x.country_verified_at or 0))
        return {"ip": p.observed_exit_ip, "country": str(p.observed_country_code or p.country_code or "").upper(),
                "source": "engine", "mode": "xray"}

    def _open_ip_details(self):
        from .ip_info import SharedIpDetailsDialog, direct_identity, fetch_details
        fa = self.language != "en"
        mode = self._ip_mode()
        engine = getattr(self, "engine_mode", ENGINE_XRAY)
        if engine == ENGINE_DIRECT:
            from .direct.probe import trace
            coordinator = self.direct_controller.coordinator
            status = coordinator.status
            if status.phase not in ("connected", "paused") or not status.exit_ip:
                return
            def loader():
                route = coordinator.status
                if route.phase not in ("connected", "paused") or not route.socks_port:
                    raise RuntimeError("The Direct route is disconnected")
                result = trace(route.probe_port or route.socks_port)
                return {"ip": result.get("ip"), "country": result.get("loc"), "source": "UAC Direct"}
            label = "UAC Direct"
        elif mode == "xray":
            port = getattr(self.engine, "probe_http_port", getattr(self.engine, "http_port", None))
            from .ip_info import cache_get as _cg, cache_put as _cp
            def loader(port=port):
                ip = str((getattr(self, "_ip_info", None) or {}).get("ip") or "")
                hit = _cg(("details", ip)) if ip else None
                if hit:
                    return hit
                data = fetch_details(port)
                _cp(("details", data.get("ip", "")), data)
                return data
            label = "\u200fتونل \u2068Xray\u2069" if fa else "Xray tunnel"
        elif mode == "pow":
            from .pow.coordinator import FORWARD_HTTP_PORT
            coordinator = getattr(getattr(self, "pow_controller", None), "coordinator", None)
            pow_port = int(getattr(coordinator, "forward_http_port", 0) or FORWARD_HTTP_PORT)
            loader = lambda pow_port=pow_port: fetch_details(pow_port)
            label = "\u200fتونل \u2068UAC PoW\u2069" if fa else "UAC PoW tunnel"
        else:
            loader = direct_identity
            label = "\u200fاتصال مستقیم" if fa else "Direct connection"
        old = getattr(self, "_ip_dialog", None)
        try:
            if old is not None and old.isVisible():
                old.close()
        except RuntimeError:
            pass
        self._ip_dialog = dialog = SharedIpDetailsDialog(self, fa, loader, label, engine=engine)
        dialog.show(); dialog.raise_()

    def _configure_technical_widgets(self):
        widgets = [self.logs, self.domains, self.carrier, self.log_filter, self.maker_repo_url]
        for widget in widgets:
            widget.setLayoutDirection(Qt.LeftToRight)
            widget.setProperty("technical", True)
            if isinstance(widget, QLabel): widget.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)


        table_direction = Qt.LeftToRight if self.language == "en" else Qt.RightToLeft
        for table in (self.results_table, self.bookmarks_table):
            table.setProperty("technical", True)
        self.maker_table.setLayoutDirection(Qt.LeftToRight)
        self.maker_table.setProperty("technical", True)
        self.maker_country_rail.setLayoutDirection(table_direction)
        self.maker_search.setLayoutDirection(table_direction)
        self.maker_progress.domain.setLayoutDirection(table_direction)

    def _sync_maker_editor_direction(self):
        persian_placeholder = self.language == "fa" and not self.maker_source_editor.toPlainText().strip()
        self.maker_source_editor.setLayoutDirection(
            Qt.RightToLeft if persian_placeholder else Qt.LeftToRight
        )

    def _sync_sidebar_language_layout(self):
        rtl = self.language == "fa"
        direction = Qt.RightToLeft if rtl else Qt.LeftToRight
        alignment = (Qt.AlignRight if rtl else Qt.AlignLeft) | Qt.AlignVCenter
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
        try:
            self._sync_engine_ui()
        except Exception:
            pass
        self.sidebar_footer.updateGeometry()
        self.sidebar.updateGeometry()
        self._fit_sidebar()

    # Sidebar fitting: nav rows, the star card and the footer must never
    # overlap. Nav rows shrink a little first, then the star card goes
    # compact (no sentence), then it is hidden.
    def _fit_sidebar(self):
        sidebar = getattr(self, "sidebar", None)
        if sidebar is None or not hasattr(self, "rating_card"):
            return
        side = self.sidebar_layout
        margins = side.contentsMargins()
        available = max(sidebar.height(), self.centralWidget().height() if self.centralWidget() else 0, self.height())
        available = min(available, self.height()) - margins.top() - margins.bottom()
        logo = self.logo_card.sizeHint().height()
        footer = self.sidebar_footer.sizeHint().height()
        fixed = logo + 14 + footer + 4 * side.spacing()
        if not self.sidebar_compact_spacer.isHidden():
            fixed += _layout.COMPACT_NAV_SPACER + side.spacing()
        buttons = self.nav
        nav_count = sum(not button.isHidden() for button in buttons)
        gap = _layout.SIDEBAR_GAP
        nav_height = _layout.NAV_HEIGHTS[-1]
        for height in _layout.NAV_HEIGHTS:
            if fixed + nav_count * (height + gap) + 180 <= available:
                nav_height = height
                break
        if self.engine_mode == ENGINE_XRAY and nav_count:
            nav_height = min(nav_height, (available - fixed - 10) // nav_count - gap)
        for button in buttons:
            button.setFixedHeight(nav_height)
        rest = available - fixed - nav_count * (nav_height + gap)
        compact_width = self.width() < 1240
        self.rating_text.setVisible(True)
        full = self.rating_card.sizeHint().height() if not compact_width else 10**6
        self.rating_text.setVisible(False)
        short = self.rating_card.sizeHint().height()
        breathing = 10 + 16  # spacing above the footer + minimum stretch
        if rest >= full + breathing:
            mode = "full"
        elif rest >= short + breathing:
            mode = "compact"
        else:
            mode = "hidden"
        self.rating_text.setVisible(mode == "full")
        self.rating_card.setVisible(mode != "hidden")
        self._sidebar_rating_mode = mode
        side.invalidate()

    def tr(self, persian: str, english: str | None = None) -> str:
        return (english or FA_EN.get(persian, persian)) if self.language == "en" else persian

    def _ui_text(self, persian, english):
        return english if self.language == "en" else _fonts.persian_ui_text(persian)

    def toggle_language(self):
        """Switch fa <-> en with the engine-switch snapshot fade.

        The language change re-applies the app stylesheet (slow repolish), so
        the relayout runs on the next tick under the overlay, the new frame is
        painted while still hidden, and only then the fade starts. Starting
        the fade before that paint made it finish before its first frame.
        """
        if getattr(self, "_language_switching", False) or getattr(self, "_engine_switching", False):
            return
        started = time.perf_counter()
        overlay = None
        if _animations_enabled() and self.isVisible():
            try:
                snapshot = self.grab()
                content = getattr(self, "stack", None)
                content_rect = (QRect(content.mapTo(self, QPoint(0, 0)), content.size())
                                if content is not None else QRect())
                overlay = _eswitch.SwitchOverlay(self, snapshot, content_rect, QRect())
                overlay.show(); overlay.raise_(); overlay.repaint()
            except Exception as exc:
                self._append_log(f"LANG SWITCH: overlay failed: {exc}")
                overlay = None
        if overlay is None:
            self._toggle_language_now()
            self._append_log("LANG SWITCH: no animation (motion off or hidden)")
            return
        self._language_switching = True
        central = self.centralWidget()
        if central is not None:
            central.setUpdatesEnabled(False)

        def cleanup():
            try:
                overlay.hide(); overlay.deleteLater()
            except Exception:
                pass
            self._language_switching = False
            self._language_switch_anim = None

        def run():
            relayout_ms = paint_ms = 0.0
            try:
                part = time.perf_counter()
                self._toggle_language_now()
                try:
                    self._sync_sidebar_language_layout()
                except Exception:
                    pass
                relayout_ms = (time.perf_counter() - part) * 1000.0
            except Exception as exc:
                self._append_log(f"LANG SWITCH: relayout error: {exc}")
            finally:
                if central is not None:
                    central.setUpdatesEnabled(True)
            try:
                part = time.perf_counter()
                overlay.raise_()
                if central is not None:
                    central.repaint()      # paint the new layout while still covered
                overlay.repaint()
                paint_ms = (time.perf_counter() - part) * 1000.0
            except Exception:
                pass
            self._append_log(
                f"LANG SWITCH: anim=on relayout={relayout_ms:.0f}ms paint={paint_ms:.0f}ms "
                f"total={(time.perf_counter() - started) * 1000.0:.0f}ms")

            def start_fade():
                try:
                    fade = _eswitch.make_animation(overlay, b"progress", 0.0, 1.0,
                                                   _eswitch.FADE_MS, parent=self)
                    fade.finished.connect(cleanup)
                    self._language_switch_anim = fade
                    fade.start()
                except Exception:
                    cleanup()
            QTimer.singleShot(16, start_fade)

        QTimer.singleShot(0, run)

    def _toggle_language_now(self):
        self.language = "en" if self.language == "fa" else "fa"
        self.storage.settings["language"] = self.language
        self.storage.save_settings()
        self._apply_language()

    def _apply_language(self):
        self._apply_app_style()
        QTimer.singleShot(0, getattr(self, "_maker_update_chips", lambda: None))
        direction = Qt.LeftToRight if self.language == "en" else Qt.RightToLeft
        self.setLayoutDirection(direction)
        self.sidebar.setLayoutDirection(direction)
        self.content_shell.setLayoutDirection(direction)
        self.hero_card.setLayoutDirection(direction)
        self.sidebar.setProperty("rtl", self.language != "en"); _restyle(self.sidebar)
        # Rebind ONLY from the i18n catalog. Never remap by the widget's current
        # text (that left Persian strings stuck on English UI and the reverse).
        for widget_type in (QLabel, QPushButton, QCheckBox, QToolButton):
            for widget in self.findChildren(widget_type):
                fa = widget.property("i18nFa"); en = widget.property("i18nEn")
                if fa is not None and en is not None:
                    widget.setText(self._ui_text(str(fa), str(en)))
        for page in self.stack.findChildren(SettingsPage):
            page.refresh_labels()
        self.global_settings_page.refresh_labels()
        for index, (fa, en) in enumerate((("پیشنهادی", "Suggested"), ("دستی", "Manual"), ("کانفیگ‌های من", "My configs"))):
            self.config_segments.setTabText(index, self._ui_text(fa, en))
        self.config_search.setPlaceholderText(self._ui_text("جست‌وجوی کانفیگ‌ها…", "Search configs…"))
        if self._profile_ping_busy:
            self.profile_ping_all_btn.setText(self._ui_text("در حال پینگ…", "Pinging…"))
        for table in self.profile_pages:
            table.setHorizontalHeaderLabels(["", *(
                ("Config name", "Server address", "SNI", "Ping", "Actions") if self.language == "en" else
                ("نام کانفیگ", "آدرس سرور", "SNI", "پینگ", "عملیات")
            )])
        self.profile_select_all_checkbox.setAccessibleName(self.tr("انتخاب همه نتایج", "Select all results"))
        self.profile_select_all_checkbox.setToolTip(self.tr(
            "انتخاب یا لغو انتخاب همه کانفیگ‌های نمایش‌داده‌شده",
            "Select or clear all visible configs",
        ))
        self._sync_profile_sort_control()
        self._position_profile_select_all()
        self.route_source_tabs.setTabText(0, self.tr("پیشنهادی", "Suggested")); self.route_source_tabs.setTabText(1, "User Config")
        self.scan_tabs.setTabText(0, self._ui_text("نتایج آزمایش", "Test results"))
        self.scan_tabs.setTabText(1, self._ui_text("ذخیره‌شده‌ها", "Saved"))
        self.scan_search.setPlaceholderText(self._ui_text("جست‌وجوی دامنه…", "Search domains…"))
        self.scan_selection_label.setAlignment(Qt.AlignLeft if self.language == "fa" else Qt.AlignRight)
        self._update_scan_domain_count()
        self._update_scan_summary()
        result_headers = (["", "Domain", "IP", "Data center", "Ping", "Stability", "First byte", "Bytes/2s", "Score"] if self.language == "en" else ["", "دامنه", "IP", "مرکز داده", "پینگ", "پایداری", "اولین پاسخ", "بایت/۲ثانیه", "امتیاز"])
        for table in (self.results_table, self.bookmarks_table):
            table.setHorizontalHeaderLabels(result_headers)
            for column in (1, 2):
                table.horizontalHeaderItem(column).setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.scan_progress.domain.setLayoutDirection(direction)
        self.scan_progress.domain.setToolTip(self.scan_progress.domain.text())
        self.app_routing_view.set_language()
        self.maker_model.set_headers(
            ["", "Exit country", "Connection status", "Real ping", "Config address"]
            if self.language == "en"
            else ["", "کشور خروجی", "وضعیت اتصال", "پینگ واقعی", "آدرس کانفیگ"],
            rtl=self.language != "en",
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
            self._bind_text(self.maker_import_badge, "آماده دریافت", "Ready to import")
            self._set_maker_progress_status("آماده بررسی", "Ready to check")
            self._set_maker_progress_detail("منتظر کانفیگ", "Waiting for configs")
        self.maker_search.setPlaceholderText(self._ui_text("جست‌وجوی کانفیگ‌ها…", "Search configs…"))
        self.maker_select_all_checkbox.setAccessibleName(self.tr("انتخاب همه کانفیگ‌ها", "Select all configs"))
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
        for button in self.nav:
            button.setProperty("rtl", self.language != "en"); _restyle(button)
        self.language_button.setText("فارسی" if self.language == "en" else "English")
        self.data_button.setText(self.tr("باز کردن پوشه داده‌ها", "Open Data Folder"))
        self._sync_sidebar_language_layout()
        QTimer.singleShot(0, self._sync_sidebar_language_layout)
        self._update_tray_text()
        self.status_pill.set_language(self.language); self.activity_bar.set_language(self.language)
        self.dns_lab_page.refresh()
        self.direct_routing_view.refresh_labels()
        if self._latest_update:
            self._render_update_info(self._latest_update)
        elif not self._update_in_progress:
            self.update_status.setText(self.tr("برای بررسی نسخه آماده است", "Ready to check for updates"))
            self.update_versions.setText(self.tr(f"نصب‌شده: {ltr_isolate(__version__)}  •  آخرین نسخه: —", f"Installed: {__version__}  •  Latest: —"))
        self.manual_list.set_empty_text(self.tr("کانفیگ دستی ندارید", "No manual configs"),
                                        self.tr("از دکمهٔ افزودن یا چسباندن لینک استفاده کنید.", "Add a config or paste a link."))
        self.user_config_list.set_empty_text(self.tr("فهرست کانفیگ‌های من خالی است", "No saved configs"),
                                             self.tr("کانفیگ‌های سالم را از سازندهٔ SNI اضافه کنید.", "Add healthy configs from SNI Config Maker."))
        self.suggested_list.set_empty_text(self.tr("کانفیگ اصلی موجود نیست", "No original configs"),
                                           self.tr("لیست اصلی را بازیابی کنید.", "Restore the original list."))
        for table in self.profile_pages:
            table.no_matches = self.tr("کانفیگی با این جست‌وجو پیدا نشد.", "No configs match this search.")
        self._update_config_actions()
        self.log_filter.setPlaceholderText(self.tr("فیلتر لاگ‌ها…", "Filter logs…"))
        self._set_log_count(len(self._all_log_lines))
        try:
            self._render_logs()
        except Exception:
            pass
        if not self.activity_bar.busy: self.activity_bar.set_activity("", "idle", False)
        hero_alignment = (Qt.AlignLeft | Qt.AlignAbsolute) if self.language == "en" else (Qt.AlignRight | Qt.AlignAbsolute)
        self.status.setAlignment(hero_alignment | Qt.AlignVCenter); self.connection_hint.setAlignment(hero_alignment | Qt.AlignVCenter); self.hero_badge.setAlignment(hero_alignment | Qt.AlignVCenter)
        if self.connecting:
            self._set_connection_visual("connecting")
        elif self.connection_error and not self.engine.running:
            self._set_connection_visual("error")
        else:
            self._set_state(self.engine.running)
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
        self.global_settings_page.refresh()
        self.pow_controller.refresh_settings_page()
        self._refresh_app_routing_notice()
        self._layout_home_dashboard()
        if self._update_notification is not None and self._latest_update is not None:
            self._show_update_notification(self._latest_update)
        self.refresh_profiles()
        self._update_scan_selection()
        self._maker_repo_url_changed()
        # Engine-specific home labels (PoW vs Xray) and PoW page summary.
        try:
            self._apply_engine_home()
        except Exception:
            pass
        controller = getattr(self, "pow_controller", None)
        if controller is not None:
            try:
                controller.apply_language()
            except Exception:
                pass
        gateway_popup = getattr(self, "gateway_devices_popup", None)
        if gateway_popup is not None and hasattr(gateway_popup, "set_language"):
            try:
                gateway_popup.set_language(self.language)
            except Exception:
                pass

    def _change_global_settings(self, **changes):
        before = self.global_settings.snapshot()
        if ((changes.get("connection_mode", before.connection_mode) != before.connection_mode
             and self._protected_session())
                or (changes.get("kill_switch", before.kill_switch) != before.kill_switch
                    and self._engine_busy())):
            self._reject_guarded_change()
            self.global_settings_page.refresh()
            return False
        try:
            self.global_settings.change(**changes)
        except ValueError:
            self.show_toast(self.tr("دامنه یا آی‌پی واردشده معتبر نیست.",
                                    "Enter a valid domain or IP address."), "warning")
            self.global_settings_page.refresh()
            return False
        except OSError as exc:
            self.show_toast(str(exc), "danger")
            self.global_settings_page.refresh()
            return False
        self._global_settings_changed(before)
        return True

    def _protected_session(self):
        mode = self.engine_mode
        if mode == ENGINE_POW:
            guarded = self.pow_controller.coordinator.protected
        elif mode == ENGINE_DIRECT:
            guarded = self.direct_controller.coordinator.status.protected
        else:
            return False
        preferences = self.global_settings.snapshot()
        return guarded or (preferences.kill_switch and preferences.connection_mode == "vpn"
                           and self._engine_busy())

    def _reject_guarded_change(self):
        self.show_toast(self.tr("برای این تغییر، ابتدا اتصال VPN را دستی قطع کنید.",
                                "Disconnect the VPN manually before making this change."), "warning")

    def _navigation_animations_enabled(self):
        return _animations_enabled() and not self.global_settings.reduce_navigation_motion

    def _global_settings_changed(self, before):
        current = self.global_settings.snapshot()
        if before.auto_connect != current.auto_connect:
            self._auto_connect.configure()
        self.global_settings_page.refresh()
        if before.routing_mode != current.routing_mode:
            self._bypass_apply_timer.stop()
        self.app_routing_view.refresh()
        if self.engine_mode == ENGINE_XRAY:
            self._sync_xray_output_controls()
        elif self.engine_mode == ENGINE_POW:
            controller = self.pow_controller
            if ((before.lan_share, before.lan_share_mode, before.lan_share_port)
                    != (current.lan_share, current.lan_share_mode, current.lan_share_port)):
                controller.apply_global_lan_share()
            self._pow_sync_home_visuals()
        elif self.engine_mode == ENGINE_DIRECT:
            self.direct_controller.refresh()

    def _refresh_app_routing_notice(self):
        if hasattr(self, "app_routing_view") and self.app_routing_view.isVisible():
            self.app_routing_view.refresh_notice()

    def _save_flag(self, key, value): self.storage.settings[key] = value; self.storage.save_settings()

    def _assistant_enabled_changed(self, enabled):
        if not ASSISTANT_FEATURE_ENABLED:
            self.assistant_toggle.blockSignals(True)
            self.assistant_toggle.setChecked(False)
            self.assistant_toggle.blockSignals(False)
            self._save_flag("assistant_enabled", False)
            return
        enabled = bool(enabled)
        self._save_flag("assistant_enabled", enabled)
        controller = self.assistant_controller
        if controller is None:
            return
        if enabled:
            controller.enable()
        else:
            controller.disable(persist=False)

    def _replay_assistant_guide(self):
        if not ASSISTANT_FEATURE_ENABLED:
            return
        if not self.assistant_guides_toggle.isChecked():
            self.assistant_guides_toggle.setChecked(True)
        if not self.assistant_toggle.isChecked():
            self.assistant_toggle.setChecked(True)
        if self.assistant_controller is not None:
            self.assistant_controller.start_tour()

    def _assistant_guides_changed(self, enabled):
        self._save_flag("assistant_guides_enabled", bool(enabled))
        controller = self.assistant_controller
        if controller is not None and controller.enabled:
            if not enabled and controller._tour:
                controller.skip_tour()
            controller.evaluate(force=True)

    def _assistant_warnings_changed(self, enabled):
        self._save_flag("assistant_warnings_enabled", bool(enabled))
        controller = self.assistant_controller
        if controller is not None and controller.enabled:
            controller.evaluate(force=True)

    def _xray_output(self):
        session = self._xray_session_mode
        if session is not None and (self.connecting or self.engine.running):
            return session
        return self.global_settings.snapshot().connection_mode

    def _proxy_mode_enabled(self) -> bool:
        return self._xray_output() == "proxy"

    def _tun_mode_enabled(self) -> bool:
        return self._xray_output() == "vpn"

    def _set_xray_output(self, mode):
        if self._change_global_settings(connection_mode=mode):
            self._xray_session_mode = mode
        self._sync_xray_output_controls()

    def _sync_xray_output_controls(self):
        proxy, vpn = self._proxy_mode_enabled(), self._tun_mode_enabled()
        for option, toggle, value in ((self.proxy_option, self.proxy_mode, proxy),
                                      (self.tun_option, self.tun_mode, vpn)):
            self._pow_set_toggle(toggle, value)
            option.setProperty("active", value)
            _restyle(option)
        self.proxy_option.setEnabled(not vpn)

    def _set_direct_output(self, mode):
        if not self._change_global_settings(connection_mode=mode):
            self.direct_controller.refresh()
            return
        if mode == "local":
            self.direct_controller.stop()
            self.direct_controller.refresh()
        elif (self.direct_controller.busy
              and self.direct_controller.coordinator.session_vpn != (mode == "vpn")):
            self._set_activity("اتصال Direct برای تغییر نوع خروجی دوباره برقرار می‌شود.",
                               "Direct is reconnecting to change its output.", "running", True)
            self.direct_controller.restart_if_active()

    def _set_windows_proxy_preference(self, enabled):
        direct = self.engine_mode == ENGINE_DIRECT
        controller = self.direct_controller if direct else self.pow_controller
        preferences = self.global_settings.snapshot()
        try:
            if preferences.connection_mode == "vpn":
                return
            if controller.busy:
                controller.coordinator.set_system_proxy_enabled(enabled)
            self.global_settings.change(connection_mode="proxy" if enabled else "local")
            self.app_routing_view.refresh()
        except (OSError, RuntimeError) as exc:
            self.show_toast(self.tr("تغییر پروکسی ویندوز اعمال نشد.", "Could not change Windows Proxy."), "warning")
            self.bridge.engine_log.emit(f"Windows Proxy: {exc}", self.engine_mode)
        finally:
            if direct:
                controller.refresh_output_controls()
            else:
                self._pow_sync_home_visuals()

    def _proxy_mode_changed(self, enabled):
        if getattr(self, "engine_mode", ENGINE_XRAY) in (ENGINE_DIRECT, ENGINE_POW):
            if not getattr(self, "_pow_home_loading", False):
                self._set_windows_proxy_preference(bool(enabled))
            return
        enabled = bool(enabled)
        self._set_xray_output("proxy" if enabled else "local")
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
                    if item.data(Qt.UserRole) and not widget.isRowHidden(row):
                        widget.setRangeSelected(QTableWidgetSelectionRange(row, 0, row, widget.columnCount() - 1), True)
            widget.update_marks()
        finally:
            widget.blockSignals(False)
        self._sync_profile_select_all(widget)
        self._update_config_actions()

    def _sync_profile_select_all(self, widget):
        checkbox = getattr(self, "profile_select_all_checkbox", None)
        if checkbox is None or widget is not self._current_profile_list():
            return
        selectable = [
            item
            for row in range(widget.count())
            if (item := widget.item(row)) is not None and item.data(Qt.UserRole) and not widget.isRowHidden(row)
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
            self._ui_text("در حال پینگ…", "Pinging…")
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
            self._ui_text("تست پینگ همه", "Ping all")
        )
        self.refresh_profiles()
        self._set_activity(
            f"پینگ کامل شد؛ {successful} از {len(by_id)} کانفیگ پاسخ داد.",
            f"Ping completed; {successful} of {len(by_id)} configs responded.",
            "success", False,
        )

    def _position_profile_select_all(self):
        checkbox = getattr(self, "profile_select_all_checkbox", None)
        if checkbox is None:
            return
        widget = self._current_profile_list()
        if widget is None:
            return
        header = widget.horizontalHeader()
        if checkbox.parentWidget() is not header:
            checkbox.setParent(header)
        col = ProfileTable.MARK
        checkbox.move(header.sectionViewportPosition(col) + (header.sectionSize(col) - checkbox.width()) // 2,
                      (header.height() - checkbox.height()) // 2)
        checkbox.show()
        checkbox.raise_()

    def _filter_config_rows(self, *_):
        query = self.config_search.text().strip().casefold()
        for table in self.profile_pages:
            table.filter_rows(query)
        self._update_config_actions()

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
            self._set_xray_output("proxy" if fallback else "local")
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
        if getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_DIRECT:
            self._set_direct_output("vpn" if enabled else "local")
            return
        if getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_POW:
            if getattr(self, "_pow_home_loading", False):
                return
            self.pow_controller.set_exit_mode(False if enabled else None)
            self._pow_sync_home_visuals()
            return
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
        if not availability_error:
            self._set_xray_output("vpn" if enabled else "proxy")
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
            self._set_xray_output("vpn" if runtime_enabled else
                                  "proxy" if self.engine._proxy_enabled else "local")
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
        popup.update_devices(
            self._gateway_devices,
            self._gateway_device_names,
        )
        popup.show()
        self._position_gateway_devices_popup()
        popup.raise_()

    def _gateway_runtime_names_received(self, names):
        results = {
            str(address): DeviceNameResult(str(name), "dhcp", 100)
            for address, name in dict(names or {}).items()
            if str(name or "").strip()
        }
        self.bridge.gateway_device_names_changed.emit({
            "generation": self._gateway_device_name_generation,
            "results": results,
            "pending": [],
        })

    def _queue_gateway_device_name_resolution(self):
        devices = {
            address: mac
            for address, mac in self._gateway_devices.items()
            if (
                address not in self._gateway_device_names
                and address not in self._gateway_device_name_pending
            )
        }
        if not devices:
            return
        gateway = getattr(self.engine, "gateway", None)
        gateway_address = (
            str(getattr(gateway, "gateway_address", "") or "")
            if gateway is not None else ""
        )
        generation = self._gateway_device_name_generation
        self._gateway_device_name_pending.update(devices)

        def work():
            results = self._gateway_device_name_resolver.resolve_many(
                devices,
                gateway_address,
            )
            self.bridge.gateway_device_names_changed.emit({
                "generation": generation,
                "devices": devices,
                "results": results,
                "pending": list(devices),
            })

        threading.Thread(
            target=work,
            name="gateway-device-names",
            daemon=True,
        ).start()

    def _gateway_device_names_updated(self, payload):
        values = dict(payload or {})
        generation = values.get("generation")
        if (
            generation is not None
            and int(generation) != self._gateway_device_name_generation
        ):
            return
        for address in values.get("pending", ()):
            self._gateway_device_name_pending.discard(str(address))
        snapshot = dict(values.get("devices", {}) or {})
        results = dict(values.get("results", values) or {})
        changed = False
        for address, result in results.items():
            address = str(address)
            if address not in self._gateway_devices:
                continue
            if snapshot and snapshot.get(address) != self._gateway_devices.get(address):
                continue
            if isinstance(result, DeviceNameResult):
                name = str(result.name or "").strip()
                priority = int(result.priority)
            else:
                name = str(result or "").strip()
                priority = 100
            if not name:
                continue
            previous_priority = self._gateway_device_name_priorities.get(
                address,
                -1,
            )
            if priority < previous_priority:
                continue
            if self._gateway_device_names.get(address) != name:
                self._gateway_device_names[address] = name
                changed = True
            self._gateway_device_name_priorities[address] = priority
        if changed:
            popup = getattr(self, "gateway_devices_popup", None)
            if popup is not None:
                popup.update_devices(
                    self._gateway_devices,
                    self._gateway_device_names,
                )
                if popup.isVisible():
                    self._position_gateway_devices_popup()

    def _gateway_devices_updated(self, devices):
        self._gateway_devices = dict(devices or {})
        current = set(self._gateway_devices)
        self._gateway_device_names = {
            address: name
            for address, name in self._gateway_device_names.items()
            if address in current
        }
        self._gateway_device_name_priorities = {
            address: priority
            for address, priority in self._gateway_device_name_priorities.items()
            if address in current
        }
        self._gateway_device_name_pending.intersection_update(current)
        toggle = getattr(self, "gateway_mode", None)
        if toggle is None:
            return
        count = len(self._gateway_devices)
        active = self._gateway_runtime_active()
        badge = getattr(self, "gateway_devices_badge", None)
        if badge is not None:
            badge.setText(str(count))
            badge.setToolButtonStyle(Qt.ToolButtonTextBesideIcon if count else Qt.ToolButtonIconOnly)
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
            popup.update_devices(
                self._gateway_devices,
                self._gateway_device_names,
            )
            if popup.isVisible():
                self._position_gateway_devices_popup()
        self._queue_gateway_device_name_resolution()
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
        if getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_DIRECT:
            return
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
        self._gateway_device_name_generation += 1
        self._gateway_device_name_pending.clear()
        self._cancel_gateway_apply()
        self._set_gateway_toggle(False)
        self._sync_gateway_controls()
        if stop and (requested or active or pending_enable):
            self._queue_gateway_mode_apply(False, reason=reason, force=True)
        return requested or active or pending_enable

    def _gateway_mode_changed(self, enabled):
        if getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_POW:
            if not getattr(self, "_pow_home_loading", False):
                # On = force; off = auto (adaptive may turn it on again).
                self.pow_controller.set_h2_fragment(bool(enabled))
                self._pow_h2_label_state = None
                self._pow_sync_home_visuals()
            return
        enabled = bool(enabled)

        if not enabled:
            self._reset_gateway_mode(reason="user", stop=True)
            return
        self._gateway_requested = True
        self._cancel_gateway_apply()
        self._set_gateway_toggle(True)
        self._sync_gateway_controls()

        if (
            self.engine.running
            and getattr(self, "_ui_running", False)
            and not self.connecting
        ):
            self._queue_gateway_mode_apply(
                True,
                reason="user",
            )
            return

        self._set_activity(
            "درگاه موبایل آماده است؛ منتظر اتصال VPN…",
            "Mobile Gateway is armed; waiting for VPN connection…",
            "warning",
            False,
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

            if reason == "user":
                if getattr(self, "_ui_running", False):
                    self._set_activity(
                        "درگاه موبایل خاموش شد؛ اتصال VPN فعال ماند.",
                        "Mobile Gateway disabled; the VPN connection stayed active.",
                        "success",
                        False,
                    )
                else:
                    self._set_activity(
                        "درگاه موبایل خاموش شد.",
                        "Mobile Gateway disabled.",
                        "success",
                        False,
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
                    "در حال راه‌اندازی رابط TUN و بررسی ترافیک تونل…",
                    "Starting the TUN interface and checking tunnel traffic…",
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
                    raise RuntimeError(f"TUN traffic check failed: {detail}")
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
        source_getter = getattr(self, "_selected_route_source", None)
        if callable(source_getter) and source_getter() == "suggested":
            return ""
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
        if (profile.origin not in DIRECT_PROFILE_ORIGINS
                and profile.origin != "builtin"):
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
        if getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_DIRECT:
            self.direct_controller.refresh_country()
            return
        if getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_POW and hasattr(self, "pow_country_button"):
            self._update_pow_country_selector()
            return
        source = self._selected_route_source()
        original_label = getattr(self, "original_configs_label", None)
        if original_label is not None:
            original_label.setVisible(source == "suggested")
        if hasattr(self.country_combo, "setVisible"):
            self.country_combo.setVisible(source != "suggested")
        if source == "suggested":
            self.country_combo.blockSignals(True)
            self.country_combo.clear()
            self.country_combo.addItem(
                cyber_icon("server", "#78fff0", 19),
                "UAC Spoof Original Configs", "ALL",
            )
            self.country_combo.setCurrentIndex(0)
            self.country_combo.blockSignals(False)
            count = len(self._route_source_profiles())
            self.country_count.setText(self.tr(
                f"{count} کانفیگ اصلی", f"{count} original configs"
            ))
            return
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
        if getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_POW:
            if getattr(self, "_pow_home_loading", False):
                return
            code = str(self.country_combo.currentData() or "")
            self._pow_setting(exit_country_code=code)
            return
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
        if getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_POW:
            if getattr(self, "_pow_home_loading", False):
                return
            automatic = self.route_source_tabs.currentIndex() == 0
            if automatic:
                self._pow_setting(exit_country_code="")
            self._fill_pow_country_combo(
                self.pow_controller.store.snapshot().exit_country_code, automatic)
            return
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
        if (getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_XRAY and not self._closing and self.auto_mode.isChecked()
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
        widget = self._current_profile_list()
        with QSignalBlocker(self.config_segments):
            self.config_segments.setCurrentIndex(2 - index)
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
        if getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_DIRECT:
            return
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

    def _pick_best_changed(self, enabled):
        if getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_POW:
            if not getattr(self, "_pow_home_loading", False):
                self._pow_setting(optimized_mode=bool(enabled))
            return
        self._save_flag("pick_best", enabled)

    def _auto_mode_changed(self, enabled):
        if getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_DIRECT:
            self.direct_controller.save("auto_select_dns", bool(enabled))
            return
        if getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_POW:
            if not getattr(self, "_pow_home_loading", False):
                self._pow_setting(exit_mode="chain" if enabled else "warp")
            return
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
        if getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_POW:
            if not getattr(self, "_pow_home_loading", False):
                value = str(carrier or "auto").strip().lower()
                if value not in ("auto", "mci", "irancell"):
                    value = "auto"
                self._pow_setting(firewall_profile=value)
            return
        tuning = self.storage.activate_carrier(carrier)
        self.bridge.log.emit(
            f"CARRIER PROFILE active={carrier} edge={tuning.pattern_connect_ip} "
            f"fakeSni={tuning.pattern_fake_sni} sessions={tuning.pattern_max_sessions}")
        self.refresh_profiles()

    def _effective_profile_fake_sni(self, profile, carrier=None):
        if _is_direct_route(profile):
            return str(profile.sni or "").strip()
        carrier = carrier or self.storage.tuning.carrier_mode
        builtin_route = MainWindow._builtin_route_entry(self, profile, carrier)
        if builtin_route.get("fake_sni"):
            return str(builtin_route["fake_sni"]).strip()
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

    def _update_route_card(self, profile, carrier=None):
        """Refresh the selected Xray route and retain its technical details in the tooltip."""
        from .route_card import card_title, route_kind
        if getattr(self, "engine_mode", ENGINE_XRAY) != ENGINE_XRAY:
            return
        if profile is None:
            self.active_profile.setText("—")
            self.active_profile.setToolTip("")
            self.route_card.set_secondary("")
            return
        self.active_profile.setText(card_title(profile, self.language))
        kind = route_kind(profile, bool(self.storage.settings.get("multi_gene_enabled", False)))
        detail = f"{kind}\n{self._profile_route_label(profile, carrier)}"
        self.active_profile.setToolTip(detail)
        self.route_card.set_secondary(detail)

    def _profile_route_label(self, profile, carrier=None, include_ping=True):
        if profile is None:
            return ""
        fake_sni = self._effective_profile_fake_sni(profile, carrier)
        label = (
            f"{_route_label(profile)} SNI"
            if _is_direct_route(profile) else "Fake SNI"
        )
        target = (
            profile.target_label
            if include_ping else
            f"{profile.address}:{profile.port} / {profile.sni}"
        )
        return f"{target}\n{label} {fake_sni}"

    def _attach_profile_row(self, table, item, profile, tooltip, icon, sni):
        row = item.row()
        source = self.tr("پیشنهادی", "Suggested")
        if table is self.user_config_list:
            source = self.tr("کانفیگ‌های من", "My configs")
        elif table is self.manual_list:
            source = self.tr("دستی", "Manual")
        country = self._country_metadata(profile.observed_country_code or profile.country_code)
        search_text = " ".join(map(str, (profile.name, profile.address, profile.port,
                                       f"{profile.address}:{profile.port}", profile.sni, sni,
                                       profile.protocol, profile.country_code, *country)))
        item.setData(Qt.UserRole + 2, search_text.casefold())
        item.setToolTip(tooltip)

        for column, title, subtitle in (
            (ProfileTable.NAME, profile.name, source),
            (ProfileTable.SERVER, profile.address, self.tr(f"درگاه {profile.port}", f"Port {profile.port}")),
        ):
            cell = QWidget()
            cell.setAttribute(Qt.WA_TransparentForMouseEvents)
            box = QVBoxLayout(cell)
            box.setContentsMargins(6, 0, 6, 0)
            box.setSpacing(1)
            box.setAlignment(Qt.AlignVCenter)
            name = ElidedLabel(title)
            name.setObjectName("configCellName" if column == ProfileTable.NAME else "configServer")
            side = Qt.AlignRight if column == ProfileTable.NAME and self.language == "fa" else Qt.AlignLeft
            alignment = side | Qt.AlignAbsolute | Qt.AlignVCenter
            name.setAlignment(alignment)
            if column == ProfileTable.SERVER:
                name.setLayoutDirection(Qt.LeftToRight)
            detail = ElidedLabel(self._ui_text(subtitle, subtitle))
            detail.setObjectName("configCellDetail")
            detail.setAlignment(alignment)
            if column == ProfileTable.NAME:
                name_row = QHBoxLayout()
                flag = QLabel(cell)
                flag.setPixmap(icon.pixmap(17, 13))
                flag.setVisible(profile.route_is_verified)
                name_row.setSpacing(5)
                name_row.addWidget(flag)
                name_row.addWidget(name, 1)
                box.addLayout(name_row)
            else:
                box.addWidget(name)
            box.addWidget(detail)
            text = QTableWidgetItem()
            text.setToolTip(tooltip)
            table.setItem(row, column, text)
            table.setCellWidget(row, column, cell)

        sni_cell = QTableWidgetItem(ltr_isolate(sni) if sni else "—")
        sni_cell.setTextAlignment(Qt.AlignCenter)
        sni_cell.setToolTip(tooltip)
        table.setItem(row, ProfileTable.SNI, sni_cell)
        ping_label = QLabel(f"{profile.last_ping_ms:.0f} ms" if profile.last_ping_ok else "—")
        ping_label.setObjectName("configPing")
        ping_label.setLayoutDirection(Qt.LeftToRight)
        ping_label.setAlignment(Qt.AlignCenter)
        ping_label.setAttribute(Qt.WA_TransparentForMouseEvents)
        latency = profile.last_ping_ms
        ping_label.setProperty("quality", "unknown" if not profile.last_ping_ok else
                               "fast" if latency <= 180 else "medium" if latency <= 500 else "slow")
        table.setCellWidget(row, ProfileTable.PING, ping_label)

        active = profile.id == self.storage.selected_id
        actions = QWidget()
        buttons = QHBoxLayout(actions)
        buttons.setContentsMargins(4, 0, 4, 0)
        buttons.setSpacing(4)
        buttons.setAlignment(Qt.AlignCenter)
        for name, fa, en, icon_name, callback, width, color in (
            ("profileRowActivate", "", "", "", self._activate_profile_by_id, 73, ""),
            ("profileRowEdit", "ویرایش کانفیگ", "Edit config", "edit", self._edit_profile_by_id, 23, "#91cce2"),
            ("profileRowDelete", "حذف کانفیگ", "Delete config", "trash",
             lambda profile_id: self.delete_profile({profile_id}), 23, "#f2a1ae"),
        ):
            button = QToolButton()
            button.setObjectName(name)
            button.setFixedSize(width, 27)
            button.setCursor(Qt.PointingHandCursor)
            if icon_name:
                label = self.tr(fa, en)
                button.setToolTip(label)
                button.setAccessibleName(label)
                button.setIcon(cyber_icon(icon_name, color, 13))
                button.setIconSize(QSize(13, 13))
            else:
                self._set_profile_activate_button(button, active)
            button.clicked.connect(lambda _checked=False, action=callback, key=profile.id: action(key))
            buttons.addWidget(button)
        table.setCellWidget(row, ProfileTable.ACTIONS, actions)

    def _set_profile_activate_button(self, button, active):
        label = self.tr("فعال است", "Active") if active else self.tr("فعال‌سازی", "Activate")
        button.setText(label)
        button.setToolTip(label)
        button.setAccessibleName(label)
        button.setProperty("active", active)
        button.setEnabled(not active)
        _restyle(button)

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
        target_item = None
        for table in self.profile_pages:
            table.selectionModel().clear()
            for row in range(table.count()):
                item = table.item(row)
                actions = table.cellWidget(row, ProfileTable.ACTIONS)
                if actions is None:
                    continue
                active = item.data(Qt.UserRole) == profile.id
                button = actions.findChild(QToolButton, "profileRowActivate")
                if button.property("active") != active:
                    self._set_profile_activate_button(button, active)
                if active and table is widget:
                    target_item = item
        if target_item is not None:
            widget.setCurrentItem(target_item)
        self.profile_tabs.setCurrentIndex(self._profile_tab_index(widget))
        self._refresh_country_selector()
        self._update_route_card(profile)
        self._update_config_actions()

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
                    header = QTableWidgetItem(self.tr(
                        f"{title}  ·  {count} کانفیگ",
                        f"{title}  ·  {count} configs",
                    ))
                    header.setData(Qt.UserRole, None)
                    header.setData(Qt.UserRole + 1, "country-header")
                    header.setFlags(Qt.NoItemFlags)
                    header.setIcon(country_flag_icon(code, 30, 20))
                    header.setForeground(QColor("#79efe7"))
                    header.setBackground(QColor("#112a3d"))
                    font = header.font(); font.setWeight(QFont.Weight.Medium); header.setFont(font)
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
            item = QTableWidgetItem(item_text); item.setData(Qt.UserRole, profile.id)
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
                sni = self._effective_profile_fake_sni(profile, carrier)
                tooltip = "\n".join(part for part in (item_text, item.toolTip()) if part)
                attach_row(target, item, profile, tooltip, item_icon, sni)
            if profile.id == self.storage.selected_id:
                if isinstance(target, ProfileTable):
                    target.show_current_profile(item)
                else:
                    target.setCurrentItem(item)
        if hasattr(self, "config_search"):
            self._filter_config_rows()
            count = self._ui_text(str(len(self.storage.profiles)), str(len(self.storage.profiles)))
            caption = self.tr("کانفیگ موجود", "configs available")
            self.config_count_label.setText(f'<span dir="ltr"><b style="color:#46DCE8;font-size:22px">{count}</b>&nbsp; {caption}</span>')
        else:
            self.config_count_label.setText(self.tr(f"{len(self.storage.profiles)} کانفیگ", f"{len(self.storage.profiles)} configs"))
        selected = self.storage.selected(); self._update_route_card(selected, carrier)
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

    def _set_maker_progress_status(self, fa, en, state="idle"):
        label = self._bind_text(self.maker_progress.status, fa, en)
        self.maker_progress.set_status(label.text(), state)

    def _set_maker_progress_detail(self, fa, en):
        label = self._bind_text(self.maker_progress.domain, fa, en)
        self.maker_progress.setFormat(label.text())

    def _set_maker_guide_button(self, button):
        if self._maker_guide_button is button:
            return
        if self._maker_guide_button is not None:
            self._maker_guide_button.setProperty("guided", False)
            _restyle(self._maker_guide_button)
        self._maker_guide_button = button
        if button is not None:
            button.setProperty("guided", True)
            _restyle(button)

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
        self._bind_text(self.maker_import_badge, "در حال پردازش…", "Processing…")

        def work():
            try:
                maker = SniConfigMaker(
                    fake_sni=self.storage.tuning.pattern_fake_sni,
                )
                imported = loader(maker)
                converted = maker.convert_many(imported.profiles)
                if replace and not converted.profiles:
                    raise ValueError(self.tr("کانفیگ قابل استفاده در منبع پیدا نشد.", "No usable configs found in this source."))
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
            self._bind_text(self.maker_import_badge, "خطا در دریافت یا پردازش", "Import failed")
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
            self._set_maker_progress_status("آماده بررسی", "Ready to check")
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
                try:
                    source_edge = ipaddress.ip_address(
                        str(profile.address or "").strip()
                    )
                    if source_edge.version != 4 or source_edge.is_loopback:
                        profile.address = VERIFIED_SPOOF_EDGE
                except ValueError:
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
        compact = [(f"{len(added_profiles)} کانفیگ وارد شد", f"{len(added_profiles)} configs imported")]
        if issue_count:
            compact.append((f"{issue_count} مشکل", f"{issue_count} issues"))
        elif duplicate_count:
            compact.append((f"{duplicate_count} تکراری", f"{duplicate_count} duplicates"))
        self._bind_text(self.maker_import_badge, " · ".join(fa for fa, _ in compact),
                        " · ".join(en for _, en in compact))
        self.maker_import_badge.setToolTip("  •  ".join(details))
        source = str(meta.get("source", ""))
        if source.startswith("http"):
            self.storage.settings["sni_maker_url"] = source
            self.storage.save_settings()
        self._set_maker_progress_detail(
            f"{len(self._maker_profiles)} کانفیگ آمادهٔ بررسی",
            f"{len(self._maker_profiles)} configs ready to check",
        )
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
        carrier, clean_ips = self._maker_precheck_clean_ips()
        self._maker_launch_test(profiles, carrier, clean_ips)

    def _maker_precheck_clean_ips(self):
        """Small modal: detect carrier (ASN) and find its clean IPs. Never blocks testing."""
        fallback = str(getattr(self.storage.tuning, "carrier_mode", "") or "auto").lower()
        try:
            from .sni_cleanip_precheck import CleanIpPrecheckDialog
            tunings = self.storage.all_carrier_tunings()

            def tuning_for(carrier):
                return tunings.get(carrier) or self.storage.tuning

            def fake_sni_for(carrier):
                return str(getattr(tuning_for(carrier), "pattern_fake_sni", "") or "").strip() or "chatgpt.com"

            def seeds_for(carrier):
                t = tuning_for(carrier)
                return [t.pattern_connect_ip, *str(t.pattern_fallback_ips or "").split(",")]

            dialog = CleanIpPrecheckDialog(self, self._clean_ip_cache(), fallback,
                                           fake_sni_for, seeds_for, self.language)
            dialog.exec()
            dialog.wait_worker(3000)
            carrier, ips = dialog.result_carrier, list(dialog.result_ips)
            if dialog.cancelled:
                self._append_log("SNI MAKER: clean IP search cancelled; testing with normal edges")
                return carrier, []
            if ips:
                self._append_log(f"SNI MAKER: {len(ips)} clean IPs on {carrier}: {', '.join(ips)}")
            else:
                self._append_log(f"SNI MAKER: no clean IP found on {carrier}; testing with normal edges")
            return carrier, ips
        except Exception as exc:
            self._append_log(f"SNI MAKER: clean IP pre-check unavailable ({exc}); testing with normal edges")
            return fallback, []

    def _maker_launch_test(self, profiles, carrier="", clean_ips=None):
        if self._maker_running:
            return
        clean_edges = {carrier: list(clean_ips)} if carrier and clean_ips else {}
        self._maker_generation += 1
        generation = self._maker_generation
        self._maker_running = True
        self._assistant_maker_test_completed_at = 0.0
        self._assistant_maker_next_action = ""
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
        self._set_maker_progress_status("در حال بررسی اتصال", "Checking connections", "running")
        self._set_maker_progress_detail(
            f"۰ از {len(profiles)} کانفیگ",
            f"0 of {len(profiles)} configs",
        )
        workers = self.maker_threads.value()
        timeout = float(self.maker_timeout.value())
        tuning = self.storage.tuning
        carrier_tunings = self.storage.all_carrier_tunings()
        tester = self._maker_tester
        cancel = self._maker_cancel_event

        def progress(batch, done, total):
            self.bridge.maker_batch.emit(batch, done, total, generation)

        def work():
            try:
                results = tester.run_all_modes(
                    profiles, tuning, cancel,
                    workers=workers, timeout=timeout,
                    progress=progress,
                    carrier_tunings=carrier_tunings,
                    clean_edges=clean_edges,
                    preferred_carrier=carrier,
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
                direct = _is_direct_route(profile)
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
                route_label = _route_label(profile)
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
            elif result.carrier_mode or result.strategy:

                attempt = "/".join(
                    value
                    for value in (
                        result.carrier_mode,
                        result.strategy,
                    )
                    if value
                )

                updates.append({
                    "key": key,
                    "status": "retrying",
                    "country_code": "XX",
                    "ping_ms": None,
                    "error": (
                        f"{attempt}: "
                        f"{result.error or 'route failed'}"
                    ),
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

                route_label = _route_label(profile)

                profile.name = (
                    f"{self._maker_base_names.get(key, profile.name)}"
                    f" · {route_label}"
                )

                updates.append({
                    "key": key,
                    "status": "failed",
                    "country_code": "XX",
                    "ping_ms": None,
                    "error": (
                        result.error
                        or "All route modes failed"
                    ),
                })
        self.maker_model.update_batch(updates)
        self.maker_progress.setValue(done)
        self._set_maker_progress_detail(
            f"{done} از {total} کانفیگ بررسی شد",
            f"{done} of {total} configs checked",
        )

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
        if healthy and not cancelled:
            self._assistant_maker_test_completed_at = time.time()
            self._assistant_maker_next_action = "maker_add_all"
        self._set_maker_progress_status(
            "بررسی متوقف شد" if cancelled else "بررسی کامل شد",
            "Checking stopped" if cancelled else "Checking complete",
            "warning" if cancelled else "success",
        )
        self._set_maker_progress_detail(
            f"{healthy} کانفیگ سالم در {len(self._maker_country_labels)} کشور",
            f"{healthy} healthy configs across {len(self._maker_country_labels)} countries",
        )
        self._set_activity(
            f"تست کانفیگ‌ها پایان یافت؛ {healthy} کانفیگ سالم است.",
            f"Config testing finished; {healthy} configs are healthy.",
            "warning" if cancelled else "success", False,
        )
        controller = self.assistant_controller
        if controller is not None and getattr(controller, "enabled", False):
            QTimer.singleShot(0, lambda: controller.evaluate(force=True))

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
        self._set_maker_progress_status("بررسی ناموفق بود", "Connection check failed", "warning")
        self._set_maker_progress_detail(str(message), str(message))
        self.show_toast(str(message), "danger")

    def _maker_stop_test(self):
        if not self._maker_running:
            return
        self._maker_cancel_event.set()
        self.maker_stop_btn.setEnabled(False)
        self._set_maker_progress_status("در حال توقف…", "Stopping…", "warning")
        tester = self._maker_tester
        if tester is not None:
            threading.Thread(target=tester.stop, name="sni-maker-stop", daemon=True).start()

    def _maker_clear(self):
        self._maker_stop_test()
        self._maker_generation += 1
        self._maker_import_generation += 1
        self._maker_finish_test_ui()
        self._maker_import_in_progress = False
        self._assistant_maker_test_completed_at = 0.0
        self._assistant_maker_next_action = ""
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
        self._bind_text(self.maker_import_badge, "آماده دریافت", "Ready to import")
        self.maker_import_badge.setToolTip("")
        self.maker_progress.setMaximum(100); self.maker_progress.setValue(0)
        self._set_maker_progress_status("آماده بررسی", "Ready to check")
        self._set_maker_progress_detail("منتظر کانفیگ", "Waiting for configs")
        self._maker_repo_url_changed()
        self._update_maker_guide()

    def _maker_update_chips(self, *_args):
        if not hasattr(self, "maker_chip_healthy"):
            return
        model = self.maker_model
        rows = model.results()
        counts = model.status_counts()
        healthy = int(counts.get("healthy", 0))
        failed = int(counts.get("failed", 0)) + int(counts.get("invalid", 0))
        ech = sum(1 for row in rows if "ech=" in (row.uri or "").lower() or "echcl=" in (row.uri or "").lower())
        self.maker_chip_total.setText(self._ui_text(f"{len(rows)} مجموع", f"{len(rows)} total"))
        self.maker_chip_healthy.setText(self._ui_text(f"{healthy} سالم", f"{healthy} healthy"))
        self.maker_chip_failed.setText(self._ui_text(f"{failed} ناموفق", f"{failed} failed"))
        self.maker_chip_ech.setText(f"ECH {ech}")
        self.maker_chip_ech.setToolTip(self.tr("کانفیگ‌های ECH مستقیماً وصل می‌شوند.",
                                             "ECH configs connect directly."))
        self.maker_chip_ech.setVisible(ech > 0)
        self.maker_empty_hint.setText(self.tr(
            "\u0628\u0631\u0627\u06cc \u0634\u0631\u0648\u0639\u060c \u0644\u06cc\u0646\u06a9 \u0644\u06cc\u0633\u062a \u0631\u0627 \u0648\u0627\u0631\u062f \u06a9\u0646\u06cc\u062f \u0648 \u00ab\u062f\u0631\u06cc\u0627\u0641\u062a\u00bb \u0631\u0627 \u0628\u0632\u0646\u06cc\u062f\n\u06cc\u0627 \u06a9\u0627\u0646\u0641\u06cc\u06af\u200c\u0647\u0627 \u0631\u0627 \u0628\u0627\u0644\u0627 \u067e\u06cc\u0633\u062a \u06a9\u0646\u06cc\u062f",
            "Load configs to start\nEnter a list URL and press Load, or paste links above"))
        self.maker_empty_hint.setVisible(not rows)

    def _maker_summary_changed(self, summary):
        self._maker_update_chips()
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
        self.maker_summary_badge.setText(self._ui_text(
            f"{healthy} کانفیگ آمادهٔ ذخیره" if healthy else "کانفیگ‌های سالم پس از بررسی آمادهٔ ذخیره‌اند.",
            f"{healthy} configs ready to save" if healthy else "Check configs to find routes you can save.",
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

    def _maker_open_configs(self):
        self.profile_tabs.setCurrentWidget(self.profile_pages[0])
        self.show_page(1)

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
        self._assistant_maker_test_completed_at = 0.0
        self._assistant_maker_next_action = ""

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
            if item is not None and item.data(Qt.UserRole)
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
            if hasattr(self, "_update_route_card"):
                self._update_route_card(selected)
            else:
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
        if dialog.exec() and (updated := dialog.result_profile()):
            self.storage.profiles[self.storage.profiles.index(profile)] = updated
            self.storage.selected_id = updated.id
            self.storage.save_profiles()
            self.refresh_profiles()
            self._set_activity("تغییرات کانفیگ ذخیره شد.", "Config changes saved.", "success", False)

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
        self.sync_btn.setEnabled(False)
        self._set_activity("در حال بازیابی کانفیگ‌های اصلی…", "Restoring original configs…")
        try:
            count = self.storage.restore_original_suggested_profiles()
            self.bridge.profiles_changed.emit()
            self.bridge.log.emit(f"Original suggested configs restored: {count}")
            self._set_activity(
                f"{count} کانفیگ اصلی UAC Spoof بازیابی شد.",
                f"Restored {count} UAC Spoof original configs.",
                "success", False,
            )
        except Exception as exc:
            self._handle_error(str(exc))
        finally:
            self.sync_btn.setEnabled(True)

    def _begin_connect_attempt(self):
        self._cancel_mode_apply()
        self._connect_cancel.set()
        self._connect_generation += 1
        self._connect_cancel = threading.Event()
        return self._connect_generation, self._connect_cancel

    def _attempt_cancelled(self, generation, cancel):
        return self._closing or cancel.is_set() or generation != self._connect_generation

    def _resume_pending_connection(self):
        if self._closing:
            self._connection_retry_pending = False
            return
        worker = self._connect_thread
        if worker and worker.is_alive():
            QTimer.singleShot(75, self._resume_pending_connection)
            return
        self._connection_retry_pending = False
        self.toggle_connection()

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
    def _attempt_tuning_for_profile(profile, base_tuning, fake_sni, mux_enabled,
                                    route_plan=None):
        tuning = replace(base_tuning, pattern_fake_sni=fake_sni,
                         xray_mux_enabled=mux_enabled)
        if profile.origin == "builtin" and base_tuning.carrier_mode == "mci":
            plan = route_plan or MCI_BUILTIN_ROUTE_PLANS[0]
            primary = str(plan[1])
            tuning = Tuning.enforce_carrier(base_tuning, "mci")
            tuning = replace(
                tuning,
                pattern_fake_sni=MCI_BUILTIN_FAKE_SNI,
                pattern_connect_ip=primary,
                pattern_fallback_ips=MCI_BUILTIN_FALLBACK_EDGES,
                pattern_use_profile_edges=False,
                pattern_fake_repeat=MCI_BUILTIN_FAKE_REPEAT,
                pattern_inject_delay_ms=MCI_BUILTIN_INJECT_DELAY_MS,
            )
        if profile.verified_spoof:
            tuning = replace(
                tuning,
                pattern_connect_ip=profile.address or VERIFIED_SPOOF_EDGE,
                pattern_fallback_ips=profile.fallback_address,
                pattern_use_profile_edges=False,
            )
        if base_tuning.carrier_mode == "irancell":
            tuning = MainWindow._prefer_irancell_profile_edges(profile, tuning)
        return tuning

    @staticmethod
    def _prefer_irancell_profile_edges(profile, tuning):
        """Try the config's own IPv4 before the carrier anycast edges.

        IranCell often cannot open the saved Cloudflare pair. The profile is
        left unchanged; only this attempt's route list is reordered.
        """
        if _is_direct_route(profile):
            return tuning
        ordered = []
        raw = [
            getattr(profile, "address", ""),
            getattr(profile, "fallback_address", ""),
            tuning.pattern_connect_ip,
            *str(tuning.pattern_fallback_ips or "").replace(";", ",").split(","),
        ]
        for value in raw:
            for part in str(value or "").replace(";", ",").split(","):
                try:
                    ip = str(ipaddress.IPv4Address(part.strip()))
                except (ipaddress.AddressValueError, ValueError):
                    continue
                if ip not in ordered:
                    ordered.append(ip)
        if not ordered:
            return tuning
        return replace(
            tuning,
            pattern_connect_ip=ordered[0],
            pattern_fallback_ips=",".join(ordered[1:8]),
            pattern_use_profile_edges=False,
        )

    @staticmethod
    def _mci_builtin_route_plan(profile, carrier, attempt_index=0):
        if profile.origin != "builtin" or carrier != "mci":
            return None
        if profile.verified_spoof and profile.address:
            strategy = str(profile.method or "wrong_seq").strip().lower()
            if strategy not in {"wrong_seq", "full5", "full10", "full20", "tls_sni_records", "sni_boundary", "sni_split", "multi64", "plain"}:
                strategy = "wrong_seq"
            return strategy, profile.address
        index = max(0, int(attempt_index)) % len(MCI_BUILTIN_ROUTE_PLANS)
        return MCI_BUILTIN_ROUTE_PLANS[index]

    def _multi_gene_status_text(self) -> str:
        winner_id = self.storage.gene_last_winner
        if not winner_id:
            return self.tr("هنوز ژن برنده‌ای ثبت نشده.", "No winning gene recorded yet.")
        gene = next((g for g in self.storage.gene_strategies
                     if isinstance(g, dict) and str(g.get("id", "")) == winner_id), None)
        name = gene_display_label(gene, self.language) if gene else winner_id
        entry = self.storage.gene_stats.get(winner_id, {})
        stamp = float(entry.get("last_success_at", 0) or 0) if isinstance(entry, dict) else 0.0
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(stamp)) if stamp else "—"
        return self.tr(f"آخرین ژن برنده: {ltr_isolate(name)} · {ltr_isolate(when)}",
                       f"Last winning gene: {name} · {when}")

    def _apply_gene_strategy(self, carrier, strategy_name, tuning):
        """Overlay selected Gene Lab strategy (including MCI when imported)."""
        gene = self.storage.selected_gene_strategy()
        if not gene:
            return strategy_name, tuning
        return MainWindow._overlay_gene(gene, strategy_name, tuning, log=self.bridge.log.emit)

    @staticmethod
    def _overlay_gene(gene, strategy_name, tuning, log=None):
        """Apply one gene's method + fake SNI + timing (+ its own working edges,
        tried first by the Pattern relay core) to a tuning copy."""
        if not isinstance(gene, dict):
            return strategy_name, tuning
        method = str(gene.get("method", "") or "").strip().lower()
        if method not in {
            "wrong_seq", "plain", "full5", "full10", "full20", "multi64",
            "tls_sni_records", "sni_boundary", "sni_split", "primitive",
        }:
            return strategy_name, tuning
        fake_sni = str(gene.get("fake_sni", "") or "").strip() or tuning.pattern_fake_sni
        gene_edges = gene_edge_ips(gene)
        if gene_edges and log is not None:
            log(f"GENE EDGES: {gene.get('id', '')} using {len(gene_edges)} ips")
        import json as _json
        ops = gene.get("ops") if method == "primitive" else None
        ops_json = _json.dumps(ops) if isinstance(ops, list) and ops else ""
        return method, replace(
            tuning,
            pattern_gene_edges=",".join(gene_edges),
            pattern_gene_ops=ops_json,
            pattern_fake_sni=fake_sni,
            pattern_fake_repeat=max(1, min(5, int(gene.get("fake_repeat", 1) or 1))),
            pattern_inject_delay_ms=max(0, min(20, int(gene.get("inject_delay_ms", tuning.pattern_inject_delay_ms) or 0))),
            sni_split_delay_ms=max(0, min(80, int(gene.get("fragment_delay_ms", tuning.sni_split_delay_ms) or 0))),
            multi_fragment_size=max(1, min(128, int(gene.get("chunk_size", tuning.multi_fragment_size) or 5))),
            multi_delay_ms=max(0, min(80, int(gene.get("fragment_delay_ms", tuning.multi_delay_ms) or 0))),
        )

    @staticmethod
    def _profile_connection_strategy(profile, carrier, default_strategy,
                                     builtin_route=None, route_plan=None):
        route = builtin_route if isinstance(builtin_route, dict) else {}
        if profile.origin == "builtin" and carrier == "mci":
            return str((route_plan or MCI_BUILTIN_ROUTE_PLANS[0])[0])
        cached = str(route.get("strategy", "") or "").strip().lower()
        if cached in {"plain", "wrong_seq", "tls_sni_records", "full5", "full10", "full20", "sni_boundary", "sni_split", "multi64", "primitive"}:
            return cached
        profile_strategy = {
            "full5": "full5",
            "tls_sni_records": "tls_sni_records",
        }.get(str(profile.method or "").strip().lower(), "")
        if profile.origin == USER_CONFIG_ORIGIN and profile_strategy:
            return profile_strategy
        return default_strategy

    @staticmethod
    def _adaptive_strategies(carrier, first, cached=""):
        """Order route strategies for any computer: last winner, then carrier defaults."""
        if carrier == "mci":
            return [first]
        order = []

        def add(name):
            name = str(name or "").strip().lower()
            if name in {"full5", "wrong_seq", "tls_sni_records", "full20", "full10", "plain", "sni_boundary", "sni_split", "multi64", "primitive"} and name not in order:
                order.append(name)

        add(cached)
        add(first)
        defaults = {
            "irancell": ("full5", "wrong_seq", "tls_sni_records"),
            "auto": ("wrong_seq", "full5", "tls_sni_records"),
        }.get(carrier, ("wrong_seq", "full5", "tls_sni_records"))
        for name in defaults:
            add(name)
        return order[:3]

    @staticmethod
    def _plan_profile_attempts(profile_snis, pool, attempts_used, multi_gene,
                               locked, reality_direct=False):
        """Return ([(fake_sni, gene_or_None), ...], attempts_used).

        Off / no pool / Reality: the original SNI list, unchanged.
        On: up to 3 distinct pool genes (overall cap 9), each with its own SNI;
        without Strategy lock one built-in attempt follows the genes.
        """
        snis = list(profile_snis or [])
        if not multi_gene or not pool or reality_direct:
            return [(value, None) for value in snis], attempts_used
        genes = [g for g in gene_pool.plan_profile_genes(pool, attempts_used)
                 if str(g.get("fake_sni", "") or "").strip()]
        attempts = [(str(g["fake_sni"]).strip().lower(), g) for g in genes]
        if not locked:
            attempts += [(value, None) for value in snis[:1]]
        return attempts, attempts_used + len(genes)

    @staticmethod
    def _fallback_strategies(carrier, first, cached="", locked=False):
        """Strategy lock: only the current method; otherwise adaptive rotation."""
        if locked:
            return [str(first or "").strip().lower()]
        return MainWindow._adaptive_strategies(carrier, first, cached)

    @staticmethod
    def _initial_connection_strategy(carrier, country_code=""):
        if country_code:
            return "wrong_seq"
        if carrier == "mci":
            return "tls_sni_records"
        if carrier == "irancell":
            return "full5"
        return "wrong_seq"

    def _profile_mux_enabled(self, profile, tuning, carrier=None) -> bool:
        """Use a fresh route-specific compatibility result without changing Advanced."""
        if not tuning.xray_mux_enabled:
            return False
        carrier = carrier or tuning.carrier_mode
        builtin_route = MainWindow._builtin_route_entry(self, profile, carrier)
        if builtin_route and builtin_route.get("mux_enabled") is False:
            return False
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
        engine = getattr(self, "engine", None)
        live_edge = str(getattr(engine, "active_upstream_address", "") or "").strip()
        if not live_edge:
            fragment = getattr(engine, "fragment", None)
            live_edge = str(getattr(fragment, "active_edge", "") or "").strip()
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
        if _is_direct_route(profile):
            reality_sni = str(profile.sni or "").strip().lower()
            return [reality_sni] if reality_sni else []
        builtin = profile.origin == "builtin"
        if builtin and carrier == "mci":
            original_sni = str(profile.sni or "").strip().lower()
            return [original_sni] * len(MCI_BUILTIN_ROUTE_PLANS) if original_sni else []
        candidate_limit = max(limit, 4) if builtin else limit
        candidates = self._sni_candidates(profile, carrier, candidate_limit)
        if builtin:
            preferred = []
            cached = MainWindow._builtin_route_entry(
                self, profile, carrier
            ).get("fake_sni", "")
            hints = BUILTIN_PROFILE_SNI_HINTS.get(
                str(profile.sni or "").strip().lower(), ()
            )
            values = ((MCI_BUILTIN_FAKE_SNI, "support.cloudflare.com",
                       "www.speedtest.net", cached, *hints)
                      if carrier == "mci" else (cached, *hints))
            for value in values:
                value = str(value or "").strip().lower()
                if value and value not in preferred:
                    preferred.append(value)
            candidates = [
                *preferred,
                *(value for value in candidates if value not in preferred),
            ]
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
        return candidates[:max(1, candidate_limit)]

    def _builtin_route_entry(self, profile, carrier=None):
        if profile is None or profile.origin != "builtin":
            return {}
        carrier = carrier or self.storage.tuning.carrier_mode
        scoped = self.storage.settings.get("builtin_profile_routes_by_carrier", {})
        bucket = scoped.get(carrier, {}) if isinstance(scoped, dict) else {}
        entry = bucket.get(profile.id, {}) if isinstance(bucket, dict) else {}
        if not isinstance(entry, dict):
            return {}
        signature = profile.source_uri or f"{profile.protocol}:{profile.config_host}:{profile.config_port}"
        if entry.get("signature") != signature:
            return {}
        if time.time() - float(entry.get("tested_at", 0) or 0) > BUILTIN_ROUTE_CACHE_TTL_S:
            return {}
        return entry

    def _remember_builtin_route(self, profile, carrier, fake_sni, strategy,
                                tuning, mux_enabled):
        if profile.origin != "builtin":
            return
        scoped = self.storage.settings.get("builtin_profile_routes_by_carrier", {})
        scoped = dict(scoped) if isinstance(scoped, dict) else {}
        bucket = scoped.get(carrier, {})
        bucket = dict(bucket) if isinstance(bucket, dict) else {}
        engine = getattr(self, "engine", None)
        active_edge = str(getattr(engine, "active_upstream_address", "") or "").strip()
        if not active_edge:
            fragment = getattr(engine, "fragment", None)
            active_edge = str(getattr(fragment, "active_edge", "") or "").strip()
        bucket[profile.id] = {
            "fake_sni": str(fake_sni or "").strip().lower(),
            "strategy": strategy if strategy in {
                "plain", "wrong_seq", "tls_sni_records", "full5", "full10", "full20",
                "sni_boundary", "sni_split", "multi64",
            } else "wrong_seq",
            "edge": active_edge or tuning.pattern_connect_ip,
            "fallback_ips": tuning.pattern_fallback_ips,
            "mux_enabled": bool(mux_enabled),
            "signature": profile.source_uri or f"{profile.protocol}:{profile.config_host}:{profile.config_port}",
            "tested_at": time.time(),
        }
        scoped[carrier] = bucket
        self.storage.settings["builtin_profile_routes_by_carrier"] = scoped

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
        tuning = self.storage.tuning
        if (
                auto_enabled
                and forced_profile is None
                and tuning.carrier_mode == "mci"
                and self._selected_route_source() == "suggested"):
            candidates = [
                profile for profile in candidates
                if MainWindow._mci_builtin_auto_eligible(profile)
            ]
            initial_positions = {
                profile.id: index for index, profile in enumerate(candidates)
            }
            candidates.sort(
                key=lambda profile: (
                    MainWindow._mci_builtin_auto_rank(profile),
                    initial_positions.get(profile.id, 999999),
                )
            )
        if cancel_event.is_set():
            raise EngineCancelled("Connection attempt cancelled")
        ping_host = (candidates[0].address if country_code and candidates else "")\
            or tuning.pattern_connect_ip or "104.18.32.47"


        ok, latency = profile_ping(ping_host, 443, fake_sni, 3.5)
        self.bridge.log.emit(f"PATTERN EDGE PING 1/1 {ping_host}:443 sni={fake_sni} => {'OK' if ok else 'FAIL'}")
        if ok and latency > 0:
            latency_signal = getattr(self.bridge, "latency", None)
            if latency_signal is not None:
                latency_signal.emit(latency, "edge")
        for profile in candidates:
            if profile.origin != USER_CONFIG_ORIGIN:
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
        candidate_positions = {profile.id: index for index, profile in enumerate(candidates)}
        def quality(profile):
            result = benchmarks.get(profile.id, {})
            fresh = now - float(result.get("tested_at", 0)) < 24 * 3600
            page_ok = (bool(result.get("ok")) and result.get("engine") == "patterniha-wrong-seq-v1" and fresh)
            if carrier == "mci":
                download_fresh = now - float(result.get("download_tested_at", 0) or 0) < 6 * 3600
                download_verified = (
                    result.get("download_ok") is True
                    and download_fresh
                    and (
                        profile.origin != "builtin"
                        or (
                            result.get("url") == MCI_BUILTIN_WEB_GATE
                            and int(result.get("download_bytes", 0) or 0)
                            >= MCI_BUILTIN_WEB_GATE_MIN_BYTES
                        )
                    )
                )
                download_mbps = float(result.get("download_mbps", 0) or 0)
                benchmark_known = bool(result) and result.get("engine") == "patterniha-wrong-seq-v1"
                download_failed = (result.get("download_ok") is False
                                   or result.get("download_state") == "failed")
                if profile.origin == "builtin" and not download_verified:
                    page_ok = False



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
                original_order = (candidate_positions.get(profile.id, 999999)
                                  if profile.origin == "builtin" and not download_verified else 0)
                return (tier, original_order,
                        -float(result.get("score", 0)) if page_ok else 0,
                        float(result.get("download_first_byte_ms", 999999) or 999999),
                        -download_mbps, profile.id != remembered_id,
                        not profile.last_ping_ok,
                        profile.last_ping_ms if profile.last_ping_ok else 999999)
            upload_rank = 0 if result.get("upload_ok") is True else 1 if result.get("upload_ok") is None else 2
            return (not page_ok, upload_rank if page_ok else 3,
                    -float(result.get("score", 0)) if page_ok else 0, profile.id != remembered_id,
                    not profile.last_ping_ok, profile.last_ping_ms if profile.last_ping_ok else 999999)
        ordered = sorted(candidates, key=quality)
        if (auto_enabled and forced_profile is None and ordered
                and (country_code or self._selected_route_source() == "user-config")):
            try:
                ordered = MainWindow._auto_latency_order(self, ordered, cancel_event)
            except EngineCancelled:
                raise
            except Exception as exc:
                self.bridge.log.emit(f"AUTO PICK: latency ranking unavailable ({exc}); using previous order")
        return ordered

    def _auto_latency_order(self, candidates, cancel_event, probe_top=6, fresh_seconds=AUTO_LATENCY_FRESH_SECONDS):
        """Fastest first. Fresh measured latency (stored in settings
        'auto_latency', never on the profile) -> quick real probe of the top N
        when stale -> nearer region as tie-breaker."""
        store = self.storage.settings.get(AUTO_LATENCY_KEY, {})
        store = dict(store) if isinstance(store, dict) else {}
        now = time.time()
        if not bool(getattr(getattr(self, "engine", None), "running", False)):
            try:
                return MainWindow._auto_quality_order(self, candidates, cancel_event, store, now)
            except EngineCancelled:
                raise
            except Exception as exc:
                self.bridge.log.emit(f"AUTO PICK: quality probe unavailable ({exc}); using latency order")
        ids = {p.id for p in candidates}
        fresh = {pid: v for pid, v in store.items()
                 if pid in ids and isinstance(v, dict) and now - float(v.get("at", 0) or 0) < fresh_seconds}
        fresh_ok = sum(1 for v in fresh.values() if v.get("ok"))
        engine = getattr(self, "engine", None)
        can_probe = not bool(getattr(engine, "running", False))
        if fresh_ok < 3 and can_probe:
            pool = auto_latency_rank(candidates, {})[:probe_top]
            pool = [p for p in pool if p.id not in fresh][:probe_top]
            if pool:
                self.bridge.log.emit(f"AUTO PICK: quick latency probe of {len(pool)} configs (real request, 4s)")
                started = time.monotonic()
                results = MainWindow._auto_probe(self, pool, cancel_event)
                if cancel_event.is_set():
                    raise EngineCancelled("Connection attempt cancelled")
                for pid, (ok, ms) in results.items():
                    store[pid] = {"ok": bool(ok), "ms": float(ms or 0), "at": now}
                    fresh[pid] = store[pid]
                live = {pid for pid in ids}
                store = {pid: v for pid, v in store.items() if pid in live or now - float(v.get("at", 0) or 0) < 7 * 86400}
                self.storage.settings[AUTO_LATENCY_KEY] = store
                try:
                    self.storage.save_settings()
                except Exception:
                    pass
                good = sum(1 for ok, _ms in results.values() if ok)
                self.bridge.log.emit(f"AUTO PICK: probe done {good}/{len(pool)} ok in {time.monotonic() - started:.1f}s")
        ranked = auto_latency_rank(candidates, fresh)
        for index, profile in enumerate(ranked[:3], 1):
            value = fresh.get(profile.id)
            ms = (f"{value['ms']:.0f} ms" if value and value.get("ok") else
                  "fail" if value else (f"~{profile.last_ping_ms:.0f} ms (last test)" if profile.last_ping_ok else "untested"))
            code = profile.observed_country_code or profile.country_code or "XX"
            self.bridge.log.emit(f"AUTO PICK #{index}: {profile.name} [{code}] {ms}")
        best = fresh.get(ranked[0].id) if ranked else None
        if best and best.get("ok") and best.get("ms"):
            latency_signal = getattr(self.bridge, "latency", None)
            if latency_signal is not None:
                latency_signal.emit(float(best["ms"]), "edge")
        return ranked

    def _auto_quality_order(self, candidates, cancel_event, store, now):
        """Probe the top N in parallel (copies): 3x204 + 2 pages; EWMA history per config."""
        base = auto_latency_rank(candidates, {})
        def hist(p):
            v = store.get(p.id)
            return v.get("qs") if isinstance(v, dict) and v.get("qs") is not None else None
        with_hist = sorted([p for p in base if hist(p) is not None], key=hist)
        pool_order = with_hist + [p for p in base if hist(p) is None]
        pool = pool_order[:AUTO_QUALITY_POOL]
        if not pool:
            return list(candidates)
        self.bridge.log.emit(f"AUTO PICK: quality probe of {len(pool)} configs (3x generate_204 + 2 pages, parallel)")
        started = time.monotonic()
        results = MainWindow._auto_quality_probe(self, pool, cancel_event)
        if cancel_event.is_set():
            raise EngineCancelled("Connection attempt cancelled")
        scored, failed, breakdown = [], [], {}
        for p in pool:
            res = results.get(p.id) or {}
            prev = hist(p)
            if res.get("ok"):
                score, br = auto_quality_score(res.get("quality") or {"s204": [res.get("ms")], "pages": []})
                qs = score if prev is None else round(0.5 * float(prev) + 0.5 * score, 1)
                store[p.id] = {"ok": True, "ms": float(br["med204"]), "qs": qs, "last": score, "at": now}
                breakdown[p.id] = (score, qs, br)
                scored.append(p)
            else:
                qs = 20000.0 if prev is None else round(0.5 * float(prev) + 10000.0, 1)
                store[p.id] = {"ok": False, "ms": 0.0, "qs": qs, "at": now}
                failed.append(p)
        scored.sort(key=lambda p: breakdown[p.id][0] * 0.6 + breakdown[p.id][1] * 0.4)
        ids = {p.id for p in candidates}
        store = {pid: v for pid, v in store.items() if pid in ids or now - float(v.get("at", 0) or 0) < 7 * 86400}
        self.storage.settings[AUTO_LATENCY_KEY] = store
        try:
            self.storage.save_settings()
        except Exception:
            pass
        self.bridge.log.emit(f"AUTO PICK: quality probe done {len(scored)}/{len(pool)} ok in {time.monotonic() - started:.1f}s")
        rest = [p for p in pool_order if p not in pool]
        ranked = scored + rest + failed
        for index, profile in enumerate(scored[:3], 1):
            score, qs, br = breakdown[profile.id]
            code = profile.observed_country_code or profile.country_code or "XX"
            self.bridge.log.emit(
                f"AUTO PICK #{index}: {profile.name} [{code}] score={score:.0f} "
                f"(204 med {br['med204']} ms ok {br['ok204']}, page {br['page']} ms ok {br['okpage']}, ewma {qs:.0f})")
        if scored:
            latency_signal = getattr(self.bridge, "latency", None)
            if latency_signal is not None:
                latency_signal.emit(float(breakdown[scored[0].id][2]["med204"]), "edge")
        return ranked

    def _auto_quality_probe(self, profiles, cancel_event):
        """{profile_id: {'ok', 'ms', 'quality'}} via real requests through copies."""
        probe = getattr(self, "_auto_quality_fn", None)
        if callable(probe):
            return probe(profiles, cancel_event)
        copies = [replace(p) for p in profiles]
        for c in copies:
            c._quality_probe = True
        tester = SniBatchTester(lambda _m: None)
        results = tester.run_all_modes(
            copies, self.storage.tuning, cancel_event, workers=len(copies), timeout=3.0,
            carrier_tunings=self.storage.all_carrier_tunings(),
            preferred_carrier=str(self.storage.tuning.carrier_mode or ""))
        by_copy = {id(c): p.id for c, p in zip(copies, profiles)}
        out = {p.id: {"ok": False} for p in profiles}
        for result in results:
            pid = by_copy.get(id(result.profile))
            if pid:
                out[pid] = {"ok": bool(result.ok), "ms": float(result.ping_ms or 0),
                            "quality": getattr(result, "quality", None)}
        return out

    def _auto_probe(self, profiles, cancel_event):
        """{profile_id: (ok, ms)} via a real request through each config (copies only)."""
        probe = getattr(self, "_auto_probe_fn", None)
        if callable(probe):
            return probe(profiles, cancel_event)
        copies = [replace(p) for p in profiles]
        tester = SniBatchTester(lambda _m: None)
        results = tester.run_all_modes(
            copies, self.storage.tuning, cancel_event, workers=len(copies), timeout=4.0,
            carrier_tunings=self.storage.all_carrier_tunings(),
            preferred_carrier=str(self.storage.tuning.carrier_mode or ""))
        by_copy = {id(c): p.id for c, p in zip(copies, profiles)}
        out = {p.id: (False, 0.0) for p in profiles}
        for result in results:
            pid = by_copy.get(id(result.profile))
            if pid:
                out[pid] = (bool(result.ok), float(result.ping_ms or 0))
        return out

    @staticmethod
    def _mci_builtin_auto_eligible(profile):
        if profile.origin != "builtin":
            return True
        try:
            path = str(parse_outbound(profile).get("path", "") or "").lower()
        except (TypeError, ValueError):
            return True
        return not (
            path == "//assignment"
            or path.startswith("/assignment?telegram--kanal--")
        )

    @staticmethod
    def _mci_builtin_auto_rank(profile):
        if profile.origin != "builtin":
            return 1
        source = str(profile.source_uri or "").lower()
        return 0 if "?path=assignment&" in source else 1

    def _save_profile_benchmark(self, profile, strategy, page_ok, upload_state=None,
                                fake_sni="", count_page_sample=True, carrier=None,
                                download_state=None):
        carrier = carrier or self.storage.tuning.carrier_mode
        key = f"profile_benchmarks_pattern_{carrier}"
        values = self.storage.settings.get(key, {})
        if not isinstance(values, dict): values = {}
        previous = values.get(profile.id, {}) if isinstance(values.get(profile.id, {}), dict) else {}
        measured_download_state = (download_state
                                   or getattr(self.engine, "last_download_state", "not_tested")
                                   or "not_tested")
        hard_mci_payload_failure = (
            carrier == "mci"
            and profile.origin == "builtin"
            and measured_download_state == "failed"
        )
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
            keep_previous = (bool(previous.get("ok")) and page_failures < 2
                             and not hard_mci_payload_failure)
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
            if download_failures >= 2 or hard_mci_payload_failure:
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
        if (hard_mci_payload_failure
                and self.storage.settings.get(f"working_profile_{carrier}") == profile.id):
            self.storage.settings.pop(f"working_profile_{carrier}", None)
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

    def _verify_mci_builtin_payload(self, profile, carrier, cancel):
        if carrier != "mci" or profile.origin != "builtin":
            return True, "not required"
        result, detail = self.engine.probe_web_access(
            timeout=18.0, connect_timeout=12.0, patient=True, cancel_event=cancel
        )
        verified = (
            result is True
            and getattr(self.engine, "last_download_state", "") == "verified"
            and int(getattr(self.engine, "last_download_bytes", 0) or 0)
            >= MCI_BUILTIN_WEB_GATE_MIN_BYTES
        )
        return verified, detail

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

    def nativeEvent(self, event_type, message):
        if sys.platform == "win32":
            from ctypes.wintypes import MSG

            event = MSG.from_address(int(message))
            if event.message == 0x0218 and event.wParam == 0x0012:  # PBT_APMRESUMEAUTOMATIC
                controller = getattr(self, "pow_controller", None)
                if controller is not None and controller.running:
                    controller.coordinator.notify_resume()
                direct = getattr(self, "direct_controller", None)
                if direct is not None and direct.busy:
                    direct.coordinator.notify_resume()
        return super().nativeEvent(event_type, message)

    def toggle_connection(self, *, automatic=False):
        auto_connect = getattr(self, "_auto_connect", None)
        if not automatic and auto_connect is not None and self._engine_busy():
            self._bypass_apply_timer.stop()
            auto_connect.user_stopped()
        direct = getattr(self, "direct_controller", None)
        if direct is not None and (direct.busy or self.engine_mode == ENGINE_DIRECT):
            if direct.busy or not self._engine_busy():
                direct.toggle()
            return
        try:
            pow_controller = getattr(self, "pow_controller", None)
            pow_busy = bool(pow_controller is not None and pow_controller.busy)
        except Exception:
            pow_controller = None
            pow_busy = False
        if pow_busy or getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_POW:
            pow_controller.toggle()
            return
        if getattr(self, "_maker_running", False) and not self.engine.running and not self.connecting:
            self.show_toast(self.tr(
                "ابتدا تست زنده سازنده SNI را متوقف کنید",
                "Stop the SNI Maker live test before connecting",
            ), "warning")
            return
        worker = getattr(self, "_connect_thread", None)
        if (not self.connecting and worker is not None
                and worker.is_alive()):
            if not getattr(self, "_connection_retry_pending", False):
                self._connection_retry_pending = True
                self._cancel_connect_attempt(notify=False)
                QTimer.singleShot(75, self._resume_pending_connection)
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
        try:
            self._apply_xray_port_setting()
            port_problem = self.engine.check_configured_ports()
        except Exception as exc:
            port_problem = str(exc)
        if port_problem:
            message = self.tr(
                f"پورت پروکسی انتخاب‌شده آزاد نیست: {port_problem}. در همین صفحه پورت دیگری بگذارید.",
                f"The chosen proxy port is not free: {port_problem}. Pick another port on this page.",
            )
            self.connection_error = message; self._set_connection_visual("error"); self._handle_error(message)
            return
        preferences = self.global_settings.snapshot()
        self._xray_session_mode = preferences.connection_mode
        self.engine.connection_preferences = preferences
        generation, cancel = self._begin_connect_attempt()
        base_tuning = replace(self.storage.tuning, iran_direct=preferences.iran_direct)
        carrier = base_tuning.carrier_mode
        bypass = list(self.global_settings.processes()) if preferences.routing_mode == "bypass" else []
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
                if _is_direct_route(profile)
                else profile.spoof_fake_sni
                for profile in country_profiles
                if (
                    profile.sni
                    if _is_direct_route(profile)
                    else profile.spoof_fake_sni
                )
            ), VERIFIED_SPOOF_FAKE_SNI)]
        if not seed_snis:
            direct_seed = next((
                profile.sni
                for profile in self._route_source_profiles(verified_only=True)
                if _is_direct_route(profile) and profile.sni
            ), "")
            if direct_seed:
                seed_snis = [direct_seed]
        if not seed_snis:
            message = self.tr("هیچ SNI معتبر در مخزن اسکن پیدا نشد", "No valid SNI was found in the scan repository")
            self.connection_error = message; self._set_connection_visual("error"); self._handle_error(message)
            return
        self.connecting = True; self.connection_error = ""; self._set_connection_visual("connecting")
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
            strategy_locked = bool(getattr(self.storage, "strategy_locked", False))
            locked_strategy = ""
            if strategy_locked:
                self.bridge.log.emit("STRATEGY LOCK: on (no automatic method switching)")
            try:
                self.bridge.activity.emit(self.tr(f"در حال آزمایش دسترسی {ltr_isolate('SNI')}…", "Testing SNI reachability…"), "running", True)
                profiles = self._ordered_profiles(
                    seed_snis[0], cancel, auto_enabled, manual_only, forced_profile
                )
                if self._attempt_cancelled(generation, cancel):
                    raise EngineCancelled("Connection attempt cancelled")
                clean_csv, clean_sources = "", {}
                if getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_XRAY:
                    clean_csv, clean_sources = self._find_clean_edges(carrier, base_tuning, cancel)
                    if self._attempt_cancelled(generation, cancel):
                        raise EngineCancelled("Connection attempt cancelled")
                if not profiles:
                    raise ValueError(self.tr("کانفیگی موجود نیست", "No config available"))
                multi_gene = (bool(getattr(self.storage, "multi_gene_enabled", False))
                              and str(carrier or "").lower() in {"auto", "irancell"})
                gene_pool_list = []
                gene_attempts_used = 0
                if multi_gene:
                    pool_now = time.time()
                    for cooled_id in gene_pool.cooled_down(
                            self.storage.gene_strategies, self.storage.gene_stats, pool_now):
                        self.bridge.log.emit(f"MULTI-GENE: cooldown skip {cooled_id}")
                    gene_pool_list = gene_pool.ordered_pool(
                        self.storage.gene_strategies, self.storage.gene_stats,
                        pool_now, self.storage.gene_last_winner,
                    )
                    if gene_pool_list:
                        self.bridge.log.emit(
                            "MULTI-GENE: pool=" + ",".join(str(g["id"]) for g in gene_pool_list)
                            + f" lock={'on' if strategy_locked else 'off'}"
                        )
                    else:
                        multi_gene = False
                        self.bridge.log.emit("MULTI-GENE: no eligible confirmed genes; normal connect")
                for index, profile in enumerate(profiles, 1):
                    profile_snis = self._profile_sni_candidates(profile, carrier, limit=3)
                    profile_passed = False
                    profile_download_state = "not_tested"
                    profile_mux_enabled = self._profile_mux_enabled(profile, base_tuning, carrier)
                    builtin_route = MainWindow._builtin_route_entry(self, profile, carrier)
                    profile_attempts, gene_attempts_used = MainWindow._plan_profile_attempts(
                        profile_snis, gene_pool_list, gene_attempts_used, multi_gene,
                        strategy_locked, _is_direct_route(profile),
                    )
                    if (multi_gene and not _is_direct_route(profile)
                            and not any(g is not None for _sni, g in profile_attempts)):
                        self.bridge.log.emit("MULTI-GENE: gene attempt cap reached")
                    for sni_index, (fake_sni, attempt_gene) in enumerate(profile_attempts, 1):
                        download_state = "not_tested"
                        download_detail = ""
                        if self._attempt_cancelled(generation, cancel):
                            raise EngineCancelled("Connection attempt cancelled")
                        self.bridge.log.emit(f"CONFIG TRY {index}/{len(profiles)} {profile.name} SNI {sni_index}/{len(profile_attempts)}={fake_sni}")
                        route_plan = self._mci_builtin_route_plan(
                            profile, carrier, sni_index - 1
                        )
                        attempt_strategy = self._profile_connection_strategy(
                            profile, carrier, strategy, builtin_route, route_plan
                        )
                        attempt_tuning = self._attempt_tuning_for_profile(
                            profile, base_tuning, fake_sni, profile_mux_enabled,
                            route_plan,
                        )
                        if attempt_gene is not None:
                            attempt_strategy, attempt_tuning = MainWindow._overlay_gene(
                                attempt_gene, attempt_strategy, attempt_tuning,
                                log=self.bridge.log.emit,
                            )
                            self.bridge.log.emit(
                                f"MULTI-GENE: try {_cs_gene_label(attempt_gene)} "
                                f"method={attempt_strategy} fakeSni={fake_sni}"
                            )
                        elif not multi_gene:
                            attempt_strategy, attempt_tuning = self._apply_gene_strategy(
                                carrier, attempt_strategy, attempt_tuning
                            )
                        elif not _is_direct_route(profile):
                            self.bridge.log.emit(
                                f"MULTI-GENE: genes exhausted for {profile.name}; built-in fallback"
                            )
                        if strategy_locked and attempt_gene is None:
                            if not locked_strategy:
                                locked_strategy = attempt_strategy
                                self.bridge.log.emit(f"STRATEGY LOCK: pinned method={locked_strategy}")
                            elif attempt_strategy != locked_strategy:
                                self.bridge.log.emit(
                                    f"STRATEGY LOCK: keep {locked_strategy} (skip {attempt_strategy})"
                                )
                                attempt_strategy = locked_strategy
                        if (
                                builtin_route.get("edge")
                                and not (
                                    profile.origin == "builtin"
                                    and carrier == "mci"
                                )):
                            attempt_tuning = replace(
                                attempt_tuning,
                                pattern_connect_ip=str(builtin_route["edge"]),
                                pattern_fallback_ips=str(
                                    builtin_route.get("fallback_ips", "") or ""
                                ),
                                pattern_use_profile_edges=False,
                            )
                        if (
                                not profile.verified_spoof
                                and not (
                                    profile.origin == "builtin"
                                    and carrier == "mci"
                                )):
                            measured_route = self._verified_route_result(fake_sni, carrier)
                            if measured_route:
                                attempt_tuning = self._bind_verified_sni_route(attempt_tuning, measured_route)
                        if carrier == "irancell":
                            attempt_tuning = self._prefer_irancell_profile_edges(
                                profile, attempt_tuning
                            )
                        if clean_csv and not _is_direct_route(profile):
                            attempt_tuning = replace(attempt_tuning, pattern_clean_edges=clean_csv)
                        session_ip = _clean_ip.valid_ipv4(getattr(self, "_clean_ip_session", ""))
                        if session_ip and not _is_direct_route(profile):
                            # Applied last so built-in routes, verified binds, Irancell
                            # profile edges and gene edges cannot push it back.
                            old_fallbacks = [attempt_tuning.pattern_connect_ip,
                                             *str(attempt_tuning.pattern_fallback_ips or "").split(",")]
                            attempt_tuning = replace(
                                attempt_tuning,
                                pattern_session_edge=session_ip,
                                pattern_connect_ip=session_ip,
                                pattern_fallback_ips=",".join(
                                    e for e in dict.fromkeys(x.strip() for x in old_fallbacks)
                                    if e and e != session_ip),
                            )
                            self.bridge.log.emit(f"CLEAN IP: using session preferred {session_ip}")
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
                            mci_builtin = profile.origin == "builtin" and carrier == "mci"
                            if mci_builtin:
                                page_ok, detail = True, "payload check pending"
                            else:
                                page_ok, detail = self.engine.probe(
                                    timeout=6, preferred_url=preferred_url,
                                    require_preferred=(carrier in preferred_urls),
                                    cancel_event=cancel,
                                )
                            if (not page_ok and carrier == "mci" and strategy_locked
                                    and attempt_strategy == "tls_sni_records"):
                                self.bridge.log.emit(
                                    f"STRATEGY LOCK: skip MCI TLS fallback {profile.name}"
                                )
                            if (not page_ok and carrier == "mci" and not strategy_locked
                                    and attempt_strategy == "tls_sni_records"):



                                self.bridge.log.emit(
                                    f"MCI TLS FALLBACK {profile.name} fakeSni={fake_sni}"
                                )
                                if self._attempt_cancelled(generation, cancel):
                                    raise EngineCancelled("Connection attempt cancelled")
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
                                if self._attempt_cancelled(generation, cancel):
                                    raise EngineCancelled("Connection attempt cancelled")
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
                            if (not page_ok and carrier != "mci"
                                    and not _is_direct_route(profile)
                                    and attempt_gene is None):
                                cached_strategy = ""
                                if isinstance(builtin_route, dict):
                                    cached_strategy = str(builtin_route.get("strategy", "") or "")
                                if strategy_locked:
                                    self.bridge.log.emit(
                                        f"STRATEGY LOCK: skip adaptive {profile.name} "
                                        f"method={attempt_strategy} fakeSni={fake_sni}"
                                    )
                                for alternate_strategy in self._fallback_strategies(
                                        carrier, attempt_strategy, cached_strategy,
                                        strategy_locked):
                                    if alternate_strategy == attempt_strategy or page_ok:
                                        continue
                                    self.bridge.log.emit(
                                        f"ADAPTIVE ROUTE {profile.name} "
                                        f"{attempt_strategy}->{alternate_strategy} "
                                        f"fakeSni={fake_sni}"
                                    )
                                    if self._attempt_cancelled(generation, cancel):
                                        raise EngineCancelled("Connection attempt cancelled")
                                    self.engine.stop(notify=False)
                                    fallback_tuning = replace(
                                        attempt_tuning, xray_mux_enabled=False
                                    )
                                    self.engine.start(
                                        profile, fallback_tuning, bypass, notify=False,
                                        enable_system_proxy=False,
                                        strategy_override=alternate_strategy,
                                        cancel_event=cancel,
                                    )
                                    page_ok, detail = self.engine.probe(
                                        timeout=8, preferred_url=preferred_url,
                                        require_preferred=(carrier in preferred_urls),
                                        cancel_event=cancel,
                                    )
                                    if page_ok:
                                        attempt_strategy = alternate_strategy
                                        attempt_tuning = fallback_tuning
                                        profile_mux_enabled = False
                                        self._remember_profile_mux(
                                            profile, False, fallback_tuning, carrier
                                        )
                                        break
                            if self._attempt_cancelled(generation, cancel):
                                raise EngineCancelled("Connection attempt cancelled")
                            if profile.origin == "builtin" and carrier == "mci":
                                payload_ok, payload_detail = self._verify_mci_builtin_payload(
                                    profile, carrier, cancel
                                )
                                download_detail = payload_detail
                                download_state = "verified" if payload_ok else "failed"
                                profile_download_state = download_state
                                page_ok = payload_ok
                                if payload_ok:
                                    detail = payload_detail
                                    payload_latency = float(
                                        getattr(self.engine, "last_download_first_byte_ms", 0)
                                        or getattr(self.engine, "last_download_ms", 0)
                                        or 0
                                    )
                                    if payload_latency > 0:
                                        self.engine.last_probe_ms = payload_latency
                                    self.engine.last_probe_url = MCI_BUILTIN_WEB_GATE
                                else:
                                    detail = f"payload check failed: {payload_detail}"
                                    engine = getattr(self, "engine", None)
                                    actual_edge = str(
                                        getattr(engine, "active_upstream_address", "")
                                        or attempt_tuning.pattern_connect_ip
                                    ).strip()
                                    self.bridge.log.emit(
                                        f"MCI BUILTIN PAYLOAD REJECT {profile.name} "
                                        f"edge={actual_edge} "
                                        f"strategy={attempt_strategy}: {payload_detail}"
                                    )
                            if page_ok and profile.route_is_verified:
                                self.bridge.activity.emit(self.tr(
                                    "در حال بررسی کشور واقعی آی‌پی خروجی…",
                                    "Verifying the real exit-IP country…",
                                ), "running", True)
                                location = current_location(proxy=True, timeout=5.0, http_port=self.engine.probe_http_port)
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
                                with self._proxy_mode_apply_lock:
                                    connection_mode = self._apply_connection_mode_after_probe(cancel)
                                if self._attempt_cancelled(generation, cancel):
                                    raise EngineCancelled("Connection attempt cancelled")
                                self.storage.settings[f"working_profile_{carrier}"] = profile.id
                                if profile.origin != "builtin":
                                    self.storage.settings[f"working_strategy_{carrier}"] = attempt_strategy
                                    self.storage.settings[f"working_pattern_sni_{carrier}"] = fake_sni
                                    self.storage.settings[f"working_pattern_sni_at_{carrier}"] = time.time()
                                self.storage.settings["selected_id"] = profile.id



                                working_tuning = replace(base_tuning, pattern_fake_sni=fake_sni)
                                if profile.verified_spoof:
                                    working_tuning.pattern_connect_ip = profile.address or VERIFIED_SPOOF_EDGE
                                    working_tuning.pattern_fallback_ips = profile.fallback_address
                                    working_tuning.pattern_use_profile_edges = False
                                engine = getattr(self, "engine", None)
                                active_edge = str(getattr(engine, "active_upstream_address", "") or "").strip()
                                if not active_edge:
                                    fragment = getattr(engine, "fragment", None)
                                    active_edge = str(getattr(fragment, "active_edge", "") or "").strip()
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
                                if profile.origin != "builtin":
                                    self.storage.settings[f"working_pattern_edge_{carrier}"] = active_edge or working_tuning.pattern_connect_ip
                                    self.storage.settings[f"working_pattern_route_{carrier}"] = {
                                        "edge": active_edge or working_tuning.pattern_connect_ip,
                                        "fake_sni": fake_sni,
                                        "tested_at": time.time(),
                                    }
                                MainWindow._remember_builtin_route(
                                    self, profile, carrier, fake_sni,
                                    attempt_strategy, attempt_tuning,
                                    profile_mux_enabled,
                                )
                                if profile.origin == "builtin":
                                    self.storage.save_settings()
                                else:
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
                                if attempt_gene is not None:
                                    self.storage.record_gene_result(attempt_gene, True)
                                    self.bridge.log.emit(
                                        f"MULTI-GENE: win {_cs_gene_label(attempt_gene)} "
                                        f"method={attempt_strategy} fakeSni={fake_sni}"
                                    )
                                self.bridge.profiles_changed.emit()
                                quality = (f"; download={download_detail}"
                                           if carrier == "mci" and download_detail else "")
                                self.bridge.log.emit(f"CONFIG WIN {profile.name} fakeSni={fake_sni}: {detail}{quality}")
                                try:
                                    from .connect_summary import format_connected_block, edge_source
                                    _edge = str(getattr(self.engine, 'active_upstream_address', '') or getattr(getattr(self.engine, 'fragment', None), 'active_edge', '') or attempt_tuning.pattern_connect_ip or '').strip()
                                    if ':' in _edge and _edge.count(':') == 1:
                                        _edge = _edge.split(':')[0]
                                    _pedges = [profile.address, *str(getattr(profile, 'fallback_address', '') or '').split(',')]
                                    _from = edge_source(_edge, attempt_tuning.pattern_gene_edges if attempt_gene is not None else '', _pedges, bool(attempt_tuning.pattern_use_profile_edges))
                                    if _edge and _edge == str(getattr(attempt_tuning, 'pattern_session_edge', '') or ''):
                                        _from = 'clean-scan (session)'
                                    elif _edge in clean_sources and _from != 'gene':
                                        _from = clean_sources[_edge]
                                    if _edge and clean_csv:
                                        self._clean_ip_cache().record(carrier, _edge, True, float(getattr(self.engine, 'last_probe_ms', 0) or 0))
                                    try:
                                        old_ref = getattr(self, '_clean_refresher', None)
                                        if old_ref is not None:
                                            old_ref.stop()
                                        if bool(self.storage.settings.get(_clean_ip.SETTING_KEY, True)):
                                            self._clean_refresher = _clean_ip.BackgroundRefresher(
                                                self._clean_ip_cache(), carrier, attempt_tuning.pattern_fake_sni,
                                                active_edges=[_edge, *clean_csv.split(','), attempt_tuning.pattern_connect_ip,
                                                              *str(attempt_tuning.pattern_fallback_ips or '').split(','),
                                                              *str(attempt_tuning.pattern_gene_edges or '').split(',')],
                                                log=self.bridge.log.emit,
                                                alive=lambda: bool(getattr(self.engine, 'running', False)) and not (hasattr(cancel, 'is_set') and cancel.is_set()),
                                            ).start()
                                    except Exception:
                                        pass
                                    for _line in format_connected_block(profile.name, attempt_gene, attempt_strategy, fake_sni, _edge, _from, carrier, strategy_locked, multi_gene, getattr(attempt_tuning, 'pattern_gene_ops', ''), ech_state=str(getattr(self.engine, 'ech_state', '') or '')).split('\n'):
                                        self.bridge.log.emit(_line)
                                except Exception as _summary_error:
                                    self.bridge.log.emit(f'CONNECTED summary unavailable: {_summary_error}')
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
                                if download_state != "verified":
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
                            try:
                                from .connect_summary import format_fail_line
                                self.bridge.log.emit(format_fail_line(profile.name, attempt_gene, attempt_strategy, last_error))
                            except Exception:
                                pass
                        except EngineCancelled:
                            raise
                        except Exception as attempt_error:
                            last_error = str(attempt_error)
                            self.bridge.log.emit(f"CONFIG FAIL {profile.name} fakeSni={fake_sni}: {last_error}")
                            try:
                                from .connect_summary import format_fail_line
                                self.bridge.log.emit(format_fail_line(profile.name, attempt_gene, attempt_strategy, last_error))
                            except Exception:
                                pass
                        if self._attempt_cancelled(generation, cancel):
                            raise EngineCancelled("Connection attempt cancelled")
                        if attempt_gene is not None:
                            gene_id = str(attempt_gene.get("id", ""))
                            cooled = self.storage.record_gene_result(attempt_gene, False)
                            self.bridge.log.emit(f"MULTI-GENE: fail {_cs_gene_label(attempt_gene) or gene_id} on {profile.name}")
                            if cooled:
                                hours = gene_pool.COOLDOWN_SECONDS // 3600
                                self.bridge.log.emit(
                                    f"MULTI-GENE: cooldown {gene_id} for {hours}h after "
                                    f"{gene_pool.FAILS_BEFORE_COOLDOWN} consecutive fails"
                                )
                                gene_pool_list = [
                                    g for g in gene_pool_list if str(g.get("id", "")) != gene_id
                                ]
                        self.engine.stop(notify=False)
                    if not profile_passed:
                        self._save_profile_benchmark(profile, strategy, False, "not_tested",
                                                     profile_snis[-1] if profile_snis else "",
                                                     carrier=carrier,
                                                     download_state=profile_download_state)
                raise RuntimeError("No profile passed the real YouTube/page traffic test. " + last_error)
            except EngineCancelled:
                return
            except Exception as exc:
                if not self._attempt_cancelled(generation, cancel):
                    self.bridge.error.emit(str(exc))
                    self.bridge.state.emit(False)
            finally:
                if not connected and not self._attempt_cancelled(generation, cancel):
                    self.engine.stop(notify=False)

        self._connect_thread = threading.Thread(target=work, name=f"connect-{generation}", daemon=True)
        self._connect_thread.start()

    def _set_xray_hint(self, text):
        if self.engine_mode == ENGINE_XRAY:
            self.connection_hint.setText(text)

    def _set_connection_visual(self, state, *, direct_color_state=None):
        states = {
            "disconnected": (f"{ltr_isolate('VPN')} خاموش است", "VPN is OFF", "اتصال امن فعال نیست", "Your connection is not active", "اتصال", "Connect", "play", "idle", True),
            "connecting": ("در حال اتصال…", "Connecting…", "در حال ایجاد مسیر امن…", "Establishing secure route…", "قطع اتصال", "Disconnect", "x-circle", "cancel", True),
            "connected": (f"{ltr_isolate('VPN')} متصل است", "VPN is ON", "تونل امن فعال است", "Secure tunnel is active", "قطع اتصال", "Disconnect", "power", "connected", True),
            "disconnecting": ("در حال قطع اتصال…", "Disconnecting…", "در حال بازگردانی پروکسی سیستم…", "Restoring system proxy…", "در حال قطع…", "Disconnecting…", "loader", "loading", False),
            "error": ("خطای اتصال", "Connection Error", f"اتصال ناموفق بود؛ {ltr_isolate('Live Logs')} را بررسی کنید.", "Connection failed. Check Live Logs for details.", "تلاش دوباره", "Retry", "refresh", "error", True),
            "paused": ("اتصال در حالت مکث است", "Connection paused", "مسیر مستقیم فعال است", "The direct route is active", "قطع اتصال", "Disconnect", "power", "connected", True),
        }
        direct = getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_DIRECT
        fa_status, en_status, fa_hint, en_hint, fa_button, en_button, icon_name, button_state, enabled = states[state]
        if direct and state == "connected":
            fa_hint, en_hint = "مسیر Direct تأیید شده است.", "The Direct route is verified."
        elif direct and state == "disconnected":
            icon_name = "power"
        elif direct and state == "disconnecting":
            fa_hint, en_hint = "در حال بستن نشست Direct…", "Closing the Direct session…"
        self.connection_hint.setToolTip("")
        self._bind_text(self.status, fa_status, en_status)
        self._bind_text(self.connection_hint, fa_hint, en_hint)
        self._bind_text(self.connect_button, fa_button, en_button)
        self.connect_button.setEnabled(enabled)
        direct_color_state = (direct_color_state or state) if direct else None
        dialog = getattr(self, "_engine_switch_dialog", None)
        if dialog is not None:
            dialog.set_connection_state(direct_color_state or state)
        self.connect_button.setProperty("directState", direct_color_state)
        self.status_pill.setProperty("directState", direct_color_state)
        if direct:
            icon_color = _direct_theme.BUTTON_TEXT_COLORS[direct_color_state]
        else:
            icon_color = "#031422" if state == "disconnected" else "#eaffff"
        self.connect_button.setProperty("state", button_state); self.connect_button.setIcon(cyber_icon(icon_name, icon_color, 20)); _restyle(self.connect_button)
        visual_state = "connecting" if state == "disconnecting" else state
        self.status_pill.set_state(visual_state)
        self.orb.set_state(visual_state, direct_color_state=direct_color_state)
        self.hero_card.set_wave_state(state, direct_color_state=direct_color_state)
        if self.network_metrics.connection_state != state:
            self.network_metrics.set_connection_state(state)
            if hasattr(self, "global_settings_page"):
                self.global_settings_page.refresh_capabilities()
            if state == "disconnected":
                self._traffic_totals.reset()
            self._target_latency_generation += 1
            self._target_latency_busy = False
            if state == "connected" and not direct:
                QTimer.singleShot(0, self._queue_target_latency_probe)
                QTimer.singleShot(0, self._poll_traffic)
        if not direct and state in ("connected", "disconnected"):
            self._schedule_ip_refresh(1500 if state == "connected" else 900)
        self.status.setObjectName("heroStatusOn" if state == "connected" else "heroStatusError" if state == "error" else "heroStatus")
        self.status.setText(_accent_state_word(self.status.text()))
        _restyle(self.status)
        self._refresh_app_routing_notice()

    def _set_state(self, running):
        if getattr(self, "engine_mode", ENGINE_XRAY) != ENGINE_XRAY:
            return
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

    def _set_traffic(self, report):
        self._traffic_busy = False
        run_id, sources = report
        if (sources is not None and self.engine_mode == ENGINE_XRAY
                and self.engine.run_id == run_id and self.network_metrics.connection_state == "connected"):
            self._display_traffic(*self._traffic_totals.update(sources))

    def _poll_traffic(self):
        if self._closing or self.network_metrics.connection_state != "connected":
            return
        if self.engine_mode == ENGINE_POW:
            self._display_traffic(*self._traffic_totals.update(self.pow_controller.coordinator.traffic_sources()))
        elif self.engine_mode == ENGINE_XRAY and self.engine.running and not self._traffic_busy:
            self._traffic_busy = True
            run_id = self.engine.run_id

            def work():
                try:
                    sources = self.engine.traffic_sources()
                except OSError:
                    sources = None
                self.bridge.traffic.emit((run_id, sources))

            threading.Thread(target=work, name="xray-traffic", daemon=True).start()

    def _display_traffic(self, upload, download, *, sample=True):
        self.network_metrics.set_traffic(upload, download, sample=sample)
        if sample:
            self.hero_card.set_wave_traffic(upload, download)

    def _dns_probe_route(self):
        if self.network_metrics.connection_state != "connected":
            return None
        if self.engine_mode == ENGINE_POW:
            coordinator = self.pow_controller.coordinator
            if coordinator.running and coordinator.exit_port:
                return self.engine_mode, coordinator.exit_port, None
        elif self.engine_mode == ENGINE_XRAY and self.engine.running and self.engine.socks_port:
            return self.engine_mode, self.engine.probe_socks_port, self.engine.run_id
        return None

    def _queue_target_latency_probe(self):
        if self._closing or self._target_latency_busy:
            return
        route = self._dns_probe_route()
        if route is None:
            return
        self._target_latency_busy = True
        self._target_latency_generation += 1
        generation = self._target_latency_generation
        port = route[1]

        def work():
            from .direct.probe import verify_dns
            started = time.monotonic()
            result = verify_dns(port, "8.8.8.8", timeout=2.0)
            delay = max(1.0, (time.monotonic() - started) * 1000) if result.ok else None
            self.bridge.target_latency.emit(delay, route, generation)

        threading.Thread(target=work, name="network-metrics-dns", daemon=True).start()

    def _target_latency_finished(self, milliseconds, route, generation):
        if generation != self._target_latency_generation:
            return
        self._target_latency_busy = False
        if route is not None and route == self._dns_probe_route():
            detail = self.tr("پاسخ DNS از مسیر فعال · ۸.۸.۸.۸", "DNS response via active route · 8.8.8.8")
            if milliseconds is None:
                detail = self.tr("پاسخ DNS دریافت نشد", "No DNS response")
            self.network_metrics.set_latency(milliseconds, detail)

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

    # ------------------------------------------------------------ quick-start wizard
    def _maybe_open_wizard(self):
        try:
            from . import first_run_wizard as _wiz
            if getattr(self, "engine_mode", ENGINE_XRAY) != ENGINE_XRAY:
                return  # engine 2 active: keep the seen-marker for when engine 1 is opened
            if _wiz.should_show(self.storage.settings, __version__) and getattr(self, "_wizard", None) is None:
                self._open_wizard()
        except Exception as exc:
            self._append_log(f"WIZARD: unavailable ({exc})")

    def _open_wizard(self):
        from . import first_run_wizard as _wiz
        if getattr(self, "_wizard", None) is not None:
            self._wizard.raise_(); self._wizard.activateWindow(); return
        if getattr(self, "engine_mode", ENGINE_XRAY) != ENGINE_XRAY:
            self.show_toast(self.tr("راهنما مخصوص موتور ۱ (Xray) است؛ اول به موتور ۱ برو", "The guide is for engine 1 (Xray); switch to engine 1 first"), "warning")
            return
        dialog = _wiz.FirstRunWizard(self, host=self, language=self.language)
        self._wizard = dialog; self._wizard_phase = ""
        hooks = ((self.bridge.maker_imported, self._wizard_on_imported), (self.bridge.maker_batch, self._wizard_on_batch),
                 (self.bridge.maker_done, self._wizard_on_done), (self.bridge.maker_failed, self._wizard_on_failed))
        # Raw Xray / SNI Maker output is never piped into the wizard (file log only).
        for signal, slot in hooks:
            signal.connect(slot)

        def closed(_result=0):
            for signal, slot in hooks:
                try:
                    signal.disconnect(slot)
                except Exception:
                    pass
            self._wizard = None; self._wizard_phase = ""
            _wiz.mark_seen(self.storage.settings, __version__); self.storage.save_settings()
            if _result != QDialog.Accepted:
                QTimer.singleShot(400, self._queue_restart_coach)
        dialog.finished.connect(closed)
        dialog.open()

    def _install_wizard_restart_button(self):
        try:
            layout = self.home_header.layout()
            button = QPushButton(); button.setObjectName("wizardRestartBtn"); button.setCursor(Qt.PointingHandCursor)
            button.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Fixed)
            self._bind_text(button, "شروع مجدد راهنما", "Restart guide")
            button.setIcon(cyber_icon("sparkles", "#04111f", 18)); button.setIconSize(QSize(18, 18))
            button.setToolTip(self.tr("راهنمای شروع سریع رو از اول اجرا کن", "Run the quick-start guide again from step 1"))
            button.setAccessibleName("Restart guide"); button.setMinimumHeight(38)
            button.setStyleSheet(
                "QPushButton#wizardRestartBtn { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #19d9c6, stop:1 #3f7dff);"
                " color: #04111f; border: none; border-radius: 19px; padding: 8px 18px; font-weight: 800; font-size: 13px; }"
                "QPushButton#wizardRestartBtn:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #35f0dd, stop:1 #5c93ff); }"
                "QPushButton#wizardRestartBtn:pressed { padding-top: 9px; }")
            button.clicked.connect(lambda: self._open_wizard())
            slot = QWidget(self.home_header)
            slot.setFixedWidth(_layout.GUIDE_WIDTH)
            slot_layout = QHBoxLayout(slot); slot_layout.setContentsMargins(0, 0, 0, 0)
            slot_layout.addWidget(button, 0, Qt.AlignVCenter)
            index = layout.indexOf(self.status_pill)
            layout.insertWidget(index if index >= 0 else layout.count(), slot, 0, Qt.AlignVCenter)
            self.wizard_restart_btn = button
            self._sync_wizard_restart_button()
        except Exception as exc:
            self.wizard_restart_btn = None
            try:
                self._append_log(f"WIZARD: restart button unavailable ({exc})")
            except Exception:
                pass

    def _sync_wizard_restart_button(self):
        button = getattr(self, "wizard_restart_btn", None)
        if button is not None:
            button.setVisible(getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_XRAY)

    def wizard_config_count(self):
        return sum(1 for p in self.storage.profiles if getattr(p, "origin", "") in DIRECT_PROFILE_ORIGINS)

    def wizard_fake_sni(self):
        return str(getattr(self.storage.tuning, "pattern_fake_sni", "") or "").strip() or "chatgpt.com"

    def wizard_seed_ips(self):
        t = self.storage.tuning
        return _clean_ip.split_ips([t.pattern_connect_ip, *str(t.pattern_fallback_ips or "").split(",")])

    def wizard_tunnel_active(self):
        return bool(self.engine.running or self.connecting)

    def wizard_log_path(self):
        return LOG_FILE

    def wizard_start_flow(self, kind, wizard, carrier):
        self._wizard_carrier = carrier or "auto"
        if self.engine.running or self.connecting:
            wizard.flow_step("fetch" if kind == "sni" else "scan", "fail", self.tr("اول قطع کن", "disconnect first"))
            wizard.flow_finished(False, self.tr("اول اتصال فعلی رو قطع کن", "Disconnect first"),
                                 self.tr("برای تست کانفیگ‌ها باید تونل خاموش باشه. قطع کن و دوباره از «ابزارها ← شروع سریع» بزن.",
                                         "Testing needs the tunnel off. Disconnect, then run Tools → Quick Start again."))
            return
        if kind == "sni":
            self._wizard_start_patterniha(wizard)
        else:
            self._wizard_phase = "scan"
            wizard.flow_step("scan", "run", self.tr("در حال اسکن…", "scanning…"))
            wizard.flow_progress(0, 0)
            cache = self._clean_ip_cache(); fake = self.wizard_fake_sni(); seeds = self.wizard_seed_ips()
            cancel = threading.Event(); self._wizard_cancel = cancel

            def work():
                found = _clean_ip.find_clean_ips(cache, carrier or "auto", fake, seeds, budget=8.0, top=5,
                                                 cancel=cancel, log=self.bridge.log.emit)
                ips = [r.ip for r in found]
                self.bridge.log.emit(f"WIZARD: clean IPs on {carrier}: {', '.join(ips) or '-'}")
                QTimer.singleShot(0, self, lambda: self._wizard_scan_done(found))
            threading.Thread(target=work, name="wizard-clean-ip", daemon=True).start()

    def _wizard_start_patterniha(self, wizard):
        """Always fetch + test + add Patterniha configs (any DPI type)."""
        if self._maker_running:
            self._maker_stop_test()
        self._wizard_phase = "fetch"
        wizard.flow_step("fetch", "run", self.tr("پترنیها", "Patterniha"))
        wizard.flow_headline(self.tr("📥 دارم لیست کانفیگ‌های پترنیها رو می‌گیرم…", "📥 Fetching the Patterniha config list…"))
        self.maker_repo_url.setText(DEFAULT_SNI_MAKER_URL)
        self._maker_fetch_repository()

    def _wizard_scan_done(self, found):
        wizard = getattr(self, "_wizard", None)
        if wizard is None or self._wizard_phase != "scan":
            return
        if found:
            best = found[0]
            wizard.flow_step("scan", "ok", self.tr(f"{len(found)} تا پیدا شد", f"{len(found)} found"))
            wizard.flow_note(f"🧭 بهترین IP تمیز: {best.ip} · {best.latency_ms:.0f} میلی‌ثانیه", f"🧭 Best clean IP: {best.ip} · {best.latency_ms:.0f} ms")
        else:
            wizard.flow_step("scan", "warn", self.tr("پیدا نشد", "none found"))
        self._wizard_start_patterniha(wizard)

    def _wizard_user_config_count(self):
        return sum(1 for p in self.storage.profiles if getattr(p, "origin", "") in USER_CONFIG_ORIGINS)

    def _wizard_saved_on_disk(self, ids):
        try:
            from .paths import PROFILES_FILE
            text = PROFILES_FILE.read_text(encoding="utf-8")
            return sum(1 for i in ids if i in text)
        except Exception:
            return 0

    def wizard_stop_flow(self):
        cancel = getattr(self, "_wizard_cancel", None)
        if cancel is not None:
            cancel.set()
        if self._wizard_phase == "test" and self._maker_running:
            self._maker_stop_test()
        self._wizard_phase = ""

    def _wizard_on_log(self, line):
        wizard = getattr(self, "_wizard", None)
        if wizard is not None and self._wizard_phase:
            wizard.flow_log(line)

    def _wizard_on_imported(self, payload, meta, generation):
        wizard = getattr(self, "_wizard", None)
        if wizard is None or self._wizard_phase != "fetch":
            return
        error = str(payload.get("error", "") if isinstance(payload, dict) else "")
        profiles = list(self._maker_profiles.values())
        if error or not profiles:
            self._wizard_phase = ""
            wizard.flow_step("fetch", "fail", self.tr("نشد", "failed"))
            wizard.flow_finished(False, self.tr("لیست پترنیها دریافت نشد", "Couldn't fetch the Patterniha list"),
                                 error or self.tr("کانفیگی پیدا نشد.", "No configs found."))
            return
        wizard.flow_step("fetch", "ok", self.tr(f"{len(profiles)} کانفیگ", f"{len(profiles)} configs"))
        wizard.flow_note(f"📥 لیست رسید · {len(profiles)} کانفیگ برای تست", f"📥 List received · {len(profiles)} configs to test")
        wizard.flow_step("test", "run", "")
        wizard.flow_progress(0, len(profiles), 0)
        self._wizard_phase = "test"
        QTimer.singleShot(0, self, lambda: self._maker_launch_test(profiles, getattr(self, "_wizard_carrier", "mci"), []))

    def _wizard_on_batch(self, batch, done, total, generation):
        wizard = getattr(self, "_wizard", None)
        if wizard is not None and self._wizard_phase == "test":
            for result in batch or []:
                if not isinstance(result, LiveConfigResult):
                    continue
                code = str(result.country_code or getattr(result.profile, "observed_country_code", "") or "").upper()
                flag, english, persian = ("", "", "")
                if code and code != "XX":
                    flag, english, persian = self._country_metadata(code)
                wizard.flow_result(bool(result.ok), flag, persian, english, float(result.ping_ms or 0))
            wizard.flow_progress(done, total, len(self.maker_model.healthy_results()))

    def _wizard_on_done(self, payload, generation):
        wizard = getattr(self, "_wizard", None)
        if wizard is None or self._wizard_phase != "test":
            return
        self._wizard_phase = ""
        healthy = len(self.maker_model.healthy_results())
        cancelled = bool(payload.get("cancelled", False)) if isinstance(payload, dict) else False
        wizard.flow_step("test", "ok" if healthy else "fail", self.tr(f"{healthy} سالم", f"{healthy} healthy"))
        if not healthy:
            wizard.flow_step("add", "warn", "-")
            wizard.flow_finished(False, self.tr("این بار کانفیگ سالمی پیدا نشد", "No healthy config this time"),
                                 self.tr("چند دقیقه دیگه دوباره امتحان کن؛ لیست پترنیها مرتب آپدیت می‌شه.", "Try again in a few minutes; the Patterniha list updates often."))
            return
        before_ids = {p.id for p in self.storage.profiles}
        self._maker_add_results("all")
        new_ids = [p.id for p in self.storage.profiles if p.id not in before_ids and p.origin in USER_CONFIG_ORIGINS]
        saved = self._wizard_saved_on_disk(new_ids)
        visible = sum(1 for row in range(self.user_config_list.count())
                      if self.user_config_list.item(row).data(Qt.UserRole) in set(new_ids))
        added = min(len(new_ids), saved)
        self._append_log(f"WIZARD: added={len(new_ids)} saved_on_disk={saved} visible_in_list={visible} "
                         f"user_configs_total={self._wizard_user_config_count()}")
        wizard.flow_step("add", "ok" if added else "fail", self.tr(f"{added} تا اضافه شد", f"{added} added"))
        total_n = self.maker_model.rowCount()
        wizard.flow_progress(total_n, total_n, healthy, added)
        if added:
            wizard.flow_note(f"➕ {added} کانفیگ سالم به User Config اضافه شد", f"➕ {added} healthy configs added to User Config")
        if added:
            wizard.flow_finished(True, self.tr(f"حله! {added} کانفیگ سالم اضافه شد 🎉", f"Done! {added} healthy configs added 🎉"),
                                 self.tr("کانفیگ‌های جدید تو User Config هستن و کانفیگ‌های قبلیت دست نخورده. حالا فقط دکمه اتصال رو بزن.",
                                         "The new configs are in User Config and your old ones are untouched. Just hit Connect."))
        elif not new_ids and self._wizard_user_config_count():
            total = self._wizard_user_config_count()
            wizard.flow_finished(True, self.tr(f"کانفیگ‌های سالم از قبل تو User Config بودن 👌 ({total} تا)", f"Healthy configs were already in User Config 👌 ({total})"),
                                 self.tr("چیزی تکراری اضافه نکردم. حالا فقط دکمه اتصال رو بزن.", "Nothing duplicated. Just hit Connect."))
        else:
            wizard.flow_finished(False, self.tr("اوه، کانفیگی ذخیره نشد 😕", "Oops, nothing got saved 😕"),
                                 self.tr("سالم‌ها پیدا شدن ولی ذخیره نشدن. «دوباره امتحان کن» رو بزن.", "Healthy configs were found but not saved. Tap Try again."))

    def _wizard_on_failed(self, message, generation):
        wizard = getattr(self, "_wizard", None)
        if wizard is None or self._wizard_phase not in ("test", "fetch"):
            return
        self._wizard_phase = ""
        wizard.flow_step("test", "fail", self.tr("خطا", "error"))
        wizard.flow_finished(False, self.tr("تست کانفیگ‌ها خطا داد", "Config testing failed"), str(message))

    def _clean_ip_cache(self):
        cache = getattr(self, "_clean_ip_cache_obj", None)
        if cache is None:
            cache = _clean_ip.CleanIpCache(DATA_DIR / "clean_ips.json")
            self._clean_ip_cache_obj = cache
        return cache

    def _open_clean_ip_scan(self, parent=None):
        try:
            from .clean_ip_dialog import CleanIpScanDialog
            tuning = self.storage.tuning
            seeds = [tuning.pattern_connect_ip, *str(tuning.pattern_fallback_ips or "").split(",")]
            dialog = CleanIpScanDialog(parent or self, self._clean_ip_cache(), tuning.carrier_mode,
                                       tuning.pattern_fake_sni, seeds, self.language)

            def chosen(ip):
                self._clean_ip_session = ip
                self._append_log(f"CLEAN IP: session preferred {ip} (full scan)")
            dialog.ip_chosen.connect(chosen)
            dialog.exec()
        except Exception as exc:
            self._append_log(f"CLEAN IP: full scan unavailable: {exc}")

    def _find_clean_edges(self, carrier, base_tuning, cancel):
        """Returns (csv, {ip: 'clean-cache'|'clean-scan'}). Never raises."""
        sources = {}
        picks = []
        session_ip = str(getattr(self, "_clean_ip_session", "") or "")
        if session_ip:
            sources[session_ip] = "clean-scan"   # applied per attempt as pattern_session_edge
        if not bool(self.storage.settings.get(_clean_ip.SETTING_KEY, True)):
            return ",".join(picks), sources
        try:
            self.bridge.activity.emit(self.tr("\u062f\u0631 \u062d\u0627\u0644 \u067e\u06cc\u062f\u0627 \u06a9\u0631\u062f\u0646 \u0628\u0647\u062a\u0631\u06cc\u0646 IP\u2026", "Finding best IP\u2026"), "running", True)
            seeds = [base_tuning.pattern_connect_ip, *str(base_tuning.pattern_fallback_ips or "").split(",")]
            event = cancel if hasattr(cancel, "is_set") else None
            results = _clean_ip.find_clean_ips(
                self._clean_ip_cache(), carrier, base_tuning.pattern_fake_sni, seeds,
                cancel=event, log=self.bridge.log.emit)
            for r in results:
                if r.ip in sources:
                    continue
                picks.append(r.ip)
                sources[r.ip] = "clean-cache" if r.source == "cache" else "clean-scan"
                self.bridge.log.emit(
                    f"CLEAN IP: picked {r.ip} ({r.latency_ms:.0f} ms, from {'cache' if r.source == 'cache' else 'scan'})")
            if not results:
                self.bridge.log.emit("CLEAN IP: none found; using normal edge list")
        except Exception as exc:
            self.bridge.log.emit(f"CLEAN IP: finder failed ({type(exc).__name__}); using normal edge list")
        return ",".join(picks), sources

    def open_tuning(self):
        if getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_DIRECT:
            self.direct_controller.open_settings()
            return
        if getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_POW:
            self.pow_controller._open_settings()
            self._load_pow_home_controls()
            return
        self.show_page(self.XRAY_SETTINGS_PAGE)

    def _open_xray_settings_form(self, return_page):
        layout = self.xray_settings_page.layout()
        if self._xray_settings_form is not None:
            old = self._xray_settings_form
            layout.removeWidget(old)
            old.hide()
            old.deleteLater()
        self._xray_settings_return_page = max(0, return_page)
        form = self._xray_settings_form = XraySettingsPage(
            self, self.storage.tuning, self.language,
            self.storage.settings.get("update_repo_url", DEFAULT_UPDATE_REPO_URL),
            self.storage.all_carrier_tunings(),
            self.storage.gene_strategies,
            self.storage.selected_gene_strategy_id,
            self.storage.strategy_locked,
            self.storage.multi_gene_enabled,
            self._multi_gene_status_text(),
            bool(self.storage.settings.get(_clean_ip.SETTING_KEY, True)),
            self._open_clean_ip_scan,
            ech_via_pattern=bool(self.storage.settings.get("ech_via_pattern", False)),
        )
        form.accepted.connect(self._save_xray_settings)
        form.rejected.connect(self._close_xray_settings)
        layout.addWidget(form)

    def _close_xray_settings(self):
        self.show_page(self._xray_settings_return_page)

    def _save_xray_settings(self):
        form = self._xray_settings_form
        self.storage.settings[_clean_ip.SETTING_KEY] = form.auto_clean_ip_value()
        self.storage.settings["ech_via_pattern"] = form.ech_via_pattern_value()
        self.engine.ech_via_pattern = bool(self.storage.settings["ech_via_pattern"])
        values = form.values()
        active = form.carrier.currentText()
        gene_strategies, gene_selected = form.gene_selection()
        self.storage.set_gene_strategies(gene_strategies, gene_selected)
        self.storage.set_strategy_locked(form.strategy_lock_enabled())
        self.storage.set_multi_gene_enabled(form.multi_gene_enabled_value())
        self.storage.set_carrier_tunings(values, active)
        with QSignalBlocker(self.carrier):
            self.carrier.setCurrentText(active)
        repo_url = form.update_repo_url() or DEFAULT_UPDATE_REPO_URL
        changed_repo = repo_url != self.storage.settings.get("update_repo_url", DEFAULT_UPDATE_REPO_URL)
        self.storage.settings["update_repo_url"] = repo_url
        self.storage.save_settings()
        self._close_xray_settings()
        self._set_activity("تنظیمات ذخیره شد.", "Settings saved.", "success", False)
        if changed_repo:
            self._update_generation += 1
            self._update_in_progress = False
            self._latest_update = None
            self.update_check_button.setEnabled(True)
            self.check_for_updates(manual=True)

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
        from .app_config import UPDATE_REPOSITORY_URL
        from .install_type import InstallType, current_installation

        installation = current_installation()
        if (installation.kind == InstallType.DEVELOPMENT or not self._latest_update
                or self._latest_update.repo_url.casefold() != UPDATE_REPOSITORY_URL.casefold()):
            self._open_release_page(url)
        elif getattr(self, "_update_transfer", None) is None:
            from .update_ui import UpdateTransfer

            self._update_transfer = UpdateTransfer(self, installation, url)

    def _open_release_page(self, url):
        if url.startswith("https://github.com/"):
            webbrowser.open(url); self._set_activity("صفحه دانلود بروزرسانی باز شد.", "The update download page was opened.", "success", False)
        else:
            self.show_toast(self.tr("لینک معتبر Release موجود نیست", "No valid release link is available"), "warning")

    def _scan_domain_list(self):
        return list(dict.fromkeys(
            line.strip().lower() for line in self.domains.toPlainText().splitlines()
            if line.strip() and not line.startswith("#")
        ))

    def _update_scan_domain_count(self):
        count = len(self._scan_domain_list())
        self.scan_domain_count.setText(self._ui_text(f"{count} دامنه", f"{count} domains"))

    def _set_scan_status(self, fa, en, state="idle"):
        self._bind_text(self.scan_state_badge, fa, en)
        self.scan_state_badge.setProperty("state", state)
        _restyle(self.scan_state_badge)
        status = self._bind_text(self.scan_progress.status, fa, en)
        self.scan_progress.set_status(status.text(), state)

    def _set_scan_detail(self, fa, en):
        label = self._bind_text(self.scan_progress.domain, fa, en)
        label.setToolTip(label.text())

    def toggle_scan(self):
        if self.scanning:
            self.scan_cancelled = True; self._scan_cancel_event.set()
            self._set_scan_status("در حال توقف…", "Stopping…", "warning")
            self.scan_stop_btn.setEnabled(False)
            self._set_activity("در حال توقف آزمایش…", "Stopping the test…", "warning", True)
            return
        domains = self._scan_domain_list()
        if not domains: self.show_toast(self.tr("حداقل یک دامنه وارد کنید", "Enter at least one domain"), "warning"); return
        self._scan_generation += 1; generation = self._scan_generation
        self._scan_cancel_event = threading.Event(); self._scan_results_by_domain = {}; self.last_results = []
        self.scanning = True
        self.scan_cancelled = False
        self.scan_button.setEnabled(False)
        self.scan_stop_btn.setEnabled(True)
        self.scan_tabs.setCurrentIndex(0)
        self.results_table.setRowCount(0)
        self._update_scan_selection()
        self.scan_progress.setMaximum(len(domains))
        self.scan_progress.setValue(0)
        self._set_scan_status("در حال آزمایش", "Testing", "running")
        self._set_scan_detail("در انتظار اولین نتیجه…", "Waiting for the first result…")
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
        detail = f"{done}/{total}  •  {result.domain}"
        self._set_scan_detail(ltr_isolate(detail), detail)
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
        self.scanning = False
        self._scan_cancel_event.set()
        self.scan_button.setEnabled(True)
        self.scan_stop_btn.setEnabled(False)
        state = "warning" if self.scan_cancelled or not self.last_results else "success"
        fa = "آزمایش متوقف شد" if self.scan_cancelled else "آزمایش کامل شد"
        en = "Test stopped" if self.scan_cancelled else "Test complete"
        self._set_scan_status(fa, en, state)
        completed = self.results_table.rowCount()
        self._set_scan_detail(f"{completed} دامنه بررسی شد.", f"{completed} domains tested.")
        self._set_activity(
            f"{fa}، {len(self.last_results)} دامنه موفق بود.",
            f"{en}. {len(self.last_results)} domains passed.",
            state, False,
        )
        self.results_table.sortItems(8, Qt.DescendingOrder)
        self._append_log(f"SNI scan completed: {len(self.last_results)} working routes")

    def _scan_failed(self, message, generation):
        if generation != self._scan_generation:
            return
        self.last_results = sorted(self._scan_results_by_domain.values(), key=lambda x: (-x.score, -x.stability, x.first_byte_ms, x.ping_ms, x.domain))
        if self.last_results: self._persist_scan_repository(self.last_results)
        self.scanning = False
        self._scan_cancel_event.set()
        self.scan_button.setEnabled(True)
        self.scan_stop_btn.setEnabled(False)
        self._set_scan_status("آزمایش با خطا متوقف شد", "Test failed", "error")
        completed = self.results_table.rowCount()
        self._set_scan_detail(f"{completed} دامنه بررسی شد.", f"{completed} domains tested.")
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
        self._filter_scan_results()

    def _fill_results(self, table, results):
        table.setSortingEnabled(False)
        table.setRowCount(0)
        for row, r in enumerate(results):
            table.insertRow(row); self._populate_result_row(table, row, r)
        table.setSortingEnabled(True)
        self._filter_scan_results()

    def _populate_result_row(self, table, row, result, checked=False):
        selector = QCheckBox()
        selector.setObjectName("rowSelector")
        selector.setToolTip(self.tr("انتخاب این نتیجه", "Select this result"))
        selector.setChecked(checked and result.success)
        selector.setEnabled(result.success)
        selector.stateChanged.connect(self._update_scan_selection)
        holder = QWidget()
        row_layout = QHBoxLayout(holder)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.addWidget(selector, alignment=Qt.AlignCenter)
        table.setCellWidget(row, 0, holder)

        domain = QTableWidgetItem(result.domain)
        domain.setData(Qt.UserRole, result.to_dict())
        domain.setToolTip(result.domain)
        address = result.resolved_ip if result.resolved_ip not in ("", "N/A") else "—"
        ip = QTableWidgetItem(address)
        ip.setToolTip(address)
        for col, item in ((1, domain), (2, ip), (3, QTableWidgetItem(result.colo or "—"))):
            item.setTextAlignment(Qt.AlignVCenter | (Qt.AlignLeft if col in (1, 2) else Qt.AlignCenter))
            if not result.success:
                item.setFlags(item.flags() & ~Qt.ItemIsSelectable)
            table.setItem(row, col, item)

        ping_tone = "success" if result.ping_ms <= 100 else "warning" if result.ping_ms <= 250 else "danger"
        stability_tone = "success" if result.stability >= 80 else "warning" if result.stability >= 50 else "danger"
        score_tone = "success" if result.score >= 800 else "warning" if result.score >= 400 else "danger"
        metrics = (
            (4, result.ping_ms, f"{result.ping_ms} ms" if result.success else "—", ping_tone if result.success else "", None),
            (5, result.stability, f"{result.stability}%", stability_tone, result.stability),
            (6, result.first_byte_ms, f"{result.first_byte_ms} ms" if result.success else "—", "", None),
            (7, result.first_two_second_bytes, format_bytes(result.first_two_second_bytes) if result.success else "—", "", None),
            (8, result.score, str(result.score) if result.score != -9999 else "—", score_tone, None),
        )
        for col, value, text, tone, stability in metrics:
            item = MetricSortItem(value, text)
            if not result.success:
                item.setFlags(item.flags() & ~Qt.ItemIsSelectable)
            table.setItem(row, col, item)
            table.setCellWidget(row, col, result_metric(text, tone, stability=stability))

    def _active_result_table(self):
        return self.results_table if self.scan_tabs.currentIndex() == 0 else self.bookmarks_table

    @staticmethod
    def _working_scan_result(table, row):
        item = table.item(row, 1) if row >= 0 and not table.isRowHidden(row) else None
        raw = item.data(Qt.UserRole) if item else None
        if isinstance(raw, dict) and raw.get("success"):
            return ScanResult(**raw)
        return None

    def _filter_scan_results(self, *_):
        query = self.scan_search.text().strip().casefold()
        for table in (self.results_table, self.bookmarks_table):
            with QSignalBlocker(table):
                for row in range(table.rowCount()):
                    item = table.item(row, 1)
                    visible = item is not None and query in item.text().casefold()
                    if table.isRowHidden(row) == visible:
                        table.setRowHidden(row, not visible)
                    if not visible:
                        holder = table.cellWidget(row, 0)
                        selector = holder.findChild(QCheckBox) if holder else None
                        if selector and selector.isChecked():
                            with QSignalBlocker(selector):
                                selector.setChecked(False)
                        index = table.model().index(row, 1)
                        table.selectionModel().select(index, QItemSelectionModel.Deselect | QItemSelectionModel.Rows)
        self._update_scan_selection()

    def _selected_results(self):
        table = self._active_result_table()
        rows = {index.row() for index in table.selectionModel().selectedRows()}
        for row in range(table.rowCount()):
            if table.isRowHidden(row):
                continue
            holder = table.cellWidget(row, 0)
            check = holder.findChild(QCheckBox) if holder else None
            if check and check.isChecked():
                rows.add(row)
        return [result for row in sorted(rows) if (result := self._working_scan_result(table, row)) is not None]

    def _selected_result(self):
        selected = self._selected_results()
        if selected:
            return max(selected, key=lambda result: result.score)
        table = self._active_result_table()
        return self._working_scan_result(table, table.currentRow())

    def _update_scan_summary(self):
        table = self._active_result_table()
        tested = good = 0
        for row in range(table.rowCount()):
            item = table.item(row, 1)
            raw = item.data(Qt.UserRole) if item else None
            if isinstance(raw, dict):
                tested += 1
                good += bool(raw.get("success"))
        bad = tested - good
        self.scan_good.setText(self._ui_text(f"{good} موفق", f"{good} passed"))
        self.scan_bad.setText(self._ui_text(f"{bad} ناموفق", f"{bad} failed"))

    def _update_scan_selection(self, *_):
        if not hasattr(self, "scan_selection_label"):
            return
        current = self._selected_result()
        self.scan_selection_label.setText(current.domain if current else "—")
        self._update_scan_summary()

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

    def _create_toast(self):
        toast = self._toast = QFrame(self.centralWidget())
        toast.setObjectName("toast")
        toast.setMinimumWidth(360)
        toast.setMaximumWidth(580)
        layout = QHBoxLayout(toast)
        layout.setContentsMargins(16, 12, 12, 12)
        layout.setSpacing(12)
        self._toast_icon = QLabel()
        self._toast_icon.setObjectName("toastDot")
        self._toast_icon.setFixedSize(24, 24)
        self._toast_text = ElidedLabel()
        self._toast_text.setObjectName("toastText")
        self._toast_action = self._bind_text(QPushButton(), "بازگردانی", "Undo")
        self._toast_action.setObjectName("toastAction")
        self._toast_action.clicked.connect(self._undo_from_toast)
        layout.addWidget(self._toast_icon)
        layout.addWidget(self._toast_text, 1)
        layout.addWidget(self._toast_action)
        shadow = QGraphicsDropShadowEffect(toast)
        shadow.setBlurRadius(32)
        shadow.setOffset(0, 8)
        shadow.setColor(QColor(0, 0, 0, 150))
        toast.setGraphicsEffect(shadow)
        self._toast_timer = QTimer(toast)
        self._toast_timer.setSingleShot(True)
        self._toast_timer.timeout.connect(toast.hide)
        self._toast_animation = QPropertyAnimation(toast, b"pos", toast)
        self._toast_animation.setDuration(240)
        self._toast_animation.setEasingCurve(QEasingCurve.OutCubic)

    def show_toast(self, message, kind="success", undo=False):
        if self._toast is None:
            self._create_toast()
        toast = self._toast
        entering = toast.isHidden()
        if toast.property("kind") != kind:
            toast.setProperty("kind", kind)
            _restyle(toast)
        toast.setProperty("assistantCreatedAt", time.time())
        icon_name, color = {
            "success": ("check-circle", "#23f5a6"),
            "warning": ("alert", "#ffd166"),
            "danger": ("x-circle", "#ff5c7c"),
        }.get(kind, ("check-circle", "#23f5e0"))
        self._toast_icon.setPixmap(cyber_pixmap(icon_name, color, 21))
        self._toast_text.setText(message)
        self._toast_action.setVisible(undo)
        size = toast.sizeHint()
        line_width = self._toast_text.fontMetrics().horizontalAdvance(" ".join(str(message).splitlines()))
        toast.resize(size.width() + line_width, size.height())
        self._toast_animation.stop()
        self._position_toast(toast)
        if entering and _animations_enabled():
            target = toast.pos()
            toast.move(target + QPoint(0, 12))
            self._toast_animation.setStartValue(toast.pos())
            self._toast_animation.setEndValue(target)
            self._toast_animation.start()
        toast.show()
        toast.raise_()
        self._toast_timer.start(6000)

    def _undo_from_toast(self):
        self._toast.hide()
        self._toast_timer.stop()
        self.undo_sni_apply()

    def _position_toast(self, toast=None):
        toast = toast or self._toast
        if toast is None:
            return
        area = self.centralWidget().rect()
        x = max(18, area.center().x() - toast.width() // 2)
        y = max(18, area.bottom() - toast.height() - 24)
        toast.move(x, y)

    def _layout_sidebar_chrome(self):
        compact = self.width() < 1240
        dense_sidebar = self.height() < 790
        self.sidebar.setFixedWidth(_layout.SIDEBAR_WIDTH[0 if compact else 1])
        self.sidebar_layout.setContentsMargins(*_layout.SIDEBAR_MARGIN[0 if dense_sidebar else 1])
        self.sidebar_layout.setSpacing(_layout.SIDEBAR_GAP)
        self.logo_root.setContentsMargins(*_layout.BRAND_MARGIN[0 if dense_sidebar else 1])
        self.logo_root.setSpacing(7 if dense_sidebar else 9)
        language = "en" if self.language == "en" else "fa"
        for label, height in zip((self.brand_label, self.version_label, self.engine_badge), _layout.BRAND_TEXT_HEIGHTS[language]):
            label.setFixedHeight(height)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._layout_sidebar_chrome()
        self._fit_sidebar()
        self._layout_home_dashboard()
        self._position_profile_select_all()
        self._layout_tool_cards(self.width() < 1180)
        self._position_toast()
        self._position_update_notification()
        self._position_gateway_devices_popup()
        if self.assistant_controller is not None:
            self.assistant_controller.schedule_reposition()

    def showEvent(self, event):
        super().showEvent(event)
        self._layout_home_dashboard()
        QTimer.singleShot(0, self._layout_home_dashboard)
        if self.assistant_controller is not None:
            QTimer.singleShot(0, self.assistant_controller.schedule_reposition)
        if self._pending_update_notification is not None:
            info = self._pending_update_notification; self._pending_update_notification = None
            QTimer.singleShot(0, lambda value=info: self._show_update_notification(value))
        if not getattr(self, "_wizard_checked", False) and QApplication.platformName() != "offscreen":
            self._wizard_checked = True
            QTimer.singleShot(900, self._maybe_open_wizard)
            QTimer.singleShot(1800, self._queue_engine_coach)
            self._schedule_ip_refresh(2200)
        if self._entrance_done or not MOTION_ENABLED or QApplication.platformName() == "offscreen":
            return
        self._entrance_done = True
        self.setWindowOpacity(0.0)
        animation = QPropertyAnimation(self, b"windowOpacity", self); animation.setDuration(520); animation.setStartValue(0.0); animation.setEndValue(1.0); animation.setEasingCurve(QEasingCurve.OutCubic)
        self._entrance_animation = animation; animation.start()

    def refresh_processes(self):
        button = self.app_routing_view.refresh_button
        if not button.isEnabled():
            return
        button.setEnabled(False)

        def work():
            try:
                self.bridge.processes.emit(running_apps())
            except (OSError, psutil.Error) as exc:
                self.bridge.processes_failed.emit(str(exc))

        threading.Thread(target=work, name="process-list", daemon=True).start()

    def _populate_processes(self, apps):
        self.app_routing_view.refresh_button.setEnabled(True)
        self.app_routing_view.set_apps(apps)

    def _process_refresh_failed(self, error):
        self.app_routing_view.refresh_button.setEnabled(True)
        self.show_toast(error, "danger")

    def _routing_selection_reconnects(self, preferences):
        engine, output, mode = self.engine_mode, preferences.connection_mode, preferences.routing_mode
        if (mode == "all" or not supports_process_routing(engine, output, mode)
                or not self._engine_busy() or self._protected_session()):
            return False
        if engine == ENGINE_DIRECT:
            active_vpn = self.direct_controller.coordinator.session_vpn
        elif engine == ENGINE_POW:
            active_proxy = self.pow_controller.coordinator.session_proxy_mode
            active_vpn = None if active_proxy is None else not active_proxy
        else:
            active_vpn = self._xray_output() == "vpn"
        return active_vpn is None or active_vpn == (output == "vpn")

    def _save_process_selection(self, name, checked):
        names = list(self.global_settings.processes())
        if checked:
            if name.casefold() in {value.casefold() for value in names}:
                return
            names.append(name)
        else:
            names = [value for value in names if value.casefold() != name.casefold()]
        try:
            self.global_settings.set_processes(names)
        except OSError as error:
            self.show_toast(str(error), "danger")
            self.app_routing_view.refresh()
            return
        self.app_routing_view.refresh()

        if self._routing_selection_reconnects(self.global_settings.snapshot()):
            if self.engine_mode == ENGINE_DIRECT:
                self.direct_controller.restart_if_active()
            else:
                self._bypass_apply_timer.start()

    def _apply_bypass_changes(self):
        if self._closing or not self._routing_selection_reconnects(self.global_settings.snapshot()):
            return
        engine = self.engine_mode
        controller = getattr(self, "pow_controller", None)
        pow_active = (
            getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_POW
            and controller is not None
            and (controller.running or controller.busy)
        )
        if pow_active:
            self._append_log(
                "APP BYPASS changed; restarting UAC PoW with updated process rules"
            )
            self._set_activity(
                "در حال اعمال عبور مستقیم برنامه‌ها روی UAC PoW…",
                "Applying app bypass changes on UAC PoW…",
                "running",
                True,
            )
            try:
                controller.disconnect(quiet=True)
            except Exception:
                pass

            def reconnect_pow():
                if self._closing or self.engine_mode != engine:
                    return
                live = getattr(self, "pow_controller", None)
                if live is None or live.running or live.busy:
                    return
                live.connect()

            QTimer.singleShot(220, reconnect_pow)
            return
        if not (self.engine.running or self.connecting):
            return
        self._append_log("APP BYPASS changed; restarting the tunnel with updated process rules")
        self._cancel_connect_attempt(notify=False)
        self.connection_error = ""
        self._set_state(False)

        def reconnect():
            if self._closing or self.engine_mode != engine or self.engine.running or self.connecting:
                return
            self.toggle_connection()

        QTimer.singleShot(180, reconnect)

    def check_ip(self, proxy=None):
        if getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_DIRECT:
            self.direct_controller.coordinator.request_exit_refresh()
            return
        controller = getattr(self, "pow_controller", None)
        if getattr(self, "engine_mode", ENGINE_XRAY) == ENGINE_POW and controller is not None and controller.coordinator.running:
            controller.check_exit_ip()
            return
        self._set_activity("در حال بررسی آی‌پی عمومی…", "Checking public IP…")
        self._refresh_ip_card(force=True)

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
        self._update_shutdown_ok = True
        transfer = getattr(self, "_update_transfer", None)
        if transfer is not None:
            transfer.cancel.set()
        if self.assistant_controller is not None:
            self.assistant_controller.disable(persist=False)
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
            self._update_shutdown_ok = False
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
                self._update_shutdown_ok = False
                self._pending_file_log_lines.append(f"SNI Maker cleanup pending: {exc}")
        try:
            self._cancel_connect_attempt(wait=True, notify=False)
        except Exception as exc:
            self._update_shutdown_ok = False
            self._pending_file_log_lines.append(f"Shutdown cleanup retry: {exc}")
        try:
            direct = getattr(self, "direct_controller", None)
            if direct is not None:
                if direct.shutdown() is False:
                    self._update_shutdown_ok = False
            controller = getattr(self, "pow_controller", None)
            if controller is not None:
                if controller.shutdown() is False:
                    self._update_shutdown_ok = False
        except Exception as exc:
            self._update_shutdown_ok = False
            self._pending_file_log_lines.append(f"PoW shutdown pending: {exc}")
        try:
            from .process_win import cleanup_bin_helpers
            cleanup_bin_helpers()
        except Exception as exc:
            self._update_shutdown_ok = False
            self._pending_file_log_lines.append(f"Helper cleanup pending: {exc}")
        try:
            self.engine.stop(notify=False, release_driver=True)
        except Exception as exc:
            self._update_shutdown_ok = False
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
    "accent2": _theme.XRAY_BLUE, "purple": "#7c3cff", "success": "#23f5a6",
    "warning": "#ffd166", "danger": "#ff5c7c", "muted": "#9fb4d8",
    "text": "#f4f8ff", "checkicon": str(ASSETS / "ui" / "check.svg").replace("\\", "/"),
    "chevronicon": str(ASSETS / "ui" / "chevron-down.svg").replace("\\", "/"),
}

STYLE = """
* { font-family: "Inter", "Vazirmatn UI FD", "Segoe UI"; font-size: 13px; color: $text; outline: 0; }
QWidget { background: transparent; }
QMainWindow, QWidget#windowRoot { background: $background; }
QWidget#page, QWidget#pageBody, QStackedWidget#content, QFrame#contentShell, QFrame#activityWrap { background: transparent; }
QScrollArea#pageScroll, QScrollArea#pageScroll > QWidget, QScrollArea#pageScroll > QWidget > QWidget,
QScrollArea#homePage, QScrollArea#homePage > QWidget, QScrollArea#homePage > QWidget > QWidget { background: transparent; border: 0; }
*[technical="true"] { font-family: "JetBrains Mono", "Vazirmatn UI FD", "Consolas"; }
QToolTip { background: #102441; color: #eafaff; border: 1px solid #326789; border-radius: 8px; padding: 7px 10px; }
QToolButton#helpDot { background: rgba(16,52,80,0.88); color: #78eefa; border: 1px solid rgba(54,211,255,0.36); border-radius: 12px; font-size: 13px; font-weight: 900; padding: 0; }
QToolButton#helpDot:hover, QToolButton#helpDot:focus { background: rgba(22,91,110,0.95); color: #ffffff; border-color: #23f5e0; }

QFrame#sidebar { background: qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 rgba(7,23,42,248),stop:0.5 rgba(5,17,34,250),stop:1 rgba(5,12,27,252)); border-right: 1px solid $border; }
QFrame#sidebar[rtl="true"] { border-right: 0; border-left: 1px solid $border; }
QLabel#version { color: #59e9f0; font-size: 10px; font-weight: 800; letter-spacing: 1.5px; }
QPushButton#navButton { min-height: 0px; text-align: left; background: transparent; border: 1px solid transparent; border-radius: 14px; padding: 8px 29px 8px 16px; color: #b3c5dc; font-size: 14px; font-weight: 650; }
QPushButton#navButton[rtl="true"] { text-align: left; padding: 8px 16px 8px 29px; }
QPushButton#navButton:hover { background: rgba(18,50,76,0.72); border-color: rgba(54,211,255,0.18); color: #f7fcff; }
QPushButton#navButton:focus { border-color: $borderstrong; }
QPushButton#navButton:pressed { background: rgba(16,67,83,0.82); }
QPushButton#navButton:checked { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(6,105,111,0.74),stop:0.55 rgba(11,76,95,0.78),stop:1 rgba(19,43,73,0.72)); color: #d8fffb; border: 1px solid rgba(35,245,224,0.45); border-left: 3px solid $accent; font-weight: 850; }
QPushButton#navButton[rtl="true"]:checked { border-left: 1px solid rgba(35,245,224,0.45); border-right: 3px solid $accent; }
QFrame#sidebarFooter { background: rgba(7,24,45,0.82); border: 1px solid rgba(54,211,255,0.18); border-radius: 15px; }
QPushButton#footerAction { min-height: 0px; background: transparent; border: 1px solid transparent; border-radius: 10px; padding: 6px 11px; color: #b3c7dc; text-align: left; font-weight: 600; }
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
QLabel#originalConfigsLabel { background: rgba(4,20,43,0.96); border: 1px solid rgba(82,244,230,0.55); border-radius: 13px; padding: 7px 15px; color: #f4ffff; font-size: 13px; font-weight: 750; }
QComboBox#countryCombo:hover, QComboBox#countryCombo:focus { border-color: #67fff0; background: rgba(6,34,55,0.98); }
QComboBox#countryCombo:disabled { color: #7890aa; border-color: rgba(111,145,181,0.28); background: rgba(8,20,38,0.72); }
QComboBox#countryCombo QAbstractItemView { min-width: 350px; background: #091c35; border: 1px solid rgba(82,244,230,0.6); border-radius: 12px; padding: 7px; outline: 0; show-decoration-selected: 1; }
QComboBox#countryCombo QAbstractItemView::item { min-height: 38px; padding: 6px 12px; margin: 2px; border-radius: 8px; color: #eafcff; }
QComboBox#countryCombo QAbstractItemView::item:hover { background: rgba(22,83,102,0.86); }
QComboBox#countryCombo QAbstractItemView::item:selected { background: rgba(14,105,111,0.92); color: #ffffff; }

QLabel#fieldLabel { color: #a9bdd7; font-size: 11px; font-weight: 750; }
QFrame#quickControls { background: rgba(9,25,54,0.86); border: 1px solid rgba(54,211,255,0.24); border-radius: 18px; }
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
QLabel#gatewayDeviceName { color: #dffffa; font-size: 12px; font-weight: 850; }
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
QComboBox#countryCombo, QLabel#originalConfigsLabel { min-height: 20px; }
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
QLineEdit#numericEdit { background: transparent; border: 0; padding: 2px; font-family: "JetBrains Mono", "Vazirmatn UI FD", "Consolas"; font-weight: 500; color: #eaffff; }
QPushButton#numericStep { min-height: 30px; background: rgba(17,54,82,0.9); border: 0; border-radius: 7px; padding: 0; color: #72f3e7; font-size: 16px; font-weight: 850; }
QPushButton#numericStep:hover { background: #176079; color: white; }
QLabel#numericSuffix { color: #7f98b4; font-size: 10px; }

QFrame#pageToolbar, QFrame#makerTestBar { background: rgba(9,25,51,0.88); border: 1px solid rgba(54,211,255,0.2); border-radius: 15px; }
QFrame#tableFrame { background: rgba(7,21,43,0.86); border: 1px solid rgba(54,211,255,0.21); border-radius: 17px; }
QFrame#makerSourceCard { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(8,32,57,0.96),stop:1 rgba(8,23,48,0.94)); border: 1px solid rgba(54,211,255,0.27); border-radius: 17px; }
QFrame#makerResultsPanel { background: rgba(5,18,37,0.94); border: 1px solid rgba(54,211,255,0.24); border-radius: 17px; }
QFrame#makerResultToolbar { background: rgba(10,29,54,0.96); border: 0; border-bottom: 1px solid rgba(54,211,255,0.19); border-top-left-radius: 16px; border-top-right-radius: 16px; }
QFrame#makerActionBar { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(8,38,58,0.93),stop:1 rgba(18,25,65,0.92)); border: 1px solid rgba(54,211,255,0.27); border-radius: 15px; }
QLabel#makerStepTitle { color: #b9fff8; font-size: 12px; font-weight: 850; padding: 0 2px; }
QLabel#makerChip { border-radius: 9px; padding: 3px 9px; font-size: 11px; font-weight: 800; background: rgba(120,160,200,0.10); border: 1px solid rgba(120,160,200,0.22); color: #afc5dc; }
QLabel#makerChip[tone="ok"] { color: #45f3b4; background: rgba(69,243,180,0.10); border-color: rgba(69,243,180,0.35); }
QLabel#makerChip[tone="bad"] { color: #ff8798; background: rgba(255,135,152,0.09); border-color: rgba(255,135,152,0.32); }
QLabel#makerChip[tone="ech"] { color: #c4b5fd; background: rgba(196,181,253,0.11); border-color: rgba(196,181,253,0.38); }
QLabel#makerEmptyHint { color: rgba(175,197,220,0.62); font-size: 13px; font-weight: 600; background: transparent; }
QTabBar#routeSourceTabs::tab { min-height: 20px; padding: 4px 12px; margin: 0 2px; border-radius: 8px; font-size: 10px; }
QFrame#makerSourceCard QPushButton, QFrame#makerTestBar QPushButton, QFrame#makerResultToolbar QPushButton, QFrame#makerActionBar QPushButton { min-height: 26px; padding: 4px 9px; border-radius: 9px; }
QLineEdit#makerRepoUrl { min-height: 22px; padding: 4px 8px; }
QLineEdit#makerSearch { min-height: 30px; }
QComboBox#makerStatusFilter { min-width: 132px; }
QTableView#makerResultsTable { background: rgba(3,14,29,0.9); border: 0; border-radius: 0; padding: 0; alternate-background-color: rgba(8,25,46,0.82); gridline-color: transparent; }
QTableView#makerResultsTable::item { padding: 9px 10px; border-bottom: 1px solid rgba(54,211,255,0.09); }
QTableView#makerResultsTable::item:hover { background: rgba(15,53,76,0.78); }
QTableView#makerResultsTable::item:selected { background: rgba(9,83,88,0.82); color: #f8ffff; }
QWidget#sniMakerPage { background: #0a1423; }
QFrame#makerHeader { background: transparent; border: 0; }
QFrame#makerHeader QLabel#pageHeaderIcon { border-radius: 8px; }
QFrame#makerHeader QLabel#pageTitle { font-size: 24px; font-weight: 600; }
QFrame#makerHeader QLabel#pageSubtitle { font-size: 11px; font-weight: 500; color: #a8bdcf; }
#sniMakerPage QFrame#makerSourceCard, #sniMakerPage QFrame#makerTestBar,
#sniMakerPage QFrame#makerResultsPanel, #sniMakerPage QFrame#makerFooter {
    background: #0e1d2d; border: 1px solid #264253; border-radius: 8px;
}
#sniMakerPage QLabel#makerStepTitle { color: #e2eff8; font-size: 13px; font-weight: 600; padding: 0; }
#sniMakerPage QLabel#makerDetail { color: #9cb6ca; font-size: 11px; font-weight: 500; }
#sniMakerPage QLabel#scanStatus, #sniMakerPage QLabel#scanPercent { font-size: 11px; font-weight: 600; }
QFrame#makerProgress { background: transparent; border: 0; }
#sniMakerPage QFrame#makerResultToolbar, #sniMakerPage QFrame#makerFilters,
#sniMakerPage QFrame#makerActionBar { background: transparent; border: 0; border-radius: 0; }
#sniMakerPage QFrame#makerResultToolbar { border-bottom: 1px solid #264253; }
#sniMakerPage QFrame#makerActionBar { border-top: 1px solid #264253; }
#sniMakerPage QLabel#makerChip { background: transparent; border: 0; border-left: 1px solid #264253;
    border-radius: 0; padding: 1px 8px; font-size: 12px; font-weight: 600;
}
#sniMakerPage QLabel#makerChip[tone="total"] { color: #d9e8f3; }
#sniMakerPage QLineEdit#makerRepoUrl, #sniMakerPage QLineEdit#makerSearch,
#sniMakerPage QPlainTextEdit#makerSourceEditor, #sniMakerPage QComboBox#makerStatusFilter {
    background: #091725; border: 1px solid #2a4658; border-radius: 6px;
    min-height: 0; padding: 4px 8px; font-size: 12px; font-weight: 500;
}
#sniMakerPage QLineEdit#makerRepoUrl, #sniMakerPage QPlainTextEdit#makerSourceEditor {
    font-family: "JetBrains Mono", "Consolas", "Vazirmatn UI FD"; font-size: 11px;
}
#sniMakerPage QLineEdit:focus, #sniMakerPage QPlainTextEdit:focus,
#sniMakerPage QComboBox:focus { border-color: #3cb3bf; }
#sniMakerPage QComboBox#makerStatusFilter { min-width: 95px; padding-right: 24px; }
#sniMakerPage QFrame QPushButton { min-height: 32px; padding: 0 8px; border-radius: 6px; font-size: 12px; font-weight: 600; }
#sniMakerPage QPushButton#numericStep { min-height: 24px; padding: 0; font-size: 14px; border-radius: 5px; }
#sniMakerPage QPushButton[makerPrimary="true"]:enabled {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #1ad7ce,stop:1 #30c3e8);
    border: 1px solid #56e7ee; color: #062331;
}
#sniMakerPage QPushButton[makerPrimary="true"]:hover:enabled { background: #59e5eb; }
#sniMakerPage QPushButton#makerClearButton { background: #0b1b29; border-color: #2a4658; color: #f3aab9; }
#sniMakerPage QPushButton#makerClearButton:hover { background: #3b2133; border-color: #ad5670; }
#sniMakerPage QPushButton[guided="true"] { border: 1px solid #59d8df; font-weight: 600; }
#sniMakerPage QPushButton#secondaryAction[guided="true"] { background: #124453; color: #e3fffc; }
#sniMakerPage QTableView#makerResultsTable { background: #0a1827; alternate-background-color: #0c1b2a; }
#sniMakerPage QTableView#makerResultsTable::item { padding: 4px 8px; border-bottom: 1px solid #1b3346; }
#sniMakerPage QTableView#makerResultsTable QHeaderView::section {
    background: #112638; color: #b9d3e2; padding: 4px 8px; border-bottom: 1px solid #264253;
    font-size: 11px; font-weight: 600;
}
#sniMakerPage QTableView#makerResultsTable::indicator, #sniMakerPage QCheckBox#makerSelectAll::indicator {
    width: 12px; height: 12px; background: #0b1b29; border: 1px solid #4a7088; border-radius: 3px;
}
#sniMakerPage QTableView#makerResultsTable::indicator:checked, #sniMakerPage QCheckBox#makerSelectAll::indicator:checked {
    background: #1ad7ce; border-color: #6bf0e7; image: url("$checkicon");
}
#sniMakerPage QLabel#makerFooterSummary { color: #7be8db; font-size: 11px; font-weight: 500; }
QFrame#makerFooter QPushButton#quietButton { background: transparent; border-color: transparent; color: #76e8ed; }
QFrame#makerFooter QPushButton#quietButton:hover { background: #143548; border-color: #285466; }
QTabBar::tab { background: rgba(9,27,51,0.82); padding: 10px 23px; border: 1px solid transparent; border-radius: 10px; margin: 4px; color: $muted; font-weight: 650; }
QTabBar::tab:hover { background: rgba(18,53,80,0.82); color: $text; }
QTabBar::tab:selected { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(9,90,94,0.8),stop:1 rgba(13,52,76,0.82)); border-color: rgba(35,245,224,0.42); color: #bcfff8; font-weight: 850; }
QTabBar::tab:focus { border-color: $accent; }
QTabBar::tab:disabled { color: #425a73; background: #081525; }
QWidget#configsPage { background: #07111E; }
QFrame#configsHeader { background: transparent; border: 0; }
QFrame#configsHeader QLabel#pageHeaderIcon { border-radius: 8px; }
QFrame#configsHeader QLabel#pageTitle { font-size: 24px; font-weight: 600; }
QFrame#configsHeader QLabel#pageSubtitle, QLabel#configCount { font-size: 12px; font-weight: 500; color: #a6c0d4; }
QFrame#configToolbar, QFrame#configPanel {
    background: #0B1B2D; border: 1px solid #1E4057; border-radius: 8px;
}
QFrame#configTabsRow, QFrame#configTableFooter { background: transparent; border: 0; }
QFrame#configTabsRow { border-bottom: 1px solid #1E4057; }
QFrame#configTableFooter { border-top: 1px solid #1E4057; }
QFrame#configTableFooter QLabel { color: #a6c0d4; font-size: 12px; font-weight: 500; }
QFrame#configToolbar QPushButton, QFrame#configTableFooter QPushButton {
    background: #11283c; border: 1px solid #2b4a63; border-radius: 6px;
    min-height: 32px; padding: 0 8px; font-size: 12px; font-weight: 600;
}
QFrame#configToolbar QPushButton:hover, QFrame#configTableFooter QPushButton:hover,
QFrame#configToolbar QPushButton:focus, QFrame#configTableFooter QPushButton:focus {
    background: #15334a; border-color: #46DCE8;
}
QFrame#configToolbar QPushButton:disabled { background: #0a1a2a; color: #7893ab; }
QFrame#configToolbar QPushButton#addConfigButton {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #20dacd,stop:1 #38cce5);
    border-color: #68edf2; color: #071f2a;
}
QFrame#configToolbar QPushButton#addConfigButton:hover { background: #65e5eb; }
QFrame#configTableFooter QPushButton { min-height: 24px; color: #f2acb8; }
QLineEdit#configSearch, QComboBox#profileSortCombo {
    background: #081725; border: 1px solid #1E4057; border-radius: 6px;
    min-height: 22px; padding: 0 8px; font-size: 12px; font-weight: 500;
}
QComboBox#profileSortCombo { padding-right: 24px; }
QLineEdit#configSearch:focus, QComboBox#profileSortCombo:focus { border-color: #46DCE8; }
QTabBar#configSegments {
    background: #081725; border: 1px solid #1E4057; border-radius: 7px; padding: 3px;
}
QTabBar#configSegments::tab {
    background: transparent; border: 1px solid transparent; border-radius: 5px;
    padding: 4px 12px; margin: 0; color: #adc7da; font-size: 12px; font-weight: 600;
}
QTabBar#configSegments::tab:hover { background: #10293d; }
QTabBar#configSegments::tab:selected { background: #123a46; border-color: #357887; color: #b1fbff; }
QTableWidget#profileTable {
    background: #091725; alternate-background-color: #0c1b2b; border: 0; border-radius: 0;
    padding: 0; selection-background-color: #143245;
}
QTableWidget#profileTable::item { padding: 0 4px; border-bottom: 1px solid #1b3549; }
QTableWidget#profileTable::item:selected { background: #143245; }
QTableWidget#profileTable QHeaderView::section {
    background: #102437; color: #adc8dd; padding: 4px; border: 0;
    border-bottom: 1px solid #1E4057; font-size: 12px; font-weight: 500;
}
QTableWidget#profileTable::indicator, QCheckBox#profileSelectAll::indicator {
    width: 12px; height: 12px; background: #0b1b29; border: 1px solid #4a7088; border-radius: 3px;
}
QTableWidget#profileTable::indicator:checked, QCheckBox#profileSelectAll::indicator:checked {
    background: #46DCE8; border-color: #8aeff6; image: url("$checkicon");
}
QCheckBox#profileSelectAll::indicator:disabled { border-color: #2c485d; }
QLabel#configCellName { color: #e5eef7; font-family: "Inter", "Vazirmatn UI FD", "Segoe UI"; font-size: 13px; font-weight: 600; }
QLabel#configServer { color: #d6e6f3; font-family: "Inter", "Segoe UI"; font-size: 12px; font-weight: 500; }
QLabel#configCellDetail { color: #91adc4; font-size: 11px; font-weight: 500; }
QLabel#configPing { color: #91adc4; font-family: "Bahnschrift", "Segoe UI"; font-size: 14px; font-weight: 600; }
QLabel#configPing[quality="fast"] { color: #72e9b5; }
QLabel#configPing[quality="medium"] { color: #f0cb83; }
QLabel#configPing[quality="slow"] { color: #f2a1ae; }
QToolButton#profileRowActivate {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #20dacd,stop:1 #38cce5);
    color: #071f2a; border: 1px solid #68edf2; border-radius: 6px; padding: 0; font-weight: 600;
}
QToolButton#profileRowActivate:hover { background: #65e5eb; }
QToolButton#profileRowActivate[active="true"] { background: #143a47; border-color: #347c87; color: #a7f5ed; }
QToolButton#profileRowEdit, QToolButton#profileRowDelete {
    background: #102335; border: 1px solid #2b485e; border-radius: 6px; padding: 0;
}
QToolButton#profileRowEdit:hover, QToolButton#profileRowEdit:focus { border-color: #46DCE8; }
QToolButton#profileRowDelete:hover, QToolButton#profileRowDelete:focus { border-color: #f2a1ae; }
QCheckBox#profileSelectAll { background: transparent; border: 0; padding: 0; }

QLabel#helperText, QLabel#settingsSubtitle, QLabel#modalSubtitle { color: #aebfd5; font-size: 12px; }
QFrame#scanProgressPanel { background: rgba(8,25,49,0.9); border: 1px solid rgba(54,211,255,0.2); border-radius: 14px; }
QLabel#scanStatus { color: #a8bad0; font-size: 11px; font-weight: 800; }
QLabel#scanStatus[state="running"] { color: #71ecfa; }
QLabel#scanStatus[state="success"] { color: $success; }
QLabel#scanStatus[state="warning"] { color: $warning; }
QLabel#scanPercent { color: $accent; font-size: 15px; font-weight: 900; }
QLabel#scanDomain { color: #829bb5; font-family: "JetBrains Mono", "Vazirmatn UI FD", "Consolas"; font-size: 11px; }
QHeaderView::section { background: #0c203b; border: 0; border-bottom: 1px solid rgba(54,211,255,0.28); padding: 11px 10px; font-size: 11px; font-weight: 850; color: #a7eef4; }
QLabel#statusBadge { border-radius: 9px; padding: 3px 8px; font-size: 10px; font-weight: 850; }
QLabel#statusBadge[kind="success"] { color: #8ff8bc; background: rgba(8,59,43,0.8); border: 1px solid rgba(35,245,166,0.32); }
QLabel#statusBadge[kind="warning"] { color: #ffe09b; background: rgba(65,45,12,0.78); border: 1px solid rgba(255,209,102,0.35); }
QLabel#statusBadge[kind="danger"] { color: #ffadbc; background: rgba(66,17,37,0.78); border: 1px solid rgba(255,92,124,0.38); }
QLabel#statusBadge[kind="info"] { color: #9aebff; background: rgba(9,48,70,0.8); border: 1px solid rgba(44,199,255,0.32); }
QLabel#selectionText { color: #9bb0c8; font-size: 11px; font-weight: 700; }

QWidget#sniLabPage { background: #07111E; }
QFrame#labHeader { background: transparent; border: 0; }
QFrame#labHeader QLabel#pageHeaderIcon { border-radius: 8px; color: #46DCE8; }
QFrame#labHeader QLabel#pageTitle { font-size: 24px; font-weight: 600; }
QFrame#labHeader QLabel#pageSubtitle { color: #a6c0d4; font-size: 12px; font-weight: 500; }
#sniLabPage QFrame#domainPanel, #sniLabPage QFrame#scanOptions, #sniLabPage QFrame#labResults {
    background: #0B1B2D; border: 1px solid #1E4057; border-radius: 8px;
}
#sniLabPage QFrame#labToolbar, #sniLabPage QFrame#sniActionBar, #sniLabPage QFrame#labProgress {
    background: transparent; border: 0; border-radius: 0;
}
#sniLabPage QFrame#labToolbar { border-bottom: 1px solid #1E4057; }
#sniLabPage QFrame#labSelection { background: #102437; border-top: 1px solid #1E4057; border-bottom: 1px solid #1E4057; }
#sniLabPage QLabel#labStep { color: #e5eff7; font-size: 13px; font-weight: 600; }
#sniLabPage QLabel#labDetail, #sniLabPage QLabel#labProgressDetail, #sniLabPage QLabel#labState,
#sniLabPage QLabel#scanStatus, #sniLabPage QLabel#scanPercent, #sniLabPage QFrame#labSelection QLabel {
    color: #a6c0d4; font-size: 11px; font-weight: 500;
}
#sniLabPage QLabel#labState[state="running"], #sniLabPage QLabel#scanStatus[state="running"],
#sniLabPage QLabel#scanPercent, #sniLabPage QFrame#labSelection QLabel#labSelectedDomain { color: #46DCE8; }
#sniLabPage QLabel#labState[state="success"], #sniLabPage QLabel#scanStatus[state="success"],
#sniLabPage QLabel[tone="success"] { color: #64dfb7; }
#sniLabPage QLabel#labState[state="warning"], #sniLabPage QLabel#scanStatus[state="warning"],
#sniLabPage QLabel[tone="warning"] { color: #edcc79; }
#sniLabPage QLabel#labState[state="error"], #sniLabPage QLabel#scanStatus[state="error"],
#sniLabPage QLabel[tone="danger"] { color: #f298a4; }
#sniLabPage QLabel#labCount { font-size: 12px; font-weight: 600; }
#sniLabPage QLineEdit#labSearch, #sniLabPage QPlainTextEdit#domainEditor {
    background: #081725; border: 1px solid #28465d; border-radius: 6px;
    color: #dbeaf4; padding: 4px 7px; font-size: 12px; font-weight: 500;
}
#sniLabPage QLineEdit#labSearch { min-height: 24px; }
#sniLabPage QPlainTextEdit#domainEditor { font-family: "Consolas", "JetBrains Mono", "Vazirmatn UI FD"; font-size: 13px; padding: 4px; }
#sniLabPage QLineEdit#labSearch:focus, #sniLabPage QPlainTextEdit#domainEditor:focus { border-color: #46DCE8; }
#sniLabPage QFrame#numericInput { background: #081725; border: 1px solid #28465d; border-radius: 6px; }
#sniLabPage QLineEdit#numericEdit, #sniLabPage QLabel#scanPercent { font-family: "Bahnschrift", "Inter", "Segoe UI"; }
#sniLabPage QFrame QPushButton {
    background: #11283c; border: 1px solid #2b4a63; color: #dfedf6;
    min-height: 32px; padding: 0 7px; border-radius: 6px; font-size: 12px; font-weight: 600;
}
#sniLabPage QFrame QPushButton:hover { background: #19374b; border-color: #3a7085; }
#sniLabPage QFrame QPushButton:focus { border-color: #46DCE8; }
#sniLabPage QFrame QPushButton:disabled { background: #0a1928; border-color: #22394b; color: #829aaf; }
#sniLabPage QFrame QPushButton#numericStep { min-height: 22px; border: 0; padding: 0; font-size: 14px; color: #9fdbec; }
#sniLabPage QPushButton#labPrimary:enabled {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #20dacd,stop:1 #38cce5); border-color: #56e7ee; color: #071f2a;
}
#sniLabPage QPushButton#labPrimary:hover:enabled { background: #59e5eb; }
#sniLabPage QTableWidget#resultsTable {
    background: #081725; alternate-background-color: #0d1e2e; border: 0; border-radius: 0; padding: 0; gridline-color: transparent;
}
#sniLabPage QTableWidget#resultsTable::item {
    padding: 2px 5px; border-bottom: 1px solid #1b3549; color: #dbeaf4; font-size: 12px;
}
#sniLabPage QTableWidget#resultsTable::item:selected { background: #103441; color: #f1fafc; }
#sniLabPage QTableWidget#resultsTable QHeaderView::section {
    background: #112638; border: 0; border-bottom: 1px solid #1E4057;
    padding: 3px 4px; color: #b9d3e2; font-size: 11px; font-weight: 600;
}
#sniLabPage QCheckBox#rowSelector::indicator { width: 11px; height: 11px; border-radius: 6px; }
#sniLabPage QLabel#labMetric { color: #dbeaf4; font-family: "Bahnschrift", "Segoe UI"; font-size: 13px; font-weight: 600; }
#sniLabPage QLabel#labMetric[tone="success"] { color: #64dfb7; }
#sniLabPage QLabel#labMetric[tone="warning"] { color: #edcc79; }
#sniLabPage QLabel#labMetric[tone="danger"] { color: #f298a4; }
#sniLabPage QProgressBar#labStability { border: 0; border-radius: 2px; background: #294252; padding: 0; }
#sniLabPage QProgressBar#labStability::chunk { border-radius: 2px; background: #f298a4; }
#sniLabPage QProgressBar#labStability[tone="success"]::chunk { background: #64dfb7; }
#sniLabPage QProgressBar#labStability[tone="warning"]::chunk { background: #edcc79; }

QFrame#terminalCard { background: rgba(3,12,25,0.96); border: 1px solid rgba(54,211,255,0.24); border-radius: 17px; }
QFrame#terminalToolbar { background: rgba(9,27,49,0.96); border-bottom: 1px solid rgba(54,211,255,0.2); border-top-left-radius: 16px; border-top-right-radius: 16px; }
QLabel#terminalLive { color: $success; font-size: 10px; font-weight: 900; letter-spacing: 1.5px; }
QLineEdit#logFilter { min-height: 0px; max-height: 30px; padding: 0px 10px; border-radius: 10px; background: rgba(3,14,29,0.8); }
QFrame#logToolGroup { background: rgba(3,14,29,0.8); border: 1px solid rgba(138,163,191,0.22); border-radius: 10px; }
QFrame#logToolDivider { background: rgba(138,163,191,0.18); border: none; }
QToolButton#logToolButton, QToolButton#logToolButtonDanger { background: transparent; border: none; border-radius: 7px; padding: 0px; margin: 0px; }
QToolButton#logToolButton:hover { background: rgba(138,163,191,0.12); }
QToolButton#logToolButtonDanger:hover { background: rgba(255,107,125,0.13); }
QToolButton#logToolButton:pressed { background: rgba(138,163,191,0.2); }
QToolButton#logToolButtonDanger:pressed { background: rgba(255,107,125,0.22); }
QFrame#logSummary { background: rgba(9,27,49,0.92); border: 1px solid rgba(54,211,255,0.18); border-radius: 14px; }
QLabel#logSumCaption { color: #74879a; font-size: 11px; }
QLabel#logSumValue { color: #dce7f2; font-size: 13px; }
QLabel#logSumValueMono { color: #dce7f2; font-size: 12px; font-family: "JetBrains Mono", "Consolas"; }
QTextEdit#logs { font-family: "JetBrains Mono", "Vazirmatn UI FD", "Consolas"; font-size: 13px; color: #d7e8f5; background: qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 rgba(2,10,22,0.99),stop:1 rgba(3,15,28,0.99)); border: 0; border-radius: 0; padding: 18px; selection-background-color: #12646b; }
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
QLabel#versionChip { color: #9ffdf5; background: rgba(8,69,78,0.56); border: 1px solid rgba(72,236,225,0.28); border-radius: 7px; padding: 0px 6px; font-size: 10px; font-weight: 800; }
QPushButton#powExitSelector { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(12,40,70,0.98),stop:1 rgba(7,24,48,0.98)); border: 1px solid rgba(54,211,255,0.30); border-radius: 16px; padding: 0; text-align: left; }
QPushButton#powExitSelector:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(15,56,88,0.99),stop:1 rgba(9,34,62,0.99)); border-color: rgba(103,255,240,0.75); }
QPushButton#powExitSelector:pressed { background: rgba(6,22,42,0.99); border-color: #67fff0; }
QPushButton#powExitSelector:focus { border-color: rgba(103,255,240,0.85); }
QLabel#powExitTitle { color: #f4ffff; font-size: 14px; font-weight: 850; background: transparent; }
QLabel#powExitSubtitle { color: #86a6c4; font-size: 11px; font-weight: 600; background: transparent; }
QLabel#powExitBadge, QLabel#powExitChevron { background: transparent; }
QLabel#powExitChevron { border-radius: 13px; }
QPushButton#powExitSelector:hover QLabel#powExitChevron { background: rgba(103,255,240,0.12); }
QFrame#powCard { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(11,32,63,0.94),stop:1 rgba(7,22,44,0.9)); border: 1px solid rgba(54,211,255,0.22); border-radius: 19px; }
QFrame#powStatusCard { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(8,42,62,0.94),stop:0.7 rgba(8,27,55,0.95),stop:1 rgba(32,18,75,0.85)); border: 1px solid rgba(54,211,255,0.32); border-radius: 21px; }
QLabel#powCardTitle { color: #f7fcff; font-size: 18px; font-weight: 880; }
QLabel#powState { color: #f7fdff; font-size: 24px; font-weight: 900; }
QLabel#powDetail, QLabel#powRoute, QLabel#powExit, QLabel#powHint, QLabel#powStep, QLabel#powIdentityDetail { color: #b4c7dc; font-size: 13px; font-weight: 500; }
QLabel#powIdentityState { color: #f7fcff; font-size: 15px; font-weight: 800; }
QLabel#powFieldLabel { color: #9fb4d8; font-size: 13px; font-weight: 700; }
QComboBox#powCombo { background: rgba(7,20,38,0.9); border: 1px solid rgba(54,211,255,0.25); border-radius: 10px; padding: 8px 12px; color: #eaf4ff; }
QDialog#powSettingsDialog, QDialog#powCountryPicker { background: #071225; }
QFrame#powDialogHeader { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(12,43,72,0.98),stop:0.68 rgba(8,32,59,0.98),stop:1 rgba(19,35,74,0.96)); border-bottom: 1px solid rgba(54,211,255,0.28); }
QLabel#powDialogIcon { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(12,76,87,0.82),stop:1 rgba(12,39,75,0.84)); border: 1px solid rgba(35,245,224,0.34); border-radius: 11px; }
QLabel#powDialogTitle { color: #f7fcff; font-size: 17px; font-weight: 900; }
QLabel#powDialogSubtitle { color: #8fa9c6; font-size: 12px; font-weight: 500; }
QToolButton#powDialogClose { color: #9fb4d8; background: transparent; border: 1px solid transparent; border-radius: 9px; font-size: 14px; font-weight: 800; }
QToolButton#powDialogClose:hover { color: #ffffff; background: rgba(255,92,124,0.16); border-color: rgba(255,92,124,0.45); }
QScrollArea#powDialogScroll, QScrollArea#powDialogScroll > QWidget, QScrollArea#powDialogScroll > QWidget > QWidget { background: #071225; border: 0; }
QLabel#powLearnedLine { color: #b4c7dc; font-size: 12px; font-weight: 600; }
QFrame#powSegmented { background: rgba(4,16,32,0.92); border: 1px solid rgba(54,211,255,0.22); border-radius: 10px; }
QFrame#settingsCard QFrame#powSegmented { background: rgba(4,16,32,0.92); }
QPushButton#powSegment { background: transparent; border: 0; border-radius: 7px; color: #9fb4d8; padding: 5px 11px; min-height: 18px; font-size: 12px; font-weight: 700; }
QPushButton#powSegment:hover { background: rgba(22,83,102,0.55); color: #eafcff; }
QPushButton#powSegment:checked { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(14,105,111,0.95),stop:1 rgba(20,74,120,0.95)); color: #ffffff; }
QPushButton#powCountryButton { text-align: left; background: rgba(4,20,43,0.96); border: 1px solid rgba(82,244,230,0.55); border-radius: 13px; padding: 7px 15px; color: #f4ffff; font-size: 13px; font-weight: 750; }
QPushButton#powCountryButton:hover { border-color: #67fff0; background: rgba(6,34,55,0.98); }
QLineEdit#powCountrySearch { background: rgba(4,16,32,0.92); border: 1px solid rgba(54,211,255,0.28); border-radius: 10px; padding: 8px 12px; color: #eaf4ff; font-size: 13px; }
QLineEdit#powCountrySearch:focus { border-color: #67fff0; }
QListWidget#powCountryList { background: #091c35; border: 1px solid rgba(54,211,255,0.22); border-radius: 12px; padding: 6px; outline: 0; color: #eafcff; font-size: 13px; }
QListWidget#powCountryList::item { padding: 4px 10px; margin: 1px; border-radius: 8px; }
QListWidget#powCountryList::item:hover { background: rgba(22,83,102,0.86); }
QListWidget#powCountryList::item:selected { background: rgba(14,105,111,0.92); color: #ffffff; }
QLabel#powPickerCount { color: #9ffdf5; background: rgba(8,69,78,0.56); border: 1px solid rgba(72,236,225,0.25); border-radius: 9px; padding: 2px 8px; font-size: 10px; font-weight: 800; }
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

QDialog#closeChoiceDialog, QMessageBox, QMessageBox#cyberMessageBox { background: #071225; border: 1px solid rgba(54,211,255,0.32); }
QFrame#modalHeader { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(12,43,72,0.98),stop:0.68 rgba(8,32,59,0.98),stop:1 rgba(19,35,74,0.96)); border-bottom: 1px solid rgba(54,211,255,0.28); }
QFrame#modalFooter { background: rgba(5,18,36,0.98); border-top: 1px solid rgba(54,211,255,0.18); }
QScrollArea#modalScroll, QScrollArea#modalScroll > QWidget, QScrollArea#modalScroll > QWidget > QWidget { background: #071225; border: 0; }
QWidget#xraySettingsPage, QWidget#xraySettingsView { background: #07111E; }
QFrame#xraySettingsHeader { background: transparent; border: 0; }
QFrame#xraySettingsHeader QLabel#pageHeaderIcon { border-radius: 8px; background: #12364C; border: 1px solid #1E5269; }
QFrame#xraySettingsHeader QLabel#pageTitle { font-size: 24px; font-weight: 600; }
QFrame#xraySettingsHeader QLabel#pageSubtitle { color: #91ADC4; font-size: 12px; }
QWidget#xraySettingsView QTabWidget::pane, QWidget#xraySettingsView QScrollArea#pageScroll,
QWidget#xraySettingsView QWidget#pageBody { background: transparent; border: 0; }
QWidget#xraySettingsView QTabWidget#settingsTabs QTabBar { background: #0B1B2D; border: 1px solid #1E4057; border-radius: 8px; }
QWidget#xraySettingsView QTabWidget#settingsTabs QTabBar::tab {
    color: #A6C1D5; background: transparent; border: 1px solid transparent; min-height: 32px;
    padding: 0 11px; margin: 4px 3px; border-radius: 5px; font-size: 13px; font-weight: 500;
}
QWidget#xraySettingsView QTabWidget#settingsTabs QTabBar::tab:selected { color: #B9FCFF; background: #103642; border-color: #236C7D; }
QWidget#xraySettingsView QTabWidget#settingsTabs QTabBar::tab:focus { border-color: #46DCE8; }
QWidget#xraySettingsView QFrame#settingsCard { background: #0B1B2D; border: 1px solid #1E4057; border-radius: 8px; }
QWidget#xraySettingsView QFrame#settingsDivider { background: #1C344A; }
QWidget#xraySettingsView QLabel#settingsCardTitle { color: #E8F5FA; font-size: 14px; font-weight: 600; }
QWidget#xraySettingsView QLabel#settingsRowTitle { color: #DFEDF5; font-size: 13px; font-weight: 500; }
QWidget#xraySettingsView QLabel#settingsRowHelp, QWidget#xraySettingsView QLabel#settingsSubtitle { color: #91ADC4; font-size: 12px; }
QWidget#xraySettingsView QComboBox#settingsSelect, QWidget#xraySettingsView QLineEdit[technical="true"],
QWidget#xraySettingsView QPushButton#settingsAction, QWidget#xraySettingsView QPushButton#proxyPortReset,
QWidget#xraySettingsView QPushButton#xraySettingsSave {
    min-height: 32px; padding: 0 8px; border-radius: 6px; border: 1px solid #2A4A61;
    color: #DFEDF5; background: #0B1B2D; font-size: 12px; font-weight: 500;
}
QWidget#xraySettingsView QComboBox#settingsSelect { padding: 0 19px 0 8px; }
QWidget#xraySettingsView QFrame#numericInput { min-width: 0; background: #081726; border: 1px solid #2A4A61; border-radius: 6px; }
QWidget#xraySettingsView QPushButton#numericStep { min-height: 22px; border-radius: 4px; }
QWidget#xraySettingsView QPushButton#settingsAction:hover, QWidget#xraySettingsView QPushButton#proxyPortReset:hover { background: #12314A; border-color: #3B6F82; }
QWidget#xraySettingsView QComboBox#settingsSelect:focus, QWidget#xraySettingsView QLineEdit[technical="true"]:focus,
QWidget#xraySettingsView QPushButton#settingsAction:focus, QWidget#xraySettingsView QPushButton#proxyPortReset:focus { border-color: #46DCE8; }
QWidget#xraySettingsView QPushButton#settingsAction:disabled, QWidget#xraySettingsView QLineEdit[technical="true"]:disabled,
QWidget#xraySettingsView QComboBox#settingsSelect:disabled { color: #70889C; }
QWidget#xraySettingsView QToolButton#helpDot { min-width: 0; min-height: 0; margin: 0; padding: 0; border-radius: 8px; }
QLabel#xraySettingsTip { color: #A6C1D5; background: #0A1E2D; border: 1px solid #1E4057; border-radius: 8px; padding: 9px 12px; }
QFrame#xraySettingsFooter { border-top: 1px solid #1E4057; }
QWidget#xraySettingsView QPushButton#xraySettingsSave {
    color: #082332; background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #27DBD6,stop:1 #36C7E7); border-color: #69E5EF;
}
QWidget#xraySettingsView QPushButton#xraySettingsSave:hover,
QWidget#xraySettingsView QPushButton#xraySettingsSave:focus { background: #69E5EF; }
QLabel#modalTitle { color: #f7fcff; font-size: 24px; font-weight: 900; }
QLabel#settingsTitle { color: #edfaff; font-size: 15px; font-weight: 850; }
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

QFrame#assistantHelpCard { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(8,48,61,0.96),stop:1 rgba(27,23,73,0.94)); border: 1px solid rgba(35,245,224,0.34); border-radius: 18px; }
QFrame#assistantBubble { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(7,30,54,0.99),stop:1 rgba(18,26,67,0.99)); border: 2px solid rgba(64,240,226,0.78); border-radius: 20px; }
QScrollArea#assistantBubbleTextScroll, QScrollArea#assistantBubbleTextScroll > QWidget, QScrollArea#assistantBubbleTextScroll > QWidget > QWidget { background: transparent; border: 0; }
QLabel#assistantBubbleText { color: #f4fbff; font-size: 14px; font-weight: 650; line-height: 1.5; padding: 2px; }
QPushButton#assistantBubbleButton { min-height: 30px; padding: 5px 11px; color: #dffcff; background: rgba(10,60,78,0.88); border: 1px solid rgba(54,211,255,0.42); border-radius: 9px; font-size: 11px; font-weight: 800; }
QPushButton#assistantBubbleButton:hover { color: #031422; background: #58f5e7; border-color: #dffffc; }
QFrame#assistantToggleOption { background: rgba(5,22,42,0.82); border: 1px solid rgba(54,211,255,0.18); border-radius: 12px; }
QFrame#assistantToggleOption:hover { border-color: rgba(35,245,224,0.48); background: rgba(9,38,58,0.92); }
QFrame#assistantPreferenceOption { background: rgba(4,22,40,0.62); border: 1px solid rgba(54,211,255,0.2); border-radius: 11px; }
QFrame#assistantPreferenceOption:hover { border-color: rgba(35,245,224,0.48); background: rgba(8,42,57,0.82); }

QScrollBar:vertical { background: rgba(5,15,30,0.72); width: 10px; margin: 2px; border-radius: 5px; }
QScrollBar::handle:vertical { background: #27516d; border-radius: 5px; min-height: 36px; }
QScrollBar::handle:vertical:hover { background: #387b93; }
QScrollBar:horizontal { background: rgba(5,15,30,0.72); height: 10px; margin: 2px; border-radius: 5px; }
QScrollBar::handle:horizontal { background: #27516d; border-radius: 5px; min-width: 36px; }
QScrollBar::handle:horizontal:hover { background: #387b93; }
QScrollBar::add-line, QScrollBar::sub-line, QScrollBar::add-page, QScrollBar::sub-page { width: 0; height: 0; background: transparent; }
"""
STYLE += GLOBAL_SETTINGS_STYLE
for _name, _value in sorted(COLOR_TOKENS.items(), key=lambda item: -len(item[0])):
    STYLE = STYLE.replace(f"${_name}", _value)

# UAC PoW look (mockup): same rules, green-black surfaces and mint accents.
STYLE = _fonts.finish_style(STYLE)
POW_STYLE = (
    _theme.map_css(STYLE) + _quick_controls.style(ENGINE_POW)
    + shared_global_settings_style(ENGINE_POW) + _eswitch.brand_style(ENGINE_POW) + app_routing_style(ENGINE_POW)
)
_POW_STYLE_CACHE = {"version": _theme.palette_version(), "style": POW_STYLE}


def pow_style() -> str:
    """PoW stylesheet for the current palette (rebuilt after set_palette)."""
    if _POW_STYLE_CACHE["version"] != _theme.palette_version():
        _POW_STYLE_CACHE["version"] = _theme.palette_version()
        _POW_STYLE_CACHE["style"] = (
            _theme.map_css(STYLE) + _quick_controls.style(ENGINE_POW)
            + shared_global_settings_style(ENGINE_POW) + _eswitch.brand_style(ENGINE_POW) + app_routing_style(ENGINE_POW)
        )
    return _POW_STYLE_CACHE["style"]


_LOCAL_STYLE_CACHE: dict = {}


def app_style(pow_on: bool, language: str) -> str:
    """Engine theme + language font order (Vazirmatn first for fa)."""
    key = (bool(pow_on), language, _theme.palette_version())
    cached = _LOCAL_STYLE_CACHE.get(key)
    if cached is None:
        base = pow_style() if pow_on else (
            STYLE + _quick_controls.style(ENGINE_XRAY)
            + shared_global_settings_style(ENGINE_XRAY) + _eswitch.brand_style(ENGINE_XRAY)
            + app_routing_style(ENGINE_XRAY)
        )
        cached = _fonts.localize_style(base, language)
        _LOCAL_STYLE_CACHE[key] = cached
    return cached


_COMBINED_STYLE_CACHE: dict = {}


def combined_app_style(language: str) -> str:
    """Engine themes in one sheet, scoped by QMainWindow[engine=...].

    Installed once (per language); an engine switch then only flips the
    window's ``engine`` property instead of replacing the app stylesheet.
    """
    key = (language, _theme.palette_version())
    cached = _COMBINED_STYLE_CACHE.get(key)
    if cached is None:
        cached = _eswitch.combine_styles({
            ENGINE_XRAY: app_style(False, language),
            ENGINE_POW: app_style(True, language),
            ENGINE_DIRECT: _fonts.localize_style(
                _theme.map_css(STYLE, direct=True) + _direct_theme.STYLE
                + _quick_controls.style(ENGINE_DIRECT) + shared_global_settings_style(ENGINE_DIRECT)
                + _eswitch.brand_style(ENGINE_DIRECT) + app_routing_style(ENGINE_DIRECT),
                language,
            ),
        })
        _COMBINED_STYLE_CACHE[key] = cached
    return cached


def is_app_style(css: str) -> bool:
    return (css in (STYLE, POW_STYLE, pow_style()) or css in _LOCAL_STYLE_CACHE.values()
            or css in _COMBINED_STYLE_CACHE.values())
