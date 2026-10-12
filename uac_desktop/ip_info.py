"""Public-IP helpers for the Home IP card + the details dialog.

* direct mode (not connected): the real IP fetched *bypassing* any proxy, with
  the country/carrier taken from the wizard's weighted vote (Speedtest/ip-api
  first) so MCI's Azerbaijan transit egress still shows Iran.
* tunnel mode: the exit IP fetched through the local HTTP proxy of the active
  engine (Xray http_port or PoW forward port).
"""
from __future__ import annotations

import json
import threading

from PySide6.QtCore import QEvent, QObject, Qt, QTimer, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QDialog, QFrame, QGridLayout, QHBoxLayout, QLabel,
                               QPushButton, QVBoxLayout, QWidget)

FSI, PDI, RLM = "\u2068", "\u2069", "\u200f"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) UAC-Spoofer"

FA_EXTRA = {
    "IR": "ایران", "AZ": "آذربایجان", "TR": "ترکیه", "AE": "امارات", "AM": "ارمنستان",
    "IQ": "عراق", "RU": "روسیه", "US": "آمریکا", "GB": "انگلستان", "FR": "فرانسه",
    "NL": "هلند", "DE": "آلمان", "FI": "فنلاند", "SE": "سوئد", "CA": "کانادا",
    "JP": "ژاپن", "SG": "سنگاپور", "HK": "هنگ‌کنگ", "IN": "هند", "PL": "لهستان",
    "IT": "ایتالیا", "ES": "اسپانیا", "AT": "اتریش", "CH": "سوئیس", "QA": "قطر",
    "OM": "عمان", "KW": "کویت", "SA": "عربستان", "GE": "گرجستان", "KZ": "قزاقستان",
    "BG": "بلغارستان", "RO": "رومانی", "UA": "اوکراین", "LT": "لیتوانی", "LV": "لتونی",
    "EE": "استونی", "NO": "نروژ", "DK": "دانمارک", "BE": "بلژیک", "CZ": "چک",
    "AU": "استرالیا", "KR": "کره جنوبی", "BR": "برزیل", "IL": "اسرائیل",
}


def iso(text) -> str:
    return f"{FSI}{text}{PDI}"


def country_name(code: str, fa: bool = True) -> str:
    code = str(code or "").upper()
    if not code:
        return ""
    try:
        from .verified_configs import COUNTRIES
        known = COUNTRIES.get(code)
        if known:
            return known[2] if fa else known[1]
    except Exception:
        pass
    if fa and code in FA_EXTRA:
        return FA_EXTRA[code]
    try:
        from .pow.regions import ALL_NAMES
        return ALL_NAMES.get(code, code)
    except Exception:
        return code


def _session(proxy_port=None):
    import requests
    s = requests.Session(); s.trust_env = False  # never inherit the system proxy
    s.headers.update({"User-Agent": UA, "Accept": "application/json"})
    if proxy_port:
        url = f"http://127.0.0.1:{int(proxy_port)}"
        s.proxies = {"http": url, "https": url}
    return s


def _norm_ipinfo(d):
    org = str(d.get("org") or "")
    asn, _, name = org.partition(" ")
    loc = d.get("loc") or ""
    return {"ip": d.get("ip", ""), "city": d.get("city", ""), "region": d.get("region", ""),
            "country": str(d.get("country", "")).upper(), "org": name if asn.startswith("AS") else org,
            "asn": asn if asn.startswith("AS") else "", "timezone": d.get("timezone", ""),
            "hostname": d.get("hostname", ""), "loc": loc, "source": "ipinfo.io"}


def _norm_ipwho(d):
    if d.get("success") is False:
        raise ValueError(d.get("message") or "ipwho failed")
    conn = d.get("connection") or {}
    tz = d.get("timezone") or {}
    return {"ip": d.get("ip", ""), "city": d.get("city", ""), "region": d.get("region", ""),
            "country": str(d.get("country_code", "")).upper(), "org": conn.get("org") or conn.get("isp") or "",
            "asn": f"AS{conn['asn']}" if conn.get("asn") else "", "timezone": tz.get("id", "") if isinstance(tz, dict) else str(tz),
            "hostname": "", "source": "ipwho.is"}


def _norm_ipapi(d):
    if d.get("status") == "fail":
        raise ValueError(d.get("message") or "ip-api failed")
    asn = str(d.get("as") or "").split(" ")[0]
    return {"ip": d.get("query", ""), "city": d.get("city", ""), "region": d.get("regionName", ""),
            "country": str(d.get("countryCode", "")).upper(), "org": d.get("isp") or d.get("org") or "",
            "asn": asn if asn.startswith("AS") else "", "timezone": d.get("timezone", ""),
            "hostname": d.get("reverse", ""), "source": "ip-api.com"}


DETAIL_SOURCES = (
    ("https://ipwho.is/", _norm_ipwho),
    ("http://ip-api.com/json/?fields=status,message,query,city,regionName,countryCode,isp,org,as,timezone,reverse", _norm_ipapi),
    ("https://ipinfo.io/json", _norm_ipinfo),
)

# ipinfo.io does not answer on some Iranian networks: after one failure it is
# skipped for a while instead of burning a timeout on every lookup.
_IPINFO_DEAD = {"until": 0.0}
IPINFO_SKIP_S = 1800
_CACHE: dict = {}
CACHE_TTL_S = 600


def cache_get(key, ttl: float = CACHE_TTL_S):
    import time as _t
    hit = _CACHE.get(key)
    if hit and _t.time() - hit[0] < ttl:
        return dict(hit[1])
    return None


def cache_put(key, info):
    import time as _t
    if info and info.get("ip"):
        _CACHE[key] = (_t.time(), dict(info))


def _sources(include_ipinfo=True):
    import time as _t
    for url, norm in DETAIL_SOURCES:
        if "ipinfo.io" in url and (not include_ipinfo or _t.time() < _IPINFO_DEAD["until"]):
            continue
        yield url, norm


def fetch_details(proxy_port=None, timeout: float = 4.0, get=None, include_ipinfo=True) -> dict:
    """ipwho.is -> ip-api -> ipinfo (skipped when known-unreachable)."""
    import time as _t
    errors = []
    session = None
    for url, norm in _sources(include_ipinfo):
        try:
            if get is not None:
                data = get(url, proxy_port)
            else:
                session = session or _session(proxy_port)
                data = session.get(url, timeout=timeout).json()
            info = norm(data)
            if info.get("ip") and info.get("country"):
                if ":" in info["ip"] and get is None:
                    # IPv6 exit: ask about the IPv4 one (shorter, matches the card)
                    try:
                        v4 = session.get("https://api.ipify.org?format=json", timeout=timeout).json().get("ip", "")
                        if v4:
                            info2 = norm(session.get(url.replace("ipwho.is/", f"ipwho.is/{v4}"), timeout=timeout).json()) if "ipwho" in url else None
                            info = info2 if info2 and info2.get("country") else dict(info, ip=v4)
                    except Exception:
                        pass
                return info
            errors.append(f"{url.split('/')[2]}: incomplete answer")
        except Exception as exc:
            if "ipinfo.io" in url:
                _IPINFO_DEAD["until"] = _t.time() + IPINFO_SKIP_S
            errors.append(f"{url.split('/')[2]}: {exc}")
    raise RuntimeError("; ".join(errors) or "no source answered")


def fetch_fast(proxy_port=None, timeout: float = 3.0, get=None) -> dict:
    """Card lookup: one fast source (ipwho.is, then ip-api), 3s each, no ipinfo."""
    return fetch_details(proxy_port, timeout=timeout, get=get, include_ipinfo=False)


def direct_identity(timeout: float = 6.0, identity_fn=None, details_fn=None) -> dict:
    """Real (direct) IP + weighted-vote carrier/country (Iran beats transit)."""
    out: dict = {}

    def ident():
        try:
            if identity_fn is not None:
                out["id"] = identity_fn()
            else:
                from .first_run_wizard import lookup_identity
                out["id"] = lookup_identity(timeout=timeout)
        except Exception:
            out["id"] = {}

    t = threading.Thread(target=ident, daemon=True); t.start()
    try:
        info = (details_fn or fetch_details)(None)
    except Exception as exc:
        info = {"ip": "", "error": str(exc)}
    t.join(timeout + 4)
    idv = out.get("id") or {}
    country = str(idv.get("country") or "").upper()
    if not country and idv.get("family") in {"mci", "irancell", "tci", "rightel", "shatel"}:
        country = "IR"
    if country:
        if info.get("country") and info["country"] != country:
            info["geo_country"] = info["country"]
        info["country"] = country
    info["carrier_fa"] = idv.get("fa", "") if idv.get("fa") not in ("", "-") else ""
    info["carrier_en"] = idv.get("en", "") if idv.get("en") not in ("", "-") else ""
    if idv.get("asn") and not info.get("asn"):
        info["asn"] = idv["asn"]
    info["mode"] = "direct"
    return info


def card_subtitle(info: dict, fa: bool, kind: str = "") -> str:
    """'ایران، همراه اول' / 'آلمان، تونل Xray' (RTL-safe)."""
    name = country_name(info.get("country", ""), fa)
    if info.get("mode") == "direct":
        tail = (info.get("carrier_fa") if fa else info.get("carrier_en")) or ""
        if not tail:
            tail = "اتصال مستقیم" if fa else "Direct connection"
    else:
        tail = kind or ("تونل" if fa else "Tunnel")
    if fa:
        parts = [p for p in (name, tail) if p]
        return RLM + "، ".join(iso(p) if p.isascii() else p for p in parts)
    return " · ".join(p for p in (name, tail) if p)


# ------------------------------------------------------------------ clickable card
class ClickableCard(QObject):
    def __init__(self, card, callback):
        super().__init__(card)
        self.card = card; self.callback = callback
        card.setCursor(Qt.PointingHandCursor)
        card.setAttribute(Qt.WA_Hover, True)
        extra = ('QFrame#metricCard[ipHot="true"] { border: 1px solid rgba(35,245,224,0.55);'
                 ' background-color: rgba(35,245,224,0.055); }')
        card.setStyleSheet((card.styleSheet() or "") + extra)
        card.installEventFilter(self)

    def _hot(self, on):
        self.card.setProperty("ipHot", bool(on))
        self.card.style().unpolish(self.card); self.card.style().polish(self.card); self.card.update()

    def eventFilter(self, obj, event):
        t = event.type()
        if t == QEvent.Enter:
            self._hot(True)
        elif t == QEvent.Leave:
            self._hot(False)
        elif t == QEvent.MouseButtonRelease and event.button() == Qt.LeftButton:
            if self.card.rect().contains(event.position().toPoint()):
                QTimer.singleShot(0, self.callback)
        return False


# ------------------------------------------------------------------ dialog
ACCENT = "#23f5e0"


def icon_tile(name, size=28, glyph=15, color=ACCENT):
    """App vector line icon in a small rounded accent-tinted tile."""
    tile = QLabel(); tile.setObjectName("ipTile"); tile.setFixedSize(size, size)
    tile.setAlignment(Qt.AlignCenter)
    radius = max(7, size // 3)
    tile.setStyleSheet(f"QLabel#ipTile {{ background: rgba(35,245,224,0.10); border: 1px solid rgba(35,245,224,0.28);"
                       f" border-radius: {radius}px; }}")
    try:
        from .icons import pixmap as _pix
        tile.setPixmap(_pix(name, color, glyph))
    except Exception:
        pass
    return tile


def button_icon(name, color="#eaffff", size=16):
    try:
        from .icons import icon as _icon
        return _icon(name, color, size)
    except Exception:
        return None


class _Relay(QObject):
    done = Signal(object)
    failed = Signal(str)


FA_CITIES = {
    "karaj": "کرج", "tehran": "تهران", "mashhad": "مشهد", "isfahan": "اصفهان", "esfahan": "اصفهان",
    "shiraz": "شیراز", "tabriz": "تبریز", "qom": "قم", "ahvaz": "اهواز", "kermanshah": "کرمانشاه",
    "rasht": "رشت", "urmia": "ارومیه", "zahedan": "زاهدان", "hamadan": "همدان", "yazd": "یزد",
    "ardabil": "اردبیل", "bandar abbas": "بندرعباس", "arak": "اراک", "zanjan": "زنجان",
    "sanandaj": "سنندج", "qazvin": "قزوین", "kerman": "کرمان", "gorgan": "گرگان", "sari": "ساری",
    "singapore": "سنگاپور", "frankfurt": "فرانکفورت", "frankfurt am main": "فرانکفورت",
    "amsterdam": "آمستردام", "london": "لندن", "paris": "پاریس", "helsinki": "هلسینکی",
    "stockholm": "استکهلم", "istanbul": "استانبول", "dubai": "دبی", "tokyo": "توکیو",
    "hong kong": "هنگ‌کنگ", "los angeles": "لس‌آنجلس", "new york": "نیویورک", "moscow": "مسکو",
    "vienna": "وین", "zurich": "زوریخ", "warsaw": "ورشو", "baku": "باکو", "toronto": "تورنتو",
    "berlin": "برلین", "nuremberg": "نورنبرگ", "falkenstein": "فالکنشتاین", "ashburn": "اشبرن",
}
FA_REGIONS = {
    "alborz": "البرز", "tehran": "تهران", "razavi khorasan": "خراسان رضوی", "isfahan": "اصفهان",
    "fars": "فارس", "east azerbaijan": "آذربایجان شرقی", "west azerbaijan": "آذربایجان غربی",
    "khuzestan": "خوزستان", "gilan": "گیلان", "mazandaran": "مازندران", "qom": "قم", "kerman": "کرمان",
    "yazd": "یزد", "hamadan": "همدان", "kermanshah": "کرمانشاه", "golestan": "گلستان", "qazvin": "قزوین",
    "markazi": "مرکزی", "hormozgan": "هرمزگان", "kurdistan": "کردستان", "zanjan": "زنجان",
    "ardabil": "اردبیل", "sistan and baluchestan": "سیستان و بلوچستان", "central singapore": "سنگاپور مرکزی",
    "hesse": "هسن", "north holland": "هلند شمالی", "england": "انگلستان", "ile-de-france": "ایل‌دوفرانس",
    "île-de-france": "ایل‌دوفرانس", "bavaria": "باواریا", "uusimaa": "اوسیما", "stockholm": "استکهلم",
}
_FA_DIGITS = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")


def _clean_region(name):
    low = str(name or "").strip().lower()
    for suffix in (" province", " ostan", " region", " state"):
        if low.endswith(suffix):
            low = low[: -len(suffix)]
    return low


def place_fa(text, table, clean=None):
    raw = str(text or "").strip()
    if not raw:
        return ""
    key = clean(raw) if clean else raw.lower()
    hit = table.get(key)
    return hit if hit else iso(raw)


def location_text(info, fa=True):
    city, region, code = info.get("city", ""), info.get("region", ""), info.get("country", "")
    if fa:
        parts = [place_fa(city, FA_CITIES), place_fa(region, FA_REGIONS, _clean_region), country_name(code, True)]
    else:
        parts = [city, region, country_name(code, False)]
    out = []
    for p in parts:
        if p and p not in out:
            out.append(p)
    return (RLM + "، ".join(out)) if fa else ", ".join(out)


def tz_offset(tz):
    try:
        from datetime import datetime
        from zoneinfo import ZoneInfo
        off = datetime.now(ZoneInfo(tz)).utcoffset()
    except Exception:
        return ""
    minutes = int(off.total_seconds() // 60)
    sign = "+" if minutes >= 0 else "-"
    minutes = abs(minutes)
    return f"UTC{sign}{minutes // 60}" + (f":{minutes % 60:02d}" if minutes % 60 else "")


def timezone_text(tz, fa=True):
    tz = str(tz or "")
    if not tz:
        return ""
    city = tz.split("/")[-1].replace("_", " ")
    off = tz_offset(tz)
    if fa:
        name = FA_CITIES.get(city.lower()) or iso(city)
        return RLM + name + (f" \u2066({off})\u2069" if off else "")  # LRI..PDI keeps the parentheses intact
    return city + (f" ({off})" if off else "")


class IpDetailsDialog(QDialog):
    """Small non-modal RTL details window (ipinfo.io / ipwho.is via the active tunnel)."""

    def __init__(self, parent, fa: bool, loader, mode_label: str = ""):
        super().__init__(parent)
        self.fa = fa; self.loader = loader; self.info = {}
        self.setObjectName("ipDetails")
        self.setWindowTitle("جزئیات آی‌پی" if fa else "IP details")
        self.setLayoutDirection(Qt.RightToLeft if fa else Qt.LeftToRight)
        self.setModal(False); self.setAttribute(Qt.WA_DeleteOnClose, True)
        self.setFixedWidth(430)
        self.setStyleSheet(
            "QDialog#ipDetails { background: #0b1626; }"
            "QLabel { color: #d9eaf7; font-size: 12px; background: transparent; }"
            "QLabel#ipTitle { font-size: 13px; font-weight: 800; color: #9fe9e0; }"
            "QFrame#ipHero { border-radius: 16px; border: 1px solid rgba(35,245,224,0.30);"
            " background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 rgba(35,245,224,0.16), stop:1 rgba(63,125,255,0.10)); }"
            "QLabel#ipBig { font-family: 'JetBrains Mono','Consolas'; font-size: 22px; font-weight: 800; color: #eaffff; }"
            "QLabel#ipChip { color: #04111f; font-weight: 800; font-size: 11px; border-radius: 10px; padding: 3px 11px;"
            " background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #19d9c6, stop:1 #3f7dff); }"
            "QLabel#ipKey { color: #8fa9bf; }"
            "QLabel#ipVal { color: #eaf6ff; font-weight: 600; }"
            "QLabel#asnChip { font-family: 'Inter','Segoe UI','Consolas'; color: #c4b5fd; font-size: 10px; font-weight: 800;"
            " border: 1px solid rgba(196,181,253,0.55); border-radius: 8px; padding: 1px 7px; background: rgba(196,181,253,0.08); }"
            "QFrame#ipPanel { background: rgba(255,255,255,0.035); border: 1px solid rgba(35,245,224,0.18); border-radius: 14px; }"
            "QPushButton#ipAction { background: rgba(35,245,224,0.12); color: #eaffff; border: 1px solid rgba(35,245,224,0.40);"
            " border-radius: 11px; padding: 7px 16px; font-weight: 700; }"
            "QPushButton#ipAction:hover { background: rgba(35,245,224,0.22); }"
            "QPushButton#ipX { background: transparent; border: none; border-radius: 14px; }"
            "QPushButton#ipX:hover { background: rgba(255,255,255,0.08); }")
        root = QVBoxLayout(self); root.setContentsMargins(16, 14, 16, 14); root.setSpacing(12)
        top = QHBoxLayout(); top.setSpacing(8)
        top.addWidget(icon_tile("globe", 30, 17), 0, Qt.AlignVCenter)
        self.title = QLabel(RLM + ("جزئیات آی‌پی عمومی" if fa else "Public IP details")); self.title.setObjectName("ipTitle")
        self.title.setAlignment((Qt.AlignRight if fa else Qt.AlignLeft) | Qt.AlignVCenter)
        self.title.ensurePolished(); self.title.setFixedWidth(self.title.fontMetrics().horizontalAdvance(self.title.text()) + 12)
        top.addWidget(self.title, 0, Qt.AlignVCenter); top.addStretch(1)
        self.x_btn = QPushButton(); self.x_btn.setObjectName("ipX"); self.x_btn.setFixedSize(28, 28)
        self.x_btn.setCursor(Qt.PointingHandCursor); self.x_btn.setToolTip("بستن" if fa else "Close")
        ic = button_icon("x-circle", "#9fb4d8", 18)
        if ic is not None:
            self.x_btn.setIcon(ic)
        else:
            self.x_btn.setText("✕")
        self.x_btn.clicked.connect(self.close)
        top.addWidget(self.x_btn, 0, Qt.AlignVCenter)
        root.addLayout(top)
        # hero
        self.hero = QFrame(); self.hero.setObjectName("ipHero")
        try:
            from PySide6.QtWidgets import QGraphicsDropShadowEffect
            from PySide6.QtGui import QColor
            glow = QGraphicsDropShadowEffect(self.hero); glow.setBlurRadius(28); glow.setOffset(0, 0)
            glow.setColor(QColor(35, 245, 224, 70)); self.hero.setGraphicsEffect(glow)
        except Exception:
            pass
        hero = QVBoxLayout(self.hero); hero.setContentsMargins(16, 14, 16, 14); hero.setSpacing(8)
        line = QHBoxLayout(); line.setSpacing(12)
        self.flag = QLabel(); self.flag.setFixedSize(40, 28); self.flag.setVisible(False)
        self.big = QLabel("…"); self.big.setObjectName("ipBig"); self.big.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.big.setAlignment((Qt.AlignRight if fa else Qt.AlignLeft) | Qt.AlignVCenter)
        line.addWidget(self.flag); line.addWidget(self.big); line.addStretch(1)  # packed at the start edge
        hero.addLayout(line)
        chip_row = QHBoxLayout()
        self.mode = QLabel(mode_label); self.mode.setObjectName("ipChip")
        chip_row.addWidget(self.mode); chip_row.addStretch(1)
        hero.addLayout(chip_row)
        root.addWidget(self.hero)
        self.panel = QFrame(); self.panel.setObjectName("ipPanel")
        self.grid = QGridLayout(self.panel); self.grid.setContentsMargins(12, 10, 12, 10)
        self.grid.setHorizontalSpacing(10); self.grid.setVerticalSpacing(9)
        root.addWidget(self.panel)
        self.status = QLabel(); self.status.setWordWrap(True); self.status.setAlignment(Qt.AlignCenter)
        root.addWidget(self.status)
        row = QHBoxLayout()
        self.copy_btn = QPushButton("کپی آی‌پی" if fa else "Copy IP"); self.copy_btn.setObjectName("ipAction")
        self.retry_btn = QPushButton("تلاش دوباره" if fa else "Retry"); self.retry_btn.setObjectName("ipAction")
        for btn, name in ((self.copy_btn, "copy"), (self.retry_btn, "refresh")):
            btn.setCursor(Qt.PointingHandCursor)
            ic = button_icon(name)
            if ic is not None:
                btn.setIcon(ic)
        self.copy_btn.clicked.connect(self.copy_ip); self.retry_btn.clicked.connect(self.load)
        row.addWidget(self.copy_btn); row.addWidget(self.retry_btn); row.addStretch(1)
        root.addLayout(row)
        self.close_btn = self.x_btn  # compat
        self.relay = _Relay()  # parentless: outlives the dialog while a fetch finishes
        self.relay.done.connect(self.show_info); self.relay.failed.connect(self.show_error)
        self.load()

    def _clear(self):
        while self.grid.count():
            item = self.grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                lay = item.layout()
                while lay.count():
                    sub = lay.takeAt(0)
                    if sub.widget():
                        sub.widget().deleteLater()

    def load(self):
        self._clear(); self.big.setText("…"); self.flag.setVisible(False)
        self.copy_btn.setEnabled(False); self.retry_btn.setVisible(False)
        self.status.setStyleSheet("color: #8fa9bf;")
        self.status.setText(RLM + ("در حال دریافت اطلاعات…" if self.fa else "Loading details…"))
        self.status.setVisible(True); self.panel.setVisible(False)
        relay, loader = self.relay, self.loader

        def work():
            try:
                result = loader()
            except Exception as exc:
                try:
                    relay.failed.emit(str(exc))
                except RuntimeError:
                    pass
                return
            try:
                relay.done.emit(result)
            except RuntimeError:
                pass
        threading.Thread(target=work, name="ip-details", daemon=True).start()

    @staticmethod
    def _start(widget):
        """Pack a widget at the start edge (right in RTL) via layout, not text alignment."""
        box = QWidget(); hb = QHBoxLayout(box); hb.setContentsMargins(0, 0, 0, 0); hb.setSpacing(0)
        hb.addWidget(widget, 0); hb.addStretch(1)
        return box

    def _val(self, text, latin=False):
        text = str(text or "—")
        lab = QLabel((RLM + (iso(text) if latin else text)) if self.fa else text); lab.setObjectName("ipVal")
        if latin:
            lab.setStyleSheet("font-family: 'Inter', 'Segoe UI', 'Consolas';")  # fa font draws Persian digits
        lab.setTextInteractionFlags(Qt.TextSelectableByMouse); lab.setWordWrap(True)
        from PySide6.QtWidgets import QSizePolicy
        lab.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Preferred)
        lab.ensurePolished()
        lab.setFixedWidth(min(lab.fontMetrics().horizontalAdvance(text) + 10, 236))  # hug the text: never stretches, so it stays packed at the start edge
        # Absolute: a Latin-only label would otherwise flip to the far (left) edge.
        # fa: RLM makes every paragraph RTL, so AlignRight always lands on the right edge.
        lab.setAlignment((Qt.AlignRight if self.fa else Qt.AlignLeft) | Qt.AlignVCenter)
        return lab

    def _row(self, i, icon_name, key, value_widget):
        k = QLabel(key); k.setObjectName("ipKey"); k.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        k.setFixedWidth(78)
        self.grid.addWidget(icon_tile(icon_name), i, 0, Qt.AlignVCenter)
        self.grid.addWidget(k, i, 1, Qt.AlignVCenter)
        self.grid.addWidget(value_widget, i, 2)

    def show_info(self, info):
        self.info = info or {}
        fa = self.fa
        ip = self.info.get("ip") or "—"
        self.big.setText(RLM + iso(ip) if fa else ip)
        self.big.ensurePolished(); self.big.setFixedWidth(self.big.fontMetrics().horizontalAdvance(ip) + 12)
        code = str(self.info.get("country", "")).upper()
        if len(code) == 2:
            try:
                from .ui import country_flag_icon
                self.flag.setPixmap(country_flag_icon(code, 40, 28).pixmap(40, 28)); self.flag.setVisible(True)
            except Exception:
                self.flag.setVisible(False)
        i = 0
        loc = location_text(self.info, fa)
        if loc:
            self._row(i, "map-pin", "موقعیت" if fa else "Location", self._start(self._val(loc))); i += 1
        carrier = self.info.get("carrier_fa" if fa else "carrier_en")
        if carrier:
            self._row(i, "radio", "اپراتور" if fa else "Carrier", self._start(self._val(carrier, latin=carrier.isascii()))); i += 1
        asn, org = self.info.get("asn", ""), self.info.get("org", "")
        if asn or org:
            # Stacked: [AS chip] on top, org name under it, both on the start (right) edge.
            box = QWidget(); vb = QVBoxLayout(box); vb.setContentsMargins(0, 0, 0, 0); vb.setSpacing(4)
            edge = Qt.AlignRight if fa else Qt.AlignLeft
            if asn:
                chip = QLabel(asn); chip.setObjectName("asnChip"); vb.addWidget(self._start(chip))
            if org:
                vb.addWidget(self._start(self._val(org, latin=True)))
            self._row(i, "server", "شبکه" if fa else "Network", box); i += 1
        tz = timezone_text(self.info.get("timezone"), fa)
        if tz:
            self._row(i, "clock", "منطقه زمانی" if fa else "Timezone", self._start(self._val(tz))); i += 1
        host = self.info.get("hostname")
        if host:
            self._row(i, "network", "نام میزبان" if fa else "Hostname", self._start(self._val(host, latin=True))); i += 1
        self.grid.setColumnStretch(2, 1)
        self.panel.setVisible(i > 0); self.copy_btn.setEnabled(bool(self.info.get("ip")))
        src = self.info.get("source", "")
        self.status.setText((RLM + f"منبع: {iso(src)}" if fa else f"Source: {src}") if src else "")
        self.status.setStyleSheet("color: #6f879c; font-size: 10px;")
        self.adjustSize()

    def show_error(self, message):
        self.big.setText("—"); self.panel.setVisible(False); self.retry_btn.setVisible(True)
        self.status.setStyleSheet("color: #ff8798;")
        self.status.setText(RLM + ("دریافت اطلاعات آی‌پی ناموفق بود. اتصال را بررسی کن و دوباره امتحان کن."
                                   if self.fa else "Could not load IP details. Check the connection and retry."))
        self.status.setToolTip(str(message))

    def copy_ip(self):
        ip = self.info.get("ip")
        if ip:
            QGuiApplication.clipboard().setText(ip)
            self.copy_btn.setText("کپی شد ✓" if self.fa else "Copied ✓")
            QTimer.singleShot(1500, lambda: self.copy_btn.setText("کپی آی‌پی" if self.fa else "Copy IP"))
