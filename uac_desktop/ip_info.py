"""Public-IP helpers for the Home IP card + the details dialog.

* direct mode (not connected): the real IP fetched *bypassing* any proxy, with
  the country/carrier taken from the wizard's weighted vote (Speedtest/ip-api
  first) so MCI's Azerbaijan transit egress still shows Iran.
* tunnel mode: the exit IP fetched through the local HTTP proxy of the active
  engine (Xray http_port or PoW forward port).
"""
from __future__ import annotations

import threading
from html import escape
from string import Template

from PySide6.QtCore import QEvent, QObject, Qt, QTimer, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QDialog, QFrame, QHBoxLayout, QLabel,
                               QPushButton, QSizePolicy, QVBoxLayout, QWidget)

from .fonts import LATIN, UI_STACK_EN, UI_STACK_FA
from .icons import icon, pixmap
from .theme import IP_DETAILS_PALETTES

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
            "isp": conn.get("isp") or "",
            "asn": f"AS{conn['asn']}" if conn.get("asn") else "", "timezone": tz.get("id", "") if isinstance(tz, dict) else str(tz),
            "hostname": "", "source": "ipwho.is"}


def _norm_ipapi(d):
    if d.get("status") == "fail":
        raise ValueError(d.get("message") or "ip-api failed")
    asn = str(d.get("as") or "").split(" ")[0]
    return {"ip": d.get("query", ""), "city": d.get("city", ""), "region": d.get("regionName", ""),
            "country": str(d.get("countryCode", "")).upper(), "org": d.get("org") or d.get("isp") or "",
            "isp": d.get("isp") or "",
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
_DETAILS_STYLE = Template("""
QFrame#ipShell { background: $background; border: 1px solid $edge; border-radius: 9px; }
#ipShell QLabel, #ipShell QPushButton { font-family: $font; font-size: 12px; font-weight: 500; }
#ipShell QLabel { color: $text; background: transparent; }
#ipShell QLabel#ipTitle { font-size: 18px; font-weight: 600; }
#ipShell QLabel#ipSection { font-weight: 600; }
#ipShell QLabel[ipMuted="true"] { color: $muted; font-size: 11px; }
#ipShell QLabel#ipTile, #ipShell QLabel#ipChip {
    color: $accent; background: $wash; border: 1px solid $edge; border-radius: 6px;
}
#ipShell QLabel#ipChip { padding: 3px 8px; font-size: 11px; }
#ipShell QFrame#ipHero {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 $wash,stop:1 $panel);
    border: 1px solid $edge; border-radius: 9px;
}
#ipShell QFrame#ipPanel { background: $panel; border: 1px solid $edge; border-radius: 9px; }
#ipShell QFrame#ipDivider { background: $edge; border: none; }
#ipShell QLabel#ipBig { font-family: $digits; font-size: 31px; font-weight: 600; }
#ipShell QLabel#ipBig[ipv6="true"] { font-size: 15px; }
#ipShell QLabel[ipLatin="true"] { font-family: $latin; }
#ipShell QLabel#asnChip {
    font-family: $digits; color: $accent; background: $wash;
    border-radius: 4px; padding: 3px 8px;
}
#ipShell QPushButton#ipCopy {
    background: $accent; color: $button_text; border: 1px solid $accent; border-radius: 6px;
    min-height: 34px; min-width: 106px; padding: 0 5px; font-weight: 600;
}
#ipShell QPushButton#ipCopy:hover, #ipShell QPushButton#ipCopy:focus { border-color: $text; }
#ipShell QPushButton#ipCopy:disabled { color: $muted; background: $panel; border-color: $edge; }
#ipShell QPushButton#ipRetry {
    color: $accent; background: $panel; border: 1px solid $edge; border-radius: 6px; padding: 5px 10px;
}
#ipShell QPushButton#ipX {
    background: transparent; border: 1px solid transparent; border-radius: 6px;
    min-width: 24px; min-height: 24px; padding: 0;
}
#ipShell QPushButton#ipX:hover { background: $wash; }
#ipShell QPushButton#ipX:focus { border-color: $edge; }
#ipShell QLabel#ipStatus { color: $muted; }
#ipShell QLabel#ipStatus[failed="true"] { color: $error; }
""")


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


class SharedIpDetailsDialog(QDialog):
    """Public IP and network details for the active engine's existing lookup."""

    def __init__(self, parent, fa: bool, loader, mode_label: str = "", *, engine: str = "xray"):
        super().__init__(parent, Qt.Dialog | Qt.FramelessWindowHint)
        from .ui import ElidedLabel

        self.fa, self.loader = fa, loader
        self.info = {}
        self.setObjectName("ipDetails")
        self.setWindowTitle(self._tr("جزئیات آی‌پی عمومی", "Public IP details"))
        self.setLayoutDirection(Qt.RightToLeft if fa else Qt.LeftToRight)
        self.setAttribute(Qt.WA_DeleteOnClose)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedWidth(460)
        self.theme = IP_DETAILS_PALETTES[engine]
        self.setStyleSheet(_DETAILS_STYLE.substitute(
            self.theme, font=UI_STACK_FA if fa else UI_STACK_EN,
            digits=f'"Bahnschrift", "Segoe UI", "{LATIN}"', latin=UI_STACK_EN,
        ))
        accent, muted = self.theme["accent"], self.theme["muted"]
        opposite = Qt.AlignLeft if fa else Qt.AlignRight

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        shell = QFrame()
        shell.setObjectName("ipShell")
        outer.addWidget(shell)
        root = QVBoxLayout(shell)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(10)

        self.header = QWidget()
        top = QHBoxLayout(self.header)
        top.setContentsMargins(0, 0, 0, 0)
        top.setSpacing(9)
        globe = self._glyph("globe", 34, 17)
        globe.setObjectName("ipTile")
        top.addWidget(globe)
        heading = QVBoxLayout()
        heading.setSpacing(1)
        self.title = self._label(self.windowTitle(), "ipTitle")
        heading.addWidget(self.title)
        heading.addWidget(self._label(self._tr("اطلاعات مسیر فعلی اینترنت", "Current internet route"), muted=True))
        top.addLayout(heading, 1)
        self.close_btn = QPushButton(icon("x", muted, 16), "")
        self.close_btn.setObjectName("ipX")
        self.close_btn.setFixedSize(26, 26)
        self.close_btn.setCursor(Qt.PointingHandCursor)
        self.close_btn.setToolTip(self._tr("بستن", "Close"))
        self.close_btn.setAccessibleName(self.close_btn.toolTip())
        self.close_btn.clicked.connect(self.close)
        top.addWidget(self.close_btn, 0, Qt.AlignVCenter)
        root.addWidget(self.header)

        self.hero = QFrame()
        self.hero.setObjectName("ipHero")
        hero = QHBoxLayout(self.hero)
        hero.setContentsMargins(16, 12, 16, 12)
        hero.setSpacing(10)
        country_box = QWidget()
        country_box.setFixedWidth(126)
        country_layout = QVBoxLayout(country_box)
        country_layout.setContentsMargins(0, 0, 0, 0)
        country_layout.setSpacing(5)
        badge = QWidget()
        badge.setFixedWidth(80)
        country_badge = QVBoxLayout(badge)
        country_badge.setContentsMargins(0, 0, 0, 0)
        country_badge.setSpacing(3)
        self.flag = self._label()
        self.flag.setFixedSize(40, 28)
        self.country = ElidedLabel()
        self.country.setAlignment(Qt.AlignCenter)
        country_badge.addWidget(self.flag, 0, Qt.AlignHCenter)
        country_badge.addWidget(self.country)
        country_layout.addWidget(badge, 0, Qt.AlignLeading)
        country_layout.addStretch(1)
        self.mode = self._label(f"•  {mode_label}", "ipChip")
        self.mode.setVisible(bool(mode_label))
        country_layout.addWidget(self.mode, 0, Qt.AlignLeading)
        hero.addWidget(country_box)

        address = QVBoxLayout()
        address.setSpacing(3)
        self.family = self._label(muted=True)
        self.big = self._label(name="ipBig")
        self.big.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.big.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.city = ElidedLabel()
        self.city.setProperty("ipMuted", True)
        for label in (self.family, self.big, self.city):
            label.setLayoutDirection(Qt.LeftToRight)
            label.setAlignment(opposite | Qt.AlignAbsolute | Qt.AlignVCenter)
        self.family.setProperty("ipLatin", True)
        address.addWidget(self.family)
        address.addWidget(self.big)
        address.addStretch(1)
        address.addWidget(self.city)
        hero.addLayout(address, 1)
        self.hero.setFixedHeight(125)
        root.addWidget(self.hero)

        self.section = self._label(self._tr("اطلاعات شبکه", "Network information"), "ipSection")
        root.addWidget(self.section)
        self.panel = QFrame()
        self.panel.setObjectName("ipPanel")
        panel = QVBoxLayout(self.panel)
        panel.setContentsMargins(10, 1, 10, 1)
        panel.setSpacing(0)
        self.values = {}
        for key, glyph, fa_key, en_key in (
            ("location", "map-pin", "موقعیت", "Location"),
            ("carrier", "radio", "اپراتور", "Carrier"),
            ("org", "server", "نام شبکه", "Network name"),
            ("asn", "hash", "شناسه شبکه (ASN)", "Network ID (ASN)"),
            ("timezone", "clock", "منطقه زمانی", "Time zone"),
            ("hostname", "network", "نام میزبان", "Hostname"),
        ):
            row = QWidget()
            line = QHBoxLayout(row)
            line.setContentsMargins(3, 0, 3, 0)
            line.setSpacing(8)
            line.addWidget(self._glyph(glyph, 18, 16))
            line.addWidget(self._label(self._tr(fa_key, en_key), muted=True))
            value = self._label() if key == "asn" else ElidedLabel()
            value.setObjectName("asnChip" if key == "asn" else "ipVal")
            value.setTextInteractionFlags(Qt.TextSelectableByMouse)
            value.setAlignment(opposite | Qt.AlignAbsolute | Qt.AlignVCenter)
            if key == "asn":
                value.setMaximumWidth(110)
                line.addStretch()
                line.addWidget(value, 0, Qt.AlignVCenter)
            else:
                line.addWidget(value, 1)
            row.setFixedHeight(43)
            if self.values:
                divider = QFrame()
                divider.setObjectName("ipDivider")
                divider.setFixedHeight(1)
                panel.addWidget(divider)
                if key == "hostname":
                    self.host_divider = divider
                    self.host_row = row
            panel.addWidget(row)
            self.values[key] = value
        root.addWidget(self.panel)

        self.status = self._label(name="ipStatus")
        self.status.setWordWrap(True)
        root.addWidget(self.status)
        footer = QHBoxLayout()
        footer.setSpacing(8)
        self.source = self._label(muted=True)
        self.source.setTextFormat(Qt.RichText)
        self.source.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        footer.addWidget(self.source, 1)
        self.copy_btn = QPushButton(icon("copy", self.theme["button_text"], 16), self._tr("کپی آی‌پی", "Copy IP"))
        self.copy_btn.setObjectName("ipCopy")
        self.copy_btn.setLayoutDirection(Qt.LeftToRight)
        self.copy_btn.clicked.connect(self.copy_ip)
        self.retry_btn = QPushButton(icon("refresh", accent, 16), self._tr("تلاش دوباره", "Retry"))
        self.retry_btn.setObjectName("ipRetry")
        self.retry_btn.clicked.connect(self.load)
        for button in (self.copy_btn, self.retry_btn):
            button.setCursor(Qt.PointingHandCursor)
            footer.addWidget(button)
        root.addLayout(footer)

        self._copy_feedback = QTimer(self, singleShot=True, interval=1500)
        self._copy_feedback.timeout.connect(self._reset_copy_text)
        self.relay = _Relay()  # parentless so an in-flight lookup can finish after close
        self.relay.done.connect(self.show_info)
        self.relay.failed.connect(self.show_error)
        self.load()

    def _tr(self, fa, en):
        return fa if self.fa else en

    @staticmethod
    def _label(text="", name="", *, muted=False):
        label = QLabel(text)
        label.setTextFormat(Qt.PlainText)
        label.setObjectName(name)
        if muted:
            label.setProperty("ipMuted", True)
        return label

    def _glyph(self, name, size, glyph):
        label = self._label()
        label.setFixedSize(size, size)
        label.setAlignment(Qt.AlignCenter)
        label.setPixmap(pixmap(name, self.theme["accent"], glyph))
        return label

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and self.header.rect().contains(self.header.mapFrom(self, event.position().toPoint())):
            if self.windowHandle().startSystemMove():
                event.accept()
                return
        super().mousePressEvent(event)

    def _set_status(self, text="", *, error=None):
        self.status.setProperty("failed", error is not None)
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)
        self.status.setText(text)
        self.status.setToolTip(str(error or ""))
        self.status.setVisible(bool(text))
        self.retry_btn.setVisible(error is not None)

    def load(self):
        self.info = {}
        self.big.setText("…")
        self.family.clear()
        self.city.setText("")
        self.flag.hide()
        self.country.setText("")
        self.source.clear()
        self._copy_feedback.stop()
        self._reset_copy_text()
        self.copy_btn.setEnabled(False)
        self.section.hide()
        self.panel.hide()
        self._set_status(self._tr("در حال دریافت اطلاعات…", "Loading details…"))
        relay, loader = self.relay, self.loader

        def work():
            try:
                result = loader()
            except Exception as exc:
                relay.failed.emit(str(exc))
            else:
                relay.done.emit(result)

        threading.Thread(target=work, name="ip-details", daemon=True).start()

    def show_info(self, info):
        self.info = info or {}
        ip = self.info.get("ip") or ""
        if not ip and self.info.get("error"):
            self.show_error(self.info["error"])
            return
        ipv6 = ":" in ip
        self.big.setProperty("ipv6", ipv6)
        self.big.style().unpolish(self.big)
        self.big.style().polish(self.big)
        address = ip or "—"
        if ipv6 and len(ip) > 23:
            break_at = min((i + 1 for i, ch in enumerate(ip) if ch == ":"), key=lambda i: abs(i - len(ip) / 2))
            address = f"{ip[:break_at]}\n{ip[break_at:]}"
        self.big.setText(address)
        self.big.setToolTip(ip if address != ip and ip else "")
        self.family.setText(f"Public IPv{6 if ipv6 else 4}" if ip else "")
        code = str(self.info.get("country") or "").upper()
        if len(code) == 2:
            from .ui import country_flag_icon

            self.flag.setPixmap(country_flag_icon(code, 40, 28).pixmap(40, 28))
            self.flag.show()
        self.country.setText(country_name(code, self.fa))
        self.city.setText(", ".join(part for part in (self.info.get("city"), code) if part))

        localized_carrier = self.info.get("carrier_fa" if self.fa else "carrier_en")
        values = {
            "location": location_text(self.info, self.fa),
            "carrier": localized_carrier or self.info.get("isp"),
            "org": self.info.get("org"),
            "asn": self.info.get("asn"),
            "timezone": timezone_text(self.info.get("timezone"), self.fa),
            "hostname": self.info.get("hostname"),
        }
        for key, value in values.items():
            text = str(value or "—").strip(RLM) or "—"
            label = self.values[key]
            if self.fa and key in ("carrier", "org", "hostname"):
                label.setProperty("ipLatin", text.isascii())
                label.style().unpolish(label)
                label.style().polish(label)
            if self.fa and key != "asn":
                text = RLM + (iso(text) if text.isascii() else text)
            label.setText(text)
            if key == "asn":
                label.setToolTip(text)
        self.host_row.setVisible(bool(values["hostname"]))
        self.host_divider.setVisible(bool(values["hostname"]))
        self.section.show()
        self.panel.show()
        self._set_status()
        src = self.info.get("source")
        if src:
            name = self._tr("منبع اطلاعات", "Source")
            self.source.setText(f'{name}: <span dir="ltr" style="color:{self.theme["accent"]}">{escape(str(src))}</span>')
            self.source.setToolTip(str(src))
        self.copy_btn.setEnabled(bool(ip))
        QTimer.singleShot(0, self, self.adjustSize)

    def show_error(self, message):
        self.big.setText("—")
        self._set_status(self._tr("دریافت اطلاعات ناموفق بود. اتصال را بررسی کن و دوباره امتحان کن.",
                                  "Could not load IP details. Check the connection and retry."), error=message)
        QTimer.singleShot(0, self, self.adjustSize)

    def _reset_copy_text(self):
        self.copy_btn.setText(self._tr("کپی آی‌پی", "Copy IP"))

    def copy_ip(self):
        ip = self.info.get("ip")
        if ip:
            QGuiApplication.clipboard().setText(ip)
            self.copy_btn.setText(self._tr("کپی شد ✓", "Copied ✓"))
            self._copy_feedback.start()
