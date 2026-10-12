"""Active Route card: clean config titles + a tidy multi-line route detail."""
from __future__ import annotations

import re
import unicodedata

from PySide6.QtCore import Qt
from PySide6.QtGui import QFontMetrics
from PySide6.QtWidgets import QHBoxLayout, QLabel, QSizePolicy, QVBoxLayout, QWidget

from .verified_configs import COUNTRIES

_JUNK_PATTERNS = [
    r"https?://\S+", r"t\.me/\S+", r"@[\w.]+",
    r"(?i)\b(?:telegram|tg|channel|join|kanal|free|vpn|proxy|config|configs)\b[:\-_]*",
    r"\b[0-9a-f]{6,}\b", r"\b\d{5,}\b",
]
_SEP_RE = re.compile(r"[\s|_\-\u00b7\u2022/\\#:;,]+")


def _is_cjk_or_symbol(ch: str) -> bool:
    if ch.isascii():
        return False
    cat = unicodedata.category(ch)
    if cat.startswith("S") or cat in ("Co", "Cn", "Cs", "Mn"):
        return True   # emoji / symbols / regional indicators
    name = unicodedata.name(ch, "")
    return any(tag in name for tag in ("CJK", "HIRAGANA", "KATAKANA", "HANGUL", "VARIATION"))


def clean_profile_name(name: str, max_words: int = 4) -> str:
    """'HK · 未知_10111903 | @chan' -> 'HK'. Keeps Latin/Persian words, drops
    CJK, emoji, telegram tags, long ids and route suffixes (SNI/ECH/Reality)."""
    text = str(name or "")
    text = "".join(" " if _is_cjk_or_symbol(c) else c for c in text)
    for pattern in _JUNK_PATTERNS:
        text = re.sub(pattern, " ", text)
    words = [w for w in _SEP_RE.split(text) if w and not re.fullmatch(r"[\W_]+", w)]
    words = [w for w in words if w.upper() not in {"SNI", "ECH", "REALITY", "BY"}]
    words = [w for w in words
             if not re.fullmatch(r"\d{5,}|(?=.*\d)[0-9a-fA-F]{6,}", w)]
    out = []
    for word in words:
        if word.lower() not in (x.lower() for x in out):
            out.append(word)
    return " ".join(out[:max_words]).strip()


def card_title(profile, language: str = "en") -> str:
    if profile is None:
        return ""
    code = str(getattr(profile, "country_code", "") or "").upper()
    country = ""
    if code and code in COUNTRIES:
        entry = COUNTRIES[code]
        country = entry[1] if language == "en" else (entry[2] or entry[1])
    elif re.fullmatch(r"[A-Z]{2}", code) and code != "XX":
        country = code
    short = clean_profile_name(getattr(profile, "name", ""))
    if short.upper() == code or (country and short.lower() == country.lower()):
        short = ""
    if not short:
        short = str(getattr(profile, "sni", "") or "")[:40]
    if country and short:
        return f"{country} \u00b7 {short}"
    return country or short or str(getattr(profile, "name", "") or "-")


def route_kind(profile, gene_active: bool = False) -> str:
    from .models import route_label
    label = route_label(profile)
    if label == "SNI":
        return "Gene" if gene_active else "Spoof"
    return label


def ping_color(ms) -> str:
    try:
        ms = float(ms)
    except (TypeError, ValueError):
        return "#8fa9bf"
    if ms <= 0:
        return "#8fa9bf"
    return "#45f3b4" if ms < 400 else "#ffd166" if ms < 1200 else "#ff8798"


class _Elided(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._full = ""
        self.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Fixed)
        self.setTextFormat(Qt.PlainText)

    def set_full(self, text):
        self._full = str(text or "")
        self._sync()

    def _sync(self):
        width = self.contentsRect().width()
        shown = QFontMetrics(self.font()).elidedText(self._full, Qt.ElideMiddle, width) if width > 0 else self._full
        super().setText(shown)
        self.setToolTip(self._full if shown != self._full else "")

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._sync()


class RouteDetails(QWidget):
    """Two rows: [pill] endpoint  /  SNI (elided). No ping here."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("routeDetails")
        self.setLayoutDirection(Qt.LeftToRight)   # IPs/hosts always LTR
        root = QVBoxLayout(self); root.setContentsMargins(0, 0, 0, 0); root.setSpacing(3)
        row = QHBoxLayout(); row.setContentsMargins(0, 0, 0, 0); row.setSpacing(6)
        self.pill = QLabel(); self.pill.setObjectName("routePill"); self.pill.setAlignment(Qt.AlignCenter)
        self.endpoint = _Elided(); self.endpoint.setObjectName("routeEndpoint")
        self.ping = QLabel(); self.ping.setObjectName("routePing")
        self.ping.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        row.addWidget(self.pill); row.addWidget(self.endpoint, 1)
        self.ping.hide()  # ping lives in the Ping stat card, not here
        self.sni = _Elided(); self.sni.setObjectName("routeSni")
        root.addLayout(row); root.addWidget(self.sni)
        self.setStyleSheet(
            "QLabel#routePill { font-family: 'Inter', 'Segoe UI'; border-radius: 7px; padding: 1px 7px; font-size: 10px; font-weight: 800; }"
            "QLabel#routeEndpoint { font-family: 'JetBrains Mono', 'Consolas'; color: #cfe3f2; font-size: 11px; }"
            "QLabel#routePing { font-family: 'JetBrains Mono', 'Consolas'; font-size: 11px; font-weight: 700; }"
            "QLabel#routeSni { font-family: 'JetBrains Mono', 'Consolas'; color: #8fa9bf; font-size: 10px; }")
        self.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Fixed)

    PILL_COLORS = {"ECH": "#c4b5fd", "Reality": "#62dcff", "Gene": "#ffd166", "Spoof": "#45f3b4"}

    def set_route(self, kind, endpoint, ping_ms, sni_label, sni):
        color = self.PILL_COLORS.get(kind, "#afc5dc")
        self.pill.setText(kind)
        self.pill.setStyleSheet(f"color: {color}; border: 1px solid {color}; background: rgba(255,255,255,0.04);")
        self.endpoint.set_full(endpoint)
        try:
            ping_ok = float(ping_ms or 0) > 0
        except (TypeError, ValueError):
            ping_ok = False
        self.ping.setText(f"{float(ping_ms):.0f} ms" if ping_ok else "\u2014")
        self.ping.setStyleSheet(f"color: {ping_color(ping_ms)};")
        self.sni.set_full(f"{sni_label} {sni}".strip() if sni else "")
        self.sni.setVisible(bool(sni))
