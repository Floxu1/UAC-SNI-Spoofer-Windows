"""Labels and connection hints for the active route."""
from __future__ import annotations

import re
import unicodedata

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
