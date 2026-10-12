"""Region helpers — port of mobile ``PowRegions`` (codes only, no Android)."""

from __future__ import annotations

AUTOMATIC = ""

BUNDLED = {
    "AT": "Austria", "AU": "Australia", "BE": "Belgium", "CA": "Canada",
    "CH": "Switzerland", "CZ": "Czechia", "DE": "Germany", "DK": "Denmark",
    "ES": "Spain", "FI": "Finland", "FR": "France", "GB": "United Kingdom",
    "ID": "Indonesia", "IE": "Ireland", "IN": "India", "IT": "Italy",
    "JP": "Japan", "NL": "Netherlands", "NO": "Norway", "PL": "Poland",
    "RO": "Romania", "RS": "Serbia", "SE": "Sweden", "SG": "Singapore",
    "US": "United States",
}
EXTRA_NAMES = {
    "AE": "United Arab Emirates", "AR": "Argentina", "BG": "Bulgaria",
    "BR": "Brazil", "CL": "Chile", "EE": "Estonia", "GR": "Greece",
    "HK": "Hong Kong", "HU": "Hungary", "IL": "Israel", "IS": "Iceland",
    "KR": "South Korea", "LT": "Lithuania", "LV": "Latvia", "MD": "Moldova",
    "MX": "Mexico", "MY": "Malaysia", "NZ": "New Zealand", "PT": "Portugal",
    "SK": "Slovakia", "TR": "Türkiye", "TW": "Taiwan", "UA": "Ukraine",
}

ALL_NAMES = {**BUNDLED, **EXTRA_NAMES}


def is_code(code: str) -> bool:
    key = (code or "").strip().upper()
    return len(key) == 2 and key.isalpha() and key.isascii()


def normalize_region(code: str | None) -> str:
    key = (code or "").strip().upper()
    return key.lower() if is_code(key) else AUTOMATIC


def egress_region(code: str | None) -> str | None:
    normalized = normalize_region(code)
    return normalized.upper() if normalized else None


def region_name(code: str) -> str:
    key = normalize_region(code).upper()
    if not key:
        return ""
    return ALL_NAMES.get(key, key)
