"""Engine themes for the desktop UI.

Xray keeps the original cyan/navy "cyber" palette. UAC PoW follows the PoW
mockup (Documents/powui/mockup-target.png): the same deep navy surfaces with
quieter, less saturated cards, neutral blue-grey hairline borders and a neon
mint accent. The PoW look is derived from the cyber stylesheet by remapping
colours, so every stylesheet rule and painted widget follows one palette.

All tunables live in POW_PALETTE (values sampled from the mockup pixels).
"""

from __future__ import annotations

import colorsys
import re
from functools import lru_cache

# Single source of truth for the UAC PoW look. Change values here, or call
# set_palette(...), to retune the whole PoW UI.
POW_PALETTE: dict = {
    # Accents (mockup: Connect #3aefae..#48f3b9, toggles #2dee93,
    # eyebrows #32eaaf/#42f0af, status dot #29e995, brand "PoW" #1ee888).
    "accent": "#3cf0af",
    "accent2": "#2dee93",
    "brand_accent": "#1ee888",
    "accent_hue": 158.0,        # cyan-side accents -> mint
    "accent_hue_alt": 152.0,    # blue-side accents -> green (2nd gradient stop)
    "accent_sat": 0.92,         # saturation multiplier for accents
    # Surfaces (mockup: window #050d14, sidebar #0c1823, cards #0d1a28..#101e2a,
    # inputs #0a151f) - navy, but calmer than the cyber theme.
    "surface_hue": 208.0,
    "surface_sat_max": 0.55,
    "surface_light": 0.82,      # lightness multiplier for card fills
    # Teal-tinted dark fills (mockup icon tiles #0d2e2f, nav highlight
    # #0d3635): keep their own teal hue, just calmer.
    "tint_sat": 0.70,
    # Hairline borders / low-alpha accent strokes (mockup card edge #1d2e3c):
    # neutral blue-grey instead of tinted green.
    "hairline": "#8aa3bf",
    "hairline_alpha_max": 0.60,  # translucent accents -> neutral, never green
    # Brand cube faces.
    "cube_top": "#6ff5c6",
    "cube_left": "#1faf78",
    "cube_right": "#2fd99a",
    "cube_hole": "#0e3a2e",
}

_STATE = {"pow": False, "version": 0}


def set_pow(enabled: bool) -> None:
    _STATE["pow"] = bool(enabled)


def is_pow() -> bool:
    return _STATE["pow"]


def palette_version() -> int:
    return _STATE["version"]


def accent() -> str:
    return str(POW_PALETTE["accent"])


def brand_accent() -> str:
    return str(POW_PALETTE["brand_accent"])


def set_palette(**changes) -> None:
    """Retune the PoW palette at runtime (clears derived caches)."""
    unknown = set(changes) - set(POW_PALETTE)
    if unknown:
        raise KeyError(f"unknown palette keys: {sorted(unknown)}")
    POW_PALETTE.update(changes)
    map_rgba.cache_clear()
    _STATE["version"] += 1


def _hex_rgb(value: str) -> tuple[int, int, int]:
    value = value.lstrip("#")
    return (int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16))


@lru_cache(maxsize=8192)
def map_rgba(r: int, g: int, b: int, a: int = 255) -> tuple[int, int, int]:
    """Cyber colour -> PoW colour (alpha is kept by the caller)."""
    pal = POW_PALETTE
    h, l, s = colorsys.rgb_to_hls(r / 255.0, g / 255.0, b / 255.0)
    hue = h * 360.0
    if s < 0.10 or l > 0.94 or not (165.0 <= hue <= 295.0):
        return (r, g, b)
    if l < 0.24:
        if hue < 200.0:
            nh, nl, ns = hue, l, s * pal["tint_sat"]
        else:
            nh = pal["surface_hue"]
            nl = l if l < 0.07 else l * pal["surface_light"]
            ns = min(s, pal["surface_sat_max"])
    elif s >= 0.45 and l >= 0.40:
        if a < round(255 * pal["hairline_alpha_max"]):
            return _hex_rgb(pal["hairline"])
        if l > 0.78:
            return (r, g, b)   # pale tinted text stays as designed
        nh = pal["accent_hue"] if hue < 205.0 else pal["accent_hue_alt"]
        nl, ns = l, min(1.0, s * pal["accent_sat"])
    else:
        return (r, g, b)       # muted blue-grey text is already on-mockup
    rr, gg, bb = colorsys.hls_to_rgb((nh % 360.0) / 360.0, nl, ns)
    return (round(rr * 255), round(gg * 255), round(bb * 255))


def map_rgb(r: int, g: int, b: int) -> tuple[int, int, int]:
    return map_rgba(r, g, b, 255)


def _hex(rgb: tuple[int, int, int]) -> str:
    return "#{:02x}{:02x}{:02x}".format(*rgb)


def map_hex(value: str) -> str:
    text = value.strip()
    if not text.startswith("#"):
        return value
    digits = text[1:]
    if len(digits) == 3:
        digits = "".join(ch * 2 for ch in digits)
    if len(digits) != 6:
        return value
    try:
        rgb = _hex_rgb(digits)
    except ValueError:
        return value
    return _hex(map_rgba(*rgb))


def themed(value):
    """Colour string for the active theme (non-strings pass through)."""
    if isinstance(value, str) and is_pow():
        return map_hex(value)
    return value


_HEX_RE = re.compile(r"(?<=[\s:,(])#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})\b")
_RGB_RE = re.compile(r"rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*(?:,\s*([\d.]+)\s*)?\)")


def map_css(text: str) -> str:
    """Remap every literal colour in a Qt stylesheet to the PoW palette."""

    def _hex_sub(match: re.Match) -> str:
        return map_hex("#" + match.group(1))

    def _rgb_sub(match: re.Match) -> str:
        r, g, b = (min(255, int(match.group(i))) for i in (1, 2, 3))
        alpha_text = match.group(4)
        if alpha_text is None:
            return "rgb({},{},{})".format(*map_rgba(r, g, b))
        alpha = float(alpha_text)
        alpha_255 = round(alpha * 255) if alpha <= 1.0 else round(alpha)
        nr, ng, nb = map_rgba(r, g, b, max(0, min(255, alpha_255)))
        return f"rgba({nr},{ng},{nb},{alpha_text})"

    return _RGB_RE.sub(_rgb_sub, _HEX_RE.sub(_hex_sub, text))
