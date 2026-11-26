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

XRAY_BLUE = "#2cc7ff"
XRAY_HUD_BLUE = "#79B5FF"
ENGINE_BRAND_PALETTES = {
    "xray": {
        "accent": "#27DFE9", "surface": "#0B1B29", "tint": "#123747",
        "edge": "#185567", "tray": "#081521", "glass": "#155768",
        "pill_light": "#8AF7FC", "pill_dark": "#11BDD1",
    },
    "pow": {
        "accent": "#37E9AC", "surface": "#0C1B24", "tint": "#133934",
        "edge": "#1A594C", "tray": "#08171D", "glass": "#155344",
        "pill_light": "#9FFFE4", "pill_dark": "#17C797",
    },
    "direct": {
        "accent": "#FF974D", "surface": "#16181C", "tint": "#35251D",
        "edge": "#69452F", "tray": "#101316", "glass": "#5D3925",
        "pill_light": "#FFC293", "pill_dark": "#F7893E",
    },
}

XRAY_DASHBOARD = {
    "surface": "#0A1B30",
    "gradient": "#0C2338",
    "border": "#17445C",
    "accent": "#46DCE8",
    "secondary": "#91ADC4",
    "icon_tile": "#12364C",
    "active_track": "#176D7F",
}

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

DIRECT_PALETTE = {
    "background": "#0d0e10",
    "surface": "#17191c",
    "border": "#2b2d31",
    "primary": "#f67b36",
    "accent": "#ffad6e",
    "text": "#f2f2f4",
    "secondary": "#95979e",
    "sidebar": "#121315",
    "raised": "#202225",
    "selected": "#2b211b",
    "ember_border": "#574031",
    "steel": "#9b9089",
}

IP_DETAILS_PALETTES = {
    "xray": dict(background="#0C1826", panel="#0D1F2E", wash="#133342", edge="#214657",
                 accent=XRAY_DASHBOARD["accent"], muted=XRAY_DASHBOARD["secondary"],
                 text="#EBF5FC", button_text="#071722", error="#FF9BA9"),
    "pow": dict(background="#0D1C1A", panel="#10261F", wash="#173C31", edge="#25493E",
                accent=ENGINE_BRAND_PALETTES["pow"]["accent"], muted="#A1BBB3",
                text="#EBF5FC", button_text="#092219", error="#FF9BA9"),
    "direct": dict(background="#141618", panel="#1B1D1F", wash="#322820", edge="#493B30",
                   accent=ENGINE_BRAND_PALETTES["direct"]["accent"], muted="#ABB0B8",
                   text=DIRECT_PALETTE["text"], button_text="#22160D", error="#F18A98"),
}

NETWORK_METRICS = {
    # Panel, surface gradient, matte edge, icon tile, accent, text, dim text.
    "xray": (XRAY_DASHBOARD["surface"], XRAY_DASHBOARD["gradient"], XRAY_DASHBOARD["surface"],
             XRAY_DASHBOARD["border"], XRAY_DASHBOARD["icon_tile"], XRAY_DASHBOARD["accent"], "#F1F4F9",
             XRAY_DASHBOARD["secondary"]),
    "pow": ("#0C1921", "#172832", "#11212B", "#29404C", "#173039", "#43DCBB", "#F0F6F8", "#A7B9C2"),
    "direct": ("#111214", "#202224", "#191C1E", "#303236", "#302720", DIRECT_PALETTE["primary"],
               DIRECT_PALETTE["text"], "#ABB0B8"),
}

APP_ROUTING_PALETTES = {
    "xray": {
        "background": "#07111E", "surface": "#0B1B2D", "tile": "#102437", "border": "#1E4057",
        "hover": "#152E43", "selected": "#102D39", "selected_border": "#287281",
        "accent": XRAY_DASHBOARD["accent"], "text": "#E3EDF7", "muted": "#A6BCCF",
        "vpn": "#92CAC3", "track_off": "#31465A", "thumb_on": "#E4FCFF",
    },
    "pow": {
        "background": "#0B151D", "surface": "#0E1D29", "tile": "#122431", "border": "#293D4C",
        "hover": "#192D38", "selected": "#153039", "selected_border": "#2E6959",
        "accent": ENGINE_BRAND_PALETTES["pow"]["accent"], "text": "#E5EEF5", "muted": "#A2B5C2",
        "vpn": "#9BD2C0", "track_off": "#304655", "thumb_on": "#D8FBF3",
    },
    "direct": {
        "background": DIRECT_PALETTE["background"], "surface": DIRECT_PALETTE["surface"],
        "tile": DIRECT_PALETTE["raised"], "border": "#34373A",
        "hover": "#252729", "selected": "#26211D", "selected_border": "#835334",
        "accent": ENGINE_BRAND_PALETTES["direct"]["accent"], "text": DIRECT_PALETTE["text"], "muted": "#A6ABB2",
        "vpn": "#9CC6B6", "track_off": "#383B40", "thumb_on": "#FFF2E9",
    },
}

def connection_wave_colors(engine):
    if engine == "pow":
        return POW_PALETTE["accent2"], POW_PALETTE["accent"]
    if engine == "xray":
        return XRAY_BLUE, XRAY_HUD_BLUE
    return ()


_STATE = {"engine": "xray", "version": 0}


def set_engine(engine: str) -> None:
    _STATE["engine"] = engine


def set_pow(enabled: bool) -> None:
    set_engine("pow" if enabled else "xray")


def is_pow() -> bool:
    return _STATE["engine"] == "pow"


def is_direct() -> bool:
    return _STATE["engine"] == "direct"


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


@lru_cache(maxsize=8192)
def direct_rgba(r: int, g: int, b: int, alpha: int = 255) -> tuple[int, int, int]:
    """Translate the shared chrome's color roles to graphite and ember."""
    h, light, saturation = colorsys.rgb_to_hls(r / 255, g / 255, b / 255)
    if saturation < .10 or h * 360 < 74 or h * 360 > 326:
        return r, g, b
    if light < .27:
        shade = min(42, round(11 + 109 * light))
        return shade, shade + 1, shade + 3
    if light > .86:
        return _hex_rgb(DIRECT_PALETTE["text"])
    if saturation >= .52 and .39 <= light <= .83:
        if alpha < 115:
            return _hex_rgb(DIRECT_PALETTE["steel"])
        role = "primary" if light < .65 else "accent"
        return _hex_rgb(DIRECT_PALETTE[role])
    return _hex_rgb(DIRECT_PALETTE["secondary"])


def _hex(rgb: tuple[int, int, int]) -> str:
    return "#{:02x}{:02x}{:02x}".format(*rgb)


def map_hex(value: str, direct: bool = False) -> str:
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
    mapper = direct_rgba if direct else map_rgba
    return _hex(mapper(*rgb))


def themed(value):
    """Colour string for the active theme (non-strings pass through)."""
    if isinstance(value, str) and (is_pow() or is_direct()):
        return map_hex(value, direct=is_direct())
    return value


_HEX_RE = re.compile(r"(?<=[\s:,(])#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})\b")
_RGB_RE = re.compile(r"rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*(?:,\s*([\d.]+)\s*)?\)")


def map_css(text: str, direct: bool = False) -> str:
    """Remap literal colors in the shared Qt stylesheet to an engine palette."""
    mapper = direct_rgba if direct else map_rgba

    def _hex_sub(match: re.Match) -> str:
        return map_hex("#" + match.group(1), direct=direct)

    def _rgb_sub(match: re.Match) -> str:
        r, g, b = (min(255, int(match.group(i))) for i in (1, 2, 3))
        alpha_text = match.group(4)
        if alpha_text is None:
            return "rgb({},{},{})".format(*mapper(r, g, b))
        alpha = float(alpha_text)
        alpha_255 = round(alpha * 255) if alpha <= 1.0 else round(alpha)
        nr, ng, nb = mapper(r, g, b, max(0, min(255, alpha_255)))
        return f"rgba({nr},{ng},{nb},{alpha_text})"

    return _RGB_RE.sub(_rgb_sub, _HEX_RE.sub(_hex_sub, text))
