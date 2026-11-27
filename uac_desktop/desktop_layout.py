"""PoW-derived geometry shared by all desktop engine themes."""

from dataclasses import dataclass


MIN_WINDOW_SIZE = (1080, 700)
SIDEBAR_WIDTH = (238, 286)
SIDEBAR_MARGIN = ((14, 10, 14, 10), (18, 20, 18, 18))
BRAND_MARGIN = ((10, 8, 10, 8), (12, 10, 12, 10))
BRAND_ICON = 46
ENGINE_SWITCH_STRETCH = (5, 5, 6, 4)
ENGINE_SWITCH_HEIGHT = 48
ENGINE_OPTION_HEIGHT = 34
SIDEBAR_GAP = 4
NAV_HEIGHTS = (46, 44, 42, 40)
NAV_ICON = 22
COMPACT_NAV_SPACER = 36
GUIDE_WIDTH = 176
COUNTRY_TEXT_HEIGHTS = (18, 28, 34)
CONNECT_HEIGHT = 56
BRAND_TEXT_HEIGHTS = {"fa": (29, 19, 19), "en": (22, 15, 15)}
HEADER_TEXT_HEIGHTS = {"fa": ((19, 24, 21), (19, 28, 21)), "en": ((15, 33, 16), (16, 36, 16))}
STATUS_PILL_SIZE = {"fa": (151, 37), "en": (180, 36)}
ACTIVITY_HEIGHT = {"fa": 60, "en": 52}
DASHBOARD_GAP = 12
HERO_TEXT_HEIGHTS = {"fa": (27, 19), "en": (22, 15)}
# Preserve the hero's viewport sizing curve when the lower panels are packed tightly.
HERO_VIEWPORT_RESERVE = (494, 542, 568)
DIRECT_QUICK_MARGINS = (14, 11, 14, 11)
QUICK_HEADER_HEIGHT = 18
DIRECT_QUICK_TILE_HEIGHT = 50
QUICK_TILE_HEIGHT = 45
QUICK_GRID_GAP = 8
QUICK_GRID_MARGINS = (14, 8, 14, 8)
QUICK_DROPDOWN_SIZE = (90, 33)
QUICK_SWITCH = (40, 22)
QUICK_SWITCH_TARGET = (44, 26)
QUICK_PANEL_BORDER = 1
QUICK_PANEL_HEIGHT = (QUICK_HEADER_HEIGHT + 2 * (QUICK_GRID_GAP + QUICK_TILE_HEIGHT)
                      + QUICK_GRID_MARGINS[1] + QUICK_GRID_MARGINS[3] + 2 * QUICK_PANEL_BORDER)
METRIC_HEIGHT = 91
METRIC_GAP = 8
METRIC_PANEL_PADDING = 8
METRIC_PANEL_RADIUS = 12
METRIC_RADIUS = 10
METRIC_WEIGHTS = (3, 2, 2, 2, 3)
METRIC_MARGINS = (11, 8, 11, 8)
METRIC_HEADER = 24
METRIC_ICON = 15
METRIC_ICON_RADIUS = 6
METRIC_HEADER_GAP = 6
METRIC_REFRESH_SIZE = 20
METRIC_REFRESH_ICON = 12
METRIC_CAPTION = 15
METRIC_CAPTION_GAP = 3
METRIC_READING = 30
METRIC_READING_GAP = 4
METRIC_LEGEND_FONT = 9
METRIC_VALUE_FONT = 24
METRIC_MIN_VALUE_FONT = 14
METRIC_IP_FONT = 19
METRIC_UNIT_FONT = 10
METRIC_SIGNAL_SIZE = (37, 23)
METRIC_SIGNAL_TRANSITION_MS = 180


@dataclass(frozen=True)
class DashboardLayout:
    margin: tuple[int, int, int, int]
    header: int
    hero: int
    country: int


def dashboard_layout(stack_height: int, narrow: bool, dense: bool) -> DashboardLayout:
    margin = (14, 8, 14, 8) if dense else (26, 18, 26, 14)
    header = 88 if dense else 100
    reserve = HERO_VIEWPORT_RESERVE[0 if dense else 1 if narrow else 2]
    return DashboardLayout(margin, header, max(178, min(318, stack_height - reserve)), 104)
