"""Theme tokens and shared styles for the dashboard quick controls."""

from string import Template

from .fonts import DASHBOARD_HEADING_QSS, DASHBOARD_LABEL_QSS, dashboard_text_color
from .theme import XRAY_DASHBOARD


SWITCH_MS = 200
PALETTES = {
    "xray": {
        "surface": XRAY_DASHBOARD["surface"], "tile": XRAY_DASHBOARD["surface"], "border": XRAY_DASHBOARD["border"],
        "hover": XRAY_DASHBOARD["gradient"], "hover_border": XRAY_DASHBOARD["active_track"],
        "action": XRAY_DASHBOARD["gradient"], "icon": XRAY_DASHBOARD["accent"], "muted_icon": XRAY_DASHBOARD["accent"],
        "text": "#E3EDF7", "secondary": XRAY_DASHBOARD["secondary"],
        "track_off": XRAY_DASHBOARD["border"], "track_on": XRAY_DASHBOARD["active_track"],
        "thumb_off": XRAY_DASHBOARD["secondary"], "thumb_on": XRAY_DASHBOARD["accent"],
        "dropdown_surface": XRAY_DASHBOARD["surface"], "dropdown_border": XRAY_DASHBOARD["border"],
        "dropdown_focus": XRAY_DASHBOARD["accent"],
        "radius": 8,
    },
    "direct": {
        "surface": "#17191B", "tile": "#1E2022", "border": "#303236",
        "hover": "#242628", "hover_border": "#3B3D41", "action": "#29231F",
        "icon": "#DE9464", "muted_icon": "#959BA4", "text": "#F2F2F4", "secondary": "#95979E",
        "track_off": "#383B40", "track_on": "#C77E50", "thumb_off": "#95979E", "thumb_on": "#FFF2E9",
        "radius": 9,
    },
    "pow": {
        "surface": "#0E1D29", "tile": "#122431", "border": "#293D4C",
        "hover": "#182C39", "hover_border": "#3A5666", "action": "#14313A",
        "icon": "#50CCBC", "muted_icon": "#8CA6B6", "text": "#E5EEF5", "secondary": "#A2B5C2",
        "track_off": "#304655", "track_on": "#248E85", "thumb_off": "#91AABD", "thumb_on": "#D8FBF3",
        "dropdown_surface": "#0D1D27", "dropdown_border": "#385261", "dropdown_focus": "#518D8F",
        "dropdown_hover": "#162A35", "dropdown_text": "#D1E7EB",
        "radius": 8,
    },
    "tor": {
        "surface": "#14111D", "tile": "#1B1629", "border": "#33294A",
        "hover": "#231B36", "hover_border": "#583D8A", "action": "#261B3D",
        "icon": "#C08CFF", "muted_icon": "#A396BD", "text": "#F3EFFA", "secondary": "#9E96B3",
        "track_off": "#322A45", "track_on": "#8F4DF0", "thumb_off": "#A396BD", "thumb_on": "#F3EBFF",
        "dropdown_surface": "#120E1B", "dropdown_border": "#423363", "dropdown_focus": "#B47AFF",
        "dropdown_hover": "#231B36", "dropdown_text": "#E8DCFF",
        "radius": 8,
    },
}

_TILE_SELECTORS = (
    "QFrame#toggleOption", "QFrame#proxyModeOption[active]", "QFrame#tunModeOption[active]",
    "QFrame#gatewayModeOption[state]", "QFrame#carrierControl",
)
_TILE_PREFIX = "QFrame#quickControls "

_STYLE = Template("""
QFrame#quickControls { background: $surface; border-color: $border; border-radius: 14px; }
QLabel#quickControlsTitle { color: $text; $heading_font }
QLabel#quickControlsStamp { color: $secondary; font-size: 10px; }
$tiles { background: $tile_fill; border: 1px solid $border; border-radius: ${radius}px; }
$hover_tiles { background: $hover; border-color: $hover_border; }
QFrame#quickControls QPushButton#advancedButton { padding: 0 11px; border-radius: ${radius}px; border-color: $border; background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 $tile,stop:1 $action); color: $text; $label_font }
QFrame#quickControls QPushButton#advancedButton:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 $hover,stop:1 $action); border-color: $hover_border; }
QFrame#quickControls QPushButton#advancedButton:focus { border-color: $icon; }
QFrame#quickControls QLabel#controlLabel { color: $text; $label_font }
""")

_DROPDOWN_STYLE = Template("""
QFrame#quickControls QComboBox#carrierModeCombo { color: $dropdown_text; background: $dropdown_surface; border: 1px solid $dropdown_border; border-radius: 6px; $label_font min-height: 0; padding: 0 0 0 8px; }
QFrame#quickControls QComboBox#carrierModeCombo:hover, QFrame#quickControls QComboBox#carrierModeCombo:focus { background: $dropdown_hover; border-color: $dropdown_focus; }
QFrame#quickControls QComboBox#carrierModeCombo::drop-down { width: 20px; }
QFrame#quickControls QComboBox#carrierModeCombo::down-arrow { width: 11px; height: 11px; }
""")

_XRAY_DETAILS_STYLE = Template("""
QFrame#quickControls QToolButton#gatewayDevicesBadge { min-width: 0; padding: 0 2px; color: $secondary; background: transparent; border: 1px solid transparent; border-radius: 6px; }
QFrame#quickControls QToolButton#gatewayDevicesBadge:hover, QFrame#quickControls QToolButton#gatewayDevicesBadge:focus { background: $gradient; border-color: $border; }
QFrame#quickControls QComboBox#carrierModeCombo::down-arrow { image: none; }
QFrame#quickControls QComboBox#carrierModeCombo QAbstractItemView { background: $surface; border-color: $border; selection-background-color: $border; selection-color: $accent; }
""")


def style(engine):
    palette = PALETTES[engine]
    secondary = dashboard_text_color(palette["secondary"]).name()
    tile_fill = palette["tile"]
    if engine == "xray":
        tile_fill = f"qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 {palette['action']},stop:1 {tile_fill})"
    stylesheet = _STYLE.substitute(
        palette,
        text=dashboard_text_color(palette["text"]).name(),
        secondary=secondary,
        heading_font=DASHBOARD_HEADING_QSS,
        label_font=DASHBOARD_LABEL_QSS,
        tile_fill=tile_fill,
        tiles=", ".join(_TILE_PREFIX + tile for tile in _TILE_SELECTORS),
        hover_tiles=", ".join(_TILE_PREFIX + tile + ":hover" for tile in _TILE_SELECTORS),
    )
    if "dropdown_surface" in palette:
        stylesheet += _DROPDOWN_STYLE.substitute(
            palette,
            dropdown_hover=palette.get("dropdown_hover", palette["hover"]),
            dropdown_text=dashboard_text_color(palette.get("dropdown_text", palette["text"])).name(),
            label_font=DASHBOARD_LABEL_QSS,
        )
    if engine == "xray":
        stylesheet += _XRAY_DETAILS_STYLE.substitute(XRAY_DASHBOARD, secondary=secondary)
    return stylesheet
