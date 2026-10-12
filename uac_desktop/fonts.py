"""Bundled UI fonts.

* Inter (OFL) for English/Latin text,
* Vazirmatn UI FD (OFL, same files as the Android build) for Persian,
* JetBrains Mono (OFL) for numbers: IP, ping, speed, stats and counters.

The files live in ``assets/fonts`` which the PyInstaller spec ships as part of
the ``assets`` tree; ``paths.ASSETS`` already resolves to ``sys._MEIPASS`` in a
frozen build.
"""
from __future__ import annotations

import re

from PySide6.QtGui import QFont, QFontDatabase

from .paths import ASSETS

LATIN = "Inter"
PERSIAN = "Vazirmatn UI FD"
MONO = "JetBrains Mono"

FONT_FILES = (
    "Inter-Regular.ttf", "Inter-Medium.ttf", "Inter-SemiBold.ttf", "Inter-Bold.ttf",
    "vazirmatn_ui_fd_regular.ttf", "vazirmatn_ui_fd_medium.ttf",
    "vazirmatn_ui_fd_semibold.ttf", "vazirmatn_ui_fd_bold.ttf",
    "JetBrainsMono-Regular.ttf", "JetBrainsMono-Medium.ttf",
    # Legacy family kept registered for any code that still asks for it.
    "Vazirmatn-Regular.ttf", "Vazirmatn-Bold.ttf",
)

# QSS family stacks. The fa stylesheet swaps the first two entries.
UI_STACK_EN = f'"{LATIN}", "{PERSIAN}", "Segoe UI"'
UI_STACK_FA = f'"{PERSIAN}", "{LATIN}", "Segoe UI"'
MONO_STACK = f'"{MONO}", "{PERSIAN}", "Consolas"'

_LOADED: dict[str, list[str]] = {}


def font_dir():
    return ASSETS / "fonts"


def load_fonts() -> dict[str, list[str]]:
    """Register the bundled fonts once; returns {file: [families]}."""
    if _LOADED:
        return dict(_LOADED)
    for name in FONT_FILES:
        path = font_dir() / name
        if not path.exists():
            continue
        font_id = QFontDatabase.addApplicationFont(str(path))
        if font_id >= 0:
            _LOADED[name] = list(QFontDatabase.applicationFontFamilies(font_id))
    # Glyph fallback in both directions (Latin inside Persian text and back).
    QFont.insertSubstitutions(LATIN, [PERSIAN, "Segoe UI"])
    QFont.insertSubstitutions(PERSIAN, [LATIN, "Segoe UI"])
    QFont.insertSubstitutions(MONO, [PERSIAN, "Consolas"])
    return dict(_LOADED)


def ui_families(language: str) -> list[str]:
    if language == "fa":
        return [PERSIAN, LATIN, "Segoe UI"]
    return [LATIN, PERSIAN, "Segoe UI"]


def mono_families() -> list[str]:
    return [MONO, PERSIAN, "Consolas"]


def _tune(font: QFont) -> QFont:
    font.setStyleStrategy(QFont.StyleStrategy(
        QFont.StyleStrategy.PreferAntialias | QFont.StyleStrategy.PreferQuality))
    font.setHintingPreference(QFont.HintingPreference.PreferVerticalHinting)
    font.setKerning(True)
    return font


LATIN_TRACKING = 101.5  # percent; never negative, never on Persian


def make_font(language: str = "en", point_size: float = 10,
              weight: QFont.Weight = QFont.Weight.Normal) -> QFont:
    font = QFont()
    font.setFamilies(ui_families(language))
    font.setPointSizeF(point_size)
    font.setWeight(weight)
    font.setLetterSpacing(QFont.SpacingType.PercentageSpacing,
                          100.0 if language == "fa" else LATIN_TRACKING)
    return _tune(font)


def make_mono_font(point_size: float = 10,
                   weight: QFont.Weight = QFont.Weight.Medium) -> QFont:
    font = QFont()
    font.setFamilies(mono_families())
    font.setPointSizeF(point_size)
    font.setWeight(weight)
    return _tune(font)


def apply_app_font(app, language: str = "en") -> None:
    load_fonts()
    wanted = ui_families(language)
    current = app.font()
    tracking = 100.0 if language == "fa" else LATIN_TRACKING
    if (list(current.families()) == wanted
            and current.hintingPreference() == QFont.HintingPreference.PreferVerticalHinting
            and abs(current.letterSpacing() - tracking) < 0.01
            and current.letterSpacingType() == QFont.SpacingType.PercentageSpacing):
        return
    app.setFont(make_font(language))


def _weight(value: int) -> int:
    """Light, airy hierarchy: nothing heavier than Medium (real 500 cut)."""
    return 500 if value >= 500 else 400


MIN_PX = 12          # ~9pt captions; body stays 13px+ (~10pt)
MAX_TRACKING_PX = 1.2  # uppercase micro labels: ~110% at 12px


FONT_QSS = f"""
QLabel#metricLabel, QLabel#fieldLabel, QLabel#pageSubtitle, QLabel#powExitSubtitle,
QLabel#powDialogSubtitle, QLabel#gatewayPopupSubtitle, QLabel#powRowDesc {{ font-weight: 500; }}
QLabel#metricValue[numeric="true"] {{ font-family: {MONO_STACK}; font-weight: 500; font-size: 18px; }}
QLabel#profileRowPing, QLabel#scanDomain, QLabel#powPickerCount {{ font-family: {MONO_STACK}; font-weight: 500; }}
QLabel#metricSecondary {{ font-family: {UI_STACK_EN}; font-weight: 400; }}
QLabel#powRowDesc, QLabel#powHint, QLabel#powDetail, QLabel#heroHint, QLabel#helperText,
QLabel#powDialogSubtitle, QLabel#powExitSubtitle, QLabel#metricSecondary {{ padding-top: 2px; padding-bottom: 1px; }}
QLineEdit#numericEdit {{ font-family: {MONO_STACK}; font-weight: 500; }}
"""


def finish_style(css: str) -> str:
    css = re.sub(r"font-weight:\s*(\d+|bold|bolder)",
                 lambda m: f"font-weight: {_weight(700 if not m.group(1).isdigit() else int(m.group(1)))}", css)
    css = re.sub(r"font-size:\s*(\d+)px", lambda m: f"font-size: {max(MIN_PX, int(m.group(1)))}px", css)
    css = re.sub(r"letter-spacing:\s*(-?[\d.]+)px",
                 lambda m: f"letter-spacing: {min(MAX_TRACKING_PX, max(0.0, float(m.group(1)))):g}px", css)
    return css + FONT_QSS


def localize_style(css: str, language: str) -> str:
    if language == "fa":
        # Persian: Vazirmatn first and no tracking (letter spacing breaks joining).
        css = css.replace(UI_STACK_EN, UI_STACK_FA)
        css = re.sub(r"\s*letter-spacing:\s*[^;}]+;?", " ", css)
        # Live Logs body is Persian prose; JetBrains Mono first breaks Arabic joining.
        css = css.replace(
            'QTextEdit#logs { font-family: "JetBrains Mono", "Vazirmatn UI FD", "Consolas";',
            'QTextEdit#logs { font-family: "Vazirmatn UI FD", "JetBrains Mono", "Consolas";',
        )
    return css


def airy_html(text: str, rtl: bool = False, line_height: int = 145) -> str:
    """Rich text with a taller line height for wrapped descriptions."""
    import html as _html
    direction = " dir='rtl'" if rtl else ""
    body = _html.escape(text).replace("\n", "<br>")
    return f"<div{direction} style='line-height:{line_height}%'>{body}</div>"
