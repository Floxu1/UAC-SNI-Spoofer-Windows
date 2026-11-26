"""Fast, animated Xray <-> UAC PoW engine switch.

Why this exists: swapping the whole application stylesheet on every engine
switch made Qt re-parse ~390 rules and re-polish all ~1050 widgets (about
350-430 ms of frozen UI).  Instead we install ONE combined stylesheet in
which every rule is scoped to ``QMainWindow[engine="xray"|"pow"]``.  A
switch then only flips the window's ``engine`` property and re-polishes
the widgets that are on screen; hidden pages are re-polished lazily (just
before they are shown, or on idle ticks after the animation).

Scoping every rule with the same ancestor selector adds the same
specificity to all of them, so the cascade inside the window is exactly
the one of the original per-engine sheet.
"""

from __future__ import annotations

import re
from string import Template

from PySide6.QtCore import Property, QEasingCurve, QPointF, QPropertyAnimation, QRect, QRectF, Qt
from PySide6.QtGui import QColor, QLinearGradient, QPainter, QPainterPath, QPen, QRadialGradient, QRegion
from PySide6.QtWidgets import QFrame, QWidget

from .desktop_layout import ENGINE_OPTION_HEIGHT, ENGINE_SWITCH_HEIGHT
from .theme import ENGINE_BRAND_PALETTES

SWITCH_MS = 220          # pill slide (OutCubic)
FADE_MS = 200            # content cross-fade
ENGINE_PROPERTY = "engine"

_BRAND_RADIUS = 18
_BRAND_STYLE = Template("""
QFrame#logoCard {
    background: qlineargradient(x1:0,y1:1,x2:1,y2:0,stop:0 $surface,stop:0.38 $surface,stop:1 $tint);
    border: 1px solid $edge; border-radius: ${card_radius}px;
}
QLabel#logoMark {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 $glass,stop:1 $surface);
    border: 1px solid $edge; border-top-color: $accent; border-radius: 14px;
}
QLabel#brand { color: #F4F7FA; font-size: 18px; font-weight: 600; }
QLabel#brandEdition, QLabel#engineBadge { color: #AFBED0; font-size: 11px; font-weight: 500; }
QFrame#engineSwitch { background: $tray; border: 1px solid $surface; border-radius: ${tray_radius}px; }
QPushButton#engineOption { background: transparent; border: 1px solid transparent;
    min-height: ${option_body}px; max-height: ${option_body}px;
    border-radius: ${option_radius}px; padding: 0 2px; color: #B8C7D8; font-size: 11px; font-weight: 500; }
QPushButton#engineOption:hover { color: #F4F7FA; background: rgba(255,255,255,0.055); }
QPushButton#engineOption:focus { border-color: $edge; }
QPushButton#engineOption:checked { color: #08141B; font-weight: 600; }
QPushButton#engineOption:checked:hover { background: rgba(255,255,255,0.10); }
""")


def brand_style(engine: str) -> str:
    return _BRAND_STYLE.substitute(
        ENGINE_BRAND_PALETTES[engine], card_radius=_BRAND_RADIUS,
        tray_radius=ENGINE_SWITCH_HEIGHT // 2, option_radius=ENGINE_OPTION_HEIGHT // 2,
        option_body=ENGINE_OPTION_HEIGHT - 2,
    )


class EngineBrandCard(QFrame):
    """Shared brand panel with a soft reflection behind the existing controls."""

    def __init__(self):
        super().__init__()
        self.setObjectName("logoCard")
        self._accent = QColor(ENGINE_BRAND_PALETTES["xray"]["accent"])

    def set_engine(self, engine: str):
        accent = QColor(ENGINE_BRAND_PALETTES[engine]["accent"])
        if self._accent != accent:
            self._accent = accent
            self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        clip = QPainterPath()
        clip.addRoundedRect(QRectF(self.rect()).adjusted(1, 1, -1, -1), _BRAND_RADIUS - 1, _BRAND_RADIUS - 1)
        painter.setClipPath(clip)
        painter.translate(self.width() * .97, self.height() * .07)
        painter.rotate(-38)
        painter.scale(self.width() * .56, 11)
        reflection = QRadialGradient(QPointF(), 1)
        for position, opacity in ((0, 61), (.45, 23), (1, 0)):
            color = QColor(self._accent)
            color.setAlpha(opacity)
            reflection.setColorAt(position, color)
        painter.fillRect(QRectF(-1, -1, 2, 2), reflection)


_RULE = re.compile(r"([^{}]+)\{([^{}]*)\}", re.S)
_SELF_TYPES = ("QMainWindow", "QWidget", "*", "")


def _split_selectors(selector: str) -> list[str]:
    out, depth, current = [], 0, ""
    for ch in selector:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            if current.strip():
                out.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        out.append(current.strip())
    return out


def parse_rules(css: str) -> list[tuple[str, str]]:
    return [(m.group(1).strip(), m.group(2).strip()) for m in _RULE.finditer(css)]


def _scope_selector(selector: str, scope: str) -> str:
    parts = []
    for single in _split_selectors(selector):
        parts.append(f"{scope} {single}")
        simple = not re.search(r"[\s>]", single)
        type_name = re.match(r"[A-Za-z*]*", single).group(0)
        if simple and type_name in _SELF_TYPES:
            # Rules that can style the main window itself (e.g. its background).
            parts.append(scope + single[len(type_name):])
    return ", ".join(parts)


def engine_scope(engine: str) -> str:
    return f'QMainWindow[{ENGINE_PROPERTY}="{engine}"]'


def combine_styles(styles: dict[str, str]) -> str:
    """One stylesheet holding every engine's rules, each scoped to its engine.

    ``styles`` maps engine key -> that engine's full stylesheet.  Tooltip rules
    of the first engine are also emitted unscoped (lowest specificity) so a
    tooltip that is not parented inside the window is still themed.
    """
    keys = list(styles)
    parsed = {key: parse_rules(styles[key]) for key in keys}
    out = []
    first = parsed[keys[0]]
    out += [f"{s} {{ {b} }}" for s, b in first if "QToolTip" in s]
    for key in keys:
        scope = engine_scope(key)
        out += [f"{_scope_selector(s, scope)} {{ {b} }}" for s, b in parsed[key]]
    return "\n".join(out)


def _mix(a: QColor, b: QColor, t: float) -> QColor:
    return QColor(
        round(a.red() + (b.red() - a.red()) * t),
        round(a.green() + (b.green() - a.green()) * t),
        round(a.blue() + (b.blue() - a.blue()) * t),
        round(a.alpha() + (b.alpha() - a.alpha()) * t),
    )


class EngineThumb(QWidget):
    """The sliding highlight of the Xray / UAC PoW segmented switch.

    Painted by hand so both its position and its accent colours can be
    animated smoothly (a stylesheet change would snap).
    """

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.setObjectName("engineThumb")
        self.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self._palettes = {
            engine: tuple(QColor(tokens[key]) for key in ("pill_light", "accent", "pill_dark"))
            for engine, tokens in ENGINE_BRAND_PALETTES.items()
        }
        self._from = self._to = next(iter(self._palettes))
        self._mix = 1.0

    def set_engine(self, engine: str) -> None:
        self._from = self._to = engine
        self._mix = 1.0
        self.update()

    def blend_to(self, engine: str) -> None:
        self._from, self._to, self._mix = self._to, engine, 0.0
        self.update()

    def _get_mix(self) -> float:
        return self._mix

    def _set_mix(self, value: float) -> None:
        self._mix = max(0.0, min(1.0, float(value)))
        self.update()

    mix = Property(float, _get_mix, _set_mix)

    def colors(self) -> tuple[QColor, QColor, QColor]:
        a, b = self._palettes[self._from], self._palettes[self._to]
        return tuple(_mix(x, y, self._mix) for x, y in zip(a, b))

    def paintEvent(self, _event):
        start, accent, end = self.colors()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        rect = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        gradient = QLinearGradient(rect.topLeft(), rect.bottomRight())
        gradient.setColorAt(0.0, start)
        gradient.setColorAt(.52, accent)
        gradient.setColorAt(1.0, end)
        painter.setBrush(gradient)
        painter.setPen(QPen(QColor(255, 255, 255, 65), 1.0))
        radius = rect.height() / 2
        painter.drawRoundedRect(rect, radius, radius)


class SwitchOverlay(QWidget):
    """Snapshot of the window before the switch, faded out over the new look.

    The content area also shrinks/slides a touch while it fades.  A hole is
    left over the engine switch so its live pill animation stays visible.
    """

    def __init__(self, parent: QWidget, snapshot, content: QRect, hole: QRect):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents, False)  # swallow clicks mid-switch
        self.setAttribute(Qt.WA_OpaquePaintEvent, False)
        self._snapshot = snapshot
        self._content = QRect(content)
        self._hole = QRect(hole)
        self._progress = 0.0
        self.setGeometry(parent.rect())

    def _get_progress(self) -> float:
        return self._progress

    def _set_progress(self, value: float) -> None:
        self._progress = max(0.0, min(1.0, float(value)))
        self.update()

    progress = Property(float, _get_progress, _set_progress)

    def paintEvent(self, _event):
        p = self._progress
        if p >= 1.0:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.SmoothPixmapTransform, True)
        dpr = self._snapshot.devicePixelRatio() or 1.0
        full = QRegion(self.rect()).subtracted(QRegion(self._hole))
        painter.setOpacity(1.0 - p)
        # Chrome (sidebar etc.) fades in place.
        painter.setClipRegion(full.subtracted(QRegion(self._content)))
        painter.drawPixmap(0, 0, self._snapshot)
        # Content fades while easing back/down slightly.
        painter.setClipRegion(full.intersected(QRegion(self._content)))
        scale = 1.0 - 0.02 * p
        center = QPointF(self._content.center())
        painter.translate(center.x(), center.y() + 8.0 * p)
        painter.scale(scale, scale)
        painter.translate(-center.x(), -center.y())
        source = QRect(
            round(self._content.x() * dpr), round(self._content.y() * dpr),
            round(self._content.width() * dpr), round(self._content.height() * dpr),
        )
        painter.drawPixmap(QRectF(self._content), self._snapshot, QRectF(source))


def make_animation(target, prop: bytes, start, end, duration: int = SWITCH_MS, curve=QEasingCurve.OutCubic, parent=None):
    animation = QPropertyAnimation(target, prop, parent)
    animation.setDuration(duration)
    animation.setStartValue(start)
    animation.setEndValue(end)
    animation.setEasingCurve(curve)
    return animation
