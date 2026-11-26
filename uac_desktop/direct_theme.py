"""Carbon, graphite and ember styling for the shared desktop shell."""

from string import Template

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QConicalGradient, QLinearGradient, QPainterPath, QPen, QRadialGradient

from .paths import ASSETS
from .theme import DIRECT_PALETTE


# Gradient start, gradient end, button border, button text, status accent.
CONNECTION_COLORS = {
    "disconnected": ("#FFB477", "#FF8038", "#FFAA6D", "#17110D", "#FF974D"),
    "connected": ("#287C60", "#1B5947", "#468F75", "#E1FFF2", "#65CBA3"),
    "connecting": ("#493922", "#30261B", "#806039", "#F3CE91", "#E9BC60"),
    "reconnecting": ("#493020", "#302219", "#956238", "#FFD0A3", "#E6A15C"),
    "disconnecting": ("#303337", "#242628", "#494D52", "#C2C6CC", "#A1A8B0"),
    "error": ("#803544", "#592630", "#A54C5B", "#FFE4E8", "#F18A98"),
}
CONNECTION_ACCENTS = {state: colors[4] for state, colors in CONNECTION_COLORS.items()}
CONNECTION_ACCENTS["paused"] = DIRECT_PALETTE["primary"]
HERO_CONNECTED_WORD = "#3CF0AF"
BUTTON_TEXT_COLORS = {state: colors[3] for state, colors in CONNECTION_COLORS.items()}
BUTTON_TEXT_COLORS["paused"] = DIRECT_PALETTE["text"]
ORBIT_SPEEDS = {"disconnected": .38, "connecting": 4.5, "connected": 1.15, "error": .48, "paused": .28}
ORBIT_INTENSITY = {"disconnected": 118, "connecting": 245, "connected": 224, "error": 235, "paused": 126}
CARD_BORDERS = {
    "disconnected": "#38312C",
    "connected": "#2C3833",
    "error": "#382D30",
}
CONNECTION_BORDER_MS = 500


def _connection_style():
    rules = []
    for state, (start, end, border, text, accent) in CONNECTION_COLORS.items():
        button = f'QPushButton#connectButton[directState="{state}"]'
        rules.append(f"""
{button}, {button}:hover, {button}:disabled {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {start},stop:1 {end});
    border-color: {border};
    color: {text};
}}
QFrame#statusPill[directState="{state}"] QLabel#statusPillText {{ color: {accent}; }}
""")
    return "".join(rules)


STYLE = Template("""
QMainWindow, QWidget#windowRoot { background: $background; }
QFrame#sidebar { background: $sidebar; border-right-color: $border; }
QFrame#sidebar[rtl="true"] { border-left-color: $border; }
QFrame#sidebarFooter { background: $surface; border-color: $border; }
QPushButton#navButton { color: $secondary; }
QPushButton#navButton:hover { background: $surface; border-color: $border; color: $text; }
QPushButton#navButton:checked { background: $selected; color: $accent; border-color: $ember_border; border-left-color: $primary; }
QPushButton#navButton[rtl="true"]:checked { border-left-color: transparent; border-right-color: $primary; }
QPushButton#footerAction { color: $secondary; }
QPushButton#footerAction:hover { background: $surface; border-color: $border; color: $text; }
QFrame#ratingCard { background: $surface; border-color: $border; }
QLabel#ratingTitle { color: $text; }
QLabel#ratingText { color: $secondary; }
QPushButton#ratingButton { background: $raised; color: $text; border-color: #3b3d41; }
QPushButton#ratingButton:hover { background: $selected; border-color: $ember_border; }
QFrame#pageHeader { background: $surface; border-color: $border; }
QWidget#homePage QFrame#pageHeader { background: transparent; border-color: transparent; }
QLabel#pageTitle { color: $text; }
QLabel#pageSubtitle { color: $secondary; }
QFrame#statusPill, QFrame#statusPill[state="connected"], QFrame#statusPill[state="connecting"], QFrame#statusPill[state="error"] { background: $surface; border-color: $border; }
QLabel#statusPillText { color: $secondary; }
QFrame#heroCard { background: #151618; border-color: transparent; }
QFrame#orbShell { background: rgba(23,25,28,0.35); border-color: transparent; }
QLabel#orbCaption { color: #baa492; }
QLabel#heroBadge { color: $accent; }
QLabel#heroStatus, QLabel#heroStatusOn, QLabel#heroStatusError { color: $text; }
QLabel#heroStatusOn { color: #CFFFF9; }
QLabel#heroHint { color: $secondary; }
QPushButton#connectButton[directState="paused"] { background: $raised; color: $text; border-color: #4d5056; }
QPushButton#connectButton[directState="paused"]:hover { background: #303338; border-color: #65686f; }
QFrame#countrySelectorCard, QFrame#countrySelectorCard:hover, QFrame#countrySelectorCard[mode="manual"], QFrame#quickControls, QFrame#activityBar, QFrame#card, QFrame#settingsCard { background: $surface; border-color: $border; }
QLabel#countryIcon { background: $selected; border-color: $ember_border; }
QLabel#countryTitle { color: $text; }
QLabel#countryDescription { color: $secondary; }
QPushButton#powExitSelector { background: $raised; border-color: #393b40; }
QPushButton#powExitSelector:hover, QPushButton#powExitSelector:focus { background: $surface; border-color: $ember_border; }
QLabel#powExitBadge, QLabel#powExitChevron, QPushButton#powExitSelector:hover QLabel#powExitChevron { background: transparent; border-color: transparent; }
QLabel#powExitTitle { color: $text; }
QLabel#fieldLabel { color: $secondary; }
QLabel#controlLabel { color: #c4c5cb; }
QFrame#activityBar[state="success"], QFrame#activityBar[state="warning"], QFrame#activityBar[state="error"] { border-color: $border; }
QLabel#activityMessage { color: $secondary; }
QComboBox::down-arrow { image: url("$chevron"); }
QCheckBox::indicator:checked { image: url("$check"); }
""").substitute(DIRECT_PALETTE, chevron=(ASSETS / "ui" / "lucide-direct-chevron-down.svg").as_posix(),
                check=(ASSETS / "ui" / "lucide-direct-check.svg").as_posix()) + _connection_style()


def paint_card_wash(painter, rect):
    width, height = rect.width(), rect.height()
    mask = QPainterPath()
    mask.addRoundedRect(rect.adjusted(1, 1, -1, -1), 13, 13)
    painter.setClipPath(mask, Qt.IntersectClip)
    glow = QRadialGradient(QPointF(width * .18, height * .52), max(90, width * .42))
    glow.setColorAt(0, QColor(153, 75, 25, 53))
    glow.setColorAt(1, Qt.transparent)
    painter.fillRect(rect, glow)


def connection_edge_colors(state):
    return (
        QColor(CARD_BORDERS.get(state, CARD_BORDERS["disconnected"])),
        QColor(CONNECTION_ACCENTS.get(state, CONNECTION_ACCENTS["disconnected"])),
    )


def paint_orbit(painter, rect, color, rotation, state):
    size = min(rect.width(), rect.height())
    bounds = rect.adjusted(size * .028, size * .028, -size * .028, -size * .028)
    track = QColor(color)
    track.setAlpha(46)
    painter.setBrush(Qt.NoBrush)
    painter.setPen(QPen(track, max(.8, size / 224)))
    painter.drawEllipse(bounds)

    sweep = QConicalGradient(bounds.center(), rotation)
    intensity = ORBIT_INTENSITY.get(state, ORBIT_INTENSITY["disconnected"])
    for position, fraction in ((0, 0), (.56, 0), (.68, .16), (.89, .75), (.945, 1), (1, 0)):
        tint = QColor(color)
        tint.setAlpha(round(intensity * fraction))
        sweep.setColorAt(position, tint)
    width = 2.8 if state == "connecting" else 2.1
    painter.setPen(QPen(sweep, max(1.3, width * size / 224)))
    painter.drawEllipse(bounds)


def paint_connection_edge(painter, rect, border, reflection):
    painter.setBrush(Qt.NoBrush)
    painter.setPen(QPen(border, 1))
    painter.drawRoundedRect(rect.adjusted(.5, .5, -.5, -.5), 25.5, 25.5)

    inset = max(26, rect.width() * .18)
    start = QPointF(rect.left() + inset, rect.top() + 1.5)
    end = QPointF(rect.right() - inset, start.y())
    gradient = QLinearGradient(start, end)
    for position, alpha in ((0, 0), (.25, 23), (.5, 82), (.75, 23), (1, 0)):
        color = QColor(reflection)
        color.setAlpha(alpha)
        gradient.setColorAt(position, color)
    painter.setPen(QPen(gradient, 1, Qt.SolidLine, Qt.FlatCap))
    painter.drawLine(start, end)
