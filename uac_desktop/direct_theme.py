"""Carbon, graphite and ember styling for the shared desktop shell."""

from string import Template

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QLinearGradient, QPainterPath, QPen, QRadialGradient

from .paths import ASSETS
from .theme import DIRECT_PALETTE


CONNECTION_ACCENTS = {
    "disconnected": DIRECT_PALETTE["primary"],
    "connecting": "#FFAD62",
    "connected": "#50DBA5",
    "error": "#FF626C",
}
CARD_BORDERS = {
    "disconnected": "#38312C",
    "connected": "#2C3833",
    "error": "#382D30",
}
CONNECTION_BORDER_MS = 500
CONNECTED_BUTTON_TEXT = DIRECT_PALETTE["text"]
IDLE_BUTTON_TEXT = "#190F09"


STYLE = Template("""
QMainWindow, QWidget#windowRoot { background: $background; }
QFrame#sidebar { background: $sidebar; border-right-color: $border; }
QFrame#sidebar[rtl="true"] { border-left-color: $border; }
QFrame#logoCard { background: $surface; border-color: $border; }
QFrame#sidebarFooter { background: $surface; border-color: $border; }
QLabel#logoMark { background: $selected; border-color: $ember_border; }
QLabel#brand { color: $text; }
QLabel#brandEdition { color: $secondary; }
QFrame#engineSwitch { background: $raised; border-color: $border; }
QPushButton#engineOption { color: $secondary; }
QPushButton#engineOption:hover { background: $surface; border-color: $border; color: $text; }
QPushButton#engineOption:checked, QPushButton#engineOption:checked:hover { color: $accent; background: transparent; }
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
QFrame#statusPill, QFrame#statusPill[state="connected"], QFrame#statusPill[state="connecting"] { background: $surface; border-color: $border; }
QFrame#statusPill[state="connecting"] { border-color: $connecting; }
QFrame#statusPill[state="connected"] { border-color: $connected; }
QFrame#statusPill[state="error"] { background: $surface; border-color: $error; }
QLabel#statusPillText { color: $secondary; }
QFrame#statusPill[state="connecting"] QLabel#statusPillText { color: $connecting; }
QFrame#statusPill[state="connected"] QLabel#statusPillText { color: $connected; }
QFrame#statusPill[state="error"] QLabel#statusPillText { color: $error; }
QFrame#heroCard { background: #151618; border-color: transparent; }
QFrame#orbShell { background: rgba(23,25,28,0.35); border-color: transparent; }
QLabel#orbCaption { color: #baa492; }
QLabel#heroBadge { color: $accent; }
QLabel#heroStatus, QLabel#heroStatusOn, QLabel#heroStatusError { color: $text; }
QLabel#heroHint { color: $secondary; }
QPushButton#connectButton, QPushButton#connectButton[state="cancel"], QPushButton#connectButton[state="error"] { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 $accent,stop:1 $primary); color: $idle_button_text; border-color: #ffb889; }
QPushButton#connectButton:hover, QPushButton#connectButton[state="cancel"]:hover, QPushButton#connectButton[state="error"]:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #ffc393,stop:1 #ff8847); border-color: #ffd0ad; }
QPushButton#connectButton[state="connected"], QPushButton#connectButton[state="loading"]:disabled { background: $raised; color: $connected_button_text; border-color: #4d5056; }
QPushButton#connectButton[state="connected"]:hover { background: #303338; border-color: #65686f; }
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
""").substitute(DIRECT_PALETTE, **CONNECTION_ACCENTS,
                idle_button_text=IDLE_BUTTON_TEXT,
                connected_button_text=CONNECTED_BUTTON_TEXT, chevron=(ASSETS / "ui" / "lucide-direct-chevron-down.svg").as_posix(),
                check=(ASSETS / "ui" / "lucide-direct-check.svg").as_posix())


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
