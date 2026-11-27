"""Obsidian and violet styling for the UAC Tor engine."""

from string import Template

from .paths import ASSETS
from .theme import TOR_PALETTE

STYLE = Template("""
QMainWindow, QWidget#windowRoot { background: $background; }
QFrame#sidebar { background: $sidebar; border-right-color: $border; }
QFrame#sidebar[rtl="true"] { border-left-color: $border; }
QFrame#sidebarFooter { background: $surface; border-color: $border; }
QPushButton#navButton { color: $secondary; }
QPushButton#navButton:hover { background: $surface; border-color: $border; color: $text; }
QPushButton#navButton:checked { background: $selected; color: $accent; border-color: $violet_border; border-left-color: $primary; }
QPushButton#navButton[rtl="true"]:checked { border-left-color: transparent; border-right-color: $primary; }
QPushButton#footerAction { color: $secondary; }
QPushButton#footerAction:hover { background: $surface; border-color: $border; color: $text; }
QFrame#ratingCard { background: $surface; border-color: $border; }
QLabel#ratingTitle { color: $text; }
QLabel#ratingText { color: $secondary; }
QPushButton#ratingButton { background: $raised; color: $text; border-color: #3c3252; }
QPushButton#ratingButton:hover { background: $selected; border-color: $violet_border; }
QFrame#pageHeader { background: $surface; border-color: $border; }
QWidget#homePage QFrame#pageHeader { background: transparent; border-color: transparent; }
QLabel#pageTitle { color: $text; }
QLabel#pageSubtitle { color: $secondary; }
QFrame#heroCard { background: #120f1c; border-color: $border; }
QFrame#orbShell { background: rgba(20,17,29,0.45); border-color: transparent; }
QLabel#orbCaption { color: #b79de0; }
QLabel#heroBadge { color: $accent; }
QLabel#heroStatus, QLabel#heroStatusOn, QLabel#heroStatusError { color: $text; }
QLabel#heroStatusOn { color: #e2d4ff; }
QLabel#heroHint { color: $secondary; }
QFrame#countrySelectorCard, QFrame#countrySelectorCard:hover, QFrame#countrySelectorCard[mode="manual"],
QFrame#quickControls, QFrame#activityBar, QFrame#card, QFrame#settingsCard { background: $surface; border-color: $border; }
QLabel#countryIcon { background: $selected; border-color: $violet_border; }
QLabel#countryTitle { color: $text; }
QLabel#countryDescription { color: $secondary; }
QPushButton#powExitSelector { background: $raised; border-color: #3a2f52; }
QPushButton#powExitSelector:hover, QPushButton#powExitSelector:focus { background: $surface; border-color: $violet_border; }
QLabel#powExitTitle { color: $text; }
QLabel#controlLabel { color: #d5cce6; }
QLabel#activityMessage { color: $secondary; }
""").substitute(TOR_PALETTE)
