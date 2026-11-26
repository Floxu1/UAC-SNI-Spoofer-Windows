"""Shared confirmation for changing engines while a connection is active."""
from __future__ import annotations

from string import Template

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import QDialog, QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from .direct_theme import CONNECTION_ACCENTS
from .fonts import UI_STACK_FA
from .icons import icon, pixmap
from .theme import APP_ROUTING_PALETTES, ENGINE_BRAND_PALETTES, IP_DETAILS_PALETTES


_NAMES = {"xray": "Xray", "pow": "UAC PoW", "direct": "UAC Direct"}
_STATES = {
    "connected": ("اتصال فعال", "Connected"),
    "connecting": ("در حال اتصال", "Connecting"),
    "reconnecting": ("در حال اتصال مجدد", "Reconnecting"),
    "disconnecting": ("در حال قطع اتصال", "Disconnecting"),
    "disconnected": ("اتصال قطع است", "Disconnected"),
    "paused": ("اتصال در حالت مکث", "Paused"),
    "error": ("خطای اتصال", "Connection failed"),
}
_STYLE = Template("""
QFrame#switchShell {
    background: qlineargradient(x1:0,y1:1,x2:1,y2:0,stop:0 $background,stop:0.62 $surface,stop:1 $selected);
    border: 1px solid $edge; border-radius: 12px;
}
QLabel, QPushButton {
    color: $text; font-family: $font; font-size: 12px;
}
QLabel { background: transparent; border: none; }
QPushButton { min-height: 41px; max-height: 41px; min-width: 0; padding: 0; margin: 0; }
QLabel#switchTitle { font-size: 18px; font-weight: 700; }
QLabel#switchName { font-size: 15px; font-weight: 700; }
QLabel#switchMuted { font-size: 11px; color: $muted; }
QLabel#switchMark { background: $selected; border: 1px solid $edge; border-radius: 11px; }
QFrame#switchWarning { background: $tile; border-radius: 7px; }
QFrame#switchFooter { border-top: 1px solid $edge; background: transparent; }
QPushButton#switchCancel {
    background: $tile; border: 1px solid $edge; border-radius: 7px; min-width: 120px; max-width: 120px;
}
QPushButton#switchGo {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 $accent,stop:1 $pill_dark);
    color: $button_text; border: 1px solid $pill_light; border-radius: 7px; font-size: 13px; font-weight: 700;
}
QPushButton#switchCancel:hover { background: $hover; }
QPushButton#switchGo:hover {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 $pill_light,stop:1 $accent);
}
QPushButton#switchCancel:focus { border-color: $selected_border; }
QPushButton#switchGo:focus { border-color: $text; }
""")


class SharedEngineSwitchDialog(QDialog):
    def __init__(self, parent, language, current, target, state):
        super().__init__(parent, Qt.Dialog | Qt.FramelessWindowHint)
        self._language = language
        self._current = current
        details = IP_DETAILS_PALETTES[current]
        colors = {**ENGINE_BRAND_PALETTES[current], **APP_ROUTING_PALETTES[current],
                  **{key: details[key] for key in ("accent", "edge", "button_text")}}
        accent = colors["accent"]
        self.setWindowTitle(self._tr("تعویض موتور", "Switch engine"))
        self.setObjectName("engineSwitchConfirm")
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setModal(True)
        self.setFixedWidth(440)
        self.setLayoutDirection(Qt.LeftToRight if language == "en" else Qt.RightToLeft)
        self.setStyleSheet(_STYLE.substitute(colors, font=UI_STACK_FA))

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        shell = QFrame(objectName="switchShell")
        outer.addWidget(shell)
        root = QVBoxLayout(shell)
        root.setContentsMargins(1, 1, 1, 1)
        root.setSpacing(0)
        body = QVBoxLayout()
        body.setContentsMargins(20, 23, 20, 17)
        body.setSpacing(0)
        root.addLayout(body, 1)

        header = QHBoxLayout()
        header.setSpacing(10)
        mark = self._glyph("arrow-right-left", accent, 26, 44)
        mark.setObjectName("switchMark")
        header.addWidget(mark)
        heading = QVBoxLayout()
        heading.setSpacing(2)
        self.title = QLabel(self.windowTitle(), objectName="switchTitle")
        heading.addWidget(self.title)
        heading.addWidget(QLabel(self._tr("تعویض مسیر اتصال", "Change the connection engine"), objectName="switchMuted"))
        header.addLayout(heading, 1)
        body.addLayout(header)
        body.addSpacing(21)

        cards = QWidget()
        cards.setLayoutDirection(Qt.LeftToRight)
        cards.setFixedHeight(113)
        row = QHBoxLayout(cards)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(14)
        self.current_card = self._card(current, False)
        self.target_card = self._card(target, True)
        row.addWidget(self.current_card, 1)
        row.addWidget(self._glyph("arrow-right", accent, 35, 34))
        row.addWidget(self.target_card, 1)
        body.addWidget(cards)
        body.addSpacing(16)

        warning = QFrame(objectName="switchWarning")
        warning.setFixedHeight(45)
        warning_row = QHBoxLayout(warning)
        warning_row.setContentsMargins(12, 0, 12, 0)
        warning_row.setSpacing(7)
        warning_row.addWidget(self._glyph("info", accent, 15, 16))
        warning_row.addWidget(QLabel(self._tr("برای تعویض موتور، اتصال فعلی قطع خواهد شد.",
                                             "Switching engines will end your current connection.")), 1)
        body.addWidget(warning)

        footer = QFrame(objectName="switchFooter")
        buttons = QHBoxLayout(footer)
        buttons.setContentsMargins(20, 14, 20, 14)
        buttons.setSpacing(8)
        self.go_btn = QPushButton(icon("arrow-right-left", colors["button_text"], 18),
                                  self._tr("قطع اتصال و تعویض", "Disconnect and switch"), objectName="switchGo")
        self.go_btn.setIconSize(QSize(18, 18))
        self.cancel_btn = QPushButton(self._tr("انصراف", "Cancel"), objectName="switchCancel")
        self.cancel_btn.setFixedWidth(122)
        for button, action, stretch in ((self.go_btn, self.accept, 1), (self.cancel_btn, self.reject, 0)):
            button.setFixedHeight(43)
            button.setCursor(Qt.PointingHandCursor)
            button.clicked.connect(action)
            buttons.addWidget(button, stretch)
        root.addWidget(footer)
        self.cancel_btn.setDefault(True)
        self.cancel_btn.setFocus()
        self.set_connection_state(state)
        self.ensurePolished()
        self.setFixedHeight(outer.sizeHint().height())

    def _tr(self, fa, en):
        return en if self._language == "en" else fa

    @staticmethod
    def _glyph(name, color, size, tile):
        label = QLabel(alignment=Qt.AlignCenter)
        label.setFixedSize(tile, tile)
        label.setPixmap(pixmap(name, color, size))
        return label

    def _card(self, engine, target):
        from .ui import _engine_mark

        theme = APP_ROUTING_PALETTES[engine]
        colors = IP_DETAILS_PALETTES[engine]
        accent = colors["accent"]
        edge = theme["selected_border"] if target else colors["edge"]
        card = QFrame(objectName="switchEngineCard")
        card.setProperty("engineKey", engine)
        card.setFixedHeight(113)
        fill = (f"qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 {theme['selected']},stop:1 {theme['background']})"
                if target else theme["tile"])
        card.setStyleSheet(f"QFrame#switchEngineCard {{background: {fill}; border: 1px solid {edge}; border-radius: 9px;}}")
        stack = QVBoxLayout(card)
        stack.setContentsMargins(6, 10, 6, 10)
        stack.setSpacing(4)
        mark = QLabel(alignment=Qt.AlignCenter, objectName="switchMark")
        mark.setFixedSize(36, 36)
        mark.setPixmap(_engine_mark(engine, 25, accent))
        mark.setStyleSheet(f"background: {theme['selected']}; border-color: {edge}; border-radius: 7px;")
        stack.addWidget(mark, 0, Qt.AlignHCenter)
        stack.addWidget(QLabel(_NAMES[engine], alignment=Qt.AlignCenter, objectName="switchName"))
        caption = QLabel(self._tr("موتور جدید", "New engine") if target else "",
                         alignment=Qt.AlignCenter, objectName="switchMuted")
        caption.setFixedHeight(16)
        stack.addWidget(caption)
        if not target:
            self.current_status = caption
        return card

    def set_connection_state(self, state):
        text = self._tr(*_STATES.get(state, _STATES["disconnected"]))
        color = CONNECTION_ACCENTS.get(state, CONNECTION_ACCENTS["disconnected"])
        if state == "connected" and self._current != "direct":
            color = IP_DETAILS_PALETTES[self._current]["accent"]
        dot = f'<span style="color:{color}">●</span>'
        direction = "ltr" if self._language == "en" else "rtl"
        self.current_status.setText(f'<span dir="{direction}">{dot}&nbsp; {text}</span>')
