"""Non-blocking coach-mark bubbles that point at a widget.

A bubble is a child overlay of the main window (no modal loop, nothing is
blocked), follows window moves/resizes and the target's position, and shows
one at a time through CoachQueue. Each key is shown once (settings flag).
"""
from __future__ import annotations

from PySide6.QtCore import QEvent, QObject, QPoint, QRect, QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

RLM = "\u200f"
ARROW = 10
RADIUS = 14


class CoachBubble(QWidget):
    def __init__(self, window, target, text, button_text, language="fa", on_close=None):
        super().__init__(window)
        self.window_ = window; self.target = target; self.on_close = on_close
        self.fa = language != "en"
        self.setObjectName("coachBubble")
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setLayoutDirection(Qt.RightToLeft if self.fa else Qt.LeftToRight)
        self.side = "below"
        root = QVBoxLayout(self); root.setContentsMargins(16, 14 + ARROW, 16, 12); root.setSpacing(10)
        self.label = QLabel((RLM if self.fa else "") + text); self.label.setWordWrap(True)
        self.label.setObjectName("coachText")
        self.label.setStyleSheet("color: #eaf6ff; font-size: 13px; background: transparent;")
        self.label.setAlignment((Qt.AlignRight if self.fa else Qt.AlignLeft) | Qt.AlignVCenter)
        row = QHBoxLayout(); row.addStretch(1)
        self.button = QPushButton(button_text); self.button.setObjectName("coachOk"); self.button.setCursor(Qt.PointingHandCursor)
        self.button.setStyleSheet(
            "QPushButton#coachOk { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #19d9c6, stop:1 #3f7dff);"
            " color: #04111f; border: none; border-radius: 11px; padding: 6px 18px; font-weight: 800; }"
            "QPushButton#coachOk:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #35f0dd, stop:1 #5c93ff); }")
        self.button.clicked.connect(self.dismiss)
        row.addWidget(self.button)
        root.addWidget(self.label); root.addLayout(row)
        self.setFixedWidth(320)
        window.installEventFilter(self)
        self._timer = QTimer(self); self._timer.setInterval(400); self._timer.timeout.connect(self.reposition)

    # -- geometry
    def target_rect(self) -> QRect:
        t = self.target
        if t is None or not t.isVisible():
            return QRect()
        return QRect(t.mapTo(self.window_, QPoint(0, 0)), t.size())

    def reposition(self):
        rect = self.target_rect()
        if rect.isNull():
            self.hide(); return
        self.adjustSize()
        w, h = self.width(), self.sizeHint().height()
        W, H = self.window_.width(), self.window_.height()
        below = rect.bottom() + 6 + h <= H - 8
        self.side = "below" if below else "above"
        m = self.layout().contentsMargins()
        if below:
            self.layout().setContentsMargins(m.left(), 14 + ARROW, m.right(), 12)
            y = rect.bottom() + 6
        else:
            self.layout().setContentsMargins(m.left(), 14, m.right(), 12 + ARROW)
            y = rect.top() - 6 - h
        x = rect.center().x() - w // 2
        x = max(8, min(x, W - w - 8))
        self.setGeometry(x, max(8, y), w, h)
        self._arrow_x = max(RADIUS + ARROW, min(rect.center().x() - x, w - RADIUS - ARROW))
        self.raise_(); self.update()

    def show_bubble(self):
        self.reposition(); self.show(); self.raise_(); self._timer.start()

    def eventFilter(self, obj, event):
        if obj is self.window_ and event.type() in (QEvent.Resize, QEvent.Move, QEvent.Show, QEvent.LayoutRequest):
            QTimer.singleShot(0, self.reposition)
        return False

    def dismiss(self):
        self._timer.stop()
        try:
            self.window_.removeEventFilter(self)
        except Exception:
            pass
        self.hide(); self.deleteLater()
        if callable(self.on_close):
            self.on_close()

    def paintEvent(self, _event):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        body = QRectF(self.rect()).adjusted(1, 1, -1, -1)
        ax = float(getattr(self, "_arrow_x", self.width() / 2))
        path = QPainterPath()
        if self.side == "below":
            body.setTop(body.top() + ARROW)
            path.addRoundedRect(body, RADIUS, RADIUS)
            tri = QPainterPath(); tri.moveTo(ax - ARROW, body.top() + 1); tri.lineTo(ax, body.top() - ARROW); tri.lineTo(ax + ARROW, body.top() + 1); tri.closeSubpath()
        else:
            body.setBottom(body.bottom() - ARROW)
            path.addRoundedRect(body, RADIUS, RADIUS)
            tri = QPainterPath(); tri.moveTo(ax - ARROW, body.bottom() - 1); tri.lineTo(ax, body.bottom() + ARROW); tri.lineTo(ax + ARROW, body.bottom() - 1); tri.closeSubpath()
        path = path.united(tri)
        p.setPen(QPen(QColor(35, 245, 224, 150), 1.2)); p.setBrush(QColor(9, 26, 46, 245))
        p.drawPath(path); p.end()


class CoachQueue(QObject):
    """One bubble at a time; waits while a modal dialog (e.g. the wizard) is open."""

    def __init__(self, window, settings, save, language_fn, is_blocked=None):
        super().__init__(window)
        self.window_ = window; self.settings = settings; self.save = save
        self.language_fn = language_fn; self.is_blocked = is_blocked or (lambda: False)
        self.pending: list = []; self.current = None
        self._timer = QTimer(self); self._timer.setInterval(700); self._timer.timeout.connect(self._pump)

    def seen(self, key) -> bool:
        return bool(self.settings.get(f"coach_{key}_seen", False))

    def enqueue(self, key, target_fn, text_fa, text_en, button_fa, button_en):
        if self.seen(key) or any(item[0] == key for item in self.pending) or (self.current and self.current[0] == key):
            return
        self.pending.append((key, target_fn, text_fa, text_en, button_fa, button_en))
        self._timer.start()

    def _pump(self):
        if self.current is not None or not self.pending:
            if not self.pending:
                self._timer.stop()
            return
        if self.is_blocked() or not self.window_.isVisible():
            return
        key, target_fn, tfa, ten, bfa, ben = self.pending[0]
        target = target_fn()
        if target is None or not target.isVisible():
            return
        self.pending.pop(0)
        fa = self.language_fn() != "en"
        bubble = CoachBubble(self.window_, target, tfa if fa else ten, bfa if fa else ben,
                             "fa" if fa else "en", on_close=lambda k=key: self._closed(k))
        self.current = (key, bubble)
        bubble.show_bubble()

    def _closed(self, key):
        self.settings[f"coach_{key}_seen"] = True
        try:
            self.save()
        except Exception:
            pass
        self.current = None
        if self.pending:
            self._timer.start()
