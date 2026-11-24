"""Shared Rive waves for the desktop connection card."""

import base64
import time

from PySide6.QtCore import QObject, QRect, QRectF, Qt, QTimer, QUrl
from PySide6.QtGui import QColor, QImage, QLinearGradient, QPainter, QPainterPath
from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineSettings

from . import theme
from .paths import ASSETS


_ASSETS = ASSETS / "ui" / "velocity-energy-flow"


class VelocityFlow(QObject):
    _STATES = {"connecting": 1, "connected": 2, "error": 3}

    def __init__(self, card, orb, engine):
        super().__init__(card)
        self._card = card
        self._orb = orb
        # Composite Rive's alpha in the same painter as the connection card.
        self.page = QWebEnginePage(self)
        self.page.settings().setAttribute(QWebEngineSettings.LocalContentCanAccessRemoteUrls, False)
        self.page.setVisible(False)
        self._poster = QImage(str(_ASSETS / "idle.png"))
        self._frame = QImage()
        self._wave = QImage()
        self._engine = None
        self._colors = ()
        self._band = QRect()
        self._clip = QPainterPath()
        self._frame_pending = False
        self._ready = False
        self._visible = False
        self._state = 0
        self._running = False
        self._traffic_sample = None
        self._energy = 0.0
        self._frames = QTimer(self, interval=33)
        self._frames.timeout.connect(self._request_frame)
        self.page.loadFinished.connect(self._loaded)
        self.page.load(QUrl.fromLocalFile(str(_ASSETS / "index.html")))
        self.set_engine(engine)
        self.fit_card()

    def fit_card(self):
        card = self._card
        top = round(card.height() * .46)
        self._band = QRect(2, top, max(0, card.width() - 4), max(0, card.height() - top - 6))
        self._clip = QPainterPath()
        self._clip.addRoundedRect(QRectF(card.rect()).adjusted(1, 1, -1, -1), 25, 25)
        if self._ready:
            self._resize_canvas()
            self._request_frame()

    def paint(self, painter):
        if self._visible:
            painter.save()
            painter.setClipPath(self._clip, Qt.IntersectClip)
            if self._card.layoutDirection() == Qt.LeftToRight:
                painter.translate(2 * self._band.x() + self._band.width(), 0)
                painter.scale(-1, 1)
            painter.drawImage(self._band, self._wave)
            painter.restore()

    def set_engine(self, engine):
        colors = theme.connection_wave_colors(engine)
        if engine == self._engine and colors == self._colors:
            return
        changed = engine != self._engine
        self._engine, self._colors = engine, colors
        self._refresh_wave()
        if changed:
            self._traffic_sample = None
            self._energy = 0.0
            self._send(0.0)
        self._card.update(self._band)

    def _refresh_wave(self):
        source = self._poster if self._frame.isNull() else self._frame
        if not self._colors or source.isNull():
            self._wave = source
            return
        self._wave = source.convertToFormat(QImage.Format_ARGB32_Premultiplied)
        tint = QLinearGradient(0, 0, source.width(), 0)
        start, end = map(QColor, self._colors)
        tint.setColorAt(0, start)
        tint.setColorAt(.6, end.lighter(140))
        tint.setColorAt(1, end)
        painter = QPainter(self._wave)
        painter.setCompositionMode(QPainter.CompositionMode_SourceIn)
        painter.fillRect(self._wave.rect(), tint)
        painter.end()

    def set_active(self, visible, running):
        running = bool(visible and running)
        if visible == self._visible and running == self._running:
            return
        self._visible = visible
        self._running = running
        self.page.setVisible(running)
        self._send()
        if running:
            self._frames.start()
        else:
            self._frames.stop()
        self._card.update(self._band)

    def set_connection_state(self, state):
        value = self._STATES.get(state, 0)
        if value == self._state:
            return
        self._state = value
        self._energy = 0.0
        self._traffic_sample = None
        self._send(0.0)

    def set_traffic_counters(self, sent, received):
        if self._state != self._STATES["connected"]:
            return
        now = time.monotonic()
        previous = self._traffic_sample
        self._traffic_sample = (now, sent, received)
        if previous is None:
            return
        last_time, last_sent, last_received = previous
        if sent < last_sent or received < last_received:
            self._energy = 0.0
        elif now - last_time < .5:
            self._traffic_sample = previous
            return
        else:
            rate = (sent - last_sent + received - last_received) / (now - last_time)
            self._energy = round(rate / (rate + 384 * 1024), 3)
        self._send(self._energy)

    def _loaded(self, ok):
        self._ready = ok
        if ok:
            self._resize_canvas()
            self._send(self._energy)

    def _resize_canvas(self):
        width = min(self._band.width(), 1200)
        height = min(self._band.height(), 180)
        self.page.runJavaScript(f"resizeVelocityFlow({width}, {height});")

    def _request_frame(self):
        if not (self._ready and self._visible and self._running) or self._frame_pending:
            return
        self._frame_pending = True
        self.page.runJavaScript("readVelocityFrame()", self._show_frame)

    def _show_frame(self, payload):
        self._frame_pending = False
        if not (self._visible and self._running and payload):
            return
        wave, _, core = payload.partition(",")
        if wave:
            self._frame = QImage.fromData(base64.b64decode(wave), "PNG")
            self._refresh_wave()
            self._card.update(self._band)
        if core and self._engine == "direct" and self._orb is not None:
            self._orb.set_direct_frame(QImage.fromData(base64.b64decode(core), "PNG"))

    def _send(self, energy=None):
        if self._ready:
            animate = "true" if self._running else "false"
            sample = "null" if energy is None else str(energy)
            direct = "true" if self._engine == "direct" else "false"
            self.page.runJavaScript(f"updateVelocityFlow({self._state}, {sample}, {animate}, {direct});")
