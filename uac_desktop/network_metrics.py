"""Shared five-card network dashboard, driven by the active engine's telemetry."""

from __future__ import annotations

import math
import time

from PySide6.QtCore import QEasingCurve, QPointF, QRectF, QSize, Qt, QVariantAnimation
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QSizePolicy, QToolButton, QVBoxLayout, QWidget

from . import desktop_layout as layout, fonts, theme
from .engine import format_bytes
from .icons import icon, pixmap


class MetricReading(QLabel):
    def __init__(self, kind, text):
        super().__init__(text)
        self.kind = kind
        self.show_route = False
        self.unit_color = self.palette().windowText().color()
        self.ip_legend = None
        self.setObjectName("hudReading")
        self.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Fixed)
        self.setFixedHeight(layout.METRIC_READING)
        self.setLayoutDirection(Qt.LeftToRight)
        self.digits = QFont("Bahnschrift")
        self.digits.setFamilies(["Bahnschrift", "Segoe UI", "Vazirmatn UI FD"])
        self.digits.setPixelSize(layout.METRIC_VALUE_FONT)
        self.digits.setWeight(fonts.DASHBOARD_WEIGHT)
        self.units = QFont(self.digits)
        self.units.setPixelSize(layout.METRIC_UNIT_FONT)
        self.units.setWeight(QFont.Normal)
        if kind == "ip":
            self.digits.setPixelSize(layout.METRIC_IP_FONT)

    def setText(self, text):
        super().setText(text)
        if self.kind == "ip":
            self.setToolTip(text if text not in ("—", "…") else "")
            if self.ip_legend is not None:
                self.ip_legend.setText("IPv6" if ":" in text else "IPv4")

    def paintEvent(self, event):
        text = self.text()
        unit = ""
        if self.kind in ("upload", "download", "latency"):
            value, _, suffix = text.rpartition(" ")
            if suffix in ("B", "KB", "MB", "GB", "TB", "ms"):
                text, unit = value, suffix
            elif self.kind == "latency" and text == "—":
                unit = "ms"
        if self.kind == "route" and not self.show_route:
            text = "—"
        painter = QPainter(self)
        painter.setRenderHint(QPainter.TextAntialiasing, True)
        painter.setFont(self.units)
        unit_width = painter.fontMetrics().horizontalAdvance(unit) + layout.METRIC_READING_GAP if unit else 0
        painter.setFont(self.digits)
        metrics = painter.fontMetrics()
        if self.kind == "route" and text != "—":
            font = QFont(self.font())
            font.setPixelSize(layout.METRIC_IP_FONT)
            font.setWeight(fonts.DASHBOARD_WEIGHT)
            painter.setFont(font)
            metrics = painter.fontMetrics()
        available = max(0, self.width() - unit_width)
        width = metrics.horizontalAdvance(text)
        if unit and width > available:
            font = painter.font()
            font.setPixelSize(max(layout.METRIC_MIN_VALUE_FONT, font.pixelSize() * available // width))
            painter.setFont(font)
            metrics = painter.fontMetrics()
        shown = metrics.elidedText(text, Qt.ElideMiddle if self.kind == "ip" else Qt.ElideRight, available)
        baseline = (self.height() + layout.METRIC_VALUE_FONT) // 2 - 3
        painter.setPen(self.palette().windowText().color())
        painter.drawText(QPointF(0, baseline), shown)
        if unit:
            painter.setFont(self.units)
            painter.setPen(self.unit_color)
            painter.drawText(QPointF(metrics.horizontalAdvance(shown) + layout.METRIC_READING_GAP, baseline), unit)


class MetricSignal(QWidget):
    def __init__(self, kind, motion):
        super().__init__()
        self.kind = kind
        self.motion = motion
        self.setFixedSize(*layout.METRIC_SIGNAL_SIZE)
        self.ink = self.palette().highlight().color()
        self.muted = self.palette().windowText().color()
        self.state = "disconnected"
        self.levels = (0.0,) * (5 if kind == "bars" else 1)
        self._target = self.levels
        self._start = self.levels
        self.has_latency = False
        self._transition = QVariantAnimation(self, startValue=0.0, endValue=1.0,
                                             duration=layout.METRIC_SIGNAL_TRANSITION_MS)
        self._transition.setEasingCurve(QEasingCurve.OutCubic)
        self._transition.valueChanged.connect(self._interpolate)

    def _interpolate(self, progress):
        self.levels = tuple(a + (b - a) * progress for a, b in zip(self._start, self._target))
        self.update()

    def _apply(self, target):
        if target != self._target:
            self._transition.stop()
            self._start, self._target = self.levels, target
            if self.motion() and self.isVisible():
                self._transition.start()
            else:
                self._interpolate(1.0)

    def add_rate(self, rate):
        level = min(1.0, math.log1p(rate / 256) / math.log1p(65536))
        self._apply((*self._target[1:], level))

    def set_latency(self, value):
        self.has_latency = value is not None
        self._apply((min(1.0, math.log1p((value or 0) / 25) / math.log1p(1000 / 25)),))
        self.update()

    def clear(self):
        if not (self.has_latency or any(self.levels) or any(self._target)):
            return
        self._transition.stop()
        self.levels = self._start = self._target = (0.0,) * len(self.levels)
        self.has_latency = False
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        if self.kind == "bars":
            p.setPen(Qt.NoPen)
            for index, level in enumerate(self.levels):
                color = QColor(self.ink)
                color.setAlpha(round(31 + 134 * level))
                p.setBrush(color)
                height = 1 + 15 * level
                p.drawRoundedRect(QRectF(5 + index * 6, 21 - height, 3, height), 1, 1)
        elif self.kind == "gauge":
            bounds = QRectF(5, 6, 28, 28)
            edge = QColor(self.muted)
            edge.setAlpha(47)
            p.setPen(QPen(edge, 2.2, Qt.SolidLine, Qt.RoundCap))
            p.drawArc(bounds, 0, 180 * 16)
            if self.has_latency:
                accent = QColor(self.ink)
                accent.setAlpha(108)
                p.setPen(QPen(accent, 2.2, Qt.SolidLine, Qt.RoundCap))
                p.drawArc(bounds, 180 * 16, -round(self.levels[0] * 180 * 16))
                angle = math.pi * (1 - self.levels[0])
                p.setPen(QPen(self.ink, 1.3, Qt.SolidLine, Qt.RoundCap))
                p.drawLine(QPointF(19, 20), QPointF(19 + 10 * math.cos(angle), 20 - 10 * math.sin(angle)))
        else:
            status = {"connected": "LIVE", "connecting": "LINK", "disconnecting": "STOP",
                      "paused": "PAUSE", "error": "ERROR"}.get(self.state, "IDLE")
            color = self.ink if self.state in ("connected", "connecting") else self.muted
            p.setBrush(color)
            p.setPen(Qt.NoPen)
            p.drawEllipse(QPointF(4, 17), 2.5, 2.5)
            font = QFont("Bahnschrift")
            font.setPixelSize(layout.METRIC_LEGEND_FONT)
            p.setFont(font)
            p.setPen(fonts.dashboard_text_color(color))
            p.drawText(QPointF(10, 20), status)


class NetworkMetricCard(QFrame):
    def __init__(self, kind, title, glyph, reading, signal=None, legend=""):
        super().__init__()
        self.kind, self.glyph = kind, glyph
        self.setObjectName("hudCard")
        self.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Fixed)
        self.setFixedHeight(layout.METRIC_HEIGHT)
        root = QVBoxLayout(self)
        root.setContentsMargins(*layout.METRIC_MARGINS)
        root.setSpacing(0)
        self.header = QWidget()
        self.header.setFixedHeight(layout.METRIC_HEADER)
        head = self.header_layout = QHBoxLayout(self.header)
        head.setContentsMargins(0, 0, 0, 0)
        head.setSpacing(layout.METRIC_HEADER_GAP)
        self.icon_label = QLabel()
        self.icon_label.setObjectName("hudIcon")
        self.icon_label.setFixedSize(layout.METRIC_HEADER, layout.METRIC_HEADER)
        self.icon_label.setAlignment(Qt.AlignCenter)
        self.title = QLabel(title)
        self.title.setObjectName("hudTitle")
        self.title.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        if not legend:
            self.title.setAlignment(Qt.AlignLeft | Qt.AlignAbsolute | Qt.AlignVCenter)
        self.legend = QLabel(legend)
        self.legend.setObjectName("hudLegend")
        head.addWidget(self.icon_label)
        head.addWidget(self.title, 1)
        if legend:
            head.addWidget(self.legend)
        root.addWidget(self.header)

        root.addStretch()
        caption = QWidget()
        caption.setFixedHeight(layout.METRIC_CAPTION)
        self.caption = QHBoxLayout(caption)
        self.caption.setContentsMargins(0, 0, 0, 0)
        self.caption.setSpacing(layout.METRIC_CAPTION_GAP)
        self.secondary = QLabel()
        self.secondary.setObjectName("hudLegend")
        self.secondary.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.caption.addWidget(self.secondary, 1)
        root.addWidget(caption)

        readout = QWidget()
        readout.setLayoutDirection(Qt.LeftToRight)
        self.readout = QHBoxLayout(readout)
        self.readout.setContentsMargins(0, 0, 0, 0)
        self.readout.setSpacing(layout.METRIC_READING_GAP)
        self.value = reading
        self.readout.addWidget(reading, 1)
        if signal is not None:
            self.readout.addWidget(signal, 0, Qt.AlignBottom)
        root.addWidget(readout)

    def set_secondary(self, message):
        self.setToolTip(message)
        if self.kind == "ip":
            self.secondary.setText(message)


class SharedNetworkMetrics(QFrame):
    def __init__(self, translate, motion):
        super().__init__()
        self.setObjectName("networkMetrics")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setFixedHeight(layout.METRIC_HEIGHT + 2 * layout.METRIC_PANEL_PADDING)
        self.connection_state = "disconnected"
        self._sample = None
        self._engine = None
        self.up_bars, self.down_bars = MetricSignal("bars", motion), MetricSignal("bars", motion)
        self.dns_gauge, self.route_status = MetricSignal("gauge", motion), MetricSignal("route", motion)
        cards = [
            ("route", "مسیر فعال", "Active route", "route", "—", self.route_status, "ROUTE"),
            ("latency", "تأخیر DNS", "DNS latency", "gauge", "—", self.dns_gauge, ""),
            ("upload", "آپلود", "Upload", "upload", "0 B", self.up_bars, ""),
            ("download", "دانلود", "Download", "download", "0 B", self.down_bars, ""),
            ("ip", "آی‌پی عمومی", "Public IP", "map-pin", "—", None, "IPv4"),
        ]
        grid = QHBoxLayout(self)
        padding = layout.METRIC_PANEL_PADDING
        grid.setContentsMargins(padding, padding, padding, padding)
        grid.setSpacing(layout.METRIC_GAP)
        self.cards = []
        for weight, (kind, fa, en, glyph, text, signal, legend) in zip(layout.METRIC_WEIGHTS, cards):
            card = NetworkMetricCard(kind, translate(fa, en), glyph, MetricReading(kind, text), signal, legend)
            card.title.setProperty("i18nFa", fa)
            card.title.setProperty("i18nEn", en)
            grid.addWidget(card, weight)
            self.cards.append(card)
        self.route, self.latency, self.upload, self.download, self.ip = self.cards
        self.ip.value.ip_legend = self.ip.legend
        self.ip_refresh = QToolButton()
        self.ip_refresh.setObjectName("hudRefresh")
        self.ip_refresh.setCursor(Qt.PointingHandCursor)
        self.ip_refresh.setFixedSize(layout.METRIC_REFRESH_SIZE, layout.METRIC_REFRESH_SIZE)
        self.ip_refresh.setAccessibleName(translate("بررسی آی‌پی", "Check IP"))
        self.ip.header_layout.addWidget(self.ip_refresh)

    def set_engine(self, engine):
        if engine == self._engine:
            return
        self._engine = engine
        panel, top, bottom, border, tile, ink, text, muted = theme.NETWORK_METRICS[engine]
        reading_color = fonts.dashboard_text_color(text).name()
        label_color = fonts.dashboard_text_color(muted)
        self.setStyleSheet(f"""
            QFrame#networkMetrics {{ background: {panel}; border-radius: {layout.METRIC_PANEL_RADIUS}px; }}
            QFrame#hudCard {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 {top},stop:1 {bottom});
                             border: 1px solid {border}; border-radius: {layout.METRIC_RADIUS}px; }}
            QFrame#hudCard[ipHot="true"] {{ border-color: {tile}; }}
            QLabel#hudIcon {{ background: {tile}; border-radius: {layout.METRIC_ICON_RADIUS}px; }}
            QLabel#hudTitle {{ color: {label_color.name()}; {fonts.DASHBOARD_LABEL_QSS} }}
            QLabel#hudLegend {{ color: {label_color.name()}; font-size: {layout.METRIC_LEGEND_FONT}px; }}
            QLabel#hudReading {{ color: {reading_color}; }}
            QToolButton#hudRefresh {{ background: {tile}; border: 1px solid {border}; border-radius: 5px; padding: 0; }}
            QToolButton#hudRefresh:hover, QToolButton#hudRefresh:focus {{ border-color: {ink}; }}
        """)
        for card in self.cards:
            card.icon_label.setPixmap(pixmap(card.glyph, ink, layout.METRIC_ICON, lucide=True))
            card.value.unit_color = label_color
        icon_size = layout.METRIC_REFRESH_ICON
        self.ip_refresh.setIcon(icon("refresh", ink, icon_size, lucide=True))
        self.ip_refresh.setIconSize(QSize(icon_size, icon_size))
        for signal in (self.up_bars, self.down_bars, self.dns_gauge, self.route_status):
            signal.ink, signal.muted = QColor(ink), QColor(muted)
            signal.update()

    def set_connection_state(self, state):
        if self.connection_state == state:
            return
        self.connection_state = state
        self.route_status.state = state
        self.route_status.update()
        self.route.value.show_route = state in ("connected", "connecting", "paused", "error")
        self.route.value.update()
        if state not in ("connected", "paused"):
            self.reset_traffic()
        if state != "connected":
            self.set_latency(None)

    def reset_traffic(self):
        self._sample = None
        self.up_bars.clear()
        self.down_bars.clear()
        self.upload.value.setText("0 B")
        self.download.value.setText("0 B")

    def set_traffic(self, upload, download, *, sample=True):
        upload, download = max(0, upload), max(0, download)
        self.upload.value.setText(format_bytes(upload))
        self.download.value.setText(format_bytes(download))
        if not sample:
            return
        now = time.monotonic()
        if self._sample is not None:
            sampled, previous_up, previous_down = self._sample
            elapsed = now - sampled
            if elapsed < .2:
                return
            for current, previous, bars in ((upload, previous_up, self.up_bars),
                                            (download, previous_down, self.down_bars)):
                if current < previous:
                    bars.clear()
                else:
                    bars.add_rate((current - previous) / elapsed)
        self._sample = now, upload, download

    def set_latency(self, milliseconds, detail=""):
        self.latency.value.setText(f"{milliseconds:.0f} ms" if milliseconds is not None else "—")
        self.latency.set_secondary(detail)
        self.dns_gauge.set_latency(milliseconds)
