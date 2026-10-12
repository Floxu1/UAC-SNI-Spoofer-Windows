"""Live Logs page: readable, grouped log view with a summary header.

Mixed into ``MainWindow``. Formatting/collapsing lives in :mod:`logfmt`
(pure, tested); this file only builds the widgets and renders.
"""

from __future__ import annotations

import datetime
import time
from pathlib import Path

from PySide6.QtCore import QEvent, QSize, Qt, QTimer
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QFrame, QGridLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QToolButton, QVBoxLayout, QWidget,
)

from . import logfmt
from .paths import ASSETS

_STATE_TEXT = {
    "idle": ("آماده", "Idle", "#8394a6"),
    "connecting": ("در حال اتصال…", "Connecting…", "#f2b84b"),
    "connected": ("وصل", "Connected", "#3cf0af"),
    "dropped": ("قطع شد", "Dropped", "#ff6b7d"),
}


class LogToolButton(QToolButton):
    """Ghost icon button for the Live Logs toolbar: muted icon, bright on hover."""

    MUTED = "#8496a9"
    HOVER = "#e3edf6"
    DANGER = "#ff6b7d"

    def __init__(self, icon_name: str, danger: bool = False, parent=None):
        super().__init__(parent)
        from .ui import cyber_icon  # late: ui imports this module

        self.setObjectName("logToolButtonDanger" if danger else "logToolButton")
        self.setCursor(Qt.PointingHandCursor)
        self.setAutoRaise(True)
        self.setFocusPolicy(Qt.TabFocus)
        self.setFixedSize(34, 26)
        self.setIconSize(QSize(16, 16))
        self._icons = (
            cyber_icon(icon_name, self.MUTED, 16),
            cyber_icon(icon_name, self.DANGER if danger else self.HOVER, 16),
        )
        self.setIcon(self._icons[0])
        self.setAttribute(Qt.WA_Hover, True)

    def event(self, event):
        kind = event.type()
        if kind == QEvent.HoverEnter:
            self.setIcon(self._icons[1])
        elif kind == QEvent.HoverLeave:
            self.setIcon(self._icons[0])
        return super().event(event)


def flag_path(code: str) -> str:
    code = str(code or "").strip().lower()
    if len(code) != 2 or not code.isalpha():
        return ""
    path = ASSETS / "flags" / "4x3" / f"{code}.png"
    return path.as_posix() if path.exists() else ""


class LogsPageMixin:
    """Live Logs page for MainWindow (both engines; PoW gets the summary)."""

    # -- build -------------------------------------------------------------------

    def _logs_page(self):
        self.log_model = logfmt.LogModel()
        self._log_follow = True
        self._log_rendering = False
        page = QWidget(); root = QVBoxLayout(page); root.setContentsMargins(34, 28, 34, 26); root.setSpacing(14)
        self.log_count_label = QLabel(self.tr("۰ خط", "0 lines")); self.log_count_label.setObjectName("summaryPill")
        root.addWidget(self._page_header("لاگ زنده", "Live Logs", "مرحله به مرحله: کلید، اسکن، تونل، سایفون و قطعی‌ها", "Step by step: key, scan, tunnel, Psiphon and drops", self.log_count_label))
        root.addWidget(self._build_log_summary())
        terminal = QFrame(); terminal.setObjectName("terminalCard"); terminal_layout = QVBoxLayout(terminal); terminal_layout.setContentsMargins(0, 0, 0, 0); terminal_layout.setSpacing(0)
        toolbar = QFrame(); toolbar.setObjectName("terminalToolbar"); bar = QHBoxLayout(toolbar); bar.setContentsMargins(12, 8, 12, 8); bar.setSpacing(8)
        from .ui import PulseDot, ToggleSwitch  # late: ui imports this module
        live_dot = PulseDot(); live_dot.set_state("connected"); live_label = self._bind_text(QLabel(), "LIVE", "LIVE"); live_label.setObjectName("terminalLive")
        self.log_filter = QLineEdit(); self.log_filter.setObjectName("logFilter"); self.log_filter.setPlaceholderText(self.tr("فیلتر لاگ‌ها…", "Filter logs…")); self.log_filter.setClearButtonEnabled(True); self.log_filter.setMinimumWidth(120); self.log_filter.setMaximumWidth(240); self.log_filter.setFixedHeight(30)
        self.log_details = ToggleSwitch(); self.log_details.setAccessibleName("Show raw engine lines"); details_label = self._bind_text(QLabel(), "جزئیات", "Details")
        details_label.setToolTip(self.tr("نمایش خطوط خام موتور (اسکن هر آی‌پی، پیام‌های هسته)", "Show raw engine lines (per-IP scan, core messages)"))
        self.log_pause = ToggleSwitch(); self.log_pause.setAccessibleName("Pause live logs"); pause_label = self._bind_text(QLabel(), "توقف", "Pause")
        self.log_autoscroll = ToggleSwitch(); self.log_autoscroll.setChecked(True); self.log_autoscroll.setAccessibleName("Auto-scroll live logs"); auto_label = self._bind_text(QLabel(), "اسکرول خودکار", "Auto-scroll")
        self._log_tip_buttons = []
        self.log_tools = QFrame(); self.log_tools.setObjectName("logToolGroup"); self.log_tools.setFixedHeight(30)
        tools = QHBoxLayout(self.log_tools); tools.setContentsMargins(2, 0, 2, 0); tools.setSpacing(0)
        self.log_jump = self._log_tool("رفتن به جدیدترین", "Jump to latest", "arrow-down")
        self._log_jump_divider = self._log_tool_divider()
        copy = self._log_tool("کپی", "Copy", "copy")
        export = self._log_tool("ذخیره در فایل…", "Export to file…", "download")
        clear = self._log_tool("پاک کردن", "Clear", "trash", danger=True)
        for index, widget in enumerate((self.log_jump, self._log_jump_divider, copy, self._log_tool_divider(), export, self._log_tool_divider(), clear)):
            tools.addWidget(widget, 0, Qt.AlignVCenter)
        self.log_jump.setVisible(False); self._log_jump_divider.setVisible(False)
        copy.clicked.connect(self._copy_logs); export.clicked.connect(self._export_logs); clear.clicked.connect(self.logs_clear)
        self.log_jump.clicked.connect(self._jump_to_latest)
        for widget in (live_dot, live_label):
            bar.addWidget(widget, 0, Qt.AlignVCenter)
        bar.addSpacing(6); bar.addWidget(self.log_filter, 1, Qt.AlignVCenter)
        bar.addSpacing(4)
        for widget in (self.log_details, details_label, self.log_pause, pause_label, self.log_autoscroll, auto_label):
            bar.addWidget(widget, 0, Qt.AlignVCenter)
        bar.addStretch(); bar.addWidget(self.log_tools, 0, Qt.AlignVCenter)
        terminal_layout.addWidget(toolbar)
        self.logs = QTextEdit(); self.logs.setReadOnly(True); self.logs.setObjectName("logs"); self.logs.setAcceptRichText(True)
        self.logs.verticalScrollBar().valueChanged.connect(self._log_scrolled)
        terminal_layout.addWidget(self.logs, 1)
        root.addWidget(terminal, 1)
        self._log_render_timer = QTimer(self); self._log_render_timer.setSingleShot(True); self._log_render_timer.setInterval(120)
        self._log_render_timer.timeout.connect(self._render_logs)
        self._log_summary_timer = QTimer(self); self._log_summary_timer.setInterval(1000)
        self._log_summary_timer.timeout.connect(self._update_log_summary)
        self._log_summary_timer.start()
        self.log_filter.textChanged.connect(self._render_logs); self.log_pause.toggled.connect(self._toggle_log_pause)
        self.log_details.toggled.connect(self._render_logs)
        self.log_autoscroll.toggled.connect(lambda on: on and self._jump_to_latest())
        return page

    def _log_tool(self, persian, english, icon_name, danger=False):
        button = LogToolButton(icon_name, danger)
        button.setToolTip(self.tr(persian, english)); button.setAccessibleName(english)
        self._log_tip_buttons.append((button, persian, english))
        return button

    def _log_tool_divider(self):
        line = QFrame(); line.setObjectName("logToolDivider"); line.setFixedSize(1, 14)
        return line

    def _build_log_summary(self):
        frame = QFrame(); frame.setObjectName("logSummary")
        grid = QGridLayout(frame); grid.setContentsMargins(16, 10, 16, 10); grid.setHorizontalSpacing(16); grid.setVerticalSpacing(3)
        self._log_summary_values = {}
        specs = [
            ("state", "وضعیت", "State"), ("route", "مسیر", "Route"), ("exit", "خروجی", "Exit"),
            ("parallel", "موازی", "Parallel"), ("uptime", "مدت اتصال", "Uptime"), ("drop", "آخرین قطعی", "Last drop"),
        ]
        self._log_summary_cells = {}
        for column, (key, fa, en) in enumerate(specs):
            # Header and value share one grid column and are both centred, so a
            # value always sits directly under its own header in RTL and LTR.
            caption = self._bind_text(QLabel(), fa, en); caption.setObjectName("logSumCaption")
            caption.setAlignment(Qt.AlignCenter)
            row = QWidget(); row_layout = QHBoxLayout(row); row_layout.setContentsMargins(0, 0, 0, 0); row_layout.setSpacing(6)
            icon = QLabel(); icon.setFixedSize(18, 13); icon.setVisible(False)
            value = QLabel("—"); value.setTextFormat(Qt.PlainText)
            value.setObjectName("logSumValueMono" if key in ("exit", "uptime") else "logSumValue")
            value.setAlignment(Qt.AlignCenter)
            row_layout.addStretch(1); row_layout.addWidget(icon, 0, Qt.AlignVCenter); row_layout.addWidget(value, 0, Qt.AlignVCenter); row_layout.addStretch(1)
            if key == "exit":
                # Flag stays on the left of the IP; centring keeps the column aligned.
                row.setLayoutDirection(Qt.LeftToRight)
            grid.addWidget(caption, 0, column); grid.addWidget(row, 1, column)
            grid.setColumnStretch(column, 1)
            self._log_summary_values[key] = (value, icon)
            self._log_summary_cells[key] = row
        self.log_summary = frame
        return frame

    # -- data in -----------------------------------------------------------------------

    def _append_log(self, message):
        stamp = datetime.datetime.now().strftime("%H:%M:%S"); line = f"[{stamp}] {message}"
        self._all_log_lines.append(line); self._all_log_lines = self._all_log_lines[-5000:]
        model = getattr(self, "log_model", None)
        if model is not None:
            model.add(str(message), stamp)
            if not self.log_pause.isChecked():
                self._schedule_log_render()
        self._set_log_count(len(self._all_log_lines))
        self._pending_file_log_lines.append(line)
        if not self._log_flush_timer.isActive(): self._log_flush_timer.start()

    def _schedule_log_render(self):
        timer = getattr(self, "_log_render_timer", None)
        if timer is not None and not timer.isActive():
            timer.start()

    def _append_log_line(self, line):
        """Compatibility: route a preformatted '[HH:MM:SS] msg' line through the model."""
        self.log_model.add(line)
        self._schedule_log_render()

    # -- render ------------------------------------------------------------------------

    def _log_language(self):
        return "fa" if getattr(self, "language", "en") == "fa" else "en"

    def _render_logs(self, *_):
        if not hasattr(self, "logs") or not hasattr(self, "log_model") or self.log_pause.isChecked():
            return
        details = self.log_details.isChecked()
        rows = self.log_model.rows(details=details, query=self.log_filter.text(), max_rows=900)
        fa = self._log_language() == "fa"
        self.logs.setLayoutDirection(Qt.RightToLeft if fa else Qt.LeftToRight)
        html = logfmt.render_html(rows, "fa" if fa else "en", details, flag_path=flag_path)
        bar = self.logs.verticalScrollBar()
        follow = self._log_follow and self.log_autoscroll.isChecked()
        old = bar.value()
        self._log_rendering = True
        try:
            self.logs.setHtml(html)
            if follow:
                bar.setValue(bar.maximum())
            else:
                bar.setValue(min(old, bar.maximum()))
        finally:
            self._log_rendering = False
        self._set_log_jump_visible(not follow and bar.maximum() > 0)
        for button, persian, english in getattr(self, "_log_tip_buttons", []):
            button.setToolTip(self.tr(persian, english))
        self._update_log_summary()

    def _log_scrolled(self, value):
        if self._log_rendering:
            return
        bar = self.logs.verticalScrollBar()
        self._log_follow = value >= bar.maximum() - 4
        if self._log_follow:
            self._set_log_jump_visible(False)

    def _jump_to_latest(self):
        self._log_follow = True
        bar = self.logs.verticalScrollBar(); bar.setValue(bar.maximum())
        self._set_log_jump_visible(False)

    def _set_log_jump_visible(self, visible):
        self.log_jump.setVisible(bool(visible))
        self._log_jump_divider.setVisible(bool(visible))

    def _log_cell_width(self, key):
        cell = getattr(self, "_log_summary_cells", {}).get(key)
        if cell is None or not cell.isVisible():
            return 10 ** 6  # not laid out yet: no elision
        return max(60, cell.width() - 8)

    def _update_log_summary(self):
        values = getattr(self, "_log_summary_values", None)
        model = getattr(self, "log_model", None)
        if not values or model is None:
            return
        pow_on = getattr(self, "engine_mode", "") == "pow"
        self.log_summary.setVisible(pow_on)
        if not pow_on:
            return
        state = model.state
        fa = self._log_language() == "fa"
        fa_text, en_text, color = _STATE_TEXT.get(state.status, _STATE_TEXT["idle"])
        label, _icon = values["state"]
        label.setText(fa_text if fa else en_text); label.setStyleSheet(f"color: {color};")
        exit_ip, country = state.exit_ip, state.exit_country
        controller = getattr(self, "pow_controller", None)
        coordinator = getattr(controller, "coordinator", None)
        parallel = state.parallel
        try:
            sessions = coordinator.parallel_sessions() if coordinator is not None else []
            if state.status == "connected" and len(sessions) >= 2:
                parallel = len(sessions)
        except Exception:
            pass
        connected = state.status == "connected"
        route = values["route"][0]
        route_text = state.route if connected and state.route else "—"
        route.setToolTip(route_text if route_text != "—" else "")
        route.setText(route.fontMetrics().elidedText(route_text, Qt.ElideRight, self._log_cell_width("route")))
        exit_label, flag = values["exit"]
        exit_label.setText(exit_ip if connected and exit_ip else "—")
        path = flag_path(country) if connected else ""
        if path:
            flag.setPixmap(QPixmap(path).scaled(18, 13, Qt.IgnoreAspectRatio, Qt.SmoothTransformation)); flag.setVisible(True)
        else:
            flag.setVisible(False)
        if connected and parallel >= 2:
            values["parallel"][0].setText(self.tr(f"{parallel} نشست", f"{parallel} sessions"))
        else:
            values["parallel"][0].setText(self.tr("خاموش / ۱", "off / 1") if connected else "—")
        values["uptime"][0].setText(state.uptime() or "—")
        drop = values["drop"][0]
        if state.last_drop:
            text = f"{state.last_drop_stamp} · {state.last_drop}"
            drop.setToolTip(text)
            drop.setText(drop.fontMetrics().elidedText(text, Qt.ElideRight, self._log_cell_width("drop")))
        else:
            drop.setText(self.tr("بدون قطعی", "none")); drop.setToolTip("")

    # -- actions -----------------------------------------------------------------------

    def _visible_log_text(self):
        details = self.log_details.isChecked()
        rows = self.log_model.rows(details=details, query=self.log_filter.text(), max_rows=100000)
        return logfmt.render_text(rows, self._log_language(), details)

    def _copy_logs(self):
        QApplication.clipboard().setText(self._visible_log_text())
        self._set_activity("لاگ‌ها کپی شد.", "Logs copied.", "success", False)

    def _export_logs(self):
        default = Path.home() / "Documents" / f"uac-live-log-{time.strftime('%Y%m%d-%H%M%S')}.txt"
        path, _ = QFileDialog.getSaveFileName(self, self.tr("ذخیره لاگ", "Export logs"), str(default), "Text (*.txt)")
        if not path:
            return
        self._write_log_export(Path(path))

    def _write_log_export(self, path: Path):
        readable = logfmt.render_text(self.log_model.rows(details=False, max_rows=100000), "en", False)
        raw = self.log_model.plain_text()
        try:
            path.write_text(
                "UAC Spoofer Live Logs — readable view\n\n" + readable + "\n\n---- raw lines ----\n" + raw + "\n",
                encoding="utf-8",
            )
        except OSError as exc:
            self._set_activity(f"ذخیره لاگ نشد: {exc}", f"Could not export logs: {exc}", "error", False)
            return
        self._set_activity("لاگ‌ها ذخیره شد.", f"Logs exported to {path}", "success", False)

    def _toggle_log_pause(self, paused):
        if paused:
            self._set_activity("نمایش Live Logs متوقف شد؛ ثبت فایل ادامه دارد.", "Live Logs display paused; file logging continues.", "warning", False)
        else:
            self._log_paused_lines.clear(); self._render_logs(); self._set_activity("نمایش Live Logs از سر گرفته شد.", "Live Logs display resumed.", "success", False)

    def logs_clear(self):
        self.logs.clear(); self._all_log_lines.clear(); self._log_paused_lines.clear(); self.log_model.clear()
        self._set_log_count(0); self._render_logs()
        self._set_activity("نمایش لاگ پاک شد.", "Log view cleared.", "success", False)

    # -- setting changes ------------------------------------------------------------------

    def _log_pow_setting_changes(self, old, new):
        controller = getattr(self, "pow_controller", None)
        connected = bool(controller is not None and controller.busy)
        for line in logfmt.setting_changes(old, new, connected):
            self.bridge.log.emit(line)
