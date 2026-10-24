"""Local-proxy port editors for engine settings dialogs (not Home).

Engine 1 (Xray): section inside TuningDialog (Advanced Settings).
Engine 2 (PoW): section inside PowSettingsDialog (تنظیمات PoW).

Reuses :mod:`uac_desktop.proxy_ports` for validation and persistence.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget,
)

from . import proxy_ports as P


def _numeric(window, value: int, minimum: int, maximum: int):
    """Build a NumericInput (same control as TuningDialog) with LTR digits."""
    from uac_desktop.ui import NumericInput

    widget = NumericInput(value, minimum, maximum)
    widget.setRange(minimum, maximum)
    widget.setMinimumWidth(148)
    widget.setMaximumWidth(180)
    widget.setLayoutDirection(Qt.LeftToRight)
    return widget


class PortEditor(QWidget):
    """Shared save/validate/reset logic; hosts two NumericInputs + note/error."""

    saved = Signal(str)

    def __init__(self, window, mode: str = "xray", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._window = window
        self.mode = "pow" if mode == "pow" else "xray"
        self._loading = False
        self.setObjectName("proxyPortEditor")

        if self.mode == "xray":
            self.socks = _numeric(window, P.XRAY_SOCKS_DEFAULT, P.PORT_MIN, P.PORT_MAX)
            self.http = _numeric(window, P.XRAY_HTTP_DEFAULT, P.PORT_MIN, P.PORT_MAX)
            self.pow_http = None
            self.pow_socks = None
            for w in (self.socks, self.http):
                w.edit.editingFinished.connect(self._commit)
                w.plus.clicked.connect(self._commit_soon)
                w.minus.clicked.connect(self._commit_soon)
        else:
            self.socks = None
            self.http = None
            self.pow_http = _numeric(window, P.POW_HTTP_DEFAULT, P.PORT_MIN, P.PORT_MAX)
            self.pow_socks = _numeric(window, P.POW_SOCKS_DEFAULT, P.PORT_MIN, P.PORT_MAX)
            for w in (self.pow_http, self.pow_socks):
                w.edit.editingFinished.connect(self._commit)
                w.plus.clicked.connect(self._commit_soon)
                w.minus.clicked.connect(self._commit_soon)

        self.note = QLabel()
        window._bind_text(self.note, "از اتصال بعدی اعمال می‌شود", "Applies on the next connect")
        self.note.setObjectName("proxyPortPanelNote")
        self.note.setWordWrap(True)
        self.note.setVisible(False)

        self.error = QLabel("")
        self.error.setObjectName("proxyPortPanelError")
        self.error.setWordWrap(True)
        self.error.setStyleSheet("color: #ff6b6b;")
        self.error.setVisible(False)

        self.reset_btn = QPushButton()
        window._bind_text(self.reset_btn, "پیش‌فرض", "Defaults")
        self.reset_btn.setObjectName("proxyPortReset")
        self.reset_btn.setCursor(Qt.PointingHandCursor)
        self.reset_btn.setFixedHeight(28)
        self.reset_btn.clicked.connect(self.reset_defaults)

        self.reload()

    def _commit_soon(self) -> None:
        if self._loading:
            return
        from PySide6.QtCore import QTimer
        QTimer.singleShot(0, self._commit)

    def _tr(self, fa: str, en: str) -> str:
        return self._window.tr(fa, en)

    def _running(self) -> bool:
        window = self._window
        pow_controller = getattr(window, "pow_controller", None)
        if self.mode == "xray":
            return bool(getattr(window.engine, "running", False) or getattr(window, "connecting", False))
        return bool(
            getattr(pow_controller, "running", False)
            or getattr(pow_controller, "busy", False)
            or getattr(pow_controller, "_connecting", False)
        )

    def reload(self) -> None:
        self._loading = True
        try:
            if self.mode == "xray":
                socks, http = P.xray_ports_from_settings(self._window.storage.settings)
                self.socks.setValue(socks)
                self.http.setValue(http)
            else:
                store = getattr(getattr(self._window, "pow_controller", None), "store", None)
                http = store.proxy_http_port() if store is not None else P.POW_HTTP_DEFAULT
                socks = store.psiphon_socks_port() if store is not None else P.POW_SOCKS_DEFAULT
                self.pow_http.setValue(http)
                self.pow_socks.setValue(socks)
            self.error.clear()
            self.error.setVisible(False)
            self.note.setVisible(self._running())
        finally:
            self._loading = False

    def reset_defaults(self) -> None:
        self._loading = True
        try:
            if self.mode == "xray":
                self.socks.setValue(P.XRAY_SOCKS_DEFAULT)
                self.http.setValue(P.XRAY_HTTP_DEFAULT)
            else:
                self.pow_http.setValue(P.POW_HTTP_DEFAULT)
                self.pow_socks.setValue(P.POW_SOCKS_DEFAULT)
        finally:
            self._loading = False
        self._commit()

    def _current_values(self):
        if self.mode == "xray":
            return int(self.socks.value()), int(self.http.value())
        return int(self.pow_http.value()), int(self.pow_socks.value())

    def _saved_ports(self) -> set[int]:
        if self.mode == "xray":
            return set(P.xray_ports_from_settings(self._window.storage.settings))
        store = getattr(getattr(self._window, "pow_controller", None), "store", None)
        if store is None:
            return {P.POW_HTTP_DEFAULT, P.POW_SOCKS_DEFAULT}
        return {store.proxy_http_port(), store.psiphon_socks_port()}

    def _problems(self) -> list[str]:
        if self.mode == "xray":
            socks, http = self._current_values()
            errors = P.validate_xray_ports(socks, http, self._tr)
            ports = [socks, http]
        else:
            http, socks = self._current_values()
            errors = P.validate_pow_ports(http, socks, self._tr)
            ports = [http, socks]
        if errors:
            return errors
        saved = self._saved_ports()
        changed = [port for port in ports if port not in saved]
        busy = P.busy_reasons(changed, P.is_app_helper)
        if busy:
            return [self._tr("این پورت آزاد نیست: ", "This port is not free: ") + "; ".join(busy)]
        return []

    def _commit(self) -> None:
        if self._loading:
            return
        errors = self._problems()
        if errors:
            self.error.setText("\n".join(errors))
            self.error.setVisible(True)
            return
        self.error.clear()
        self.error.setVisible(False)
        running = self._running()
        if self.mode == "xray":
            socks, http = self._current_values()
            self._window.storage.settings[P.XRAY_SOCKS_KEY] = socks
            self._window.storage.settings[P.XRAY_HTTP_KEY] = http
            self._window.storage.save_settings()
            apply = getattr(self._window, "_apply_xray_port_setting", None)
            if callable(apply):
                apply()
            line = f"PROXY PORT saved: engine 1 SOCKS={socks} HTTP={http}"
        else:
            http, socks = self._current_values()
            store = getattr(getattr(self._window, "pow_controller", None), "store", None)
            if store is None:
                self.error.setText(self._tr("ذخیره موتور ۲ در دسترس نیست", "Engine 2 store is unavailable"))
                self.error.setVisible(True)
                return
            http = store.save_proxy_http_port(http)
            socks = store.save_psiphon_socks_port(socks)
            line = f"PROXY PORT saved: engine 2 HTTP={http} SOCKS={socks}"
        self.note.setVisible(running)
        try:
            self._window.bridge.log.emit(line)
        except Exception:
            pass
        toast = getattr(self._window, "show_toast", None)
        if callable(toast):
            toast(self._tr(
                "پورت پروکسی ذخیره شد" + ("؛ از اتصال بعدی اعمال می‌شود" if running else ""),
                "Proxy port saved" + ("; it applies on the next connect" if running else ""),
            ), "success")
        self.saved.emit(line)


# Back-compat alias used by older tests / callers
class ProxyPortPanel(PortEditor):
    """Alias — prefer PortEditor. Kept so imports do not break."""

    def __init__(self, window, mode: str = "xray", parent: QWidget | None = None) -> None:
        super().__init__(window, mode=mode, parent=parent)
        # Minimal frame chrome if someone still embeds this widget directly.
        self.setObjectName("proxyPortPanel")


def build_pow_ports_section(window, controller) -> QFrame:
    """PowSection for PowSettingsDialog: HTTP + Psiphon SOCKS with Defaults."""
    from uac_desktop.pow_ui import PowSection, _setting_row

    editor = PortEditor(window, mode="pow")
    controller.proxy_port_editor = editor
    # Expose fields for tests / release
    controller.pow_http_port_input = editor.pow_http
    controller.pow_socks_port_input = editor.pow_socks

    section = PowSection(
        window,
        "پورت پروکسی محلی",
        "Local proxy ports",
        "globe",
        trailing=editor.reset_btn,
    )
    section.add(_setting_row(
        window,
        "پورت HTTP",
        "HTTP port",
        f"پیش‌فرض {P.POW_HTTP_DEFAULT} · پروکسی سیستم ویندوز",
        f"Default {P.POW_HTTP_DEFAULT} · Windows system proxy",
        editor.pow_http,
    ))
    section.add(_setting_row(
        window,
        "پورت SOCKS5 (سایفون)",
        "SOCKS5 port (Psiphon)",
        f"پیش‌فرض {P.POW_SOCKS_DEFAULT} · فقط سایفون",
        f"Default {P.POW_SOCKS_DEFAULT} · Psiphon only",
        editor.pow_socks,
    ))
    # note + error under the rows
    foot = QFrame()
    foot.setObjectName("powSettingRow")
    fl = QVBoxLayout(foot)
    fl.setContentsMargins(12, 4, 12, 8)
    fl.setSpacing(4)
    fl.addWidget(editor.note)
    fl.addWidget(editor.error)
    section.add(foot)
    return section


def install_xray_ports_into_tuning(dialog, window=None) -> PortEditor:
    """Add a ports section to TuningDialog (simple layout, always visible)."""
    host = window
    if host is None:
        host = dialog.parent()
    walk = host
    while walk is not None and not hasattr(walk, "storage"):
        walk = walk.parent() if hasattr(walk, "parent") else None
    if walk is not None:
        host = walk
    if host is None or not hasattr(host, "storage"):
        raise RuntimeError("install_xray_ports_into_tuning: MainWindow not found")
    editor = PortEditor(host, mode="xray", parent=dialog)
    dialog.proxy_port_editor = editor
    dialog.proxy_socks_input = editor.socks
    dialog.proxy_http_input = editor.http

    # Build section with same _section helper as the rest of the dialog
    section = dialog._section(
        dialog.t("پورت پروکسی محلی", "Local proxy ports"),
        dialog.t(
            "پورت‌هایی که پروکسی سیستم ویندوز به آن‌ها وصل می‌شود (موتور ۱ · Xray).",
            "Ports the Windows system proxy uses (Engine 1 · Xray).",
        ),
        [
            (dialog.t("پورت SOCKS5", "SOCKS5 port"), editor.socks,
             dialog.t(f"پیش‌فرض {P.XRAY_SOCKS_DEFAULT}", f"Default {P.XRAY_SOCKS_DEFAULT}")),
            (dialog.t("پورت HTTP", "HTTP port"), editor.http,
             dialog.t(f"پیش‌فرض {P.XRAY_HTTP_DEFAULT}", f"Default {P.XRAY_HTTP_DEFAULT}")),
        ],
        dialog.t(
            "با پایان ویرایش ذخیره می‌شود. وقتی وصل هستید از اتصال بعدی اعمال می‌شود.",
            "Saved when you finish editing. Applies on the next connect if already connected.",
        ),
    )
    # Defaults button + note/error under the section
    extras = QHBoxLayout()
    extras.setContentsMargins(18, 0, 18, 8)
    extras.addWidget(editor.reset_btn)
    extras.addStretch(1)
    wrap = QFrame()
    wrap.setObjectName("settingsSection")
    wl = QVBoxLayout(wrap)
    wl.setContentsMargins(0, 0, 0, 0)
    wl.setSpacing(0)
    wl.addWidget(section)
    wl.addLayout(extras)
    note_row = QVBoxLayout()
    note_row.setContentsMargins(18, 0, 18, 10)
    note_row.addWidget(editor.note)
    note_row.addWidget(editor.error)
    wl.addLayout(note_row)
    dialog._proxy_ports_section = wrap
    return editor
