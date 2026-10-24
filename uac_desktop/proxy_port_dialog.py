"""Local proxy port settings for both engines (Network Tools > Proxy Port)."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QFrame, QGridLayout, QHBoxLayout, QLabel, QPushButton, QSpinBox,
    QVBoxLayout,
)

from . import proxy_ports as P


class ProxyPortDialog(QDialog):
    """Edits the engine-1 SOCKS/HTTP pair and the engine-2 HTTP port.

    The dialog only validates; the caller saves the values it returns from
    :meth:`values` after ``exec()`` is accepted.
    """

    def __init__(self, parent, xray_ports: tuple[int, int], pow_port: int,
                 language: str = "fa", running_note: bool = False, busy_check=None,
                 pow_socks: int = P.POW_SOCKS_DEFAULT):
        super().__init__(parent)
        self.t = (lambda fa, en: en if language == "en" else fa)
        self._busy_check = busy_check
        self.setObjectName("proxyPortDialog")
        self.setWindowTitle(self.t("پورت پروکسی", "Proxy Port"))
        self.setLayoutDirection(Qt.LeftToRight if language == "en" else Qt.RightToLeft)
        self.setMinimumWidth(500)

        root = QVBoxLayout(self); root.setContentsMargins(20, 18, 20, 18); root.setSpacing(12)
        title = QLabel(self.t("پورت پروکسی محلی", "Local proxy port")); title.setObjectName("settingsTitle")
        hint = QLabel(self.t(
            "پروکسی سیستم ویندوز (کلید «پروکسی ویندوز») به همین پورت‌ها وصل می‌شود. "
            "برنامه‌های دیگر هم می‌توانند با 127.0.0.1 و همین پورت از تونل استفاده کنند.",
            "The Windows system proxy (the Windows Proxy switch) points at these ports. "
            "Other apps can also use the tunnel through 127.0.0.1 and these ports."))
        hint.setObjectName("settingsSubtitle"); hint.setWordWrap(True)
        root.addWidget(title); root.addWidget(hint)

        self.xray_socks = self._spin(xray_ports[0])
        self.xray_http = self._spin(xray_ports[1])
        self.pow_http = self._spin(pow_port)
        self.pow_socks = self._spin(pow_socks)

        box1 = self._section(
            self.t("موتور ۱ (Xray)", "Engine 1 (Xray)"),
            [(self.t("پورت SOCKS5", "SOCKS5 port"), self.xray_socks, P.XRAY_SOCKS_DEFAULT),
             (self.t("پورت HTTP", "HTTP port"), self.xray_http, P.XRAY_HTTP_DEFAULT)])
        box2 = self._section(
            self.t("موتور ۲ (UAC PoW)", "Engine 2 (UAC PoW)"),
            [(self.t("پورت HTTP", "HTTP port"), self.pow_http, P.POW_HTTP_DEFAULT),
             (self.t("پورت SOCKS5 (سایفون)", "SOCKS5 port (Psiphon)"), self.pow_socks, P.POW_SOCKS_DEFAULT)],
            self.t("در حالت App Bypass پورت HTTP هم HTTP و هم SOCKS است. "
                   "پورت SOCKS همان خروجی سایفون است که پروکسی ویندوز و برنامه‌ها به آن وصل می‌شوند. "
                   "اگر زنجیره سایفون خاموش باشد (فقط WARP)، خروجی 1820 می‌ماند (با MASQUE موازی 1825).",
                   "With App Bypass the HTTP port serves both HTTP and SOCKS. "
                   "The SOCKS port is the Psiphon exit that the Windows proxy and apps use. "
                   "With the Psiphon chain off (WARP only) the exit stays 1820 (1825 with parallel MASQUE)."))
        root.addWidget(box1); root.addWidget(box2)

        if running_note:
            note = QLabel(self.t("تغییر پورت از اتصال بعدی اعمال می‌شود.",
                                 "A new port takes effect on the next connect."))
            note.setObjectName("settingsSubtitle"); note.setWordWrap(True)
            root.addWidget(note)

        self.error = QLabel(""); self.error.setObjectName("proxyPortError"); self.error.setWordWrap(True)
        self.error.setStyleSheet("color: #ff6b6b;"); self.error.setVisible(False)
        root.addWidget(self.error)

        buttons = QHBoxLayout(); buttons.setSpacing(8)
        self.reset_btn = QPushButton(self.t("پیش‌فرض", "Defaults"))
        self.cancel_btn = QPushButton(self.t("لغو", "Cancel"))
        self.save_btn = QPushButton(self.t("ذخیره", "Save")); self.save_btn.setObjectName("primaryButton")
        for button in (self.reset_btn, self.cancel_btn, self.save_btn):
            button.setMinimumHeight(36)
        buttons.addWidget(self.reset_btn); buttons.addStretch(1)
        buttons.addWidget(self.cancel_btn); buttons.addWidget(self.save_btn)
        root.addLayout(buttons)
        self.reset_btn.clicked.connect(self.reset_defaults)
        self.cancel_btn.clicked.connect(self.reject)
        self.save_btn.clicked.connect(self.try_accept)

    def _spin(self, value: int) -> QSpinBox:
        spin = QSpinBox(); spin.setRange(P.PORT_MIN, P.PORT_MAX); spin.setValue(int(value))
        spin.setLayoutDirection(Qt.LeftToRight); spin.setMinimumHeight(32); spin.setMinimumWidth(120)
        return spin

    def _section(self, heading: str, rows, note: str = "") -> QFrame:
        frame = QFrame(); frame.setObjectName("settingsCard")
        grid = QGridLayout(frame); grid.setContentsMargins(14, 12, 14, 12); grid.setHorizontalSpacing(12); grid.setVerticalSpacing(8)
        head = QLabel(heading); head.setObjectName("settingsTitle")
        grid.addWidget(head, 0, 0, 1, 3)
        for index, (label, spin, default) in enumerate(rows, start=1):
            grid.addWidget(QLabel(label), index, 0)
            grid.addWidget(spin, index, 1)
            grid.addWidget(QLabel(self.t(f"پیش‌فرض: {default}", f"Default: {default}")), index, 2)
        if note:
            text = QLabel(note); text.setObjectName("settingsSubtitle"); text.setWordWrap(True)
            grid.addWidget(text, len(rows) + 1, 0, 1, 3)
        return frame

    def reset_defaults(self) -> None:
        self.xray_socks.setValue(P.XRAY_SOCKS_DEFAULT)
        self.xray_http.setValue(P.XRAY_HTTP_DEFAULT)
        self.pow_http.setValue(P.POW_HTTP_DEFAULT)
        self.pow_socks.setValue(P.POW_SOCKS_DEFAULT)
        self.error.setVisible(False)

    def values(self) -> tuple[tuple[int, int], int]:
        return (int(self.xray_socks.value()), int(self.xray_http.value())), int(self.pow_http.value())

    def pow_socks_value(self) -> int:
        return int(self.pow_socks.value())

    def problems(self) -> list[str]:
        (socks, http), pow_port = self.values()
        pow_socks = self.pow_socks_value()
        errors = P.validate_xray_ports(socks, http, self.t) + P.validate_pow_ports(pow_port, pow_socks, self.t)
        if errors or self._busy_check is None:
            return errors
        busy = self._busy_check([socks, http, pow_port, pow_socks])
        if busy:
            errors.append(self.t("این پورت آزاد نیست: ", "This port is not free: ") + "; ".join(busy))
        return errors

    def try_accept(self) -> None:
        errors = self.problems()
        if errors:
            self.error.setText("\n".join(errors)); self.error.setVisible(True)
            return
        self.accept()
