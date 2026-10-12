"""Small confirm dialog: switching engines while connected/connecting."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout

STYLE = """
QDialog#engineSwitchGuard { background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #071428, stop:1 #0a1d33);
  border: 1px solid rgba(35,245,224,0.35); }
QLabel { background: transparent; color: #cfe3f2; }
QLabel#guardIcon { font-size: 30px; }
QLabel#guardTitle { color: #f2fbff; font-size: 16px; font-weight: 700; }
QLabel#guardBody { color: #9db4c8; font-size: 12px; }
QPushButton#guardGo { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #19d9c6, stop:1 #3f7dff);
  color: #04111f; border: none; border-radius: 12px; font-weight: 800; padding: 9px 18px; }
QPushButton#guardGo:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #35f0dd, stop:1 #5c93ff); }
QPushButton#guardCancel { background: rgba(255,255,255,0.06); color: #cfe3f2; border: 1px solid rgba(255,255,255,0.12);
  border-radius: 12px; padding: 9px 18px; }
QPushButton#guardCancel:hover { border-color: rgba(35,245,224,0.5); }
"""

RLM = "\u200f"


class EngineSwitchGuard(QDialog):
    """accept() = disconnect then switch; reject() = stay on the current engine."""

    def __init__(self, parent=None, language="fa", target_name=""):
        super().__init__(parent)
        fa = language != "en"
        t = (lambda a, b: a if fa else b)
        self.setObjectName("engineSwitchGuard"); self.setModal(True); self.setStyleSheet(STYLE)
        self.setWindowTitle(t("تعویض موتور", "Switch engine"))
        self.setLayoutDirection(Qt.RightToLeft if fa else Qt.LeftToRight)
        self.setFixedWidth(380)
        root = QVBoxLayout(self); root.setContentsMargins(22, 20, 22, 18); root.setSpacing(8)
        icon = QLabel("🔌"); icon.setObjectName("guardIcon")
        self.title = QLabel((RLM if fa else "") + t("اول اتصال رو قطع کن تا بری موتور بعدی", "Disconnect first to switch engines"))
        self.title.setObjectName("guardTitle"); self.title.setWordWrap(True)
        self.body = QLabel((RLM if fa else "") + t("الان وصلی (یا داری وصل می‌شی). اگه بخوای، خودم قطع می‌کنم و می‌برمت روی موتور بعدی.",
                                                   "You're connected (or connecting). I can disconnect and take you to the other engine."))
        self.body.setObjectName("guardBody"); self.body.setWordWrap(True)
        for w in (icon, self.title, self.body):
            root.addWidget(w)
        row = QHBoxLayout(); row.setSpacing(8); row.addStretch(1)
        self.cancel_btn = QPushButton(t("باشه", "OK")); self.cancel_btn.setObjectName("guardCancel")
        self.go_btn = QPushButton(t("قطع و سوییچ", "Disconnect & switch")); self.go_btn.setObjectName("guardGo")
        for b in (self.cancel_btn, self.go_btn):
            b.setCursor(Qt.PointingHandCursor); row.addWidget(b)
        self.cancel_btn.setDefault(True)
        self.cancel_btn.clicked.connect(self.reject); self.go_btn.clicked.connect(self.accept)
        root.addSpacing(6); root.addLayout(row)
