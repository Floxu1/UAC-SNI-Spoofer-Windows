"""Offline, bilingual Windows setup UI. All installation work is delegated to MSI."""
from __future__ import annotations

import subprocess
import sys
import threading
from pathlib import Path

from installer import bootstrap_backend as backend


def main() -> int:
    args = sys.argv[1:]
    if args and all(arg.lower() in ("/quiet", "/qn", "/norestart", "--quiet") for arg in args):
        return backend.silent_install()
    if args:
        # Automation uses the separately published MSI, without a GUI or auto-launch.
        return 87
    return run_ui()


def run_ui() -> int:
    from PySide6.QtCore import QByteArray, QDir, QEasingCurve, QLocale, QPropertyAnimation, Qt, Signal
    from PySide6.QtGui import QFont, QFontDatabase, QIcon, QPainter, QPixmap
    from PySide6.QtSvg import QSvgRenderer
    from PySide6.QtWidgets import (QApplication, QCheckBox, QDialog, QFileSystemModel, QFrame, QHBoxLayout,
                                   QLabel, QLineEdit, QMessageBox, QProgressBar, QPushButton, QTreeView, QVBoxLayout)
    from installer.bootstrap_strings import TEXT, translate
    from uac_desktop import theme

    assets = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1])) / "assets"
    app = QApplication(sys.argv)
    app.setApplicationName("UAC Spoofer Desktop Setup")
    app.setWindowIcon(QIcon(str(assets / "icon.png")))
    for name in ("regular", "semibold", "bold"):
        QFontDatabase.addApplicationFont(str(assets / "fonts" / f"vazirmatn_ui_fd_{name}.ttf"))

    class Setup(QDialog):
        event = Signal(str, object)

        def __init__(self):
            super().__init__()
            self.language = backend.saved_language()
            self.folder, self.desktop, self.start_menu = backend.installation_defaults()
            self.stage = 0
            self.cancel_event = None
            self.last_error = None
            self.result_code = None
            self.activity = "waiting"
            self.position = None
            self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
            self.setObjectName("setupWindow")
            self.setAttribute(Qt.WA_TranslucentBackground)
            self.setFixedSize(650, 570)
            self.event.connect(self.receive)
            self.outer = QVBoxLayout(self)
            self.outer.setContentsMargins(0, 0, 0, 0)
            self.root = None
            self.render()

        def tr(self, key, **values):
            return translate(self.language, key, **values)

        def label(self, key, role="", *, raw=False):
            label = QLabel(key if raw else self.tr(key), objectName=role)
            label.setTextFormat(Qt.PlainText)
            return label

        def frame(self, role, height=0):
            panel = QFrame(objectName=role)
            if height:
                panel.setFixedHeight(height)
            return panel

        def button(self, key, action, primary=False):
            button = QPushButton(self.tr(key), objectName="primary" if primary else "secondary")
            button.setCursor(Qt.PointingHandCursor)
            button.clicked.connect(action)
            return button

        def set_language(self, language):
            self.language = language
            self.render()

        def turn(self, stage):
            self.stage = stage
            self.render()

        def render(self):
            if self.root is not None:
                self.outer.removeWidget(self.root)
                self.root.hide()
                self.root.deleteLater()
            rtl = self.language == "fa"
            QLocale.setDefault(QLocale("fa_IR" if rtl else "en_US"))
            self.setWindowTitle(f"UAC Spoofer Desktop — {self.tr('setup')}")
            self.setLayoutDirection(Qt.RightToLeft if rtl else Qt.LeftToRight)
            font = "Vazirmatn UI FD" if rtl else "Segoe UI"
            self.setFont(QFont(font, 10))
            self.setStyleSheet(STYLE.replace("SETUP_CHECK", (assets / "ui" / "lucide-direct-check.svg").as_posix()))
            self.root = self.frame("shell")
            self.outer.addWidget(self.root)
            layout = QVBoxLayout(self.root)
            layout.setContentsMargins(1, 1, 1, 1)
            layout.setSpacing(0)

            titlebar = self.frame("titlebar", 42)
            bar = QHBoxLayout(titlebar)
            bar.setContentsMargins(18, 0, 15, 0)
            brand = self.label("", raw=True)
            brand.setPixmap(QIcon(str(assets / "icon.png")).pixmap(24, 24))
            bar.addWidget(brand)
            bar.addWidget(self.label(self.windowTitle(), "muted", raw=True), 1)
            close = QPushButton("×", objectName="close")
            close.setAccessibleName(self.tr("close"))
            close.setCursor(Qt.PointingHandCursor)
            close.clicked.connect(self.close)
            bar.addWidget(close)
            titlebar.mousePressEvent = self.drag
            titlebar.mouseMoveEvent = self.drag
            layout.addWidget(titlebar)

            hero = self.frame("hero", 157)
            main = QHBoxLayout(hero)
            main.setContentsMargins(25, 13, 25, 13)
            main.setSpacing(12)
            words = QVBoxLayout()
            words.setSpacing(0)
            edition = self.label("edition", "kicker")
            words.addWidget(edition)
            for text in ("UAC <span style='color:#46DCE8'>Spoofer</span>", "Desktop"):
                heading = QLabel(text, objectName="headline")
                heading.setFixedHeight(39)
                heading.setLayoutDirection(Qt.LeftToRight)
                heading.setAlignment((Qt.AlignRight if rtl else Qt.AlignLeft) | Qt.AlignVCenter)
                words.addWidget(heading)
            words.addWidget(self.label("tagline", "muted"))
            main.addLayout(words, 1)
            insignia = self.label("", raw=True)
            insignia.setPixmap(QIcon(str(assets / "icon.png")).pixmap(117, 117))
            main.addWidget(insignia)
            layout.addWidget(hero)

            navigation = self.frame("steps", 46)
            steps = QHBoxLayout(navigation)
            steps.setContentsMargins(25, 0, 25, 0)
            steps.setSpacing(8)
            for index, step in enumerate(("welcome", "options", "install", "finish")):
                if index:
                    separator = self.frame("connector", 1)
                    separator.setFixedWidth(22)
                    steps.addWidget(separator)
                bubble = QLabel(QLocale().toString(index + 1),
                                objectName="stepActive" if index == self.stage else "stepNumber")
                bubble.setFont(QFont(font, 10))
                bubble.setFixedSize(20, 20)
                bubble.setAlignment(Qt.AlignCenter)
                steps.addWidget(bubble)
                steps.addWidget(self.label(step, "active" if index == self.stage else "muted"), 1)
            layout.addWidget(navigation)

            body = QFrame()
            content = QVBoxLayout(body)
            content.setContentsMargins(25, 19, 25, 15)
            content.setSpacing(9)
            footer = self.frame("footer", 57)
            commands = QHBoxLayout(footer)
            commands.setContentsMargins(25, 0, 25, 0)
            commands.setSpacing(8)
            signature = self.label("UAC DESKTOP", "signature", raw=True)
            signature.setAlignment((Qt.AlignRight if rtl else Qt.AlignLeft) | Qt.AlignVCenter)
            commands.addWidget(signature, 1)
            if self.stage == 0:
                self.welcome(content, commands)
            elif self.stage == 1:
                self.options(content, commands)
            elif self.stage == 2:
                self.installing(content, commands)
            else:
                self.finish(content, commands)
            layout.addWidget(body, 1)
            layout.addWidget(footer)
            animation = QPropertyAnimation(self, b"windowOpacity", self)
            animation.setStartValue(.96)
            animation.setEndValue(1.0)
            animation.setDuration(130)
            animation.setEasingCurve(QEasingCurve.OutCubic)
            animation.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)

        def welcome(self, content, commands):
            heading = QHBoxLayout()
            heading.addWidget(self.label("ready", "pageTitle"), 1)
            for language, title in (("fa", "فارسی"), ("en", "English")):
                button = QPushButton(title, objectName="languageCurrent" if self.language == language else "language")
                button.setCursor(Qt.PointingHandCursor)
                button.clicked.connect(lambda _, chosen=language: self.set_language(chosen))
                heading.addWidget(button)
            content.addLayout(heading)
            intro = self.label("intro", "muted")
            intro.setWordWrap(True)
            content.addWidget(intro)
            content.addSpacing(8)
            cards = QHBoxLayout()
            cards.setSpacing(8)
            for engine, title in (("xray", "Xray"), ("pow", "UAC PoW"), ("direct", "UAC Direct")):
                tile = self.frame("tile", 52)
                row = QHBoxLayout(tile)
                row.setContentsMargins(11, 0, 11, 0)
                accent = theme.ENGINE_BRAND_PALETTES[engine]["accent"]
                glyph_label = self.label("", raw=True)
                glyph_label.setPixmap(QIcon(str(assets / f"setup-{engine}.png")).pixmap(22, 22))
                row.addWidget(glyph_label)
                value = self.label(title, raw=True)
                value.setStyleSheet(f"color:{accent};font-weight:600")
                row.addWidget(value, 1)
                cards.addWidget(tile, 1)
            content.addLayout(cards)
            content.addStretch(1)
            content.addWidget(self.label("offline", "muted"))
            commands.addWidget(self.button("cancel", self.close))
            commands.addWidget(self.button("start", lambda: self.turn(1), True))

        def options(self, content, commands):
            content.addWidget(self.label("folder", "pageTitle"))
            row = QHBoxLayout()
            self.path_entry = QLineEdit(self.folder)
            self.path_entry.setLayoutDirection(Qt.LeftToRight)
            self.path_entry.textChanged.connect(lambda value: setattr(self, "folder", value))
            row.addWidget(self.path_entry, 1)
            row.addWidget(self.button("browse", self.browse))
            content.addLayout(row)
            for key, field in (("desktop", "desktop"), ("menu", "start_menu")):
                option = QCheckBox(self.tr(key))
                option.setChecked(getattr(self, field))
                option.toggled.connect(lambda checked, name=field: setattr(self, name, checked))
                content.addWidget(option)
            self.option_error = self.label("", "error", raw=True)
            self.option_error.setWordWrap(True)
            content.addWidget(self.option_error)
            content.addStretch(1)
            commands.addWidget(self.button("back", lambda: self.turn(0)))
            commands.addWidget(self.button("now", self.start, True))

        def browse(self):
            dialog = QDialog(self)
            dialog.setWindowTitle(self.tr("folder"))
            dialog.resize(490, 380)
            layout = QVBoxLayout(dialog)
            model = QFileSystemModel(dialog)
            model.setFilter(QDir.AllDirs | QDir.NoDotAndDotDot)
            model.setRootPath("")
            tree = QTreeView()
            tree.setModel(model)
            tree.setHeaderHidden(True)
            tree.setLayoutDirection(Qt.LeftToRight)
            for column in range(1, model.columnCount()):
                tree.hideColumn(column)
            index = model.index(self.folder)
            if index.isValid():
                tree.setCurrentIndex(index)
            layout.addWidget(tree, 1)
            controls = QHBoxLayout()
            controls.addStretch(1)
            controls.addWidget(self.button("cancel", dialog.reject))
            controls.addWidget(self.button("select", dialog.accept, True))
            layout.addLayout(controls)
            if dialog.exec() and tree.currentIndex().isValid():
                self.path_entry.setText(model.filePath(tree.currentIndex()))

        def start(self):
            try:
                target = backend.validate_directory(self.folder.strip())
            except (OSError, ValueError):
                self.option_error.setText(self.tr("invalid"))
                return
            if backend.running_application():
                self.option_error.setText(self.tr("busy"))
                return
            self.folder = str(target)
            self.activity = "waiting"
            self.last_error = None
            self.result_code = None
            self.cancel_event = threading.Event()
            self.turn(2)
            owner = int(self.winId())
            def work():
                try:
                    result = backend.start_install(target, self.desktop, self.start_menu, self.cancel_event,
                                                   self.event.emit, owner=owner)
                except InterruptedError:
                    result = 1602
                except (OSError, ValueError):
                    result = backend.PAYLOAD
                self.event.emit("done", result)
            threading.Thread(target=work, daemon=True).start()

        def installing(self, content, commands):
            content.addWidget(self.label("installing", "pageTitle"))
            self.current_action = self.label("waiting", "muted")
            self.current_action.setWordWrap(True)
            content.addWidget(self.current_action)
            self.gauge = QProgressBar()
            self.gauge.setTextVisible(False)
            self.gauge.setRange(0, 0)
            content.addWidget(self.gauge)
            self.percent = self.label("", "kicker", raw=True)
            content.addWidget(self.percent, 0, Qt.AlignTrailing)
            content.addStretch(1)
            self.cancel_button = self.button("cancel", self.cancel_current)
            commands.addWidget(self.cancel_button)

        def receive(self, kind, value):
            if kind == "progress" and self.stage == 2:
                if value >= 0 and (self.gauge.maximum() == 0 or value >= self.gauge.value()):
                    self.gauge.setRange(0, 100)
                    self.gauge.setValue(value)
                    locale = QLocale()
                    self.percent.setText(locale.toString(value) + locale.percent())
            elif kind == "action" and self.stage == 2 and not self.cancel_event.is_set():
                self.current_action.setText(self.tr(value) if value in TEXT else self.tr("action", action=value))
            elif kind == "msi_error":
                self.last_error = value
            elif kind == "done":
                self.result_code = value
                self.turn(3)

        def finish(self, content, commands):
            successful = self.result_code in (0, 3010)
            line = QHBoxLayout()
            symbol = self.label("" if successful else "!", "success" if successful else "error", raw=True)
            symbol.setFixedSize(32, 32)
            symbol.setAlignment(Qt.AlignCenter)
            if successful:
                check = (assets / "ui" / "lucide-direct-check.svg").read_bytes().replace(b"#24160e", b"#5fe4ab")
                scale = self.devicePixelRatioF()
                pixmap = QPixmap(round(20 * scale), round(20 * scale))
                pixmap.fill(Qt.transparent)
                painter = QPainter(pixmap)
                QSvgRenderer(QByteArray(check)).render(painter)
                painter.end()
                pixmap.setDevicePixelRatio(scale)
                symbol.setPixmap(pixmap)
            line.addWidget(symbol)
            line.addWidget(self.label("success" if successful else "failed", "pageTitle"), 1)
            content.addLayout(line)
            if successful:
                content.addWidget(self.label("reboot" if self.result_code == 3010 else "installed", "muted"))
                try:
                    backend.seed_language(self.language)
                except OSError:
                    content.addWidget(self.label("language_failed", "error"))
                self.launch = QCheckBox(self.tr("launch"))
                self.launch.setChecked(self.result_code == 0)
                self.launch.setEnabled(self.result_code == 0)
                content.addWidget(self.launch)
                commands.addWidget(self.button("finish", self.complete, True))
            else:
                failure = {1602: "canceled", 1223: "permission", backend.BUSY: "busy",
                           backend.PAYLOAD: "integrity", backend.COMMUNICATION: "worker_failed"}.get(self.result_code)
                message = self.tr(failure) if failure else self.tr("error", code=self.result_code)
                content.addWidget(self.label(message, "muted", raw=True))
                if self.last_error not in (None, -2147483648):
                    content.addWidget(self.label(self.tr("code", code=self.last_error), "muted", raw=True))
                commands.addWidget(self.button("close", self.close))
                commands.addWidget(self.button("retry", lambda: self.turn(1), True))
            content.addStretch(1)

        def complete(self):
            if self.launch.isChecked():
                try:
                    backend.launch_from_desktop(Path(self.folder))
                except (OSError, subprocess.SubprocessError):
                    self.message("launch_failed")
                    return
            self.accept()

        def message(self, title, text=None, confirm=False):
            box = QMessageBox(self)
            box.setWindowTitle(self.tr("setup"))
            box.setText(self.tr(title))
            if text:
                box.setInformativeText(self.tr(text))
            if confirm:
                cancel = box.addButton(self.tr("cancel"), QMessageBox.DestructiveRole)
                keep = box.addButton(self.tr("keep"), QMessageBox.RejectRole)
                box.setDefaultButton(keep)
            else:
                box.addButton(self.tr("close"), QMessageBox.AcceptRole)
            box.exec()
            return confirm and box.clickedButton() == cancel

        def cancel_current(self):
            if not self.cancel_event.is_set() and self.message("cancel_title", "cancel_help", True):
                if self.stage != 2:
                    return
                self.cancel_event.set()
                self.cancel_button.setEnabled(False)
                self.current_action.setText(self.tr("canceling"))

        def closeEvent(self, event):
            if self.stage == 2:
                event.ignore()
                self.cancel_current()
            else:
                super().closeEvent(event)

        def reject(self):
            if self.stage == 2:
                self.cancel_current()
            else:
                super().reject()

        def drag(self, event):
            if event.button() == Qt.LeftButton:
                self.position = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            elif event.buttons() == Qt.LeftButton and self.position is not None:
                self.move(event.globalPosition().toPoint() - self.position)

    setup = Setup()
    setup.show()
    return app.exec()


STYLE = """
QWidget { color: #e9f0f6; }
QFrame#shell { background: #11161C; border: 1px solid #34414b; border-radius: 11px; }
QFrame#titlebar { background: #181F26; border-bottom: 1px solid #263640; border-top-left-radius: 10px; border-top-right-radius: 10px; }
QFrame#hero { background: qlineargradient(x1:0,y1:1,x2:1,y2:0,stop:0 #131b23,stop:1 #13343c); border-bottom: 1px solid #263640; }
QFrame#steps { border-bottom: 1px solid #263640; }
QFrame#footer { background: #161d24; border-top: 1px solid #263640; border-bottom-left-radius: 10px; border-bottom-right-radius: 10px; }
QFrame#tile { background: #181F26; border: 1px solid #2d3b46; border-radius: 7px; }
QFrame#connector { background: #34414b; }
QLabel#headline { font-size: 34px; font-weight: 700; }
QLabel#pageTitle { font-size: 21px; font-weight: 600; }
QLabel#kicker { color: #46DCE8; font-size: 12px; font-weight: 600; }
QLabel#muted { color: #9caebb; font-size: 12px; }
QLabel#signature { color: #7f929f; font-size: 10px; }
QLabel#active { color: #8ff3f5; font-size: 12px; }
QLabel#stepActive { background: #46DCE8; color: #0a171a; border-radius: 10px; font-weight: 600; }
QLabel#stepNumber { background: #26323b; color: #9caebb; border: 1px solid #35434c; border-radius: 10px; }
QLabel#success { background: #153830; color: #5fe4ab; border-radius: 8px; font-size: 23px; }
QLabel#error { color: #ffaaa6; }
QPushButton { background: #1c2831; border: 1px solid #344650; border-radius: 6px; padding: 7px 13px; }
QPushButton:hover { border-color: #70bfca; }
QPushButton:focus, QLineEdit:focus { border-color: #46DCE8; }
QPushButton:disabled { color: #82919b; }
QPushButton#close { background: transparent; border: 0; font-size: 17px; padding: 1px 7px; }
QPushButton#primary { color: #0a2025; font-weight: 700; min-width: 95px; border-color: #60eff2;
  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #65e8ec,stop:1 #37b9cd); }
QPushButton#primary:hover { background: #82f4f2; }
QPushButton#language, QPushButton#languageCurrent { font-size: 11px; padding: 3px 8px; }
QPushButton#languageCurrent { color: #8ff3f5; border-color: #43808d; }
QCheckBox { spacing: 8px; min-height: 25px; }
QCheckBox::indicator { width: 14px; height: 14px; border: 1px solid #5d7884; border-radius: 3px; background: #182029; }
QCheckBox::indicator:checked { background: #46DCE8; border: 1px solid #92f8fc; image: url("SETUP_CHECK"); }
QCheckBox::indicator:focus { border-color: white; }
QLineEdit { padding: 8px; border: 1px solid #41525f; border-radius: 6px; background: #101820; }
QProgressBar { border: 1px solid #273d45; background: #19252d; border-radius: 5px; min-height: 10px; max-height: 10px; }
QProgressBar::chunk { background: #46DCE8; border-radius: 4px; }
QDialog, QMessageBox { background: #11161C; }
QDialog#setupWindow { background: transparent; }
QTreeView { background: #101820; alternate-background-color: #182029; selection-background-color: #28525b; }
"""


if __name__ == "__main__":
    raise SystemExit(main())
