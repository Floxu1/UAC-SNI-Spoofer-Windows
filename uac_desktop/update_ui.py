"""Download and confirm a verified update without blocking the desktop."""
from __future__ import annotations

import threading

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtWidgets import QApplication, QMessageBox, QProgressDialog

from .updater import UpdateCancelled, discard_update, prepare_update


class UpdateTransfer(QObject):
    progress = Signal(int)
    finished = Signal(object, str)

    def __init__(self, window, installation, release_url):
        super().__init__(window)
        self.window = window
        self.release_url = release_url
        self.cancel = threading.Event()
        tr = window.tr
        self.dialog = QProgressDialog(tr("در حال دریافت بستهٔ سازگار…", "Downloading the compatible package…"),
                                      tr("لغو", "Cancel"), 0, 1000, window)
        self.dialog.setWindowTitle(tr("به‌روزرسانی UAC", "UAC update"))
        self.dialog.setWindowModality(Qt.WindowModal)
        self.dialog.setAutoClose(False)
        self.dialog.setAutoReset(False)
        self.dialog.setMinimumDuration(0)
        self.dialog.canceled.connect(self.cancel.set)
        self.progress.connect(self.dialog.setValue, Qt.QueuedConnection)
        self.finished.connect(self._finish, Qt.QueuedConnection)
        self.dialog.setValue(0)
        self.dialog.show()

        def work():
            try:
                update = prepare_update(installation, self.cancel,
                                        lambda count, size: self.progress.emit(count * 1000 // size))
            except UpdateCancelled:
                self.finished.emit(None, "")
            except Exception as error:
                self.finished.emit(None, str(error))
            else:
                if self.cancel.is_set():
                    discard_update(update)
                    update = None
                self.finished.emit(update, "")

        threading.Thread(target=work, name="uac-update-download", daemon=True).start()

    def _finish(self, update, error):
        self.dialog.hide()
        self.dialog.deleteLater()
        self.window._update_transfer = None
        self.deleteLater()
        if self.cancel.is_set() or self.window._closing:
            if update is not None:
                discard_update(update)
            return
        tr = self.window.tr
        if error:
            self.window._append_log(f"UPDATE: {error}")
            box = QMessageBox(QMessageBox.Warning, tr("به‌روزرسانی", "Update"),
                              tr("دریافت بستهٔ معتبر کامل نشد. نسخهٔ فعلی قابل استفاده است.",
                                 "A verified package could not be downloaded. The current version is available."),
                              QMessageBox.Close, self.window)
            box.setDetailedText(error)
            release = box.addButton(tr("صفحهٔ انتشار", "Release page"), QMessageBox.ActionRole)
            box.exec()
            if box.clickedButton() == release:
                self.window._open_release_page(self.release_url)
            return
        if update is None:
            return
        message = tr("بسته بررسی شد. برای نصب، اتصال قطع و برنامه پس از به‌روزرسانی باز می‌شود.",
                     "The package is verified. Installing will disconnect and restart the app.")
        box = QMessageBox(QMessageBox.Question, tr("به‌روزرسانی", "Update"), message,
                          QMessageBox.Cancel, self.window)
        install = box.addButton(tr("نصب و راه‌اندازی مجدد", "Install and restart"), QMessageBox.AcceptRole)
        box.exec()
        if box.clickedButton() != install or self.window._closing:
            discard_update(update)
            return
        self.window._prepared_update = update
        self.window._force_quit = True
        QApplication.quit()
