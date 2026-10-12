"""Full clean-IP scan dialog (non-blocking, cancellable)."""
from __future__ import annotations

import threading

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView, QDialog, QHBoxLayout, QHeaderView, QLabel, QProgressBar,
    QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout,
)

from . import clean_ip


class _ScanWorker(QThread):
    result = Signal(object)
    progress = Signal(int, int)

    def __init__(self, cache, carrier, fake_sni, seeds, count=400, parent=None):
        super().__init__(parent)
        self.cache = cache; self.carrier = carrier; self.fake_sni = fake_sni
        self.seeds = list(seeds or []); self.count = int(count)
        self.cancel = threading.Event()

    def run(self):
        try:
            cached = list(self.cache.entries(self.carrier).keys())
            ips = list(dict.fromkeys(clean_ip.split_ips(self.seeds + cached)
                                     + clean_ip.sample_cloudflare(self.count, exclude=cached)))
            total = len(ips); done = [0]

            def on_result(r):
                done[0] += 1
                try:
                    if r.ok or r.ip in cached:
                        self.cache.record(self.carrier, r.ip, r.ok, r.latency_ms, save=False)
                except Exception:
                    pass
                self.result.emit(r)
                self.progress.emit(done[0], total)

            clean_ip.scan(ips, self.fake_sni, workers=50, deadline=120.0, timeout=2.5,
                          cancel=self.cancel, on_result=on_result, source="scan")
            self.cache.flush()
        except Exception:
            pass


class CleanIpScanDialog(QDialog):
    ip_chosen = Signal(str)

    def __init__(self, parent, cache, carrier, fake_sni, seeds=(), language="fa"):
        super().__init__(parent)
        self.t = (lambda fa, en: en if language == "en" else fa)
        self.setObjectName("cleanIpDialog")
        self.setWindowTitle(self.t("\u0627\u0633\u06a9\u0646 IP \u062a\u0645\u06cc\u0632", "Clean IP scan"))
        self.setLayoutDirection(Qt.LeftToRight if language == "en" else Qt.RightToLeft)
        self.resize(620, 520)
        self.cache = cache; self.carrier = carrier; self.fake_sni = fake_sni; self.seeds = list(seeds or [])
        self._worker = None; self._rows = {}

        root = QVBoxLayout(self); root.setContentsMargins(20, 18, 20, 18); root.setSpacing(12)
        title = QLabel(self.t("\u0627\u0633\u06a9\u0646 IP \u062a\u0645\u06cc\u0632", "Clean IP scan")); title.setObjectName("settingsTitle")
        hint = QLabel(self.t(
            "IP\u0647\u0627\u06cc Cloudflare \u0628\u0627 Fake SNI \u0641\u0639\u0644\u06cc \u062a\u0633\u062a \u0645\u06cc\u200c\u0634\u0648\u0646\u062f. \u0631\u0648\u06cc \u06cc\u06a9 \u0631\u062f\u06cc\u0641 \u0633\u0627\u0644\u0645 \u0628\u0632\u0646\u06cc\u062f \u0648 \xab\u0627\u0633\u062a\u0641\u0627\u062f\u0647 \u0627\u0632 \u0627\u06cc\u0646 IP\xbb \u0631\u0627 \u0627\u0646\u062a\u062e\u0627\u0628 \u06a9\u0646\u06cc\u062f.",
            "Cloudflare IPs are tested with the current Fake SNI. Pick a healthy row and press 'Use this IP'."))
        hint.setObjectName("settingsSubtitle"); hint.setWordWrap(True)
        meta = QLabel(f"Fake SNI: {fake_sni}   |   {carrier}"); meta.setObjectName("settingsSubtitle")
        meta.setLayoutDirection(Qt.LeftToRight)
        self.progress = QProgressBar(); self.progress.setFixedHeight(6); self.progress.setTextVisible(False)
        self.progress.setRange(0, 1); self.progress.setValue(0)
        self.status = QLabel(""); self.status.setObjectName("settingsSubtitle")
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["IP", self.t("\u067e\u06cc\u0646\u06af", "Ping ms"),
                                              self.t("\u0645\u0648\u0641\u0642\u06cc\u062a", "Success %"),
                                              self.t("\u0648\u0636\u0639\u06cc\u062a", "Status")])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setLayoutDirection(Qt.LeftToRight)
        self.table.itemSelectionChanged.connect(self._sync_buttons)

        buttons = QHBoxLayout(); buttons.setSpacing(8)
        self.start_btn = QPushButton(self.t("\u0634\u0631\u0648\u0639 \u0627\u0633\u06a9\u0646", "Start scan"))
        self.cancel_btn = QPushButton(self.t("\u0644\u063a\u0648", "Cancel"))
        self.use_btn = QPushButton(self.t("\u0627\u0633\u062a\u0641\u0627\u062f\u0647 \u0627\u0632 \u0627\u06cc\u0646 IP", "Use this IP"))
        self.use_btn.setObjectName("primaryButton")
        close_btn = QPushButton(self.t("\u0628\u0633\u062a\u0646", "Close"))
        for b in (self.start_btn, self.cancel_btn, self.use_btn, close_btn):
            b.setMinimumHeight(36)
        buttons.addWidget(self.start_btn); buttons.addWidget(self.cancel_btn); buttons.addStretch(1)
        buttons.addWidget(self.use_btn); buttons.addWidget(close_btn)
        self.start_btn.clicked.connect(self.start_scan)
        self.cancel_btn.clicked.connect(self.cancel_scan)
        self.use_btn.clicked.connect(self._use_selected)
        close_btn.clicked.connect(self.close)

        for w in (title, hint, meta, self.progress, self.status, self.table):
            root.addWidget(w)
        root.addLayout(buttons)
        self._load_cached()
        self._sync_buttons()

    def _ratio(self, ip):
        e = self.cache.entries(self.carrier).get(ip) or {}
        total = int(e.get("ok", 0)) + int(e.get("fail", 0))
        return int(round(100.0 * int(e.get("ok", 0)) / total)) if total else 0

    def _set_row(self, ip, latency, ok, status=None):
        self.table.setSortingEnabled(False)
        self._rebuild_index()
        row = self._rows.get(ip)
        if row is None:
            row = self.table.rowCount(); self.table.insertRow(row); self._rows[ip] = row
        ping = QTableWidgetItem(); ping.setData(Qt.DisplayRole, int(round(latency)) if ok else 9999)
        if not ok:
            ping.setText("-")
        rate = QTableWidgetItem(); rate.setData(Qt.DisplayRole, self._ratio(ip))
        state = QTableWidgetItem(status or (self.t("\u0633\u0627\u0644\u0645", "OK") if ok else self.t("\u0646\u0627\u0645\u0648\u0641\u0642", "Failed")))
        for col, item in enumerate((QTableWidgetItem(ip), ping, rate, state)):
            item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, col, item)
        self.table.setSortingEnabled(True)

    def _load_cached(self):
        for ip, e in self.cache.entries(self.carrier).items():
            if int(e.get("ok", 0)) > 0:
                self._set_row(ip, float(e.get("latency_ms", 0) or 0), True, "cache")

    def _rebuild_index(self):
        self._rows = {}
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item is not None:
                self._rows[item.text()] = row

    def start_scan(self):
        if self._worker is not None and self._worker.isRunning():
            return
        self._worker = _ScanWorker(self.cache, self.carrier, self.fake_sni, self.seeds, parent=self)
        self._worker.result.connect(self._on_result)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self.status.setText(self.t("\u062f\u0631 \u062d\u0627\u0644 \u0627\u0633\u06a9\u0646\u2026", "Scanning\u2026"))
        self.progress.setRange(0, 0)
        self._worker.start(); self._sync_buttons()

    def cancel_scan(self):
        if self._worker is not None:
            self._worker.cancel.set()
            self.status.setText(self.t("\u0644\u063a\u0648 \u0634\u062f", "Cancelled"))

    def _on_result(self, r):
        if not r.ok and r.ip not in self._rows:
            return  # only list healthy IPs (and known ones) to keep the table readable
        self._rebuild_index()
        self._set_row(r.ip, r.latency_ms, r.ok)

    def _on_progress(self, done, total):
        self.progress.setRange(0, max(1, total)); self.progress.setValue(done)
        good = sum(1 for row in range(self.table.rowCount())
                   if (self.table.item(row, 3) and self.table.item(row, 3).text() != self.t("\u0646\u0627\u0645\u0648\u0641\u0642", "Failed")))
        self.status.setText(f"{done}/{total}  |  OK: {good}")

    def _on_finished(self):
        if self.progress.maximum() == 0:
            self.progress.setRange(0, 1)
        self.progress.setValue(self.progress.maximum())
        if self._worker is not None and not self._worker.cancel.is_set():
            self.status.setText(self.status.text() + "  |  " + self.t("\u062a\u0645\u0627\u0645 \u0634\u062f", "Done"))
        self._sync_buttons()

    def _selected_ip(self):
        rows = self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
        if not rows:
            return ""
        item = self.table.item(rows[0].row(), 0)
        return item.text() if item is not None else ""

    def _sync_buttons(self):
        running = self._worker is not None and self._worker.isRunning()
        self.start_btn.setEnabled(not running); self.cancel_btn.setEnabled(running)
        self.use_btn.setEnabled(bool(self._selected_ip()))

    def _use_selected(self):
        ip = clean_ip.valid_ipv4(self._selected_ip())
        if not ip:
            return
        try:
            item = self.table.item(self.table.currentRow(), 1)
            latency = float(item.data(Qt.DisplayRole) or 0) if item else 0.0
            self.cache.record(self.carrier, ip, True, latency if latency < 9999 else 0.0)
        except Exception:
            pass
        self.ip_chosen.emit(ip)
        self.status.setText(self.t("IP \u0627\u0646\u062a\u062e\u0627\u0628 \u0634\u062f", "IP selected") + f": {ip}")

    def _stop_worker(self):
        if self._worker is not None:
            self._worker.cancel.set()
            self._worker.wait(3000)

    def closeEvent(self, event):
        self._stop_worker(); super().closeEvent(event)

    def reject(self):
        self._stop_worker(); super().reject()
