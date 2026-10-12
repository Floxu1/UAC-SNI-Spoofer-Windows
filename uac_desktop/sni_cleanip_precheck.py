"""Minimal pre-test dialog: find clean IPs for the current carrier before SNI Maker Test All."""
from __future__ import annotations

import threading

from PySide6.QtCore import QThread, Qt, QTimer, Signal
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QProgressBar, QPushButton, QVBoxLayout

from . import clean_ip

CARRIER_NAMES = {
    "irancell": ("\u0627\u06cc\u0631\u0627\u0646\u0633\u0644", "Irancell"),
    "mci": ("\u0647\u0645\u0631\u0627\u0647 \u0627\u0648\u0644", "MCI"),
    "auto": ("\u062e\u0648\u062f\u06a9\u0627\u0631", "Auto"),
}
BUDGET_S = 8.0
TOP = 5


def carrier_label(carrier: str, language: str = "fa") -> str:
    fa, en = CARRIER_NAMES.get(str(carrier or "auto").lower(), (carrier, carrier))
    return en if language == "en" else fa


class _Worker(QThread):
    carrier_ready = Signal(str, str)      # carrier, asn
    found = Signal(int)
    done = Signal(list)

    def __init__(self, cache, fallback_carrier, fake_sni_for, seeds_for, cancel, detect=None, find=None):
        super().__init__()
        self.cache = cache; self.fallback = fallback_carrier or "auto"
        self.fake_sni_for = fake_sni_for; self.seeds_for = seeds_for; self.cancel = cancel
        self.detect = detect; self.find = find or clean_ip.find_clean_ips
        self.carrier = self.fallback; self.asn = ""

    def run(self):
        ips = []
        try:
            if self.detect is None:
                from .sni_finder import detect_carrier as detect
            else:
                detect = self.detect
            info = detect(self.fallback, timeout=3.0) or {}
            self.carrier = str(info.get("carrier") or self.fallback or "auto").lower()
            self.asn = str(info.get("asn") or "")
        except Exception:
            self.carrier = self.fallback
        self.carrier_ready.emit(self.carrier, self.asn)
        if self.cancel.is_set():
            self.done.emit([]); return
        try:
            res = self.find(self.cache, self.carrier, self.fake_sni_for(self.carrier),
                            self.seeds_for(self.carrier), budget=BUDGET_S, top=TOP,
                            sample=220, cancel=self.cancel)
            ips = [r.ip for r in res if getattr(r, "ok", False)]
            self.found.emit(len(ips))
        except Exception:
            ips = []
        self.done.emit([] if self.cancel.is_set() else ips)


class CleanIpPrecheckDialog(QDialog):
    """Auto-closes when finished. result_carrier / result_ips are set afterwards."""

    def __init__(self, parent, cache, fallback_carrier, fake_sni_for, seeds_for,
                 language="fa", detect=None, find=None, autostart=True):
        super().__init__(parent)
        self.language = language
        self.t = (lambda fa, en: en if language == "en" else fa)
        self.setObjectName("cleanIpPrecheckDialog")
        self.setWindowTitle(self.t("IP \u062a\u0645\u06cc\u0632", "Clean IP"))
        self.setLayoutDirection(Qt.LeftToRight if language == "en" else Qt.RightToLeft)
        self.setModal(True)
        self.setFixedWidth(400)
        self.setStyleSheet(
            "QDialog#cleanIpPrecheckDialog { background: #071225; border: 1px solid rgba(35,245,224,0.45); }"
            "QLabel { background: transparent; color: #cfe3f2; }"
            "QLabel#settingsTitle { color: #eaf6ff; font-size: 15px; font-weight: 600; }"
            "QLabel#settingsSubtitle { color: #8fa9bf; }"
            "QProgressBar { background: rgba(255,255,255,0.08); border: none; border-radius: 2px; }"
            "QProgressBar::chunk { background: #23f5e0; border-radius: 2px; }"
            "QPushButton { min-width: 96px; padding: 6px 14px; }")
        self.result_carrier = str(fallback_carrier or "auto").lower()
        self.result_ips: list = []
        self.cancelled = False
        self._cancel = threading.Event()
        self._started = 0

        root = QVBoxLayout(self); root.setContentsMargins(22, 20, 22, 18); root.setSpacing(10)
        self.title = QLabel(self.t("\u067e\u06cc\u062f\u0627 \u06a9\u0631\u062f\u0646 IP \u062a\u0645\u06cc\u0632", "Finding clean IPs"))
        self.title.setObjectName("settingsTitle")
        self.carrier_lbl = QLabel(); self.carrier_lbl.setObjectName("settingsSubtitle")
        self.progress = QProgressBar(); self.progress.setFixedHeight(5); self.progress.setTextVisible(False)
        self.progress.setRange(0, 100); self.progress.setValue(0)
        self.status = QLabel(); self.status.setObjectName("settingsSubtitle"); self.status.setWordWrap(True)
        row = QHBoxLayout(); row.addStretch(1)
        self.cancel_btn = QPushButton(self.t("\u0644\u063a\u0648", "Cancel")); self.cancel_btn.setMinimumHeight(32)
        self.cancel_btn.clicked.connect(self.reject)
        row.addWidget(self.cancel_btn)
        for w in (self.title, self.carrier_lbl, self.progress, self.status):
            root.addWidget(w)
        root.addLayout(row)
        self._set_carrier(self.result_carrier, "", detecting=True)
        self.status.setText(self.t("\u062f\u0631 \u062d\u0627\u0644 \u062a\u0634\u062e\u06cc\u0635 \u0627\u067e\u0631\u0627\u062a\u0648\u0631\u2026", "Detecting carrier\u2026"))

        self._tick = QTimer(self); self._tick.setInterval(100); self._tick.timeout.connect(self._advance)
        self._worker = _Worker(cache, fallback_carrier, fake_sni_for, seeds_for, self._cancel, detect, find)
        self._worker.carrier_ready.connect(self._on_carrier)
        self._worker.found.connect(self._on_found)
        self._worker.done.connect(self._on_done)
        if autostart:
            QTimer.singleShot(0, self.start)

    def start(self):
        self._tick.start(); self._worker.start()

    def _set_carrier(self, carrier, asn, detecting=False):
        name = carrier_label(carrier, self.language)
        extra = f"  \u00b7  {asn}" if asn else ""
        self.carrier_lbl.setText(self.t("\u0627\u067e\u0631\u0627\u062a\u0648\u0631: ", "Carrier: ") + name + extra)

    def _advance(self):
        self._started += 1
        self.progress.setValue(min(95, int(self._started * 100 / (BUDGET_S * 10 + 10))))

    def _on_carrier(self, carrier, asn):
        self.result_carrier = carrier
        self._set_carrier(carrier, asn)
        self.status.setText(self.status_text(0))

    def status_text(self, count):
        name = carrier_label(self.result_carrier, self.language)
        return self.t(f"\u062f\u0631 \u062d\u0627\u0644 \u067e\u06cc\u062f\u0627 \u06a9\u0631\u062f\u0646 IP \u062a\u0645\u06cc\u0632 \u0631\u0648\u06cc {name}\u2026 {count} \u067e\u06cc\u062f\u0627 \u0634\u062f",
                      f"Finding clean IPs on {name}\u2026 {count} found")

    def _on_found(self, count):
        self.status.setText(self.status_text(count))

    def _on_done(self, ips):
        self._tick.stop(); self.progress.setValue(100)
        if self.cancelled:
            return
        self.result_ips = list(ips or [])
        self.accept()

    def reject(self):
        self.cancelled = True; self._cancel.set(); self._tick.stop()
        super().reject()

    def wait_worker(self, ms=3000):
        try:
            self._worker.wait(ms)
        except Exception:
            pass
