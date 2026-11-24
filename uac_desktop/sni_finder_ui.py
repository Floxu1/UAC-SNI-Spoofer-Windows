"""Simple 'Find working configs' panel on the SNI Maker page."""
from __future__ import annotations

import threading
from dataclasses import replace

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView, QFrame, QHBoxLayout, QHeaderView, QLabel, QProgressBar,
    QPushButton, QSizePolicy, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from . import sni_finder as F

S = {
    "title": ("\u067e\u06cc\u062f\u0627 \u06a9\u0631\u062f\u0646 \u06a9\u0627\u0646\u0641\u06cc\u06af\u200c\u0647\u0627\u06cc \u0633\u0627\u0644\u0645", "Find working configs"),
    "sub": ("\u0627\u067e\u0631\u0627\u062a\u0648\u0631 \u0634\u0645\u0627 \u0634\u0646\u0627\u0633\u0627\u06cc\u06cc \u0645\u06cc\u200c\u0634\u0648\u062f\u060c IP\u0647\u0627\u06cc \u062a\u0645\u06cc\u0632 \u0647\u0645\u0627\u0646 \u0627\u067e\u0631\u0627\u062a\u0648\u0631 \u067e\u06cc\u062f\u0627 \u0645\u06cc\u200c\u0634\u0648\u0646\u062f \u0648 \u0647\u0631 \u06a9\u0627\u0646\u0641\u06cc\u06af \u0628\u0627 \u062a\u0631\u0627\u0641\u06cc\u06a9 \u0648\u0627\u0642\u0639\u06cc \u062a\u0633\u062a \u0645\u06cc\u200c\u0634\u0648\u062f.",
            "Detects your carrier, finds that carrier's clean IPs and tests every config with real traffic."),
    "cancel": ("\u0644\u063a\u0648", "Cancel"),
    "adv": ("\u062d\u0631\u0641\u0647\u200c\u0627\u06cc (\u0627\u0628\u0632\u0627\u0631\u0647\u0627\u06cc \u0642\u0628\u0644\u06cc)", "Advanced (classic tools)"),
    "ready": ("\u0622\u0645\u0627\u062f\u0647", "Ready"),
    "detect": ("\u062f\u0631 \u062d\u0627\u0644 \u0634\u0646\u0627\u0633\u0627\u06cc\u06cc \u0627\u067e\u0631\u0627\u062a\u0648\u0631\u2026", "Detecting carrier\u2026"),
    "clean": ("\u062f\u0631 \u062d\u0627\u0644 \u067e\u06cc\u062f\u0627 \u06a9\u0631\u062f\u0646 IP \u062a\u0645\u06cc\u0632\u2026", "Finding clean IPs\u2026"),
    "test": ("\u062f\u0631 \u062d\u0627\u0644 \u062a\u0633\u062a \u06a9\u0627\u0646\u0641\u06cc\u06af\u200c\u0647\u0627", "Testing configs"),
    "load": ("\u062f\u0631 \u062d\u0627\u0644 \u062f\u0631\u06cc\u0627\u0641\u062a \u06a9\u0627\u0646\u0641\u06cc\u06af\u200c\u0647\u0627\u2026", "Loading configs\u2026"),
    "done": ("\u062a\u0645\u0627\u0645 \u0634\u062f", "Done"),
    "none": ("\u06a9\u0627\u0646\u0641\u06cc\u06af \u0633\u0627\u0644\u0645\u06cc \u067e\u06cc\u062f\u0627 \u0646\u0634\u062f", "No working config found"),
    "add": ("\u0627\u0641\u0632\u0648\u062f\u0646", "Add"),
    "addall": ("\u0627\u0641\u0632\u0648\u062f\u0646 \u0647\u0645\u0647", "Add all"),
    "added": ("\u0627\u0636\u0627\u0641\u0647 \u0634\u062f", "Added"),
    "country": ("\u06a9\u0634\u0648\u0631", "Country"),
    "name": ("\u0646\u0627\u0645", "Name"),
    "ms": ("\u067e\u06cc\u0646\u06af", "Ping"),
    "carrier": ("\u0627\u067e\u0631\u0627\u062a\u0648\u0631", "Carrier"),
    "disc": ("\u0628\u0631\u0627\u06cc \u062a\u0633\u062a \u0627\u0648\u0644 \u0627\u062a\u0635\u0627\u0644 \u0631\u0627 \u0642\u0637\u0639 \u06a9\u0646\u06cc\u062f", "Disconnect first to run the test"),
    "cancelled": ("\u0644\u063a\u0648 \u0634\u062f", "Cancelled"),
    "err": ("\u062e\u0637\u0627\u061b \u0631\u0648\u0634 \u0642\u0628\u0644\u06cc \u0627\u062c\u0631\u0627 \u0634\u062f", "Error; classic test was used"),
    "reval": ("\u0628\u0627\u0632\u0628\u06cc\u0646\u06cc \u06a9\u0627\u0646\u0641\u06cc\u06af\u200c\u0647\u0627\u06cc \u0642\u062f\u06cc\u0645\u06cc\u2026", "Re-checking older configs\u2026"),
    "cleanips": ("IP \u062a\u0645\u06cc\u0632", "clean IPs"),
    "found": ("\u0633\u0627\u0644\u0645", "working"),
    "skipped": ("\u06a9\u0627\u0646\u0641\u06cc\u06af \u06a9\u0627\u0631\u0628\u0631 \u062f\u0633\u062a \u0646\u062e\u0648\u0631\u062f", "existing user config left untouched"),
}
CARRIER_LABEL = {"mci": "MCI", "irancell": "Irancell", "auto": "Auto"}
MAX_CONFIGS = 60
WORKERS = 20


class _Bridge(QObject):
    status = Signal(str, int, int)
    finished = Signal(object)
    revalidated = Signal(object)


class FinderPanel(QFrame):
    def __init__(self, window):
        super().__init__()
        self.w = window
        self.setObjectName("makerSourceCard")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self._cancel = None; self._thread = None; self._reval_thread = None
        self._report = None; self._classic = []
        self.bridge = _Bridge(); self.bridge.status.connect(self._on_status)
        self.bridge.finished.connect(self._on_finished); self.bridge.revalidated.connect(self._on_revalidated)
        root = QVBoxLayout(self); root.setContentsMargins(14, 10, 14, 10); root.setSpacing(6)
        head = QHBoxLayout(); head.setSpacing(8)
        self.title = QLabel(self.t("title")); self.title.setObjectName("makerStepTitle")
        self.carrier_pill = QLabel(""); self.carrier_pill.setObjectName("summaryPill")
        self.carrier_pill.setAlignment(Qt.AlignCenter); self.carrier_pill.setVisible(False)
        head.addWidget(self.title); head.addStretch(1); head.addWidget(self.carrier_pill)
        root.addLayout(head)
        self.subtitle = QLabel(self.t("sub")); self.subtitle.setObjectName("selectionText"); self.subtitle.setWordWrap(True)
        root.addWidget(self.subtitle)
        row = QHBoxLayout(); row.setSpacing(8)
        self.status = QLabel(self.t("ready")); self.status.setObjectName("selectionText")
        self.status.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.find_btn = window._action_button(S["title"][0], S["title"][1], "sparkles", "primaryAction")
        self.cancel_btn = window._action_button(S["cancel"][0], S["cancel"][1], "x-circle", "dangerButton")
        self.cancel_btn.setEnabled(False)
        self.find_btn.clicked.connect(self.start); self.cancel_btn.clicked.connect(self.cancel)
        row.addWidget(self.status, 1); row.addWidget(self.find_btn); row.addWidget(self.cancel_btn)
        root.addLayout(row)
        self.bar = QProgressBar(); self.bar.setFixedHeight(5); self.bar.setTextVisible(False)
        self.bar.setRange(0, 1); self.bar.setValue(0); self.bar.setVisible(False)
        root.addWidget(self.bar)
        self.table = QTableWidget(0, 5); self.table.setObjectName("makerResultsTable")
        self.table.setHorizontalHeaderLabels([self.t("country"), self.t("name"), self.t("ms"), self.t("carrier"), ""])
        self.table.verticalHeader().hide(); self.table.setShowGrid(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionMode(QAbstractItemView.NoSelection)
        hh = self.table.horizontalHeader(); hh.setSectionResizeMode(1, QHeaderView.Stretch)
        for c, wdt in ((0, 80), (2, 80), (3, 90), (4, 100)):
            hh.setSectionResizeMode(c, QHeaderView.Fixed); self.table.setColumnWidth(c, wdt)
        self.table.verticalHeader().setDefaultSectionSize(38)
        self.table.setMaximumHeight(260); self.table.setVisible(False)
        root.addWidget(self.table)
        foot = QHBoxLayout(); foot.setSpacing(8)
        self.adv_btn = QPushButton(); self.adv_btn.setObjectName("quietButton"); self.adv_btn.setCheckable(True)
        self.adv_btn.setCursor(Qt.PointingHandCursor); self.adv_btn.toggled.connect(self._toggle_classic)
        self.add_all_btn = window._action_button(S["addall"][0], S["addall"][1], "download", "secondaryAction")
        self.add_all_btn.setVisible(False); self.add_all_btn.clicked.connect(self._add_all)
        foot.addWidget(self.adv_btn); foot.addStretch(1); foot.addWidget(self.add_all_btn)
        root.addLayout(foot)
        self._update_adv_text(False)

    # -------------------------------------------------------------- helpers
    def t(self, key):
        fa, en = S[key]
        return self.w.tr(fa, en)

    def log(self, msg):
        try:
            self.w.bridge.log.emit(str(msg))
        except Exception:
            pass

    def attach_classic(self, widgets):
        self._classic = [w for w in widgets if w is not None]
        for w in self._classic:
            w.setVisible(False)

    def _update_adv_text(self, on):
        arrow = "\u25be" if on else ("\u25b8" if getattr(self.w, "language", "fa") == "en" else "\u25c2")
        self.adv_btn.setText(f"{arrow}  " + self.t("adv"))

    def _toggle_classic(self, on):
        self._update_adv_text(on)
        for w in self._classic:
            w.setVisible(bool(on))

    def _busy(self, on):
        self.find_btn.setEnabled(not on); self.cancel_btn.setEnabled(on)
        self.bar.setVisible(on)
        if on:
            self.bar.setRange(0, 0)

    # -------------------------------------------------------------- run
    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return
        w = self.w
        if getattr(w.engine, "running", False) or getattr(w, "connecting", False):
            self.status.setText(self.t("disc")); return
        if getattr(w, "_maker_tester", None) is not None:
            return
        try:
            text = w.maker_source_editor.toPlainText().strip()
        except Exception:
            text = ""
        url = w.maker_repo_url.text().strip() if hasattr(w, "maker_repo_url") else ""
        storage = w.storage
        user_carrier = storage.tuning.carrier_mode
        gene = self._current_gene()
        tunings = storage.all_carrier_tunings()
        cache = w._clean_ip_cache()
        self._cancel = threading.Event(); cancel = self._cancel
        self.table.setRowCount(0); self.table.setVisible(False); self.add_all_btn.setVisible(False)
        self._busy(True); self.status.setText(self.t("detect"))
        bridge = self.bridge; log = self.log

        def work():
            report = None; profiles = []
            try:
                info = F.detect_carrier(user_carrier)
                net = F.network_key()
                bridge.status.emit("carrier:" + info["carrier"] + ("*" if info.get("fallback") else ""), 0, 0)
                log(f"SNI FINDER: carrier detect {info}")
                bridge.status.emit("load", 0, 0)
                from .sni_maker import SniConfigMaker
                tuning = tunings.get(info["carrier"]) or storage.tuning
                maker = SniConfigMaker(fake_sni=tuning.pattern_fake_sni)
                imported = maker.import_text(text) if text else maker.import_url(url)
                profiles = maker.convert_many(imported.profiles).profiles[:MAX_CONFIGS]
                if not profiles or cancel.is_set():
                    bridge.finished.emit(F.FinderReport(carrier=info["carrier"], error="no configs" if not profiles else "cancelled"))
                    return
                report = F.run_finder(
                    profiles, tuning, carrier_info=info, network=net, gene=gene, cache=cache,
                    cancel=cancel, log=log, workers=WORKERS, timeout=12.0, top=10,
                    progress=lambda stage, a, b: bridge.status.emit(stage, a, b))
            except Exception as exc:
                log(f"SNI FINDER: failed ({type(exc).__name__}: {exc}); falling back to classic test")
                report = self._classic_fallback(profiles, storage, cancel, log, exc)
            bridge.finished.emit(report)

        self._thread = threading.Thread(target=work, name="sni-finder", daemon=True); self._thread.start()

    def _classic_fallback(self, profiles, storage, cancel, log, exc):
        report = F.FinderReport(error=f"fallback: {exc}")
        if not profiles:
            return report
        try:
            from .sni_batch import SniBatchTester
            tester = SniBatchTester(log)
            live = tester.run_all_modes(profiles, storage.tuning, cancel, workers=WORKERS, timeout=10.0,
                                        carrier_tunings=storage.all_carrier_tunings())
            res = [F.FinderResult(profile=r.profile, ok=True, edge=r.profile.address,
                                  latency_ms=float(r.ping_ms or 0), country_code=r.country_code)
                   for r in live if r.ok]
            report.results = F.rank(res, 10)
            report.profiles = [r.profile for r in report.results]
        except Exception as exc2:
            log(f"SNI FINDER: classic fallback failed too: {exc2}")
        return report

    def _current_gene(self):
        st = self.w.storage
        try:
            genes = list(st.gene_strategies or [])
            sel = str(st.selected_gene_strategy_id or "")
            gene = next((g for g in genes if str(g.get("id")) == sel), None)
            if gene is None and getattr(st, "multi_gene_enabled", False) and genes:
                gene = genes[0]
            return gene
        except Exception:
            return None

    def cancel(self):
        if self._cancel is not None:
            self._cancel.set(); self.status.setText(self.t("cancelled"))

    def shutdown(self):
        self.cancel()

    def _on_status(self, stage, a, b):
        if stage.startswith("carrier:"):
            c = stage.split(":", 1)[1]
            fallback = c.endswith("*"); c = c.rstrip("*")
            self.carrier_pill.setText(CARRIER_LABEL.get(c, c) + (" (?)" if fallback else ""))
            self.carrier_pill.setVisible(True)
            return
        if stage == "test" and b:
            self.bar.setRange(0, b); self.bar.setValue(a - 1)
            self.status.setText(f"{self.t('test')} {a}/{b}")
        elif stage in S:
            self.status.setText(self.t(stage))

    def _on_finished(self, report):
        self._busy(False); self._report = report
        if report is None:
            self.status.setText(self.t("none")); return
        carrier = CARRIER_LABEL.get(report.carrier, report.carrier)
        if self._cancel is not None and self._cancel.is_set():
            self.status.setText(self.t("cancelled"))
        else:
            self.status.setText(f"{carrier}  |  {self.t('cleanips')}: {len(report.clean_ips)}  |  "
                                f"{self.t('found')}: {len(report.profiles)}/{report.tested}"
                                + (f"  |  {self.t('err')}" if str(report.error).startswith("fallback") else ""))
        self._fill(report)

    def _fill(self, report):
        rows = list(zip(report.results, report.profiles))
        self.table.setRowCount(len(rows))
        for i, (r, p) in enumerate(rows):
            vals = [str(getattr(p, "country_code", "") or "-"), str(p.name),
                    f"{r.latency_ms:.0f} ms", CARRIER_LABEL.get(report.carrier, report.carrier)]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(v); item.setTextAlignment(Qt.AlignCenter if c != 1 else Qt.AlignVCenter | Qt.AlignLeading)
                self.table.setItem(i, c, item)
            btn = QPushButton(self.t("add")); btn.setObjectName("secondaryAction"); btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda _=False, prof=p, b=btn: self._add([prof], b))
            self.table.setCellWidget(i, 4, btn)
        self.table.setVisible(bool(rows)); self.add_all_btn.setVisible(bool(rows))
        if not rows and not (self._cancel and self._cancel.is_set()):
            self.status.setText(self.status.text() + "  |  " + self.t("none"))

    def _add(self, profiles, button=None):
        try:
            from .sni_maker import config_signature
            st = self.w.storage
            merged, added, updated, skipped = F.merge_profiles(
                st.profiles, profiles, lambda p: config_signature(p))
            st.profiles[:] = merged
            st.save_profiles()
            try:
                self.w.refresh_profiles()
            except Exception:
                pass
            self.log(f"SNI FINDER: added={added} updated={updated} untouched={skipped}")
            if button is not None:
                button.setEnabled(False)
                button.setText(self.t("added") if (added or updated) else self.t("skipped"))
        except Exception as exc:
            self.log(f"SNI FINDER: add failed: {exc}")

    def _add_all(self):
        if self._report is not None and self._report.profiles:
            self._add(list(self._report.profiles), None)
            for i in range(self.table.rowCount()):
                b = self.table.cellWidget(i, 4)
                if b is not None:
                    b.setEnabled(False); b.setText(self.t("added"))

    # -------------------------------------------------------------- revalidation
    def on_page_shown(self):
        try:
            self._start_revalidation()
        except Exception as exc:
            self.log(f"SNI FINDER: revalidation skipped: {exc}")

    def _start_revalidation(self, limit=8):
        w = self.w
        if (self._reval_thread is not None and self._reval_thread.is_alive()) or \
                (self._thread is not None and self._thread.is_alive()):
            return
        if getattr(w.engine, "running", False) or getattr(w, "connecting", False) or getattr(w, "_maker_tester", None):
            return
        candidates = [p for p in w.storage.profiles if F.is_finder_profile(p)]
        if not candidates:
            return
        storage = w.storage; log = self.log; bridge = self.bridge
        user_carrier = storage.tuning.carrier_mode; tunings = storage.all_carrier_tunings()
        gene = self._current_gene()

        def work():
            updates = []
            try:
                info = F.detect_carrier(user_carrier); carrier = info["carrier"]; net = F.network_key()
                stale = [p for p in candidates if F.is_stale(p, carrier, net)][:limit]
                if not stale:
                    return
                log(f"SNI FINDER: revalidating {len(stale)} profiles on {carrier}")
                tuning = tunings.get(carrier) or storage.tuning
                method, fake_sni, ops = F.connect_route(carrier, tuning, gene)
                from .sni_batch import SniBatchTester
                groups = {}
                for p in stale:
                    groups.setdefault(p.address, []).append(p)
                cancel = threading.Event()
                for edge, group in groups.items():
                    t = replace(tuning, carrier_mode=carrier, pattern_connect_ip=edge, pattern_fallback_ips="",
                                pattern_fake_sni=fake_sni, xray_mux_enabled=False)
                    if hasattr(t, "pattern_gene_ops"):
                        t.pattern_gene_ops = ops
                    tester = SniBatchTester(log)
                    try:
                        live = tester.run(group, t, cancel, workers=8, timeout=12.0, strategy=method,
                                          probe=F.make_probe(carrier))
                    finally:
                        tester.stop()
                    ok_ids = {r.profile.id: r for r in live if r.ok}
                    for p in group:
                        r = ok_ids.get(p.id)
                        updates.append(F.mark_revalidated(p, bool(r), float(getattr(r, "ping_ms", 0) or 0),
                                                          carrier, net))
            except Exception as exc:
                log(f"SNI FINDER: revalidation error {type(exc).__name__}: {exc}")
            finally:
                if updates:
                    bridge.revalidated.emit(updates)

        self.status.setText(self.t("reval"))
        self._reval_thread = threading.Thread(target=work, name="sni-finder-reval", daemon=True)
        self._reval_thread.start()

    def _on_revalidated(self, updates):
        try:
            st = self.w.storage
            by_id = {u.id: u for u in updates}
            changed = 0
            for i, p in enumerate(st.profiles):
                if p.id in by_id and F.is_finder_profile(p):
                    st.profiles[i] = by_id[p.id]; changed += 1
            if changed:
                st.save_profiles()
                try:
                    self.w.refresh_profiles()
                except Exception:
                    pass
            demoted = sum(1 for u in updates if u.maker_meta.get("demoted"))
            self.log(f"SNI FINDER: revalidated {changed}, demoted {demoted}")
            self.status.setText(self.t("ready"))
        except Exception as exc:
            self.log(f"SNI FINDER: revalidation apply failed: {exc}")
