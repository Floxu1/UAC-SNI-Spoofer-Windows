"""Live Logs page: model-driven view, summary header, details, copy/export."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6.QtWidgets")

from PySide6.QtWidgets import QApplication

from uac_desktop import ui as ui_module
from uac_desktop.pow import config as C
from uac_desktop.pow_ui import ENGINE_POW

from test_logfmt import SESSION


@pytest.fixture(scope="module")
def app():
    yield QApplication.instance() or QApplication([])


@pytest.fixture()
def window(app, tmp_path, monkeypatch):
    from uac_desktop import paths, storage
    import uac_desktop.pow_ui as pow_ui

    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(ui_module, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(ui_module, "LOG_FILE", tmp_path / "data" / "test.log")
    monkeypatch.setattr(paths, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(pow_ui, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(storage, "SETTINGS_FILE", tmp_path / "data" / "settings.json")
    monkeypatch.setattr(ui_module.MainWindow, "_queue_target_latency_probe", lambda _window: None)
    win = ui_module.MainWindow()
    win.engine_mode = ENGINE_POW
    win.language = "en"
    win._apply_language()
    yield win
    win.shutdown()
    win._force_quit = True
    win.close()
    win.deleteLater()


def _feed(win):
    for line in SESSION:
        win._append_log(line, ENGINE_POW)
    win._render_logs()


def test_view_is_grouped_and_collapsed(window):
    _feed(window)
    text = window.logs.toPlainText()
    assert "Connected: Psiphon over MASQUE" in text
    assert "Probing Cloudflare addresses for a clean IP" in text and "×13" in text
    assert "Scan 162.159.199.3:443 trying" not in text
    assert "CLEAN-IP SCAN" in text and "CONNECTED" in text
    window.log_details.setChecked(True)
    assert "Scan 162.159.199.3:443 trying" in window.logs.toPlainText()


def test_summary_header(window):
    _feed(window)
    window._update_log_summary()
    values = {k: v[0].text() for k, v in window._log_summary_values.items()}
    assert values["state"] == "Connected"
    assert values["route"] == "Psiphon over MASQUE"
    assert values["exit"] == "172.105.251.210"
    assert values["parallel"] == "3 sessions"
    assert not window._log_summary_values["exit"][1].isHidden()
    window._append_log("UAC PoW path lost: outer leg exited", ENGINE_POW)
    window._update_log_summary()
    assert window._log_summary_values["state"][0].text() == "Dropped"
    assert "outer leg exited" in window._log_summary_values["drop"][0].toolTip()


def test_copy_export_clear(window, tmp_path):
    _feed(window)
    window._copy_logs()
    copied = QApplication.clipboard().text()
    assert "Connected: Psiphon over MASQUE" in copied and "PARALLEL" in copied
    out = tmp_path / "export.txt"
    window._write_log_export(out)
    body = out.read_text(encoding="utf-8")
    assert "readable view" in body and "---- raw lines ----" in body and "Scan 162.159.199.3:443 trying" in body
    window.logs_clear()
    assert window.log_model.entries == [] or all("cleared" in e.raw.lower() for e in window.log_model.entries)


def test_autoscroll_pauses_when_scrolled_up(window):
    window.resize(1080, 700)
    window.show()
    idx = next(i for i, b in enumerate(window.nav) if b.property("iconName") == "activity")
    window.show_page(idx)
    QApplication.processEvents()
    for i in range(300):
        window._append_log(f"Network: line {i}")
    window._render_logs()
    bar = window.logs.verticalScrollBar()
    assert bar.maximum() > 0 and bar.value() == bar.maximum()
    bar.setValue(0)
    window._append_log("Psiphon connected via F")
    window._render_logs()
    assert bar.value() == 0 and not window.log_jump.isHidden()
    window._jump_to_latest()
    assert bar.value() == bar.maximum()


def test_setting_change_is_logged(window):
    window._pow_setting(parallel_masque=True)
    assert any(e.raw == "Setting changed: Parallel MASQUE on" for e in window.log_model.entries)


def test_persian_view(window):
    window.language = "fa"
    window._apply_language()
    _feed(window)
    html = window.logs.toHtml()
    assert "وصل شد" in window.logs.toPlainText()
    assert "162.159.199.95:443" in window.logs.toPlainText()


def test_toolbar_is_one_compact_segmented_group(window):
    from uac_desktop.log_panel import LogToolButton

    window.resize(1080, 700); window.show(); QApplication.processEvents()
    group = window.log_tools
    buttons = group.findChildren(LogToolButton)
    assert [b.accessibleName() for b in buttons] == ["Jump to latest", "Copy", "Export to file…", "Clear"]
    assert group.height() == 30 and window.log_filter.height() == 30
    assert [b.objectName() for b in buttons].count("logToolButtonDanger") == 1
    assert all(b.toolTip() for b in buttons) and all(not b.text() for b in buttons)
    # Filter, toggles and the group share one vertical centre line.
    centre = lambda w: w.mapTo(window, w.rect().center()).y()
    assert abs(centre(group) - centre(window.log_filter)) <= 1
    assert abs(centre(group) - centre(window.log_details)) <= 2
