"""Live Logs summary strip: every value sits under its own header (FA + EN)."""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6.QtWidgets")

from PySide6.QtCore import QPoint
from PySide6.QtWidgets import QApplication, QLabel

from uac_desktop import ui as ui_module
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
    win = ui_module.MainWindow()
    win.engine_mode = ENGINE_POW
    yield win
    win.hide()


def _centre_x(widget, root):
    return widget.mapTo(root, QPoint(0, 0)).x() + widget.width() / 2


def _visible_centre(row, value, icon, root):
    left = value.mapTo(root, QPoint(0, 0)).x()
    right = left + value.width()
    if icon.isVisible():
        il = icon.mapTo(root, QPoint(0, 0)).x()
        left, right = min(left, il), max(right, il + icon.width())
    return (left + right) / 2


@pytest.mark.parametrize("language", ["fa", "en", "fa"])
def test_summary_values_under_headers(window, language):
    window.language = language
    window._apply_language()
    window.resize(1280, 760)
    window.show()
    idx = next(i for i, b in enumerate(window.nav) if b.property("iconName") == "activity")
    window.show_page(idx)
    for line in SESSION:
        window._append_log(line)
    window._render_logs()
    QApplication.processEvents()
    window._update_log_summary()
    QApplication.processEvents()
    strip = window.log_summary
    captions = [l for l in strip.findChildren(QLabel) if l.objectName() == "logSumCaption"]
    assert len(captions) == 6
    grid = strip.layout()
    for key, (value, icon) in window._log_summary_values.items():
        row = window._log_summary_cells[key]
        r, c, _rs, _cs = grid.getItemPosition(grid.indexOf(row))
        caption = grid.itemAtPosition(0, c).widget()
        hx = _centre_x(caption, strip)
        vx = _visible_centre(row, value, icon, strip)
        assert abs(hx - vx) <= 4, (language, key, hx, vx, value.text())
        # caption cell and value cell are the same column box
        assert abs(_centre_x(row, strip) - _centre_x(caption, strip)) <= 1
    if language == "fa":
        # RTL: first column (state) is on the right side
        state_row = window._log_summary_cells["state"]
        drop_row = window._log_summary_cells["drop"]
        assert state_row.mapTo(strip, QPoint(0, 0)).x() > drop_row.mapTo(strip, QPoint(0, 0)).x()
