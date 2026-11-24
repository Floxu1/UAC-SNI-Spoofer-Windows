"""Settings → Advanced → Gene Lab: toggles sit exactly like the stream-optimization row.

Each section has its own label-column width, so positions are compared as the
offset from the start edge of the section's field column (right edge in RTL,
left edge in LTR).
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6.QtWidgets")

from PySide6.QtCore import QPoint
from PySide6.QtWidgets import QApplication

from uac_desktop import fonts as ui_fonts
from uac_desktop import ui as ui_module
from uac_desktop.models import Tuning


@pytest.fixture(scope="module")
def app():
    application = QApplication.instance() or QApplication([])
    ui_fonts.load_fonts()
    yield application


def _span(widget, dialog):
    left = widget.mapTo(dialog, QPoint(0, 0)).x()
    return left, left + widget.width()


def _start_offset(toggle, field, dialog, rtl):
    t_left, t_right = _span(toggle, dialog)
    f_left, f_right = _span(field, dialog)
    return (f_right - t_right) if rtl else (t_left - f_left)


@pytest.mark.parametrize("language", ["fa", "en"])
def test_gene_toggles_align_with_stream_optimization(app, language):
    ui_fonts.apply_app_font(app, language)
    dialog = ui_module.TuningDialog(None, Tuning.carrier_preset("auto"), language,
                                    multi_gene_enabled=True, strategy_locked=True,
                                    multi_gene_status="status")
    dialog.resize(820, 760)
    dialog.advanced_toggle.setChecked(True)
    dialog.show()
    app.processEvents()
    rtl = language == "fa"
    try:
        ref = _start_offset(dialog.upload_optimized, dialog.keepalive_count, dialog, rtl)
        for toggle, anchor in ((dialog.strategy_lock, dialog.gene_import_btn), (dialog.multi_gene, dialog.gene_combo)):
            assert toggle.isVisible()
            assert abs(_start_offset(toggle, anchor, dialog, rtl) - ref) <= 2
            assert toggle.size() == dialog.upload_optimized.size()
        assert abs(_span(dialog.upload_optimized, dialog)[0] - _span(dialog.strategy_lock, dialog)[0]) <= 2
    finally:
        dialog.close()
