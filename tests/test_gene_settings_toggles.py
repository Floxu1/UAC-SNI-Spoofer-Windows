"""Check the shared trailing control lane in each Xray settings tab."""
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


@pytest.mark.parametrize("language", ["fa", "en"])
def test_gene_toggles_align_with_stream_optimization(app, language):
    ui_fonts.apply_app_font(app, language)
    page = ui_module.XraySettingsPage(None, Tuning.carrier_preset("auto"), language,
                                     multi_gene_enabled=True, strategy_locked=True,
                                     multi_gene_status="status")
    page.resize(820, 760)
    page.show()
    try:
        offsets = []
        for index, toggle in ((0, page.multi_gene), (1, page.upload_optimized), (2, page.strategy_lock)):
            page.tabs.setCurrentIndex(index)
            app.processEvents()
            assert toggle.isVisible()
            assert toggle.size() == page.upload_optimized.size()
            row = toggle.parentWidget()
            x = toggle.mapTo(row, QPoint()).x()
            offsets.append(x if language == "fa" else row.width() - x - toggle.width())
        assert max(offsets) - min(offsets) <= 2
    finally:
        page.close()
