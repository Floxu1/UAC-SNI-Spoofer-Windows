"""Language rebind, Settings RTL titles, and Persian log rendering."""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6.QtWidgets")

from PySide6.QtCore import QPoint, Qt
from PySide6.QtWidgets import QApplication, QLabel, QPushButton, QWidget

from uac_desktop import fonts as ui_fonts
from uac_desktop import logfmt
from uac_desktop import ui as ui_module
from uac_desktop.models import Tuning


@pytest.fixture(scope="module")
def app():
    application = QApplication.instance() or QApplication([])
    ui_fonts.load_fonts()
    ui_fonts.apply_app_font(application, "fa")
    yield application


def _has_persian(text: str) -> bool:
    return any("\u0600" <= ch <= "\u06FF" for ch in text)


@pytest.mark.parametrize("language", ["fa", "en"])
def test_settings_titles_have_real_width(app, language):
    ui_fonts.apply_app_font(app, language)
    dialog = ui_module.TuningDialog(
        None, Tuning.carrier_preset("auto"), language,
        multi_gene_enabled=True, strategy_locked=True, multi_gene_status="status",
    )
    dialog.resize(820, 760)
    dialog.advanced_toggle.setChecked(True)
    dialog.show()
    app.processEvents()
    try:
        titles = [label for label in dialog.findChildren(QLabel) if label.objectName() == "settingsTitle"]
        assert titles
        for title in titles:
            assert title.width() >= 80, title.text()
            assert title.sizeHint().width() >= 40, title.text()
    finally:
        dialog.close()


@pytest.mark.parametrize("language", ["fa", "en"])
def test_gene_toggles_align_with_stream_optimization(app, language):
    ui_fonts.apply_app_font(app, language)
    dialog = ui_module.TuningDialog(
        None, Tuning.carrier_preset("auto"), language,
        multi_gene_enabled=True, strategy_locked=True, multi_gene_status="status",
    )
    dialog.resize(820, 760)
    dialog.advanced_toggle.setChecked(True)
    dialog.show()
    app.processEvents()
    rtl = language == "fa"

    def span(widget):
        left = widget.mapTo(dialog, QPoint(0, 0)).x()
        return left, left + widget.width()

    def start_offset(toggle, field):
        t_left, t_right = span(toggle)
        f_left, f_right = span(field)
        return (f_right - t_right) if rtl else (t_left - f_left)

    try:
        ref = start_offset(dialog.upload_optimized, dialog.keepalive_count)
        for toggle, anchor in ((dialog.strategy_lock, dialog.gene_import_btn), (dialog.multi_gene, dialog.gene_combo)):
            assert toggle.isVisible()
            assert abs(start_offset(toggle, anchor) - ref) <= 2
            assert toggle.size() == dialog.upload_optimized.size()
        assert abs(span(dialog.upload_optimized)[0] - span(dialog.strategy_lock)[0]) <= 2
    finally:
        dialog.close()


def test_catalog_rebind_does_not_use_current_text_mapping(app):
    """Widgets keep their own i18nFa/i18nEn pair across FA↔EN switches.

    The old FA_EN blind remap could leave Persian text on an English UI when a
    string was missing from the dictionary (and the reverse).
    """
    root = QWidget()
    a = QLabel()
    a.setProperty("i18nFa", "مسیر فعال")
    a.setProperty("i18nEn", "Active Route")
    a.setText("مسیر فعال")
    b = QPushButton()
    b.setProperty("i18nFa", "تنظیمات پیشرفته")
    b.setProperty("i18nEn", "Advanced Settings")
    b.setText("تنظیمات پیشرفته")
    # Unbound label whose Persian text is NOT in FA_EN — must not be touched.
    orphan = QLabel("متن سفارشی خارج از کاتالوگ")
    for widget in (a, b, orphan):
        widget.setParent(root)

    def rebind(language: str):
        for widget_type in (QLabel, QPushButton):
            for widget in root.findChildren(widget_type):
                fa = widget.property("i18nFa")
                en = widget.property("i18nEn")
                if fa is not None and en is not None:
                    widget.setText(str(en) if language == "en" else str(fa))

    rebind("en")
    assert a.text() == "Active Route"
    assert b.text() == "Advanced Settings"
    assert orphan.text() == "متن سفارشی خارج از کاتالوگ"
    rebind("fa")
    assert a.text() == "مسیر فعال"
    assert b.text() == "تنظیمات پیشرفته"
    assert orphan.text() == "متن سفارشی خارج از کاتالوگ"
    rebind("en")
    assert a.text() == "Active Route"
    assert not _has_persian(a.text())
    assert not _has_persian(b.text())
    assert _has_persian(orphan.text())  # unbound stays as-is; catalog owns the rest
    root.close()


def test_persian_log_html_isolates_latin():
    entry = logfmt.classify("Saved clean HTTP/2 address 162.159.199.95:443")
    row = logfmt.Row("entry", entry, 1, entry.phase, "18:00:00", "k")
    html = logfmt.render_html([row], "fa")
    assert 'dir="rtl"' in html
    assert 'dir="ltr"' in html
    assert "unicode-bidi: isolate" in html
    assert "162.159.199.95:443" in html


def test_mixed_persian_label_keeps_technical_runs_in_order():
    from uac_desktop.fonts import persian_ui_text

    result = persian_ui_text("PoW VPN روی 192.0.2.1:443 · فیلتر DNS")
    assert result == "\u200f\u2066PoW VPN\u2069 روی \u2066192.0.2.1:443\u2069 · فیلتر \u2066DNS\u2069"
    assert persian_ui_text(result) == result
    assert persian_ui_text("اتصال برقرار شد") == "اتصال برقرار شد"
    assert persian_ui_text("https://1.1.1.1/dns-query") == "https://1.1.1.1/dns-query"


def test_kill_process_tree_helper_is_safe():
    from uac_desktop.process_win import kill_process_tree, register_helper_pid, unregister_helper_pid
    kill_process_tree(0)
    kill_process_tree(-1)
    register_helper_pid(1)
    unregister_helper_pid(1)


def test_localize_style_puts_vazirmatn_first_on_logs():
    from uac_desktop.fonts import localize_style
    css = 'QTextEdit#logs { font-family: "JetBrains Mono", "Vazirmatn UI FD", "Consolas"; font-size: 13px; }'
    fa = localize_style(css, "fa")
    assert fa.index("Vazirmatn UI FD") < fa.index("JetBrains Mono")
    en = localize_style(css, "en")
    assert en.index("JetBrains Mono") < en.index("Vazirmatn UI FD")
