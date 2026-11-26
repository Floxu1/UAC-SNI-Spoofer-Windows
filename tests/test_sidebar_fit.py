"""Sidebar: nav rows, star card and footer never overlap at any size."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6.QtWidgets")

from PySide6.QtWidgets import QApplication

from uac_desktop import ui as ui_module
from uac_desktop.pow_ui import ENGINE_POW, ENGINE_XRAY


@pytest.fixture(scope="module")
def app():
    yield QApplication.instance() or QApplication([])


@pytest.fixture(scope="module")
def window(app, tmp_path_factory):
    from uac_desktop import paths, storage
    import uac_desktop.pow_ui as pow_ui

    data = tmp_path_factory.mktemp("sidebar")
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(ui_module, "DATA_DIR", data)
        patch.setattr(ui_module, "LOG_FILE", data / "test.log")
        patch.setattr(paths, "DATA_DIR", data)
        patch.setattr(pow_ui, "DATA_DIR", data)
        patch.setattr(storage, "SETTINGS_FILE", data / "settings.json")
        win = ui_module.MainWindow()
        yield win
        win.shutdown()
        win._force_quit = True
        win.close()
        win.deleteLater()


def sidebar_overlaps(win):
    """List of problems: overlapping or out-of-bounds sidebar blocks."""
    side = win.sidebar
    blocks = [("logo", win.logo_card)]
    blocks += [(b.text(), b) for b in win.nav if b.isVisible()]
    if win.rating_card.isVisible():
        blocks.append(("rating", win.rating_card))
    blocks.append(("footer", win.sidebar_footer))
    rects = sorted(((name, w.geometry()) for name, w in blocks), key=lambda pair: pair[1].top())
    problems = []
    if side.layout().minimumSize().height() > side.height():
        problems.append(f"sidebar needs {side.layout().minimumSize().height()}px, has {side.height()}")
    for (name_a, a), (name_b, b) in zip(rects, rects[1:]):
        if a.bottom() >= b.top():
            problems.append(f"{name_a} overlaps {name_b} ({a.bottom()} >= {b.top()})")
    for name, rect in rects:
        if rect.top() < 0 or rect.bottom() > side.height():
            problems.append(f"{name} outside sidebar ({rect.top()}..{rect.bottom()} of {side.height()})")
    if win.rating_card.isVisible():
        inner = win.rating_card
        for child in (win.rating_title, win.rating_button):
            if child.geometry().bottom() > inner.height():
                problems.append("star card content clipped")
    return problems


@pytest.mark.parametrize("engine", [ENGINE_XRAY, ENGINE_POW, "direct"])
@pytest.mark.parametrize("language", ["en", "fa"])
@pytest.mark.parametrize("size", [(1080, 700), (1280, 800), (1440, 900), (1600, 960), (1920, 1040), (1920, 1200)])
def test_sidebar_never_overlaps(window, engine, language, size):
    window.language = language
    window._apply_language()
    window.engine_buttons[engine].click()
    window.resize(*size)
    window.show()
    for _ in range(5):
        QApplication.processEvents()
    # The window must not have grown to make room (a maximised window cannot).
    assert window.height() == size[1]
    assert window.sidebar.minimumSizeHint().height() <= window.sidebar.height()
    sidebar, content = window.sidebar.geometry(), window.content_shell.geometry()
    if language == "en":
        assert sidebar.left() == 0 and sidebar.right() + 1 == content.left()
    else:
        assert content.left() == 0 and content.right() + 1 == sidebar.left()
    assert sidebar_overlaps(window) == []
    if engine == ENGINE_XRAY:
        rows = sorted(
            (button for button in window.nav if button.isVisible()),
            key=lambda button: button.y(),
        )
        assert [row.property("iconName") for row in rows] == [
            "home", "file-cog", "sparkles", "flask", "activity", "shield", "wrench",
            "settings", "xray-settings", "headphones",
        ]
        assert all(row.size() == rows[0].size() and row.iconSize() == rows[0].iconSize() for row in rows)
        assert len({bottom.y() - top.y() for top, bottom in zip(rows, rows[1:])}) == 1
        assert all(row.menu() is None for row in rows)


def test_star_card_shows_when_there_is_room(window):
    window.language = "en"; window._apply_language()
    window.engine_buttons[ENGINE_POW].click()
    window.resize(1920, 1040); window.show()
    for _ in range(5):
        QApplication.processEvents()
    assert window.rating_card.isVisible() and window.rating_text.isVisible()
    window.resize(1080, 700)
    for _ in range(5):
        QApplication.processEvents()
    assert sidebar_overlaps(window) == []


@pytest.mark.parametrize("engine", [ENGINE_XRAY, ENGINE_POW, "direct"])
@pytest.mark.parametrize("language", ["en", "fa"])
def test_dashboard_keeps_bounds_during_connection_activity(window, engine, language, monkeypatch):
    monkeypatch.setattr(ui_module, "_animations_enabled", lambda: False)
    monkeypatch.setattr(window, "_schedule_ip_refresh", lambda *_: None)
    monkeypatch.setattr(window, "_queue_target_latency_probe", lambda: None)
    window.language = language
    window._apply_language()
    window.engine_buttons[engine].click()
    window.show_page(0)
    window.show()
    assert window.engine_mode == engine

    error = "اتصال ناموفق بود / Connection failed\n" + "x" * 3000 + "\nNetwork probe timed out." * 60
    for size in ((1080, 700), (1440, 900), (1600, 960)):
        window.resize(*size)
        page = window.home_page
        body = page.widget()
        panels = [window.home_root.itemAt(i).widget() for i in range(window.home_root.count())]
        controls = (window.status_pill, window.wizard_restart_btn, window.orb_shell,
                    window.connect_button, window.activity_bar.indicator, window.activity_bar.message)
        baseline = None
        for visual, state, message in (
            ("disconnected", "idle", ""),
            ("connecting", "running", "Connecting…"),
            ("connected", "success", "Connected"),
            ("connecting", "running", "Reconnecting…"),
            ("error", "error", error),
        ):
            window._set_connection_visual(visual)
            if visual == "error":
                window.connecting = True
                window._handle_error(message)
            else:
                window.activity_bar.set_activity(message, state, state == "running")
            for _ in range(3):
                QApplication.processEvents()

            assert (window.width(), window.height()) == size
            assert body.width() == page.viewport().width()
            assert page.horizontalScrollBar().maximum() == 0
            assert all(panel.x() >= 0 and panel.geometry().right() < body.width() for panel in panels)
            geometry = [widget.geometry() for widget in (*panels, *controls) if widget.isVisible()]
            if baseline is None:
                baseline = geometry
            assert geometry == baseline
            if window.wizard_restart_btn.isVisible():
                assert window.wizard_restart_btn.parentWidget().rect().contains(window.wizard_restart_btn.geometry())
            if visual == "error":
                activity = window.activity_bar.message
                assert "…" in activity.text() and "\n" not in activity.text()
                assert "x" * 3000 in activity.toolTip()
                assert any(entry.engine == engine and error in entry.raw for entry in window.log_model.entries)
                assert window.centralWidget().rect().contains(window._toast.geometry())
                window._toast.hide()
        window.connection_error = ""
