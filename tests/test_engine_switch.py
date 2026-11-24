"""Engine switch: fast restyle, animated pill/cross-fade, re-entrancy guard."""

from __future__ import annotations

import json
import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6.QtWidgets")

from PySide6.QtWidgets import QApplication, QWidget

from uac_desktop import engine_switch as es
from uac_desktop import ui as ui_module
from uac_desktop.pow_ui import ENGINE_POW, ENGINE_XRAY

# Generous default so slow CI boxes pass; the real number is printed.
STALL_LIMIT_MS = float(os.environ.get("UAC_SWITCH_STALL_LIMIT_MS", "150"))


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
    settings_path = tmp_path / "data" / "settings.json"
    settings_path.write_text(json.dumps({
        "engine_mode": ENGINE_XRAY,
        ui_module.ENGINE_DEFAULT_MARKER: True,
    }), encoding="utf-8")
    monkeypatch.setattr(storage, "SETTINGS_FILE", settings_path)
    app.setStyleSheet(ui_module.STYLE)
    win = ui_module.MainWindow()
    win.language = "en"
    win._apply_language()
    win.resize(1280, 800)
    win.show()
    pump(app, 0.2)
    yield win
    win.shutdown()
    win._force_quit = True
    win.close()
    win.deleteLater()


def pump(app, seconds):
    end = time.perf_counter() + seconds
    while time.perf_counter() < end:
        app.processEvents()
        time.sleep(0.005)


def wait_switch_done(app, win, timeout=3.0):
    end = time.perf_counter() + timeout
    while win._engine_switching and time.perf_counter() < end:
        app.processEvents()
        time.sleep(0.005)
    assert not win._engine_switching, "switch animation never finished"


def test_combined_sheet_scopes_every_rule_per_engine():
    xray = "QWidget { color: red; }\nQPushButton#a, QLabel#b:hover { color: blue; }\nQToolTip { color: white; }"
    pow_ = xray.replace("blue", "green")
    sheet = es.combine_styles({"xray": xray, "pow": pow_})
    rules = es.parse_rules(sheet)
    # unscoped tooltip fallback + 3 rules per engine
    assert len(rules) == 1 + 3 + 3
    assert rules[0][0] == "QToolTip"
    for selector, _body in rules[1:]:
        for part in es._split_selectors(selector):
            assert part.startswith('QMainWindow[engine="xray"]') or part.startswith('QMainWindow[engine="pow"]')
    # simple selectors can also style the window itself
    assert 'QMainWindow[engine="pow"] QWidget, QMainWindow[engine="pow"] { color: red; }' in sheet
    assert 'QMainWindow[engine="pow"] QPushButton#a, QMainWindow[engine="pow"] QLabel#b:hover { color: green; }' in sheet


def test_app_sheet_installed_once_and_switch_only_flips_property(app, window):
    sheet = app.styleSheet()
    assert sheet == ui_module.combined_app_style("en")
    assert window.property("engine") == window.engine_mode == ENGINE_XRAY
    window._switch_engine()
    wait_switch_done(app, window)
    assert window.engine_mode == ENGINE_POW
    assert window.property("engine") == ENGINE_POW
    assert app.styleSheet() is sheet or app.styleSheet() == sheet  # never replaced on a switch
    window._switch_engine()
    wait_switch_done(app, window)
    assert window.engine_mode == ENGINE_XRAY and window.property("engine") == ENGINE_XRAY


def test_instant_switch_when_motion_disabled(app, window, monkeypatch):
    monkeypatch.setattr(ui_module, "_animations_enabled", lambda: False)
    window._switch_engine()
    # completes synchronously: no overlay, no pending animation
    assert window.engine_mode == ENGINE_POW
    assert not window._engine_switching and window._engine_switch_anim is None
    assert not window.findChildren(es.SwitchOverlay)
    assert window.engine_buttons[ENGINE_POW].isChecked()
    thumb = window.engine_thumb
    assert thumb.geometry() == window.engine_buttons[ENGINE_POW].geometry()
    stats = window._engine_switch_stats
    print(f"instant switch blocking {stats['blocking_ms']:.0f} ms")
    assert stats["blocking_ms"] < STALL_LIMIT_MS * 2


def test_animated_switch_completes_and_ignores_clicks_mid_animation(app, window, monkeypatch):
    monkeypatch.setattr(ui_module, "_animations_enabled", lambda: True)
    start = window.engine_mode
    window._switch_engine()
    assert window._engine_switching
    assert window.findChildren(es.SwitchOverlay), "snapshot overlay missing"
    # Clicking again (either control) mid-animation must not switch back.
    window._switch_engine()
    window._engine_option_clicked(start)
    window.engine_buttons[start].click()
    assert window.engine_mode != start
    # The visible pill keeps showing the old engine until the slide is half way.
    assert window.engine_buttons[start].isChecked()
    pump(app, 0.05)
    window._engine_option_clicked(start)
    wait_switch_done(app, window)
    pump(app, 0.05)
    target = ENGINE_POW if start == ENGINE_XRAY else ENGINE_XRAY
    assert window.engine_mode == target
    assert window.engine_buttons[target].isChecked() and not window.engine_buttons[start].isChecked()
    assert window.engine_thumb.geometry() == window.engine_buttons[target].geometry()
    assert not [o for o in window.findChildren(es.SwitchOverlay) if o.isVisible()]
    stats = window._engine_switch_stats
    print("animated switch: first %.0f ms, second %.0f ms, total %.0f ms" % (stats["first_ms"], stats["second_ms"], stats["total_ms"]))
    assert stats["total_ms"] < 1500
    # Each UI-thread slice of the switch stays short (heavy restyle is gone).
    assert stats["first_ms"] < STALL_LIMIT_MS and stats["second_ms"] < STALL_LIMIT_MS
    # Clicking works again afterwards.
    window._engine_option_clicked(start)
    wait_switch_done(app, window)
    assert window.engine_mode == start


def test_hidden_pages_restyled_lazily_then_on_show(app, window, monkeypatch):
    monkeypatch.setattr(ui_module, "_animations_enabled", lambda: False)
    window._switch_engine()
    assert window._stale_pages, "hidden pages should be deferred"
    page = next(iter(window._stale_pages))
    index = window.stack.indexOf(page)
    window._freshen_page(page)
    assert page not in window._stale_pages
    pump(app, 1.5)
    assert not window._stale_pages, "idle restyle should finish all pages"
    assert index >= 0


def test_switch_restyle_matches_a_fresh_style(app, window, monkeypatch):
    """A widget restyled by the switch looks like one polished from scratch."""
    monkeypatch.setattr(ui_module, "_animations_enabled", lambda: False)
    window._switch_engine()
    pump(app, 1.5)
    button = window.connect_button
    before = button.palette().color(button.backgroundRole()).name(), button.font().pointSizeF()
    fresh = type(button)(button.text(), button.parentWidget())
    fresh.setObjectName(button.objectName())
    for name in button.dynamicPropertyNames():
        fresh.setProperty(bytes(name).decode(), button.property(bytes(name).decode()))
    fresh.ensurePolished()
    after = fresh.palette().color(fresh.backgroundRole()).name(), fresh.font().pointSizeF()
    fresh.deleteLater()
    assert before == after


def test_cached_icon_art_keeps_retheme_metadata():
    ui_module._theme.set_pow(False)
    try:
        a = ui_module.cyber_icon("home", "#23f5e0", 22)
        b = ui_module.cyber_icon("home", "#23f5e0", 22)
        assert a.cacheKey() == b.cacheKey()
        assert ui_module._THEMED_ART[("i", a.cacheKey())] == ("home", "#23f5e0", 22)
        ui_module._theme.set_pow(True)
        c = ui_module.cyber_icon("home", "#23f5e0", 22)
        assert c.cacheKey() != a.cacheKey()
        assert ui_module._THEMED_ART[("i", c.cacheKey())] == ("home", "#23f5e0", 22)
    finally:
        ui_module._theme.set_pow(False)
