"""Desktop PoW UI wiring — engine switch, nav page, toggle dispatch.

Runs offscreen (no event loop exec: timers never fire, no network).
"""

from __future__ import annotations

import json
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6.QtWidgets")

from PySide6.QtCore import QEvent
from PySide6.QtWidgets import QApplication

from uac_desktop import ui as ui_module
from uac_desktop.pow_ui import ENGINE_POW, ENGINE_XRAY


@pytest.fixture(scope="module")
def app():
    instance = QApplication.instance() or QApplication([])
    yield instance


@pytest.fixture()
def window(app, tmp_path, monkeypatch):
    monkeypatch.setattr(ui_module, "DATA_DIR", tmp_path / "data")
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    from uac_desktop import paths, storage
    import uac_desktop.pow_ui as pow_ui

    monkeypatch.setattr(paths, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(pow_ui, "DATA_DIR", tmp_path / "data")
    settings = tmp_path / "data" / "settings.json"
    settings.write_text(json.dumps({
        "engine_mode": ENGINE_XRAY, ui_module.ENGINE_DEFAULT_MARKER: True,
    }), encoding="utf-8")
    monkeypatch.setattr(storage, "SETTINGS_FILE", settings)
    monkeypatch.setattr(ui_module.MainWindow, "_queue_target_latency_probe", lambda _window: None)
    win = ui_module.MainWindow()
    yield win
    win.shutdown()
    win._force_quit = True
    win.close()
    win.deleteLater()


def _visible_icons(window):
    return [button.property("iconName") for button in window.nav if not button.isHidden()]


def test_xray_sidebar_opens_individual_pages(window, monkeypatch):
    assert window.engine_mode == ENGINE_XRAY
    visible = _visible_icons(window)
    assert visible == [
        "home", "file-cog", "sparkles", "flask", "activity", "shield", "wrench", "headphones", "settings",
    ]
    for index, page in ((1, "configsPage"), (2, "sniMakerPage"), (3, "sniLabPage"), (6, "toolsPage")):
        window.nav[index].click()
        assert window.stack.currentWidget().objectName() == page
        assert window.nav[index].isChecked()
    opened = []
    monkeypatch.setattr(ui_module.TuningDialog, "exec", lambda dialog: opened.append(dialog) or 0)
    window.xray_settings_button.click()
    assert len(opened) == 1
    assert window.nav[6].isChecked()
    window.nav[0].click()
    assert window.stack.currentWidget().objectName() == "homePage"


def test_pow_home_uses_connection_center_for_this_engine(window):
    window.language = "en"
    window._switch_engine()
    assert window.engine_mode == ENGINE_POW
    assert window.stack.currentWidget().objectName() == "homePage"
    assert window.country_card.isHidden() is False
    assert window.quick_controls.isHidden() is False
    assert window.connect_button.isHidden() is False
    from PySide6.QtWidgets import QLabel
    subtitle = window.home_header.findChild(QLabel, "pageSubtitle")
    assert "WARP" in subtitle.text()
    assert window._option_label(window.auto_option).text() == "Psiphon over WARP"
    # One exit control on PoW: the selector button, no tabs/count/second label.
    assert window.pow_country_button.isHidden() is False
    assert window.route_source_tabs.isHidden() is True
    assert window.country_count.isHidden() is True
    assert window.original_configs_label.isHidden() is True
    assert window.pow_country_button.title_label.text() == "Automatic"
    assert window.manual_option.isHidden() is True  # Optimized moved to Settings
    assert "nearby country first" in window.country_description.text()
    visible = _visible_icons(window)
    assert set(visible) == {"home", "activity", "shield", "headphones", "settings", "pow-settings"}
    home = next(button for button in window.nav if button.property("iconName") == "home")
    assert home.isChecked()
    window.show_page(next(
        index for index, button in enumerate(window.nav)
        if button.property("iconName") == "activity"
    ))
    assert window.stack.currentWidget().objectName() == "liveLogsPage"
    window.show_page(0)
    assert window.stack.currentWidget().objectName() == "homePage"
    window.auto_mode.setChecked(False)
    assert window.pow_controller.store.snapshot().chain_psiphon is False
    window._switch_engine()
    assert window.engine_mode == ENGINE_XRAY
    assert window.stack.currentWidget().objectName() == "homePage"
    assert "Xray" in window.home_header.findChild(QLabel, "pageSubtitle").text()
    assert window.nav[6].isHidden() is False
    assert window.route_source_tabs.tabText(0) == "Suggested"
    assert window.route_source_tabs.isHidden() is False
    assert window.pow_country_button.isHidden() is True
    assert window.manual_option.isHidden() is False


def test_connected_phase_replaces_connecting_activity(window):
    from uac_desktop.pow.status import PowPhase, PowUiStatus

    window._switch_engine()
    window.language = "en"
    window._set_activity("در حال اتصال UAC PoW…", "Connecting UAC PoW…")
    snapshot = PowUiStatus(phase=PowPhase.CONNECTED, progress=100, detail="UAC PoW ready")
    window.pow_controller._activity_kind = "progress"
    window.pow_controller._render_connected(snapshot)
    assert window.activity_bar.message.text() == "Secure PoW connection established."
    assert window.activity_bar.busy is False
    window._switch_engine()


def test_logo_badge_matches_engine(window):
    assert window.engine_mode == ENGINE_XRAY
    assert "XRAY" in window.engine_badge.text()


def test_logo_click_switches_engine(window):
    release = QEvent(QEvent.Type.MouseButtonRelease)
    assert window.eventFilter(window.logo_card, release) is True
    assert window.engine_mode == ENGINE_POW
    assert "POW" in window.engine_badge.text().upper()
    assert window.stack.currentWidget().objectName() == "homePage"
    window._switch_engine()
    assert window.engine_mode == ENGINE_XRAY
    assert window.stack.currentWidget().objectName() == "homePage"


def test_toggle_dispatches_to_pow_when_pow_engine(window, monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(
        window.pow_controller, "toggle", lambda: calls.append("pow-toggle"))
    window.engine_mode = ENGINE_POW
    window.connecting = False
    window.toggle_connection()
    assert calls == ["pow-toggle"]
    window.engine_mode = ENGINE_XRAY


def test_toggle_routes_to_pow_while_pow_busy(window, monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(
        window.pow_controller, "toggle", lambda: calls.append("pow-toggle"))
    monkeypatch.setattr(
        type(window.pow_controller), "busy", property(lambda self: True))
    window.engine_mode = ENGINE_XRAY
    window.connecting = False
    window.toggle_connection()
    assert calls == ["pow-toggle"]


def test_pow_settings_roundtrip_through_widgets(window):
    from dataclasses import replace

    controller = window.pow_controller
    window.engine_buttons[ENGINE_POW].click()

    # Home-owned values written first; the dialog must never overwrite them.
    controller.store.save(replace(
        controller.store.snapshot(),
        exit_mode="warp", optimized_mode=True, firewall_profile="mci",
        exit_country_code="nl", h2_fragmentation=True,
    ))
    window.nav[window.POW_SETTINGS_PAGE].click()
    assert window.stack.currentWidget().objectName() == "powSettingsPage"

    def _set(combo, key: str) -> None:
        for index in range(combo.count()):
            if str(combo.itemData(index) or "") == key:
                combo.setCurrentIndex(index)
                return
        raise AssertionError(f"missing option {key}")

    # Duplicates of Home controls are gone from the dialog.
    for name in ("country_combo", "chain_toggle",
                 "h2_toggle", "proxy_toggle", "tun_toggle"):
        assert getattr(controller, name) is None, name
    _set(controller.transport_combo, "masque")
    _set(controller.scan_combo, "turbo")
    _set(controller.recipe_combo, "warp-any")
    _set(controller.key_fetch_combo, "fragment")
    _set(controller.obfuscation_combo, "light")
    saved = controller.store.snapshot()
    assert saved.outer_transport == "masque"
    assert saved.scan_mode == "turbo"
    assert saved.link_recipe == "warp-any"
    assert saved.key_fetch == "fragment"
    assert saved.obfuscation_profile == "light"
    assert saved.firewall_profile == "mci"
    assert saved.chain_psiphon is False
    assert saved.optimized_mode is True
    # Optimized now lives in the dialog as a switch row.
    assert controller.optimized_toggle.isChecked() is True
    controller.optimized_toggle.setChecked(False)
    assert controller.store.snapshot().optimized_mode is False
    assert controller.store.snapshot().firewall_profile == "mci"
    assert saved.exit_country_code == "nl"
    assert saved.h2_fragmentation is True


def test_pow_country_picker_single_control(window):
    from PySide6.QtCore import Qt
    from uac_desktop.pow.regions import ALL_NAMES
    from uac_desktop.pow_ui import PowCountryPicker

    window.language = "en"
    picker = PowCountryPicker(window, "de", "NL")
    assert picker.list.count() == len(ALL_NAMES) + 1
    first = picker.list.item(0)
    assert first.data(Qt.UserRole) == ""
    assert first.text().startswith("Automatic (fastest nearby)")
    assert "Netherlands (NL)" in first.text()
    assert picker.list.currentItem().data(Qt.UserRole) == "de"
    picker.search.setText("germ")
    visible = [picker.list.item(i) for i in range(picker.list.count()) if not picker.list.item(i).isHidden()]
    assert [item.data(Qt.UserRole) for item in visible] == ["de"]
    picker._choose(visible[0])
    assert picker.selected_code == "de"


def test_pow_home_country_button_reflects_store(window):
    window.language = "en"
    window._switch_engine()
    controller = window.pow_controller
    window._pow_setting(exit_country_code="se")
    window._update_pow_country_selector()
    assert window.pow_country_button.title_label.text() == "Sweden"
    assert "SE" in window.pow_country_button.subtitle_label.text()
    assert "Sweden" in window.country_description.text()
    window._pow_setting(exit_country_code="")
    controller.store.save_region("net-x", "DE")
    window._update_pow_country_selector()
    assert window.pow_country_button.title_label.text() == "Automatic"
    assert "Nearest DE first" in window.pow_country_button.subtitle_label.text()
    assert "Last nearby exit: Germany (DE)" in window.country_description.text()
    window._switch_engine()


def test_engine_switch_segmented(window):
    xray = window.engine_buttons[ENGINE_XRAY]
    pow_button = window.engine_buttons[ENGINE_POW]
    assert xray.isChecked() and not pow_button.isChecked()
    pow_button.click()
    assert window.engine_mode == ENGINE_POW
    assert pow_button.isChecked() and not xray.isChecked()
    pow_button.click()  # clicking the active engine keeps it
    assert window.engine_mode == ENGINE_POW and pow_button.isChecked()
    xray.click()
    assert window.engine_mode == ENGINE_XRAY
    assert xray.isChecked()


def test_every_picker_country_has_bundled_flag():
    from uac_desktop.pow.regions import ALL_NAMES
    from uac_desktop.ui import _flag_png, country_flag_badge

    missing = [code for code in ALL_NAMES if _flag_png(code, "4x3") is None or _flag_png(code, "1x1") is None]
    assert missing == []
    assert country_flag_badge("DE", 38).isNull() is False


def test_pow_engine_uses_green_theme(window):
    from uac_desktop import theme
    from uac_desktop.ui import POW_STYLE, STYLE, QColor

    assert theme.is_pow() is False
    assert "#23f5e0" in STYLE and "#23f5e0" not in POW_STYLE
    window.engine_buttons[ENGINE_POW].click()
    assert theme.is_pow() is True
    accent = QColor("#23f5e0")
    assert accent.green() > accent.blue() + 40  # mint, not cyan
    # Surfaces stay navy (mockup), only accents turn mint.
    surface = QColor("#071225")
    assert surface.blue() > surface.green()
    # Palette is one swappable dict.
    theme.set_palette(accent="#3cf0af")
    assert theme.accent() == "#3cf0af"
    assert "PoW" in window.brand_label.text()
    window.engine_buttons[ENGINE_XRAY].click()
    assert theme.is_pow() is False
    assert QColor("#23f5e0").name() == "#23f5e0"
    assert window.brand_label.text() == "UAC Spoofer"
