"""Home IP card in PoW mode: exit IP + flag, parallel MASQUE badge."""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6.QtWidgets")

from PySide6.QtWidgets import QApplication

from uac_desktop import ui as ui_module
from uac_desktop.pow import config as C
from uac_desktop.pow.coordinator import PowCoordinator
from uac_desktop.pow.status import PowPhase
from uac_desktop.pow_ui import ENGINE_POW, ENGINE_XRAY

SESSIONS = [
    {"peer": "162.159.199.95:443", "colo": "FRA", "country": "DE", "state": "up", "connections": 4, "main": True},
    {"peer": "162.159.198.130:443", "colo": "AMS", "country": "NL", "state": "standby", "connections": 0, "main": False},
    {"peer": "162.159.199.213:443", "colo": "VIE", "country": "AT", "state": "skipped", "connections": 1, "main": False},
]


@pytest.fixture(scope="module")
def app():
    yield QApplication.instance() or QApplication([])


@pytest.fixture()
def window(app, tmp_path, monkeypatch):
    monkeypatch.setattr(ui_module, "DATA_DIR", tmp_path / "data")
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    from uac_desktop import paths, storage
    import uac_desktop.pow_ui as pow_ui

    monkeypatch.setattr(paths, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(pow_ui, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(storage, "SETTINGS_FILE", tmp_path / "data" / "settings.json")
    win = ui_module.MainWindow()
    yield win


def _connected(window, monkeypatch, sessions, info=None):
    info = info if info is not None else {"ip": "104.28.212.7", "country": "DE"}
    monkeypatch.setattr(PowCoordinator, "exit_info", property(lambda self: dict(info)))
    coordinator = window.pow_controller.coordinator
    monkeypatch.setattr(coordinator, "parallel_sessions", lambda: [dict(s) for s in sessions])
    coordinator._exit_port = C.PSIPHON_SOCKS_PORT
    window.engine_mode = ENGINE_POW
    window.pow_controller._sync_ip_card(SimpleNamespace(phase=PowPhase.CONNECTED))


def test_exit_ip_with_flag_and_no_badge_when_single(window, monkeypatch):
    _connected(window, monkeypatch, [])
    assert window.ip_label.text() == "104.28.212.7"
    assert not window.ip_flag.isHidden()
    assert window.ip_parallel.isHidden()
    assert ("Germany" in window.ip_card._secondary_full or "آلمان" in window.ip_card._secondary_full)


def test_parallel_badge_lists_sessions(window, monkeypatch):
    window.language = "en"
    _connected(window, monkeypatch, SESSIONS)
    badge = window.ip_parallel
    assert not badge.isHidden()
    assert badge.text.text() == "Parallel · 3"
    assert sum(not f.isHidden() for f in badge.flags) == 3
    tip = badge.toolTip()
    for session in SESSIONS:
        assert session["peer"] in tip
    assert "standby" in tip and "skipped" in tip
    assert window.ip_card._secondary_full == ""


def test_parallel_badge_persian(window, monkeypatch):
    window.language = "fa"
    _connected(window, monkeypatch, SESSIONS[:2])
    assert window.ip_parallel.text.text() == "موازی · 2"


def test_ip_card_cleared_when_not_connected(window, monkeypatch):
    _connected(window, monkeypatch, SESSIONS)
    window.pow_controller._sync_ip_card(SimpleNamespace(phase=PowPhase.IDLE))
    assert window.ip_label.text() == "—"
    assert window.ip_flag.isHidden() and window.ip_parallel.isHidden()


def test_xray_mode_untouched(window, monkeypatch):
    window.ip_label.setText("5.6.7.8")
    window.engine_mode = ENGINE_XRAY
    window.pow_controller._sync_ip_card(SimpleNamespace(phase=PowPhase.CONNECTED))
    assert window.ip_label.text() == "5.6.7.8"
    assert window.ip_flag.isHidden()
