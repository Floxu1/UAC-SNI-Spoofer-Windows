import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from types import SimpleNamespace

from uac_desktop import ui
from uac_desktop.pow_ui import ENGINE_POW, ENGINE_XRAY


def _stub(mode, settings):
    opened = []
    s = SimpleNamespace(engine_mode=mode, storage=SimpleNamespace(settings=settings), _wizard=None,
                        _append_log=lambda *_: None)
    s._open_wizard = lambda: opened.append(1)
    return s, opened


def test_wizard_never_auto_opens_on_engine_2_and_keeps_marker():
    settings = {}
    stub, opened = _stub(ENGINE_POW, settings)
    ui.MainWindow._maybe_open_wizard(stub)
    assert opened == [] and "wizard_seen_version" not in settings


def test_wizard_auto_opens_on_engine_1_when_unseen():
    stub, opened = _stub(ENGINE_XRAY, {})
    ui.MainWindow._maybe_open_wizard(stub)
    assert opened == [1]
    stub2, opened2 = _stub(ENGINE_XRAY, {"wizard_seen_version": ui.__version__})
    ui.MainWindow._maybe_open_wizard(stub2)
    assert opened2 == []


def test_restart_button_visible_only_on_engine_1():
    calls = []
    btn = SimpleNamespace(setVisible=lambda v: calls.append(v))
    ui.MainWindow._sync_wizard_restart_button(SimpleNamespace(engine_mode=ENGINE_XRAY, wizard_restart_btn=btn))
    ui.MainWindow._sync_wizard_restart_button(SimpleNamespace(engine_mode=ENGINE_POW, wizard_restart_btn=btn))
    assert calls == [True, False]
