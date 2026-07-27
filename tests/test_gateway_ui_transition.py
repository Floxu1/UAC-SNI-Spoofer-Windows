import threading
from types import SimpleNamespace

import uac_desktop.ui as ui_module
from uac_desktop.ui import MainWindow


class ToggleStub:
    def __init__(self):
        self.enabled = None
        self.checked = None

    def setEnabled(self, enabled):
        self.enabled = bool(enabled)

    def blockSignals(self, _blocked):
        pass

    def setChecked(self, checked):
        self.checked = bool(checked)


class OptionStub:
    def __init__(self):
        self.enabled = None
        self.properties = {}

    def setEnabled(self, enabled):
        self.enabled = bool(enabled)

    def setProperty(self, name, value):
        self.properties[name] = value


def gateway_ui_dummy(active=False, target=None):
    dummy = SimpleNamespace(
        engine=SimpleNamespace(gateway_running=active),
        gateway_mode=ToggleStub(),
        gateway_option=OptionStub(),
        tun_mode=ToggleStub(),
        tun_option=OptionStub(),
        _gateway_requested=bool(active or target is True),
        _gateway_apply_target=target,
        _gateway_apply_generation=4,
        _gateway_apply_cancel=threading.Event(),
        _gateway_apply_reasons={4: "user"},
        _gateway_runtime_state="inactive",
        _gateway_runtime_active=lambda: MainWindow._gateway_runtime_active(dummy),
        _set_gateway_toggle=lambda checked: MainWindow._set_gateway_toggle(
            dummy, checked
        ),
        _cancel_gateway_apply=lambda: MainWindow._cancel_gateway_apply(dummy),
        _sync_gateway_controls=lambda: MainWindow._sync_gateway_controls(dummy),
        _append_log=lambda _line: None,
    )
    return dummy


def test_gateway_toggle_is_locked_only_during_runtime_transition(monkeypatch):
    monkeypatch.setattr(ui_module, "_restyle", lambda _widget: None)
    dummy = gateway_ui_dummy(active=False, target=True)

    MainWindow._sync_gateway_controls(dummy)

    assert dummy.gateway_mode.enabled is False
    assert dummy.gateway_option.properties["state"] == "starting"
    assert dummy.tun_mode.enabled is False

    dummy.engine.gateway_running = True
    dummy._gateway_apply_target = None
    MainWindow._sync_gateway_controls(dummy)

    assert dummy.gateway_mode.enabled is True
    assert dummy.gateway_option.properties["state"] == "active"

    dummy._gateway_apply_target = False
    MainWindow._sync_gateway_controls(dummy)

    assert dummy.gateway_mode.enabled is False
    assert dummy.gateway_option.properties["state"] == "stopping"


def test_inactive_signal_does_not_cancel_pending_stop(monkeypatch):
    monkeypatch.setattr(ui_module, "_restyle", lambda _widget: None)
    dummy = gateway_ui_dummy(active=False, target=False)

    MainWindow._gateway_runtime_state_changed(dummy, "inactive")

    assert dummy._gateway_apply_generation == 4
    assert dummy._gateway_apply_target is False
    assert dummy.gateway_mode.enabled is False
