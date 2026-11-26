"""Proxy Port setting: defaults, validation, persistence and engine wiring."""

from __future__ import annotations

import os
import socket

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from uac_desktop import engine as engine_module
from uac_desktop import proxy_ports as P
from uac_desktop.pow import config as C
from uac_desktop.pow import coordinator as coordinator_module
from uac_desktop.pow import speed as S
from uac_desktop.pow.store import PowStore


def test_defaults_are_the_ports_the_app_always_used():
    assert (P.XRAY_SOCKS_DEFAULT, P.XRAY_HTTP_DEFAULT) == (engine_module.SOCKS_PORT, engine_module.HTTP_PORT)
    assert P.POW_HTTP_DEFAULT == coordinator_module.FORWARD_HTTP_PORT == 1822
    assert engine_module.FRAGMENT_PORT in P.XRAY_RESERVED
    for port in (C.CHAIN_SOCKS_PORT, C.PSIPHON_SOCKS_PORT, C.AETHER_SOCKS_PORT, S.ROUTER_PORT, *S.EXTRA_PORTS):
        assert port in P.POW_RESERVED


def test_validation_rules():
    assert P.validate_xray_ports(30808, 30809) == []
    assert P.validate_xray_ports(30808, 30808)
    assert P.validate_xray_ports(80, 30809)
    assert P.validate_xray_ports(30808, 70000)
    assert P.validate_xray_ports(40443, 30809)
    assert P.validate_pow_port(2822) == []
    assert P.validate_pow_port(1821)
    assert P.validate_pow_port("abc")


def test_xray_ports_from_settings_falls_back_to_default():
    assert P.xray_ports_from_settings({}) == (20808, 20809)
    assert P.xray_ports_from_settings({"proxy_socks_port": 30808, "proxy_http_port": 30809}) == (30808, 30809)
    assert P.xray_ports_from_settings({"proxy_socks_port": 30808, "proxy_http_port": 30808}) == (20808, 20809)
    assert P.xray_ports_from_settings({"proxy_socks_port": "x"}) == (20808, 20809)


def test_pow_store_round_trip(tmp_path):
    store = PowStore(tmp_path)
    assert store.proxy_http_port() == 1822
    assert store.save_proxy_http_port(2822) == 2822
    assert PowStore(tmp_path).proxy_http_port() == 2822
    assert store.save_proxy_http_port(1820) == 1822  # reserved -> default
    assert store.save_proxy_http_port(99999) == 1822


def test_busy_reason_reports_a_foreign_listener(monkeypatch):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        # Our own process holds it: allowed.
        assert P.busy_reason(port) == ""
        # Pretend the listener is another process.
        monkeypatch.setattr(P, "listener_pid", lambda _port: os.getpid() + 100000)
        assert str(port) in P.busy_reason(port)
        assert P.busy_reason(port, allow=lambda _pid: True) == ""
    finally:
        server.close()


def _bare_engine():
    engine = engine_module.Engine.__new__(engine_module.Engine)
    engine.preferred_ports = (engine_module.SOCKS_PORT, engine_module.HTTP_PORT)
    return engine


def test_engine_default_pair_is_never_rejected(monkeypatch):
    engine = _bare_engine()
    monkeypatch.setattr(P, "busy_reasons", lambda *_a, **_k: ["should not be called"])
    assert engine._configured_local_ports() == (20808, 20809)
    assert engine.check_configured_ports() == ""


def test_engine_custom_pair_and_busy_message(monkeypatch):
    engine = _bare_engine()
    engine.preferred_ports = (30808, 30809)
    assert engine._configured_local_ports() == (30808, 30809)
    monkeypatch.setattr(P, "busy_reasons", lambda ports, allow=None: [f"127.0.0.1:{list(ports)[0]} is used by x"])
    assert "30808" in engine.check_configured_ports()
    engine.preferred_ports = (30808, 30808)
    assert engine._configured_local_ports() == (20808, 20809)


class _FakeProxy:
    calls: list = []

    def __init__(self, log=None):
        pass

    def resume(self, **kwargs):
        _FakeProxy.calls.append(("resume", kwargs))

    def suspend(self):
        _FakeProxy.calls.append(("suspend", {}))
        return True

    def disable(self):
        _FakeProxy.calls.append(("disable", {}))
        return True


class _FakeForwarder:
    instances: list = []

    def __init__(self, listen_port, host, socks_port):
        self.listen_port = listen_port
        self.socks_port = socks_port
        _FakeForwarder.instances.append(self)

    def start(self):
        pass

    def stop(self):
        pass


def _coordinator(tmp_path, port=None):
    store = PowStore(tmp_path)
    if port is not None:
        store.save_proxy_http_port(port)
    return coordinator_module.PowCoordinator(tmp_path, store)


def test_coordinator_uses_saved_port_for_windows_proxy(tmp_path, monkeypatch):
    from uac_desktop.pow import forwarder as forwarder_module
    from uac_desktop.pow import tun_guard
    monkeypatch.setattr(tun_guard, "verify_proxy", lambda *_args, **_kwargs: (True, ""))

    _FakeProxy.calls = []
    _FakeForwarder.instances = []
    monkeypatch.setattr(engine_module, "WindowsProxy", _FakeProxy)
    monkeypatch.setattr(forwarder_module, "HttpToSocks", _FakeForwarder)
    monkeypatch.setattr(coordinator_module, "tcp_accepts", lambda _port, *a, **k: True)
    coordinator = _coordinator(tmp_path, 2822)
    coordinator._speed = C.PowSettings(iran_direct=False)
    assert coordinator.forward_http_port == 1822  # until a connect reads the store
    coordinator._forward_port = coordinator._configured_forward_port()
    coordinator._exit_port = C.PSIPHON_SOCKS_PORT
    coordinator._bypass_processes = []
    coordinator._enable_proxy()
    assert coordinator.forward_http_port == 2822
    assert _FakeForwarder.instances[-1].listen_port == 2822
    assert ("resume", {"socks_port": C.PSIPHON_SOCKS_PORT, "http_port": 2822}) in _FakeProxy.calls
    assert coordinator._proxy_session is True
    coordinator.disconnect(quiet=True)
    assert ("disable", {}) in _FakeProxy.calls
    assert coordinator._proxy_session is False


def test_coordinator_default_port_is_unchanged(tmp_path):
    coordinator = _coordinator(tmp_path)
    assert coordinator._configured_forward_port() == 1822


def test_disconnect_without_proxy_session_leaves_windows_proxy_alone(tmp_path, monkeypatch):
    _FakeProxy.calls = []
    monkeypatch.setattr(engine_module, "WindowsProxy", _FakeProxy)
    coordinator = _coordinator(tmp_path)
    coordinator.disconnect(quiet=True)
    assert ("disable", {}) not in _FakeProxy.calls


def test_dialog_validates_and_returns_values():
    pytest.importorskip("PySide6.QtWidgets")
    from PySide6.QtWidgets import QApplication

    from uac_desktop.proxy_port_dialog import ProxyPortDialog

    app = QApplication.instance() or QApplication([])
    dialog = ProxyPortDialog(None, (20808, 20809), 1822, "en", busy_check=lambda ports: [])
    assert dialog.values() == ((20808, 20809), 1822)
    dialog.xray_http.setValue(20808)
    assert dialog.problems()
    dialog.reset_defaults()
    dialog.pow_http.setValue(1821)
    assert dialog.problems()
    dialog.pow_http.setValue(2822)
    assert dialog.problems() == []
    busy = ProxyPortDialog(None, (20808, 20809), 2822, "fa", busy_check=lambda ports: ["127.0.0.1:2822 is used by x"])
    assert busy.problems()
    dialog.deleteLater(); busy.deleteLater()
    assert app is not None


# -- engine 2 Psiphon SOCKS port ---------------------------------------------
def test_pow_socks_defaults_and_validation():
    assert P.POW_SOCKS_DEFAULT == C.PSIPHON_SOCKS_PORT == 1821
    assert P.validate_pow_ports(1822, 1821) == []
    assert P.validate_pow_ports(2822, 2821) == []
    assert P.validate_pow_ports(2822, 2822)
    for internal in (C.CHAIN_SOCKS_PORT, C.AETHER_SOCKS_PORT, S.ROUTER_PORT, *S.EXTRA_PORTS):
        assert P.validate_pow_socks_port(internal)
    assert P.validate_pow_socks_port(80)


def test_pow_store_socks_round_trip(tmp_path):
    store = PowStore(tmp_path)
    assert store.psiphon_socks_port() == 1821
    assert store.save_psiphon_socks_port(2821) == 2821
    assert PowStore(tmp_path).psiphon_socks_port() == 2821
    assert store.save_psiphon_socks_port(1820) == 1821


def test_psiphon_config_receives_the_custom_port(tmp_path):
    import json
    cfg = json.loads(C.psiphon_config(socks_port=2821, data_directory=str(tmp_path),
                                      preferred_region=None, strategy=C.STRATEGY_F))
    assert cfg["LocalSocksProxyPort"] == 2821
    assert cfg["UpstreamProxyURL"] == f"socks5://127.0.0.1:{C.CHAIN_SOCKS_PORT}"


def test_coordinator_reads_psiphon_port_and_uses_it_as_exit(tmp_path, monkeypatch):
    from uac_desktop.pow import forwarder as forwarder_module
    from uac_desktop.pow import tun_guard
    monkeypatch.setattr(tun_guard, "verify_proxy", lambda *_args, **_kwargs: (True, ""))

    _FakeProxy.calls = []
    monkeypatch.setattr(engine_module, "WindowsProxy", _FakeProxy)
    monkeypatch.setattr(forwarder_module, "HttpToSocks", _FakeForwarder)
    monkeypatch.setattr(coordinator_module, "tcp_accepts", lambda _port, *a, **k: True)
    coordinator = _coordinator(tmp_path)
    coordinator._speed = C.PowSettings(iran_direct=False)
    assert coordinator.psiphon_socks_port == 1821
    coordinator._store.save_psiphon_socks_port(2821)
    assert coordinator._configured_psiphon_port() == 2821
    coordinator._psiphon_port = coordinator._configured_psiphon_port()
    coordinator._exit_port = coordinator.psiphon_socks_port
    coordinator._bypass_processes = []
    coordinator._enable_proxy()
    assert ("resume", {"socks_port": 2821, "http_port": 1822}) in _FakeProxy.calls
    coordinator.disconnect(quiet=True)


def test_coordinator_has_no_hardcoded_psiphon_port_left():
    import inspect
    source = inspect.getsource(coordinator_module.PowCoordinator)
    uses = [line for line in source.splitlines() if "PSIPHON_SOCKS_PORT" in line]
    assert all(("self._psiphon_port = PSIPHON_SOCKS_PORT" in line or "return PSIPHON_SOCKS_PORT" in line
                or "or PSIPHON_SOCKS_PORT" in line or "!= PSIPHON_SOCKS_PORT" in line) for line in uses), uses


def test_dialog_socks_field():
    pytest.importorskip("PySide6.QtWidgets")
    from PySide6.QtWidgets import QApplication

    from uac_desktop.proxy_port_dialog import ProxyPortDialog

    app = QApplication.instance() or QApplication([])
    seen = []
    dialog = ProxyPortDialog(None, (20808, 20809), 1822, "en",
                             busy_check=lambda ports: seen.append(list(ports)) or [])
    assert dialog.pow_socks_value() == 1821
    dialog.pow_socks.setValue(1822)
    assert dialog.problems()
    dialog.pow_socks.setValue(1825)
    assert dialog.problems()
    dialog.pow_socks.setValue(2821)
    assert dialog.problems() == [] and 2821 in seen[-1]
    dialog.reset_defaults()
    assert dialog.pow_socks_value() == 1821
    dialog.deleteLater()
    assert app is not None

# -- inline panels -----------------------------------------------------------

# -- settings-dialog ports ---------------------------------------------------
def test_home_has_no_proxy_port_panel():
    import inspect
    import uac_desktop.ui as U
    src = inspect.getsource(U.MainWindow._home_page)
    assert "ProxyPortPanel" not in src and "xray_proxy_port_panel" not in src
    tools = inspect.getsource(U.MainWindow._tools_page)
    assert "Proxy Port" not in tools and "پورت پروکسی" not in tools


def test_pow_settings_page_has_ports_section():
    import inspect
    import uac_desktop.pow_ui as pow_ui
    src = inspect.getsource(pow_ui.PowController.build_settings_page)
    assert "_build_proxy_ports_section" in src
    page = inspect.getsource(pow_ui.PowController.build_page)
    assert "_build_proxy_port_card()" not in page


def test_proxy_port_editor_xray_saves(tmp_path, monkeypatch):
    pytest.importorskip("PySide6.QtWidgets")
    from PySide6.QtWidgets import QApplication
    from uac_desktop import ui as ui_module, paths, storage
    import uac_desktop.pow_ui as pow_ui
    from uac_desktop.proxy_port_panel import PortEditor

    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(ui_module, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(paths, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(pow_ui, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(storage, "SETTINGS_FILE", tmp_path / "data" / "settings.json")
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    win = ui_module.MainWindow()
    assert not hasattr(win, "xray_proxy_port_panel") or getattr(win, "xray_proxy_port_panel", None) is None
    win.engine_buttons["xray"].click()
    win.open_tuning()
    editor = win._xray_settings_form.proxy_port_editor
    assert win.stack.currentWidget() is win.xray_settings_page
    editor.socks.setValue(30808)
    editor.http.setValue(30809)
    editor._loading = False
    editor._commit()
    assert win.storage.settings["proxy_socks_port"] == 30808
    assert win.engine.preferred_ports == (30808, 30809)
    # PoW editor
    ped = PortEditor(win, mode="pow")
    ped.pow_http.setValue(2822)
    ped.pow_socks.setValue(2821)
    ped._loading = False
    ped._commit()
    assert win.pow_controller.store.proxy_http_port() == 2822
    assert win.pow_controller.store.psiphon_socks_port() == 2821
    win.hide()
    # Stop timers that keep the process alive under offscreen.
    try:
        win.pow_controller._poll.stop()
    except Exception:
        pass
