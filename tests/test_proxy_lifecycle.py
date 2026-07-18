import json
import subprocess
import sys

import pytest

import main as desktop_main
import uac_desktop.engine as engine_module
from uac_desktop.engine import Engine, WindowsProxy


class _FakeKey:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class _FakeRegistry:
    def __init__(self, values=None):
        self.values = dict(values or {})
        self.fail_once = None

    def open_key(self, *_args, **_kwargs):
        return _FakeKey()

    def query_value(self, _key, name):
        if name not in self.values:
            raise FileNotFoundError(name)
        return self.values[name]

    def set_value(self, _key, name, _reserved, value_type, value):
        if self.fail_once == name:
            self.fail_once = None
            raise OSError(f"simulated failure for {name}")
        self.values[name] = (value, value_type)

    def delete_value(self, _key, name):
        if name not in self.values:
            raise FileNotFoundError(name)
        del self.values[name]


@pytest.fixture
def proxy_registry(monkeypatch, tmp_path):
    registry = _FakeRegistry()
    state_file = tmp_path / "windows-proxy-restore.json"
    monkeypatch.setattr(engine_module, "PROXY_STATE_FILE", state_file)
    monkeypatch.setattr(engine_module.winreg, "OpenKey", registry.open_key)
    monkeypatch.setattr(engine_module.winreg, "QueryValueEx", registry.query_value)
    monkeypatch.setattr(engine_module.winreg, "SetValueEx", registry.set_value)
    monkeypatch.setattr(engine_module.winreg, "DeleteValue", registry.delete_value)
    monkeypatch.setattr(WindowsProxy, "_refresh", staticmethod(lambda: None))
    launched = []
    monkeypatch.setattr(WindowsProxy, "_launch_watchdog",
                        staticmethod(lambda owner: launched.append(dict(owner))))
    monkeypatch.setattr(WindowsProxy, "_other_app_instance_alive",
                        staticmethod(lambda: False))
    return registry, state_file, launched


def test_proxy_round_trip_restores_exact_values_types_and_absence(proxy_registry):
    registry, state_file, launched = proxy_registry
    original = {
        "ProxyEnable": (0, engine_module.winreg.REG_DWORD),
        # Preserve a non-default registry type as well as its value.
        "ProxyServer": ("http://old-proxy:8080", engine_module.winreg.REG_EXPAND_SZ),
        # ProxyOverride intentionally did not exist.
    }
    registry.values = dict(original)
    proxy = WindowsProxy(lambda _message: None)

    proxy.enable()

    state = json.loads(state_file.read_text(encoding="utf-8"))
    assert state["version"] == 2
    assert state["values"]["ProxyOverride"] == {"exists": False}
    assert state["values"]["ProxyServer"]["type"] == engine_module.winreg.REG_EXPAND_SZ
    assert len(launched) == 1
    assert launched[0]["token"] == state["owner"]["token"]

    assert proxy.disable()
    assert registry.values == original
    assert not state_file.exists()
    assert not proxy.has_pending_restore


def test_proxy_round_trip_re_deletes_all_originally_absent_values(proxy_registry):
    registry, state_file, _launched = proxy_registry
    registry.values = {}
    proxy = WindowsProxy(lambda _message: None)

    proxy.enable()
    assert proxy.disable()

    assert registry.values == {}
    assert not state_file.exists()


def test_partial_enable_failure_rolls_back_immediately(proxy_registry):
    registry, state_file, _launched = proxy_registry
    original = {"ProxyEnable": (0, engine_module.winreg.REG_DWORD)}
    registry.values = dict(original)
    # Fail after ProxyEnable was temporarily cleared and ProxyServer changed.
    registry.fail_once = "ProxyOverride"
    proxy = WindowsProxy(lambda _message: None)

    with pytest.raises(OSError, match="ProxyOverride"):
        proxy.enable()

    assert registry.values == original
    assert not state_file.exists()
    assert not proxy.has_pending_restore


def test_partial_restore_keeps_snapshot_and_retries(proxy_registry):
    registry, state_file, _launched = proxy_registry
    original = {
        "ProxyEnable": (1, engine_module.winreg.REG_DWORD),
        "ProxyServer": ("original-proxy", engine_module.winreg.REG_SZ),
        "ProxyOverride": ("original-bypass", engine_module.winreg.REG_SZ),
    }
    registry.values = dict(original)
    proxy = WindowsProxy(lambda _message: None)
    proxy.enable()

    registry.fail_once = "ProxyOverride"
    with pytest.raises(OSError, match="ProxyOverride"):
        proxy.disable()

    assert state_file.exists()
    assert proxy.has_pending_restore
    assert registry.values["ProxyEnable"][0] == 0

    assert proxy.disable()
    assert registry.values == original
    assert not state_file.exists()


def test_corrupt_disk_state_uses_valid_in_memory_snapshot(proxy_registry):
    registry, state_file, _launched = proxy_registry
    original = {
        "ProxyEnable": (1, engine_module.winreg.REG_DWORD),
        "ProxyServer": ("original-proxy", engine_module.winreg.REG_EXPAND_SZ),
        "ProxyOverride": ("original-bypass", engine_module.winreg.REG_SZ),
    }
    registry.values = dict(original)
    proxy = WindowsProxy(lambda _message: None)
    proxy.enable()
    state_file.write_text("{truncated", encoding="utf-8")

    assert proxy.disable()
    assert registry.values == original
    assert not state_file.exists()


def test_legacy_flat_snapshot_is_backward_compatible(proxy_registry):
    registry, state_file, _launched = proxy_registry
    registry.values = {
        "ProxyEnable": (1, engine_module.winreg.REG_DWORD),
        "ProxyServer": ("app-proxy", engine_module.winreg.REG_SZ),
        "ProxyOverride": ("app-bypass", engine_module.winreg.REG_SZ),
    }
    state_file.write_text(json.dumps({
        "ProxyEnable": 0,
        "ProxyServer": "legacy-original",
        "ProxyOverride": None,
    }), encoding="utf-8")

    assert WindowsProxy.recover_stale()
    assert registry.values == {
        "ProxyEnable": (0, engine_module.winreg.REG_DWORD),
        "ProxyServer": ("legacy-original", engine_module.winreg.REG_SZ),
    }
    assert not state_file.exists()


def test_legacy_snapshot_does_not_touch_a_running_old_instance(proxy_registry, monkeypatch):
    registry, state_file, _launched = proxy_registry
    active = {
        "ProxyEnable": (1, engine_module.winreg.REG_DWORD),
        "ProxyServer": ("active-old-app", engine_module.winreg.REG_SZ),
    }
    registry.values = dict(active)
    state_file.write_text(json.dumps({"ProxyEnable": 0, "ProxyServer": "original"}),
                          encoding="utf-8")
    monkeypatch.setattr(WindowsProxy, "_other_app_instance_alive", staticmethod(lambda: True))

    assert not WindowsProxy.recover_stale()
    assert registry.values == active
    assert state_file.exists()


def test_watchdog_restores_only_matching_dead_owner(proxy_registry, monkeypatch):
    registry, state_file, _launched = proxy_registry
    registry.values = {
        "ProxyEnable": (1, engine_module.winreg.REG_DWORD),
        "ProxyServer": ("app-proxy", engine_module.winreg.REG_SZ),
        "ProxyOverride": ("app-bypass", engine_module.winreg.REG_SZ),
    }
    state_file.write_text(json.dumps({
        "version": 2,
        "owner": {"pid": 321, "create_time": 1234.5, "token": "owner-token"},
        "values": {
            "ProxyEnable": {"exists": True, "value": 0,
                            "type": engine_module.winreg.REG_DWORD},
            "ProxyServer": {"exists": False},
            "ProxyOverride": {"exists": False},
        },
    }), encoding="utf-8")
    monkeypatch.setattr(WindowsProxy, "_owner_is_alive", classmethod(lambda cls, owner: False))

    assert WindowsProxy.run_watchdog(321, 1234.5, "wrong-token", poll_interval=0.02) == 0
    assert state_file.exists()
    assert registry.values["ProxyEnable"][0] == 1

    assert WindowsProxy.run_watchdog(321, 1234.5, "owner-token", poll_interval=0.02) == 0
    assert registry.values == {"ProxyEnable": (0, engine_module.winreg.REG_DWORD)}
    assert not state_file.exists()


def test_watchdog_retries_transient_restore_failures(proxy_registry, monkeypatch):
    _registry, state_file, _launched = proxy_registry
    state = {
        "version": 2,
        "owner": {"pid": 321, "create_time": 1234.5, "token": "retry-token"},
        "values": {"ProxyEnable": {"exists": True, "value": 0,
                                    "type": engine_module.winreg.REG_DWORD}},
    }
    state_file.write_text(json.dumps(state), encoding="utf-8")
    monkeypatch.setattr(WindowsProxy, "_owner_is_alive", classmethod(lambda cls, owner: False))
    outcomes = [OSError("busy"), False, True]

    def recover(_cls, *_args, **_kwargs):
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(WindowsProxy, "recover_stale", classmethod(recover))

    assert WindowsProxy.run_watchdog(321, 1234.5, "retry-token", poll_interval=0.02) == 0
    assert outcomes == []


class _PendingProxy:
    def __init__(self):
        self.has_pending_restore = True
        self.disable_calls = 0

    def disable(self):
        self.disable_calls += 1
        self.has_pending_restore = False
        return True


class _BrokenFragment:
    def stop(self):
        raise RuntimeError("fragment cleanup failed")


def test_engine_stop_restores_pending_proxy_even_if_fragment_cleanup_fails():
    engine = object.__new__(Engine)
    engine._active = False
    engine._run_id = 0
    engine.process = None
    engine._proxy_enabled = False
    engine.system_proxy = _PendingProxy()
    engine.fragment = _BrokenFragment()
    engine.log = lambda _message: None
    engine.state = lambda _running: None

    with pytest.raises(RuntimeError, match="fragment cleanup failed"):
        engine._stop_locked(notify=False)

    assert engine.system_proxy.disable_calls == 1
    assert not engine._proxy_enabled


def test_event_loop_finally_retries_engine_and_owned_restore(monkeypatch):
    calls = []

    class App:
        def exec(self):
            raise RuntimeError("event loop failed")

    class AppEngine:
        def stop(self, notify=False):
            calls.append(("engine-stop", notify))

    class Window:
        engine = AppEngine()

        def shutdown(self):
            calls.append(("shutdown",))
            raise RuntimeError("first cleanup failed")

    monkeypatch.setattr(WindowsProxy, "process_identity",
                        staticmethod(lambda token="": {"pid": 77, "create_time": 88.5}))

    def recover(*_args, **kwargs):
        calls.append(("recover", kwargs))
        return True

    monkeypatch.setattr(WindowsProxy, "recover_stale", classmethod(lambda cls, *args, **kwargs: recover(*args, **kwargs)))

    with pytest.raises(RuntimeError, match="event loop failed"):
        desktop_main.run_event_loop(App(), Window())

    assert ("engine-stop", False) in calls
    assert ("recover", {"expected_pid": 77, "expected_create_time": 88.5}) in calls


def test_watchdog_cli_mode_validates_arguments(monkeypatch):
    monkeypatch.setattr(WindowsProxy, "run_watchdog",
                        classmethod(lambda cls, pid, created, token: (pid, created, token) == (9, 4.5, "abc")))
    assert desktop_main.proxy_watchdog_mode([]) is None
    assert desktop_main.proxy_watchdog_mode(["--proxy-watchdog", "bad", "4.5", "abc"]) == 2
    assert desktop_main.proxy_watchdog_mode(["--proxy-watchdog", "9", "4.5", "abc"]) is True


def test_main_recovers_before_admin_relaunch(monkeypatch):
    calls = []
    monkeypatch.setattr(WindowsProxy, "recover_stale",
                        classmethod(lambda cls: calls.append("recover") or True))
    monkeypatch.setattr(desktop_main, "relaunch_as_admin",
                        lambda: calls.append("relaunch") or True)

    assert desktop_main.main() == 0
    assert calls == ["recover", "relaunch"]


def test_watchdog_is_launched_detached_with_owner_identity(monkeypatch):
    calls = []
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setattr(subprocess, "Popen",
                        lambda command, **kwargs: calls.append((command, kwargs)))

    WindowsProxy._launch_watchdog({"pid": 41, "create_time": 99.25, "token": "token-1"})

    command, kwargs = calls[0]
    assert command[-4:] == ["--proxy-watchdog", "41", "99.25", "token-1"]
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["stdout"] is subprocess.DEVNULL
    assert kwargs["stderr"] is subprocess.DEVNULL
    if sys.platform == "win32":
        assert int(kwargs["creationflags"]) & 0x00000008  # DETACHED_PROCESS


def test_frozen_watchdog_starts_with_fresh_pyinstaller_environment(monkeypatch):
    calls = []
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setenv("PYINSTALLER_RESET_ENVIRONMENT", "0")
    monkeypatch.setattr(subprocess, "Popen",
                        lambda command, **kwargs: calls.append((command, kwargs)))

    WindowsProxy._launch_watchdog({"pid": 5, "create_time": 6.5, "token": "fresh"})

    command, kwargs = calls[0]
    assert command[0] == sys.executable
    assert kwargs["env"]["PYINSTALLER_RESET_ENVIRONMENT"] == "1"
    assert command[-4:] == ["--proxy-watchdog", "5", "6.5", "fresh"]
