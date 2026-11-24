"""The .NET key-fetch fallback lane (bin/keyfetch-net.ps1). Never touches the network."""

from __future__ import annotations

import io
import os

import pytest

from uac_desktop.pow import config as C
from uac_desktop.pow import coordinator as coordinator_module
from uac_desktop.pow import runner as runner_module
from uac_desktop.pow.coordinator import PowCoordinator
from uac_desktop.pow.status import PowStatusStore
from uac_desktop.pow.store import PowStore

READY_TOML = 'device_id = "d"\naccess_token = "t"\ncert_pem = "-----BEGIN CERTIFICATE-----\\nX\\n-----END CERTIFICATE-----\\n"\n'


def _coordinator(tmp_path, logs):
    return PowCoordinator(tmp_path, PowStore(tmp_path), PowStatusStore(), log=logs.append)


def _failing_core(calls):
    def fake_prepare(data_dir, settings, protocol, on_log=None, stop=None, timeout=0, api_camo=None):
        calls.append(api_camo)
        raise RuntimeError("key request failed: OOB exchange timed out")
    return fake_prepare


@pytest.fixture
def lane_enabled(monkeypatch):
    monkeypatch.delenv("UAC_NET_KEYFETCH", raising=False)
    monkeypatch.delenv("UAC_NET_KEYFETCH_FORCE", raising=False)


nt_only = pytest.mark.skipif(os.name != "nt", reason="lane is Windows-only")


def _fake_lane(lane, result):
    def fake(self, protocol, label, timeout=None):
        lane.append((protocol, timeout))
        return result
    return fake


@nt_only
@pytest.mark.parametrize("mode", ["auto", "oob"])
def test_lane_runs_first_and_success_skips_the_core(tmp_path, monkeypatch, lane_enabled, mode):
    calls, lane, logs = [], [], []
    monkeypatch.setattr("uac_desktop.pow.coordinator.prepare_identity", _failing_core(calls))
    monkeypatch.setattr(PowCoordinator, "_net_key_lane", _fake_lane(lane, True))
    assert _coordinator(tmp_path, logs)._fetch_key(C.PowSettings(key_fetch=mode), "masque", "MASQUE") is None
    assert calls == []                # core never ran
    assert lane == [("masque", PowCoordinator.NET_KEY_LANE_FIRST_TIMEOUT_S)]
    assert PowCoordinator.NET_KEY_LANE_FIRST_TIMEOUT_S <= 60
    assert any(line.startswith("Key (.NET): trying first") for line in logs)


@nt_only
def test_auto_lane_failure_falls_through_to_core_auto_then_relay(tmp_path, monkeypatch, lane_enabled):
    calls, lane, logs = [], [], []
    monkeypatch.setattr("uac_desktop.pow.coordinator.prepare_identity", _failing_core(calls))
    monkeypatch.setattr(PowCoordinator, "_net_key_lane", _fake_lane(lane, False))
    error = _coordinator(tmp_path, logs)._fetch_key(C.PowSettings(), "masque", "MASQUE")
    assert error and "timed out" in error
    assert calls == ["auto", "relay"]  # unchanged core sequence
    assert len(lane) == 1             # tried once, first; not again after the core


@nt_only
def test_oob_lane_failure_falls_through_to_core_oob(tmp_path, monkeypatch, lane_enabled):
    calls, lane, logs = [], [], []
    monkeypatch.setattr("uac_desktop.pow.coordinator.prepare_identity", _failing_core(calls))
    monkeypatch.setattr(PowCoordinator, "_net_key_lane", _fake_lane(lane, False))
    error = _coordinator(tmp_path, logs)._fetch_key(C.PowSettings(key_fetch="oob"), "masque", "MASQUE")
    assert error
    assert calls == ["oob"]
    assert len(lane) == 1


@nt_only
def test_lane_first_then_core_success(tmp_path, monkeypatch, lane_enabled):
    calls, lane, logs = [], [], []

    def ok_core(data_dir, settings, protocol, on_log=None, stop=None, timeout=0, api_camo=None):
        calls.append(api_camo)

    monkeypatch.setattr("uac_desktop.pow.coordinator.prepare_identity", ok_core)
    monkeypatch.setattr(PowCoordinator, "_net_key_lane", _fake_lane(lane, False))
    assert _coordinator(tmp_path, logs)._fetch_key(C.PowSettings(), "masque", "MASQUE") is None
    assert calls == ["auto"] and len(lane) == 1


@nt_only
def test_force_env_runs_lane_before_an_explicit_core_route(tmp_path, monkeypatch, lane_enabled):
    calls, lane, logs = [], [], []
    monkeypatch.setenv("UAC_NET_KEYFETCH_FORCE", "1")
    monkeypatch.setattr("uac_desktop.pow.coordinator.prepare_identity", _failing_core(calls))
    monkeypatch.setattr(PowCoordinator, "_net_key_lane", _fake_lane(lane, True))
    assert _coordinator(tmp_path, logs)._fetch_key(C.PowSettings(key_fetch="fragment"), "masque", "MASQUE") is None
    assert calls == []                # core never ran
    assert any("UAC_NET_KEYFETCH_FORCE" in line for line in logs)


def test_disable_env_and_non_masque_and_other_explicit_modes_skip_the_lane(tmp_path, monkeypatch):
    calls, lane, logs = [], [], []
    monkeypatch.setattr("uac_desktop.pow.coordinator.prepare_identity", _failing_core(calls))
    monkeypatch.setattr(PowCoordinator, "_net_key_lane", _fake_lane(lane, True))
    co = _coordinator(tmp_path, logs)
    monkeypatch.setenv("UAC_NET_KEYFETCH", "0")
    assert co._fetch_key(C.PowSettings(), "masque", "MASQUE")
    assert co._fetch_key(C.PowSettings(key_fetch="oob"), "masque", "MASQUE")
    monkeypatch.delenv("UAC_NET_KEYFETCH")
    assert co._fetch_key(C.PowSettings(), "wireguard", "WireGuard")
    for mode in ("fragment", "relay", "ech", "external"):
        assert co._fetch_key(C.PowSettings(key_fetch=mode), "masque", "MASQUE")
    assert lane == []


class _FakeProc:
    def __init__(self, lines, code, on_start=None):
        self.stdout = io.StringIO("".join(line + "\n" for line in lines))
        self.returncode = None
        self._code = code
        if on_start:
            on_start()

    def poll(self):
        self.returncode = self._code
        return self._code

    def wait(self, timeout=None):
        self.returncode = self._code
        return self._code

    def kill(self):
        pass


def _fake_bin(tmp_path, monkeypatch, with_script=True):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "aether.exe").write_bytes(b"")
    if with_script:
        (bin_dir / "keyfetch-net.ps1").write_text("# fake", encoding="ascii")
    monkeypatch.setattr(runner_module, "find_aether_binary", lambda: bin_dir / "aether.exe")
    return bin_dir


@pytest.mark.skipif(os.name != "nt", reason="lane is Windows-only")
def test_lane_success_writes_identity_and_logs(tmp_path, monkeypatch, lane_enabled):
    data = tmp_path / "data"
    data.mkdir()
    bin_dir = _fake_bin(tmp_path, monkeypatch)
    seen = {}

    def fake_popen(args, **kwargs):
        seen["args"] = args
        return _FakeProc(
            ["keyfetch-net: disoob-byte0-ttl1 register=200 MASQUE=200 KEY=YES"], 0,
            on_start=lambda: (data / "uac-pow.toml").write_text(READY_TOML, encoding="utf-8"),
        )

    monkeypatch.setattr(coordinator_module.subprocess, "Popen", fake_popen)
    logs = []
    co = PowCoordinator(data, PowStore(data), PowStatusStore(), log=logs.append)
    assert co._net_key_lane("masque", "MASQUE") is True
    assert seen["args"][:6] == ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(bin_dir / "keyfetch-net.ps1")]
    assert seen["args"][6] == str(data)
    assert any(line.startswith("Key (.NET): keyfetch-net: disoob-byte0-ttl1") for line in logs)
    assert any("via the .NET lane" in line for line in logs)


@pytest.mark.skipif(os.name != "nt", reason="lane is Windows-only")
def test_lane_nonzero_exit_or_missing_script_is_a_failure(tmp_path, monkeypatch, lane_enabled):
    data = tmp_path / "data"
    data.mkdir()
    _fake_bin(tmp_path, monkeypatch)
    monkeypatch.setattr(coordinator_module.subprocess, "Popen",
                        lambda args, **kw: _FakeProc(["keyfetch-net: no method produced a key"], 1))
    logs = []
    co = PowCoordinator(data, PowStore(data), PowStatusStore(), log=logs.append)
    assert co._net_key_lane("masque", "MASQUE") is False
    assert any("got no key" in line for line in logs)


class _SlowProc:
    """Prints one line, then keeps running until released (or killed)."""

    def __init__(self, release):
        import queue
        self._q = queue.Queue()
        self._q.put("keyfetch-net: started (pid 1)\n")
        self._release = release
        self.returncode = None
        self.killed = False
        outer = self

        class _Out:
            def readline(self_inner):
                item = outer._q.get()
                return item

            def __iter__(self_inner):  # pragma: no cover - lane must use readline
                raise AssertionError("iterate")

        self.stdout = _Out()

    def poll(self):
        if self.killed or self._release.is_set():
            self.returncode = -9 if self.killed else 1
            self._q.put("")
            return self.returncode
        return None

    def wait(self, timeout=None):
        return self.poll()

    def kill(self):
        self.killed = True
        self._q.put("")


@nt_only
def test_lane_streams_lines_live_before_the_script_exits(tmp_path, monkeypatch, lane_enabled):
    import threading
    import time as _t
    _fake_bin(tmp_path, monkeypatch)
    release = threading.Event()
    proc = _SlowProc(release)
    monkeypatch.setattr(coordinator_module.subprocess, "Popen", lambda args, **kw: proc)
    logs = []
    co = PowCoordinator(tmp_path, PowStore(tmp_path), PowStatusStore(), log=logs.append)
    result = {}
    worker = threading.Thread(target=lambda: result.setdefault("ok", co._net_key_lane("masque", "MASQUE", timeout=30)))
    worker.start()
    deadline = _t.monotonic() + 5
    while not any(l.startswith("Key (.NET): keyfetch-net: started") for l in logs) and _t.monotonic() < deadline:
        _t.sleep(0.05)
    assert any(l.startswith("Key (.NET): keyfetch-net: started") for l in logs)
    assert proc.returncode is None    # still running: the line arrived live
    release.set()
    worker.join(5)
    assert result["ok"] is False


@nt_only
def test_lane_cap_kills_the_script(tmp_path, monkeypatch, lane_enabled):
    import threading
    _fake_bin(tmp_path, monkeypatch)
    proc = _SlowProc(threading.Event())
    monkeypatch.setattr(coordinator_module.subprocess, "Popen", lambda args, **kw: proc)
    logs = []
    co = PowCoordinator(tmp_path, PowStore(tmp_path), PowStatusStore(), log=logs.append)
    assert co._net_key_lane("masque", "MASQUE", timeout=0.5) is False
    assert proc.killed
    assert any("Key (.NET): timed out after" in line for line in logs)


@pytest.mark.skipif(os.name != "nt", reason="lane is Windows-only")
def test_lane_missing_script_is_skipped(tmp_path, monkeypatch, lane_enabled):
    _fake_bin(tmp_path, monkeypatch, with_script=False)
    started = []
    monkeypatch.setattr(coordinator_module.subprocess, "Popen", lambda *a, **k: started.append(1))
    logs = []
    co = PowCoordinator(tmp_path, PowStore(tmp_path), PowStatusStore(), log=logs.append)
    assert co._net_key_lane("masque", "MASQUE") is False
    assert started == []
    assert any("keyfetch-net.ps1 is missing" in line for line in logs)
