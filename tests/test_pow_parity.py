"""Windows POW tests for the Android exit and Aether contracts."""

import io
import json
import os
import socket
import threading

import pytest

from test_pow_engine import _coordinator
from uac_desktop.pow import config
from uac_desktop.pow.coordinator import PowEngineError
from uac_desktop.pow.runner import AetherProcess
from uac_desktop.pow.status import PowPhase
from uac_desktop.pow.store import PowStore


@pytest.mark.parametrize(
    "recipe, transport", [
        (config.RECIPE_MASQUE_H3_EXPERIMENTAL, "h3-experimental"),
        (config.RECIPE_MASQUE_H3_OVER_H2, "h3-over-h2"),
    ]
)
def test_new_recipe_selects_native_transport_and_fails_without_outer(tmp_path, monkeypatch, recipe, transport):
    settings = config.PowSettings(
        link_recipe=recipe, direct_psiphon_first=True, masque_ip_version="v6", h2_fingerprint="chrome"
    )
    payload = json.loads(config.chain_outer_json(tmp_path, "masque", settings))
    assert payload["masque_transport"] == transport
    assert payload["ip_scan"] == "v6" and payload["ip_scan_strict"]
    assert payload["h2_fingerprint"] == "chrome"
    coordinator, _, status, aether, psiphon = _coordinator(tmp_path, monkeypatch, ready=set())
    with pytest.raises(PowEngineError, match="WARP did not come up"):
        coordinator.connect(settings, proxy_mode=True)
    assert aether.started == ["masque"]
    assert psiphon.attempts == 0
    assert status.snapshot().phase == PowPhase.FAILED


def test_psiphon_only_skips_aether(tmp_path, monkeypatch):
    coordinator, _, _, aether, psiphon = _coordinator(tmp_path, monkeypatch, ready=set())
    monkeypatch.setattr(coordinator, "_enable_proxy", lambda: None)
    try:
        coordinator.connect(config.PowSettings(exit_mode="psiphon"), proxy_mode=True)
        assert psiphon.attempts == 1
        assert aether.started == []
    finally:
        coordinator.disconnect()


def test_vpn_failure_does_not_start_proxy(tmp_path, monkeypatch):
    coordinator, _, status, _, _ = _coordinator(tmp_path, monkeypatch, ready={"masque"})

    def fail():
        raise PowEngineError("TUN validation failed")

    monkeypatch.setattr(coordinator, "_enable_tun", fail)
    monkeypatch.setattr(coordinator, "_enable_proxy", lambda: pytest.fail("proxy started"))
    with pytest.raises(PowEngineError, match="TUN validation failed"):
        coordinator.connect(config.PowSettings(exit_mode="warp"), proxy_mode=False)
    assert status.snapshot().phase == PowPhase.FAILED
    assert not coordinator.running
    assert coordinator.exit_port == 0


def test_store_migrates_legacy_exit_and_keeps_unknown_fields(tmp_path):
    path = tmp_path / "pow_settings.json"
    legacy = {"settings_version": 2, "link_recipe": "auto", "chain_psiphon": False,
              "proxy_http_port": 17999, "unknown": "keep"}
    path.write_text(json.dumps(legacy), encoding="utf-8")
    store = PowStore(tmp_path)
    assert store.snapshot().exit_mode == "warp"
    assert store.snapshot().link_recipe == "auto"
    assert store.proxy_http_port() == 17999
    assert json.loads(path.read_text(encoding="utf-8"))["unknown"] == "keep"
    assert json.loads(path.with_suffix(".before-v3.json").read_text(encoding="utf-8")) == legacy
    assert "unknown" not in store.export_settings()
    store.import_settings({"exit_mode": "psiphon", "tun_backend": "gvisor"})
    snapshot = PowStore(tmp_path).snapshot()
    assert (snapshot.exit_mode, snapshot.tun_backend) == ("psiphon", "gvisor")


def test_expire_and_forget_path_cache_preserves_credentials(tmp_path):
    store = PowStore(tmp_path)
    identity = config.identity_path(tmp_path)
    identity.write_bytes(b"test-only")
    cache = config.clean_h2_path(tmp_path)
    cache.write_text("[]", encoding="utf-8")
    os.utime(cache, (100, 100))
    assert store.expire_path_cache(now=100 + 12 * 60 + 1) == 1
    store.save_outer_protocol("masque")
    store.forget_learned()
    assert store.remembered_outer_protocol() is None
    assert identity.read_bytes() == b"test-only"


def test_aether_requires_same_process_event_and_socks_greeting():
    class Child:
        def __init__(self):
            self.stderr = io.StringIO('AETHER_EVENT {"type":"status","status":"connected"}\n')

        def poll(self):
            return None

    process = AetherProcess()
    active = Child()
    process._process = active
    process._drain(Child())
    assert not process._ready.is_set()
    process._drain(active)
    assert process._ready.is_set()
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        server.settimeout(2)

        def reply():
            with server.accept()[0] as sock:
                assert sock.recv(3) == bytes((5, 1, 0))
                sock.sendall(bytes((5, 0)))

        thread = threading.Thread(target=reply)
        thread.start()
        assert process.wait_ready(server.getsockname()[1], 1500, threading.Event())
        thread.join(timeout=2)


def test_pause_removes_exit_and_resume_validates_it_again(tmp_path, monkeypatch):
    coordinator, _, status, aether, _ = _coordinator(tmp_path, monkeypatch, ready=set())
    exits = []
    monkeypatch.setattr(coordinator, "_enable_proxy", lambda: exits.append("enable"))
    monkeypatch.setattr(coordinator, "_teardown_exit", lambda: exits.append("teardown"))
    try:
        coordinator.connect(config.PowSettings(exit_mode="psiphon"), proxy_mode=True)
        exits.clear()
        coordinator.set_paused(True, proxy_only=True)
        assert coordinator.paused and coordinator.running
        assert status.snapshot().phase == PowPhase.PAUSED
        assert coordinator.actual_proxy_mode is None
        coordinator.set_paused(False, proxy_only=True)
        assert not coordinator.paused
        assert status.snapshot().phase == PowPhase.CONNECTED
        assert coordinator.actual_proxy_mode is True
        assert aether.started == []
        assert exits == ["teardown", "enable"]
    finally:
        coordinator.disconnect()


def test_proxy_only_pause_leaves_vpn_path_work_intact(tmp_path, monkeypatch):
    coordinator, _, status, _, _ = _coordinator(tmp_path, monkeypatch, ready=set())
    coordinator._connected.set()
    coordinator._proxy_mode = False
    status.update(PowPhase.CONNECTED, 100, "connected")
    original_cancel = coordinator._path_cancel
    coordinator.set_paused(True, proxy_only=True)
    assert not coordinator.paused
    assert status.snapshot().phase == PowPhase.CONNECTED
    assert coordinator._path_cancel is original_cancel and not original_cancel.is_set()
