"""Key fetch on desktop: mobile-parity race, live logging, no pipe deadlock."""

from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path

import pytest

from uac_desktop.pow import config as C
from uac_desktop.pow import runner as runner_module
from uac_desktop.pow.coordinator import PowCoordinator
from uac_desktop.pow.status import PowStatusStore
from uac_desktop.pow.store import PowStore

_FAKE_AETHER = r"""
import os, sys, time
cfg = os.environ["AETHER_CONFIG"]
log = os.path.join(os.path.dirname(cfg), "aether-core.log")
camo = os.environ.get("AETHER_API_CAMO", "")
with open(log, "a", encoding="utf-8") as handle:
    handle.write("12:00:00  Key: racing ECH, split ClientHello, and the current network\n")
    handle.flush()
    # env_logger-style chatter: far more than one Windows pipe buffer.
    for i in range(4000):
        sys.stderr.write("[2026-10-11T12:00:00Z INFO  aether::apifront] Key: probe line %d padding padding\n" % i)
    sys.stderr.flush()
    handle.write("12:00:01  Key: account key won via ech (sending over 162.159.199.1:443)\n")
    handle.write("12:00:01  Key: account key saved via ech\n")
    handle.flush()
print("camo=" + camo)
print('{"ipv4":"172.16.0.2","ipv6":"","gateway_proxy":"","organization":""}')
"""


def _fake_binary(monkeypatch, script: str) -> None:
    monkeypatch.setattr(runner_module, "find_aether_binary", lambda: Path(sys.executable))
    monkeypatch.setattr(
        runner_module, "_prepare_args", lambda binary, payload, renew: [sys.executable, "-c", script]
    )


def test_default_key_fetch_is_auto_race(tmp_path):
    payload = json.loads(C.key_request_json(tmp_path, C.PowSettings(), "masque"))
    assert payload["api_camo"] == "auto"
    assert runner_module.json_to_env(payload)["AETHER_API_CAMO"] == "auto"
    assert C.KEY_AUTO in C.KEY_FETCHES
    assert C.FETCH_CHOICES[0].id == C.KEY_AUTO


def test_prepare_drains_pipes_and_streams_core_log(tmp_path, monkeypatch):
    _fake_binary(monkeypatch, _FAKE_AETHER)
    lines: list[str] = []
    started = time.monotonic()
    result = runner_module.prepare_identity(
        tmp_path, C.PowSettings(), "masque", timeout=30, on_log=lines.append
    )
    assert result["ipv4"] == "172.16.0.2"
    # 4000 stderr lines would deadlock an undrained pipe until the timeout.
    assert time.monotonic() - started < 20
    assert any("account key won via ech" in line and line.startswith("Key:") for line in lines)
    assert any(line.startswith("Key: racing ECH") for line in lines)


def test_prepare_cancel_is_prompt(tmp_path, monkeypatch):
    _fake_binary(monkeypatch, "import time\ntime.sleep(60)\n")
    stop = threading.Event()
    threading.Timer(0.5, stop.set).start()
    started = time.monotonic()
    with pytest.raises(RuntimeError, match="stopped"):
        runner_module.prepare_identity(tmp_path, C.PowSettings(), "masque", timeout=60, stop=stop)
    assert time.monotonic() - started < 8


def test_prepare_timeout_is_reported(tmp_path, monkeypatch):
    _fake_binary(monkeypatch, "import time\ntime.sleep(60)\n")
    with pytest.raises(RuntimeError, match="timed out after 1s"):
        runner_module.prepare_identity(tmp_path, C.PowSettings(), "masque", timeout=1)


def test_store_migrates_old_ech_default_to_auto(tmp_path):
    (tmp_path / "pow_settings.json").write_text(json.dumps({"key_fetch": "ech", "scan_mode": "balanced"}))
    assert PowStore(tmp_path).snapshot().key_fetch == C.KEY_AUTO
    saved = json.loads((tmp_path / "pow_settings.json").read_text())
    assert saved["settings_version"] >= 2
    store = PowStore(tmp_path)
    store.save(C.PowSettings(key_fetch=C.KEY_ECH))
    assert PowStore(tmp_path).snapshot().key_fetch == C.KEY_ECH


def test_coordinator_retries_with_relay_after_race_failure(tmp_path, monkeypatch):
    calls: list[str] = []
    logs: list[str] = []

    def fake_prepare(data_dir, settings, protocol, on_log=None, stop=None, timeout=0, api_camo=None):
        calls.append(api_camo)
        if api_camo == "auto":
            raise RuntimeError("key request timed out after 90s")
        if on_log:
            on_log("Key: account key won via relay (sending over 104.21.60.172:443 / r.workers.dev)")
        return {"ipv4": "x"}

    monkeypatch.setattr("uac_desktop.pow.coordinator.prepare_identity", fake_prepare)
    coordinator = PowCoordinator(tmp_path, PowStore(tmp_path), PowStatusStore(), log=logs.append)
    assert coordinator._fetch_key(C.PowSettings(), "masque", "MASQUE") is None
    assert C.KEY_FETCH_FALLBACK == C.KEY_RELAY
    assert calls == ["auto", "relay"]
    assert any(line.startswith("Key fetch for MASQUE: OOB first, one method at a time (disoob-byte0-ttl1, then oob-insni+5-ttl1, then oob-byte0-nottl") for line in logs)
    assert any("Key fetch failed after" in line for line in logs)
    relay_name = PowCoordinator._KEY_ROUTE_NAMES["relay"]
    assert any(f"{relay_name} won the race" in line for line in logs)
    assert any(line.startswith("Key fetch retry for MASQUE:") and f"{relay_name} only" in line for line in logs)
    assert any(line.startswith("Key fetch done") and f"via {relay_name}" in line for line in logs)


def test_coordinator_explicit_mode_does_not_retry(tmp_path, monkeypatch):
    calls: list[str] = []

    def fake_prepare(*args, api_camo=None, **kwargs):
        calls.append(api_camo)
        raise RuntimeError("key request failed: boom")

    monkeypatch.setattr("uac_desktop.pow.coordinator.prepare_identity", fake_prepare)
    coordinator = PowCoordinator(tmp_path, PowStore(tmp_path), PowStatusStore(), log=lambda _m: None)
    error = coordinator._fetch_key(C.PowSettings(key_fetch="fragment"), "masque", "MASQUE")
    assert error and "boom" in error
    assert calls == ["fragment"]


def test_clean_ip_steps_are_logged(tmp_path):
    logs: list[str] = []
    coordinator = PowCoordinator(tmp_path, PowStore(tmp_path), PowStatusStore(), log=logs.append)
    for line in (
        "Key: probing 16 addresses for a clean key edge",
        "Key: clean key address 162.159.198.1:443 answered",
        "Key: clean key address 188.114.97.6:443 answered",
        "Key: key request will use 162.159.198.1:443",
        "Key: account key won via fragment (sending over 162.159.198.1:443)",
        "MASQUE identity refused; requesting a fresh certificate",
    ):
        coordinator._on_native_log(line)
    assert any(l.startswith("Clean-IP scan for the key/cert request") for l in logs)
    assert any("Clean IP for key/cert: 162.159.198.1:443 (2 clean edges answered)" in l for l in logs)
    assert any("split ClientHello won the race" in l for l in logs)
    assert any(l.startswith("Cert loop: MASQUE identity refused") for l in logs)


def test_oob_is_the_first_manual_choice_after_auto(tmp_path):
    from uac_desktop import pow_ui

    assert C.KEY_OOB == "oob" and C.KEY_OOB in C.KEY_FETCHES
    assert [c.id for c in C.FETCH_CHOICES][:3] == [C.KEY_AUTO, C.KEY_OOB, C.KEY_RELAY]
    assert [o[0] for o in pow_ui._KEY_FETCH_OPTIONS][:3] == ["auto", "oob", "relay"]
    settings = C.PowSettings(key_fetch="OOB")
    assert settings.validated().key_fetch == C.KEY_OOB
    payload = json.loads(C.key_request_json(tmp_path, settings, "masque"))
    assert payload["api_camo"] == C.KEY_OOB
    assert runner_module.json_to_env(payload)["AETHER_API_CAMO"] == "oob"
    args = runner_module._prepare_args(Path("aether.exe"), payload, False)
    assert args[-2:] == ["--api-camo", "oob"]
    store = PowStore(tmp_path)
    store.save(C.PowSettings(key_fetch=C.KEY_OOB))
    assert PowStore(tmp_path).snapshot().key_fetch == C.KEY_OOB


def test_oob_win_is_logged_by_name(tmp_path):
    logs: list[str] = []
    coordinator = PowCoordinator(tmp_path, PowStore(tmp_path), PowStatusStore(), log=logs.append)
    coordinator._on_native_log("Key: account key won via oob (sending over 104.16.24.84:443)")
    assert coordinator._key_route == "oob"
    assert any("OOB won the race" in line for line in logs)


def test_coordinator_manual_oob_does_not_retry(tmp_path, monkeypatch):
    calls: list[str] = []
    logs: list[str] = []

    def fake_prepare(*args, api_camo=None, on_log=None, **kwargs):
        calls.append(api_camo)
        if on_log:
            on_log("Key: account key won via oob (sending over 104.16.24.84:443)")
        return {"ipv4": "x"}

    monkeypatch.setattr("uac_desktop.pow.coordinator.prepare_identity", fake_prepare)
    coordinator = PowCoordinator(tmp_path, PowStore(tmp_path), PowStatusStore(), log=logs.append)
    assert coordinator._fetch_key(C.PowSettings(key_fetch="oob"), "masque", "MASQUE") is None
    assert calls == ["oob"]
    assert any(line.startswith("Key fetch for MASQUE: OOB only") for line in logs)
    assert any(line.startswith("Key fetch done") and "via OOB" in line for line in logs)


def test_oob_method_win_is_logged_and_named_in_done_line(tmp_path, monkeypatch):
    logs: list[str] = []

    def fake_prepare(*args, api_camo=None, on_log=None, **kwargs):
        if on_log:
            on_log("Key: trying OOB first: disoob-byte0-ttl1, then oob-insni+5-ttl1, then oob-byte0-nottl (one at a time)")
            on_log("Key: OOB method disoob-byte0-ttl1 failed: OOB disoob-byte0-ttl1 api.cloudflareclient.com: handshake timed out")
            on_log("Key: OOB method oob-insni+5-ttl1 won (POST /v0a4471/reg answered 200)")
            on_log("Key: account key won via oob (OOB method oob-insni+5-ttl1 won)")
        return {"ipv4": "x"}

    monkeypatch.setattr("uac_desktop.pow.coordinator.prepare_identity", fake_prepare)
    coordinator = PowCoordinator(tmp_path, PowStore(tmp_path), PowStatusStore(), log=logs.append)
    assert coordinator._fetch_key(C.PowSettings(), "masque", "MASQUE") is None
    assert coordinator._key_route == "oob"
    assert any(line == "Key fetch: OOB method oob-insni+5-ttl1 won" for line in logs)
    assert any(line.startswith("Key fetch for MASQUE: OOB first, one method at a time") for line in logs)
    assert any(line.startswith("Key fetch done") and "via OOB (oob-insni+5-ttl1)" in line for line in logs)
