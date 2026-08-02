from __future__ import annotations

import copy
import json

import uac_desktop.storage as storage_module
from uac_desktop.models import Tuning
from uac_desktop.storage import Storage


_COMPATIBILITY_SIGNATURE_FIELDS = (
    "mode",
    "xray_mux_enabled",
    "xray_mux_concurrency",
    "background_quality_probe_enabled",
    "background_quality_probe_delay_s",
    "log_level",
    "pattern_quality_preset",
    "pattern_inject_delay_ms",
    "pattern_ack_timeout_ms",
    "pattern_connect_timeout_ms",
    "pattern_relay_buffer_kb",
    "pattern_socket_buffer_kb",
    "pattern_max_sessions",
    "pattern_edge_failure_cooldown_s",
    "pattern_keepalive_idle_s",
    "pattern_keepalive_interval_s",
    "pattern_keepalive_count",
    "pattern_upload_optimized",
)


def _redirect_storage(monkeypatch, tmp_path):
    paths = {
        "SETTINGS_FILE": tmp_path / "settings.json",
        "PROFILES_FILE": tmp_path / "profiles.json",
        "BOOKMARKS_FILE": tmp_path / "bookmarks.json",
        "SNI_RESULTS_FILE": tmp_path / "sni-results.json",
    }
    for name, path in paths.items():
        monkeypatch.setattr(storage_module, name, path)
    return paths


def _legacy_mci_compatibility() -> Tuning:
    """Reproduce the v1 MCI record seen in persisted settings."""
    value = Tuning.carrier_preset("mci")
    compatibility = Tuning.preset("compatibility")
    for name in _COMPATIBILITY_SIGNATURE_FIELDS:
        setattr(value, name, getattr(compatibility, name))
    assert value.is_legacy_mci_compatibility()
    return value


def _write_v1_settings(path, *, active: dict, mci: dict, irancell: dict) -> None:
    path.write_text(json.dumps({
        "tuning": active,
        "carrier_tunings": {
            "auto": Tuning.carrier_preset("auto").to_dict(),
            "mci": mci,
            "irancell": irancell,
        },
        "speed_core_version": 3,
        "pattern_core_version": 1,
        "carrier_tuning_version": 1,
        "migration_sentinel": {"keep": [1, 2, 3]},
    }, ensure_ascii=False, indent=2), encoding="utf-8")


def test_carrier_v2_upgrades_only_slow_mci_and_preserves_route_sni_irancell(tmp_path, monkeypatch):
    paths = _redirect_storage(monkeypatch, tmp_path)
    active_auto = Tuning.carrier_preset("auto").to_dict()
    slow_mci = _legacy_mci_compatibility()
    slow_mci.pattern_connect_ip = "203.0.113.10"
    slow_mci.pattern_fallback_ips = (
        "203.0.113.10, 198.51.100.20,198.51.100.20,198.51.100.21,203.0.113.10"
    )
    slow_mci.pattern_fake_sni = "measured.mci.example"
    slow_mci.pattern_use_profile_edges = True

    irancell = Tuning.carrier_preset("irancell").to_dict()
    irancell["mode"] = "custom"
    irancell["pattern_socket_buffer_kb"] = 3584
    irancell["future_irancell_field"] = {"must": "survive exactly"}
    original_irancell = copy.deepcopy(irancell)
    _write_v1_settings(
        paths["SETTINGS_FILE"],
        active=active_auto,
        mci=slow_mci.to_dict(),
        irancell=irancell,
    )

    Storage()
    migrated = json.loads(paths["SETTINGS_FILE"].read_text(encoding="utf-8"))

    expected_mci = Tuning.carrier_preset("mci").to_dict()
    assert migrated["carrier_tuning_version"] == 3
    assert migrated["carrier_tunings"]["mci"] == expected_mci
    assert migrated["carrier_tunings"]["irancell"] == original_irancell
    assert migrated["tuning"] == active_auto
    assert migrated["migration_sentinel"] == {"keep": [1, 2, 3]}


    first_pass = paths["SETTINGS_FILE"].read_bytes()
    Storage()
    assert paths["SETTINGS_FILE"].read_bytes() == first_pass


def test_carrier_v2_upgrades_active_mci_copy_and_repairs_all_duplicate_fallbacks(
        tmp_path, monkeypatch):
    paths = _redirect_storage(monkeypatch, tmp_path)
    active_mci = _legacy_mci_compatibility()
    active_mci.pattern_connect_ip = "188.114.99.0"
    active_mci.pattern_fallback_ips = "188.114.99.0, 188.114.99.0"
    active_mci.pattern_fake_sni = "active-route.example"
    active_mci.pattern_use_profile_edges = True
    stored_mci = Tuning.carrier_preset("mci").to_dict()
    irancell = Tuning.carrier_preset("irancell").to_dict()
    original_irancell = copy.deepcopy(irancell)
    _write_v1_settings(
        paths["SETTINGS_FILE"],
        active=active_mci.to_dict(),
        mci=stored_mci,
        irancell=irancell,
    )

    Storage()
    migrated = json.loads(paths["SETTINGS_FILE"].read_text(encoding="utf-8"))
    active = migrated["tuning"]

    assert active["mode"] == "compatibility"
    assert active["pattern_max_sessions"] == 4
    assert active["pattern_socket_buffer_kb"] == 512
    assert active["pattern_connect_ip"] == "104.18.1.1"
    assert active["pattern_fallback_ips"] == "172.66.0.1"
    assert active["pattern_fake_sni"] == "www.speedtest.net"
    assert active["pattern_use_profile_edges"] is False
    assert migrated["carrier_tunings"]["mci"] == stored_mci
    assert migrated["carrier_tunings"]["irancell"] == original_irancell


def test_carrier_v2_leaves_near_match_custom_mci_and_irancell_exactly_unchanged(
        tmp_path, monkeypatch):
    paths = _redirect_storage(monkeypatch, tmp_path)
    custom_mci = _legacy_mci_compatibility()


    custom_mci.pattern_ack_timeout_ms = 7999
    custom_mci.pattern_connect_ip = "203.0.113.44"
    custom_mci.pattern_fallback_ips = "203.0.113.44,203.0.113.45"
    custom_mci.pattern_fake_sni = "custom.example"
    assert not custom_mci.is_legacy_mci_compatibility()

    original_mci = custom_mci.to_dict()
    irancell = Tuning.carrier_preset("irancell").to_dict()
    irancell["future_irancell_field"] = ["opaque", {"value": 9}]
    original_irancell = copy.deepcopy(irancell)
    _write_v1_settings(
        paths["SETTINGS_FILE"],
        active=copy.deepcopy(original_mci),
        mci=copy.deepcopy(original_mci),
        irancell=irancell,
    )

    Storage()
    migrated = json.loads(paths["SETTINGS_FILE"].read_text(encoding="utf-8"))

    expected_mci = Tuning.carrier_preset("mci").to_dict()
    expected_mci["log_level"] = original_mci["log_level"]
    assert migrated["carrier_tuning_version"] == 3
    assert migrated["carrier_tunings"]["mci"] == expected_mci
    assert migrated["tuning"] == expected_mci
    assert migrated["carrier_tunings"]["irancell"] == original_irancell


def test_carrier_v3_repairs_tampered_mci_and_is_idempotent(tmp_path, monkeypatch):
    paths = _redirect_storage(monkeypatch, tmp_path)
    tampered = Tuning.carrier_preset("mci").to_dict()
    tampered.update({
        "pattern_connect_ip": "203.0.113.17",
        "pattern_fake_sni": "tampered.example",
        "pattern_max_sessions": 63,
        "log_level": "minimal",
    })
    irancell = Tuning.carrier_preset("irancell").to_dict()
    irancell["future_irancell_field"] = {"keep": True}
    paths["SETTINGS_FILE"].write_text(json.dumps({
        "tuning": copy.deepcopy(tampered),
        "carrier_tunings": {
            "auto": Tuning.carrier_preset("auto").to_dict(),
            "mci": copy.deepcopy(tampered),
            "irancell": copy.deepcopy(irancell),
        },
        "speed_core_version": 3,
        "pattern_core_version": 1,
        "carrier_tuning_version": 3,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    Storage()
    migrated = json.loads(paths["SETTINGS_FILE"].read_text(encoding="utf-8"))
    expected = Tuning.carrier_preset("mci").to_dict()
    expected["log_level"] = "minimal"
    assert migrated["tuning"] == expected
    assert migrated["carrier_tunings"]["mci"] == expected
    assert migrated["carrier_tunings"]["irancell"] == irancell

    first_pass = paths["SETTINGS_FILE"].read_bytes()
    Storage()
    assert paths["SETTINGS_FILE"].read_bytes() == first_pass
