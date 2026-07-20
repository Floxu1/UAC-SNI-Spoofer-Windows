from __future__ import annotations

import json
import re
import threading
import time
import uuid
from types import SimpleNamespace

import uac_desktop.storage as storage_module
import uac_desktop.ui as ui_module
from uac_desktop.models import BUILTIN_CONFIGS, Tuning, parse_many
from uac_desktop.storage import Storage
from uac_desktop.ui import MainWindow
from uac_desktop.network import GeoLocation


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


def test_existing_install_receives_verified_snapshot_once(tmp_path, monkeypatch):
    paths = _redirect_storage(monkeypatch, tmp_path)
    legacy = parse_many(BUILTIN_CONFIGS, suggested=True)
    paths["PROFILES_FILE"].write_text(
        json.dumps([profile.to_dict() for profile in legacy]), encoding="utf-8"
    )

    storage = Storage()
    assert len(storage.profiles) == 60
    assert len([profile for profile in storage.profiles if profile.verified_spoof]) == 54
    assert storage.settings["verified_configs_version"] == 5
    assert storage.settings["proxy_mode"] is True
    assert "close_to_tray" not in storage.settings

    first_profiles = paths["PROFILES_FILE"].read_bytes()
    reloaded = Storage()
    assert len(reloaded.profiles) == 60
    assert paths["PROFILES_FILE"].read_bytes() == first_profiles


def test_verified_snapshot_has_no_hand_entered_ping_suffix():
    verified = storage_module.verified_profiles()

    assert len(verified) == 54
    assert all(re.fullmatch(r"SPOOF-\d{3}-[A-Z]{2}",
                            profile.source_uri.rsplit("#", 1)[-1])
               for profile in verified)
    assert all(not re.search(r"\b\d+\s*ms$", profile.name, re.I)
               for profile in verified)
    assert all(profile.country_latency_ms == 0 for profile in verified)


def test_v4_latency_labels_are_migrated_in_place(tmp_path, monkeypatch):
    paths = _redirect_storage(monkeypatch, tmp_path)
    legacy = parse_many(BUILTIN_CONFIGS, suggested=True)
    old_verified = storage_module.verified_profiles()
    old_ids = set()
    for index, profile in enumerate(old_verified, 1):
        profile.source_uri += f"-{900 + index}ms"
        profile.name += f" · {900 + index} ms"
        profile.country_latency_ms = 900 + index
        old_ids.add(profile.id)
    paths["PROFILES_FILE"].write_text(
        json.dumps([profile.to_dict() for profile in [*legacy, *old_verified]]),
        encoding="utf-8",
    )
    paths["SETTINGS_FILE"].write_text(
        json.dumps({"verified_configs_version": 4}), encoding="utf-8"
    )

    storage = Storage()
    verified = [profile for profile in storage.profiles if profile.verified_spoof]

    assert len(storage.profiles) == 60
    assert len(verified) == 54
    assert old_ids == {profile.id for profile in verified}
    assert all(not re.search(r"-\d+ms$", profile.source_uri, re.I)
               for profile in verified)
    assert all(not re.search(r"\b\d+\s*ms$", profile.name, re.I)
               for profile in verified)
    assert all(profile.country_latency_ms == 0 for profile in verified)
    assert storage.settings["verified_configs_version"] == 5


def test_v1_manual_imports_are_adopted_for_country_picker(tmp_path, monkeypatch):
    paths = _redirect_storage(monkeypatch, tmp_path)
    legacy = parse_many(BUILTIN_CONFIGS, suggested=True)
    imported = storage_module.verified_profiles()[:46]
    imported_ids = set()
    for profile in imported:
        profile.id = str(uuid.uuid4())
        imported_ids.add(profile.id)
        profile.name = profile.source_uri.rsplit("#", 1)[-1]
        profile.origin = "user"
        profile.country_code = ""
        profile.country_latency_ms = 0
        profile.verified_spoof = False
        profile.spoof_fake_sni = ""
    paths["PROFILES_FILE"].write_text(
        json.dumps([profile.to_dict() for profile in [*legacy, *imported]]),
        encoding="utf-8",
    )
    paths["SETTINGS_FILE"].write_text(
        json.dumps({"verified_configs_version": 1}), encoding="utf-8"
    )

    storage = Storage()
    verified = [profile for profile in storage.profiles if profile.verified_spoof]

    assert len(verified) == 54
    assert len(storage.profiles) == 60
    assert imported_ids.issubset({profile.id for profile in verified})
    assert all(profile.origin == "verified" for profile in verified)
    assert storage.settings["verified_configs_version"] == 5


def test_country_mode_orders_only_the_selected_verified_profiles(monkeypatch):
    bundled = parse_many(BUILTIN_CONFIGS, suggested=True)
    verified = storage_module.verified_profiles()
    storage = SimpleNamespace(
        profiles=[*bundled, *verified], settings={"selected_country": "NL"}, tuning=Tuning(),
        save_profiles=lambda: None,
    )

    logs = []
    dummy = SimpleNamespace(
        storage=storage,
        bridge=SimpleNamespace(
            log=SimpleNamespace(emit=logs.append),
            latency=SimpleNamespace(emit=lambda *_args: None),
        ),
        _selected_country_code=lambda: "NL",
        _country_profiles=lambda code=None: [
            profile for profile in storage.profiles
            if profile.verified_spoof and profile.country_code == (code or "NL")
        ],
    )
    monkeypatch.setattr(ui_module, "profile_ping", lambda *_args: (True, 18.0))

    ordered = MainWindow._ordered_profiles(
        dummy, "static.cloudflare.com", threading.Event(),
        auto_enabled=True, manual_only=True,
    )

    assert len(ordered) == 14
    assert {profile.country_code for profile in ordered} == {"NL"}
    assert all(profile.verified_spoof for profile in ordered)


def test_verified_profile_forces_its_measured_spoof_route():
    profile = storage_module.verified_profiles()[0]
    base = Tuning(
        pattern_connect_ip="198.51.100.10",
        pattern_fallback_ips="198.51.100.11",
        pattern_use_profile_edges=True,
        pattern_fake_sni="old.example",
    )

    tuning = MainWindow._attempt_tuning_for_profile(
        profile, base, "static.cloudflare.com", False
    )

    assert tuning.pattern_connect_ip == "104.19.229.21"
    assert tuning.pattern_fallback_ips == ""
    assert tuning.pattern_use_profile_edges is False
    assert tuning.pattern_fake_sni == "static.cloudflare.com"
    assert tuning.xray_mux_enabled is False
    assert base.pattern_connect_ip == "198.51.100.10"


def test_rotating_exit_needs_fresh_observed_country_for_fixed_picker():
    rotating = next(profile for profile in storage_module.verified_profiles()
                    if profile.rotating_exit)
    stable = next(profile for profile in storage_module.verified_profiles()
                  if profile.country_code == "DE" and not profile.rotating_exit)
    rotating.country_code = "DE"
    storage = SimpleNamespace(profiles=[rotating, stable], settings={})
    dummy = SimpleNamespace(storage=storage)

    initial = MainWindow._country_profiles(dummy, rotating.country_code)
    assert stable in initial
    assert rotating not in initial

    rotating.observed_country_code = rotating.country_code
    rotating.country_verified_at = time.time()
    fresh = MainWindow._country_profiles(dummy, rotating.country_code)
    assert rotating in fresh


def test_live_exit_country_relabels_profile_and_preserves_route_id():
    profile = next(profile for profile in storage_module.verified_profiles()
                   if "SPOOF-026-" in profile.source_uri.rsplit("#", 1)[-1])
    original_id = profile.id
    saves = []
    logs = []
    dummy = SimpleNamespace(
        storage=SimpleNamespace(save_profiles=lambda: saves.append(True)),
        bridge=SimpleNamespace(log=SimpleNamespace(emit=logs.append)),
    )

    changed = MainWindow._record_profile_location(
        dummy, profile,
        GeoLocation(ip="8.221.169.111", country_code="JP", country="Japan",
                    city="Tokyo", source="ipwho.is"),
    )

    assert changed is True
    assert profile.id == original_id
    assert profile.country_code == "JP"
    assert profile.observed_exit_ip == "8.221.169.111"
    assert profile.name.startswith("Japan · Spoof 026")
    assert saves == [True]
    assert "country=JP" in logs[0]


def test_auto_off_ignores_country_and_uses_selected_manual_profile(monkeypatch):
    manual = parse_many(
        "trojan://password@example.com:443?security=tls&sni=example.com#manual"
    )[0]
    suggested = next(profile for profile in storage_module.verified_profiles()
                     if profile.country_code == "NL")

    class ModeStorage:
        profiles = [manual, suggested]
        settings = {"selected_country": "NL", "selected_id": manual.id}
        tuning = Tuning()

        def selected(self):
            return next(profile for profile in self.profiles
                        if profile.id == self.settings["selected_id"])

        def save_profiles(self):
            pass

    dummy = SimpleNamespace(
        storage=ModeStorage(),
        bridge=SimpleNamespace(
            log=SimpleNamespace(emit=lambda _line: None),
            latency=SimpleNamespace(emit=lambda *_args: None),
        ),
    )
    monkeypatch.setattr(ui_module, "profile_ping", lambda *_args: (True, 12.0))

    ordered = MainWindow._ordered_profiles(
        dummy, "static.cloudflare.com", threading.Event(),
        auto_enabled=False, manual_only=False,
    )

    assert ordered == [manual]


def test_auto_on_all_countries_uses_verified_suggested_not_manual(monkeypatch):
    manual = parse_many(
        "trojan://password@example.com:443?security=tls&sni=example.com#manual"
    )[0]
    suggested = next(profile for profile in storage_module.verified_profiles()
                     if profile.country_code == "NL")

    class ModeStorage:
        profiles = [manual, suggested]
        settings = {"selected_country": "ALL", "selected_id": manual.id}
        tuning = Tuning()

        def selected(self):
            return manual

        def save_profiles(self):
            pass

    dummy = SimpleNamespace(
        storage=ModeStorage(),
        bridge=SimpleNamespace(
            log=SimpleNamespace(emit=lambda _line: None),
            latency=SimpleNamespace(emit=lambda *_args: None),
        ),
    )
    monkeypatch.setattr(ui_module, "profile_ping", lambda *_args: (True, 12.0))

    ordered = MainWindow._ordered_profiles(
        dummy, "static.cloudflare.com", threading.Event(),
        auto_enabled=True, manual_only=True,
    )

    assert ordered == [suggested]
