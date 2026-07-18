from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from .app_config import UPDATE_REPOSITORY_URL
from .models import ProxyProfile, Tuning, default_profiles
from .paths import BOOKMARKS_FILE, PROFILES_FILE, SETTINGS_FILE, SNI_RESULTS_FILE


_IO_LOCK = threading.RLock()
_SPEED_CORE_VERSION = 3
_CARRIER_TUNING_VERSION = 2
_UPDATE_REPOSITORY_VERSION = 1
_CARRIERS = ("auto", "mci", "irancell")
_LEGACY_UPDATE_REPOSITORIES = {
    f"https://github.com/floxu1/uac-sni-spoofer-{platform}"
    for platform in ("android", "androids")
}
_UPDATE_CACHE_KEYS = (
    "last_update_checked_at",
    "latest_version",
    "latest_tag",
    "latest_release_name",
    "latest_release_url",
    "update_available",
    "last_update_repo_url",
    "last_update_current_version",
    "notified_update_version",
)


def _read(path: Path, fallback):
    with _IO_LOCK:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return fallback


def _write(path: Path, value) -> None:
    with _IO_LOCK:
        temp = path.with_suffix(path.suffix + f".{os.getpid()}.{threading.get_ident()}.tmp")
        try:
            temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
            temp.replace(path)
        finally:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass


class Storage:
    def __init__(self) -> None:
        self.settings = _read(SETTINGS_FILE, {})
        self.profiles = self._load_profiles()
        self.bookmarks = _read(BOOKMARKS_FILE, [])
        self.scan_results = _read(SNI_RESULTS_FILE, [])
        if not isinstance(self.scan_results, list):
            self.scan_results = []
        # Older builds only persisted bookmarks. Seed the searchable result
        # repository from them so the Pattern core can immediately select a
        # measured Fake SNI without forcing the user to rescan.
        if not self.scan_results and isinstance(self.bookmarks, list):
            self.scan_results = [dict(item) for item in self.bookmarks if isinstance(item, dict)]
            if self.scan_results:
                self.save_scan_results()
        self._migrate_update_repository()
        # Speed migration must run first so its mode-aware Pattern defaults are
        # not pre-filled with generic values by the older core migration.
        self._migrate_speed_core()
        self._migrate_pattern_core()
        self._migrate_carrier_tunings()

    @staticmethod
    def _normalized_repository_url(value: object) -> str:
        normalized = str(value or "").strip().lower().rstrip("/")
        if normalized.endswith(".git"):
            normalized = normalized[:-4]
        return normalized.replace("https://www.github.com/", "https://github.com/", 1)

    def _migrate_update_repository(self) -> None:
        current = str(self.settings.get("update_repo_url", "") or "").strip()
        normalized = self._normalized_repository_url(current)
        replace_repository = not normalized or normalized in _LEGACY_UPDATE_REPOSITORIES
        changed = False
        if replace_repository and current != UPDATE_REPOSITORY_URL:
            self.settings["update_repo_url"] = UPDATE_REPOSITORY_URL
            changed = True
        if replace_repository:
            for key in _UPDATE_CACHE_KEYS:
                if key in self.settings:
                    self.settings.pop(key, None)
                    changed = True
        if self.settings.get("update_repository_version") != _UPDATE_REPOSITORY_VERSION:
            self.settings["update_repository_version"] = _UPDATE_REPOSITORY_VERSION
            changed = True
        if changed:
            self.save_settings()

    def _migrate_pattern_core(self) -> None:
        """Add Patterniha quality defaults without touching user profiles."""
        if self.settings.get("pattern_core_version") == 1:
            return
        tuning = self.settings.get("tuning", {})
        if not isinstance(tuning, dict):
            tuning = {}
        defaults = Tuning().to_dict()
        for key, value in defaults.items():
            if key.startswith("pattern_"):
                tuning.setdefault(key, value)
        # Legacy probes/fragment races are not part of the new core and caused
        # connection amplification during large uploads.
        tuning["fake_probe_enabled"] = False
        tuning["fake_probe_count"] = 0
        tuning["initial_race_enabled"] = False
        tuning["warm_tcp_pool_enabled"] = False
        tuning["log_level"] = "minimal"
        self.settings["tuning"] = tuning
        self.settings["pattern_core_version"] = 1
        self.save_settings()

    def _migrate_speed_core(self) -> None:
        """Add speed controls using the user's existing quality preset."""
        previous_version = int(self.settings.get("speed_core_version", 0) or 0)
        if previous_version >= _SPEED_CORE_VERSION:
            return
        tuning = self.settings.get("tuning", {})
        if not isinstance(tuning, dict):
            tuning = {}

        mode = str(tuning.get("mode", "") or "").strip().lower()
        pattern_preset = str(tuning.get("pattern_quality_preset", "") or "").strip().lower()
        preset_aliases = {
            "maximum": "maximum", "upload": "upload",
            "streaming": "streaming",
            "fast": "fast", "low_latency": "low_latency",
            "compatibility": "compatibility", "stealth": "stealth",
            "balanced": "balanced",
        }
        # Named app modes are authoritative. Custom/legacy modes fall back to
        # the Pattern preset, while their explicit values remain untouched.
        preset_name = preset_aliases.get(mode)
        if preset_name is None:
            preset_name = preset_aliases.get(pattern_preset, "balanced")
        defaults = Tuning.preset(preset_name).to_dict()
        speed_keys = (
            "xray_mux_enabled", "xray_mux_concurrency",
            "background_quality_probe_enabled", "background_quality_probe_delay_s",
            "pattern_edge_failure_cooldown_s", "pattern_keepalive_interval_s",
            "pattern_keepalive_count", "pattern_max_sessions",
        )
        for key in speed_keys:
            tuning.setdefault(key, defaults[key])
        try:
            session_cap = int(tuning.get("pattern_max_sessions", defaults["pattern_max_sessions"]) or 0)
        except (TypeError, ValueError):
            session_cap = int(defaults["pattern_max_sessions"])
            tuning["pattern_max_sessions"] = session_cap

        mode_family = {
            "fast": "fast", "low_latency": "fast",
            "streaming": "streaming",
            "compatibility": "compatibility", "stealth": "compatibility",
        }.get(mode)

        # Only throughput-oriented modes lift the old 4-6 cap. A small cap in
        # a custom/unknown or compatibility mode is an intentional choice.
        if mode_family in {"fast", "streaming"} and session_cap <= 6:
            tuning["pattern_max_sessions"] = 10

        # Streaming and compatibility intentionally avoid mux head-of-line
        # blocking. This also corrects the generic value written by v2.
        previous_mux = tuning.get("xray_mux_enabled")
        if mode_family in {"streaming", "compatibility"}:
            tuning["xray_mux_enabled"] = False

        # Restore the exact v2-generated compatibility shape without changing
        # other explicit low or custom caps.
        if (mode_family == "compatibility" and previous_version == 2
                and previous_mux is True and session_cap == 10):
            tuning["pattern_max_sessions"] = defaults["pattern_max_sessions"]
        # The former echo probe started four seconds after connect and competed
        # with the user's first page/video. Keep it explicitly opt-in.
        tuning.setdefault("background_quality_probe_enabled", False)
        self.settings["tuning"] = tuning
        self.settings["speed_core_version"] = _SPEED_CORE_VERSION
        self.settings.setdefault("update_repo_url", UPDATE_REPOSITORY_URL)
        self.save_settings()

    @staticmethod
    def _carrier_name(value: str) -> str:
        value = str(value or "auto").strip().lower()
        return value if value in _CARRIERS else "auto"

    def _best_saved_edge(self, carrier: str, domain: str = "") -> str:
        candidates = []
        for raw in self.scan_results:
            if (not isinstance(raw, dict) or not raw.get("success", True)
                    or not raw.get("edge_verified", False)):
                continue
            if self._carrier_name(raw.get("carrier", "auto")) != carrier:
                continue
            if domain and str(raw.get("domain", "")).strip().lower() != domain.lower():
                continue
            edge = str(raw.get("edge", "") or "").strip()
            if edge:
                candidates.append((float(raw.get("score", -9999) or -9999),
                                   float(raw.get("tested_at", 0) or 0), edge))
        return max(candidates, default=(0, 0, ""))[2]

    @staticmethod
    def _upgrade_mci_turbo(tuning: Tuning) -> Tuning:
        """Replace only the known slow MCI shape and retain measured routing."""
        if not tuning.is_legacy_mci_compatibility():
            return tuning

        turbo = Tuning.carrier_preset("mci")
        route_primary = str(tuning.pattern_connect_ip or "").strip() or turbo.pattern_connect_ip
        raw_fallbacks = str(tuning.pattern_fallback_ips or "")

        # A verified edge was sometimes copied into both the primary and
        # fallback slots. Keep the user's fallback order, but remove the
        # primary and repeated entries. If nothing remains, seed one distinct
        # MCI default so failover is still possible.
        seen = {route_primary.casefold()}
        route_fallbacks: list[str] = []
        for item in raw_fallbacks.split(","):
            item = item.strip()
            key = item.casefold()
            if not item or key in seen:
                continue
            seen.add(key)
            route_fallbacks.append(item)
        if not route_fallbacks:
            defaults = f"{turbo.pattern_fallback_ips},{turbo.pattern_connect_ip}"
            for item in defaults.split(","):
                item = item.strip()
                key = item.casefold()
                if not item or key in seen:
                    continue
                seen.add(key)
                route_fallbacks.append(item)
                break

        fake_sni = str(tuning.pattern_fake_sni or "").strip() or turbo.pattern_fake_sni
        turbo.pattern_connect_ip = route_primary
        turbo.pattern_fallback_ips = ",".join(route_fallbacks)
        turbo.pattern_fake_sni = fake_sni
        turbo.pattern_use_profile_edges = bool(tuning.pattern_use_profile_edges)
        return turbo

    def _initialize_carrier_tunings_v1(self) -> None:
        """Split legacy Advanced settings/caches into carrier-owned buckets."""
        raw_current = self.settings.get("tuning", {})
        current = Tuning.from_dict(raw_current if isinstance(raw_current, dict) else {})
        active = self._carrier_name(current.carrier_mode)
        raw_map = self.settings.get("carrier_tunings", {})
        raw_map = dict(raw_map) if isinstance(raw_map, dict) else {}

        tunings: dict[str, dict] = {}
        for carrier in _CARRIERS:
            raw = raw_map.get(carrier)
            if isinstance(raw, dict):
                value = Tuning.from_dict(raw)
            elif carrier == active:
                value = Tuning.from_dict(current.to_dict())
            else:
                value = Tuning.carrier_preset(carrier)
            value.carrier_mode = carrier
            remembered_sni = str(self.settings.get(f"working_pattern_sni_{carrier}", "") or "").strip()
            if remembered_sni and not isinstance(raw, dict):
                value.pattern_fake_sni = remembered_sni
            saved_edge = self._best_saved_edge(carrier, remembered_sni)
            if saved_edge and carrier != active and not isinstance(raw, dict):
                value.pattern_connect_ip = saved_edge
            if carrier == "mci":
                value = self._upgrade_mci_turbo(value)
            tunings[carrier] = value.to_dict()

        # Migrate global SNI pins only into the active carrier. Per-carrier
        # remembered winners seed the other carrier without leaking edits.
        scoped_pins = self.settings.get("pattern_profile_sni_pins_by_carrier", {})
        scoped_pins = dict(scoped_pins) if isinstance(scoped_pins, dict) else {}
        legacy_pins = self.settings.get("pattern_profile_sni_pins", {})
        if isinstance(legacy_pins, dict) and legacy_pins:
            scoped_pins.setdefault(active, dict(legacy_pins))
        scoped_globals = self.settings.get("pattern_global_sni_pin_by_carrier", {})
        scoped_globals = dict(scoped_globals) if isinstance(scoped_globals, dict) else {}
        legacy_global = self.settings.get("pattern_global_sni_pin")
        if legacy_global:
            scoped_globals.setdefault(active, legacy_global)
        for carrier in ("mci", "irancell"):
            remembered = self.settings.get(f"working_pattern_sni_{carrier}")
            if remembered:
                scoped_globals.setdefault(carrier, remembered)

        # Route old Mux evidence to the carrier whose working profile produced
        # it. Unknown entries remain only under the active carrier.
        scoped_mux = self.settings.get("profile_mux_compatibility_by_carrier", {})
        scoped_mux = dict(scoped_mux) if isinstance(scoped_mux, dict) else {}
        legacy_mux = self.settings.get("profile_mux_compatibility", {})
        if isinstance(legacy_mux, dict):
            for profile_id, entry in legacy_mux.items():
                owners = [carrier for carrier in ("mci", "irancell")
                          if self.settings.get(f"working_profile_{carrier}") == profile_id]
                for carrier in owners or [active]:
                    bucket = scoped_mux.setdefault(carrier, {})
                    if isinstance(bucket, dict):
                        bucket.setdefault(profile_id, entry)

        self.settings["carrier_tunings"] = tunings
        self.settings["pattern_profile_sni_pins_by_carrier"] = scoped_pins
        self.settings["pattern_global_sni_pin_by_carrier"] = scoped_globals
        self.settings["profile_mux_compatibility_by_carrier"] = scoped_mux
        self.settings["tuning"] = tunings[active]

    def _migrate_mci_turbo_v2(self) -> None:
        """Upgrade the exact legacy MCI record without rebuilding other carriers."""
        raw_map = self.settings.get("carrier_tunings")
        if isinstance(raw_map, dict):
            raw_mci = raw_map.get("mci")
            if isinstance(raw_mci, dict):
                mci = Tuning.from_dict(raw_mci)
                if mci.is_legacy_mci_compatibility():
                    migrated = dict(raw_map)
                    migrated["mci"] = self._upgrade_mci_turbo(mci).to_dict()
                    self.settings["carrier_tunings"] = migrated

        # The active tuning is persisted separately for startup. Do not copy
        # the map entry over it: upgrade it only when it independently has the
        # same MCI compatibility signature, preserving its own route/SNI.
        raw_active = self.settings.get("tuning")
        if isinstance(raw_active, dict):
            active = Tuning.from_dict(raw_active)
            if active.is_legacy_mci_compatibility():
                self.settings["tuning"] = self._upgrade_mci_turbo(active).to_dict()

    def _migrate_carrier_tunings(self) -> None:
        """Run carrier isolation v1, then the narrow idempotent MCI v2 repair."""
        try:
            previous_version = int(self.settings.get("carrier_tuning_version", 0) or 0)
        except (TypeError, ValueError):
            previous_version = 0
        if previous_version >= _CARRIER_TUNING_VERSION:
            return
        if previous_version < 1:
            self._initialize_carrier_tunings_v1()
        self._migrate_mci_turbo_v2()
        self.settings["carrier_tuning_version"] = _CARRIER_TUNING_VERSION
        self.save_settings()

    def _load_profiles(self) -> list[ProxyProfile]:
        raw = _read(PROFILES_FILE, [])
        profiles = [ProxyProfile.from_dict(x) for x in raw if isinstance(x, dict)]
        if not profiles:
            profiles = default_profiles()
            _write(PROFILES_FILE, [x.to_dict() for x in profiles])
        return profiles

    @property
    def selected_id(self) -> str:
        selected = self.settings.get("selected_id", "")
        if any(x.id == selected for x in self.profiles):
            return selected
        return self.profiles[0].id if self.profiles else ""

    @selected_id.setter
    def selected_id(self, value: str) -> None:
        self.settings["selected_id"] = value
        self.save_settings()

    @property
    def tuning(self) -> Tuning:
        return Tuning.from_dict(self.settings.get("tuning", {}))

    def set_tuning(self, tuning: Tuning) -> None:
        carrier = self._carrier_name(tuning.carrier_mode)
        tuning.carrier_mode = carrier
        values = self.settings.get("carrier_tunings", {})
        values = dict(values) if isinstance(values, dict) else {}
        values[carrier] = tuning.to_dict()
        self.settings["carrier_tunings"] = values
        self.settings["tuning"] = tuning.to_dict()
        self.save_settings()

    def tuning_for_carrier(self, carrier: str) -> Tuning:
        carrier = self._carrier_name(carrier)
        values = self.settings.get("carrier_tunings", {})
        raw = values.get(carrier) if isinstance(values, dict) else None
        tuning = Tuning.from_dict(raw) if isinstance(raw, dict) else Tuning.carrier_preset(carrier)
        tuning.carrier_mode = carrier
        return tuning

    def all_carrier_tunings(self) -> dict[str, Tuning]:
        return {carrier: self.tuning_for_carrier(carrier) for carrier in _CARRIERS}

    def activate_carrier(self, carrier: str) -> Tuning:
        carrier = self._carrier_name(carrier)
        current = self.tuning
        values = self.settings.get("carrier_tunings", {})
        values = dict(values) if isinstance(values, dict) else {}
        current_carrier = self._carrier_name(current.carrier_mode)
        values[current_carrier] = current.to_dict()
        target = self.tuning_for_carrier(carrier)
        values[carrier] = target.to_dict()
        self.settings["carrier_tunings"] = values
        self.settings["tuning"] = target.to_dict()
        self.save_settings()
        return target

    def set_carrier_tunings(self, values: dict[str, Tuning], active_carrier: str) -> Tuning:
        stored = self.settings.get("carrier_tunings", {})
        stored = dict(stored) if isinstance(stored, dict) else {}
        for carrier, tuning in values.items():
            carrier = self._carrier_name(carrier)
            tuning.carrier_mode = carrier
            stored[carrier] = tuning.to_dict()
        active_carrier = self._carrier_name(active_carrier)
        active = Tuning.from_dict(stored.get(active_carrier, Tuning.carrier_preset(active_carrier).to_dict()))
        active.carrier_mode = active_carrier
        stored[active_carrier] = active.to_dict()
        self.settings["carrier_tunings"] = stored
        self.settings["tuning"] = active.to_dict()
        self.save_settings()
        return active

    def save_profiles(self) -> None:
        _write(PROFILES_FILE, [x.to_dict() for x in self.profiles])

    def save_settings(self) -> None:
        _write(SETTINGS_FILE, self.settings)

    def save_bookmarks(self) -> None:
        _write(BOOKMARKS_FILE, self.bookmarks)

    def save_scan_results(self) -> None:
        _write(SNI_RESULTS_FILE, self.scan_results)

    def selected(self) -> ProxyProfile | None:
        return next((x for x in self.profiles if x.id == self.selected_id), None)
