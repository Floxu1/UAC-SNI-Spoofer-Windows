import time
from types import SimpleNamespace

from uac_desktop.network import ScanResult
from uac_desktop.storage import Storage
from uac_desktop.ui import MainWindow


class ProgressStub:
    def __init__(self):
        self.values = []
        self.formats = []

    def setValue(self, value):
        self.values.append(value)

    def setFormat(self, value):
        self.formats.append(value)


class ActivityStub:
    def __init__(self):
        self.messages = []

    def set_activity(self, *value):
        self.messages.append(value)


def _scan_dummy(generation=7):
    streamed = []
    dummy = SimpleNamespace(
        _scan_generation=generation,
        scanning=True,
        scan_progress=ProgressStub(),
        activity_bar=ActivityStub(),
        language="fa",
        storage=SimpleNamespace(tuning=SimpleNamespace(
            carrier_mode="irancell", pattern_connect_ip="104.19.229.21")),
        _scan_context={
            "generation": generation,
            "carrier": "irancell",
            "edge": "104.19.229.21",
        },
        _scan_results_by_domain={},
        _upsert_scan_result=streamed.append,
        tr=lambda fa, en=None: fa,
    )
    return dummy, streamed


def test_successful_sni_is_streamed_before_scan_done():
    dummy, streamed = _scan_dummy()
    result = ScanResult(
        domain="support.cloudflare.com",
        success=True,
        score=900,
        edge="104.19.229.21",
        edge_verified=True,
    )

    MainWindow._scan_progress(dummy, 1, 20, result, 7)

    assert dummy.scan_progress.values == [1]
    assert dummy.scan_progress.formats[-1].startswith("1/20")
    assert streamed == [result]
    assert dummy._scan_results_by_domain[result.domain] is result
    assert result.carrier == "irancell"
    assert result.edge == "104.19.229.21"
    assert result.edge_verified is True
    assert result.tested_at > 0


def test_failed_or_stale_sni_is_not_inserted_into_live_table():
    dummy, streamed = _scan_dummy()
    MainWindow._scan_progress(dummy, 1, 2, ScanResult(domain="failed.example"), 7)
    MainWindow._scan_progress(dummy, 2, 2, ScanResult(domain="stale.example", success=True), 6)

    assert streamed == []
    assert dummy.scan_progress.values == [1]


def test_recent_working_sni_precedes_higher_unverified_lab_score():
    dummy = SimpleNamespace(storage=SimpleNamespace(
        scan_results=[
            {"domain": "new-score.example", "success": True, "score": 1200},
            {"domain": "working.example", "success": True, "score": 600},
        ],
        bookmarks=[],
        settings={
            "working_pattern_sni_irancell": "working.example",
            "working_pattern_sni_at_irancell": time.time(),
        },
        tuning=SimpleNamespace(carrier_mode="irancell"),
    ))

    assert MainWindow._sni_candidates(dummy, carrier="irancell", limit=2) == [
        "working.example", "new-score.example"
    ]


def _migrated_tuning(tuning, version=0):
    storage = Storage.__new__(Storage)
    storage.settings = {"tuning": dict(tuning), "speed_core_version": version}
    storage.save_settings = lambda: None
    Storage._migrate_speed_core(storage)
    return storage.settings["tuning"], storage.settings["speed_core_version"]


def test_speed_migration_lifts_old_fast_handshake_cap():
    tuning, version = _migrated_tuning({"mode": "fast", "pattern_max_sessions": 6})

    assert tuning["pattern_max_sessions"] == 10
    assert tuning["xray_mux_enabled"] is True
    assert tuning["background_quality_probe_enabled"] is False
    assert version == 3


def test_speed_migration_uses_streaming_mux_and_session_defaults():
    tuning, version = _migrated_tuning({"mode": "streaming"})

    assert tuning["xray_mux_enabled"] is False
    assert tuning["xray_mux_concurrency"] == 4
    assert tuning["pattern_max_sessions"] == 10
    assert tuning["pattern_keepalive_interval_s"] == 2
    assert version == 3


def test_speed_migration_preserves_compatibility_and_stealth_low_caps():
    for mode, cap in (("compatibility", 4), ("stealth", 5)):
        tuning, _ = _migrated_tuning({
            "mode": mode,
            "pattern_max_sessions": cap,
            "xray_mux_enabled": True,
        })
        assert tuning["pattern_max_sessions"] == cap
        assert tuning["xray_mux_enabled"] is False


def test_speed_migration_repairs_v2_generic_compatibility_defaults():
    tuning, version = _migrated_tuning({
        "mode": "compatibility",
        "pattern_quality_preset": "compatibility",
        "pattern_max_sessions": 10,
        "xray_mux_enabled": True,
    }, version=2)

    assert tuning["pattern_max_sessions"] == 4
    assert tuning["xray_mux_enabled"] is False
    assert version == 3


def test_speed_migration_uses_pattern_preset_for_missing_custom_values():
    tuning, _ = _migrated_tuning({
        "mode": "custom",
        "pattern_quality_preset": "streaming",
        "pattern_max_sessions": 5,
    })

    assert tuning["pattern_max_sessions"] == 5
    assert tuning["xray_mux_enabled"] is False
    assert tuning["xray_mux_concurrency"] == 4
    assert tuning["pattern_keepalive_interval_s"] == 2


def test_speed_migration_preserves_unknown_mode_explicit_low_cap():
    tuning, _ = _migrated_tuning({
        "mode": "my-private-profile",
        "pattern_quality_preset": "low_latency",
        "pattern_max_sessions": 3,
        "xray_mux_enabled": False,
    })

    assert tuning["pattern_max_sessions"] == 3
    assert tuning["xray_mux_enabled"] is False
    assert tuning["pattern_edge_failure_cooldown_s"] == 6
