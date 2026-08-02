from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest

from uac_desktop import __version__
import uac_desktop.ui as ui_module
from uac_desktop.engine import EngineCancelled
from uac_desktop.models import ProxyProfile, Tuning, default_profiles
from uac_desktop.network import ScanResult
from uac_desktop.ui import DEFAULT_UPDATE_REPO_URL, MainWindow


class StorageStub:
    def __init__(self, *, settings=None, scan_results=None, bookmarks=None, tuning=None):
        self.settings = settings or {}
        self.scan_results = scan_results or []
        self.bookmarks = bookmarks or []
        self.tuning = tuning or Tuning()
        self.saved_settings = 0
        self.saved_results = 0

    def save_settings(self):
        self.saved_settings += 1

    def save_scan_results(self):
        self.saved_results += 1


def test_current_carrier_sni_beats_higher_other_carrier_score():
    storage = StorageStub(
        scan_results=[
            {"domain": "mci-fast.example", "success": True, "score": 1200,
             "carrier": "mci", "tested_at": time.time()},
            {"domain": "irancell-good.example", "success": True, "score": 600,
             "carrier": "irancell", "tested_at": time.time()},
        ],
        tuning=Tuning(carrier_mode="irancell"),
    )
    dummy = SimpleNamespace(storage=storage)

    assert MainWindow._sni_candidates(dummy, carrier="irancell", limit=2) == [
        "irancell-good.example", "mci-fast.example"
    ]


def test_scan_repository_keeps_same_domain_measurements_per_carrier_and_edge():
    storage = StorageStub(
        scan_results=[{
            "domain": "support.cloudflare.com", "success": True, "score": 900,
            "carrier": "mci", "edge": "104.18.8.83", "tested_at": 1,
        }],
        tuning=Tuning(carrier_mode="irancell", pattern_connect_ip="104.19.229.21"),
    )
    dummy = SimpleNamespace(storage=storage)
    result = ScanResult(
        domain="support.cloudflare.com", success=True, score=700,
        carrier="irancell", edge="104.19.229.21", tested_at=2,
    )

    MainWindow._persist_scan_repository(dummy, [result])

    keys = {(item["carrier"], item["edge"], item["domain"])
            for item in storage.scan_results}
    assert keys == {
        ("mci", "104.18.8.83", "support.cloudflare.com"),
        ("irancell", "104.19.229.21", "support.cloudflare.com"),
    }
    assert storage.saved_results == 1


def test_profile_mux_compatibility_is_route_scoped_and_does_not_change_global_tuning():
    profile_a = ProxyProfile(id="route-a", source_uri="vless://a@example.com")
    profile_b = ProxyProfile(id="route-b", source_uri="vless://b@example.com")
    mci_tuning = Tuning(
        carrier_mode="mci", xray_mux_enabled=True,
        pattern_connect_ip="188.114.98.0",
    )
    irancell_tuning = Tuning(
        carrier_mode="irancell", xray_mux_enabled=True,
        pattern_connect_ip="104.19.229.21",
    )
    storage = StorageStub(settings={"tuning": mci_tuning.to_dict()}, tuning=mci_tuning)
    dummy = SimpleNamespace(storage=storage)

    MainWindow._remember_profile_mux(dummy, profile_a, False, mci_tuning, "mci")

    assert MainWindow._profile_mux_enabled(dummy, profile_a, mci_tuning, "mci") is False
    assert MainWindow._profile_mux_enabled(dummy, profile_b, mci_tuning, "mci") is True
    assert MainWindow._profile_mux_enabled(dummy, profile_a, irancell_tuning, "irancell") is True

    changed_mci_edge = Tuning.from_dict(mci_tuning.to_dict())
    changed_mci_edge.pattern_connect_ip = "188.114.99.0"
    assert MainWindow._profile_mux_enabled(dummy, profile_a, changed_mci_edge, "mci") is True

    MainWindow._remember_profile_mux(dummy, profile_a, False, irancell_tuning, "irancell")
    assert MainWindow._profile_mux_enabled(dummy, profile_a, irancell_tuning, "irancell") is False
    assert set(storage.settings["profile_mux_compatibility_by_carrier"]) == {"mci", "irancell"}
    assert storage.settings["tuning"]["xray_mux_enabled"] is True


def test_cached_update_recomputes_semver_instead_of_trusting_stale_flag():
    storage = StorageStub(settings={
        "update_repo_url": DEFAULT_UPDATE_REPO_URL,
        "last_update_repo_url": DEFAULT_UPDATE_REPO_URL,
        "last_update_current_version": __version__,
        "latest_version": __version__,
        "latest_release_url": DEFAULT_UPDATE_REPO_URL + "/releases/tag/v" + __version__,
        "update_available": True,
    })
    rendered = []
    dummy = SimpleNamespace(storage=storage, _latest_update=None,
                            _render_update_info=rendered.append)

    assert MainWindow._restore_cached_update(dummy) is True
    assert rendered[0].is_update_available is False


def test_cached_update_is_rejected_after_repo_or_app_version_change():
    storage = StorageStub(settings={
        "update_repo_url": DEFAULT_UPDATE_REPO_URL,
        "last_update_repo_url": "https://github.com/example/old-repo",
        "last_update_current_version": "0.9.0",
        "latest_version": "99.0.0",
    })
    dummy = SimpleNamespace(storage=storage, _latest_update=None,
                            _render_update_info=lambda _info: None)

    assert MainWindow._restore_cached_update(dummy) is False


def test_new_update_notification_is_emitted_once_per_version():
    storage = StorageStub(settings={})
    shown = []
    dummy = SimpleNamespace(storage=storage, _show_update_notification=shown.append)
    info = SimpleNamespace(is_update_available=True, latest_version="2.0.0")

    assert MainWindow._announce_update(dummy, info) is True
    assert MainWindow._announce_update(dummy, info) is False
    assert shown == [info]
    assert storage.settings["notified_update_version"] == "2.0.0"
    assert storage.saved_settings == 1


def test_profile_benchmark_uses_captured_connection_carrier():
    storage = StorageStub(tuning=Tuning(carrier_mode="mci"))
    engine = SimpleNamespace(
        last_probe_ms=250, last_probe_url="https://www.youtube.com/generate_204",
        last_upload_state="not_tested", last_upload_ok=None,
        last_upload_mbps=0, last_upload_speed_valid=False,
        last_upload_ms=0, last_upload_reason="",
    )
    dummy = SimpleNamespace(storage=storage, engine=engine)
    profile = ProxyProfile(id="captured-carrier")

    MainWindow._save_profile_benchmark(
        dummy, profile, "wrong_seq", True, "not_tested",
        "support.cloudflare.com", carrier="irancell",
    )

    assert "profile_benchmarks_pattern_irancell" in storage.settings
    assert "profile_benchmarks_pattern_mci" not in storage.settings


def test_failed_log_flush_schedules_retry_and_preserves_order(monkeypatch):
    import uac_desktop.ui as ui_module

    class TimerStub:
        def __init__(self):
            self.delays = []

        def start(self, delay):
            self.delays.append(delay)

    class Writer:
        def __init__(self, owner):
            self.owner = owner

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def write(self, value):
            self.owner.written.append(value)

    class FlakyPath:
        def __init__(self):
            self.calls = 0
            self.written = []

        def open(self, *_args, **_kwargs):
            self.calls += 1
            if self.calls == 1:
                raise OSError("temporary lock")
            return Writer(self)

    path = FlakyPath()
    monkeypatch.setattr(ui_module, "LOG_FILE", path)
    dummy = SimpleNamespace(
        _pending_file_log_lines=["first", "second"],
        _log_flush_failures=0, _closing=False, _log_flush_timer=TimerStub(),
    )

    MainWindow._flush_log_buffer(dummy)
    assert dummy._pending_file_log_lines == ["first", "second"]
    assert dummy._log_flush_timer.delays

    MainWindow._flush_log_buffer(dummy)
    assert dummy._pending_file_log_lines == []
    assert path.written == ["first\nsecond\n"]


def test_connect_button_cancels_an_in_progress_attempt():
    calls = []
    dummy = SimpleNamespace(
        connecting=True,
        connection_error="old error",
        engine=SimpleNamespace(running=False),
        bridge=SimpleNamespace(log=SimpleNamespace(emit=lambda text: calls.append(("log", text)))),
        _set_connection_visual=lambda state: calls.append(("visual", state)),
        _set_activity=lambda *args: calls.append(("activity", *args)),
        _cancel_connect_attempt=lambda **kwargs: calls.append(("cancel", kwargs)),
        _set_state=lambda running: calls.append(("state", running)),
    )

    MainWindow.toggle_connection(dummy)

    assert dummy.connecting is False
    assert dummy.connection_error == ""
    assert ("cancel", {"notify": True}) in calls
    assert ("state", False) in calls
    assert calls.index(("visual", "disconnecting")) < calls.index(("cancel", {"notify": True}))


def test_retry_waits_for_previous_connection_worker(monkeypatch):
    scheduled = []
    cancelled = []
    dummy = SimpleNamespace(
        connecting=False,
        engine=SimpleNamespace(running=False),
        _maker_running=False,
        _connect_thread=SimpleNamespace(is_alive=lambda: True),
        _connection_retry_pending=False,
        _cancel_connect_attempt=lambda **kwargs: cancelled.append(kwargs),
        _resume_pending_connection=lambda: None,
    )
    monkeypatch.setattr(
        ui_module.QTimer, "singleShot",
        lambda delay, callback: scheduled.append((delay, callback)),
    )

    MainWindow.toggle_connection(dummy)

    assert dummy._connection_retry_pending is True
    assert cancelled == [{"notify": False}]
    assert scheduled == [(75, dummy._resume_pending_connection)]


def test_applied_sni_is_displayed_and_used_for_verified_profile_without_changing_server_sni():
    profile = ProxyProfile(
        id="verified-route", sni="server.example",
        spoof_fake_sni="static.cloudflare.com", verified_spoof=True,
    )
    result = ScanResult(
        domain="community.cloudflare.com", success=True, score=900,
        carrier="irancell", tested_at=time.time(),
    )

    class ApplyStorage:
        def __init__(self):
            self.profiles = [profile]
            self.scan_results = [result.to_dict()]
            self.bookmarks = []
            self.settings = {}
            self.tuning = Tuning(
                carrier_mode="irancell",
                pattern_fake_sni="static.cloudflare.com",
            )

        def set_tuning(self, tuning):
            self.tuning = tuning

    storage = ApplyStorage()
    dummy = SimpleNamespace(
        storage=storage,
        _bind_verified_sni_route=MainWindow._bind_verified_sni_route,
    )
    dummy._sni_candidates = lambda profile, carrier, limit: MainWindow._sni_candidates(
        dummy, profile, carrier, limit,
    )
    dummy._effective_profile_fake_sni = lambda profile, carrier=None: MainWindow._effective_profile_fake_sni(
        dummy, profile, carrier,
    )

    MainWindow._apply_carrier_sni(
        dummy, {profile.id: result}, result,
    )

    assert profile.sni == "server.example"
    assert MainWindow._effective_profile_fake_sni(
        dummy, profile, "irancell",
    ) == "community.cloudflare.com"
    assert MainWindow._profile_sni_candidates(
        dummy, profile, "irancell", 3,
    ) == ["community.cloudflare.com", "static.cloudflare.com"]
    assert "Fake SNI community.cloudflare.com" in MainWindow._profile_route_label(
        dummy, profile, "irancell",
    )


def test_verified_user_config_uses_its_healthy_sni_first_and_respects_limit():
    profile = ProxyProfile(
        id="healthy-user-config",
        origin="sni-maker",
        verified_spoof=True,
        spoof_fake_sni="known.good",
    )
    dummy = SimpleNamespace(
        storage=SimpleNamespace(tuning=Tuning(carrier_mode="irancell")),
        _sni_candidates=lambda *_args: [
            "global-one.example",
            "global-two.example",
            "global-three.example",
        ],
    )

    assert MainWindow._profile_sni_candidates(
        dummy, profile, "irancell", 2,
    ) == ["known.good", "global-one.example"]


def test_irancell_builtin_uses_profile_hint_before_global_candidates():
    profile = ProxyProfile(
        id="builtin-two",
        origin="builtin",
        sni="www.ignitelimit.com",
        source_uri="trojan://humanity@127.0.0.1:40443?type=ws&sni=www.ignitelimit.com",
    )
    dummy = SimpleNamespace(
        storage=SimpleNamespace(
            settings={}, tuning=Tuning(carrier_mode="irancell")
        ),
        _sni_candidates=lambda *_args: [
            "chatgpt.com",
            "developers.cloudflare.com",
            "use.fontawesome.com",
        ],
    )

    assert MainWindow._profile_sni_candidates(
        dummy, profile, "irancell", 3,
    ) == [
        "support.cloudflare.com",
        "chatgpt.com",
        "developers.cloudflare.com",
        "use.fontawesome.com",
    ]


def test_builtin_route_cache_is_scoped_away_from_user_config():
    builtin = ProxyProfile(
        id="builtin-route", origin="builtin", source_uri="trojan://builtin"
    )
    user_config = ProxyProfile(
        id="user-route", origin="sni-maker", source_uri="trojan://user"
    )
    settings = {
        "builtin_profile_routes_by_carrier": {
            "irancell": {
                builtin.id: {
                    "fake_sni": "cached.example",
                    "strategy": "tls_sni_records",
                    "signature": builtin.source_uri,
                    "tested_at": time.time(),
                }
            }
        }
    }
    dummy = SimpleNamespace(
        storage=SimpleNamespace(
            settings=settings, tuning=Tuning(carrier_mode="irancell")
        )
    )

    assert MainWindow._builtin_route_entry(
        dummy, builtin, "irancell"
    )["fake_sni"] == "cached.example"
    assert MainWindow._builtin_route_entry(
        dummy, user_config, "irancell"
    ) == {}


def test_forced_profile_overrides_auto_mode_country_order(monkeypatch):
    preferred = ProxyProfile(id="clicked", origin="verified", verified_spoof=True)
    other = ProxyProfile(id="other", origin="verified", verified_spoof=True)

    class OrderedStorage:
        def __init__(self):
            self.profiles = [other, preferred]
            self.settings = {}
            self.tuning = Tuning(carrier_mode="irancell")

        def save_profiles(self):
            return None

    monkeypatch.setattr(ui_module, "profile_ping", lambda *_args: (True, 25.0))
    dummy = SimpleNamespace(
        storage=OrderedStorage(),
        bridge=SimpleNamespace(latency=SimpleNamespace(emit=lambda *_args: None),
                               log=SimpleNamespace(emit=lambda *_args: None)),
    )

    ordered = MainWindow._ordered_profiles(
        dummy, "community.cloudflare.com", threading.Event(),
        auto_enabled=True, forced_profile=preferred,
    )

    assert ordered == [preferred]


def test_mci_suggested_auto_skips_only_builtin_404_paths(monkeypatch):
    profiles = default_profiles()

    class OrderedStorage:
        def __init__(self, carrier):
            self.profiles = list(profiles)
            self.settings = {}
            self.tuning = Tuning(carrier_mode=carrier)

        def save_profiles(self):
            return None

    monkeypatch.setattr(ui_module, "profile_ping", lambda *_args: (True, 25.0))

    def ordered(carrier, source="suggested", forced_profile=None,
                source_profiles=None):
        storage = OrderedStorage(carrier)
        candidates = list(source_profiles if source_profiles is not None else profiles)
        dummy = SimpleNamespace(
            storage=storage,
            bridge=SimpleNamespace(
                latency=SimpleNamespace(emit=lambda *_args: None),
                log=SimpleNamespace(emit=lambda *_args: None),
            ),
            _selected_route_source=lambda: source,
            _route_source_profiles=lambda: candidates,
        )
        return MainWindow._ordered_profiles(
            dummy, "community.cloudflare.com", threading.Event(),
            auto_enabled=True, forced_profile=forced_profile,
        ), storage

    mci_profiles, mci_storage = ordered("mci")
    assert [profile.name for profile in mci_profiles] == [
        "uacSpoofer 3", "uacSpoofer 1", "uacSpoofer 2", "uacSpoofer 6",
    ]
    assert [profile.name for profile in mci_storage.profiles] == [
        f"uacSpoofer {index}" for index in range(1, 7)
    ]

    forced, _storage = ordered("mci", forced_profile=profiles[3])
    assert forced == [profiles[3]]

    user_profiles = [
        ProxyProfile(
            name="uacSpoofer 4", origin="sni-maker",
            source_uri=profiles[3].source_uri, verified_route=True,
        ),
        ProxyProfile(
            name="uacSpoofer 5", origin="sni-maker",
            source_uri=profiles[4].source_uri, verified_route=True,
        ),
    ]
    user_ordered, _storage = ordered(
        "mci", source="user-config", source_profiles=user_profiles,
    )
    assert user_ordered == user_profiles

    irancell_profiles, _storage = ordered("irancell")
    assert irancell_profiles == profiles


def test_forced_user_config_keeps_mci_tls_strategy_in_auto_mode():
    assert MainWindow._initial_connection_strategy("mci", "") == "tls_sni_records"
    assert MainWindow._initial_connection_strategy("irancell", "") == "wrong_seq"
    assert MainWindow._initial_connection_strategy("mci", "DE") == "wrong_seq"


def test_mci_builtin_uses_isolated_live_route_without_mutating_user_tuning():
    base = Tuning.carrier_preset("mci")
    base.pattern_connect_ip = "188.114.97.4"
    base.pattern_fallback_ips = "188.114.99.160"
    base.pattern_relay_buffer_kb = 256
    base.pattern_socket_buffer_kb = 512
    base.pattern_upload_optimized = False
    base.xray_mux_enabled = True
    profile = ProxyProfile(origin="builtin")

    attempt = MainWindow._attempt_tuning_for_profile(
        profile, base, "chatgpt.com", True,
    )

    assert attempt.pattern_connect_ip == ui_module.MCI_BUILTIN_PRIMARY_EDGE
    assert attempt.pattern_fallback_ips == ui_module.MCI_BUILTIN_FALLBACK_EDGES
    assert attempt.pattern_fake_sni == "chatgpt.com"
    assert attempt.pattern_fake_repeat == ui_module.MCI_BUILTIN_FAKE_REPEAT == 1
    assert attempt.pattern_inject_delay_ms == ui_module.MCI_BUILTIN_INJECT_DELAY_MS == 0
    assert attempt.pattern_ack_timeout_ms == 8000
    assert attempt.pattern_use_profile_edges is False
    assert attempt.pattern_max_sessions == 4
    assert attempt.pattern_relay_buffer_kb == 256
    assert attempt.pattern_socket_buffer_kb == 512
    assert attempt.pattern_upload_optimized is False
    assert attempt.xray_mux_enabled is False
    assert base.pattern_connect_ip == "188.114.97.4"
    assert base.pattern_fallback_ips == "188.114.99.160"
    assert base.pattern_max_sessions == 4
    assert base.pattern_relay_buffer_kb == 256
    assert base.pattern_socket_buffer_kb == 512
    assert base.pattern_upload_optimized is False
    assert base.xray_mux_enabled is True


def test_mci_builtin_uses_live_primary_plan_but_user_config_keeps_existing_strategy():
    builtin = ProxyProfile(origin="builtin")
    user = ProxyProfile(origin="sni-maker", method="combined")

    assert MainWindow._profile_connection_strategy(
        builtin, "mci", "tls_sni_records", {"strategy": "wrong_seq"},
    ) == ui_module.MCI_BUILTIN_ROUTE_PLANS[0][0]
    assert MainWindow._profile_connection_strategy(
        user, "mci", "tls_sni_records", {},
    ) == "tls_sni_records"


def test_mci_builtin_starts_with_live_verified_web_route():
    profile = ProxyProfile(
        id="builtin-two",
        origin="builtin",
        sni="www.ignitelimit.com",
        source_uri="trojan://humanity@127.0.0.1:40443?type=ws&sni=www.ignitelimit.com",
    )
    dummy = SimpleNamespace(
        storage=SimpleNamespace(
            settings={}, tuning=Tuning(carrier_mode="mci")
        ),
        _sni_candidates=lambda *_args: [
            "chatgpt.com", "community.cloudflare.com"
        ],
    )

    assert MainWindow._profile_sni_candidates(
        dummy, profile, "mci", 3,
    ) == ["www.ignitelimit.com"] * len(ui_module.MCI_BUILTIN_ROUTE_PLANS)
    assert ui_module.MCI_BUILTIN_ROUTE_PLANS[0] == (
        "plain", "104.18.1.1"
    )


def test_mci_builtin_rotates_explicit_routes_without_touching_user_config():
    builtin = ProxyProfile(origin="builtin")
    user = ProxyProfile(origin="sni-maker")
    base = Tuning.carrier_preset("mci")

    plans = [
        MainWindow._mci_builtin_route_plan(builtin, "mci", index)
        for index in range(len(ui_module.MCI_BUILTIN_ROUTE_PLANS))
    ]

    assert plans == list(ui_module.MCI_BUILTIN_ROUTE_PLANS)
    assert MainWindow._mci_builtin_route_plan(user, "mci", 0) is None
    assert MainWindow._mci_builtin_route_plan(builtin, "irancell", 0) is None
    for plan in plans:
        attempt = MainWindow._attempt_tuning_for_profile(
            builtin, base, "www.speedtest.net", True, plan,
        )
        assert attempt.pattern_connect_ip == plan[1]
        assert attempt.pattern_fallback_ips == ui_module.MCI_BUILTIN_FALLBACK_EDGES
        assert attempt.pattern_fake_repeat == 1
        assert attempt.pattern_inject_delay_ms == 0
        assert MainWindow._profile_connection_strategy(
            builtin, "mci", "wrong_seq", {}, plan,
        ) == plan[0]


def test_mci_builtin_payload_gate_requires_real_body_and_skips_user_config():
    calls = []

    class EngineStub:
        running = True
        last_download_state = "failed"
        last_download_bytes = 0

        def probe_web_access(self, **kwargs):
            calls.append(kwargs)
            return False, "ReadTimeout"

    dummy = SimpleNamespace(engine=EngineStub())
    builtin = ProxyProfile(origin="builtin")
    user = ProxyProfile(origin="sni-maker")

    assert MainWindow._verify_mci_builtin_payload(
        dummy, builtin, "mci", threading.Event(),
    ) == (False, "ReadTimeout")
    assert calls == [{
        "timeout": 10.0,
        "connect_timeout": 4.0,
        "cancel_event": calls[0]["cancel_event"],
    }]
    assert MainWindow._verify_mci_builtin_payload(
        dummy, user, "mci", threading.Event(),
    ) == (True, "not required")
    assert len(calls) == 1


def test_mci_builtin_payload_gate_accepts_one_verified_pass():
    calls = []

    class EngineStub:
        running = True
        last_download_state = "verified"
        last_download_bytes = ui_module.MCI_BUILTIN_WEB_GATE_MIN_BYTES

        def probe_web_access(self, **kwargs):
            calls.append(kwargs)
            return True, f"pass {len(calls)}"

    dummy = SimpleNamespace(engine=EngineStub())
    builtin = ProxyProfile(origin="builtin")

    assert MainWindow._verify_mci_builtin_payload(
        dummy, builtin, "mci", threading.Event(),
    ) == (True, "pass 1")
    assert len(calls) == 1


def test_mci_user_config_keeps_its_existing_edge_and_mux_setting():
    base = Tuning.carrier_preset("mci")
    base.pattern_connect_ip = "188.114.97.4"
    base.pattern_fallback_ips = "188.114.99.160"
    base.pattern_fake_repeat = 1
    base.pattern_inject_delay_ms = 4
    base.pattern_ack_timeout_ms = 3100
    profile = ProxyProfile(origin="sni-maker")

    attempt = MainWindow._attempt_tuning_for_profile(
        profile, base, "chatgpt.com", True,
    )

    assert attempt.pattern_connect_ip == "188.114.97.4"
    assert attempt.pattern_fallback_ips == "188.114.99.160"
    assert attempt.pattern_fake_repeat == 1
    assert attempt.pattern_inject_delay_ms == 4
    assert attempt.pattern_ack_timeout_ms == 3100
    assert attempt.xray_mux_enabled is True


def test_irancell_builtin_does_not_receive_mci_hybrid_tuning():
    base = Tuning.carrier_preset("irancell")
    profile = ProxyProfile(origin="builtin")

    attempt = MainWindow._attempt_tuning_for_profile(
        profile, base, "chatgpt.com", True,
    )

    assert attempt.pattern_connect_ip == base.pattern_connect_ip
    assert attempt.pattern_fallback_ips == base.pattern_fallback_ips
    assert attempt.pattern_fake_repeat == base.pattern_fake_repeat == 1
    assert attempt.pattern_inject_delay_ms == base.pattern_inject_delay_ms
    assert attempt.pattern_ack_timeout_ms == base.pattern_ack_timeout_ms


def test_profile_click_reconnects_only_when_tunnel_is_active():
    profile = ProxyProfile(id="clicked-profile", name="Clicked")

    class ClickStorage:
        def __init__(self):
            self.profiles = [profile]
            self.selected_id = ""
            self.settings = {}

        def selected(self):
            return profile if self.selected_id == profile.id else None

    class TextStub:
        def setText(self, _value):
            return None

        def set_secondary(self, _value):
            return None

    item = SimpleNamespace(data=lambda _role: profile.id)
    queued = []
    dummy = SimpleNamespace(
        storage=ClickStorage(),
        active_profile=TextStub(), route_card=TextStub(), ping_label=TextStub(),
        latency_card=SimpleNamespace(sparkline=SimpleNamespace(add_value=lambda _value: None)),
        connecting=False, engine=SimpleNamespace(running=False),
        _profile_switch_waiting=False,
        _profile_route_label=lambda _profile: "route",
        _update_config_actions=lambda: None,
        _queue_profile_switch=queued.append,
    )

    MainWindow._profile_clicked(dummy, item)
    assert queued == []

    dummy.engine.running = True
    MainWindow._profile_clicked(dummy, item)
    assert queued == [profile.id]


def test_rapid_profile_switch_uses_last_click_and_starts_once(monkeypatch):
    first = ProxyProfile(id="first", name="First")
    second = ProxyProfile(id="second", name="Second")
    scheduled = []
    cancelled = []
    started = []
    storage = SimpleNamespace(profiles=[first, second], selected_id=first.id)
    dummy = SimpleNamespace(
        storage=storage,
        _pending_profile_switch_id="",
        _profile_switch_waiting=False,
        _forced_profile_id="",
        _connect_thread=None,
        _closing=False,
        connecting=True,
        connection_error="",
        _cancel_connect_attempt=lambda **kwargs: cancelled.append(kwargs),
        _set_state=lambda _running: None,
        _set_connection_visual=lambda _state: None,
        _set_activity=lambda *_args: None,
        toggle_connection=lambda: started.append(True),
    )
    dummy._resume_profile_switch = lambda: MainWindow._resume_profile_switch(dummy)
    monkeypatch.setattr(ui_module.QTimer, "singleShot",
                        lambda _delay, callback: scheduled.append(callback))

    MainWindow._queue_profile_switch(dummy, first.id)
    MainWindow._queue_profile_switch(dummy, second.id)

    assert len(scheduled) == 1
    assert cancelled == [{"notify": False}]
    scheduled[0]()
    assert storage.selected_id == second.id
    assert dummy._forced_profile_id == second.id
    assert started == [True]


def test_latency_card_shows_8888_tunnel_latency():
    class LabelStub:
        def __init__(self):
            self.text = ""

        def setText(self, value):
            self.text = value

    class SparklineStub:
        def __init__(self):
            self.values = []

        def add_value(self, value):
            self.values.append(value)

    secondary = []
    label = LabelStub()
    sparkline = SparklineStub()
    dummy = SimpleNamespace(
        ping_label=label,
        latency_card=SimpleNamespace(
            set_secondary=secondary.append,
            sparkline=sparkline,
        ),
        engine=SimpleNamespace(tun_running=True),
        _target_latency_generation=3,
        _target_latency_busy=True,
        _target_latency_pending=False,
    )

    MainWindow._set_latency(dummy, 0.0, "testing")
    assert label.text == "…"
    assert secondary[-1] == "8.8.8.8 • Checking…"

    MainWindow._target_latency_finished(dummy, 87.6, "tun", 3)
    assert label.text == "88 ms"
    assert secondary[-1] == "8.8.8.8 • TUN TLS"
    assert sparkline.values == [87.6]


def test_latency_card_falls_back_to_direct_8888_ping():
    label = SimpleNamespace(text="", setText=lambda value: setattr(label, "text", value))
    secondary = []
    sparkline = []
    dummy = SimpleNamespace(
        ping_label=label,
        latency_card=SimpleNamespace(
            set_secondary=secondary.append,
            sparkline=SimpleNamespace(add_value=sparkline.append),
        ),
        engine=SimpleNamespace(tun_running=True),
        _target_latency_generation=8,
        _target_latency_busy=True,
        _target_latency_pending=False,
    )

    MainWindow._target_latency_finished(dummy, 62.0, "direct-fallback", 8)

    assert label.text == "62 ms"
    assert secondary[-1] == "8.8.8.8 • Direct fallback"
    assert sparkline == [62.0]


def test_latency_card_shows_active_proxy_config_delay():
    label = SimpleNamespace(text="", setText=lambda value: setattr(label, "text", value))
    secondary = []
    sparkline = []
    dummy = SimpleNamespace(
        ping_label=label,
        latency_card=SimpleNamespace(
            set_secondary=secondary.append,
            sparkline=SimpleNamespace(add_value=sparkline.append),
        ),
        engine=SimpleNamespace(
            tun_running=False,
            running=True,
            _proxy_enabled=True,
            run_id=12,
        ),
        tr=lambda fa, en: en,
        _target_latency_generation=9,
        _target_latency_busy=True,
        _target_latency_pending=False,
    )

    MainWindow._target_latency_finished(dummy, 143.4, "proxy|12", 9)

    assert label.text == "143 ms"
    assert secondary[-1] == "Active config • Live delay"
    assert sparkline == [143.4]


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("Reply from 8.8.8.8: bytes=32 time=62ms TTL=117", 62.0),
        ("Reply from 8.8.8.8: bytes=32 time<1ms TTL=117", 1.0),
        ("Request timed out.", None),
    ],
)
def test_parse_direct_8888_ping(output, expected):
    assert ui_module._parse_ping_latency(output) == expected


def test_close_event_hides_window_when_user_chooses_system_tray():
    class EventStub:
        def __init__(self):
            self.ignored = False
            self.accepted = False

        def ignore(self):
            self.ignored = True

        def accept(self):
            self.accepted = True

    event = EventStub()
    calls = []
    dummy = SimpleNamespace(
        _force_quit=False,
        _ask_close_action=lambda: "tray",
        _hide_to_tray=lambda: calls.append("tray") or True,
        shutdown=lambda: calls.append("shutdown"),
    )

    MainWindow.closeEvent(dummy, event)

    assert event.ignored is True
    assert event.accepted is False
    assert calls == ["tray"]


def test_close_event_shuts_down_only_when_user_chooses_quit():
    class EventStub:
        def __init__(self):
            self.ignored = False
            self.accepted = False

        def ignore(self):
            self.ignored = True

        def accept(self):
            self.accepted = True

    event = EventStub()
    calls = []
    dummy = SimpleNamespace(
        _force_quit=False,
        _ask_close_action=lambda: "quit",
        _hide_to_tray=lambda: False,
        shutdown=lambda: calls.append("shutdown"),
    )

    MainWindow.closeEvent(dummy, event)

    assert event.accepted is True
    assert event.ignored is False
    assert calls == ["shutdown"]
    assert dummy._force_quit is True


def test_proxy_mode_off_keeps_engine_running_and_restores_only_windows_proxy(monkeypatch):
    class EngineStub:
        running = True

        def __init__(self):
            self.enable_calls = 0
            self.disable_calls = 0

        def enable_system_proxy(self, *_args):
            self.enable_calls += 1

        def disable_system_proxy(self):
            self.disable_calls += 1

    class ProxyOptionStub:
        def __init__(self):
            self.enabled = None

        def setProperty(self, _name, value):
            self.enabled = value

    storage = StorageStub(settings={"proxy_mode": True})
    engine = EngineStub()
    activity = []
    queued = []
    dummy = SimpleNamespace(
        storage=storage,
        engine=engine,
        connecting=True,
        proxy_option=ProxyOptionStub(),
        proxy_mode=SimpleNamespace(
            blockSignals=lambda *_args: None,
            setChecked=lambda *_args: None,
        ),
        _save_flag=lambda key, value: (
            storage.settings.__setitem__(key, value), storage.save_settings()
        ),
        _set_activity=lambda *args: activity.append(args),
        _queue_proxy_mode_apply=lambda: queued.append(True),
        _proxy_mode_enabled=lambda: bool(storage.settings.get("proxy_mode", True)),
        _handle_error=lambda error: (_ for _ in ()).throw(AssertionError(error)),
    )
    monkeypatch.setattr(ui_module, "_restyle", lambda _widget: None)

    MainWindow._proxy_mode_changed(dummy, False)
    MainWindow._apply_proxy_mode_live(dummy)

    assert engine.running is True
    assert engine.disable_calls == 1
    assert engine.enable_calls == 0
    assert storage.settings["proxy_mode"] is False
    assert dummy.proxy_option.enabled is False
    assert queued == [True]


def test_verified_connection_skips_windows_proxy_when_proxy_mode_is_off():
    class EngineStub:
        def enable_system_proxy(self, *_args):
            raise AssertionError("Windows proxy must stay off")

        def disable_system_proxy(self):
            raise AssertionError("No proxy snapshot exists to restore")

    logs = []
    dummy = SimpleNamespace(
        storage=StorageStub(settings={"proxy_mode": False}),
        engine=EngineStub(),
        bridge=SimpleNamespace(
            log=SimpleNamespace(emit=logs.append),
            activity=SimpleNamespace(emit=lambda *_args: None),
        ),
        _proxy_mode_enabled=lambda: False,
        tr=lambda _fa, en: en,
    )

    enabled = MainWindow._apply_proxy_mode_after_probe(dummy)

    assert enabled is False
    assert "remain active" in logs[-1]


def test_verified_connection_enables_windows_proxy_by_default():
    class EngineStub:
        def __init__(self):
            self.enable_calls = []

        def enable_system_proxy(self, cancel):
            self.enable_calls.append(cancel)

        def disable_system_proxy(self):
            raise AssertionError("Proxy mode stayed enabled")

    engine = EngineStub()
    activity = []
    dummy = SimpleNamespace(
        storage=StorageStub(settings={}),
        engine=engine,
        bridge=SimpleNamespace(
            log=SimpleNamespace(emit=lambda *_args: None),
            activity=SimpleNamespace(emit=lambda *args: activity.append(args)),
        ),
        _proxy_mode_enabled=lambda: True,
        tr=lambda _fa, en: en,
    )
    cancel = object()

    enabled = MainWindow._apply_proxy_mode_after_probe(dummy, cancel)

    assert enabled is True
    assert engine.enable_calls == [cancel]
    assert activity[-1][0] == "Applying Windows system proxy…"


def test_verified_connection_starts_tun_and_requires_youtube_traffic():
    calls = []

    class EngineStub:
        def suspend_system_proxy_for_tun(self):
            calls.append("proxy-off")

        def enable_tun(self, cancel):
            calls.append(("tun-on", cancel))

        def disable_tun(self):
            calls.append("tun-off")

        def probe_tun(self, **kwargs):
            calls.append(("probe", kwargs))
            return True, "HTTP 204"

    dummy = SimpleNamespace(
        storage=StorageStub(settings={"tun_mode": True, "proxy_mode": True}),
        engine=EngineStub(),
        bridge=SimpleNamespace(
            activity=SimpleNamespace(emit=lambda *args: calls.append(("activity", args))),
        ),
        _tun_mode_enabled=lambda: True,
        _proxy_mode_enabled=lambda: True,
        _apply_proxy_mode_after_probe=lambda _cancel: (_ for _ in ()).throw(
            AssertionError("Windows Proxy must not be enabled in TUN Mode")
        ),
        tr=lambda _fa, en: en,
    )
    cancel = object()

    mode = MainWindow._apply_connection_mode_after_probe(dummy, cancel)

    assert mode == "tun"
    assert calls[1] == ("tun-on", cancel)
    probe = calls[2][1]
    assert probe["preferred_url"] == "https://www.youtube.com/generate_204"
    assert probe["require_preferred"] is True
    assert probe["cancel_event"] is cancel
    assert calls[3] == "proxy-off"


def test_turning_tun_off_live_restores_saved_windows_proxy_preference():
    calls = []

    class EngineStub:
        def disable_tun(self):
            calls.append("tun-off")

        def enable_system_proxy(self):
            calls.append("proxy-on")

        def disable_system_proxy(self):
            calls.append("proxy-off")

    dummy = SimpleNamespace(
        engine=EngineStub(),
        _tun_mode_enabled=lambda: False,
        _proxy_mode_enabled=lambda: True,
    )

    enabled = MainWindow._apply_tun_mode_live(dummy)

    assert enabled is False
    assert calls == ["proxy-on", "tun-off"]


def test_live_tun_failure_restores_windows_proxy_and_stops_tun():
    calls = []

    class EngineStub:
        def suspend_system_proxy_for_tun(self):
            calls.append("proxy-off")

        def enable_tun(self):
            calls.append("tun-on")

        def probe_tun(self, **_kwargs):
            return False, "YouTube timeout"

        def disable_tun(self):
            calls.append("tun-off")

        def enable_system_proxy(self):
            calls.append("proxy-on")

    dummy = SimpleNamespace(
        engine=EngineStub(),
        _tun_mode_enabled=lambda: True,
        _proxy_mode_enabled=lambda: True,
    )

    try:
        MainWindow._apply_tun_mode_live(dummy)
        assert False, "failed TUN verification must be reported"
    except RuntimeError as exc:
        assert "YouTube timeout" in str(exc)

    assert calls == ["tun-on", "tun-off", "proxy-on"]


def test_live_tun_probe_does_not_hold_mode_mutation_lock():
    calls = []

    class RecordingLock:
        depth = 0

        def __enter__(self):
            self.depth += 1
            return self

        def __exit__(self, *_args):
            self.depth -= 1

    lock = RecordingLock()

    class EngineStub:
        def enable_tun(self, _cancel, expected_run_id=None):
            assert lock.depth == 1
            calls.append(("tun-on", expected_run_id))

        def probe_tun(self, **_kwargs):
            assert lock.depth == 0
            calls.append("probe")
            return True, "HTTP 204"

        def suspend_system_proxy_for_tun(self, expected_run_id=None):
            assert lock.depth == 1
            calls.append(("proxy-suspend", expected_run_id))

    dummy = SimpleNamespace(
        engine=EngineStub(),
        _proxy_mode_apply_lock=lock,
        _tun_mode_enabled=lambda: True,
        _proxy_mode_enabled=lambda: True,
    )

    enabled = MainWindow._apply_tun_mode_live(
        dummy, 17, threading.Event(), lambda: True
    )

    assert enabled is True
    assert lock.depth == 0
    assert calls == [("tun-on", 17), "probe", ("proxy-suspend", 17)]


def test_stale_live_tun_worker_never_mutates_a_new_engine_run():
    calls = []
    active = {"current": True}

    class EngineStub:
        run_id = 1
        tun_running = True

        def enable_tun(self, _cancel, expected_run_id=None):
            calls.append(("tun-on", expected_run_id))

        def probe_tun(self, **_kwargs):
            calls.append("probe")
            self.run_id = 2
            active["current"] = False
            return True, "HTTP 204"

        def suspend_system_proxy_for_tun(self, **_kwargs):
            calls.append("proxy-suspend")

        def disable_tun(self, **_kwargs):
            calls.append("tun-off")

        def enable_system_proxy(self, **_kwargs):
            calls.append("proxy-on")

    dummy = SimpleNamespace(
        engine=EngineStub(),
        _tun_mode_enabled=lambda: True,
        _proxy_mode_enabled=lambda: True,
    )

    with pytest.raises(EngineCancelled):
        MainWindow._apply_tun_mode_live(
            dummy, 1, threading.Event(), lambda: active["current"]
        )

    assert calls == [("tun-on", 1), "probe"]


def test_failed_live_tun_stop_keeps_tun_and_suspends_windows_proxy():
    calls = []

    class EngineStub:
        tun_running = True

        def enable_system_proxy(self):
            calls.append("proxy-on")

        def disable_tun(self):
            calls.append("tun-off")
            raise RuntimeError("sing-box did not stop")

        def suspend_system_proxy_for_tun(self):
            calls.append("proxy-suspend")

    dummy = SimpleNamespace(
        engine=EngineStub(),
        _tun_mode_enabled=lambda: False,
        _proxy_mode_enabled=lambda: True,
    )

    with pytest.raises(RuntimeError, match="did not stop"):
        MainWindow._apply_tun_mode_live(dummy)

    assert calls == ["proxy-on", "tun-off", "proxy-suspend"]


def test_failed_tun_stop_ui_reflects_still_running_runtime(monkeypatch):
    class ToggleStub:
        def __init__(self):
            self.checked = None

        def blockSignals(self, _value):
            pass

        def setChecked(self, value):
            self.checked = value

    class OptionStub:
        def __init__(self):
            self.active = None
            self.enabled = None

        def setProperty(self, _name, value):
            self.active = value

        def setEnabled(self, value):
            self.enabled = value

    settings = {"tun_mode": False}
    tun = ToggleStub()
    tun_option = OptionStub()
    proxy_option = OptionStub()
    errors = []
    dummy = SimpleNamespace(
        engine=SimpleNamespace(tun_running=True),
        storage=StorageStub(settings=settings),
        tun_mode=tun,
        tun_option=tun_option,
        proxy_option=proxy_option,
        _tun_mode_enabled=lambda: bool(settings["tun_mode"]),
        _save_flag=lambda key, value: settings.__setitem__(key, value),
        _handle_error=errors.append,
    )
    monkeypatch.setattr(ui_module, "_restyle", lambda _widget: None)

    MainWindow._tun_mode_apply_finished(
        dummy, False, False, "sing-box did not stop"
    )

    assert settings["tun_mode"] is True
    assert tun.checked is True
    assert tun_option.active is True
    assert proxy_option.enabled is False
    assert errors == ["sing-box did not stop"]


def test_connect_mode_rechecks_toggle_and_hands_off_without_direct_gap():
    calls = []
    settings = {"tun_mode": True, "proxy_mode": True}

    class EngineStub:
        tun_running = False

        def enable_tun(self, _cancel):
            calls.append("tun-on")
            self.tun_running = True
            settings["tun_mode"] = False

        def enable_system_proxy(self, _cancel):
            calls.append("proxy-on")

        def disable_tun(self):
            calls.append("tun-off")
            self.tun_running = False

        def disable_system_proxy(self):
            calls.append("proxy-off")

        def probe_tun(self, **_kwargs):
            raise AssertionError("The changed preference must be rechecked before probing")

    engine = EngineStub()
    dummy = SimpleNamespace(
        engine=engine,
        storage=StorageStub(settings=settings),
        bridge=SimpleNamespace(
            activity=SimpleNamespace(emit=lambda *_args: None),
        ),
        _tun_mode_enabled=lambda: bool(settings["tun_mode"]),
        _proxy_mode_enabled=lambda: bool(settings["proxy_mode"]),
        _apply_proxy_mode_after_probe=lambda _cancel: calls.append("proxy-verified") or True,
        tr=lambda _fa, en: en,
    )

    mode = MainWindow._apply_connection_mode_after_probe(dummy, object())

    assert mode == "proxy"
    assert calls == ["tun-on", "proxy-on", "tun-off", "proxy-verified"]
