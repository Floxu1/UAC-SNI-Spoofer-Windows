from __future__ import annotations

import time
from types import SimpleNamespace

from uac_desktop import __version__
import uac_desktop.ui as ui_module
from uac_desktop.models import ProxyProfile, Tuning
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


def test_latency_card_shows_testing_then_live_tunnel_result():
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
        tr=lambda _fa, en: en,
    )

    MainWindow._set_latency(dummy, 0.0, "testing")
    assert label.text == "…"
    assert secondary[-1] == "Testing route…"

    MainWindow._set_latency(dummy, 87.6, "tunnel")
    assert label.text == "88 ms"
    assert secondary[-1] == "Live tunnel test"
    assert sparkline.values == [87.6]


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
