from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest
import requests

import uac_desktop.engine as engine_module
import uac_desktop.ui as ui_module
from uac_desktop.engine import (
    DOWNLOAD_PROBE_BYTES,
    Engine,
    EngineCancelled,
    mci_quality_score,
)
from uac_desktop.models import ProxyProfile, Tuning
from uac_desktop.ui import MainWindow


class RunningProcess:
    def poll(self):
        return None


class StreamResponse:
    def __init__(self, chunks, status_code=200):
        self.status_code = status_code
        self._chunks = chunks
        self.closed = False

    def iter_content(self, chunk_size):
        assert chunk_size == 32 * 1024
        yield from self._chunks

    def close(self):
        self.closed = True


def running_engine():
    engine = Engine(lambda _line: None, lambda _running: None,
                    lambda _up, _down: None)
    engine._active = True
    engine.process = RunningProcess()
    return engine


def test_download_probe_is_bounded_streamed_and_records_metrics(monkeypatch):
    response = StreamResponse([b"D" * (64 * 1024) for _ in range(4)])
    captured = {}

    class Session:
        def __init__(self):
            self.trust_env = True
            self.closed = False

        def get(self, url, **kwargs):
            captured.update(url=url, kwargs=kwargs, session=self)
            return response

        def close(self):
            self.closed = True

    monkeypatch.setattr(engine_module.requests, "Session", Session)
    engine = running_engine()

    ok, detail = engine.probe_download(size=4 * 1024 * 1024)

    assert ok is True
    assert engine.last_download_state == "verified"
    assert engine.last_download_speed_valid is True
    assert engine.last_download_bytes == DOWNLOAD_PROBE_BYTES
    assert engine.last_download_mbps > 0
    assert engine.last_download_ms > 0
    assert engine.last_download_first_byte_ms is not None
    assert f"bytes={DOWNLOAD_PROBE_BYTES}" in captured["url"]
    assert captured["kwargs"]["stream"] is True
    assert captured["kwargs"]["allow_redirects"] is False
    assert captured["kwargs"]["headers"]["Range"] == f"bytes=0-{DOWNLOAD_PROBE_BYTES - 1}"
    assert captured["kwargs"]["proxies"]["https"].startswith("http://127.0.0.1:")
    assert captured["session"].trust_env is False
    assert captured["session"].closed is True
    assert response.closed is True
    assert "Mbps" in detail and "first-byte" in detail


def test_download_probe_honors_total_deadline_with_partial_sample(monkeypatch):
    response = StreamResponse([b"D" * (32 * 1024) for _ in range(20)])

    class Session:
        def __init__(self):
            self.trust_env = True

        def get(self, _url, **_kwargs):
            return response

        def close(self):
            pass

    class Clock:
        value = -0.3

        def __call__(self):
            self.value += 0.3
            return self.value

    monkeypatch.setattr(engine_module.requests, "Session", Session)
    monkeypatch.setattr(engine_module.time, "perf_counter", Clock())
    engine = running_engine()

    ok, _detail = engine.probe_download(timeout=0.5)

    assert ok is True
    assert engine.last_download_bytes == 32 * 1024
    assert engine.last_download_bytes < DOWNLOAD_PROBE_BYTES
    assert response.closed is True


def test_download_probe_cancel_closes_stream_and_propagates(monkeypatch):
    cancel = threading.Event()

    def chunks():
        yield b"D" * (32 * 1024)
        cancel.set()
        yield b"D" * (32 * 1024)

    response = StreamResponse(chunks())
    session_holder = {}

    class Session:
        def __init__(self):
            self.trust_env = True
            self.closed = False
            session_holder["value"] = self

        def get(self, _url, **_kwargs):
            return response

        def close(self):
            self.closed = True

    monkeypatch.setattr(engine_module.requests, "Session", Session)
    engine = running_engine()

    with pytest.raises(EngineCancelled):
        engine.probe_download(cancel_event=cancel)

    assert response.closed is True
    assert session_holder["value"].closed is True


def test_download_endpoint_timeout_is_advisory_while_engine_runs(monkeypatch):
    session_holder = {}

    class Session:
        def __init__(self):
            self.trust_env = True
            self.closed = False
            session_holder["value"] = self

        def get(self, _url, **_kwargs):
            raise requests.ReadTimeout("endpoint stalled")

        def close(self):
            self.closed = True

    monkeypatch.setattr(engine_module.requests, "Session", Session)
    engine = running_engine()

    ok, detail = engine.probe_download()

    assert ok is None
    assert detail == "ReadTimeout"
    assert engine.last_download_ok is None
    assert engine.last_download_state == "inconclusive"
    assert engine.last_download_speed_valid is False
    assert session_holder["value"].trust_env is False
    assert session_holder["value"].closed is True


def test_strict_download_timeout_rejects_running_route(monkeypatch):
    class Session:
        def __init__(self):
            self.trust_env = True

        def get(self, _url, **kwargs):
            assert kwargs["timeout"] == (1.8, 4.5)
            raise requests.ReadTimeout("route stalled")

        def close(self):
            pass

    monkeypatch.setattr(engine_module.requests, "Session", Session)
    engine = running_engine()

    ok, detail = engine.probe_download(size=64 * 1024, timeout=5.0, strict=True)

    assert ok is False
    assert detail == "ReadTimeout"
    assert engine.last_download_ok is False
    assert engine.last_download_state == "failed"


def test_web_access_probe_matches_verified_mci_two_target_gate(monkeypatch):
    calls = []
    responses = []
    sessions = []
    active = 0
    maximum = 0
    lock = threading.Lock()

    class Response:
        status_code = 200

        def __init__(self, body):
            self.body = body
            self.closed = False

        def iter_content(self, chunk_size):
            assert chunk_size == 512
            yield self.body

        def close(self):
            self.closed = True

    class Session:
        def __init__(self):
            self.trust_env = True
            self.closed = False
            sessions.append(self)

        def get(self, url, **kwargs):
            nonlocal active, maximum
            calls.append((url, kwargs))
            with lock:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.01)
            with lock:
                active -= 1
            response = Response(url.encode()[:1] * 512)
            responses.append(response)
            return response

        def close(self):
            self.closed = True

    monkeypatch.setattr(engine_module.requests, "Session", Session)
    engine = running_engine()

    ok, detail = engine.probe_web_access()

    assert ok is True
    assert "Google 200/512B" in detail
    assert "YouTube 200/512B" in detail
    assert engine.last_download_state == "verified"
    assert engine.last_download_bytes == 1024
    assert engine.last_download_speed_valid is True
    assert maximum == 1
    hosts = {url.split("/", 3)[2] for url, _kwargs in calls}
    assert hosts == {"www.google.com", "i.ytimg.com"}
    assert all(call[1]["proxies"]["https"].startswith(
        "http://127.0.0.1:") for call in calls)
    assert all(call[1]["stream"] is True for call in calls)
    assert all(call[1]["timeout"][0] <= 4.0 for call in calls)
    assert all(call[1]["timeout"][1] <= 7.5 for call in calls)
    assert all(response.closed for response in responses)
    assert len(sessions) == 1
    assert all(session.closed for session in sessions)

    calls.clear()
    ok, _detail = engine.probe_web_access(
        timeout=8.0, connect_timeout=4.5
    )
    assert ok is True
    assert all(call[1]["timeout"] == (4.5, 7.5) for call in calls)


def test_web_access_probe_rejects_short_or_missing_body(monkeypatch):
    class Response:
        status_code = 200

        def __init__(self, body):
            self.body = body

        def iter_content(self, chunk_size=None):
            yield self.body

        def close(self):
            pass

    class Session:
        trust_env = True

        def get(self, url, **_kwargs):
            if "google.com" in url:
                return Response(b"short")
            if url.endswith("generate_204"):
                response = Response(b"")
                response.status_code = 204
                return response
            return Response(b"x" * 4096)

        def close(self):
            pass

    monkeypatch.setattr(engine_module.requests, "Session", Session)
    engine = running_engine()

    ok, detail = engine.probe_web_access()

    assert ok is False
    assert detail == "Google short body 5B"
    assert engine.last_download_state == "failed"
    assert engine.last_download_bytes == 0


def test_web_access_probe_handles_broken_target_without_crash(monkeypatch):
    class Session:
        trust_env = True

        def get(self, _url, **_kwargs):
            raise ValueError("broken fixture")

        def close(self):
            pass

    monkeypatch.setattr(engine_module.requests, "Session", Session)
    engine = running_engine()

    ok, detail = engine.probe_web_access(timeout=99)

    assert ok is False
    assert detail == "broken fixture"
    assert engine.last_download_state == "failed"
    assert engine.last_download_bytes == 0


def test_web_access_probe_rejects_page_when_youtube_cdn_is_offline(monkeypatch):
    calls = []

    class Response:
        status_code = 200

        def __init__(self, body):
            self.body = body

        def iter_content(self, chunk_size=None):
            yield self.body

        def close(self):
            pass

    class Session:
        trust_env = True

        def get(self, url, **_kwargs):
            calls.append(url)
            if "i.ytimg.com" in url:
                raise requests.ReadTimeout("YouTube CDN stalled")
            size = 8192 if url == "https://www.youtube.com/" else 4096
            return Response(b"x" * size)

        def close(self):
            pass

    monkeypatch.setattr(engine_module.requests, "Session", Session)
    engine = running_engine()

    ok, detail = engine.probe_web_access()

    assert ok is False
    assert detail == "YouTube CDN stalled"
    assert calls.count(
        "https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg"
    ) == 1
    assert engine.last_download_state == "failed"


def test_web_access_probe_reports_transient_critical_cdn_failure(monkeypatch):
    attempts = {}
    lock = threading.Lock()

    class Response:
        status_code = 200

        def __init__(self, body):
            self.body = body

        def iter_content(self, chunk_size=None):
            yield self.body

        def close(self):
            pass

    class Session:
        trust_env = True

        def get(self, url, **_kwargs):
            with lock:
                attempts[url] = attempts.get(url, 0) + 1
                attempt = attempts[url]
            if "i.ytimg.com" in url and attempt == 1:
                raise requests.ReadTimeout("transient CDN timeout")
            size = 8192 if url == "https://www.youtube.com/" else 4096
            return Response(b"x" * size)

        def close(self):
            pass

    monkeypatch.setattr(engine_module.requests, "Session", Session)
    engine = running_engine()

    ok, detail = engine.probe_web_access()

    assert ok is False
    assert detail == "transient CDN timeout"
    assert attempts[
        "https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg"
    ] == 1
    assert engine.last_download_state == "failed"


def test_download_probe_is_failed_only_when_engine_is_stopped():
    engine = Engine(lambda _line: None, lambda _running: None,
                    lambda _up, _down: None)

    ok, detail = engine.probe_download()

    assert ok is False
    assert detail == "engine stopped"
    assert engine.last_download_state == "failed"


def benchmark_engine(**overrides):
    values = {
        "last_probe_ms": 800.0,
        "last_probe_url": "https://api.ipify.org?format=json",
        "last_upload_state": "not_tested",
        "last_upload_ok": None,
        "last_upload_mbps": 0.0,
        "last_upload_speed_valid": False,
        "last_upload_ms": 0.0,
        "last_upload_reason": "",
        "last_download_state": "verified",
        "last_download_ok": True,
        "last_download_mbps": 8.0,
        "last_download_speed_valid": True,
        "last_download_ms": 260.0,
        "last_download_first_byte_ms": 90.0,
        "last_download_bytes": 256 * 1024,
        "last_download_reason": "sample",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


class StorageStub:
    def __init__(self, carrier="mci", settings=None, profiles=None):
        self.tuning = Tuning(carrier_mode=carrier)
        self.settings = settings or {}
        self.profiles = profiles or []
        self.saved = 0

    def save_settings(self):
        self.saved += 1

    def save_profiles(self):
        pass


def test_mci_score_uses_real_download_and_first_byte_metrics():
    assert mci_quality_score(500, 10.0, 80) > mci_quality_score(500, 0.3, 3000)
    assert mci_quality_score(500, None, None) > mci_quality_score(500, 0.3, 3000)

    storage = StorageStub()
    fast = ProxyProfile(id="fast")
    slow = ProxyProfile(id="slow")
    dummy = SimpleNamespace(storage=storage, engine=benchmark_engine())
    MainWindow._save_profile_benchmark(
        dummy, fast, "wrong_seq", True, carrier="mci", download_state="verified"
    )
    dummy.engine = benchmark_engine(last_download_mbps=0.3,
                                    last_download_first_byte_ms=3000.0,
                                    last_download_ms=1500.0)
    MainWindow._save_profile_benchmark(
        dummy, slow, "wrong_seq", True, carrier="mci", download_state="verified"
    )

    values = storage.settings["profile_benchmarks_pattern_mci"]
    assert values["fast"]["score"] > values["slow"]["score"]
    assert values["fast"]["download_mbps"] == 8.0
    assert values["fast"]["download_first_byte_ms"] == 90.0
    assert values["fast"]["download_bytes"] == 256 * 1024


def test_inconclusive_mci_endpoint_preserves_page_and_verified_speed():
    previous = {
        "ok": True, "page_ok": True, "score": 82, "startup_ms": 700.0,
        "sample_count": 2, "consecutive_failures": 0,
        "download_ok": True, "download_state": "verified",
        "download_mbps": 6.25, "download_speed_valid": True,
        "download_ms": 330.0, "download_first_byte_ms": 110.0,
        "download_bytes": 256 * 1024, "download_sample_count": 2,
        "consecutive_download_failures": 0,
        "download_tested_at": time.time(),
        "engine": "patterniha-wrong-seq-v1", "tested_at": time.time(),
    }
    storage = StorageStub(settings={"profile_benchmarks_pattern_mci": {"p1": previous}})
    engine = benchmark_engine(last_download_state="inconclusive",
                              last_download_ok=None,
                              last_download_mbps=0.0,
                              last_download_speed_valid=False,
                              last_download_ms=1500.0,
                              last_download_first_byte_ms=None,
                              last_download_bytes=0,
                              last_download_reason="ReadTimeout")
    dummy = SimpleNamespace(storage=storage, engine=engine)

    MainWindow._save_profile_benchmark(
        dummy, ProxyProfile(id="p1"), "wrong_seq", True,
        carrier="mci", download_state="inconclusive",
    )

    value = storage.settings["profile_benchmarks_pattern_mci"]["p1"]
    assert value["ok"] is True
    assert value["download_ok"] is True
    assert value["download_state"] == "verified"
    assert value["download_mbps"] == 6.25
    assert value["download_ms"] == 330.0
    assert value["last_download_probe_state"] == "inconclusive"


def test_builtin_mci_payload_failure_immediately_clears_stale_success():
    previous = {
        "ok": True, "page_ok": True, "score": 80, "startup_ms": 600.0,
        "sample_count": 2, "consecutive_failures": 0,
        "download_ok": True, "download_state": "verified",
        "download_mbps": 5.0, "download_speed_valid": True,
        "download_ms": 300.0, "download_first_byte_ms": 90.0,
        "download_bytes": 64 * 1024, "download_sample_count": 1,
        "consecutive_download_failures": 0,
        "download_tested_at": time.time(),
        "engine": "patterniha-wrong-seq-v1", "tested_at": time.time(),
    }
    storage = StorageStub(settings={
        "working_profile_mci": "builtin-1",
        "profile_benchmarks_pattern_mci": {"builtin-1": previous},
    })
    engine = benchmark_engine(last_download_state="failed",
                              last_download_ok=False,
                              last_download_mbps=0.0,
                              last_download_speed_valid=False,
                              last_download_bytes=0,
                              last_download_reason="ReadTimeout")
    dummy = SimpleNamespace(storage=storage, engine=engine)

    MainWindow._save_profile_benchmark(
        dummy, ProxyProfile(id="builtin-1", origin="builtin"),
        "full20", False, carrier="mci", download_state="failed",
    )

    value = storage.settings["profile_benchmarks_pattern_mci"]["builtin-1"]
    assert value["ok"] is False
    assert value["download_ok"] is False
    assert value["download_state"] == "failed"
    assert "working_profile_mci" not in storage.settings


def test_irancell_keeps_original_score_and_ignores_download_fields():
    storage = StorageStub(carrier="irancell")
    engine = benchmark_engine(
        last_probe_ms=1200.0,
        last_probe_url="https://www.youtube.com/generate_204",
        last_download_mbps=100.0,
        last_download_first_byte_ms=1.0,
    )
    dummy = SimpleNamespace(storage=storage, engine=engine)

    MainWindow._save_profile_benchmark(
        dummy, ProxyProfile(id="ir"), "wrong_seq", True,
        carrier="irancell", download_state="verified",
    )

    value = storage.settings["profile_benchmarks_pattern_irancell"]["ir"]
    assert value["score"] == 80
    assert "download_mbps" not in value


def test_mci_profile_order_uses_global_fast_unknown_untested_slow_failed_tiers(monkeypatch):
    now = time.time()
    fast = ProxyProfile(id="fast", origin="github")
    unknown = ProxyProfile(id="unknown", origin="github")
    untested = ProxyProfile(id="untested", origin="github")
    slow = ProxyProfile(id="slow", origin="github")
    failed = ProxyProfile(id="failed", origin="github")
    profiles = [slow, failed, untested, unknown, fast]
    base = {"engine": "patterniha-wrong-seq-v1", "tested_at": now,
            "startup_ms": 500.0, "consecutive_failures": 0}
    benchmarks = {
        "fast": {**base, "ok": True, "score": 90, "download_ok": True,
                 "download_state": "verified", "download_mbps": 8.0,
                 "download_first_byte_ms": 90.0, "download_tested_at": now},
        "unknown": {**base, "ok": True, "score": 88,
                    "download_ok": None, "download_state": "inconclusive"},
        "slow": {**base, "ok": True, "score": 50, "download_ok": True,
                 "download_state": "verified", "download_mbps": 0.4,
                 "download_first_byte_ms": 600.0, "download_tested_at": now},
        "failed": {**base, "ok": False, "score": 0,
                   "consecutive_failures": 2},
    }
    storage = StorageStub(
        settings={"profile_benchmarks_pattern_mci": benchmarks},
        profiles=profiles,
    )
    storage.tuning.pattern_connect_ip = "188.114.98.0"
    dummy = SimpleNamespace(
        storage=storage,
        bridge=SimpleNamespace(log=SimpleNamespace(emit=lambda _line: None)),
    )
    dummy._selected_route_source = lambda: "suggested"
    dummy._route_source_profiles = lambda verified_only=False: [
        profile for profile in profiles
        if not verified_only or profile.verified_spoof
    ]
    monkeypatch.setattr(ui_module, "profile_ping", lambda *_args: (True, 20.0))

    ordered = MainWindow._ordered_profiles(
        dummy, "support.cloudflare.com", threading.Event(), True, False
    )

    assert [profile.id for profile in ordered] == [
        "fast", "unknown", "untested", "slow", "failed"
    ]


def test_builtin_mci_ignores_old_cloudflare_only_success(monkeypatch):
    now = time.time()
    old = ProxyProfile(id="old", origin="builtin")
    web = ProxyProfile(id="web", origin="builtin")
    profiles = [old, web]
    base = {
        "ok": True,
        "engine": "patterniha-wrong-seq-v1",
        "tested_at": now,
        "download_ok": True,
        "download_state": "verified",
        "download_mbps": 8.0,
        "download_bytes": ui_module.MCI_BUILTIN_WEB_GATE_MIN_BYTES,
        "download_first_byte_ms": 90.0,
        "download_tested_at": now,
    }
    storage = StorageStub(settings={
        "profile_benchmarks_pattern_mci": {
            "old": {**base, "score": 99,
                    "url": "https://speed.cloudflare.com/__down"},
            "web": {**base, "score": 80,
                    "url": ui_module.MCI_BUILTIN_WEB_GATE},
        },
    }, profiles=profiles)
    storage.tuning.pattern_connect_ip = "104.18.32.47"
    dummy = SimpleNamespace(
        storage=storage,
        bridge=SimpleNamespace(log=SimpleNamespace(emit=lambda _line: None)),
    )
    dummy._selected_route_source = lambda: "suggested"
    dummy._route_source_profiles = lambda verified_only=False: profiles
    monkeypatch.setattr(ui_module, "profile_ping", lambda *_args: (True, 20.0))

    ordered = MainWindow._ordered_profiles(
        dummy, "support.cloudflare.com", threading.Event(), True, False
    )

    assert [profile.id for profile in ordered] == ["web", "old"]


def test_post_page_probe_and_warmup_are_mci_only_and_advisory(monkeypatch):
    calls = []

    class FakeEngine:
        last_download_state = "not_tested"
        last_download_mbps = 0.0
        last_download_ms = 0.0

        def probe_download(self, **kwargs):
            calls.append(("download", kwargs))
            raise requests.ReadTimeout("Cloudflare stalled")

        def warmup(self, **kwargs):
            calls.append(("warmup", kwargs))

    class ImmediateThread:
        def __init__(self, target, kwargs, **_thread_kwargs):
            self.target = target
            self.kwargs = kwargs

        def start(self):
            self.target(**self.kwargs)

    dummy = SimpleNamespace(
        engine=FakeEngine(),
        bridge=SimpleNamespace(log=SimpleNamespace(emit=lambda _line: None)),
    )
    cancel = threading.Event()
    monkeypatch.setattr(ui_module.threading, "Thread", ImmediateThread)

    assert MainWindow._probe_mci_download(dummy, "irancell", cancel) == (
        "not_tested", "carrier skipped"
    )
    assert MainWindow._schedule_mci_warmup(dummy, "irancell", cancel) is False
    state, detail = MainWindow._probe_mci_download(dummy, "mci", cancel)
    assert state == "inconclusive"
    assert detail == "ReadTimeout"
    assert MainWindow._schedule_mci_warmup(dummy, "mci", cancel) is True
    assert [name for name, _kwargs in calls] == ["download", "warmup"]
    assert calls[0][1]["size"] == 256 * 1024
    assert calls[0][1]["timeout"] == 1.5
    assert calls[1][1]["timeout"] == 2.0
