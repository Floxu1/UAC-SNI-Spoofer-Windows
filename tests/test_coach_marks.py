import time
import pytest
from PySide6.QtWidgets import QApplication, QPushButton, QWidget
from uac_desktop.coach_mark import CoachBubble, CoachQueue

try:
    from tests.test_engine_switch_guard import window  # noqa: F401
except Exception:  # pragma: no cover
    from test_engine_switch_guard import window  # noqa: F401


def pump(ms=50):
    end = time.time() + ms / 1000
    while time.time() < end:
        QApplication.processEvents()


@pytest.fixture
def host(qapp=None):
    app = QApplication.instance() or QApplication([])
    w = QWidget(); w.resize(800, 600)
    b = QPushButton("t", w); b.setGeometry(600, 40, 120, 30)
    w.show(); pump()
    yield w, b
    w.hide(); w.deleteLater()


def test_queue_one_at_a_time_and_once(host):
    w, b = host
    settings = {}
    q = CoachQueue(w, settings, lambda: None, lambda: "fa")
    q.enqueue("a", lambda: b, "الف", "A", "باشه", "OK")
    q.enqueue("b", lambda: b, "ب", "B", "باشه", "OK")
    q._pump(); q._pump()
    assert q.current[0] == "a" and len(q.pending) == 1
    bubble = q.current[1]
    assert bubble.isVisible() and bubble.layoutDirection().name == "RightToLeft"
    bubble.button.click(); pump()
    assert settings["coach_a_seen"] is True and q.current is None
    q._pump(); assert q.current[0] == "b"
    q.enqueue("a", lambda: b, "x", "x", "x", "x")
    assert all(i[0] != "a" for i in q.pending)


def test_bubble_points_at_target_and_follows_resize(host):
    w, b = host
    bub = CoachBubble(w, b, "سلام", "باشه"); bub.show_bubble(); pump()
    assert bub.geometry().top() >= b.geometry().bottom()
    assert bub.geometry().right() <= w.width()
    b.move(100, 400); w.resize(700, 520); pump(100); bub.reposition()
    assert abs(bub.geometry().center().x() - b.geometry().center().x()) < 200 or bub.geometry().left() == 8
    assert bub.side in ("above", "below")


def test_blocked_queue_waits(host):
    w, b = host
    blocked = [True]
    q = CoachQueue(w, {}, lambda: None, lambda: "en", is_blocked=lambda: blocked[0])
    q.enqueue("a", lambda: b, "x", "Hi", "x", "OK"); q._pump()
    assert q.current is None
    blocked[0] = False; q._pump(); assert q.current is not None


def test_disconnect_then_switch_awaits_stop(window, monkeypatch):
    w = window
    from uac_desktop.pow_ui import ENGINE_XRAY, ENGINE_POW
    w.engine_mode = ENGINE_XRAY
    state = {"busy": True}
    monkeypatch.setattr(w, "_engine_busy", lambda: state["busy"])
    switched = []
    monkeypatch.setattr(w, "_switch_engine", lambda *a, **k: switched.append(1))
    w._disconnect_then_switch(timeout=5)
    pump(300)
    assert not switched  # still busy -> must wait
    state["busy"] = False
    pump(400)
    assert switched == [1]


def test_reset_connection_ui_clears_fake_connected(window, monkeypatch):
    w = window
    monkeypatch.setattr(w, "_engine_busy", lambda: False)
    seen = []
    monkeypatch.setattr(w, "_set_connection_visual", lambda s: seen.append(s))
    w.connection_error = "x"
    w._reset_connection_ui()
    assert seen[-1] == "disconnected" and w.connection_error == ""
