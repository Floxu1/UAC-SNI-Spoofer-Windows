from __future__ import annotations

import os
import time
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QEventLoop, QRect, Qt
from PySide6.QtGui import QColor, QImage, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QLabel,
    QLineEdit,
    QMainWindow,
    QProgressBar,
    QPushButton,
    QStackedWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from uac_desktop.assistant import (
    AssistantAssetManager,
    AssistantBubbleTail,
    AssistantContext,
    AssistantContextCollector,
    AssistantController,
    AssistantDecision,
    AssistantMessageBubble,
    AssistantMessageQueue,
    AssistantPositionManager,
    AssistantSettings,
    AssistantState,
    AssistantStateResolver,
)
from uac_desktop.assistant_messages import LRI, PDI, ltr, message, mixed


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance() or QApplication(["assistant-tests"])
    yield app


def _process_events(app: QApplication, milliseconds: int = 0) -> None:
    deadline = time.monotonic() + (milliseconds / 1000)
    while True:
        app.processEvents(QEventLoop.AllEvents, 20)
        if time.monotonic() >= deadline:
            break
        time.sleep(0.005)


class StorageStub:
    def __init__(self, settings=None):
        self.settings = dict(settings or {})
        self.save_count = 0

    def save_settings(self):
        self.save_count += 1


class LogStub:
    def __init__(self):
        self.messages = []

    def emit(self, value):
        self.messages.append(str(value))


class DemoWindow(QMainWindow):
    TARGETS = {
        0: ("connect_button", "country_combo"),
        1: ("profile_tabs", "add_btn", "profile_ping_all_btn"),
        2: ("maker_repo_url", "maker_text_btn", "maker_start_btn", "maker_table"),
        3: ("domains",),
        4: ("logs",),
        5: ("process_table",),
        6: ("tools_grid",),
        7: ("assistant_replay_button",),
    }

    def __init__(self):
        super().__init__()
        self.resize(960, 680)
        self.storage = StorageStub()
        self.bridge = SimpleNamespace(log=LogStub())
        self.engine = SimpleNamespace(running=False, tun_running=False)
        self._closing = False
        self.connection_error = ""
        self.connecting = False
        self.scanning = False
        self._maker_import_in_progress = False
        self._maker_running = False
        self._maker_profiles = {}
        self._gateway_apply_target = None
        self._gateway_runtime_state = "inactive"
        self._update_in_progress = False
        self._profile_ping_busy = False

        central = QWidget(self)
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        self.stack = QStackedWidget(central)
        root.addWidget(self.stack)
        self.pages = []
        for page_index in range(8):
            page = QWidget()
            page.setObjectName(f"page_{page_index}")
            layout = QVBoxLayout(page)
            for name in self.TARGETS[page_index]:
                widget = QTextEdit() if name == "maker_repo_url" else QPushButton(name)
                widget.setObjectName(name)
                setattr(self, name, widget)
                layout.addWidget(widget)
            layout.addStretch()
            self.pages.append(page)
            self.stack.addWidget(page)

        self.maker_source_editor = self.maker_repo_url
        self.invalid_field = QLineEdit(self.pages[0])
        self.invalid_field.setObjectName("requiredInput")
        self.pages[0].layout().insertWidget(0, self.invalid_field)
        self.validation_label = QLabel("", self.pages[0])
        self.validation_label.setObjectName("validationError")
        self.pages[0].layout().insertWidget(1, self.validation_label)

        self.maker_progress = SimpleNamespace(bar=QProgressBar(), _maximum=10)
        self.scan_progress = SimpleNamespace(bar=QProgressBar(), _maximum=20)
        self.activity_bar = SimpleNamespace(
            state="idle", updated_at=0.0, message=QLabel("")
        )

        self.toast = QFrame(central)
        self.toast.setObjectName("toast")
        toast_layout = QVBoxLayout(self.toast)
        self.toast_text = QLabel("")
        self.toast_text.setObjectName("toastText")
        toast_layout.addWidget(self.toast_text)
        self.toast.hide()

    def show_page(self, index: int):
        self.stack.setCurrentIndex(int(index))


@pytest.fixture
def demo_window(qapp):
    window = DemoWindow()
    window.show()
    _process_events(qapp, 20)
    yield window
    controller = getattr(window, "_test_controller", None)
    if controller is not None:
        controller.disable(persist=False)
    window.close()
    window.deleteLater()
    _process_events(qapp, 20)


def _context(**values) -> AssistantContext:
    defaults = {"captured_at": 100.0}
    defaults.update(values)
    return AssistantContext(**defaults)


def test_state_resolver_enforces_global_priority_order(qapp):
    invalid = QLineEdit()
    context = _context(
        active_error="خطای فعال",
        active_warning="هشدار فعال",
        invalid_widgets=[invalid],
        missing_prerequisites=["input"],
        operation_running=True,
        operation_kind="scan",
        fresh_success="انجام شد",
        success_at=99.0,
    )

    decision = AssistantStateResolver().resolve(context)

    assert decision is not None
    assert (decision.state, decision.priority, decision.target) == (
        AssistantState.SAD,
        100,
        invalid,
    )


@pytest.mark.parametrize(
    ("values", "expected_state", "expected_priority"),
    [
        ({"active_warning": "هشدار", "invalid_widgets": [None], "operation_running": True}, AssistantState.SURPRISED, 90),
        ({"validation_errors": ["فیلد اشتباهه"], "operation_running": True}, AssistantState.CONFUSED, 80),
        ({"missing_prerequisites": ["source"], "operation_running": True}, AssistantState.CONFUSED, 75),
        ({"operation_running": True, "operation_kind": "scan"}, AssistantState.THINKING, 70),
        ({"operation_running": True, "operation_kind": "maker_test"}, AssistantState.WAITING, 70),
        ({"fresh_success": "تموم شد", "success_at": 95.0}, AssistantState.HAPPY, 60),
    ],
)
def test_state_resolver_selects_each_priority_tier(values, expected_state, expected_priority):
    decision = AssistantStateResolver().resolve(_context(**values))
    assert decision is not None
    assert (decision.state, decision.priority) == (expected_state, expected_priority)


def test_state_resolver_ignores_stale_success():
    assert AssistantStateResolver().resolve(
        _context(fresh_success="old", success_at=90.0)
    ) is None


def test_persian_messages_use_rtl_and_unicode_bidi_isolation(qapp):
    assert ltr("Settings") == f"{LRI}Settings{PDI}"
    assert f"{LRI}User Config{PDI}" in message("configs_tabs")
    assert mixed("Connection timeout") == f"{LRI}Connection timeout{PDI}"
    assert mixed("خطای API Key") == f"خطای {LRI}API Key{PDI}"

    bubble = AssistantMessageBubble(reduced_motion=True)
    bubble.set_message(message("configs_tabs"), False, False, False, True)
    assert bubble.layoutDirection() == Qt.RightToLeft
    assert bubble.text.layoutDirection() == Qt.RightToLeft
    assert bubble.text.alignment() & Qt.AlignRight
    assert bubble.text.wordWrap()
    assert bubble.close_button.accessibleName()
    bubble.deleteLater()


def _save_test_image(path: Path, *, width=20, height=20, opaque_rect=QRect(4, 5, 6, 7)) -> None:
    image = QImage(width, height, QImage.Format_ARGB32)
    image.fill(QColor(0, 0, 0, 0))
    for x in range(opaque_rect.left(), opaque_rect.right() + 1):
        for y in range(opaque_rect.top(), opaque_rect.bottom() + 1):
            image.setPixelColor(x, y, QColor(220, 30, 40, 255))
    assert image.save(str(path))


def test_asset_mapping_covers_every_state_and_shipped_files_exist():
    expected = {
        state: f"wizard_{index:02d}_{state.value}.png"
        for index, state in enumerate(AssistantState, start=1)
    }
    assert AssistantAssetManager.FILES == expected

    root = Path(__file__).resolve().parents[1] / "wizard guider"
    assert AssistantAssetManager(root).available_states() == set(AssistantState)


def test_asset_manager_crops_alpha_and_falls_back_to_normal(qapp, tmp_path):
    normal_path = tmp_path / AssistantAssetManager.FILES[AssistantState.NORMAL]
    _save_test_image(normal_path)
    warnings = []
    manager = AssistantAssetManager(tmp_path, warnings.append)

    normal = manager.pixmap(AssistantState.NORMAL)
    fallback = manager.pixmap(AssistantState.SAD)

    assert (normal.width(), normal.height()) == (6, 7)
    assert not fallback.isNull()
    assert fallback.toImage() == normal.toImage()
    assert manager.available_states() == {AssistantState.NORMAL}
    assert len(warnings) == 1
    assert "wizard_05_sad.png" in warnings[0]


def test_asset_manager_missing_folder_returns_empty_pixmap_and_logs_once(qapp, tmp_path):
    missing = tmp_path / "missing-assets"
    warnings = []
    manager = AssistantAssetManager(missing, warnings.append)

    assert manager.available_states() == set()
    assert manager.pixmap(AssistantState.CONFUSED).isNull()
    assert manager.pixmap(AssistantState.CONFUSED).isNull()
    assert len(warnings) == 2
    assert "wizard_07_confused.png" in warnings[0]
    assert "wizard_01_normal.png" in warnings[1]


def test_position_manager_keeps_all_rectangles_in_bounds(qapp):
    host = QWidget()
    host.resize(900, 620)
    target = QWidget(host)
    target.setGeometry(770, 530, 90, 45)
    pixmap = QPixmap(160, 260)
    pixmap.fill(Qt.transparent)

    assistant_rect, bubble_rect, target_rect, _mirrored = AssistantPositionManager().calculate(
        host, target, pixmap
    )

    bounds = host.rect().adjusted(16, 16, -16, -16)
    assert bounds.contains(assistant_rect)
    assert bounds.contains(bubble_rect)
    assert target_rect == target.geometry()
    host.deleteLater()


def test_guiding_image_mirrors_only_when_assistant_is_right_of_target(qapp):
    host = QWidget()
    host.resize(800, 600)
    pixmap = QPixmap(100, 200)
    pixmap.fill(Qt.transparent)
    positioner = AssistantPositionManager()

    left_target = QWidget(host)
    left_target.setGeometry(30, 250, 60, 40)
    assistant_right, _, target_left_rect, mirror_on_right = positioner.calculate(
        host, left_target, pixmap
    )
    right_target = QWidget(host)
    right_target.setGeometry(700, 250, 60, 40)
    assistant_left, _, target_right_rect, mirror_on_left = positioner.calculate(
        host, right_target, pixmap
    )

    assert assistant_right.center().x() > target_left_rect.center().x()
    assert mirror_on_right is True
    assert assistant_left.center().x() < target_right_rect.center().x()
    assert mirror_on_left is False
    host.deleteLater()


def test_message_queue_prioritizes_and_replaces_obsolete_lower_priority_items():
    queue = AssistantMessageQueue()
    low = AssistantDecision(AssistantState.NORMAL, "low", 10, page_index=0)
    medium = AssistantDecision(AssistantState.HAPPY, "medium", 50, page_index=0)
    high = AssistantDecision(AssistantState.SAD, "high", 100, page_index=0)

    queue.push(low)
    queue.push(medium)
    queue.push(high)

    assert queue.pop(0) is high
    assert queue.pop(0) is None


def test_message_queue_keeps_priority_order_and_discards_other_pages():
    queue = AssistantMessageQueue()
    global_item = AssistantDecision(AssistantState.WAITING, "global", 80, page_index=-1)
    page_zero = AssistantDecision(AssistantState.HAPPY, "zero", 60, page_index=0)
    page_one = AssistantDecision(AssistantState.CONFUSED, "one", 40, page_index=1)
    queue.push(global_item)
    queue.push(page_zero)
    queue.push(page_one)
    queue.discard_other_pages(1)

    assert queue.pop(1) is global_item
    assert queue.pop(1) is page_one
    assert queue.pop(1) is None


def test_assistant_settings_persist_toggle_seen_and_reset():
    storage = StorageStub()
    settings = AssistantSettings(storage)

    assert settings.enabled is False
    assert settings.guides_enabled is True
    settings.set_enabled(True)
    settings.mark_seen("home_connect")
    settings.mark_seen("configs_tabs")

    restored = AssistantSettings(storage)
    assert restored.enabled is True
    assert restored.seen() == {"home_connect", "configs_tabs"}
    assert storage.settings["assistant_seen_guides"] == ["configs_tabs", "home_connect"]

    restored.reset_guides()
    assert restored.seen() == set()
    assert restored.guides_enabled is True
    assert storage.save_count == 4


def test_controller_enable_disable_cleans_widgets_timers_queue_and_state(qapp, demo_window, tmp_path):
    controller = AssistantController(demo_window, tmp_path, reduced_motion=True)
    demo_window._test_controller = controller

    controller.enable()
    controller.queue.push(
        AssistantDecision(AssistantState.HAPPY, "queued", 60, page_index=0)
    )
    controller._tour = controller.registry.all()
    assert controller.enabled is True
    assert controller.settings.enabled is True
    assert controller._evaluate_timer.isActive()
    assert controller.overlay is not None
    assert controller.bubble is not None

    controller.disable()

    assert controller.enabled is False
    assert controller.settings.enabled is False
    assert not controller._evaluate_timer.isActive()
    assert not controller._reposition_timer.isActive()
    assert not controller._hide_timer.isActive()
    assert controller.queue.pop(0) is None
    assert controller._tour == []
    assert controller._tour_index == -1
    assert controller.current_decision is None
    assert controller.current_context is None
    assert controller.overlay is None
    assert controller.bubble is None
    assert controller._host is None


def test_context_snapshot_detects_current_page_validation_operation_and_progress(demo_window):
    demo_window.stack.setCurrentIndex(0)
    demo_window.invalid_field.setProperty("invalid", True)
    demo_window.validation_label.setText("این مقدار درست نیست.")
    demo_window._maker_running = True
    demo_window.maker_progress.bar.setMaximum(10)
    demo_window.maker_progress.bar.setValue(4)

    snapshot = AssistantContextCollector(demo_window).collect("requiredInput", 12.5)

    assert (snapshot.page_index, snapshot.page_name, snapshot.route) == (0, "home", "home")
    assert demo_window.invalid_field in snapshot.invalid_widgets
    assert snapshot.validation_errors == ["این مقدار درست نیست."]
    assert (snapshot.operation_running, snapshot.operation_kind) == (True, "maker_test")
    assert (snapshot.progress_value, snapshot.progress_maximum) == (4, 10)
    assert (snapshot.last_action, snapshot.last_action_at) == ("requiredInput", 12.5)
    assert "requiredInput" in snapshot.visible_target_names


def test_context_snapshot_and_resolver_follow_live_error_loading_success_and_normal(demo_window):
    collector = AssistantContextCollector(demo_window)
    resolver = AssistantStateResolver()

    assert resolver.resolve(collector.collect()) is None

    demo_window.connecting = True
    assert resolver.resolve(collector.collect()).state == AssistantState.THINKING

    demo_window.connecting = False
    demo_window.activity_bar.state = "success"
    demo_window.activity_bar.updated_at = time.time()
    demo_window.activity_bar.message.setText("اتصال برقرار شد")
    assert resolver.resolve(collector.collect()).state == AssistantState.HAPPY

    demo_window.connection_error = "Connection timeout"
    error = resolver.resolve(collector.collect())
    assert error.state == AssistantState.SAD
    assert f"{LRI}Connection timeout{PDI}" in error.text

    demo_window.connection_error = ""
    demo_window.activity_bar.updated_at = time.time() - 30
    assert resolver.resolve(collector.collect()) is None


def _install_realistic_maker_inputs(window: DemoWindow):
    page = window.pages[2]
    layout = page.layout()
    repository_url = QLineEdit(page)
    repository_url.setObjectName("makerRepoUrl")
    repository_load = QPushButton("دریافت", page)
    repository_load.setObjectName("makerRepoButton")
    manual_editor = QTextEdit(page)
    manual_editor.setObjectName("makerSourceEditor")
    layout.insertWidget(0, repository_url)
    layout.insertWidget(1, repository_load)
    layout.insertWidget(2, manual_editor)
    window.maker_repo_url = repository_url
    window.maker_repo_btn = repository_load
    window.maker_source_editor = manual_editor
    return repository_url, repository_load, manual_editor


def test_sni_maker_url_present_guides_user_to_load_button(
    qapp, demo_window, tmp_path
):
    repository_url, repository_load, manual_editor = _install_realistic_maker_inputs(
        demo_window
    )
    demo_window.stack.setCurrentIndex(2)
    repository_url.setText("https://example.test/subscription")
    manual_editor.clear()
    repository_url.setFocus()
    _process_events(qapp, 20)

    controller = AssistantController(demo_window, tmp_path, reduced_motion=True)
    demo_window._test_controller = controller
    controller.enable()
    controller._evaluate_timer.stop()
    controller.evaluate(force=True)

    assert controller.current_decision is not None
    assert controller.current_decision.target is repository_load
    assert "دریافت" in controller.current_decision.text


def test_sni_maker_focused_empty_manual_editor_gets_manual_input_prompt(
    qapp, demo_window, tmp_path
):
    repository_url, _repository_load, manual_editor = _install_realistic_maker_inputs(
        demo_window
    )
    demo_window.stack.setCurrentIndex(2)
    repository_url.setText("https://example.test/subscription")
    manual_editor.clear()
    manual_editor.setFocus()
    _process_events(qapp, 20)

    controller = AssistantController(demo_window, tmp_path, reduced_motion=True)
    demo_window._test_controller = controller
    controller.enable()
    controller._evaluate_timer.stop()
    controller.evaluate(force=True)

    assert controller.current_context.focus_widget is manual_editor
    assert controller.current_decision is not None
    assert controller.current_decision.target is manual_editor
    assert "کانفیگ" in controller.current_decision.text


def test_tour_next_previous_and_cross_page_navigation(qapp, demo_window, tmp_path):
    controller = AssistantController(demo_window, tmp_path, reduced_motion=True)
    demo_window._test_controller = controller
    controller.enable()
    controller._evaluate_timer.stop()

    controller.start_tour()
    _process_events(qapp, 120)
    assert controller._tour_index == 0
    assert controller.current_decision.guide_id == "home_connect"
    assert demo_window.stack.currentIndex() == 0

    controller.next_step()
    _process_events(qapp, 120)
    assert controller._tour_index == 1
    assert controller.current_decision.guide_id == "home_country"

    controller.next_step()
    _process_events(qapp, 120)
    assert controller._tour_index == 2
    assert controller.current_decision.guide_id == "configs_tabs"
    assert demo_window.stack.currentIndex() == 1

    controller.previous_step()
    _process_events(qapp, 120)
    assert controller._tour_index == 1
    assert controller.current_decision.guide_id == "home_country"
    assert demo_window.stack.currentIndex() == 0

    controller.skip_tour()
    assert controller._tour == []
    assert controller._tour_index == -1


def test_position_manager_avoids_covering_the_target(qapp):
    host = QWidget()
    host.resize(1100, 700)
    target = QWidget(host)
    target.setGeometry(480, 300, 150, 60)
    pixmap = QPixmap(150, 240)
    pixmap.fill(Qt.transparent)

    _assistant, bubble, target_rect, _mirrored = AssistantPositionManager().calculate(
        host, target, pixmap, bubble_size=QRect(0, 0, 360, 170).size()
    )

    assert not bubble.intersects(target_rect.adjusted(-10, -10, 10, 10))
    host.deleteLater()


def test_dialog_context_resolves_to_dialog_guidance(qapp, demo_window):
    dialog = QDialog(demo_window)
    field = QLineEdit(dialog)
    field.setObjectName("dialogField")
    layout = QVBoxLayout(dialog)
    layout.addWidget(field)
    dialog.show()
    dialog.activateWindow()
    field.setFocus()
    _process_events(qapp, 20)

    context = AssistantContextCollector(demo_window).collect()
    decision = AssistantStateResolver().resolve(context)

    assert context.active_dialog is dialog
    assert decision is not None
    assert decision.state == AssistantState.GUIDING_RIGHT
    assert decision.target is field
    dialog.close()


def test_stale_connection_error_expires_from_live_context(demo_window):
    collector = AssistantContextCollector(demo_window)
    demo_window.connection_error = "old error"
    assert collector.collect().active_error == "old error"
    collector._connection_error_at -= 61
    assert collector.collect().active_error == ""


def test_dismissed_normal_message_respects_cooldown(qapp, demo_window, tmp_path):
    demo_window.storage.settings["assistant_guides_enabled"] = False
    controller = AssistantController(demo_window, tmp_path, reduced_motion=True)
    demo_window._test_controller = controller
    controller.enable()
    _process_events(qapp, 20)
    controller.evaluate(force=True)
    assert controller.current_decision.state == AssistantState.NORMAL
    controller.dismiss_message()
    assert controller.bubble.isHidden()
    controller.evaluate()
    assert controller.bubble.isHidden()


def test_first_visit_guide_stays_visible_until_acknowledged(qapp, demo_window, tmp_path):
    controller = AssistantController(demo_window, tmp_path, reduced_motion=True)
    demo_window._test_controller = controller
    controller.enable()
    _process_events(qapp, 850)
    assert controller.current_decision.guide_id == "home_connect"
    assert controller.bubble.isVisible()
    assert "home_connect" not in controller.settings.seen()
    controller.dismiss_message()
    assert "home_connect" in controller.settings.seen()


def test_tools_guide_resolves_first_widget_from_list(demo_window, tmp_path):
    controller = AssistantController(demo_window, tmp_path, reduced_motion=True)
    demo_window.tool_cards = [QPushButton("first", demo_window.pages[6])]
    assert controller._resolve_target("tool_cards") is demo_window.tool_cards[0]
    controller.deleteLater()


def test_bubble_tail_renders_in_both_directions(qapp):
    tail = AssistantBubbleTail()
    tail.show()
    for direction in ("left", "right"):
        tail.set_direction(direction)
        image = QImage(tail.size(), QImage.Format_ARGB32)
        image.fill(Qt.transparent)
        tail.render(image)
        assert any(
            image.pixelColor(x, y).alpha() > 0
            for x in range(image.width())
            for y in range(image.height())
        )
    tail.deleteLater()


def test_warning_preference_does_not_hide_invalid_field_guidance(qapp, demo_window, tmp_path):
    demo_window.storage.settings.update({
        "assistant_guides_enabled": False,
        "assistant_warnings_enabled": False,
    })
    demo_window.invalid_field.setProperty("invalid", True)
    controller = AssistantController(demo_window, tmp_path, reduced_motion=True)
    demo_window._test_controller = controller
    controller.enable()
    _process_events(qapp, 20)
    controller.evaluate(force=True)
    assert controller.current_decision.state == AssistantState.CONFUSED


def test_warning_preference_hides_error_state(qapp, demo_window, tmp_path):
    demo_window.storage.settings.update({
        "assistant_guides_enabled": False,
        "assistant_warnings_enabled": False,
    })
    demo_window.connection_error = "Connection timeout"
    controller = AssistantController(demo_window, tmp_path, reduced_motion=True)
    demo_window._test_controller = controller
    controller.enable()
    _process_events(qapp, 20)
    controller.evaluate(force=True)
    assert controller.current_decision.state == AssistantState.NORMAL


def test_modal_host_destruction_leaves_controller_operational(qapp, demo_window, tmp_path):
    controller = AssistantController(demo_window, tmp_path, reduced_motion=True)
    demo_window._test_controller = controller
    controller.enable()
    dialog = QDialog(demo_window)
    dialog.setModal(True)
    dialog.show()
    _process_events(qapp, 20)
    controller.evaluate(force=True)
    assert controller._host is dialog
    dialog.close()
    dialog.deleteLater()
    _process_events(qapp, 30)
    controller.evaluate(force=True)
    assert controller._host is demo_window.centralWidget()


def test_reposition_stays_inside_host_after_resize(qapp, demo_window, tmp_path):
    demo_window.storage.settings["assistant_guides_enabled"] = False
    controller = AssistantController(demo_window, tmp_path, reduced_motion=True)
    demo_window._test_controller = controller
    controller.enable()
    _process_events(qapp, 20)
    for width, height in ((700, 520), (1200, 760)):
        demo_window.resize(width, height)
        _process_events(qapp, 20)
        controller.schedule_reposition()
        _process_events(qapp, 40)
        host_rect = controller._host.rect()
        assert host_rect.contains(controller.bubble.geometry())
        assert host_rect.contains(controller.overlay._assistant_rect)


def test_main_window_assistant_controls_stay_locked(qapp, tmp_path, monkeypatch):
    import uac_desktop.storage as storage_module
    import uac_desktop.ui as ui_module

    for name, filename in (
        ("SETTINGS_FILE", "settings.json"),
        ("PROFILES_FILE", "profiles.json"),
        ("BOOKMARKS_FILE", "bookmarks.json"),
        ("SNI_RESULTS_FILE", "sni-results.json"),
    ):
        monkeypatch.setattr(storage_module, name, tmp_path / filename)
    monkeypatch.setattr(ui_module.MainWindow, "_setup_tray", lambda self: setattr(self, "_tray", None))
    monkeypatch.setattr(ui_module.MainWindow, "refresh_processes", lambda self: None)
    monkeypatch.setattr(ui_module.MainWindow, "check_for_updates", lambda self, manual=False: None)
    monkeypatch.setattr(ui_module.MainWindow, "_queue_target_latency_probe", lambda self: None)
    monkeypatch.setattr(ui_module.Engine, "recover_stale_tun", lambda self: None)

    window = ui_module.MainWindow()
    try:
        window.show()
        _process_events(qapp, 20)
        assert window.assistant_toggle.isChecked() is False
        assert window.assistant_toggle.isEnabled() is False
        assert window.assistant_option.row_click_enabled is False
        assert window.assistant_guides_toggle.isChecked() is True
        assert window.assistant_warnings_toggle.isChecked() is True
        window.assistant_toggle.setChecked(True)
        _process_events(qapp, 20)
        assert window.assistant_toggle.isChecked() is False
        assert window.assistant_controller is None
        assert window.storage.settings["assistant_enabled"] is False
        window.assistant_replay_button.click()
        _process_events(qapp, 120)
        assert window.assistant_toggle.isChecked() is False
    finally:
        window._force_quit = True
        window.close()
