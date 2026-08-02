from __future__ import annotations

import inspect
import os
import time
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QEvent, QEventLoop, QPoint, QRect, QSize, Qt
from PySide6.QtGui import QColor, QImage, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QMainWindow,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from uac_desktop.assistant import (
    AssistantBubbleTail,
    AssistantController,
    AssistantDecision,
    AssistantMessageBubble,
    AssistantPositionManager,
    AssistantState,
)


SAFE_EDGE = 16
BUBBLE_ASSISTANT_GAP = 16
CONTROL_GAP = 12


@pytest.fixture(scope="session")
def qapp():
    return QApplication.instance() or QApplication(["assistant-layout-tests"])


def _process_events(app: QApplication, milliseconds: int = 0) -> None:
    deadline = time.monotonic() + milliseconds / 1000
    while True:
        app.processEvents(QEventLoop.AllEvents, 20)
        if time.monotonic() >= deadline:
            return
        time.sleep(0.005)


def _pixmap(width: int = 180, height: int = 260) -> QPixmap:
    pixmap = QPixmap(width, height)
    pixmap.fill(QColor(30, 100, 220, 255))
    return pixmap


def _safe_area(host: QWidget) -> QRect:
    return host.rect().adjusted(SAFE_EDGE, SAFE_EDGE, -SAFE_EDGE, -SAFE_EDGE)


def _placement_values(result):
    if isinstance(result, tuple):
        assert len(result) >= 4
        return result[0], result[1], result[2], bool(result[3])
    return (
        QRect(result.assistant_rect),
        QRect(result.bubble_rect),
        QRect(result.target_rect),
        bool(result.mirrored),
    )


def _calculate(
    manager: AssistantPositionManager,
    host: QWidget,
    target: QWidget | None,
    *,
    bubble_size: QSize = QSize(330, 180),
    exclusion_rects: list[QRect] | None = None,
    preferred: str = "auto",
    previous=None,
):
    method = getattr(manager, "calculate_placement", None) or manager.calculate
    signature = inspect.signature(method)
    if exclusion_rects and "exclusion_rects" not in signature.parameters:
        pytest.fail("placement engine does not accept critical exclusion rectangles")
    values = {
        "host": host,
        "target": target,
        "pixmap": _pixmap(),
        "preferred": preferred,
        "bubble_size": bubble_size,
        "exclusion_rects": exclusion_rects,
        "previous": previous,
    }
    kwargs = {
        name: value
        for name, value in values.items()
        if name in signature.parameters and (value is not None or name in {"target", "previous"})
    }
    return method(**kwargs)


def _axis_gap(first: QRect, second: QRect) -> tuple[int, int]:
    horizontal = max(first.left() - second.right() - 1, second.left() - first.right() - 1, 0)
    vertical = max(first.top() - second.bottom() - 1, second.top() - first.bottom() - 1, 0)
    return horizontal, vertical


def _assert_no_overlap_with_gap(first: QRect, second: QRect, gap: int) -> None:
    assert not first.intersects(second), (first, second)
    horizontal, vertical = _axis_gap(first, second)
    assert max(horizontal, vertical) >= gap, (first, second, horizontal, vertical)


@pytest.mark.parametrize(
    ("host_size", "target_geometry", "bubble_size"),
    [
        (QSize(1200, 760), QRect(1020, 300, 110, 48), QSize(320, 150)),
        (QSize(900, 620), QRect(30, 260, 100, 48), QSize(360, 210)),
        (QSize(760, 520), QRect(330, 230, 100, 50), QSize(350, 250)),
        (QSize(700, 500), QRect(), QSize(390, 300)),
    ],
)
def test_bubble_never_overlaps_full_assistant_bounding_rect(
    qapp, host_size, target_geometry, bubble_size
):
    host = QWidget()
    host.resize(host_size)
    target = None
    if target_geometry.isValid() and not target_geometry.isEmpty():
        target = QWidget(host)
        target.setGeometry(target_geometry)

    result = _calculate(
        AssistantPositionManager(), host, target, bubble_size=bubble_size
    )
    assistant_rect, bubble_rect, _target_rect, _mirrored = _placement_values(result)

    _assert_no_overlap_with_gap(assistant_rect, bubble_rect, BUBBLE_ASSISTANT_GAP)
    host.deleteLater()


@pytest.mark.parametrize(
    "host_size",
    [QSize(1200, 760), QSize(720, 480), QSize(420, 300), QSize(300, 220)],
)
def test_assistant_and_bubble_are_fully_contained_in_active_viewport(qapp, host_size):
    host = QWidget()
    host.resize(host_size)
    result = _calculate(
        AssistantPositionManager(), host, None, bubble_size=QSize(330, 180)
    )
    assistant_rect, bubble_rect, _target_rect, _mirrored = _placement_values(result)

    safe = _safe_area(host)
    assert safe.contains(assistant_rect), (safe, assistant_rect)
    assert safe.contains(bubble_rect), (safe, bubble_rect)
    host.deleteLater()


@pytest.mark.parametrize(
    "target_geometry",
    [
        QRect(30, 30, 150, 48),
        QRect(910, 30, 150, 48),
        QRect(30, 610, 150, 48),
        QRect(910, 610, 150, 48),
        QRect(500, 330, 150, 48),
    ],
)
def test_target_is_an_exclusion_zone_for_bubble_and_assistant(qapp, target_geometry):
    host = QWidget()
    host.resize(1120, 720)
    target = QWidget(host)
    target.setGeometry(target_geometry)

    result = _calculate(
        AssistantPositionManager(), host, target, bubble_size=QSize(350, 190)
    )
    assistant_rect, bubble_rect, target_rect, _mirrored = _placement_values(result)
    padded_target = target_rect.adjusted(
        -CONTROL_GAP, -CONTROL_GAP, CONTROL_GAP, CONTROL_GAP
    )

    assert not assistant_rect.intersects(padded_target)
    assert not bubble_rect.intersects(padded_target)
    host.deleteLater()


def test_critical_sidebar_and_primary_controls_are_excluded(qapp):
    host = QWidget()
    host.resize(1100, 720)
    sidebar = QRect(16, 16, 190, 688)
    primary_action = QRect(760, 620, 300, 64)
    critical = [sidebar, primary_action]

    result = _calculate(
        AssistantPositionManager(),
        host,
        None,
        bubble_size=QSize(350, 180),
        exclusion_rects=critical,
    )
    assistant_rect, bubble_rect, _target_rect, _mirrored = _placement_values(result)

    for zone in critical:
        padded = zone.adjusted(-CONTROL_GAP, -CONTROL_GAP, CONTROL_GAP, CONTROL_GAP)
        assert not assistant_rect.intersects(padded)
        assert not bubble_rect.intersects(padded)
    host.deleteLater()


def test_tiny_viewport_uses_non_overlapping_contained_fallback_layout(qapp):
    host = QWidget()
    host.resize(300, 220)

    result = _calculate(
        AssistantPositionManager(), host, None, bubble_size=QSize(300, 180)
    )
    assistant_rect, bubble_rect, _target_rect, _mirrored = _placement_values(result)
    safe = _safe_area(host)

    assert safe.contains(assistant_rect)
    assert safe.contains(bubble_rect)
    assert not assistant_rect.intersects(bubble_rect)
    assert assistant_rect.width() >= 56 and assistant_rect.height() >= 72
    assert bubble_rect.width() >= 180 and bubble_rect.height() >= 72
    host.deleteLater()


class _Storage:
    def __init__(self):
        self.settings = {
            "assistant_enabled": False,
            "assistant_guides_enabled": False,
        }

    def save_settings(self):
        pass


class _Log:
    def __init__(self):
        self.messages = []

    def emit(self, value):
        self.messages.append(str(value))


class LayoutWindow(QMainWindow):
    def __init__(self, size=QSize(1100, 720)):
        super().__init__()
        self.resize(size)
        self.storage = _Storage()
        self.bridge = SimpleNamespace(log=_Log())
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
        self.activity_bar = SimpleNamespace(
            state="idle", updated_at=0.0, message=QPushButton("")
        )

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        self.stack = QStackedWidget()
        self.page = QWidget()
        page_layout = QVBoxLayout(self.page)
        self.target = QPushButton("کنترل هدف")
        self.target.setObjectName("layoutTarget")
        page_layout.addWidget(self.target)
        page_layout.addStretch()
        self.stack.addWidget(self.page)
        layout.addWidget(self.stack)

    def show_page(self, index: int):
        self.stack.setCurrentIndex(index)


def _write_asset(root: Path) -> None:
    image = QImage(180, 260, QImage.Format_ARGB32)
    image.fill(QColor(0, 0, 0, 0))
    for x in range(10, 171):
        for y in range(5, 256):
            image.setPixelColor(x, y, QColor(40, 110, 230, 255))
    assert image.save(str(root / "wizard_01_normal.png"))


@pytest.fixture
def layout_controller(qapp, tmp_path):
    _write_asset(tmp_path)
    window = LayoutWindow()
    window.show()
    _process_events(qapp, 20)
    controller = AssistantController(window, tmp_path, reduced_motion=True)
    controller.enabled = True
    controller._ensure_widgets()
    yield window, controller
    controller.disable(persist=False)
    window.close()
    window.deleteLater()
    _process_events(qapp, 20)


def _show_text(controller: AssistantController, text: str) -> QRect:
    controller.show_decision(
        AssistantDecision(AssistantState.NORMAL, text, 10, timeout=0)
    )
    QApplication.processEvents()
    return QRect(controller.bubble.geometry())


def test_short_and_long_persian_messages_get_responsive_distinct_sizes(
    qapp, layout_controller
):
    window, controller = layout_controller
    short_rect = _show_text(controller, "همه‌چی خوبه. من اینجام.")
    short_text_height = controller.bubble.text.height()
    long_text = (
        "این یک پیام فارسی طولانی برای بررسی اندازه‌ی واکنش‌گرا و شکستن درست "
        "خط‌هاست. برای ادامه، گزینه‌ی موردنظر رو بررسی کن و بعد روی دکمه بزن. "
    ) * 8
    long_rect = _show_text(controller, long_text)
    long_text_height = controller.bubble.text.height()

    logical_maximum = min(420, int((window.centralWidget().width() - 32) * 0.35))
    assert 220 <= short_rect.width() <= 360
    assert short_rect.height() <= 190
    assert short_rect.width() <= long_rect.width() <= logical_maximum
    assert long_rect.height() > short_rect.height()
    assert long_text_height > short_text_height
    assert _safe_area(window.centralWidget()).contains(long_rect)
    assert controller.bubble.text.wordWrap()
    assert controller.bubble.text.layoutDirection() == Qt.RightToLeft
    assert controller.bubble.text.geometry().bottom() < controller.bubble.ack_button.geometry().top()


@pytest.mark.parametrize("direction", ["left", "right", "top", "bottom"])
def test_tail_supports_all_four_directions(qapp, direction):
    tail = AssistantBubbleTail()
    tail.set_direction(direction)

    assert tail._direction == direction
    if direction in {"top", "bottom"}:
        assert tail.width() >= tail.height()
    else:
        assert tail.height() >= tail.width()
    tail.deleteLater()


def _expected_tail_direction(assistant_rect: QRect, bubble_rect: QRect) -> str:
    if bubble_rect.right() < assistant_rect.left():
        return "right"
    if bubble_rect.left() > assistant_rect.right():
        return "left"
    if bubble_rect.bottom() < assistant_rect.top():
        return "bottom"
    if bubble_rect.top() > assistant_rect.bottom():
        return "top"
    pytest.fail("bubble and assistant overlap, so a tail direction is undefined")


def test_tail_uses_bubble_edge_and_aligns_with_relative_mouth_anchor(
    qapp, layout_controller
):
    window, controller = layout_controller
    _show_text(controller, "برای ادامه، روی این گزینه بزن.")
    assistant_rect = QRect(controller.overlay._assistant_rect)
    bubble_rect = QRect(controller.bubble.geometry())
    tail_rect = QRect(controller.tail.geometry())
    direction = controller.tail._direction
    expected = _expected_tail_direction(assistant_rect, bubble_rect)
    mouth = QPoint(
        assistant_rect.left() + round(assistant_rect.width() * 0.55),
        assistant_rect.top() + round(assistant_rect.height() * 0.34),
    )

    assert direction == expected
    assert _safe_area(window.centralWidget()).contains(tail_rect)
    assert not tail_rect.intersects(assistant_rect)
    if direction == "right":
        assert abs(tail_rect.left() - bubble_rect.right()) <= 3
        assert abs(tail_rect.center().y() - mouth.y()) <= 14
    elif direction == "left":
        assert abs(tail_rect.right() - bubble_rect.left()) <= 3
        assert abs(tail_rect.center().y() - mouth.y()) <= 14
    elif direction == "bottom":
        assert abs(tail_rect.top() - bubble_rect.bottom()) <= 3
        assert abs(tail_rect.center().x() - mouth.x()) <= 14
    else:
        assert abs(tail_rect.bottom() - bubble_rect.top()) <= 3
        assert abs(tail_rect.center().x() - mouth.x()) <= 14


def test_active_dialog_is_viewport_and_uses_dialog_local_coordinates(
    qapp, layout_controller
):
    window, controller = layout_controller
    dialog = QDialog(window)
    dialog.resize(720, 480)
    dialog.setWindowModality(Qt.ApplicationModal)
    dialog_layout = QVBoxLayout(dialog)
    dialog_layout.addStretch()
    dialog_target = QPushButton("تنظیم مهم")
    dialog_target.setObjectName("dialogTarget")
    dialog_layout.addWidget(dialog_target)
    dialog.show()
    dialog.activateWindow()
    dialog_target.setFocus()
    _process_events(qapp, 40)

    assert QApplication.activeModalWidget() is dialog
    controller.show_decision(
        AssistantDecision(
            AssistantState.GUIDING_RIGHT,
            "این تنظیم رو بررسی کن.",
            50,
            target=dialog_target,
        )
    )
    _process_events(qapp, 20)

    assert controller._host is dialog
    mapped = controller.positioner.map_rect(dialog_target, dialog)
    expected_top_left = dialog_target.mapTo(dialog, QPoint(0, 0))
    assert mapped == QRect(expected_top_left, dialog_target.size())
    assert _safe_area(dialog).contains(controller.overlay._assistant_rect)
    assert _safe_area(dialog).contains(controller.bubble.geometry())
    assert not controller.bubble.geometry().intersects(mapped.adjusted(-12, -12, 12, 12))

    dialog.close()
    _process_events(qapp, 40)
    controller._ensure_widgets()
    assert controller._host is window.centralWidget()
    dialog.deleteLater()


def test_dialog_header_footer_and_other_controls_are_exclusion_zones(
    qapp, layout_controller
):
    window, controller = layout_controller
    dialog = QDialog(window)
    dialog.resize(760, 620)
    dialog.setWindowModality(Qt.ApplicationModal)
    layout = QVBoxLayout(dialog)
    header = QFrame()
    header.setObjectName("modalHeader")
    header.setFixedHeight(72)
    layout.addWidget(header)
    other_control = QPushButton("Other important control")
    layout.addWidget(other_control)
    layout.addStretch()
    target = QPushButton("Guided target")
    layout.addWidget(target)
    footer = QFrame()
    footer.setObjectName("modalFooter")
    footer.setFixedHeight(72)
    layout.addWidget(footer)
    dialog.show()
    dialog.activateWindow()
    target.setFocus()
    _process_events(qapp, 40)

    controller.show_decision(
        AssistantDecision(
            AssistantState.GUIDING_RIGHT,
            "این کنترل را بررسی کن.",
            50,
            target=target,
        )
    )
    _process_events(qapp, 30)
    placement = controller.current_placement
    protected = [
        controller.positioner.map_rect(header, dialog),
        controller.positioner.map_rect(footer, dialog),
        controller.positioner.map_rect(other_control, dialog),
    ]
    for zone in protected:
        assert not placement.assistant_rect.intersects(zone.adjusted(-12, -12, 12, 12))
        assert not placement.bubble_rect.intersects(zone.adjusted(-12, -12, 12, 12))

    dialog.close()
    dialog.deleteLater()


def test_target_and_registered_exclusions_are_never_covered(qapp):
    host = QWidget()
    host.resize(1280, 800)
    target = QPushButton("Guided action", host)
    target.setGeometry(790, 325, 180, 56)
    exclusions = [
        QRect(0, 0, 1280, 110),
        QRect(0, 110, 270, 690),
        QRect(300, 650, 950, 120),
        QRect(330, 170, 310, 180),
    ]

    result = _calculate(
        AssistantPositionManager(),
        host,
        target,
        bubble_size=QSize(350, 180),
        exclusion_rects=exclusions,
    )
    assistant_rect, bubble_rect, target_rect, _mirrored = _placement_values(result)
    protected_target = target_rect.adjusted(-CONTROL_GAP, -CONTROL_GAP, CONTROL_GAP, CONTROL_GAP)

    assert not assistant_rect.intersects(protected_target)
    assert not bubble_rect.intersects(protected_target)
    for exclusion in exclusions:
        protected = exclusion.adjusted(-CONTROL_GAP, -CONTROL_GAP, CONTROL_GAP, CONTROL_GAP)
        assert not assistant_rect.intersects(protected)
        assert not bubble_rect.intersects(protected)
    host.deleteLater()


def test_close_choice_dialog_content_is_not_covered(qapp, layout_controller, request):
    from uac_desktop.ui import CloseChoiceDialog

    window, controller = layout_controller
    dialog = CloseChoiceDialog(window, language="en", tray_available=True)

    def cleanup():
        dialog.close()
        _process_events(qapp, 40)
        controller._ensure_widgets()
        dialog.deleteLater()
        _process_events(qapp, 20)

    request.addfinalizer(cleanup)
    dialog.setWindowModality(Qt.ApplicationModal)
    dialog.show()
    dialog.activateWindow()
    tray_button = dialog.findChild(QPushButton, "trayChoiceButton")
    assert tray_button is not None
    tray_button.setFocus()
    _process_events(qapp, 40)

    controller.show_decision(
        AssistantDecision(
            AssistantState.GUIDING_RIGHT,
            "Choose whether the app should stay in the tray or exit.",
            55,
            target=tray_button,
        )
    )
    _process_events(qapp, 30)
    assert controller.overlay._highlight_rect.isValid()
    assert not controller.overlay._highlight_rect.isEmpty()

    protected_widgets = [
        widget
        for widget in dialog.findChildren(QWidget)
        if widget.isVisible()
        and not widget.objectName().startswith("assistant")
        and widget.objectName()
        in {
            "closeChoiceIcon",
            "closeChoiceTitle",
            "closeChoiceText",
            "closeChoiceDetail",
            "quietButton",
            "dangerButton",
            "trayChoiceButton",
        }
    ]
    assert protected_widgets
    protected_rects = [
        QRect(widget.mapToGlobal(QPoint(0, 0)), widget.size())
        for widget in protected_widgets
    ]
    visible_assistant_parts = []
    assistant_host = controller._host
    if controller.overlay.isVisible() and controller.overlay._assistant_rect.isValid():
        assistant_rect = QRect(controller.overlay._assistant_rect)
        visible_assistant_parts.append(
            QRect(assistant_host.mapToGlobal(assistant_rect.topLeft()), assistant_rect.size())
        )
    if controller.bubble.isVisible():
        bubble_rect = QRect(controller.bubble.geometry())
        visible_assistant_parts.append(
            QRect(assistant_host.mapToGlobal(bubble_rect.topLeft()), bubble_rect.size())
        )
    for assistant_part in visible_assistant_parts:
        for protected in protected_rects:
            assert not assistant_part.intersects(protected.adjusted(-4, -4, 4, 4))



def test_visual_overlay_is_click_through_but_bubble_remains_interactive(
    qapp, layout_controller
):
    _window, controller = layout_controller
    _show_text(controller, "برای ادامه، روی این گزینه بزن.")
    assert controller.overlay.testAttribute(Qt.WA_TransparentForMouseEvents)
    assert not controller.bubble.testAttribute(Qt.WA_TransparentForMouseEvents)
    assert controller.tail.testAttribute(Qt.WA_TransparentForMouseEvents)


def test_resize_recomputes_and_contains_layout(qapp, layout_controller):
    window, controller = layout_controller
    controller.enable()
    controller._evaluate_timer.stop()
    controller._event_timer.stop()
    _show_text(controller, "اندازه‌ی پنجره تغییر می‌کنه و جای من هم اصلاح می‌شه.")
    before = (QRect(controller.overlay._assistant_rect), QRect(controller.bubble.geometry()))

    window.resize(620, 420)
    controller.eventFilter(window, QEvent(QEvent.Type.Resize))
    _process_events(qapp, 90)
    after = (QRect(controller.overlay._assistant_rect), QRect(controller.bubble.geometry()))

    assert after != before
    safe = _safe_area(window.centralWidget())
    assert safe.contains(after[0])
    assert safe.contains(after[1])
    assert not after[0].intersects(after[1])


def test_resize_and_scroll_reposition_requests_are_debounced_once(
    qapp, layout_controller
):
    _window, controller = layout_controller
    calls = []
    controller._reposition_timer.timeout.disconnect()
    controller._reposition_timer.timeout.connect(lambda: calls.append(time.monotonic()))

    for _ in range(12):
        controller.schedule_reposition()
        controller.eventFilter(controller.window, QEvent(QEvent.Type.Wheel))
        controller.eventFilter(controller.window, QEvent(QEvent.Type.Resize))

    assert controller._reposition_timer.isActive()
    _process_events(qapp, 60)
    assert len(calls) == 1


def test_scrolled_target_is_mapped_in_host_coordinates_after_ensure_visible(qapp):
    host = QWidget()
    host.resize(720, 500)
    scroll = QScrollArea(host)
    scroll.setGeometry(20, 20, 680, 450)
    content = QWidget()
    content.resize(640, 1500)
    target = QPushButton("هدف پایین صفحه", content)
    target.setGeometry(220, 1300, 180, 44)
    scroll.setWidget(content)
    host.show()
    _process_events(qapp, 20)
    positioner = AssistantPositionManager()
    before = positioner.map_rect(target, host)

    positioner.ensure_visible(target)
    _process_events(qapp, 20)
    after = positioner.map_rect(target, host)

    assert scroll.verticalScrollBar().value() > 0
    assert after.top() < before.top()
    assert scroll.geometry().adjusted(0, 0, 0, 8).contains(after.center())
    result = _calculate(positioner, host, target, bubble_size=QSize(300, 160))
    assistant_rect, bubble_rect, target_rect, _mirrored = _placement_values(result)
    assert _safe_area(host).contains(assistant_rect)
    assert _safe_area(host).contains(bubble_rect)
    assert not bubble_rect.intersects(target_rect.adjusted(-12, -12, 12, 12))
    host.close()
    host.deleteLater()


def test_dense_widget_tree_navigation_and_reposition_burst_stays_bounded(
    qapp, layout_controller, monkeypatch
):
    window, controller = layout_controller
    dense_table = QWidget(window.page)
    dense_table.setObjectName("denseTableFixture")
    dense_table.setGeometry(0, 0, 1080, 1500)
    for index in range(2048):
        cell = QPushButton(dense_table) if index % 64 == 0 else QWidget(dense_table)
        cell.setObjectName(f"denseCell_{index}")
        row, column = divmod(index, 32)
        cell.setGeometry(column * 34, row * 22, 32, 20)
    dense_table.show()
    second_page = QWidget()
    window.stack.addWidget(second_page)
    _process_events(qapp, 30)
    assert len(dense_table.findChildren(QWidget)) >= 2048

    _show_text(controller, "برای ادامه، کنترل موردنظر رو انتخاب کن.")
    controller._evaluate_timer.stop()
    controller._event_timer.stop()
    original_reposition = controller.reposition
    reposition_calls = []

    def counted_reposition():
        reposition_calls.append(time.perf_counter())
        original_reposition()

    controller._reposition_timer.timeout.disconnect()
    monkeypatch.setattr(controller, "reposition", counted_reposition)
    controller._reposition_timer.timeout.connect(counted_reposition)

    started = time.perf_counter()
    for _ in range(160):
        controller.schedule_reposition()
    for index in range(18):
        page_index = index % 2
        window.stack.setCurrentIndex(page_index)
        controller.on_navigation(page_index)
        controller.schedule_reposition()
    _process_events(qapp, 450)
    elapsed = time.perf_counter() - started

    assert len(reposition_calls) <= 4
    assert elapsed < 8.0


def test_long_message_is_fully_scrollable_without_text_clipping(qapp):
    bubble = AssistantMessageBubble(reduced_motion=True)
    bubble.setStyleSheet(
        "QFrame#assistantBubble { border: 2px solid cyan; }"
        "QLabel#assistantBubbleText { font-size: 14px; padding: 2px; }"
    )
    long_message = (
        "این پیام طولانی باید تا آخرین جمله کامل نمایش داده شود و هیچ بخشی از متن "
        "در پایین حباب بریده نشود. برای دیدن ادامه‌ی راهنما، متن را اسکرول کن. "
    ) * 18
    bubble.set_message(long_message, False, False, False, True)
    bubble.resize(bubble.measure_for(QSize(900, 460)))
    bubble.show()
    _process_events(qapp, 30)

    viewport = bubble.text_scroll.viewport()
    scrollbar = bubble.text_scroll.verticalScrollBar()
    assert bubble.text.width() <= viewport.width()
    assert bubble.text.height() >= bubble.text.heightForWidth(bubble.text.width())
    assert scrollbar.maximum() > 0, (
        bubble.size(), bubble.text.size(), viewport.size(),
        bubble.text_scroll.size(), bubble.text_scroll.verticalScrollBarPolicy(),
    )
    assert scrollbar.maximum() + viewport.height() >= bubble.text.height()
    scrollbar.setValue(scrollbar.maximum())
    assert scrollbar.value() == scrollbar.maximum()

    bubble.close()
    bubble.deleteLater()
