from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable

from PySide6.QtCore import (
    Property, QEvent, QEasingCurve, QPoint, QPointF, QRect, QPropertyAnimation,
    QSize, Qt, QTimer,
)
from PySide6.QtGui import (
    QColor, QAccessible, QAccessibleAnnouncementEvent, QBitmap, QImage,
    QFont, QFontMetrics, QPainter, QPainterPath, QPen, QPixmap, QRegion, QTransform,
)
from PySide6.QtWidgets import (
    QApplication, QAbstractItemView, QAbstractScrollArea, QDialog, QFrame,
    QGraphicsOpacityEffect, QHBoxLayout, QLabel, QPushButton, QScrollArea,
    QStyle, QVBoxLayout, QWidget,
)
from shiboken6 import isValid as is_qt_valid

from .assistant_messages import message, mixed
from .paths import ROOT


class AssistantState(str, Enum):
    NORMAL = "normal"
    THINKING = "thinking"
    WAITING = "waiting"
    HAPPY = "happy"
    SAD = "sad"
    GUIDING_RIGHT = "guiding_right"
    CONFUSED = "confused"
    SURPRISED = "surprised"


@dataclass(slots=True)
class AssistantContext:
    captured_at: float
    page_index: int = 0
    page_name: str = "home"
    route: str = "home"
    active_dialog: QWidget | None = None
    focus_widget: QWidget | None = None
    focused_name: str = ""
    selected_widget: QWidget | None = None
    selected_value: str = ""
    invalid_widgets: list[QWidget] = field(default_factory=list)
    validation_errors: list[str] = field(default_factory=list)
    operation_running: bool = False
    operation_kind: str = ""
    progress_value: int | None = None
    progress_maximum: int | None = None
    active_error: str = ""
    error_at: float = 0.0
    active_warning: str = ""
    warning_at: float = 0.0
    fresh_success: str = ""
    success_at: float = 0.0
    disabled_widgets: list[QWidget] = field(default_factory=list)
    missing_prerequisites: list[str] = field(default_factory=list)
    scroll_value: int = 0
    scroll_maximum: int = 0
    visible_target_names: set[str] = field(default_factory=set)
    hidden_target_names: set[str] = field(default_factory=set)
    connected: bool = False
    tun_running: bool = False
    gateway_state: str = "inactive"
    resources_ready: bool = True
    last_action: str = ""
    last_action_at: float = 0.0
    activity_state: str = "idle"
    activity_message: str = ""
    activity_at: float = 0.0
    action_hint: str = ""
    action_target: QWidget | None = None


@dataclass(slots=True)
class GuideDefinition:
    id: str
    page: int
    route: str
    target: str
    trigger: str
    message_key: str
    assistant_state: AssistantState = AssistantState.GUIDING_RIGHT
    preferred_position: str = "auto"
    priority: int = 10
    condition: str = "always"
    show_once: bool = True
    cooldown: float = 0.0
    next_step: str = ""
    previous_step: str = ""
    auto_scroll: bool = True
    dismissible: bool = True
    timeout: int = 0


@dataclass(slots=True)
class AssistantDecision:
    state: AssistantState
    text: str
    priority: int
    target: QWidget | None = None
    guide_id: str = ""
    preferred_position: str = "auto"
    dismissible: bool = True
    timeout: int = 0
    page_index: int = -1


@dataclass(slots=True)
class AssistantPlacement:
    assistant_rect: QRect
    bubble_rect: QRect
    target_rect: QRect
    highlight_rect: QRect
    tail_rect: QRect
    tail_direction: str
    face_anchor: QPoint
    mirrored: bool
    docked: bool = False

    def legacy(self) -> tuple[QRect, QRect, QRect, bool]:
        return self.assistant_rect, self.bubble_rect, self.target_rect, self.mirrored


class AssistantSettings:
    def __init__(self, storage):
        self.storage = storage

    @property
    def enabled(self) -> bool:
        return bool(self.storage.settings.get("assistant_enabled", False))

    @property
    def guides_enabled(self) -> bool:
        return bool(self.storage.settings.get("assistant_guides_enabled", True))

    @property
    def warnings_enabled(self) -> bool:
        return bool(self.storage.settings.get("assistant_warnings_enabled", True))

    def set_enabled(self, enabled: bool) -> None:
        self.storage.settings["assistant_enabled"] = bool(enabled)
        self.storage.save_settings()

    def seen(self) -> set[str]:
        values = self.storage.settings.get("assistant_seen_guides", [])
        return {str(value) for value in values if str(value)} if isinstance(values, list) else set()

    def mark_seen(self, guide_id: str) -> None:
        values = self.seen()
        values.add(str(guide_id))
        self.storage.settings["assistant_seen_guides"] = sorted(values)
        self.storage.save_settings()

    def reset_guides(self) -> None:
        self.storage.settings["assistant_seen_guides"] = []
        self.storage.settings["assistant_guides_enabled"] = True
        self.storage.save_settings()


class AssistantAssetManager:
    FILES = {
        AssistantState.NORMAL: "wizard_01_normal.png",
        AssistantState.THINKING: "wizard_02_thinking.png",
        AssistantState.WAITING: "wizard_03_waiting.png",
        AssistantState.HAPPY: "wizard_04_happy.png",
        AssistantState.SAD: "wizard_05_sad.png",
        AssistantState.GUIDING_RIGHT: "wizard_06_guiding_right.png",
        AssistantState.CONFUSED: "wizard_07_confused.png",
        AssistantState.SURPRISED: "wizard_08_surprised.png",
    }
    FACE_ANCHORS = {
        AssistantState.NORMAL: QPointF(0.55, 0.32),
        AssistantState.THINKING: QPointF(0.55, 0.32),
        AssistantState.WAITING: QPointF(0.55, 0.32),
        AssistantState.HAPPY: QPointF(0.55, 0.32),
        AssistantState.SAD: QPointF(0.55, 0.32),
        AssistantState.GUIDING_RIGHT: QPointF(0.55, 0.34),
        AssistantState.CONFUSED: QPointF(0.55, 0.32),
        AssistantState.SURPRISED: QPointF(0.55, 0.32),
    }

    def __init__(self, root: Path | None = None, log: Callable[[str], None] | None = None):
        self.root = Path(root or (ROOT / "wizard guider"))
        self.log = log or (lambda _text: None)
        self._cache: dict[tuple[AssistantState, bool], QPixmap] = {}
        self._warned: set[str] = set()

    def _warn(self, text: str) -> None:
        if text not in self._warned:
            self._warned.add(text)
            self.log(text)

    def _load_cropped(self, state: AssistantState) -> QPixmap:
        path = self.root / self.FILES[state]
        image = QImage(str(path))
        if image.isNull() and state != AssistantState.NORMAL:
            self._warn(f"Assistant image missing: {path}")
            return self._load_cropped(AssistantState.NORMAL)
        if image.isNull():
            self._warn(f"Assistant normal image missing: {path}")
            return QPixmap()
        if image.hasAlphaChannel():
            mask = QBitmap.fromImage(image.createAlphaMask())
            bounds = QRegion(mask).boundingRect()
            if bounds.isValid() and not bounds.isEmpty():
                image = image.copy(bounds)
        return QPixmap.fromImage(image)

    def pixmap(self, state: AssistantState | str, mirrored: bool = False) -> QPixmap:
        try:
            normalized = state if isinstance(state, AssistantState) else AssistantState(str(state))
        except ValueError:
            normalized = AssistantState.NORMAL
        key = (normalized, bool(mirrored))
        if key not in self._cache:
            pixmap = self._load_cropped(normalized)
            if mirrored and not pixmap.isNull():
                pixmap = pixmap.transformed(QTransform().scale(-1, 1), Qt.SmoothTransformation)
            self._cache[key] = pixmap
        return QPixmap(self._cache[key])

    def available_states(self) -> set[AssistantState]:
        return {
            state for state, filename in self.FILES.items()
            if (self.root / filename).is_file()
        }

    def face_anchor(self, state: AssistantState | str, mirrored: bool = False) -> QPointF:
        try:
            normalized = state if isinstance(state, AssistantState) else AssistantState(str(state))
        except ValueError:
            normalized = AssistantState.NORMAL
        anchor = self.FACE_ANCHORS.get(normalized, QPointF(0.55, 0.34))
        return QPointF(1.0 - anchor.x(), anchor.y()) if mirrored else QPointF(anchor)


class AssistantGuideRegistry:
    def __init__(self):
        self._guides = [
            GuideDefinition("home_connect", 0, "home", "connect_button", "first_visit", "home_connect", condition="disconnected", priority=30, next_step="home_country"),
            GuideDefinition("home_country", 0, "home", "country_combo", "tour", "home_country", priority=20, previous_step="home_connect", next_step="configs_tabs"),
            GuideDefinition("configs_tabs", 1, "configs", "profile_tabs", "first_visit", "configs_tabs", priority=20, next_step="configs_add"),
            GuideDefinition("configs_add", 1, "configs", "add_btn", "tour", "configs_add", priority=15, previous_step="configs_tabs", next_step="configs_ping"),
            GuideDefinition("configs_ping", 1, "configs", "profile_ping_all_btn", "tour", "configs_ping", priority=14, previous_step="configs_add", next_step="maker_source"),
            GuideDefinition("maker_source", 2, "sni_maker", "maker_repo_btn", "first_visit", "maker_load", condition="maker_url_ready", priority=25, next_step="maker_convert"),
            GuideDefinition("maker_convert", 2, "sni_maker", "maker_text_btn", "tour", "maker_convert", priority=20, previous_step="maker_source", next_step="maker_test"),
            GuideDefinition("maker_test", 2, "sni_maker", "maker_start_btn", "next_action", "maker_test", condition="maker_ready", priority=30, previous_step="maker_convert", next_step="maker_results"),
            GuideDefinition("maker_results", 2, "sni_maker", "maker_table", "tour", "maker_results", priority=15, previous_step="maker_test", next_step="lab_domains"),
            GuideDefinition("lab_domains", 3, "sni_lab", "domains", "first_visit", "lab_domains", priority=20, next_step="logs"),
            GuideDefinition("logs", 4, "live_logs", "logs", "first_visit", "logs", priority=10, next_step="bypass"),
            GuideDefinition("bypass", 5, "app_bypass", "process_table", "first_visit", "bypass", priority=10, next_step="tools"),
            GuideDefinition("tools", 6, "tools", "tool_cards", "first_visit", "tools", priority=10, next_step="support"),
            GuideDefinition("support", 7, "support", "assistant_replay_button", "first_visit", "support", priority=10),
        ]
        self._by_id = {guide.id: guide for guide in self._guides}

    def all(self) -> list[GuideDefinition]:
        return list(self._guides)

    def get(self, guide_id: str) -> GuideDefinition | None:
        return self._by_id.get(str(guide_id))

    def for_page(self, page: int) -> list[GuideDefinition]:
        return sorted(
            (guide for guide in self._guides if guide.page == page),
            key=lambda guide: -guide.priority,
        )

    @staticmethod
    def condition_matches(guide: GuideDefinition, context: AssistantContext, window) -> bool:
        if guide.condition == "disconnected":
            return not context.connected and not context.operation_running
        if guide.condition == "maker_url_ready":
            url = str(getattr(getattr(window, "maker_repo_url", None), "text", lambda: "")() or "").strip()
            button = getattr(window, "maker_repo_btn", None)
            return bool(url) and not bool(getattr(window, "_maker_profiles", {})) and bool(button and button.isEnabled())
        if guide.condition == "maker_ready":
            return bool(getattr(window, "_maker_profiles", {})) and not context.operation_running
        return True


class AssistantMessageQueue:
    def __init__(self):
        self._items: list[AssistantDecision] = []

    def push(self, item: AssistantDecision) -> None:
        self._items = [existing for existing in self._items if existing.priority > item.priority]
        self._items.append(item)
        self._items.sort(key=lambda value: -value.priority)

    def pop(self, page_index: int) -> AssistantDecision | None:
        while self._items:
            item = self._items.pop(0)
            if item.page_index in {-1, page_index}:
                return item
        return None

    def clear(self) -> None:
        self._items.clear()

    def discard_other_pages(self, page_index: int) -> None:
        self._items = [item for item in self._items if item.page_index in {-1, page_index}]


class AssistantContextCollector:
    PAGE_NAMES = ("home", "configs", "sni_maker", "sni_lab", "live_logs", "app_bypass", "tools", "support")

    def __init__(self, window):
        self.window = window
        self._connection_error_value = ""
        self._connection_error_at = 0.0

    def _dialog(self) -> QWidget | None:
        modal = QApplication.activeModalWidget()
        if isinstance(modal, QWidget):
            return modal
        active = QApplication.activeWindow()
        return active if isinstance(active, QDialog) and active is not self.window else None

    @staticmethod
    def _visible(widget: QWidget | None, root: QWidget | None = None) -> bool:
        if widget is None or not widget.isVisible():
            return False
        try:
            return widget.isVisibleTo(root or widget.window())
        except RuntimeError:
            return False

    def _active_root(self) -> QWidget:
        dialog = self._dialog()
        return dialog if dialog is not None else self.window.stack.currentWidget()

    def _validation(self, root: QWidget) -> tuple[list[QWidget], list[str]]:
        invalid = []
        errors = []
        for widget in [root, *root.findChildren(QWidget)]:
            is_invalid = bool(widget.property("invalid"))
            is_validation = widget.objectName() == "validationError"
            if not self._visible(widget, root) or not (is_invalid or is_validation):
                continue
            if is_validation and isinstance(widget, QLabel) and not widget.text().strip():
                continue
            invalid.append(widget)
            if isinstance(widget, QLabel) and widget.text().strip():
                errors.append(widget.text().strip())
        return invalid, errors

    def _operation(self) -> tuple[bool, str, int | None, int | None]:
        window = self.window
        if bool(getattr(window, "connecting", False)):
            return True, "connecting", None, None
        if bool(getattr(window, "_maker_import_in_progress", False)):
            return True, "maker_import", None, None
        if bool(getattr(window, "_maker_running", False)):
            panel = getattr(window, "maker_progress", None)
            return True, "maker_test", panel.bar.value() if panel else None, panel._maximum if panel else None
        if bool(getattr(window, "scanning", False)):
            panel = getattr(window, "scan_progress", None)
            return True, "scan", panel.bar.value() if panel else None, panel._maximum if panel else None
        if bool(getattr(window, "_gateway_apply_target", None)):
            return True, "gateway", None, None
        if bool(getattr(window, "_update_in_progress", False)):
            return True, "update", None, None
        if bool(getattr(window, "_profile_ping_busy", False)):
            return True, "profile_ping", None, None
        return False, "", None, None

    @staticmethod
    def _selected_widget(root: QWidget) -> tuple[QWidget | None, str]:
        for view in root.findChildren(QAbstractItemView):
            if not view.isVisible():
                continue
            indexes = view.selectionModel().selectedIndexes() if view.selectionModel() else []
            if indexes:
                value = str(indexes[0].data() or "")
                return view, value
        return None, ""

    def collect(self, last_action: str = "", last_action_at: float = 0.0) -> AssistantContext:
        window = self.window
        now = time.time()
        page_index = max(0, window.stack.currentIndex())
        page_name = self.PAGE_NAMES[page_index] if page_index < len(self.PAGE_NAMES) else f"page_{page_index}"
        root = self._active_root()
        invalid, validation_errors = self._validation(root)
        running, operation, progress_value, progress_maximum = self._operation()
        activity = window.activity_bar
        activity_at = float(getattr(activity, "updated_at", 0.0) or 0.0)
        activity_state = str(getattr(activity, "state", "idle") or "idle")
        activity_message = str(activity.message.text() or "")
        stored_error = str(getattr(window, "connection_error", "") or "")
        if stored_error != self._connection_error_value:
            self._connection_error_value = stored_error
            self._connection_error_at = now if stored_error else 0.0
        error = stored_error if (
            stored_error
            and not bool(window.engine.running)
            and now - self._connection_error_at <= 60
        ) else ""
        error_at = self._connection_error_at if error else 0.0
        warning = ""
        warning_at = 0.0
        success = ""
        success_at = 0.0
        toast = window.centralWidget().findChild(QFrame, "toast")
        if toast is not None and toast.isVisible():
            toast_text = toast.findChild(QLabel, "toastText")
            value = str(toast_text.text() if toast_text is not None else "")
            created_at = float(toast.property("assistantCreatedAt") or now)
            kind = str(toast.property("kind") or "")
            if kind == "danger":
                error, error_at = value, created_at
            elif kind == "warning":
                warning, warning_at = value, created_at
            elif kind == "success":
                success, success_at = value, created_at
        if not error and activity_state == "error" and now - activity_at <= 20:
            error, error_at = activity_message, activity_at
        if not warning and activity_state == "warning" and now - activity_at <= 15:
            warning, warning_at = activity_message, activity_at
        if not success and activity_state == "success" and now - activity_at <= 9:
            success, success_at = activity_message, activity_at
        focus = QApplication.focusWidget()
        selected_widget, selected_value = self._selected_widget(root)
        scroll = root if isinstance(root, QScrollArea) else root.findChild(QScrollArea)
        scroll_value = scroll.verticalScrollBar().value() if scroll else 0
        scroll_maximum = scroll.verticalScrollBar().maximum() if scroll else 0
        visible_names = set()
        hidden_names = set()
        disabled = []
        for widget in [root, *root.findChildren(QWidget)]:
            name = widget.objectName()
            if name:
                (visible_names if self._visible(widget, root) else hidden_names).add(name)
            if self._visible(widget, root) and not widget.isEnabled():
                disabled.append(widget)
        missing = []
        action_hint = ""
        action_target = None
        if page_index == 2 and not running:
            profiles = bool(getattr(window, "_maker_profiles", {}))
            editor = getattr(window, "maker_source_editor", None)
            repository = getattr(window, "maker_repo_url", None)
            load_button = getattr(window, "maker_repo_btn", None)
            convert_button = getattr(window, "maker_text_btn", None)
            test_button = getattr(window, "maker_start_btn", None)
            editor_text = editor.toPlainText().strip() if editor is not None else ""
            repository_url = repository.text().strip() if repository is not None else ""
            editor_focused = bool(
                isinstance(focus, QWidget)
                and isinstance(editor, QWidget)
                and (focus is editor or editor.isAncestorOf(focus))
            )
            if editor_focused and not editor_text:
                action_hint, action_target = "maker_manual_input", editor
            elif editor_text and convert_button is not None and convert_button.isEnabled():
                action_hint, action_target = "maker_convert", convert_button
            elif not profiles and repository_url and load_button is not None and load_button.isEnabled():
                action_hint, action_target = "maker_load", load_button
            elif profiles and test_button is not None and test_button.isEnabled():
                action_hint, action_target = "maker_test", test_button
            elif not profiles and not repository_url and not editor_text:
                action_hint, action_target = "maker_source", repository
        return AssistantContext(
            captured_at=now,
            page_index=page_index,
            page_name=page_name,
            route=page_name,
            active_dialog=self._dialog(),
            focus_widget=focus,
            focused_name=focus.objectName() if isinstance(focus, QWidget) else "",
            selected_widget=selected_widget,
            selected_value=selected_value,
            invalid_widgets=invalid,
            validation_errors=validation_errors,
            operation_running=running,
            operation_kind=operation,
            progress_value=progress_value,
            progress_maximum=progress_maximum,
            active_error=error,
            error_at=error_at,
            active_warning=warning,
            warning_at=warning_at,
            fresh_success=success,
            success_at=success_at,
            disabled_widgets=disabled,
            missing_prerequisites=missing,
            scroll_value=scroll_value,
            scroll_maximum=scroll_maximum,
            visible_target_names=visible_names,
            hidden_target_names=hidden_names,
            connected=bool(window.engine.running),
            tun_running=bool(getattr(window.engine, "tun_running", False)),
            gateway_state=str(getattr(window, "_gateway_runtime_state", "inactive")),
            resources_ready=True,
            last_action=last_action,
            last_action_at=last_action_at,
            activity_state=activity_state,
            activity_message=activity_message,
            activity_at=activity_at,
            action_hint=action_hint,
            action_target=action_target,
        )


class AssistantStateResolver:
    OPERATION_MESSAGES = {
        "connecting": (AssistantState.THINKING, "loading_connection"),
        "maker_import": (AssistantState.THINKING, "thinking"),
        "maker_test": (AssistantState.WAITING, "loading_maker"),
        "scan": (AssistantState.THINKING, "loading_scan"),
        "gateway": (AssistantState.WAITING, "loading_gateway"),
        "update": (AssistantState.THINKING, "loading_update"),
        "profile_ping": (AssistantState.WAITING, "waiting"),
        "latency": (AssistantState.WAITING, "waiting"),
    }

    def resolve(self, context: AssistantContext) -> AssistantDecision | None:
        if context.active_error:
            return AssistantDecision(AssistantState.SAD, message("error_detail", detail=mixed(context.active_error)), 100, context.invalid_widgets[0] if context.invalid_widgets else None, timeout=0)
        if context.active_warning:
            return AssistantDecision(AssistantState.SURPRISED, message("warning_detail", detail=mixed(context.active_warning)), 90, timeout=0)
        if context.invalid_widgets or context.validation_errors:
            text = mixed(context.validation_errors[0]) if context.validation_errors else message("invalid_field")
            return AssistantDecision(AssistantState.CONFUSED, text, 80, context.invalid_widgets[0] if context.invalid_widgets else context.focus_widget, timeout=0)
        if context.missing_prerequisites:
            return AssistantDecision(AssistantState.CONFUSED, message("required_field"), 75, context.focus_widget, timeout=0)
        if context.action_hint:
            return AssistantDecision(
                AssistantState.GUIDING_RIGHT,
                message(context.action_hint),
                74,
                context.action_target,
                timeout=0,
            )
        if context.operation_running:
            state, key = self.OPERATION_MESSAGES.get(context.operation_kind, (AssistantState.WAITING, "loading_generic"))
            return AssistantDecision(state, message(key), 70, timeout=0)
        if context.fresh_success and context.captured_at - context.success_at <= 9:
            return AssistantDecision(AssistantState.HAPPY, message("success_detail", detail=mixed(context.fresh_success)), 60, timeout=4500)
        if context.active_dialog is not None:
            return AssistantDecision(AssistantState.GUIDING_RIGHT, message("dialog"), 55, context.focus_widget, timeout=0)
        return None


class AssistantCollisionResolver:
    @staticmethod
    def overlap_area(first: QRect, second: QRect) -> int:
        overlap = first.intersected(second)
        return max(0, overlap.width()) * max(0, overlap.height()) if overlap.isValid() else 0

    @staticmethod
    def intersects_any(rect: QRect, zones: list[QRect]) -> bool:
        return any(zone.isValid() and not zone.isEmpty() and rect.intersects(zone) for zone in zones)

    def accepts(
        self,
        area: QRect,
        assistant_rect: QRect,
        bubble_rect: QRect,
        target_rect: QRect,
        zones: list[QRect],
        assistant_gap: int,
        target_gap: int,
    ) -> bool:
        if not area.contains(assistant_rect) or not area.contains(bubble_rect):
            return False
        if assistant_rect.adjusted(-assistant_gap, -assistant_gap, assistant_gap, assistant_gap).intersects(bubble_rect):
            return False
        protected_target = target_rect.adjusted(-target_gap, -target_gap, target_gap, target_gap) if target_rect.isValid() else QRect()
        if protected_target.isValid() and (
            assistant_rect.intersects(protected_target) or bubble_rect.intersects(protected_target)
        ):
            return False
        return not self.intersects_any(assistant_rect, zones) and not self.intersects_any(bubble_rect, zones)

    def score(
        self,
        assistant_rect: QRect,
        bubble_rect: QRect,
        target_rect: QRect,
        label: str,
        rtl: bool,
        preferred: str,
        previous: AssistantPlacement | None,
    ) -> float:
        score = 10000.0
        if label.startswith("right"):
            score += 500 if rtl else 280
        elif label.startswith("left"):
            score += 280 if rtl else 500
        elif label in {"above", "below"}:
            score += 90
        if preferred in {"left", "right"}:
            assistant_side = "left" if target_rect.isValid() and assistant_rect.center().x() < target_rect.center().x() else "right"
            if assistant_side == preferred:
                score += 380
        if target_rect.isValid():
            score -= abs(assistant_rect.center().x() - target_rect.center().x()) * 0.06
            score -= abs(assistant_rect.center().y() - target_rect.center().y()) * 0.04
        score -= abs(assistant_rect.center().x() - bubble_rect.center().x()) * 0.025
        score -= abs(assistant_rect.center().y() - bubble_rect.center().y()) * 0.025
        if previous is not None:
            score -= abs(previous.assistant_rect.x() - assistant_rect.x()) * 0.03
            score -= abs(previous.assistant_rect.y() - assistant_rect.y()) * 0.03
            score -= abs(previous.bubble_rect.x() - bubble_rect.x()) * 0.02
            score -= abs(previous.bubble_rect.y() - bubble_rect.y()) * 0.02
        return score


class AssistantPlacementEngine:
    EDGE_PADDING = 16
    TARGET_GAP = 12
    ASSISTANT_GAP = 18
    BUBBLE_GAP = 22
    MIN_ASSISTANT_HEIGHT = 96
    MAX_ASSISTANT_HEIGHT = 250
    MIN_BUBBLE_WIDTH = 220

    def __init__(self):
        self.collision = AssistantCollisionResolver()

    @staticmethod
    def map_rect(widget: QWidget, host: QWidget) -> QRect:
        try:
            top_left = host.mapFromGlobal(widget.mapToGlobal(QPoint(0, 0)))
            return QRect(top_left, widget.size())
        except RuntimeError:
            return QRect()

    @staticmethod
    def ensure_visible(target: QWidget | None) -> None:
        current = target
        while current is not None:
            try:
                if isinstance(current, QScrollArea):
                    if target is not None:
                        current.ensureWidgetVisible(target, 24, 24)
                    return
                current = current.parentWidget()
            except RuntimeError:
                return

    @staticmethod
    def _clamp(rect: QRect, area: QRect) -> QRect:
        width = min(max(1, rect.width()), max(1, area.width()))
        height = min(max(1, rect.height()), max(1, area.height()))
        left = max(area.left(), min(rect.left(), area.right() - width + 1))
        top = max(area.top(), min(rect.top(), area.bottom() - height + 1))
        return QRect(left, top, width, height)

    @staticmethod
    def _deduplicate(rects: list[QRect]) -> list[QRect]:
        result = []
        keys = set()
        for rect in rects:
            key = (rect.x(), rect.y(), rect.width(), rect.height())
            if key not in keys:
                keys.add(key)
                result.append(rect)
        return result

    def _assistant_candidates(
        self,
        area: QRect,
        target_rect: QRect,
        width: int,
        height: int,
        preferred: str,
    ) -> list[QRect]:
        candidates = []
        gap = self.BUBBLE_GAP
        if target_rect.isValid() and not target_rect.isEmpty():
            left = QRect(target_rect.left() - width - gap, target_rect.center().y() - height // 2, width, height)
            right = QRect(target_rect.right() + gap, target_rect.center().y() - height // 2, width, height)
            above = QRect(target_rect.center().x() - width // 2, target_rect.top() - height - gap, width, height)
            below = QRect(target_rect.center().x() - width // 2, target_rect.bottom() + gap, width, height)
            if preferred == "left":
                candidates.extend((left, right, above, below))
            elif preferred == "right":
                candidates.extend((right, left, above, below))
            else:
                left_space = target_rect.left() - area.left()
                right_space = area.right() - target_rect.right()
                candidates.extend((left, right) if left_space >= right_space else (right, left))
                candidates.extend((above, below))
        candidates.extend((
            QRect(area.left(), area.bottom() - height + 1, width, height),
            QRect(area.right() - width + 1, area.bottom() - height + 1, width, height),
            QRect(area.left(), area.top(), width, height),
            QRect(area.right() - width + 1, area.top(), width, height),
        ))
        horizontal = (area.left(), area.center().x() - width // 2, area.right() - width + 1)
        vertical = (area.top(), area.center().y() - height // 2, area.bottom() - height + 1)
        candidates.extend(QRect(x, y, width, height) for y in vertical for x in horizontal)
        return self._deduplicate([self._clamp(rect, area) for rect in candidates])

    def _bubble_candidates(self, assistant_rect: QRect, width: int, height: int) -> list[tuple[str, QRect]]:
        gap = self.BUBBLE_GAP
        return [
            ("right_top", QRect(assistant_rect.right() + gap, assistant_rect.top(), width, height)),
            ("right_middle", QRect(assistant_rect.right() + gap, assistant_rect.center().y() - height // 2, width, height)),
            ("right_bottom", QRect(assistant_rect.right() + gap, assistant_rect.bottom() - height + 1, width, height)),
            ("left_top", QRect(assistant_rect.left() - width - gap, assistant_rect.top(), width, height)),
            ("left_middle", QRect(assistant_rect.left() - width - gap, assistant_rect.center().y() - height // 2, width, height)),
            ("left_bottom", QRect(assistant_rect.left() - width - gap, assistant_rect.bottom() - height + 1, width, height)),
            ("above", QRect(assistant_rect.center().x() - width // 2, assistant_rect.top() - height - gap, width, height)),
            ("below", QRect(assistant_rect.center().x() - width // 2, assistant_rect.bottom() + gap, width, height)),
        ]

    @staticmethod
    def _tail_direction(assistant_rect: QRect, bubble_rect: QRect) -> str:
        if bubble_rect.left() > assistant_rect.right():
            return "left"
        if bubble_rect.right() < assistant_rect.left():
            return "right"
        if bubble_rect.top() > assistant_rect.bottom():
            return "top"
        return "bottom"

    @staticmethod
    def _face_point(assistant_rect: QRect, anchor: QPointF) -> QPoint:
        return QPoint(
            assistant_rect.left() + round(assistant_rect.width() * anchor.x()),
            assistant_rect.top() + round(assistant_rect.height() * anchor.y()),
        )

    def _tail_rect(self, assistant_rect: QRect, bubble_rect: QRect, direction: str, anchor: QPointF) -> tuple[QRect, QPoint]:
        face = self._face_point(assistant_rect, anchor)
        if direction in {"left", "right"}:
            width, height = 20, 28
            top = max(bubble_rect.top() + 12, min(face.y() - height // 2, bubble_rect.bottom() - height - 12))
            left = bubble_rect.left() - width if direction == "left" else bubble_rect.right() + 1
        else:
            width, height = 28, 20
            left = max(bubble_rect.left() + 18, min(face.x() - width // 2, bubble_rect.right() - width - 18))
            top = bubble_rect.top() - height if direction == "top" else bubble_rect.bottom() + 1
        return QRect(left, top, width, height), face

    def _build_placement(
        self,
        assistant_rect: QRect,
        bubble_rect: QRect,
        target_rect: QRect,
        anchor: QPointF,
        docked: bool = False,
    ) -> AssistantPlacement:
        mirrored = bool(target_rect.isValid() and assistant_rect.center().x() > target_rect.center().x())
        effective_anchor = QPointF(1.0 - anchor.x(), anchor.y()) if mirrored else QPointF(anchor)
        direction = self._tail_direction(assistant_rect, bubble_rect)
        tail_rect, face = self._tail_rect(assistant_rect, bubble_rect, direction, effective_anchor)
        return AssistantPlacement(
            assistant_rect,
            bubble_rect,
            target_rect,
            target_rect,
            tail_rect,
            direction,
            face,
            mirrored,
            docked,
        )

    def _free_rectangles(self, area: QRect, obstacles: list[QRect]) -> list[QRect]:
        free = [QRect(area)]
        for obstacle in obstacles:
            clipped = obstacle.intersected(area)
            if not clipped.isValid() or clipped.isEmpty():
                continue
            split = []
            for rect in free:
                overlap = rect.intersected(clipped)
                if not overlap.isValid() or overlap.isEmpty():
                    split.append(rect)
                    continue
                pieces = (
                    QRect(rect.left(), rect.top(), rect.width(), overlap.top() - rect.top()),
                    QRect(rect.left(), overlap.bottom() + 1, rect.width(), rect.bottom() - overlap.bottom()),
                    QRect(rect.left(), overlap.top(), overlap.left() - rect.left(), overlap.height()),
                    QRect(overlap.right() + 1, overlap.top(), rect.right() - overlap.right(), overlap.height()),
                )
                split.extend(piece for piece in pieces if piece.width() >= 56 and piece.height() >= 72)
            unique = self._deduplicate(split)
            pruned = []
            for candidate in sorted(unique, key=lambda rect: rect.width() * rect.height(), reverse=True):
                if any(existing.contains(candidate) for existing in pruned):
                    continue
                pruned.append(candidate)
                if len(pruned) >= 32:
                    break
            free = pruned
            if not free:
                break
        return free

    def _free_pair_candidates(
        self,
        area: QRect,
        target_rect: QRect,
        zones: list[QRect],
        assistant_size: QSize,
        bubble_size: QSize,
    ):
        obstacles = list(zones)
        if target_rect.isValid() and not target_rect.isEmpty():
            obstacles.append(target_rect.adjusted(-self.TARGET_GAP, -self.TARGET_GAP, self.TARGET_GAP, self.TARGET_GAP))
        gap = self.BUBBLE_GAP
        for free in self._free_rectangles(area, obstacles):
            horizontal_width = assistant_size.width() + gap + bubble_size.width()
            horizontal_height = max(assistant_size.height(), bubble_size.height())
            if free.width() >= horizontal_width and free.height() >= horizontal_height:
                xs = (free.left(), free.center().x() - horizontal_width // 2, free.right() - horizontal_width + 1)
                ys = (free.top(), free.center().y() - horizontal_height // 2, free.bottom() - horizontal_height + 1)
                for x in dict.fromkeys(xs):
                    for y in dict.fromkeys(ys):
                        assistant_y = y + (horizontal_height - assistant_size.height()) // 2
                        bubble_y = y + (horizontal_height - bubble_size.height()) // 2
                        left_assistant = QRect(x, assistant_y, assistant_size.width(), assistant_size.height())
                        right_bubble = QRect(x + assistant_size.width() + gap, bubble_y, bubble_size.width(), bubble_size.height())
                        yield "right_middle", left_assistant, right_bubble
                        left_bubble = QRect(x, bubble_y, bubble_size.width(), bubble_size.height())
                        right_assistant = QRect(x + bubble_size.width() + gap, assistant_y, assistant_size.width(), assistant_size.height())
                        yield "left_middle", right_assistant, left_bubble
            vertical_width = max(assistant_size.width(), bubble_size.width())
            vertical_height = assistant_size.height() + gap + bubble_size.height()
            if free.width() >= vertical_width and free.height() >= vertical_height:
                xs = (free.left(), free.center().x() - vertical_width // 2, free.right() - vertical_width + 1)
                ys = (free.top(), free.center().y() - vertical_height // 2, free.bottom() - vertical_height + 1)
                for x in dict.fromkeys(xs):
                    for y in dict.fromkeys(ys):
                        assistant_x = x + (vertical_width - assistant_size.width()) // 2
                        bubble_x = x + (vertical_width - bubble_size.width()) // 2
                        top_assistant = QRect(assistant_x, y, assistant_size.width(), assistant_size.height())
                        bottom_bubble = QRect(bubble_x, y + assistant_size.height() + gap, bubble_size.width(), bubble_size.height())
                        yield "below", top_assistant, bottom_bubble
                        top_bubble = QRect(bubble_x, y, bubble_size.width(), bubble_size.height())
                        bottom_assistant = QRect(assistant_x, y + bubble_size.height() + gap, assistant_size.width(), assistant_size.height())
                        yield "above", bottom_assistant, top_bubble

    def _solve(
        self,
        area: QRect,
        target_rect: QRect,
        zones: list[QRect],
        assistant_size: QSize,
        bubble_size: QSize,
        preferred: str,
        rtl: bool,
        anchor: QPointF,
        previous: AssistantPlacement | None,
    ) -> AssistantPlacement | None:
        best = None
        best_score = float("-inf")
        for assistant_rect in self._assistant_candidates(
            area, target_rect, assistant_size.width(), assistant_size.height(), preferred
        ):
            for label, bubble_rect in self._bubble_candidates(
                assistant_rect, bubble_size.width(), bubble_size.height()
            ):
                if not self.collision.accepts(
                    area,
                    assistant_rect,
                    bubble_rect,
                    target_rect,
                    zones,
                    self.ASSISTANT_GAP,
                    self.TARGET_GAP,
                ):
                    continue
                score = self.collision.score(
                    assistant_rect, bubble_rect, target_rect, label, rtl, preferred, previous
                )
                if score > best_score:
                    best_score = score
                    best = self._build_placement(
                        assistant_rect, bubble_rect, target_rect, anchor
                    )
        for label, assistant_rect, bubble_rect in self._free_pair_candidates(
            area, target_rect, zones, assistant_size, bubble_size
        ):
            if not self.collision.accepts(
                area,
                assistant_rect,
                bubble_rect,
                target_rect,
                zones,
                self.ASSISTANT_GAP,
                self.TARGET_GAP,
            ):
                continue
            score = self.collision.score(
                assistant_rect, bubble_rect, target_rect, label, rtl, preferred, previous
            )
            if score > best_score:
                best_score = score
                best = self._build_placement(assistant_rect, bubble_rect, target_rect, anchor)
        return best

    def _docked(
        self,
        area: QRect,
        target_rect: QRect,
        zones: list[QRect],
        aspect: float,
        bubble_size: QSize,
        anchor: QPointF,
    ) -> AssistantPlacement:
        gap = self.BUBBLE_GAP
        assistant_height = min(area.height(), max(72, min(112, area.height() // 3)))
        assistant_width = max(56, min(area.width(), round(assistant_height * aspect)))
        available_bubble_height = max(1, area.height() - assistant_height - gap)
        bubble_height = min(max(1, bubble_size.height()), available_bubble_height)
        bubble_width = min(area.width(), max(1, bubble_size.width()))
        def sample_axis(start: int, end: int, count: int = 3) -> list[int]:
            if end <= start:
                return [start]
            return sorted({round(start + (end - start) * index / (count - 1)) for index in range(count)})

        x_values = sample_axis(area.left(), area.right() - assistant_width + 1)
        y_values = sample_axis(area.top(), area.bottom() - assistant_height + 1)
        assistant_candidates = self._deduplicate([
            QRect(x, y, assistant_width, assistant_height)
            for y in y_values
            for x in x_values
        ])
        for assistant_rect in assistant_candidates:
            for _label, bubble_rect in self._bubble_candidates(assistant_rect, bubble_width, bubble_height):
                if self.collision.accepts(
                    area,
                    assistant_rect,
                    bubble_rect,
                    target_rect,
                    zones,
                    self.ASSISTANT_GAP,
                    self.TARGET_GAP,
                ):
                    return self._build_placement(assistant_rect, bubble_rect, target_rect, anchor, True)
        protected = target_rect.adjusted(-self.TARGET_GAP, -self.TARGET_GAP, self.TARGET_GAP, self.TARGET_GAP) if target_rect.isValid() else QRect()
        bubble_x_values = sample_axis(area.left(), area.right() - bubble_width + 1)
        bubble_y_values = sample_axis(area.top(), area.bottom() - bubble_height + 1)
        bubble_candidates = self._deduplicate([
            QRect(x, y, bubble_width, bubble_height)
            for y in bubble_y_values
            for x in bubble_x_values
        ])
        best = None
        best_penalty = None
        for assistant_rect in assistant_candidates:
            if protected.isValid() and assistant_rect.intersects(protected):
                continue
            for bubble_rect in bubble_candidates:
                if protected.isValid() and bubble_rect.intersects(protected):
                    continue
                if assistant_rect.adjusted(-gap, -gap, gap, gap).intersects(bubble_rect):
                    continue
                total = 0
                for zone in zones:
                    total += self.collision.overlap_area(assistant_rect, zone)
                    total += self.collision.overlap_area(bubble_rect, zone)
                if best_penalty is None or total < best_penalty:
                    best = (assistant_rect, bubble_rect)
                    best_penalty = total
                    if total == 0:
                        break
            if best_penalty == 0:
                break
        if best is None:
            assistant_rect = QRect(area.left(), area.top(), assistant_width, assistant_height)
            bubble_rect = QRect(
                area.right() - bubble_width + 1,
                area.bottom() - bubble_height + 1,
                bubble_width,
                bubble_height,
            )
            return self._build_placement(assistant_rect, bubble_rect, target_rect, anchor, True)
        assistant_rect, bubble_rect = best
        return self._build_placement(assistant_rect, bubble_rect, target_rect, anchor, True)

    def calculate_placement(
        self,
        host: QWidget,
        target: QWidget | None,
        pixmap: QPixmap,
        preferred: str = "auto",
        bubble_size: QSize | None = None,
        exclusion_rects: list[QRect] | None = None,
        previous: AssistantPlacement | None = None,
        face_anchor: QPointF | None = None,
    ) -> AssistantPlacement:
        host_rect = host.rect()
        padding = self.EDGE_PADDING if host_rect.width() > 96 and host_rect.height() > 96 else 4
        area = host_rect.adjusted(padding, padding, -padding, -padding)
        if area.width() < 1 or area.height() < 1:
            area = QRect(0, 0, max(1, host_rect.width()), max(1, host_rect.height()))
        target_rect = self.map_rect(target, host) if target is not None else QRect()
        if target_rect.isValid():
            target_rect = target_rect.intersected(host_rect)
        zones = []
        for zone in exclusion_rects or []:
            clipped = QRect(zone).adjusted(
                -self.TARGET_GAP,
                -self.TARGET_GAP,
                self.TARGET_GAP,
                self.TARGET_GAP,
            ).intersected(host_rect)
            if clipped.isValid() and not clipped.isEmpty():
                zones.append(clipped)
        aspect = pixmap.width() / max(1, pixmap.height()) if not pixmap.isNull() else 0.62
        base_height = max(
            self.MIN_ASSISTANT_HEIGHT,
            min(self.MAX_ASSISTANT_HEIGHT, max(1, round(area.height() * 0.28))),
        )
        base_height = min(base_height, area.height())
        desired_bubble = bubble_size or QSize(
            min(390, max(self.MIN_BUBBLE_WIDTH, round(area.width() * 0.34))), 176
        )
        bubble_width = min(max(1, desired_bubble.width()), area.width())
        bubble_height = min(max(1, desired_bubble.height()), area.height())
        anchor = face_anchor or QPointF(0.55, 0.34)
        for assistant_scale in (1.0, 0.86, 0.72):
            assistant_height = max(
                min(self.MIN_ASSISTANT_HEIGHT, area.height()),
                min(area.height(), round(base_height * assistant_scale)),
            )
            assistant_width = min(area.width(), max(56, round(assistant_height * aspect)))
            widths = [bubble_width]
            if bubble_width > self.MIN_BUBBLE_WIDTH:
                widths.extend((
                    max(self.MIN_BUBBLE_WIDTH, round(bubble_width * 0.88)),
                    max(self.MIN_BUBBLE_WIDTH, round(bubble_width * 0.76)),
                ))
            for width in dict.fromkeys(widths):
                width = min(width, area.width())
                extra_height = max(0, round((bubble_width - width) * 0.35))
                height = min(area.height(), bubble_height + extra_height)
                result = self._solve(
                    area,
                    target_rect,
                    zones,
                    QSize(assistant_width, assistant_height),
                    QSize(width, height),
                    preferred,
                    host.layoutDirection() == Qt.RightToLeft,
                    anchor,
                    previous,
                )
                if result is not None:
                    return result
        return self._docked(area, target_rect, zones, aspect, QSize(bubble_width, bubble_height), anchor)

    def calculate(
        self,
        host: QWidget,
        target: QWidget | None,
        pixmap: QPixmap,
        preferred: str = "auto",
        bubble_size: QSize | None = None,
        exclusion_rects: list[QRect] | None = None,
        previous: AssistantPlacement | None = None,
    ) -> tuple[QRect, QRect, QRect, bool]:
        return self.calculate_placement(
            host,
            target,
            pixmap,
            preferred,
            bubble_size,
            exclusion_rects,
            previous,
        ).legacy()


class AssistantLayoutManager(AssistantPlacementEngine):
    pass


class AssistantPositionManager(AssistantLayoutManager):
    pass


class AssistantExclusionRegistry:
    OBJECT_NAMES = {
        "sidebar",
        "toast",
        "updateNotification",
        "modalHeader",
        "modalFooter",
        "modalPrimary",
        "modalSecondary",
        "validationError",
        "metricCard",
        "activityBar",
        "pageHeader",
        "pageToolbar",
        "profileSelectionBar",
        "makerSourceCard",
        "makerTestBar",
        "makerResultToolbar",
        "makerActionBar",
        "sniMakerCountryRail",
        "scanControlCard",
        "sniActionBar",
        "terminalToolbar",
        "closeChoiceIcon",
        "closeChoiceTitle",
        "closeChoiceText",
        "closeChoiceDetail",
        "quietButton",
        "dangerButton",
        "trayChoiceButton",
    }

    def __init__(self, window):
        self.window = window
        self._providers: dict[int, list[Callable[[], list[QWidget] | tuple[QWidget, ...]]]] = {}

    def register(self, page_index: int, provider: Callable[[], list[QWidget] | tuple[QWidget, ...]]) -> None:
        self._providers.setdefault(int(page_index), []).append(provider)

    @staticmethod
    def _visible(widget: QWidget, host: QWidget) -> bool:
        try:
            return widget.isVisible() and widget.isVisibleTo(widget.window()) and widget.window().isVisible()
        except RuntimeError:
            return False

    def collect(self, host: QWidget, target: QWidget | None, page_index: int) -> list[QRect]:
        widgets = []
        focus = QApplication.focusWidget()
        if isinstance(focus, QWidget) and focus is not target:
            widgets.append(focus)
        roots = [host]
        current_page = self.window.stack.currentWidget() if hasattr(self.window, "stack") else None
        if isinstance(current_page, QWidget) and current_page is not host:
            roots.append(current_page)
        for root in roots:
            candidates = [root, *root.findChildren(QWidget)] if isinstance(host, QDialog) or root is current_page else [root]
            for widget in candidates:
                name = widget.objectName()
                if widget is not target and not name.startswith("assistant") and name in self.OBJECT_NAMES:
                    widgets.append(widget)
        for value in vars(self.window).values():
            candidates = value if isinstance(value, (list, tuple)) else (value,)
            for widget in candidates:
                if not isinstance(widget, QWidget) or widget is target:
                    continue
                if widget.objectName() in self.OBJECT_NAMES:
                    widgets.append(widget)
        popup = QApplication.activePopupWidget()
        if isinstance(popup, QWidget) and popup is not host:
            widgets.append(popup)
        modal = QApplication.activeModalWidget()
        if isinstance(modal, QWidget) and modal is not host:
            widgets.append(modal)
        for provider in self._providers.get(int(page_index), []):
            try:
                widgets.extend(widget for widget in provider() if isinstance(widget, QWidget))
            except (RuntimeError, TypeError):
                continue
        zones = []
        seen = set()
        for widget in widgets:
            if widget is target or id(widget) in seen or not self._visible(widget, host):
                continue
            seen.add(id(widget))
            rect = AssistantPlacementEngine.map_rect(widget, host)
            clipped = rect.intersected(host.rect())
            if clipped.isValid() and not clipped.isEmpty():
                if any(existing.contains(clipped) for existing in zones):
                    continue
                zones = [existing for existing in zones if not clipped.contains(existing)]
                zones.append(clipped)
        return sorted(zones, key=lambda rect: rect.width() * rect.height(), reverse=True)[:48]


class AssistantVisualOverlay(QWidget):
    def __init__(self, parent=None, reduced_motion: bool = False):
        super().__init__(parent)
        self.setObjectName("assistantVisualOverlay")
        self.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self._pixmap = QPixmap()
        self._assistant_rect = QRect()
        self._highlight_rect = QRect()
        self._pulse = 0.0
        self._idle_offset = 0
        self._move_animation = QPropertyAnimation(self, b"assistantRect", self)
        self._move_animation.setDuration(360 if not reduced_motion else 0)
        self._move_animation.setEasingCurve(QEasingCurve.OutCubic)
        self._idle_animation = QPropertyAnimation(self, b"idleOffset", self)
        self._idle_animation.setDuration(3200)
        self._idle_animation.setStartValue(0)
        self._idle_animation.setEndValue(4)
        self._idle_animation.setLoopCount(-1)
        self._idle_animation.setEasingCurve(QEasingCurve.InOutSine)
        self._pulse_timer = QTimer(self)
        self._pulse_timer.setInterval(80)
        self._pulse_timer.timeout.connect(self._tick)
        if not reduced_motion:
            self._idle_animation.start()
            self._pulse_timer.start()

    def _get_assistant_rect(self) -> QRect:
        return QRect(self._assistant_rect)

    def _set_assistant_rect(self, value: QRect) -> None:
        self._assistant_rect = QRect(value)
        self.update()

    assistantRect = Property(QRect, _get_assistant_rect, _set_assistant_rect)

    def _get_idle_offset(self) -> int:
        return self._idle_offset

    def _set_idle_offset(self, value: int) -> None:
        self._idle_offset = int(value)
        self.update()

    idleOffset = Property(int, _get_idle_offset, _set_idle_offset)

    def _tick(self) -> None:
        self._pulse = (self._pulse + 0.08) % 1.0
        self.update()

    def set_visual(
        self,
        pixmap: QPixmap,
        assistant_rect: QRect,
        highlight_rect: QRect,
        animate: bool = True,
        avoid_rects: list[QRect] | None = None,
    ) -> None:
        self._pixmap = pixmap
        self._highlight_rect = QRect(highlight_rect)
        if self._assistant_rect == assistant_rect:
            self._move_animation.stop()
            self.update()
            self.show()
            return
        corridor = self._assistant_rect.united(assistant_rect) if self._assistant_rect.isValid() else QRect()
        blocked_path = any(corridor.intersects(rect) for rect in avoid_rects or [])
        if animate and not blocked_path and self._assistant_rect.isValid() and self._move_animation.duration() > 0:
            self._move_animation.stop()
            self._move_animation.setStartValue(self._assistant_rect)
            self._move_animation.setEndValue(assistant_rect)
            self._move_animation.start()
        else:
            self._move_animation.stop()
            self._set_assistant_rect(assistant_rect)
        self.show()

    def clear(self) -> None:
        self._move_animation.stop()
        self._idle_animation.stop()
        self._pulse_timer.stop()
        self._pixmap = QPixmap()
        self._highlight_rect = QRect()
        self.hide()

    def _draw_target_pointer(self, painter: QPainter) -> None:
        target = self._highlight_rect
        if not target.isValid() or target.isEmpty() or not self._assistant_rect.isValid():
            return
        delta_x = self._assistant_rect.center().x() - target.center().x()
        delta_y = self._assistant_rect.center().y() - target.center().y()
        offset = 24 + round(3 * abs(0.5 - self._pulse) * 2)
        if abs(delta_x) >= abs(delta_y):
            if delta_x < 0:
                glyph = "☞"
                center = QPoint(target.left() - offset, target.center().y())
            else:
                glyph = "☜"
                center = QPoint(target.right() + offset, target.center().y())
        elif delta_y < 0:
            glyph = "☟"
            center = QPoint(target.center().x(), target.top() - offset)
        else:
            glyph = "☝"
            center = QPoint(target.center().x(), target.bottom() + offset)
        center.setX(max(22, min(self.width() - 22, center.x())))
        center.setY(max(22, min(self.height() - 22, center.y())))
        pointer_rect = QRect(center.x() - 22, center.y() - 22, 44, 44)
        painter.setFont(QFont("Segoe UI Symbol", 28 + round(self._pulse * 2), QFont.Bold))
        painter.setPen(QColor(0, 8, 18, 210))
        painter.drawText(pointer_rect.translated(2, 3), Qt.AlignCenter, glyph)
        painter.setPen(QColor(80, 255, 237, 245))
        painter.drawText(pointer_rect, Qt.AlignCenter, glyph)

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.setRenderHint(QPainter.SmoothPixmapTransform, True)
        if self._highlight_rect.isValid() and not self._highlight_rect.isEmpty():
            glow = 80 + int(40 * abs(0.5 - self._pulse) * 2)
            rect = self._highlight_rect.adjusted(-6, -6, 6, 6)
            painter.setPen(QPen(QColor(35, 245, 224, glow + 90), 2.2))
            painter.setBrush(QColor(35, 245, 224, 18))
            painter.drawRoundedRect(rect, 12, 12)
            self._draw_target_pointer(painter)
        if not self._pixmap.isNull() and self._assistant_rect.isValid():
            rect = self._assistant_rect.translated(0, self._idle_offset)
            painter.drawPixmap(rect, self._pixmap)
        painter.end()


class AssistantMessageBubble(QFrame):
    def __init__(self, parent=None, reduced_motion: bool = False):
        super().__init__(parent)
        self.setObjectName("assistantBubble")
        self.setLayoutDirection(Qt.RightToLeft)
        self.setAttribute(Qt.WA_StyledBackground, True)
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 15, 18, 13)
        root.setSpacing(10)
        self.text = QLabel()
        self.text.setObjectName("assistantBubbleText")
        self.text.setWordWrap(True)
        self.text.setAlignment(Qt.AlignRight | Qt.AlignTop)
        self.text.setLayoutDirection(Qt.RightToLeft)
        self.text.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.setAccessibleName("پیام دستیار کمکی")
        self.text.setAccessibleName("متن راهنمای دستیار")
        self.text_scroll = QScrollArea()
        self.text_scroll.setObjectName("assistantBubbleTextScroll")
        self.text_scroll.setFrameShape(QFrame.NoFrame)
        self.text_scroll.setWidgetResizable(False)
        self.text_scroll.setAlignment(Qt.AlignRight | Qt.AlignTop)
        self.text_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.text_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.text_scroll.setWidget(self.text)
        root.addWidget(self.text_scroll, 1)
        actions = QHBoxLayout()
        actions.setDirection(QHBoxLayout.RightToLeft)
        actions.setSpacing(7)
        self.next_button = QPushButton("بعدی")
        self.previous_button = QPushButton("قبلی")
        self.ack_button = QPushButton("متوجه شدم")
        self.skip_button = QPushButton("رد کردن راهنما")
        self.close_button = QPushButton("بستن")
        for button, name in (
            (self.next_button, "مرحله‌ی بعدی راهنما"),
            (self.previous_button, "مرحله‌ی قبلی راهنما"),
            (self.ack_button, "تأیید پیام دستیار"),
            (self.skip_button, "رد کردن راهنما"),
            (self.close_button, "بستن پیام دستیار"),
        ):
            button.setObjectName("assistantBubbleButton")
            button.setAccessibleName(name)
            button.setFocusPolicy(Qt.StrongFocus)
            actions.addWidget(button)
        actions.addStretch()
        root.addLayout(actions)
        self._effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._effect)
        self._fade = QPropertyAnimation(self._effect, b"opacity", self)
        self._fade.setDuration(180 if not reduced_motion else 0)
        self._fade.setEasingCurve(QEasingCurve.OutCubic)

    def set_message(self, text: str, tour: bool, has_previous: bool, has_next: bool, dismissible: bool) -> None:
        self.text.setText(str(text))
        self.text.setAccessibleDescription(str(text))
        self.text_scroll.verticalScrollBar().setValue(0)
        self.previous_button.setVisible(tour and has_previous)
        self.next_button.setVisible(tour and has_next)
        self.ack_button.setVisible(not tour)
        self.skip_button.setVisible(tour)
        self.close_button.setVisible(dismissible and not tour)
        self.layout().invalidate()
        try:
            QAccessible.updateAccessibility(QAccessibleAnnouncementEvent(self.text, str(text)))
        except RuntimeError:
            pass

    def measure_for(self, viewport_size: QSize) -> QSize:
        self.ensurePolished()
        self.text.ensurePolished()
        available_width = max(1, int(viewport_size.width()) - 32)
        maximum_width = min(420, max(220, int(available_width * 0.35)))
        maximum_width = min(available_width, maximum_width)
        buttons = [
            button for button in (
                self.next_button,
                self.previous_button,
                self.ack_button,
                self.skip_button,
                self.close_button,
            )
            if not button.isHidden()
        ]
        action_width = sum(button.sizeHint().width() for button in buttons) + max(0, len(buttons) - 1) * 7
        minimum_width = min(available_width, max(220, action_width + 36))
        metrics = QFontMetrics(self.text.font())
        unwrapped = metrics.horizontalAdvance(self.text.text()) + 42
        width = max(minimum_width, min(maximum_width, max(280, unwrapped)))
        width = min(available_width, width)
        action_height = max((button.sizeHint().height() for button in buttons), default=0)
        maximum_height = max(96, int(viewport_size.height()) - 32)
        maximum_text_view = max(metrics.height() * 2, maximum_height - action_height - 48)

        margins = self.layout().contentsMargins()
        frame = max(0, self.frameWidth())
        scroll_width = max(80, width - margins.left() - margins.right() - frame * 2)

        def measured_height(label_width: int) -> int:
            self.text.setFixedWidth(max(1, label_width))
            height = self.text.heightForWidth(max(1, label_width))
            bounds = metrics.boundingRect(
                QRect(0, 0, max(1, label_width), 100000),
                Qt.TextWordWrap | Qt.AlignRight | Qt.AlignTop,
                self.text.text() or " ",
            )
            height = max(height, bounds.height())
            return max(metrics.lineSpacing() + 6, height + 4)

        text_width = scroll_width
        text_height = measured_height(text_width)
        needs_scrollbar = text_height > maximum_text_view
        if needs_scrollbar:
            scrollbar_extent = self.style().pixelMetric(
                QStyle.PM_ScrollBarExtent, None, self.text_scroll
            )
            text_width = max(80, scroll_width - max(0, scrollbar_extent))
            text_height = measured_height(text_width)

        text_view_height = min(text_height, maximum_text_view)
        self.text.setFixedSize(text_width, text_height)
        self.text_scroll.setFixedHeight(text_view_height)
        self.text_scroll.setVerticalScrollBarPolicy(
            Qt.ScrollBarAlwaysOn if text_height > text_view_height else Qt.ScrollBarAlwaysOff
        )
        height = min(maximum_height, 15 + text_view_height + (10 if action_height else 0) + action_height + 13)
        return QSize(width, max(96, height))

    def reveal(self) -> None:
        self.show()
        self.raise_()
        self._fade.stop()
        if self._fade.duration() > 0:
            self._effect.setOpacity(0.0)
            self._fade.setStartValue(0.0)
            self._fade.setEndValue(1.0)
            self._fade.start()
        else:
            self._effect.setOpacity(1.0)


class AssistantBubbleTail(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._direction = "right"
        self.setFixedSize(20, 28)
        self.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self.setAttribute(Qt.WA_TranslucentBackground, True)

    def set_direction(self, direction: str) -> None:
        self._direction = direction if direction in {"left", "right", "top", "bottom"} else "right"
        if self._direction in {"top", "bottom"}:
            self.setFixedSize(28, 20)
        else:
            self.setFixedSize(20, 28)
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        path = QPainterPath()
        if self._direction == "right":
            path.moveTo(0, 4)
            path.lineTo(self.width(), self.height() / 2)
            path.lineTo(0, self.height() - 4)
        elif self._direction == "left":
            path.moveTo(self.width(), 4)
            path.lineTo(0, self.height() / 2)
            path.lineTo(self.width(), self.height() - 4)
        elif self._direction == "top":
            path.moveTo(4, self.height())
            path.lineTo(self.width() / 2, 0)
            path.lineTo(self.width() - 4, self.height())
        else:
            path.moveTo(4, 0)
            path.lineTo(self.width() / 2, self.height())
            path.lineTo(self.width() - 4, 0)
        path.closeSubpath()
        painter.setPen(QPen(QColor(64, 240, 226, 200), 1.5))
        painter.setBrush(QColor(10, 33, 62, 252))
        painter.drawPath(path)
        painter.end()


class AssistantController(QWidget):
    def __init__(self, window, asset_root: Path | None = None, reduced_motion: bool = False):
        super().__init__(window)
        self.window = window
        self.settings = AssistantSettings(window.storage)
        self.assets = AssistantAssetManager(asset_root, getattr(window.bridge, "log", None).emit if hasattr(window.bridge, "log") else None)
        self.collector = AssistantContextCollector(window)
        self.resolver = AssistantStateResolver()
        self.registry = AssistantGuideRegistry()
        self.positioner = AssistantLayoutManager()
        self.exclusions = AssistantExclusionRegistry(window)
        self.queue = AssistantMessageQueue()
        self.reduced_motion = bool(reduced_motion)
        self.enabled = False
        self.overlay: AssistantVisualOverlay | None = None
        self.bubble: AssistantMessageBubble | None = None
        self.tail: AssistantBubbleTail | None = None
        self.current_decision: AssistantDecision | None = None
        self.current_context: AssistantContext | None = None
        self.current_placement: AssistantPlacement | None = None
        self._host: QWidget | None = None
        self._scroll_sources = []
        self._last_action = ""
        self._last_action_at = 0.0
        self._last_key = ""
        self._normal_shown = False
        self._tour = []
        self._tour_index = -1
        self._tour_switching = False
        self._showing_tour = False
        self._geometry_dirty = True
        self._repositioning = False
        self._dismissed_until: dict[str, float] = {}
        self._evaluate_timer = QTimer(self)
        self._evaluate_timer.setInterval(1500)
        self._evaluate_timer.timeout.connect(self.evaluate)
        self._event_timer = QTimer(self)
        self._event_timer.setSingleShot(True)
        self._event_timer.setInterval(80)
        self._event_timer.timeout.connect(self.evaluate)
        self._reposition_timer = QTimer(self)
        self._reposition_timer.setSingleShot(True)
        self._reposition_timer.setInterval(35)
        self._reposition_timer.timeout.connect(self.reposition)
        self._navigation_timer = QTimer(self)
        self._navigation_timer.setSingleShot(True)
        self._navigation_timer.setInterval(470)
        self._navigation_timer.timeout.connect(self._finish_navigation)
        self._hide_timer = QTimer(self)
        self._hide_timer.setSingleShot(True)
        self._hide_timer.timeout.connect(self.dismiss_message)
        self._reflow_events = {
            QEvent.Resize,
            QEvent.Move,
            QEvent.LayoutRequest,
            QEvent.Wheel,
            QEvent.Show,
            QEvent.Hide,
            QEvent.ShowToParent,
            QEvent.HideToParent,
            QEvent.WindowActivate,
            QEvent.WindowDeactivate,
            QEvent.WindowStateChange,
            QEvent.FontChange,
            QEvent.ApplicationFontChange,
            QEvent.StyleChange,
            QEvent.LanguageChange,
            QEvent.LayoutDirectionChange,
            QEvent.ParentChange,
        }
        for name in ("ScreenChangeInternal", "DevicePixelRatioChange"):
            event_type = getattr(QEvent, name, None)
            if event_type is not None:
                self._reflow_events.add(event_type)

    def _resolve_target(self, name: str) -> QWidget | None:
        value = getattr(self.window, str(name), None)
        if isinstance(value, QWidget):
            return value
        if isinstance(value, (list, tuple)):
            return next((item for item in value if isinstance(item, QWidget) and is_qt_valid(item)), None)
        roots = [QApplication.activeModalWidget(), self.window.stack.currentWidget(), self.window]
        for root in roots:
            if isinstance(root, QWidget):
                found = root.findChild(QWidget, str(name))
                if found is not None:
                    return found
        return None

    def _choose_host(self) -> QWidget:
        modal = QApplication.activeModalWidget()
        if isinstance(modal, QWidget) and is_qt_valid(modal):
            if modal.objectName() == "closeChoiceDialog":
                return self.window.centralWidget()
        focus = QApplication.focusWidget()
        if isinstance(focus, QWidget):
            try:
                focus_window = focus.window()
                if isinstance(focus_window, QDialog) and focus_window is not self.window and focus_window.isVisible():
                    return focus_window
            except RuntimeError:
                pass
        if isinstance(modal, QWidget) and is_qt_valid(modal):
            return modal
        active = QApplication.activeWindow()
        if isinstance(active, QDialog) and active is not self.window and is_qt_valid(active):
            return active
        return self.window.centralWidget()

    @staticmethod
    def _alive(widget: QWidget | None) -> bool:
        return isinstance(widget, QWidget) and is_qt_valid(widget)

    def _drop_widgets(self) -> None:
        self._unbind_scroll_sources()
        self.overlay = None
        self.bubble = None
        self.tail = None
        self._host = None
        self.current_placement = None

    def _unbind_scroll_sources(self) -> None:
        for bar in self._scroll_sources:
            if not is_qt_valid(bar):
                continue
            try:
                bar.valueChanged.disconnect(self.schedule_reposition)
            except (RuntimeError, TypeError):
                pass
        self._scroll_sources = []

    def _bind_scroll_sources(self, host: QWidget) -> None:
        sources = []
        root = host
        central = self.window.centralWidget() if hasattr(self.window, "centralWidget") else None
        if host is central and hasattr(self.window, "stack"):
            current = self.window.stack.currentWidget()
            if isinstance(current, QWidget):
                root = current
        for area in root.findChildren(QAbstractScrollArea):
            for bar in (area.verticalScrollBar(), area.horizontalScrollBar()):
                if bar is not None and is_qt_valid(bar) and bar not in sources:
                    sources.append(bar)
        if len(sources) == len(self._scroll_sources) and all(
            source is existing for source, existing in zip(sources, self._scroll_sources)
        ):
            return
        self._unbind_scroll_sources()
        self._scroll_sources = sources
        for bar in self._scroll_sources:
            bar.valueChanged.connect(self.schedule_reposition)

    def _host_destroyed(self, host) -> None:
        if self._host is host:
            self._drop_widgets()

    def _ensure_widgets(self) -> None:
        host = self._choose_host()
        if self._host is host and all(self._alive(widget) for widget in (self.overlay, self.bubble, self.tail)):
            return
        if self._alive(self.overlay):
            self.overlay.clear()
            self.overlay.deleteLater()
        if self._alive(self.bubble):
            self.bubble.hide()
            self.bubble.deleteLater()
        if self._alive(self.tail):
            self.tail.hide()
            self.tail.deleteLater()
        self._host = host
        self.current_placement = None
        self.overlay = AssistantVisualOverlay(host, self.reduced_motion)
        self.overlay.setGeometry(host.rect())
        self.bubble = AssistantMessageBubble(host, self.reduced_motion)
        self.tail = AssistantBubbleTail(host)
        self._bind_scroll_sources(host)
        self.overlay.raise_()
        self.tail.raise_()
        self.bubble.raise_()
        host.destroyed.connect(lambda _object=None, current=host: self._host_destroyed(current))
        self.bubble.next_button.clicked.connect(self.next_step)
        self.bubble.previous_button.clicked.connect(self.previous_step)
        self.bubble.ack_button.clicked.connect(self.dismiss_message)
        self.bubble.close_button.clicked.connect(self.dismiss_message)
        self.bubble.skip_button.clicked.connect(self.skip_tour)

    def enable(self) -> None:
        if self.enabled:
            self.evaluate(force=True)
            return
        self.enabled = True
        self.settings.set_enabled(True)
        QApplication.instance().installEventFilter(self)
        self._ensure_widgets()
        self._evaluate_timer.start()
        QTimer.singleShot(0, lambda: self.evaluate(force=True))

    def disable(self, persist: bool = True) -> None:
        if persist:
            self.settings.set_enabled(False)
        if QApplication.instance() is not None:
            QApplication.instance().removeEventFilter(self)
        self.enabled = False
        self._evaluate_timer.stop()
        self._reposition_timer.stop()
        self._event_timer.stop()
        self._navigation_timer.stop()
        self._hide_timer.stop()
        self.queue.clear()
        self._tour = []
        self._tour_index = -1
        self.current_decision = None
        self.current_context = None
        self.current_placement = None
        if self._alive(self.overlay):
            self.overlay.clear()
            self.overlay.deleteLater()
        if self._alive(self.bubble):
            self.bubble.hide()
            self.bubble.deleteLater()
        if self._alive(self.tail):
            self.tail.hide()
            self.tail.deleteLater()
        self._drop_widgets()

    def _assistant_owned(self, watched) -> bool:
        if not isinstance(watched, QWidget):
            return False
        for widget in (self.overlay, self.bubble, self.tail):
            if self._alive(widget) and (watched is widget or widget.isAncestorOf(watched)):
                return True
        return watched.objectName().startswith("assistant")

    def _should_reflow(self, watched) -> bool:
        if watched is QApplication.instance():
            return True
        if watched in self._scroll_sources:
            return True
        if not isinstance(watched, QWidget) or self._assistant_owned(watched):
            return False
        current_page = self.window.stack.currentWidget() if hasattr(self.window, "stack") else None
        if watched in {self.window, self._host, current_page}:
            return True
        target = self.current_decision.target if self.current_decision is not None else None
        if self._alive(target) and (watched is target or watched.isAncestorOf(target)):
            return True
        dialog = QApplication.activeModalWidget()
        if isinstance(dialog, QWidget) and watched is dialog:
            return True
        return watched.objectName() in self.exclusions.OBJECT_NAMES

    def eventFilter(self, watched, event) -> bool:
        if not self.enabled:
            return False
        if self._assistant_owned(watched):
            if event.type() == QEvent.KeyPress and event.key() == Qt.Key_Escape:
                self.dismiss_message()
                return True
            return False
        bubble = self.bubble if self._alive(self.bubble) else None
        inside_bubble = bool(
            bubble is not None
            and isinstance(watched, QWidget)
            and (watched is bubble or bubble.isAncestorOf(watched))
        )
        if inside_bubble:
            if event.type() == QEvent.KeyPress and event.key() == Qt.Key_Escape:
                self.dismiss_message()
                return True
            return False
        if event.type() in {QEvent.MouseButtonPress, QEvent.KeyPress, QEvent.FocusIn}:
            name = watched.objectName() if isinstance(watched, QWidget) else type(watched).__name__
            self._last_action = str(name or type(watched).__name__)
            self._last_action_at = time.time()
            if event.type() == QEvent.KeyPress and event.key() == Qt.Key_Escape:
                self.dismiss_message()
                return False
            self._event_timer.start()
        animated_page = getattr(self.window, "_animated_page", None)
        if event.type() == QEvent.Move and watched is animated_page:
            return False
        if event.type() in self._reflow_events and self._should_reflow(watched):
            self.schedule_reposition()
        return False

    def on_navigation(self, index: int) -> None:
        if not self.enabled or self._tour_switching:
            return
        self.queue.discard_other_pages(int(index))
        self.current_decision = None
        if self._alive(self.bubble):
            self.bubble.hide()
        if self._alive(self.tail):
            self.tail.hide()
        if self._alive(self.overlay):
            self.overlay.hide()
        self._last_key = ""
        self._normal_shown = False
        self._geometry_dirty = True
        self._hide_timer.stop()
        if self._host is not None:
            self._bind_scroll_sources(self._host)
        self._navigation_timer.start()

    def _finish_navigation(self) -> None:
        if not self.enabled:
            return
        if self._host is not None:
            self._bind_scroll_sources(self._host)
        self.evaluate(force=True)

    def schedule_reposition(self) -> None:
        if self.enabled:
            self._geometry_dirty = True
            if not self._reposition_timer.isActive():
                self._reposition_timer.start()

    def _guide_decision(self, context: AssistantContext) -> AssistantDecision | None:
        if not self.settings.guides_enabled:
            return None
        seen = self.settings.seen()
        for guide in self.registry.for_page(context.page_index):
            if guide.show_once and guide.id in seen:
                continue
            if not self.registry.condition_matches(guide, context, self.window):
                continue
            target = self._resolve_target(guide.target)
            if target is None or not target.isVisible():
                continue
            return AssistantDecision(
                guide.assistant_state,
                message(guide.message_key),
                20 + guide.priority,
                target,
                guide.id,
                guide.preferred_position,
                guide.dismissible,
                guide.timeout,
                context.page_index,
            )
        return None

    def evaluate(self, force: bool = False) -> None:
        if not self.enabled or self.window._closing:
            return
        self._ensure_widgets()
        context = self.collector.collect(self._last_action, self._last_action_at)
        self.current_context = context
        if self._tour:
            urgent = self.resolver.resolve(context)
            if urgent is not None and urgent.state in {AssistantState.SAD, AssistantState.SURPRISED} and not self.settings.warnings_enabled:
                urgent = None
            if urgent is not None and urgent.priority >= 80:
                self.show_decision(urgent)
                return
            guide_id = self._tour[self._tour_index].id if 0 <= self._tour_index < len(self._tour) else ""
            if self.current_decision is None or self.current_decision.guide_id != guide_id:
                self._show_tour_step()
            elif self._geometry_dirty:
                self.reposition()
            return
        live_decision = self.resolver.resolve(context)
        if live_decision is not None and live_decision.state in {AssistantState.SAD, AssistantState.SURPRISED} and not self.settings.warnings_enabled:
            live_decision = None
        if (
            self.current_decision is not None
            and bool(self.current_decision.guide_id)
            and self._alive(self.bubble)
            and self.bubble.isVisible()
            and (live_decision is None or live_decision.priority <= self.current_decision.priority)
        ):
            if self._geometry_dirty:
                self.reposition()
            return
        decision = self.queue.pop(context.page_index)
        if decision is None:
            decision = live_decision
        if decision is None and not self._tour:
            decision = self._guide_decision(context)
        if decision is None:
            decision = AssistantDecision(AssistantState.NORMAL, message("normal"), 1, timeout=5000, page_index=context.page_index)
        key = "|".join((decision.state.value, decision.text, decision.guide_id, str(context.page_index)))
        if not force and time.time() < self._dismissed_until.get(key, 0.0):
            return
        if not force and key == self._last_key:
            if self._geometry_dirty:
                self.reposition()
            return
        self._last_key = key
        self.show_decision(decision)

    def show_decision(self, decision: AssistantDecision, tour: bool = False) -> None:
        if not self.enabled:
            return
        self._ensure_widgets()
        target = decision.target
        if not self._alive(target):
            target = None
            decision.target = None
        if target is not None and not target.isEnabled():
            decision = AssistantDecision(AssistantState.CONFUSED, message("disabled_target"), decision.priority, target, decision.guide_id, decision.preferred_position, True, 0, decision.page_index)
        self.current_decision = decision
        self._showing_tour = bool(tour)
        if target is not None:
            self.positioner.ensure_visible(target)
        has_previous = tour and self._tour_index > 0
        has_next = tour and self._tour_index + 1 < len(self._tour)
        self.bubble.set_message(decision.text, tour, has_previous, has_next, decision.dismissible)
        self.reposition()
        self.overlay.raise_()
        self.tail.raise_()
        self.bubble.raise_()
        self.bubble.reveal()
        self._hide_timer.stop()
        if decision.timeout > 0 and not tour:
            self._hide_timer.start(decision.timeout)

    def reposition(self) -> None:
        if not self.enabled or self.current_decision is None:
            return
        if self._repositioning:
            self._geometry_dirty = True
            return
        self._geometry_dirty = False
        self._repositioning = True
        try:
            self._reposition_now()
        finally:
            self._repositioning = False

    def _reposition_now(self) -> None:
        self._ensure_widgets()
        host = self._host
        if host is None or self.overlay is None or self.bubble is None or self.tail is None:
            return
        if self.overlay.geometry() != host.rect():
            self.overlay.setGeometry(host.rect())
        target = self.current_decision.target
        if not self._alive(target):
            target = None
        elif not target.isVisible():
            target = None
        elif target.window() is not host.window():
            active_dialog = QApplication.activeModalWidget()
            if target.window() is not active_dialog:
                target = None
        bubble_size = self.bubble.measure_for(host.size())
        provisional = self.assets.pixmap(self.current_decision.state, False)
        page_index = self.current_context.page_index if self.current_context is not None else -1
        exclusion_rects = self.exclusions.collect(host, target, page_index)
        placement = self.positioner.calculate_placement(
            host,
            target,
            provisional,
            self.current_decision.preferred_position,
            bubble_size,
            exclusion_rects,
            self.current_placement,
            self.assets.face_anchor(self.current_decision.state, False),
        )
        pixmap = self.assets.pixmap(
            self.current_decision.state,
            placement.mirrored and self.current_decision.state == AssistantState.GUIDING_RIGHT,
        )
        same_route = bool(
            self.current_placement is not None
            and self.current_placement.tail_direction == placement.tail_direction
            and not self.current_placement.docked
            and not placement.docked
        )
        visual_target_rect = placement.highlight_rect
        if target is not None and target.window() is not host.window():
            visual_target_rect = self.positioner.map_rect(target.window(), host).intersected(host.rect())
        self.overlay.set_visual(
            pixmap,
            placement.assistant_rect,
            visual_target_rect,
            animate=same_route,
            avoid_rects=[
                placement.bubble_rect,
                placement.target_rect.adjusted(-12, -12, 12, 12),
                *exclusion_rects,
            ],
        )
        if self.bubble.geometry() != placement.bubble_rect:
            self.bubble.setGeometry(placement.bubble_rect)
        self.tail.set_direction(placement.tail_direction)
        if self.tail.geometry() != placement.tail_rect:
            self.tail.setGeometry(placement.tail_rect)
        self.tail.show()
        self.current_placement = placement

    def dismiss_message(self) -> None:
        self._hide_timer.stop()
        if self._alive(self.bubble):
            self.bubble.hide()
        if self._alive(self.tail):
            self.tail.hide()
        if self._alive(self.overlay) and self.current_decision is not None:
            if self.current_decision.state == AssistantState.NORMAL:
                self.overlay._highlight_rect = QRect()
                self.overlay.update()
            else:
                self.overlay.hide()
        if self.current_decision is not None:
            if self.current_decision.guide_id and not self._showing_tour:
                self.settings.mark_seen(self.current_decision.guide_id)
            page_index = self.current_context.page_index if self.current_context is not None else -1
            key = "|".join((self.current_decision.state.value, self.current_decision.text, self.current_decision.guide_id, str(page_index)))
            self._dismissed_until[key] = time.time() + (8 if self.current_decision.priority >= 80 else 30)
            self._last_key = key

    def start_tour(self) -> None:
        if not self.enabled:
            self.enable()
        self.settings.reset_guides()
        self._tour = self.registry.all()
        self._tour_index = 0
        self._show_tour_step()

    def _show_tour_step(self) -> None:
        if not self._tour or not 0 <= self._tour_index < len(self._tour):
            self.skip_tour()
            return
        guide = self._tour[self._tour_index]
        self._tour_switching = True
        try:
            if self.window.stack.currentIndex() != guide.page:
                self.window.show_page(guide.page)
        finally:
            self._tour_switching = False

        def reveal():
            target = self._resolve_target(guide.target)
            decision = AssistantDecision(
                guide.assistant_state,
                message(guide.message_key),
                50 + guide.priority,
                target,
                guide.id,
                guide.preferred_position,
                guide.dismissible,
                0,
                guide.page,
            )
            self.show_decision(decision, tour=True)

        QTimer.singleShot(90, reveal)

    def next_step(self) -> None:
        if self._tour_index + 1 < len(self._tour):
            self._tour_index += 1
            self._show_tour_step()
        else:
            self.skip_tour()

    def previous_step(self) -> None:
        if self._tour_index > 0:
            self._tour_index -= 1
            self._show_tour_step()

    def skip_tour(self) -> None:
        self._tour = []
        self._tour_index = -1
        self._showing_tour = False
        self._last_key = ""
        self.evaluate(force=True)

    def notify(self, state: AssistantState | str, text: str, priority: int = 50, target: QWidget | None = None, timeout: int = 4500) -> None:
        try:
            normalized = state if isinstance(state, AssistantState) else AssistantState(str(state))
        except ValueError:
            normalized = AssistantState.NORMAL
        page = self.window.stack.currentIndex() if hasattr(self.window, "stack") else -1
        self.queue.push(AssistantDecision(normalized, str(text), int(priority), target, timeout=timeout, page_index=page))
        self.evaluate(force=True)
