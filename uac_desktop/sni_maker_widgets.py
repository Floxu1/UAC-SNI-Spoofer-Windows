from __future__ import annotations

import dataclasses
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import IntEnum
from functools import lru_cache
from pathlib import Path
from typing import Any

from PySide6.QtCore import (
    QAbstractTableModel,
    QMimeData,
    QModelIndex,
    QPointF,
    QRectF,
    QSize,
    QSortFilterProxyModel,
    Qt,
    Signal,
)
from PySide6.QtGui import (
    QBrush,
    QColor,
    QDragEnterEvent,
    QDragLeaveEvent,
    QDropEvent,
    QFont,
    QIcon,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QListView,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
)

from .sni_maker import ISO2_CODES


def normalize_country_code(value: object) -> str:
    code = str(value or "").strip().upper()
    return code if code in ISO2_CODES else "XX"


@lru_cache(maxsize=512)
def _country_badge_icon_cached(code: str, width: int, height: int) -> QIcon:
    normalized = normalize_country_code(code)
    pixmap = QPixmap(max(18, width), max(14, height))
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    rect = QRectF(0.75, 0.75, pixmap.width() - 1.5, pixmap.height() - 1.5)
    path = QPainterPath()
    radius = max(3.0, min(rect.width(), rect.height()) * 0.22)
    path.addRoundedRect(rect, radius, radius)
    if normalized == "XX":
        gradient = QLinearGradient(rect.topLeft(), rect.bottomRight())
        gradient.setColorAt(0.0, QColor("#17364c"))
        gradient.setColorAt(1.0, QColor("#0b1f34"))
        painter.fillPath(path, gradient)
        painter.setPen(QPen(QColor("#67e8f9"), max(1.1, height / 16)))
        globe = rect.adjusted(width * 0.25, height * 0.16, -width * 0.25, -height * 0.16)
        painter.drawEllipse(globe)
        painter.drawLine(QPointF(globe.left(), globe.center().y()), QPointF(globe.right(), globe.center().y()))
        painter.drawArc(globe.adjusted(globe.width() * 0.25, 0, -globe.width() * 0.25, 0), 90 * 16, 180 * 16)
    else:
        painter.setClipPath(path)

        def fill(color, x=0.0, y=0.0, w=float(width), h=float(height)):
            painter.fillRect(QRectF(x, y, w, h), QColor(color))

        if normalized in {"AT", "DE", "NL"}:
            colors = {
                "AT": ("#ed2939", "#ffffff", "#ed2939"),
                "DE": ("#181818", "#dd0000", "#ffce00"),
                "NL": ("#ae1c28", "#ffffff", "#21468b"),
            }[normalized]
            band = height / 3
            for index, color in enumerate(colors):
                fill(color, 0, index * band, width, band + 0.5)
        elif normalized == "PL":
            fill("#ffffff")
            fill("#dc143c", 0, height / 2, width, height / 2)
        elif normalized == "FR":
            band = width / 3
            for index, color in enumerate(("#0055a4", "#ffffff", "#ef4135")):
                fill(color, index * band, 0, band + 0.5, height)
        elif normalized == "FI":
            fill("#ffffff")
            fill("#003580", width * 0.29, 0, width * 0.16, height)
            fill("#003580", 0, height * 0.42, width, height * 0.2)
        elif normalized == "JP":
            fill("#ffffff")
            painter.setBrush(QColor("#bc002d")); painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(QPointF(width / 2, height / 2), height * 0.29, height * 0.29)
        elif normalized == "CH":
            fill("#d52b1e")
            arm = min(width, height) * 0.2
            fill("#ffffff", width * 0.5 - arm * 0.5, height * 0.2, arm, height * 0.6)
            fill("#ffffff", width * 0.3, height * 0.5 - arm * 0.5, width * 0.4, arm)
        elif normalized == "SG":
            fill("#ffffff")
            fill("#ef3340", 0, 0, width, height / 2)
            painter.setPen(Qt.PenStyle.NoPen); painter.setBrush(QColor("#ffffff"))
            painter.drawEllipse(QPointF(width * 0.25, height * 0.25), height * 0.19, height * 0.19)
            painter.setBrush(QColor("#ef3340"))
            painter.drawEllipse(QPointF(width * 0.29, height * 0.25), height * 0.15, height * 0.15)
        elif normalized == "US":
            stripe_height = height / 13
            for index in range(13):
                fill("#b22234" if index % 2 == 0 else "#ffffff", 0, index * stripe_height, width, stripe_height + 0.3)
            fill("#3c3b6e", 0, 0, width * 0.42, stripe_height * 7)
            painter.setPen(QPen(QColor("#ffffff"), 1.1))
            for row in range(3):
                for column in range(3):
                    painter.drawPoint(QPointF(3 + column * 4, 3 + row * 3))
        else:
            seed = (ord(normalized[0]) - 64) * 29 + (ord(normalized[1]) - 64) * 47
            hue = seed % 360
            gradient = QLinearGradient(rect.topLeft(), rect.bottomRight())
            gradient.setColorAt(0.0, QColor.fromHsv(hue, 165, 185))
            gradient.setColorAt(1.0, QColor.fromHsv((hue + 34) % 360, 205, 104))
            painter.fillPath(path, gradient)
            font = QFont("Segoe UI", max(7, int(height * 0.43)), QFont.Weight.DemiBold)
            painter.setFont(font); painter.setPen(QColor("#ffffff"))
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, normalized)
        painter.setClipping(False)
    painter.setPen(QPen(QColor(255, 255, 255, 100), 1.0))
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.drawPath(path)
    painter.end()
    return QIcon(pixmap)


def country_badge_icon(code: object, width: int = 32, height: int = 22) -> QIcon:
    return QIcon(_country_badge_icon_cached(normalize_country_code(code), int(width), int(height)))


@lru_cache(maxsize=32)
def _status_icon(status: str, size: int = 14) -> QIcon:
    colors = {
        "healthy": "#23f5a9",
        "testing": "#36d3ff",
        "converting": "#a78bfa",
        "converted": "#67e8f9",
        "ready": "#67e8f9",
        "queued": "#7894b4",
        "skipped": "#fbbf24",
        "invalid": "#fb7185",
        "failed": "#fb7185",
    }
    color = QColor(colors.get(status, "#7894b4"))
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    painter.setPen(Qt.PenStyle.NoPen)
    halo = QColor(color)
    halo.setAlpha(48)
    painter.setBrush(halo)
    painter.drawEllipse(QRectF(0, 0, size, size))
    painter.setBrush(color)
    margin = max(3.0, size * 0.28)
    painter.drawEllipse(QRectF(margin, margin, size - margin * 2, size - margin * 2))
    painter.end()
    return QIcon(pixmap)


@dataclass(slots=True)
class MakerResult:
    key: str
    uri: str
    status: str = "queued"
    country_code: str = "XX"
    ping_ms: float | None = None
    checked: bool = False
    label: str = ""
    error: str = ""
    source_uri: str = ""

    @classmethod
    def from_value(cls, value: object, sequence: int = 0) -> "MakerResult":
        if isinstance(value, cls):
            result = dataclasses.replace(value)
        elif isinstance(value, Mapping):
            raw = dict(value)
            uri = str(raw.get("uri") or raw.get("config") or raw.get("source_uri") or "").strip()
            key = str(raw.get("key") or raw.get("id") or uri or f"row-{sequence}")
            ping = raw.get("ping_ms", raw.get("ping", raw.get("latency_ms")))
            try:
                ping_value = float(ping) if ping is not None and str(ping).strip() else None
            except (TypeError, ValueError):
                ping_value = None
            if ping_value is not None and (not math.isfinite(ping_value) or ping_value < 0):
                ping_value = None
            result = cls(
                key=key,
                uri=uri,
                status=str(raw.get("status") or raw.get("state") or "queued").strip().lower(),
                country_code=str(raw.get("country_code") or raw.get("country") or "XX"),
                ping_ms=ping_value,
                checked=bool(raw.get("checked", raw.get("selected", raw.get("marked", False)))),
                label=str(raw.get("label") or raw.get("name") or ""),
                error=str(raw.get("error") or raw.get("message") or ""),
                source_uri=str(raw.get("source_uri") or ""),
            )
        else:
            uri = str(value or "").strip()
            result = cls(key=uri or f"row-{sequence}", uri=uri)
        result.key = str(result.key or result.uri or f"row-{sequence}")
        result.uri = str(result.uri or "").strip()
        result.status = str(result.status or "queued").strip().lower()
        result.country_code = normalize_country_code(result.country_code)
        if result.ping_ms is not None:
            try:
                result.ping_ms = float(result.ping_ms)
            except (TypeError, ValueError):
                result.ping_ms = None
            if result.ping_ms is not None and (not math.isfinite(result.ping_ms) or result.ping_ms < 0):
                result.ping_ms = None
        return result

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


class MakerColumns(IntEnum):
    MARK = 0
    COUNTRY = 1
    STATUS = 2
    PING = 3
    URI = 4


class MakerRoles(IntEnum):
    KeyRole = int(Qt.ItemDataRole.UserRole) + 1
    UriRole = int(Qt.ItemDataRole.UserRole) + 2
    StatusRole = int(Qt.ItemDataRole.UserRole) + 3
    CountryRole = int(Qt.ItemDataRole.UserRole) + 4
    PingRole = int(Qt.ItemDataRole.UserRole) + 5
    CheckedRole = int(Qt.ItemDataRole.UserRole) + 6
    SearchRole = int(Qt.ItemDataRole.UserRole) + 7
    RawRole = int(Qt.ItemDataRole.UserRole) + 8
    SortRole = int(Qt.ItemDataRole.UserRole) + 9


class MakerResultsModel(QAbstractTableModel):
    summaryChanged = Signal(object)

    def __init__(self, rows: Iterable[object] | None = None, parent=None):
        super().__init__(parent)
        self._rows: list[MakerResult] = []
        self._key_rows: dict[str, int] = {}
        self._headers = ("", "Country", "Status", "Ping", "Configuration")
        self._status_labels: dict[str, str] = {}
        if rows:
            self.append_batch(rows)

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(MakerColumns)

    def headerData(self, section: int, orientation: Qt.Orientation, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return self._headers[section] if 0 <= section < len(self._headers) else None
        return section + 1

    def set_headers(self, headers: Iterable[object]) -> None:
        values = tuple(str(value) for value in headers)
        if len(values) != self.columnCount() or values == self._headers:
            return
        self._headers = values
        self.headerDataChanged.emit(
            Qt.Orientation.Horizontal, 0, self.columnCount() - 1
        )

    def set_status_labels(self, labels: Mapping[object, object]) -> None:
        values = {
            str(key).strip().lower(): str(value)
            for key, value in labels.items()
        }
        if values == self._status_labels:
            return
        self._status_labels = values
        if self.rowCount():
            self.dataChanged.emit(
                self.index(0, MakerColumns.STATUS),
                self.index(self.rowCount() - 1, MakerColumns.STATUS),
                [int(Qt.ItemDataRole.DisplayRole)],
            )

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self._rows):
            return None
        result = self._rows[index.row()]
        column = MakerColumns(index.column())
        if role == Qt.ItemDataRole.DisplayRole:
            if column == MakerColumns.COUNTRY:
                return result.country_code
            if column == MakerColumns.STATUS:
                return self._status_labels.get(
                    result.status, result.status.replace("_", " ").title()
                )
            if column == MakerColumns.PING:
                return f"{result.ping_ms:.0f} ms" if result.ping_ms is not None else "—"
            if column == MakerColumns.URI:
                return result.uri
            return ""
        if role == Qt.ItemDataRole.DecorationRole:
            if column == MakerColumns.COUNTRY:
                return country_badge_icon(result.country_code)
            if column == MakerColumns.STATUS:
                return _status_icon(result.status)
        if role == Qt.ItemDataRole.CheckStateRole and column == MakerColumns.MARK:
            return Qt.CheckState.Checked if result.checked else Qt.CheckState.Unchecked
        if role == Qt.ItemDataRole.TextAlignmentRole:
            if column in {MakerColumns.MARK, MakerColumns.COUNTRY, MakerColumns.STATUS, MakerColumns.PING}:
                return int(Qt.AlignmentFlag.AlignCenter)
            return int(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        if role == Qt.ItemDataRole.ForegroundRole:
            status_colors = {
                "healthy": "#45f3b4",
                "testing": "#62dcff",
                "converting": "#c4b5fd",
                "failed": "#ff8798",
                "invalid": "#ff8798",
                "skipped": "#ffd166",
            }
            if column == MakerColumns.STATUS:
                return QBrush(QColor(status_colors.get(result.status, "#afc5dc")))
            if column == MakerColumns.PING and result.ping_ms is not None:
                color = "#45f3b4" if result.ping_ms < 180 else "#ffd166" if result.ping_ms < 500 else "#ff8798"
                return QBrush(QColor(color))
        if role == Qt.ItemDataRole.ToolTipRole:
            details = [result.label, result.uri] if result.label else [result.uri]
            if result.error:
                details.append(result.error)
            return "\n".join(details)
        if role == MakerRoles.KeyRole:
            return result.key
        if role == MakerRoles.UriRole:
            return result.uri
        if role == MakerRoles.StatusRole:
            return result.status
        if role == MakerRoles.CountryRole:
            return result.country_code
        if role == MakerRoles.PingRole:
            return result.ping_ms
        if role == MakerRoles.CheckedRole:
            return result.checked
        if role == MakerRoles.SearchRole:
            return " ".join((result.key, result.uri, result.label, result.status, result.country_code, result.error)).lower()
        if role == MakerRoles.RawRole:
            return result.to_dict()
        if role == MakerRoles.SortRole:
            if column == MakerColumns.MARK:
                return 0 if result.checked else 1
            if column == MakerColumns.COUNTRY:
                return result.country_code
            if column == MakerColumns.STATUS:
                order = {
                    "healthy": 0,
                    "testing": 1,
                    "converting": 2,
                    "converted": 3,
                    "ready": 3,
                    "queued": 4,
                    "skipped": 5,
                    "invalid": 6,
                    "failed": 7,
                }
                return order.get(result.status, 8)
            if column == MakerColumns.PING:
                return result.ping_ms if result.ping_ms is not None else float("inf")
            return (result.label or result.uri).lower()
        return None

    def flags(self, index: QModelIndex):
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        flags = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if index.column() == MakerColumns.MARK:
            flags |= Qt.ItemFlag.ItemIsUserCheckable
        return flags

    def setData(self, index: QModelIndex, value: Any, role=Qt.ItemDataRole.EditRole) -> bool:
        if (
            not index.isValid()
            or index.column() != MakerColumns.MARK
            or role != Qt.ItemDataRole.CheckStateRole
            or not 0 <= index.row() < len(self._rows)
        ):
            return False
        raw_value = getattr(value, "value", value)
        checked = raw_value == Qt.CheckState.Checked.value
        if self._rows[index.row()].checked == checked:
            return False
        self._rows[index.row()].checked = checked
        self.dataChanged.emit(
            index,
            index,
            [int(Qt.ItemDataRole.CheckStateRole), int(MakerRoles.CheckedRole)],
        )
        self._emit_summary()
        return True

    def result_at(self, row: int) -> MakerResult | None:
        return self._rows[row] if 0 <= row < len(self._rows) else None

    def results(self) -> list[MakerResult]:
        return [dataclasses.replace(result) for result in self._rows]

    def row_for_key(self, key: object) -> int:
        return self._key_rows.get(str(key), -1)

    def append_batch(self, values: Iterable[object], deduplicate: bool = False) -> list[int]:
        pending: list[MakerResult] = []
        reserved = set(self._key_rows)
        for offset, value in enumerate(values):
            result = MakerResult.from_value(value, len(self._rows) + len(pending) + offset)
            base_key = result.key
            if base_key in reserved:
                if deduplicate:
                    continue
                suffix = 2
                while f"{base_key}~{suffix}" in reserved:
                    suffix += 1
                result.key = f"{base_key}~{suffix}"
            reserved.add(result.key)
            pending.append(result)
        if not pending:
            return []
        first = len(self._rows)
        last = first + len(pending) - 1
        self.beginInsertRows(QModelIndex(), first, last)
        self._rows.extend(pending)
        self.endInsertRows()
        for row in range(first, last + 1):
            self._key_rows[self._rows[row].key] = row
        self._emit_summary()
        return list(range(first, last + 1))

    batch_append = append_batch

    def update_batch(self, updates: Iterable[object]) -> int:
        touched: set[int] = set()
        for update in updates:
            if isinstance(update, tuple) and len(update) == 2:
                selector, changes = update
                raw = dict(changes) if isinstance(changes, Mapping) else {}
            elif isinstance(update, Mapping):
                raw = dict(update)
                selector = raw.pop("row", raw.pop("index", raw.get("key", raw.get("id", raw.get("uri")))))
            else:
                continue
            row = selector if isinstance(selector, int) else self.row_for_key(selector)
            if not isinstance(row, int) or not 0 <= row < len(self._rows):
                continue
            current = self._rows[row]
            aliases = {
                "id": "key",
                "config": "uri",
                "state": "status",
                "country": "country_code",
                "ping": "ping_ms",
                "latency_ms": "ping_ms",
                "selected": "checked",
                "marked": "checked",
                "name": "label",
                "message": "error",
            }
            for source_name, value in raw.items():
                name = aliases.get(source_name, source_name)
                if name in {"row", "index"} or not hasattr(current, name):
                    continue
                if name == "country_code":
                    value = normalize_country_code(value)
                elif name == "status":
                    value = str(value or "queued").strip().lower()
                elif name == "ping_ms":
                    try:
                        value = float(value) if value is not None and str(value).strip() else None
                    except (TypeError, ValueError):
                        value = None
                    if value is not None and (not math.isfinite(value) or value < 0):
                        value = None
                elif name == "checked":
                    value = bool(value)
                elif name in {"key", "uri", "label", "error", "source_uri"}:
                    value = str(value or "")
                setattr(current, name, value)
            touched.add(row)
        if not touched:
            return 0
        self._rebuild_indices()
        roles = [
            int(Qt.ItemDataRole.DisplayRole),
            int(Qt.ItemDataRole.DecorationRole),
            int(Qt.ItemDataRole.CheckStateRole),
            int(Qt.ItemDataRole.ForegroundRole),
            int(Qt.ItemDataRole.ToolTipRole),
            int(MakerRoles.KeyRole),
            int(MakerRoles.UriRole),
            int(MakerRoles.StatusRole),
            int(MakerRoles.CountryRole),
            int(MakerRoles.PingRole),
            int(MakerRoles.CheckedRole),
            int(MakerRoles.SearchRole),
            int(MakerRoles.RawRole),
            int(MakerRoles.SortRole),
        ]
        ordered = sorted(touched)
        start = previous = ordered[0]
        for row in ordered[1:] + [ordered[-1] + 2]:
            if row != previous + 1:
                self.dataChanged.emit(
                    self.index(start, 0),
                    self.index(previous, self.columnCount() - 1),
                    roles,
                )
                start = row
            previous = row
        self._emit_summary()
        return len(touched)

    batch_update = update_batch

    def set_all_checked(self, checked: bool, rows: Iterable[int] | None = None) -> int:
        candidates = range(len(self._rows)) if rows is None else rows
        touched = []
        for row in candidates:
            if 0 <= int(row) < len(self._rows) and self._rows[int(row)].checked != bool(checked):
                self._rows[int(row)].checked = bool(checked)
                touched.append(int(row))
        if touched:
            self.dataChanged.emit(
                self.index(min(touched), MakerColumns.MARK),
                self.index(max(touched), MakerColumns.MARK),
                [int(Qt.ItemDataRole.CheckStateRole), int(MakerRoles.CheckedRole)],
            )
            self._emit_summary()
        return len(touched)

    def checked_results(self) -> list[MakerResult]:
        return [dataclasses.replace(result) for result in self._rows if result.checked]

    def checked_uris(self) -> list[str]:
        return [result.uri for result in self._rows if result.checked and result.uri]

    def healthy_results(self, country_code: object = "") -> list[MakerResult]:
        code = normalize_country_code(country_code) if str(country_code or "").strip() else ""
        return [
            dataclasses.replace(result)
            for result in self._rows
            if result.status == "healthy" and (not code or result.country_code == code)
        ]

    def country_summary(self) -> dict[str, dict[str, int]]:
        summary: dict[str, dict[str, int]] = {}
        for result in self._rows:
            counts = summary.setdefault(result.country_code, {"total": 0, "healthy": 0, "testing": 0})
            counts["total"] += 1
            if result.status == "healthy":
                counts["healthy"] += 1
            elif result.status in {"testing", "converting"}:
                counts["testing"] += 1
        return summary

    def status_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for result in self._rows:
            counts[result.status] = counts.get(result.status, 0) + 1
        return counts

    def clear(self) -> None:
        if not self._rows:
            return
        self.beginResetModel()
        self._rows.clear()
        self._key_rows.clear()
        self.endResetModel()
        self._emit_summary()

    def _rebuild_indices(self) -> None:
        rebuilt: dict[str, int] = {}
        for row, result in enumerate(self._rows):
            key = result.key
            if key in rebuilt:
                suffix = 2
                while f"{key}~{suffix}" in rebuilt:
                    suffix += 1
                result.key = f"{key}~{suffix}"
            rebuilt[result.key] = row
        self._key_rows = rebuilt

    def _emit_summary(self) -> None:
        self.summaryChanged.emit(
            {
                "total": len(self._rows),
                "checked": sum(1 for result in self._rows if result.checked),
                "statuses": self.status_counts(),
                "countries": self.country_summary(),
            }
        )


class MakerFilterProxy(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._search = ""
        self._statuses: frozenset[str] = frozenset()
        self._country = ""
        self.setDynamicSortFilter(True)
        self.setSortCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

    def set_search(self, text: object) -> None:
        value = str(text or "").strip().casefold()
        if value != self._search:
            self._search = value
            self.invalidateFilter()

    set_search_text = set_search

    def set_statuses(self, statuses: str | Iterable[object] | None) -> None:
        if isinstance(statuses, str):
            values = {statuses}
        else:
            values = set(statuses or ())
        normalized = frozenset(
            str(value).strip().lower()
            for value in values
            if str(value).strip() and str(value).strip().lower() not in {"*", "all"}
        )
        if normalized != self._statuses:
            self._statuses = normalized
            self.invalidateFilter()

    set_status_filter = set_statuses

    def set_country(self, country_code: object) -> None:
        raw = str(country_code or "").strip().upper()
        value = "" if raw in {"", "*", "ALL"} else normalize_country_code(raw)
        if value != self._country:
            self._country = value
            self.invalidateFilter()

    set_country_filter = set_country

    def clear_filters(self) -> None:
        self._search = ""
        self._statuses = frozenset()
        self._country = ""
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        model = self.sourceModel()
        if model is None:
            return False
        index = model.index(source_row, 0, source_parent)
        if self._statuses:
            status = str(model.data(index, MakerRoles.StatusRole) or "").lower()
            if status not in self._statuses:
                return False
        if self._country:
            country = str(model.data(index, MakerRoles.CountryRole) or "").upper()
            if country != self._country:
                return False
        if self._search:
            haystack = str(model.data(index, MakerRoles.SearchRole) or "").casefold()
            if self._search not in haystack:
                return False
        return True

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        model = self.sourceModel()
        left_value = model.data(left, MakerRoles.SortRole)
        right_value = model.data(right, MakerRoles.SortRole)
        try:
            return left_value < right_value
        except TypeError:
            return str(left_value).casefold() < str(right_value).casefold()

    def visible_source_rows(self) -> list[int]:
        return [self.mapToSource(self.index(row, 0)).row() for row in range(self.rowCount())]


class ConfigDropEdit(QPlainTextEdit):
    payloadAdded = Signal(str, object)
    filesDropped = Signal(object)
    textDropped = Signal(str)
    configCountChanged = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._drag_active = False
        self.setAcceptDrops(True)
        self.setObjectName("sniMakerDropEdit")
        self.setPlaceholderText("Drop configuration files or paste configuration links here")
        self.setMinimumHeight(40)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.textChanged.connect(self._emit_count)
        self.setStyleSheet(
            """
            QPlainTextEdit#sniMakerDropEdit {
                background: rgba(4, 15, 31, 0.94);
                border: 1px dashed rgba(54, 211, 255, 0.52);
                border-radius: 10px;
                padding: 6px 9px;
                color: #d8e9f5;
                selection-background-color: #0b7c82;
                font-family: "Cascadia Mono", "Consolas";
                font-size: 12px;
            }
            QPlainTextEdit#sniMakerDropEdit[dragActive="true"] {
                background: rgba(7, 49, 65, 0.96);
                border: 2px solid #23f5e0;
            }
            """
        )

    def configuration_lines(self) -> list[str]:
        return [
            line.strip()
            for line in self.toPlainText().replace("\x00", "").splitlines()
            if line.strip() and not line.lstrip().startswith(("# ", "// "))
        ]

    def append_payload(self, text: object, sources: Iterable[object] = ()) -> bool:
        payload = str(text or "").replace("\x00", "").strip()
        if not payload:
            return False
        existing = self.toPlainText()
        self.setPlainText(f"{existing.rstrip()}\n{payload}".lstrip() if existing.strip() else payload)
        paths = [str(path) for path in sources]
        self.payloadAdded.emit(payload, paths)
        return True

    def paste_from_clipboard(self) -> bool:
        clipboard = QApplication.clipboard()
        payload = clipboard.text() if clipboard is not None else ""
        if not payload.strip():
            return False
        added = self.append_payload(payload)
        if added:
            self.textDropped.emit(payload)
        return added

    def ingest_mime_data(self, mime: QMimeData) -> tuple[str, list[str]]:
        paths: list[str] = []
        chunks: list[str] = []
        if mime.hasUrls():
            for url in mime.urls():
                if not url.isLocalFile():
                    continue
                path = Path(url.toLocalFile())
                if not path.is_file():
                    continue
                try:
                    raw = path.read_bytes()
                except OSError:
                    continue
                if len(raw) > 64 * 1024 * 1024:
                    continue
                chunks.append(raw.decode("utf-8-sig", errors="replace"))
                paths.append(str(path))
        if not chunks and mime.hasText():
            chunks.append(mime.text())
        payload = "\n".join(chunk.strip() for chunk in chunks if chunk.strip())
        if payload:
            self.append_payload(payload, paths)
            if paths:
                self.filesDropped.emit(paths)
            else:
                self.textDropped.emit(payload)
        return payload, paths

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        mime = event.mimeData()
        acceptable = mime.hasText() or any(url.isLocalFile() for url in mime.urls())
        if acceptable:
            event.acceptProposedAction()
            self._set_drag_active(True)
        else:
            event.ignore()

    def dragMoveEvent(self, event) -> None:
        event.acceptProposedAction()

    def dragLeaveEvent(self, event: QDragLeaveEvent) -> None:
        self._set_drag_active(False)
        event.accept()

    def dropEvent(self, event: QDropEvent) -> None:
        payload, _paths = self.ingest_mime_data(event.mimeData())
        self._set_drag_active(False)
        if payload:
            event.acceptProposedAction()
        else:
            event.ignore()

    def _set_drag_active(self, active: bool) -> None:
        self._drag_active = bool(active)
        self.setProperty("dragActive", self._drag_active)
        self.style().unpolish(self)
        self.style().polish(self)
        self.update()

    def _emit_count(self) -> None:
        self.configCountChanged.emit(len(self.configuration_lines()))


class CountryRail(QListWidget):
    countrySelected = Signal(str)

    CountryCodeRole = int(Qt.ItemDataRole.UserRole) + 1
    HealthyCountRole = int(Qt.ItemDataRole.UserRole) + 2
    TotalCountRole = int(Qt.ItemDataRole.UserRole) + 3
    TestingCountRole = int(Qt.ItemDataRole.UserRole) + 4

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("sniMakerCountryRail")
        self.setIconSize(QSize(32, 22))
        self.setSpacing(4)
        self.setFlow(QListView.Flow.LeftToRight)
        self.setWrapping(False)
        self.setResizeMode(QListView.ResizeMode.Adjust)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setMinimumHeight(62)
        self.setMaximumHeight(66)
        self.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self._healthy_label = "healthy"
        self._total_label = "total"
        self._live_label = "live"
        self.currentItemChanged.connect(self._selection_changed)
        self.setStyleSheet(
            """
            QListWidget#sniMakerCountryRail {
                background: transparent;
                border: 0;
                outline: 0;
                padding: 2px;
            }
            QListWidget#sniMakerCountryRail::item {
                min-height: 46px;
                background: rgba(8, 27, 51, 0.88);
                border: 1px solid rgba(68, 122, 162, 0.34);
                border-radius: 11px;
                padding: 7px 10px;
                margin: 2px;
                color: #c9dced;
            }
            QListWidget#sniMakerCountryRail::item:hover {
                background: rgba(11, 49, 70, 0.94);
                border-color: rgba(54, 211, 255, 0.52);
            }
            QListWidget#sniMakerCountryRail::item:selected {
                background: rgba(7, 85, 91, 0.92);
                border: 1px solid rgba(35, 245, 224, 0.82);
                color: #ffffff;
            }
            """
        )

    def set_country_counts(
        self,
        counts: Mapping[object, object],
        labels: Mapping[object, object] | None = None,
        selected: object | None = None,
        all_label: str = "All countries",
    ) -> None:
        labels = labels or {}
        old_selected = self.selected_country()
        wanted = str(selected).upper() if selected is not None else old_selected
        entries: list[tuple[str, str, int, int, int]] = []
        total_all = healthy_all = testing_all = 0
        for raw_code, raw_counts in counts.items():
            code = normalize_country_code(raw_code)
            if isinstance(raw_counts, Mapping):
                total = int(raw_counts.get("total", raw_counts.get("count", 0)) or 0)
                healthy = int(raw_counts.get("healthy", 0) or 0)
                testing = int(raw_counts.get("testing", 0) or 0)
            elif isinstance(raw_counts, (tuple, list)):
                healthy = int(raw_counts[0] if raw_counts else 0)
                total = int(raw_counts[1] if len(raw_counts) > 1 else healthy)
                testing = int(raw_counts[2] if len(raw_counts) > 2 else 0)
            else:
                total = healthy = int(raw_counts or 0)
                testing = 0
            label = str(labels.get(raw_code, labels.get(code, code)))
            entries.append((code, label, max(0, healthy), max(0, total), max(0, testing)))
            total_all += max(0, total)
            healthy_all += max(0, healthy)
            testing_all += max(0, testing)
        entries.sort(key=lambda entry: (entry[1].casefold(), entry[0]))
        self.blockSignals(True)
        self.clear()
        self._add_country_item("*", all_label, healthy_all, total_all, testing_all)
        for entry in entries:
            self._add_country_item(*entry)
        target = self.find_country(wanted)
        self.setCurrentItem(target or self.item(0))
        self.blockSignals(False)
        current = self.selected_country()
        if current != old_selected:
            self.countrySelected.emit(current)

    def set_metric_labels(self, healthy: str, total: str, live: str) -> None:
        self._healthy_label = str(healthy)
        self._total_label = str(total)
        self._live_label = str(live)

    def _add_country_item(self, code: str, label: str, healthy: int, total: int, testing: int) -> None:
        suffix = f"{healthy} {self._healthy_label}  ·  {total} {self._total_label}"
        if testing:
            suffix += f"  ·  {testing} {self._live_label}"
        item = QListWidgetItem(f"{label}\n{suffix}")
        item.setIcon(country_badge_icon(code))
        item.setData(self.CountryCodeRole, code)
        item.setData(self.HealthyCountRole, healthy)
        item.setData(self.TotalCountRole, total)
        item.setData(self.TestingCountRole, testing)
        item.setToolTip(f"{label} · {healthy}/{total}")
        item.setSizeHint(QSize(max(150, min(230, 108 + len(label) * 6)), 56))
        self.addItem(item)

    def selected_country(self) -> str:
        item = self.currentItem()
        return str(item.data(self.CountryCodeRole)) if item is not None else "*"

    def find_country(self, country_code: object) -> QListWidgetItem | None:
        raw = str(country_code or "*").upper()
        code = "*" if raw in {"", "*", "ALL"} else normalize_country_code(raw)
        for row in range(self.count()):
            item = self.item(row)
            if item.data(self.CountryCodeRole) == code:
                return item
        return None

    def select_country(self, country_code: object) -> bool:
        item = self.find_country(country_code)
        if item is None:
            return False
        self.setCurrentItem(item)
        return True

    def _selection_changed(self, current: QListWidgetItem | None, _previous: QListWidgetItem | None) -> None:
        if current is not None:
            self.countrySelected.emit(str(current.data(self.CountryCodeRole)))
