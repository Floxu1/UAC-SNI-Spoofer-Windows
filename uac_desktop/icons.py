"""Code-native outline icons used by the desktop UI.

The module deliberately keeps the artwork in Python so packaged builds do not
need a loose icon directory.  Icons share a 24 px grid, rounded 1.8 px strokes,
and inherit the caller supplied colour.  ``PySide6.QtSvg`` is used when it is
available; a small QPainter fallback keeps controls usable in minimal builds.
"""

from __future__ import annotations

from html import escape
from typing import Final

from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPen, QPixmap

try:
    from PySide6.QtSvg import QSvgRenderer
except (ImportError, ModuleNotFoundError):
    QSvgRenderer = None




_ICONS: Final[dict[str, str]] = {
    "home": """
        <path d="M3 10.8 12 3l9 7.8"/>
        <path d="M5.5 9.2V21h13V9.2"/>
        <path d="M9.5 21v-6h5v6"/>
    """,
    "file-cog": """
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h6"/>
        <path d="M14 2v6h6"/><path d="m14 2 6 6v3"/>
        <circle cx="17" cy="17" r="2.4"/>
        <path d="M17 12.7v1.1M17 20.2v1.1M12.7 17h1.1M20.2 17h1.1M14 14l.8.8M19.2 19.2l.8.8M20 14l-.8.8M14.8 19.2l-.8.8"/>
    """,
    "flask": """
        <path d="M9 2h6M10 2v6.2l-5.4 9.2A3 3 0 0 0 7.2 22h9.6a3 3 0 0 0 2.6-4.6L14 8.2V2"/>
        <path d="M7.2 16h9.6"/><path d="M9.4 13h5.2"/>
    """,
    "activity": """
        <path d="M2 12h4l2.2-6 4 12 2.3-6H22"/>
    """,
    "shield": """
        <path d="M12 2.5 20 6v5.5c0 5-3.3 8.3-8 10-4.7-1.7-8-5-8-10V6l8-3.5Z"/>
        <path d="m8.5 12 2.2 2.2 4.8-5"/>
    """,
    "wrench": """
        <path d="M14.6 6.3a4.5 4.5 0 0 0-5.8 5.8L3 17.9A2.2 2.2 0 1 0 6.1 21l5.8-5.8a4.5 4.5 0 0 0 5.8-5.8l-2.8 2.8-3.1-.9-.9-3.1 2.8-2.8Z"/>
    """,
    "headphones": """
        <path d="M4 14v-2a8 8 0 0 1 16 0v2"/>
        <path d="M4 14h3v6H5a1 1 0 0 1-1-1v-5ZM20 14h-3v6h2a1 1 0 0 0 1-1v-5Z"/>
    """,
    "settings": """
        <circle cx="12" cy="12" r="3"/>
        <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1A1.7 1.7 0 0 0 9 4.6a1.7 1.7 0 0 0 1-1.6v-.2h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z"/>
    """,
    "folder": """
        <path d="M3 6a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6Z"/>
    """,
    "globe": """
        <circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>
    """,
    "lock": """
        <rect x="5" y="10" width="14" height="11" rx="2"/>
        <path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/>
    """,
    "upload": """
        <path d="M12 16V4M7 9l5-5 5 5"/><path d="M5 20h14"/>
    """,
    "download": """
        <path d="M12 4v12M7 11l5 5 5-5"/><path d="M5 20h14"/>
    """,
    "map-pin": """
        <path d="M20 10c0 5.5-8 12-8 12S4 15.5 4 10a8 8 0 1 1 16 0Z"/><circle cx="12" cy="10" r="2.5"/>
    """,
    "wifi": """
        <path d="M2.5 8.8a15 15 0 0 1 19 0M5.8 12.2a10 10 0 0 1 12.4 0M9.2 15.6a5 5 0 0 1 5.6 0"/>
        <circle cx="12" cy="19" r="1" fill="CURRENT" stroke="none"/>
    """,
    "server": """
        <rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/>
        <path d="M7 6.5h.01M7 17.5h.01M11 6.5h7M11 17.5h7"/>
    """,
    "zap": """
        <path d="M13 2 4 14h7l-1 8 9-12h-7l1-8Z"/>
    """,
    "play": """
        <path d="m8 5 11 7-11 7V5Z"/>
    """,
    "power": """
        <path d="M12 2v10"/><path d="M6.3 5.7a8 8 0 1 0 11.4 0"/>
    """,
    "route": """
        <circle cx="5" cy="18" r="2"/><circle cx="19" cy="6" r="2"/>
        <path d="M7 18h3a3 3 0 0 0 3-3v-6a3 3 0 0 1 3-3h1M10 10 7 7l3-3"/>
    """,
    "gauge": """
        <path d="M4.2 19a9 9 0 1 1 15.6 0"/><path d="m12 13 4-4"/>
        <path d="M6.7 16.5h.01M5.2 12h.01M7.5 7.8h.01M12 6h.01M16.5 7.8h.01M18.8 12h.01"/>
    """,
    "sliders": """
        <path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3"/>
        <path d="M1 14h6M9 8h6M17 16h6"/>
    """,
    "chevron-right": """<path d="m9 18 6-6-6-6"/>""",
    "chevron-left": """<path d="m15 18-6-6 6-6"/>""",
    "search": """<circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/>""",
    "trash": """
        <path d="M3 6h18M8 6V3h8v3M6 6l1 15h10l1-15M10 10v7M14 10v7"/>
    """,
    "edit": """
        <path d="M12 20H5a1 1 0 0 1-1-1v-7"/><path d="m14.5 4.5 5 5L10 19l-5 1 1-5 9.5-9.5Z"/><path d="m13 7 4 4"/>
    """,
    "plus": """<path d="M12 5v14M5 12h14"/>""",
    "copy": """
        <rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3"/>
    """,
    "check-circle": """
        <circle cx="12" cy="12" r="9"/><path d="m8 12 2.7 2.7L16.5 9"/>
    """,
    "alert": """
        <path d="M10.3 3.8 2.4 18a2 2 0 0 0 1.8 3h15.6a2 2 0 0 0 1.8-3L13.7 3.8a2 2 0 0 0-3.4 0Z"/>
        <path d="M12 9v4M12 17h.01"/>
    """,
    "x-circle": """
        <circle cx="12" cy="12" r="9"/><path d="m9 9 6 6M15 9l-6 6"/>
    """,
    "loader": """
        <path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1"/>
    """,
    "terminal": """
        <rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M13 15h4"/>
    """,
    "database": """
        <ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v7c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12v7c0 1.7 3.6 3 8 3s8-1.3 8-3v-7"/>
    """,
    "network": """
        <rect x="9" y="2" width="6" height="5" rx="1"/><rect x="2" y="17" width="6" height="5" rx="1"/><rect x="16" y="17" width="6" height="5" rx="1"/>
        <path d="M12 7v5M5 17v-3h14v3"/>
    """,
    "radio": """
        <circle cx="12" cy="12" r="2"/><circle cx="12" cy="12" r="6"/><path d="M4.2 4.2a11 11 0 0 0 0 15.6M19.8 4.2a11 11 0 0 1 0 15.6"/>
    """,
    "refresh": """
        <path d="M20 7v5h-5M4 17v-5h5"/><path d="M6.1 8a7 7 0 0 1 11.7-2.2L20 8M4 16l2.2 2.2A7 7 0 0 0 17.9 16"/>
    """,
    "pause": """<path d="M8 5v14M16 5v14"/>""",
    "external-link": """
        <path d="M14 4h6v6M20 4l-9 9"/><path d="M18 13v6a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h6"/>
    """,
    "star": """<path d="m12 2.5 2.9 5.9 6.5.9-4.7 4.6 1.1 6.5-5.8-3.1-5.8 3.1 1.1-6.5-4.7-4.6 6.5-.9L12 2.5Z"/>""",
    "eye": """<path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.5"/>""",
    "info": """<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7h.01"/>""",
    "clock": """<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>""",
    "filter": """<path d="M3 5h18l-7 8v6l-4 2v-8L3 5Z"/>""",
    "undo": """<path d="M9 7 4 12l5 5M5 12h8a6 6 0 0 1 6 6v1"/>""",
    "sparkles": """<path d="m12 3 1.2 3.8L17 8l-3.8 1.2L12 13l-1.2-3.8L7 8l3.8-1.2L12 3ZM19 14l.8 2.2L22 17l-2.2.8L19 20l-.8-2.2L16 17l2.2-.8L19 14ZM5 13l.8 2.2L8 16l-2.2.8L5 19l-.8-2.2L2 16l2.2-.8L5 13Z"/>""",
}


_ALIASES: Final[dict[str, str]] = {
    "config": "file-cog",
    "configs": "file-cog",
    "lab": "flask",
    "logs": "activity",
    "app-bypass": "shield",
    "tools": "wrench",
    "support": "headphones",
    "latency": "gauge",
    "location": "map-pin",
    "save": "check-circle",
    "cancel": "x-circle",
    "scan": "search",
    "status": "radio",
}


def available_icons() -> tuple[str, ...]:
    """Return the stable, sorted icon names accepted by :func:`icon`."""

    return tuple(sorted(set(_ICONS) | set(_ALIASES)))


def _normalise(name: str) -> str:
    key = str(name or "").strip().lower().replace("_", "-").replace(" ", "-")
    return _ALIASES.get(key, key)


def _colour(value: str | QColor) -> QColor:
    colour = QColor(value)
    if not colour.isValid():
        colour = QColor("#9fb4d8")
    return colour


def _svg(name: str, colour: QColor) -> bytes:
    body = _ICONS.get(name)
    if body is None:
        body = _ICONS["alert"]
    rgb = escape(colour.name(QColor.NameFormat.HexRgb), quote=True)
    opacity = max(0.0, min(1.0, colour.alphaF()))
    body = body.replace("CURRENT", rgb)
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" '
        'viewBox="0 0 24 24" fill="none" '
        f'stroke="{rgb}" stroke-opacity="{opacity:.3f}" stroke-width="1.8" '
        'stroke-linecap="round" stroke-linejoin="round">'
        f"{body}</svg>"
    ).encode("utf-8")


def _fallback_pixmap(name: str, colour: QColor, size: int) -> QPixmap:
    """Draw a recognisable fallback when QtSvg is not installed."""

    result = QPixmap(size, size)
    result.fill(Qt.GlobalColor.transparent)
    painter = QPainter(result)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    pen = QPen(colour, max(1.25, size / 13.0))
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    inset = max(2.0, size * 0.12)
    painter.drawRoundedRect(QRectF(inset, inset, size - 2 * inset, size - 2 * inset), size * 0.2, size * 0.2)
    painter.setFont(QFont("Segoe UI", max(7, int(size * 0.34)), QFont.Weight.DemiBold))
    painter.drawText(result.rect(), Qt.AlignmentFlag.AlignCenter, (name[:1] or "?").upper())
    painter.end()
    return result


def pixmap(name: str, color: str = "#9fb4d8", size: int = 22) -> QPixmap:
    """Render *name* as a transparent square :class:`QPixmap`.

    Unknown names intentionally render the ``alert`` icon; a missing icon is
    therefore visible during development instead of silently producing an
    empty button.
    """

    icon_size = max(8, min(512, int(size)))
    colour = _colour(color)
    key = _normalise(name)
    if QSvgRenderer is None:
        return _fallback_pixmap(key, colour, icon_size)

    result = QPixmap(icon_size, icon_size)
    result.fill(Qt.GlobalColor.transparent)
    renderer = QSvgRenderer(QByteArray(_svg(key, colour)))
    if not renderer.isValid():
        return _fallback_pixmap(key, colour, icon_size)
    painter = QPainter(result)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    renderer.render(painter, QRectF(0, 0, icon_size, icon_size))
    painter.end()
    return result


def icon(name: str, color: str = "#9fb4d8", size: int = 22) -> QIcon:
    """Return a consistently styled :class:`QIcon` for buttons and labels."""

    return QIcon(pixmap(name, color, size))


__all__ = ["available_icons", "icon", "pixmap"]
