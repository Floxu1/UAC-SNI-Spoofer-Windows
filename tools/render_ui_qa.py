#!/usr/bin/env python3
"""Render deterministic, offscreen visual-QA screenshots of the desktop UI.

The harness deliberately isolates ``APPDATA`` before importing the app. This
keeps screenshots away from the user's live profiles/settings and guarantees
that constructing ``MainWindow`` cannot mutate production data. It never
starts a connection, scan, probe, or any other backend action.

Examples::

    python tools/render_ui_qa.py
    python tools/render_ui_qa.py --pages home,sni --sizes desktop=1440x900
    python tools/render_ui_qa.py --languages en --output-dir qa_artifacts/en
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import shutil
import sys
import time
from typing import Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = PROJECT_ROOT / "qa_artifacts"

# These must be set before importing either PySide6 or uac_desktop. In
# particular, uac_desktop.paths resolves DATA_DIR at import time.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QT_OPENGL", "software")
os.environ.setdefault("QSG_RHI_BACKEND", "software")


PAGE_NAMES = ("home", "configs", "sni", "logs", "bypass", "tools", "support")
DEFAULT_SIZES = {"desktop": (1440, 900), "compact": (1120, 760)}


def _csv(value: str) -> list[str]:
    return [part.strip().lower() for part in value.split(",") if part.strip()]


def _parse_sizes(value: str) -> dict[str, tuple[int, int]]:
    sizes: dict[str, tuple[int, int]] = {}
    for item in value.split(","):
        item = item.strip().lower()
        if not item:
            continue
        if "=" in item:
            name, dimensions = item.split("=", 1)
        else:
            name, dimensions = item, item
        try:
            width_text, height_text = dimensions.split("x", 1)
            width, height = int(width_text), int(height_text)
        except (TypeError, ValueError) as exc:
            raise argparse.ArgumentTypeError(
                f"Invalid size {item!r}; expected name=WIDTHxHEIGHT"
            ) from exc
        if width < 800 or height < 600:
            raise argparse.ArgumentTypeError(
                f"Viewport {width}x{height} is too small for desktop QA (minimum 800x600)"
            )
        sizes[name.strip() or f"{width}x{height}"] = (width, height)
    if not sizes:
        raise argparse.ArgumentTypeError("At least one viewport size is required")
    return sizes


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render UAC Spoofer Desktop pages to PNG using Qt's offscreen platform."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Screenshot/report directory (default: %(default)s)",
    )
    parser.add_argument(
        "--languages",
        default="en,fa",
        help="Comma-separated UI languages: en,fa (default: %(default)s)",
    )
    parser.add_argument(
        "--pages",
        default=",".join(PAGE_NAMES),
        help="Comma-separated pages or 'all' (default: all pages)",
    )
    parser.add_argument(
        "--sizes",
        type=_parse_sizes,
        default=DEFAULT_SIZES,
        help="Comma-separated name=WIDTHxHEIGHT viewports",
    )
    parser.add_argument(
        "--settle-ms",
        type=int,
        default=350,
        help="Event-processing delay before each capture (default: %(default)s)",
    )
    parser.add_argument(
        "--clean",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Remove prior PNG/report artifacts before rendering (default: true)",
    )
    args = parser.parse_args(argv)

    languages = _csv(args.languages)
    invalid_languages = sorted(set(languages) - {"en", "fa"})
    if not languages or invalid_languages:
        parser.error(f"--languages accepts en/fa; invalid: {', '.join(invalid_languages) or 'empty'}")
    args.languages = languages

    pages = _csv(args.pages)
    if pages == ["all"]:
        pages = list(PAGE_NAMES)
    invalid_pages = sorted(set(pages) - set(PAGE_NAMES))
    if not pages or invalid_pages:
        parser.error(f"Unknown page(s): {', '.join(invalid_pages) or 'empty'}")
    # Preserve the user's order while dropping duplicates.
    args.pages = list(dict.fromkeys(pages))
    args.settle_ms = max(0, min(args.settle_ms, 5_000))
    return args


def _process_events(app, milliseconds: int) -> None:
    """Pump Qt events for a bounded interval without entering app.exec()."""
    from PySide6.QtCore import QEventLoop

    deadline = time.monotonic() + milliseconds / 1_000
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        app.processEvents(QEventLoop.AllEvents, max(1, min(25, int(remaining * 1_000))))
        time.sleep(min(0.01, remaining))
    app.processEvents(QEventLoop.AllEvents, 50)


def _load_fonts() -> None:
    from PySide6.QtGui import QFontDatabase

    fonts = PROJECT_ROOT / "assets" / "fonts"
    for name in ("Vazirmatn-Regular.ttf", "Vazirmatn-Bold.ttf"):
        path = fonts / name
        if path.exists():
            QFontDatabase.addApplicationFont(str(path))


def _clean_output(output: Path) -> None:
    for path in output.glob("*.png"):
        path.unlink()
    for name in ("qa-report.json", "index.html"):
        (output / name).unlink(missing_ok=True)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_gallery(output: Path, captures: Iterable[dict[str, object]]) -> None:
    cards = []
    for capture in captures:
        filename = html.escape(str(capture["file"]))
        label = html.escape(
            f'{capture["language"].upper()} · {capture["viewport"]} · {capture["page"]}'
        )
        cards.append(
            f'<figure><a href="{filename}"><img loading="lazy" src="{filename}" '
            f'alt="{label}"></a><figcaption>{label}</figcaption></figure>'
        )
    document = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>UAC Spoofer Desktop - Visual QA</title>
<style>
:root{color-scheme:dark;font-family:Segoe UI,sans-serif;background:#050d18;color:#e8f6ff}
body{margin:0;padding:24px}h1{font-size:24px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(360px,1fr));gap:18px}
figure{margin:0;padding:10px;border:1px solid #173652;border-radius:12px;background:#091827}
img{display:block;width:100%;height:auto;border-radius:7px;background:#06111f}
figcaption{padding:9px 2px 1px;color:#9cb6ca;font-size:13px}
</style></head><body><h1>UAC Spoofer Desktop - Visual QA</h1><div class="grid">"""
    document += "".join(cards)
    document += "</div></body></html>"
    (output / "index.html").write_text(document, encoding="utf-8")


def render(args: argparse.Namespace) -> int:
    output = args.output_dir.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    if args.clean:
        _clean_output(output)

    # A separate APPDATA root prevents Storage migrations/default-profile seeds
    # from touching the real desktop app. Re-create it for reproducible runs.
    sandbox_appdata = output / "_sandbox_appdata"
    if args.clean:
        shutil.rmtree(sandbox_appdata, ignore_errors=True)
    sandbox_appdata.mkdir(parents=True, exist_ok=True)
    os.environ["APPDATA"] = str(sandbox_appdata)

    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))

    from PySide6.QtCore import Qt, qVersion
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import QApplication
    from uac_desktop.ui import MainWindow, STYLE

    app = QApplication.instance() or QApplication(["render-ui-qa", "-platform", "offscreen"])
    app.setApplicationName("UAC Spoofer Desktop Visual QA")
    app.setOrganizationName("UAC-QA")
    _load_fonts()
    app.setFont(QFont("Vazirmatn", 10))
    app.setStyleSheet(STYLE)

    window = MainWindow()
    # The harness does not invoke closeEvent/shutdown: no engine action was
    # started, so hiding/deleting the widget is the cleanest frontend-only exit.
    window.setAttribute(Qt.WA_DontShowOnScreen, False)
    window.show()
    _process_events(app, max(args.settle_ms, 100))

    captures: list[dict[str, object]] = []
    failures: list[str] = []
    for language in args.languages:
        window.language = language
        window._apply_language()  # frontend-only; unlike toggle_language, does not persist
        for viewport, (width, height) in args.sizes.items():
            window.resize(width, height)
            _process_events(app, args.settle_ms)
            for page in args.pages:
                page_index = PAGE_NAMES.index(page)
                window.show_page(page_index)
                _process_events(app, args.settle_ms)

                filename = f"{language}-{viewport}-{page}.png"
                path = output / filename
                pixmap = window.grab()
                saved = not pixmap.isNull() and pixmap.save(str(path), "PNG")
                if not saved or not path.exists() or path.stat().st_size < 1_000:
                    failures.append(f"Capture failed or is suspiciously small: {filename}")
                    continue
                captures.append(
                    {
                        "file": filename,
                        "language": language,
                        "viewport": viewport,
                        "page": page,
                        "requested_size": [width, height],
                        "image_size": [pixmap.width(), pixmap.height()],
                        "bytes": path.stat().st_size,
                        "sha256": _sha256(path),
                    }
                )

    window.hide()
    window.deleteLater()
    _process_events(app, 50)

    report = {
        "ok": not failures,
        "qt_platform": os.environ.get("QT_QPA_PLATFORM", ""),
        "qt_version": qVersion(),
        "project_root": str(PROJECT_ROOT),
        "isolated_appdata": str(sandbox_appdata),
        "capture_count": len(captures),
        "failures": failures,
        "captures": captures,
    }
    (output / "qa-report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    _write_gallery(output, captures)

    print(f"Rendered {len(captures)} screenshot(s) to {output}")
    print(f"Report: {output / 'qa-report.json'}")
    print(f"Gallery: {output / 'index.html'}")
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    return render(_parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
