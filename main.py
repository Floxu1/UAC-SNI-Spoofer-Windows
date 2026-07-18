from __future__ import annotations

import os
import subprocess
import sys
import ctypes

from uac_desktop.engine import WindowsProxy


_INSTANCE_MUTEX = None


def is_admin() -> bool:
    if sys.platform != "win32":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    """WinDivert requires elevation; keep source and packaged launches consistent."""
    if sys.platform != "win32" or is_admin():
        return False
    if getattr(sys, "frozen", False):
        executable = sys.executable
        arguments = subprocess.list2cmdline(sys.argv[1:])
    else:
        executable = sys.executable
        arguments = subprocess.list2cmdline([os.path.abspath(__file__), *sys.argv[1:]])
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, arguments, os.getcwd(), 1)
    if int(result) <= 32:
        raise RuntimeError(f"Administrator relaunch failed ({result})")
    return True


def acquire_single_instance() -> bool:
    global _INSTANCE_MUTEX
    if sys.platform != "win32":
        return True
    kernel32 = ctypes.windll.kernel32
    _INSTANCE_MUTEX = kernel32.CreateMutexW(None, False, "Local\\UAC-Spoofer-Desktop-v1")
    return bool(_INSTANCE_MUTEX) and kernel32.GetLastError() != 183


def proxy_watchdog_mode(arguments: list[str]) -> int | None:
    """Handle the detached proxy-restorer before elevation or Qt startup."""
    if not arguments or arguments[0] != "--proxy-watchdog":
        return None
    if len(arguments) != 4:
        return 2
    try:
        parent_pid = int(arguments[1])
        parent_create_time = float(arguments[2])
        token = str(arguments[3])
        if parent_pid <= 0 or parent_create_time <= 0 or not token:
            return 2
    except (TypeError, ValueError):
        return 2
    return WindowsProxy.run_watchdog(parent_pid, parent_create_time, token)


def run_event_loop(app, window) -> int:
    """Guarantee a final in-process restore; the watchdog is the hard-kill fallback."""
    owner = WindowsProxy.process_identity()
    try:
        return int(app.exec())
    finally:
        # Qt may already have called shutdown via aboutToQuit.  Every operation
        # remains idempotent and later steps still run if an earlier one fails.
        try:
            window.shutdown()
        except Exception:
            pass
        try:
            window.engine.stop(notify=False)
        except Exception:
            pass
        try:
            WindowsProxy.recover_stale(expected_pid=int(owner["pid"]),
                                       expected_create_time=float(owner["create_time"]))
        except Exception:
            # The detached owner/token watchdog retries once this process exits.
            pass


def main() -> int:
    watchdog_result = proxy_watchdog_mode(sys.argv[1:])
    if watchdog_result is not None:
        return watchdog_result
    # HKCU proxy restoration does not require elevation.  Recover before the
    # UAC prompt so declining elevation cannot leave a crashed session's proxy
    # active.  Owner checks protect a currently running app instance; the
    # post-mutex recovery below remains as an idempotent elevated retry.
    try:
        WindowsProxy.recover_stale()
    except Exception:
        pass
    if relaunch_as_admin():
        return 0
    # Keep the detached watchdog lightweight: Qt and the full UI are imported
    # only for the actual foreground application path.
    from PySide6.QtGui import QFont, QFontDatabase, QIcon
    from PySide6.QtWidgets import QApplication
    from uac_desktop.paths import ASSETS
    from uac_desktop.ui import MainWindow, STYLE

    os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")
    app = QApplication(sys.argv)
    app.setApplicationName("UAC Spoofer Desktop")
    app.setOrganizationName("UAC")
    if not acquire_single_instance():
        from PySide6.QtWidgets import QMessageBox
        QMessageBox.information(None, "UAC Spoofer Desktop", "UAC Spoofer is already running.")
        return 0
    WindowsProxy.recover_stale()
    for font_file in ("Vazirmatn-Regular.ttf", "Vazirmatn-Bold.ttf"):
        QFontDatabase.addApplicationFont(str(ASSETS / "fonts" / font_file))
    app.setFont(QFont("Vazirmatn", 10))
    icon = ASSETS / "icon.png"
    if icon.exists():
        app.setWindowIcon(QIcon(str(icon)))
    app.setStyleSheet(STYLE)
    window = MainWindow()
    app.aboutToQuit.connect(window.shutdown)
    window.show()
    return run_event_loop(app, window)


if __name__ == "__main__":
    raise SystemExit(main())
