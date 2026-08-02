from __future__ import annotations

import os
import subprocess
import sys
import ctypes

os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")

from uac_desktop.engine import WindowsProxy
from uac_desktop.gateway import GatewayManager


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


def gateway_watchdog_mode(arguments: list[str]) -> int | None:
    return GatewayManager.watchdog_mode(arguments)


def bootstrap_portable_npcap() -> bool:
    if sys.platform != "win32" or not getattr(sys, "frozen", False):
        return True
    from uac_desktop.npcap import ensure_npcap

    result = ensure_npcap()
    if result.available:
        return True
    message = (
        "Npcap setup was not completed.\n\n"
        "Mobile Gateway needs Npcap. Restart the app and complete the "
        "official Npcap installer when it opens.\n\n"
        f"Details: {result.detail}"
    )
    ctypes.windll.user32.MessageBoxW(
        None,
        message,
        "UAC Spoofer Desktop",
        0x30,
    )
    return False


def run_event_loop(app, window) -> int:
    """Guarantee a final in-process restore; the watchdog is the hard-kill fallback."""
    owner = WindowsProxy.process_identity()
    try:
        return int(app.exec())
    finally:


        try:
            window.shutdown()
        except Exception:
            pass
        try:
            window.engine.stop(notify=False)
        except Exception:
            pass
        try:
            gateway = getattr(window.engine, "gateway", None)
            if gateway is not None:
                gateway.recover(force=True)
        except Exception:
            pass
        try:
            WindowsProxy.recover_stale(expected_pid=int(owner["pid"]),
                                       expected_create_time=float(owner["create_time"]))
        except Exception:

            pass


def main() -> int:
    gateway_watchdog_result = gateway_watchdog_mode(sys.argv[1:])
    if gateway_watchdog_result is not None:
        return gateway_watchdog_result
    watchdog_result = proxy_watchdog_mode(sys.argv[1:])
    if watchdog_result is not None:
        return watchdog_result




    try:
        WindowsProxy.recover_stale()
    except Exception:
        pass
    if relaunch_as_admin():
        return 0
    bootstrap_portable_npcap()
    try:
        GatewayManager().recover()
    except Exception:
        pass


    from PySide6.QtGui import QFont, QFontDatabase, QIcon
    from PySide6.QtWidgets import QApplication
    from uac_desktop.paths import ASSETS
    from uac_desktop.ui import MainWindow, STYLE

    app = QApplication(sys.argv)
    app.setApplicationName("UAC Spoofer Desktop")
    app.setOrganizationName("UAC")
    if not acquire_single_instance():
        from PySide6.QtWidgets import QMessageBox
        QMessageBox.information(None, "UAC Spoofer Desktop", "UAC Spoofer is already running.")
        return 0
    WindowsProxy.recover_stale()
    try:
        GatewayManager().recover()
    except Exception:
        pass
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
