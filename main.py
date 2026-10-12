from __future__ import annotations

import os
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





def acquire_single_instance() -> bool:
    global _INSTANCE_MUTEX
    if sys.platform != "win32":
        return True
    kernel32 = ctypes.windll.kernel32
    _INSTANCE_MUTEX = kernel32.CreateMutexW(None, False, "Local\\UAC-Spoofer-Desktop-v1")
    return bool(_INSTANCE_MUTEX) and kernel32.GetLastError() != 183




def gateway_watchdog_mode(arguments: list[str]) -> int | None:
    return GatewayManager.watchdog_mode(arguments)




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
            from uac_desktop.process_win import cleanup_bin_helpers
            cleanup_bin_helpers()
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



    try:
        WindowsProxy.recover_stale()
    except Exception:
        pass
    try:
        GatewayManager().recover()
    except Exception:
        pass

    # One-time 1.1.1 data reset: after proxy/gateway were restored from the OLD
    # owner files, before anything loads settings/profiles.
    try:
        from uac_desktop import data_reset
        data_reset.run()
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
    from uac_desktop import fonts as ui_fonts
    ui_fonts.load_fonts()
    ui_fonts.apply_app_font(app, "en")
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
