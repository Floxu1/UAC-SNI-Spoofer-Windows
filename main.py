from __future__ import annotations

# --- UAC-TOR-RELAUNCH-WAIT-START ---
def _uac_wait_relaunch_parent() -> None:
    import ctypes as _ct
    import os as _os
    import tempfile as _tf
    import time as _tm
    from pathlib import Path as _P

    marker = _P(_tf.gettempdir()) / "uac_spoofer_relaunch.pid"
    if not marker.is_file():
        return
    try:
        raw = marker.read_text(encoding="utf-8").strip()
        pid_s, _, ts_s = raw.partition(":")
        old_pid = int(pid_s)
        ts = float(ts_s or 0)
        if old_pid == _os.getpid():
            return
        if abs(_tm.time() - ts) <= 30.0 and _os.name == "nt":
            handle = _ct.windll.kernel32.OpenProcess(0x00100000, False, old_pid)
            if handle:
                try:
                    _ct.windll.kernel32.WaitForSingleObject(handle, 12000)
                finally:
                    _ct.windll.kernel32.CloseHandle(handle)
                _tm.sleep(0.2)
    except Exception:
        pass
    finally:
        try:
            marker.unlink(missing_ok=True)
        except OSError:
            pass


_uac_wait_relaunch_parent()
# --- UAC-TOR-RELAUNCH-WAIT-END ---


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
    cleanup_ok = True
    try:
        code = int(app.exec())
    finally:


        try:
            window.shutdown()
        except Exception:
            cleanup_ok = False
        try:
            window.engine.stop(notify=False)
        except Exception:
            cleanup_ok = False
        try:
            gateway = getattr(window.engine, "gateway", None)
            if gateway is not None:
                cleanup_ok = gateway.recover(force=True) is not False and cleanup_ok
        except Exception:
            cleanup_ok = False
        try:
            from uac_desktop.process_win import cleanup_bin_helpers
            cleanup_bin_helpers()
        except Exception:
            cleanup_ok = False
        try:
            WindowsProxy.recover_stale(expected_pid=int(owner["pid"]),
                                       expected_create_time=float(owner["create_time"]))
        except Exception:
            cleanup_ok = False

    update = getattr(window, "_prepared_update", None)
    if update is not None:
        from uac_desktop.updater import discard_update, launch_worker

        try:
            if (not cleanup_ok or not window._update_shutdown_ok or window._engine_busy()
                    or window.engine.system_proxy.has_pending_restore):
                raise RuntimeError("Connection or Windows proxy cleanup is still pending")
            launch_worker(update)
        except Exception as error:
            discard_update(update)
            ctypes.windll.user32.MessageBoxW(None, f"Update cancelled.\n{error}", "UAC Spoofer Desktop", 0x30)
    return code


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
