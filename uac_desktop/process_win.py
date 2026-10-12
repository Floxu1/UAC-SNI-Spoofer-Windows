"""Windows child-process helpers: job objects and process-tree kill."""
from __future__ import annotations

import atexit
import subprocess
import sys
from pathlib import Path

_HELPER_PIDS: set[int] = set()

if sys.platform != "win32":
    def kill_process_tree(pid: int) -> None:
        return

    def attach_kill_on_close_job(process) -> object | None:
        return None

    def register_helper_pid(pid: int) -> None:
        return

    def unregister_helper_pid(pid: int) -> None:
        return

    def cleanup_helper_pids() -> None:
        return

    def cleanup_bin_helpers(bin_dir: Path | None = None) -> None:
        return
else:
    import ctypes
    from ctypes import wintypes

    _KERNEL32 = ctypes.windll.kernel32
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    _JobObjectExtendedLimitInformation = 9
    _JOB_HANDLES: list[int] = []

    class _IOCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _JobBasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
            ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _JobExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JobBasicLimitInformation),
            ("IoInfo", _IOCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    def kill_process_tree(pid: int) -> None:
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return
        if pid <= 0:
            return
        try:
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                text=True,
                timeout=8,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            pass

    def attach_kill_on_close_job(process) -> object | None:
        """Put *process* in a job that is killed when the job handle closes."""
        try:
            handle = _KERNEL32.CreateJobObjectW(None, None)
            if not handle:
                return None
            info = _JobExtendedLimitInformation()
            info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            ok = _KERNEL32.SetInformationJobObject(
                ctypes.c_void_p(handle),
                _JobObjectExtendedLimitInformation,
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
            if not ok:
                _KERNEL32.CloseHandle(ctypes.c_void_p(handle))
                return None
            proc_handle = getattr(process, "_handle", None)
            if proc_handle is None:
                proc_handle = _KERNEL32.OpenProcess(0x1F0FFF, False, int(process.pid))
                owned = True
            else:
                owned = False
            if not proc_handle:
                _KERNEL32.CloseHandle(ctypes.c_void_p(handle))
                return None
            try:
                if not _KERNEL32.AssignProcessToJobObject(
                    ctypes.c_void_p(handle), ctypes.c_void_p(int(proc_handle))
                ):
                    _KERNEL32.CloseHandle(ctypes.c_void_p(handle))
                    return None
            finally:
                if owned:
                    _KERNEL32.CloseHandle(ctypes.c_void_p(int(proc_handle)))
            _JOB_HANDLES.append(int(handle))
            return handle
        except Exception:
            return None

    def register_helper_pid(pid: int) -> None:
        try:
            if int(pid) > 0:
                _HELPER_PIDS.add(int(pid))
        except Exception:
            pass

    def unregister_helper_pid(pid: int) -> None:
        try:
            _HELPER_PIDS.discard(int(pid))
        except Exception:
            pass

    def cleanup_helper_pids() -> None:
        for pid in list(_HELPER_PIDS):
            kill_process_tree(pid)
            _HELPER_PIDS.discard(pid)

    def cleanup_bin_helpers(bin_dir: Path | None = None) -> None:
        """Terminate leftover app helpers started from our bin directory."""
        cleanup_helper_pids()
        try:
            from .paths import BIN
            root = Path(bin_dir or BIN).resolve()
        except Exception:
            root = Path(bin_dir).resolve() if bin_dir else None
        images = ("uac-psiphon.exe", "uac_psiphon.exe", "aether.exe")
        for image in images:
            try:
                listed = subprocess.run(
                    ["tasklist", "/FI", f"IMAGENAME eq {image}", "/FO", "CSV", "/NH"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except Exception:
                continue
            for line in (listed.stdout or "").splitlines():
                parts = [p.strip().strip('"') for p in line.split(",")]
                if len(parts) < 2:
                    continue
                try:
                    pid = int(parts[1])
                except ValueError:
                    continue
                if root is None:
                    kill_process_tree(pid)
                    continue
                try:
                    query = subprocess.run(
                        [
                            "powershell", "-NoProfile", "-Command",
                            f"(Get-Process -Id {pid} -ErrorAction SilentlyContinue)."
                            "Path",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    )
                    exe = (query.stdout or "").strip().splitlines()
                    exe_path = exe[0].strip() if exe else ""
                    if not exe_path:
                        continue
                    if Path(exe_path).resolve().parent == root:
                        kill_process_tree(pid)
                except Exception:
                    continue

    atexit.register(cleanup_helper_pids)
