"""Psiphon inner-hop runner — Windows port of ``PowPsiphonService`` + client.

Spawns the ``uac-psiphon`` helper (same tunnel core as mobile ``libgopsi``)
with the exact config JSON ``psiphon_config()`` builds, and parses its
``PSIPHON <json>`` notice lines — the same notices the mobile IPC forwards
(connected, socks port, regions, bytes, diagnostics).
"""

from __future__ import annotations

import json
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

NoticeCallback = Callable[[str, dict], None]


def find_helper() -> Path | None:
    from ..paths import BIN

    candidates = [
        BIN / "uac-psiphon.exe",
        Path(__file__).resolve().parent.parent.parent / "bin" / "uac-psiphon.exe",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def find_server_entries() -> Path | None:
    from ..paths import ASSETS, DATA_DIR

    candidates = [
        DATA_DIR / "pow_server_entries.txt",
        ASSETS / "pow_server_entries.txt",
        Path(__file__).resolve().parent.parent.parent / "assets" / "pow_server_entries.txt",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


class PsiphonProcess:
    """Owns one uac-psiphon helper subprocess."""

    def __init__(self, on_notice: NoticeCallback | None = None) -> None:
        self._on_notice = on_notice
        self._process: subprocess.Popen | None = None
        self._reader: threading.Thread | None = None
        self._lock = threading.Lock()
        self.connected = threading.Event()
        self.socks_port: int | None = None
        self.server_region = ""
        self.client_region = ""
        self.available_regions: list[str] = []
        self.bytes_sent = 0
        self.bytes_received = 0
        self.last_diagnostic = ""

    @property
    def running(self) -> bool:
        with self._lock:
            process = self._process
        return process is not None and process.poll() is None

    def traffic_snapshot(self):
        with self._lock:
            return self._process, (self.bytes_sent, self.bytes_received)

    def start(self, config_json: str, data_dir: Path, meek_only: bool = False) -> None:
        helper = find_helper()
        if helper is None:
            raise RuntimeError("uac-psiphon.exe is missing from the app bin folder")
        entries = find_server_entries()
        if entries is None:
            raise RuntimeError("PoW server entries are missing from the app assets")
        self.stop()
        data_dir = Path(data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        config_path = data_dir / "pow-psiphon-config.json"
        config_path.write_text(config_json, encoding="utf-8")
        inner_dir = data_dir / "uac-pow-inner"
        inner_dir.mkdir(parents=True, exist_ok=True)
        args = [str(helper), "-config", str(config_path), "-serverList", str(entries)]
        # DataDirectory comes inside the config JSON already; the helper also
        # accepts it there. Nothing else to pass.
        if meek_only:
            args.append("-meekOnly")
        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            cwd=str(data_dir),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        try:
            from ..process_win import attach_kill_on_close_job, register_helper_pid
            register_helper_pid(process.pid)
            attach_kill_on_close_job(process)
        except Exception:
            pass
        reader = threading.Thread(
            target=self._drain, args=(process,), name="pow-psiphon-log", daemon=True
        )
        with self._lock:
            self._process = process
            self._reader = reader
            self.connected.clear()
            self.socks_port = None
            self.server_region = self.client_region = ""
            self.available_regions = []
            self.bytes_sent = self.bytes_received = 0
            self.last_diagnostic = ""
        reader.start()

    def _drain(self, process: subprocess.Popen) -> None:
        try:
            assert process.stdout is not None
            for raw in process.stdout:
                line = raw.strip()
                if not line:
                    continue
                if line.startswith("PSIPHON "):
                    self._handle_notice_line(line[len("PSIPHON ") :], source=process)
                elif line.startswith("PSIPHON"):
                    continue
                else:
                    self._emit("log", {"message": line[:300]})
        except Exception:
            pass

    def _handle_notice_line(self, payload: str, *, source: subprocess.Popen | None = None) -> None:
        try:
            notice = json.loads(payload)
        except ValueError:
            self._emit("log", {"message": payload[:300]})
            return
        if not isinstance(notice, dict):
            return
        kind = str(notice.get("noticeType", ""))
        data = notice.get("data")
        if not isinstance(data, dict):
            data = {}
        with self._lock:
            if source is not None and self._process is not source:
                return
            if kind == "Tunnels":
                try:
                    if int(data.get("count", 0)) >= 1:
                        self.connected.set()
                    else:
                        self.connected.clear()
                except (TypeError, ValueError):
                    pass
            elif kind == "ListeningSocksProxyPort":
                try:
                    self.socks_port = int(data.get("port", 0)) or None
                except (TypeError, ValueError):
                    pass
            elif kind == "ConnectedServerRegion":
                self.server_region = str(data.get("region", ""))
            elif kind == "ClientRegion":
                self.client_region = str(data.get("region", ""))
            elif kind == "AvailableEgressRegions":
                regions = data.get("regions") or data.get("region") or []
                if isinstance(regions, str):
                    regions = [regions]
                if isinstance(regions, list):
                    self.available_regions = [str(region) for region in regions]
            elif kind == "BytesTransferred":
                try:
                    sent = max(0, int(data.get("sent", 0)))
                    received = max(0, int(data.get("received", 0)))
                except (TypeError, ValueError):
                    pass
                else:
                    # Each notice describes the interval since the previous notice.
                    self.bytes_sent += sent
                    self.bytes_received += received
            elif kind in ("Diagnostic", "ActiveTunnel", "ClientUpgradeAvailable"):
                text = json.dumps(data, ensure_ascii=False)[:300]
                if text and text != "{}":
                    self.last_diagnostic = f"{kind}: {text}"
        self._emit(kind, data)

    def _emit(self, kind: str, data: dict) -> None:
        callback = self._on_notice
        if callback is not None:
            try:
                callback(kind, data)
            except Exception:
                pass

    def wait_connected(self, timeout_seconds: float, stop: threading.Event) -> bool:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if stop.is_set() or not self.running:
                return False
            if self.connected.is_set():
                return True
            stop.wait(0.3)
        return self.connected.is_set() and self.running and not stop.is_set()

    def stop(self) -> bool:
        with self._lock:
            process, self._process = self._process, None
            reader, self._reader = self._reader, None
            self.connected.clear()
            self.socks_port = None
        if process is None:
            return True
        pid = getattr(process, "pid", None)
        try:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        pass
        except Exception:
            pass
        if pid:
            try:
                from ..process_win import kill_process_tree, unregister_helper_pid
                kill_process_tree(pid)
                unregister_helper_pid(pid)
            except Exception:
                pass
        if reader is not None and reader.is_alive():
            reader.join(timeout=2)
        return process.poll() is not None
