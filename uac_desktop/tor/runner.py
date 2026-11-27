"""Tor subprocess manager with adaptive bootstrap timeout and ControlPort client."""
from __future__ import annotations

import re
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

from ..pow.tun_guard import KillOnCloseJob
from ..process_win import register_helper_pid, unregister_helper_pid

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_BOOTSTRAP_RE = re.compile(r"Bootstrapped\s+(\d+)%\s*\(([^)]+)\):\s*(.+)")
_FATAL_MARKERS = (
    "Not using bridge at",
    "Pluggable Transport process terminated",
    "Could not launch managed proxy",
    "Failed to parse/validate config",
    "Exiting.",
)


class TorControlClient:
    def __init__(self, port: int, cookie_path: Path) -> None:
        self.port = int(port)
        self.cookie_path = Path(cookie_path)
        self._lock = threading.Lock()

    def _command(self, cmd: str, timeout: float = 2.5) -> list[str]:
        with self._lock:
            if not self.cookie_path.is_file():
                raise OSError("Tor control cookie file is not ready")
            cookie_hex = self.cookie_path.read_bytes().hex().upper()
            with socket.create_connection(("127.0.0.1", self.port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                stream = sock.makefile("rwb", buffering=0)
                stream.write(f"AUTHENTICATE {cookie_hex}\r\n".encode("ascii"))
                auth_reply = stream.readline().decode("utf-8", errors="replace").strip()
                if not auth_reply.startswith("250"):
                    raise RuntimeError(f"Tor ControlPort auth failed: {auth_reply}")
                stream.write(f"{cmd}\r\n".encode("ascii"))
                lines: list[str] = []
                while True:
                    raw = stream.readline()
                    if not raw:
                        break
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                    lines.append(line)
                    if line.startswith("250 ") or line.startswith(("4", "5")):
                        break
                try:
                    stream.write(b"QUIT\r\n")
                except OSError:
                    pass
                return lines

    def new_identity(self) -> bool:
        lines = self._command("SIGNAL NEWNYM")
        return any(line.startswith("250") for line in lines)

    def traffic(self) -> tuple[int, int] | None:
        try:
            lines = self._command("GETINFO traffic/written traffic/read")
        except Exception:
            return None
        written = read = None
        for line in lines:
            if "traffic/written=" in line:
                try:
                    written = int(line.split("traffic/written=", 1)[1].strip())
                except ValueError:
                    pass
            elif "traffic/read=" in line:
                try:
                    read = int(line.split("traffic/read=", 1)[1].strip())
                except ValueError:
                    pass
        if written is not None and read is not None:
            return max(0, written), max(0, read)
        return None

    def ip_to_country(self, ip: str) -> str:
        ip = str(ip or "").strip()
        if not ip:
            return ""
        try:
            lines = self._command(f"GETINFO ip-to-country/{ip}")
        except Exception:
            return ""
        for line in lines:
            if f"ip-to-country/{ip}=" in line:
                cc = line.split("=", 1)[1].strip().upper()
                if len(cc) == 2 and cc.isalpha() and cc.isascii() and cc not in ("XX", "T1"):
                    return cc
        return ""

    def circuit_path(self) -> list[str]:
        try:
            lines = self._command("GETINFO circuit-status")
        except Exception:
            return []
        for line in lines:
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "BUILT" and "PURPOSE=GENERAL" in line:
                hops = []
                for hop in parts[2].split(","):
                    name = hop.split("~", 1)[1] if "~" in hop else hop[:10]
                    hops.append(name)
                if hops:
                    return hops
        return []


class TorProcess:
    def __init__(
        self,
        binary: Path,
        torrc: Path,
        working_dir: Path,
        *,
        on_log: Callable[[str], None] | None = None,
        on_bootstrap: Callable[[int, str, str], None] | None = None,
    ) -> None:
        self._log = on_log or (lambda _m: None)
        self._on_bootstrap = on_bootstrap or (lambda _p, _t, _s: None)
        self.bootstrapped = threading.Event()
        self.fatal_event = threading.Event()
        self.progress = 0
        self.last_progress_at = time.monotonic()
        self.bootstrap_summary = ""
        self.last_error = ""
        self._fatal_hits = 0
        self._job = KillOnCloseJob()
        self._process = subprocess.Popen(
            [str(binary), "-f", str(torrc)],
            cwd=str(working_dir),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            creationflags=_NO_WINDOW,
        )
        register_helper_pid(self._process.pid)
        self._job.assign(self._process)
        self._reader = threading.Thread(target=self._read, name="tor-stdout", daemon=True)
        self._reader.start()

    @property
    def pid(self) -> int:
        return int(self._process.pid)

    def running(self) -> bool:
        return self._process.poll() is None

    def _read(self) -> None:
        stream = self._process.stdout
        if stream is None:
            return
        with stream:
            for raw in stream:
                line = raw.strip()
                if not line:
                    continue
                if "[err]" in line or "[warn]" in line:
                    self.last_error = line[-220:]
                if any(marker in line for marker in _FATAL_MARKERS):
                    self._fatal_hits += 1
                    if self._fatal_hits >= 3 or "Could not launch" in line or "Failed to parse" in line:
                        self.fatal_event.set()
                match = _BOOTSTRAP_RE.search(line)
                if match:
                    pct = int(match.group(1))
                    tag = match.group(2).strip()
                    summary = match.group(3).strip()
                    if pct > self.progress:
                        self.progress = pct
                        self.last_progress_at = time.monotonic()
                    self.bootstrap_summary = summary
                    self._on_bootstrap(pct, tag, summary)
                    self._log(f"Tor bootstrap {pct}% ({tag}): {summary}")
                    if pct >= 100:
                        self.bootstrapped.set()
                    continue
                if any(k in line for k in ("[warn]", "[err]", "Opening ", "Managed proxy", "new bridge")):
                    self._log(f"Tor: {line[-260:]}")

    def wait_bootstrapped(
        self,
        timeout_s: float,
        cancel: threading.Event,
        *,
        stall_fail_s: float = 24.0,
    ) -> bool:
        started = time.monotonic()
        base_deadline = started + float(timeout_s)
        extended_deadline = started + max(float(timeout_s), 130.0)
        while True:
            now = time.monotonic()
            active_deadline = extended_deadline if self.progress >= 14 else base_deadline
            if now >= active_deadline:
                break
            if cancel.is_set() or not self.running():
                return False
            if self.bootstrapped.is_set():
                return True
            if self.fatal_event.is_set():
                return False
            idle = now - self.last_progress_at
            if self.progress <= 10 and idle >= stall_fail_s:
                self.last_error = self.last_error or f"Stalled at {self.progress}% for {int(stall_fail_s)}s"
                return False
            if self.progress >= 14 and idle >= 55.0:
                self.last_error = self.last_error or f"Consensus download stalled at {self.progress}%"
                return False
            cancel.wait(0.2)
        return self.bootstrapped.is_set() and self.running() and not cancel.is_set()

    def close(self) -> None:
        pid = self.pid
        try:
            if self.running():
                self._process.terminate()
                try:
                    self._process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.wait(timeout=2)
        finally:
            self._job.close()
            unregister_helper_pid(pid)
            self._reader.join(timeout=2)
