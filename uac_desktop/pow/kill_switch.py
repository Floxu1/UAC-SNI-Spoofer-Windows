"""Own the dynamic WFP session associated with one POW connection."""

from __future__ import annotations

import queue
import subprocess
import threading
from pathlib import Path


class VpnKillSwitch:
    def __init__(self, binary: Path, aether: Path, psiphon: Path,
                 *, direct_helpers: tuple[Path, ...] = ()) -> None:
        self._pending: queue.Queue[str | None] = queue.Queue()
        self._lock = threading.Lock()
        self._confirmed = False
        self._commands_valid = True
        arguments = [str(aether), str(psiphon)]
        if direct_helpers:
            arguments = ["--direct", *arguments, *(str(path) for path in direct_helpers)]
        self._process = subprocess.Popen(
            [str(binary), *arguments], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            encoding="ascii", errors="replace", text=True, bufsize=1,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        self._reader = threading.Thread(target=self._read, name="pow-wfp-replies", daemon=True)
        self._reader.start()
        try:
            self._expect_ok()
            self._confirmed = True
        except Exception:
            self.close()
            raise

    def _read(self) -> None:
        try:
            for line in self._process.stdout:
                self._pending.put(line.strip())
        finally:
            self._pending.put(None)

    @property
    def running(self) -> bool:
        return self._confirmed and self._process.poll() is None

    def _expect_ok(self) -> None:
        try:
            reply = self._pending.get(timeout=7)
        except queue.Empty as exc:
            raise TimeoutError("Windows Filtering Platform helper did not respond") from exc
        if reply == "OK":
            return
        if reply and reply.startswith("ERROR "):
            raise OSError(int(reply[6:], 16), f"Windows Filtering Platform: {reply[6:]}")
        raise RuntimeError("Windows Filtering Platform helper exited")

    def set_tunnel(self, allowed: bool) -> None:
        with self._lock:
            if not self.running or not self._commands_valid:
                raise RuntimeError("Windows Filtering Platform helper cannot accept further commands")
            try:
                self._process.stdin.write("TUN\n" if allowed else "BLOCK\n")
                self._process.stdin.flush()
                self._expect_ok()
            except (BrokenPipeError, TimeoutError):
                self._commands_valid = False
                raise

    def close(self) -> None:
        with self._lock:
            self._confirmed = False
            try:
                self._process.stdin.close()
            finally:
                try:
                    self._process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.wait(timeout=3)
                self._process.stdout.close()
