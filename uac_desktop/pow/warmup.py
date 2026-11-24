"""SOCKS payload probes and DNS warming for a verified PoW exit."""

from __future__ import annotations

import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .speed import _read_reply, _recv_exact

PROBE_TARGETS = (
    ("www.gstatic.com", "/generate_204"),
    ("cloudflare.com", "/cdn-cgi/trace"),
    ("www.google.com", "/generate_204"),
)
POPULAR_HOSTS = (
    "google.com", "www.google.com", "gstatic.com", "youtube.com", "googlevideo.com",
    "instagram.com", "cdninstagram.com", "telegram.org", "web.telegram.org",
    "whatsapp.net", "x.com", "twimg.com", "github.com", "wikipedia.org", "cloudflare.com",
)
_DOMAIN = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+")


def normalize_host(value: str) -> str:
    host = value.strip().rstrip(".").lower()
    if len(host) > 253 or not _DOMAIN.fullmatch(host) or host.replace(".", "").isdigit():
        return ""
    return host


def _probe(port: int, host: str, timeout: float, cancelled: threading.Event, path: str = "") -> int:
    if cancelled.is_set():
        return 0
    started = time.monotonic()
    name = host.encode("ascii")
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
            sock.sendall(b"\x05\x01\x00")
            if _recv_exact(sock, 2) != b"\x05\x00" or cancelled.is_set():
                return 0
            sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name
                         + (80 if path else 443).to_bytes(2, "big"))
            if _read_reply(sock)[:2] != b"\x05\x00" or cancelled.is_set():
                return 0
            if path:
                sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii"))
                if not _recv_exact(sock, 12).startswith(b"HTTP/"):
                    return 0
            return max(1, int((time.monotonic() - started) * 1000))
    except OSError:
        return 0


def measure_path(port: int, cancelled: threading.Event, *, targets=PROBE_TARGETS,
                 quorum: int = 2, timeout: float = 1.8) -> int:
    if not port or cancelled.is_set():
        return 0
    if len(targets) == 1:
        host, path = targets[0]
        return _probe(port, host, timeout, cancelled, path)
    with ThreadPoolExecutor(max_workers=len(targets)) as pool:
        results = pool.map(lambda target: _probe(port, target[0], timeout, cancelled, target[1]), targets)
        good = sorted(sample for sample in results if sample > 0)
    return good[len(good) // 2] if len(good) >= quorum and not cancelled.is_set() else 0


class PathWarmup:
    def __init__(self, store, log):
        self._store = store
        self._log = log
        self._lock = threading.Lock()
        self._counts: dict[str, int] = {}
        self._cancelled = threading.Event()
        self._last_dns = 0.0

    def note(self, destination: str) -> None:
        host = normalize_host(destination)
        if not host:
            return
        with self._lock:
            if host in self._counts or len(self._counts) < 512:
                self._counts[host] = self._counts.get(host, 0) + 1

    def flush(self) -> None:
        with self._lock:
            if self._counts:
                try:
                    self._store.save_dns_warm_hosts(self._counts)
                except OSError as exc:
                    self._log(f"Could not save DNS warm observations: {exc}")
                self._counts.clear()

    def forget(self) -> None:
        with self._lock:
            self._cancelled.set()
            self._counts.clear()
            self._last_dns = 0.0
            self._store.forget_learned()

    def cancel(self) -> None:
        with self._lock:
            self._cancelled.set()

    def kick(self, port: int, *, tun: bool, optimized: bool, iran_direct: bool, force: bool) -> None:
        if not port:
            return
        with self._lock:
            self._cancelled.set()
            cancelled = self._cancelled = threading.Event()
            gap = 30 * 60 if optimized else 10 * 60
            dns_due = tun and (force or not self._last_dns or time.monotonic() - self._last_dns >= gap)

        def page_turbo() -> None:
            if cancelled.wait(0.9):
                return
            if measure_path(port, cancelled, targets=PROBE_TARGETS[:2], quorum=1, timeout=1.2):
                self._log("Page Turbo primed the PoW exit")
            for _ in range(2):
                if cancelled.wait(1.5):
                    return
                measure_path(port, cancelled, timeout=1.5)

        def dns_warm() -> None:
            if cancelled.wait(2.5):
                return
            with self._lock:
                if cancelled.is_set():
                    return
                self._last_dns = time.monotonic()
            learned = self._store.dns_warm_hosts()[:12 if optimized else 20]
            hosts = [host for host in dict.fromkeys((*learned, *POPULAR_HOSTS))
                     if not (iran_direct and host.endswith(".ir"))]
            with ThreadPoolExecutor(max_workers=6) as pool:
                answers = sum(sample > 0 for sample in pool.map(
                    lambda host: _probe(port, host, 3, cancelled), hosts
                ))
            if not cancelled.is_set():
                self._log(f"DNS warm: {answers}/{len(hosts)} names primed at the PoW exit")

        threading.Thread(target=page_turbo, name="pow-page-turbo", daemon=True).start()
        if dns_due:
            threading.Thread(target=dns_warm, name="pow-dns-warm", daemon=True).start()
