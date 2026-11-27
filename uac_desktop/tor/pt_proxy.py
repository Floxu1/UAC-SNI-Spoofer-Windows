"""Local SOCKS5/HTTP-CONNECT relay for Tor & Pluggable Transports (lyrebird / snowflake).

- Uses unpoisoned DNS (DoH/DoT/Alt-port) so lyrebird/snowflake never hit 10.10.34.x.
- Transparently retries TLS ClientHello over DPI-bypass vectors on TCP RST, EOF, timeout,
  or TLS Alert (0x15) WITHOUT breaking the client connection (fixes Snowflake CheckProxy
  and WebTunnel tls: illegal parameter).
"""
from __future__ import annotations

import socket
import struct
import threading
from typing import Callable

from .bridges import resolve_unpoisoned_ipv4, transmit_client_hello

LogFn = Callable[[str], None]

_NORMAL_LADDER = (
    "direct",
    "mutator_vec26_fastpath_oob",
    "mutator_vec24_rfc_4rec",
    "mutator_vec01_oob_400",
    "uac_disoob_byte0_ttl1",
)
_CENSORED_FIRST_LADDER = (
    "mutator_vec26_fastpath_oob",
    "mutator_vec24_rfc_4rec",
    "mutator_vec01_oob_400",
    "uac_disoob_byte0_ttl1",
    "direct",
)
_CENSORED_SUFFIXES = (
    "torproject.org",
    "torproject.net",
    "cdn77.org",
    "cdn77.com",
    "fastly.net",
    "cloudfront.net",
    "appspot.com",
)


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise OSError("EOF")
        buf.extend(chunk)
    return bytes(buf)


def _is_tls_client_hello(data: bytes) -> bool:
    return len(data) >= 48 and data[0] == 0x16 and data[1] == 0x03 and data[5] == 0x01


def _needs_bypass_first(host: str) -> bool:
    h = host.lower().rstrip(".")
    return any(h == s or h.endswith("." + s) for s in _CENSORED_SUFFIXES)


class TorBridgeProxy:
    """In-process dual SOCKS5 + HTTP CONNECT proxy bound to 127.0.0.1 for Tor PTs."""

    def __init__(
        self,
        *,
        dns_cache: dict[str, list[str]] | None = None,
        save_dns_cache: Callable[[str, list[str]], None] | None = None,
        log: LogFn | None = None,
    ) -> None:
        self._dns_cache = dns_cache or {}
        self._save_dns = save_dns_cache
        self._log = log or (lambda _m: None)
        self._lock = threading.Lock()
        self._active: set[socket.socket] = set()
        self._host_winner: dict[str, str] = {}
        self._running = False
        self._server: socket.socket | None = None
        self.port = 0

    def start(self) -> int:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(128)
        srv.settimeout(1.0)
        self._server = srv
        self.port = int(srv.getsockname()[1])
        self._running = True
        threading.Thread(target=self._accept_loop, name="tor-pt-proxy", daemon=True).start()
        return self.port

    def close(self) -> None:
        self._running = False
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
            self._server = None
        with self._lock:
            socks = list(self._active)
            self._active.clear()
        for s in socks:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass

    def _accept_loop(self) -> None:
        while self._running and self._server is not None:
            try:
                client, _addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()

    def _dial_targets(self, host: str, port: int, is_domain: bool, is_ipv6: bool) -> list[tuple[int, str]]:
        if is_domain:
            ips = resolve_unpoisoned_ipv4(
                host, timeout=3.5, disk_cache=self._dns_cache, save_cache=self._save_dns
            )
            return [(socket.AF_INET, ip) for ip in ips[:3]]
        return [(socket.AF_INET6 if is_ipv6 else socket.AF_INET, host)]

    def _open_tcp(self, targets: list[tuple[int, str]], port: int, timeout: float = 5.0) -> socket.socket | None:
        for fam, ip in targets:
            s = socket.socket(fam, socket.SOCK_STREAM)
            try:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.settimeout(timeout)
                s.connect((ip, port))
                return s
            except OSError:
                try:
                    s.close()
                except OSError:
                    pass
        return None

    def _ordered_methods(self, key: str, host: str) -> list[str]:
        base = list(_CENSORED_FIRST_LADDER if _needs_bypass_first(host) else _NORMAL_LADDER)
        with self._lock:
            winner = self._host_winner.get(key)
        if winner and winner in base:
            base.remove(winner)
            base.insert(0, winner)
        return base

    def _handle_client(self, client: socket.socket) -> None:
        remote: socket.socket | None = None
        with self._lock:
            self._active.add(client)
        try:
            client.settimeout(12.0)
            first_byte = _recv_exact(client, 1)
            is_http_connect = first_byte != b"\x05"

            is_domain = False
            is_ipv6 = False
            if is_http_connect:
                header_buf = bytearray(first_byte)
                while b"\r\n\r\n" not in header_buf and len(header_buf) < 8192:
                    chunk = client.recv(1024)
                    if not chunk:
                        return
                    header_buf.extend(chunk)
                first_line = header_buf.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
                parts = first_line.split()
                if len(parts) < 2 or parts[0].upper() != "CONNECT":
                    client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                    return
                target = parts[1]
                if target.startswith("["):
                    host, _, p_s = target[1:].partition("]:")
                    is_ipv6 = True
                else:
                    host, _, p_s = target.rpartition(":")
                    is_domain = not all(c.isdigit() or c == "." for c in host)
                port = int(p_s or 443)
            else:
                nmethods = _recv_exact(client, 1)[0]
                _recv_exact(client, nmethods)
                client.sendall(b"\x05\x00")
                ver, cmd, _rsv, atyp = struct.unpack("!BBBB", _recv_exact(client, 4))
                if ver != 5 or cmd != 1:
                    client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                    return
                if atyp == 1:
                    host = socket.inet_ntoa(_recv_exact(client, 4))
                elif atyp == 3:
                    dlen = _recv_exact(client, 1)[0]
                    host = _recv_exact(client, dlen).decode("utf-8", errors="ignore").strip()
                    is_domain = True
                elif atyp == 4:
                    host = socket.inet_ntop(socket.AF_INET6, _recv_exact(client, 16))
                    is_ipv6 = True
                else:
                    client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                    return
                port = struct.unpack("!H", _recv_exact(client, 2))[0]

            targets = self._dial_targets(host, port, is_domain, is_ipv6)
            if not targets:
                self._log(f"Tor PT proxy: unpoisoned DNS failed for {host}")
                client.sendall(
                    b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
                    if is_http_connect
                    else b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00"
                )
                return

            remote = self._open_tcp(targets, port, timeout=5.0)
            if remote is None:
                self._log(f"Tor PT proxy: connect failed {host}:{port}")
                client.sendall(
                    b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
                    if is_http_connect
                    else b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00"
                )
                return

            if is_http_connect:
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

            # Peek first payload from client to detect TLS ClientHello
            client.settimeout(12.0)
            try:
                first_up = client.recv(65536)
            except OSError:
                return
            if not first_up:
                return

            key = f"{host.lower()}:{port}"
            first_down = b""
            if _is_tls_client_hello(first_up):
                methods = self._ordered_methods(key, host)
                succeeded = False
                for idx, method in enumerate(methods):
                    if not self._running:
                        return
                    if idx > 0:
                        try:
                            remote.close()
                        except OSError:
                            pass
                        remote = self._open_tcp(targets, port, timeout=4.5)
                        if remote is None:
                            return
                    try:
                        remote.settimeout(4.5)
                        if method == "direct":
                            remote.sendall(first_up)
                        else:
                            transmit_client_hello(remote, first_up, method, stride_bytes=400)
                        resp = remote.recv(65536)
                        if resp and resp[0] != 0x15:
                            first_down = resp
                            succeeded = True
                            with self._lock:
                                prev = self._host_winner.get(key)
                                self._host_winner[key] = method
                            if method != "direct" and prev != method:
                                self._log(f"Tor PT proxy: TLS handshake passed for {host} ({method})")
                            break
                    except OSError:
                        continue
                if not succeeded:
                    self._log(f"Tor PT proxy: TLS handshake failed for {host}:{port}")
                    return
            else:
                # Raw protocol (e.g. obfs4) -> forward untouched
                remote.settimeout(None)
                remote.sendall(first_up)

            with self._lock:
                self._active.add(remote)
            remote.settimeout(None)
            client.settimeout(None)
            if first_down:
                client.sendall(first_down)
            self._pipe_both(client, remote)
        except OSError:
            pass
        finally:
            with self._lock:
                self._active.discard(client)
                if remote is not None:
                    self._active.discard(remote)
            for s in (client, remote):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass

    def _pipe_both(self, client: socket.socket, remote: socket.socket) -> None:
        def down() -> None:
            try:
                while self._running:
                    chunk = remote.recv(65536)
                    if not chunk:
                        break
                    client.sendall(chunk)
            except OSError:
                pass
            finally:
                try:
                    client.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t = threading.Thread(target=down, daemon=True)
        t.start()
        try:
            while self._running:
                chunk = client.recv(65536)
                if not chunk:
                    break
                remote.sendall(chunk)
        except OSError:
            pass
        finally:
            try:
                remote.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            t.join(timeout=2.0)
