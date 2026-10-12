"""HTTP CONNECT → SOCKS5 forwarder for the PoW exit.

Windows System Proxy needs an HTTP proxy (http/https) alongside SOCKS, but
the PoW exit (Psiphon, or the aether leg in WARP-only mode) only speaks
SOCKS5. This forwarder listens on 127.0.0.1 and relays:

- ``CONNECT host:port`` tunnels (HTTPS and everything else), and
- origin-form ``GET http://...`` requests (plain HTTP),

upstream through the exit SOCKS5. Plain-Python sockets + threads, no new
dependencies. Loopback only.
"""

from __future__ import annotations

import socket
import threading

_BUFFER = 65536
#: TCP keepalive for long idle tunnels (Telegram/MTProto): first probe after
#: 60s idle, then every 10s. Setup timeouts are dropped once a tunnel is up.
KEEPALIVE_IDLE_MS = 60_000
KEEPALIVE_INTERVAL_MS = 10_000


def enable_keepalive(sock: socket.socket) -> None:
    """Turn on TCP keepalive so an idle long-lived connection stays mapped."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        return
    try:
        if hasattr(socket, "SIO_KEEPALIVE_VALS"):
            sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, KEEPALIVE_IDLE_MS, KEEPALIVE_INTERVAL_MS))
        else:
            for name, value in (("TCP_KEEPIDLE", KEEPALIVE_IDLE_MS // 1000), ("TCP_KEEPINTVL", KEEPALIVE_INTERVAL_MS // 1000), ("TCP_KEEPCNT", 6)):
                if hasattr(socket, name):
                    sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, name), value)
    except (OSError, ValueError):
        pass


def make_long_lived(*socks: socket.socket) -> None:
    """Relay phase: no idle timeout (blocking), keepalive on."""
    for sock in socks:
        try:
            sock.settimeout(None)
        except OSError:
            pass
        enable_keepalive(sock)


def _socks5_connect(upstream_host: str, upstream_port: int, target_host: str, target_port: int) -> socket.socket:
    sock = socket.create_connection((upstream_host, upstream_port), timeout=10)
    try:
        sock.sendall(bytes([0x05, 0x01, 0x00]))
        reply = sock.recv(2)
        if len(reply) != 2 or reply[0] != 0x05 or reply[1] != 0x00:
            raise OSError("socks5 handshake rejected")
        host_bytes = target_host.encode("idna")
        if len(host_bytes) > 255:
            raise OSError("target host too long")
        request = (
            bytes([0x05, 0x01, 0x00, 0x03, len(host_bytes)])
            + host_bytes
            + target_port.to_bytes(2, "big")
        )
        sock.sendall(request)
        reply = sock.recv(10)
        if len(reply) < 2 or reply[1] != 0x00:
            raise OSError(f"socks5 connect refused ({reply[1] if len(reply) > 1 else '?'})")
        return sock
    except Exception:
        sock.close()
        raise


def _relay(a: socket.socket, b: socket.socket, stop: threading.Event) -> None:
    def _copy(src: socket.socket, dst: socket.socket) -> None:
        try:
            while not stop.is_set():
                chunk = src.recv(_BUFFER)
                if not chunk:
                    break
                dst.sendall(chunk)
        except OSError:
            pass

    first = threading.Thread(target=_copy, args=(a, b), daemon=True)
    first.start()
    try:
        _copy(b, a)
    finally:
        try:
            a.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            b.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    first.join(timeout=2)


def _read_headers(conn: socket.socket) -> bytes:
    data = b""
    conn.settimeout(10)
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(_BUFFER)
        if not chunk:
            break
        data += chunk
        if len(data) > 65536:
            break
    return data


class HttpToSocks:
    """Loopback HTTP proxy that forwards through a SOCKS5 exit."""

    def __init__(self, listen_port: int, socks_host: str, socks_port: int) -> None:
        self._listen_port = listen_port
        self._socks_host = socks_host
        self._socks_port = socks_port
        self._stop = threading.Event()
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    def start(self) -> None:
        self.stop()
        self._stop.clear()
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", self._listen_port))
        server.listen(32)
        server.settimeout(1.0)
        self._server = server
        self._thread = threading.Thread(
            target=self._serve, args=(server,), name="pow-http-forward", daemon=True
        )
        self._thread.start()

    def _serve(self, server: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            worker = threading.Thread(
                target=self._handle, args=(conn,), name="pow-http-conn", daemon=True
            )
            worker.start()

    def _handle(self, conn: socket.socket) -> None:
        upstream: socket.socket | None = None
        try:
            request = _read_headers(conn)
            if not request:
                return
            head, _sep, _rest = request.partition(b"\r\n\r\n")
            request_line = head.split(b"\r\n", 1)[0].decode("latin1")
            parts = request_line.split()
            if len(parts) < 2:
                return
            method, target = parts[0].upper(), parts[1]
            if method == "CONNECT":
                host, _, port_text = target.partition(":")
                try:
                    port = int(port_text) if port_text else 443
                except ValueError:
                    return
                upstream = _socks5_connect(self._socks_host, self._socks_port, host, port)
                conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                make_long_lived(conn, upstream)
                _relay(conn, upstream, self._stop)
                return
            # Origin-form or absolute-form plain HTTP: forward to port 80
            # (or the explicit port) and relay both directions.
            if target.startswith("http://"):
                without_scheme = target[len("http://") :]
                host_port, _, _path = without_scheme.partition("/")
                host, _, port_text = host_port.partition(":")
                try:
                    port = int(port_text) if port_text else 80
                except ValueError:
                    return
            else:
                host_hdr = ""
                for header in head.split(b"\r\n")[1:]:
                    if header.lower().startswith(b"host:"):
                        host_hdr = header.split(b":", 1)[1].decode("latin1").strip()
                        break
                if not host_hdr:
                    return
                host, _, port_text = host_hdr.partition(":")
                try:
                    port = int(port_text) if port_text else 80
                except ValueError:
                    return
            upstream = _socks5_connect(self._socks_host, self._socks_port, host, port)
            upstream.sendall(request)
            make_long_lived(conn, upstream)
            _relay(conn, upstream, self._stop)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass

    def stop(self) -> None:
        self._stop.set()
        server, self._server = self._server, None
        if server is not None:
            try:
                server.close()
            except OSError:
                pass
        thread, self._thread = self._thread, None
        if thread is not None and thread.is_alive():
            thread.join(timeout=2)
