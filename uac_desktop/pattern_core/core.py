"""Managed integration of patterniha/SNI-Spoofing's wrong-sequence core.

Upstream: https://github.com/patterniha/SNI-Spoofing
Pinned revision: 13b78cf7e073f38d9cadcff542faf4a00b0a6de2
License: GPL-3.0 (a copy and the unmodified source are shipped in third_party/)

The upstream packet state machine is retained, but application lifecycle,
bounded concurrency, route fallback and the full-duplex relay are adapted for
the desktop application.  In particular, asyncio.sock_sendall() returns None;
it must not be compared with the payload length or uploads close after one
chunk.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import ipaddress
import os
import socket
import threading
import time
from dataclasses import dataclass
from typing import Callable

from pydivert import Flag, Packet, WinDivert

from .packet_templates import ClientHelloMaker
from ..tls_tools import fragments


LogFn = Callable[[str], None]
TrafficFn = Callable[[int, int], None]


def default_interface_ipv4(destination: str) -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((destination, 53))
        return str(probe.getsockname()[0])
    finally:
        probe.close()


def _valid_ipv4(value: str) -> str | None:
    try:
        return str(ipaddress.IPv4Address(value.strip()))
    except (ipaddress.AddressValueError, AttributeError):
        return None


@dataclass(slots=True)
class Quality:
    inject_delay_ms: int = 1
    ack_timeout_ms: int = 3000
    connect_timeout_ms: int = 2500
    relay_buffer_kb: int = 512
    socket_buffer_kb: int = 4096
    max_sessions: int = 12
    edge_failure_cooldown_s: int = 8
    keepalive_idle_s: int = 11
    keepalive_interval_s: int = 3
    keepalive_count: int = 3
    upload_optimized: bool = True

    @classmethod
    def from_tuning(cls, tuning) -> "Quality":
        return cls(
            inject_delay_ms=max(0, min(20, int(getattr(tuning, "pattern_inject_delay_ms", 1)))),
            ack_timeout_ms=max(500, min(10000, int(getattr(tuning, "pattern_ack_timeout_ms", 3000)))),
            connect_timeout_ms=max(500, min(10000, int(getattr(tuning, "pattern_connect_timeout_ms", 2500)))),
            relay_buffer_kb=max(32, min(1024, int(getattr(tuning, "pattern_relay_buffer_kb", 512)))),
            socket_buffer_kb=max(64, min(8192, int(getattr(tuning, "pattern_socket_buffer_kb", 4096)))),
            max_sessions=max(2, min(64, int(getattr(tuning, "pattern_max_sessions", 12)))),
            edge_failure_cooldown_s=max(1, min(60, int(getattr(
                tuning, "pattern_edge_failure_cooldown_s", 8)))),
            keepalive_idle_s=max(5, min(120, int(getattr(tuning, "pattern_keepalive_idle_s", 11)))),
            keepalive_interval_s=max(1, min(60, int(getattr(
                tuning, "pattern_keepalive_interval_s", 3)))),
            keepalive_count=max(1, min(10, int(getattr(tuning, "pattern_keepalive_count", 3)))),
            upload_optimized=bool(getattr(tuning, "pattern_upload_optimized", True)),
        )


class InjectiveConnection:
    def __init__(self, sock: socket.socket, peer_sock: socket.socket, src_ip: str, dst_ip: str,
                 src_port: int, dst_port: int, fake_data: bytes, loop: asyncio.AbstractEventLoop) -> None:
        self.sock = sock
        self.peer_sock = peer_sock
        self.src_ip, self.dst_ip = src_ip, dst_ip
        self.src_port, self.dst_port = src_port, dst_port
        self.id = (src_ip, src_port, dst_ip, dst_port)
        self.fake_data = fake_data
        self.loop = loop
        self.event = asyncio.Event()
        self.result = ""
        self.monitor = True
        self.syn_seq = -1
        self.syn_ack_seq = -1
        self.fake_scheduled = False
        self.fake_sent = False
        self.lock = threading.Lock()

    def signal(self, result: str) -> None:
        self.result = result
        try:
            self.loop.call_soon_threadsafe(self.event.set)
        except RuntimeError:
            pass


class PacketInjector:
    """Stoppable WinDivert implementation of upstream's FakeTcpInjector."""

    def __init__(self, packet_filter: str, connections: dict, registry_lock: threading.Lock,
                 inject_delay_ms: int, log: LogFn) -> None:
        self.packet_filter = packet_filter
        self.connections = connections
        self.registry_lock = registry_lock
        self.inject_delay_ms = inject_delay_ms
        self.log = log
        self.stop_event = threading.Event()
        self.ready_event = threading.Event()
        self.error: Exception | None = None



        self.w = WinDivert(packet_filter, flags=Flag.SNIFF)
        self.thread: threading.Thread | None = None
        self.fake_pool = concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="pattern-fake")

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, name="pattern-windivert", daemon=True)
        self.thread.start()
        if not self.ready_event.wait(4):
            raise RuntimeError("Pattern core WinDivert startup timed out")
        if self.error:
            if isinstance(self.error, PermissionError):
                raise RuntimeError("Pattern core requires Administrator access for WinDivert") from self.error
            raise RuntimeError(f"Pattern core WinDivert failed: {self.error}") from self.error

    def _run(self) -> None:
        try:
            self.w.open()
            self.ready_event.set()
            while not self.stop_event.is_set():
                try:
                    packet = self.w.recv(65575)
                except OSError:
                    if self.stop_event.is_set():
                        break
                    raise
                self._inject(packet)
        except Exception as exc:
            if not self.stop_event.is_set():
                self.error = exc
                self.log(f"PATTERN WinDivert error: {exc}")
        finally:
            self.ready_event.set()
            try:
                self.w.close()
            except Exception:
                pass

    def stop(self) -> None:
        self.stop_event.set()
        try:
            self.w.close()
        except Exception:
            pass
        if self.thread and self.thread is not threading.current_thread():
            self.thread.join(timeout=2)
        self.thread = None
        self.fake_pool.shutdown(wait=False, cancel_futures=True)

    def _lookup(self, key):
        with self.registry_lock:
            return self.connections.get(key)

    def _send(self, packet: Packet, recalculate: bool = False) -> None:
        if not recalculate:

            return
        try:
            self.w.send(packet, recalculate)
        except OSError:
            if not self.stop_event.is_set():
                raise

    def _abort_spoof(self, packet: Packet, connection: InjectiveConnection, reason: str) -> None:


        connection.monitor = False
        connection.signal("unexpected_close")
        self.log(f"PATTERN flow fallback: {reason}")
        self._send(packet, False)

    def _fake_send(self, packet: Packet, connection: InjectiveConnection) -> None:
        if self.inject_delay_ms:
            time.sleep(self.inject_delay_ms / 1000)
        with connection.lock:
            if not connection.monitor or self.stop_event.is_set():
                return
            packet.tcp.psh = True
            packet.ip.packet_len = packet.ip.packet_len + len(connection.fake_data)
            packet.tcp.payload = connection.fake_data
            if packet.ipv4:
                packet.ipv4.ident = (packet.ipv4.ident + 1) & 0xFFFF
            packet.tcp.seq_num = (connection.syn_seq + 1 - len(connection.fake_data)) & 0xFFFFFFFF
            connection.fake_sent = True
            self._send(packet, True)

    def _inbound(self, packet: Packet, connection: InjectiveConnection) -> None:
        tcp = packet.tcp
        if connection.syn_seq == -1:
            self._abort_spoof(packet, connection, "inbound before SYN")
            return
        if tcp.ack and tcp.syn and not tcp.rst and not tcp.fin and not tcp.payload:
            if tcp.ack_num != ((connection.syn_seq + 1) & 0xFFFFFFFF):
                self._abort_spoof(packet, connection, "SYN-ACK mismatch")
                return
            connection.syn_ack_seq = tcp.seq_num
            self._send(packet, False)
            return
        if tcp.ack and not tcp.syn and not tcp.rst and not tcp.fin and not tcp.payload and connection.fake_sent:
            if connection.syn_ack_seq == -1 or tcp.seq_num != ((connection.syn_ack_seq + 1) & 0xFFFFFFFF):
                self._abort_spoof(packet, connection, "fake ACK sequence mismatch")
                return
            if tcp.ack_num != ((connection.syn_seq + 1) & 0xFFFFFFFF):
                self._abort_spoof(packet, connection, "fake ACK number mismatch")
                return
            connection.monitor = False
            connection.signal("fake_data_ack_recv")


            return
        self._abort_spoof(packet, connection, "unexpected inbound packet")

    def _outbound(self, packet: Packet, connection: InjectiveConnection) -> None:
        tcp = packet.tcp
        if connection.fake_scheduled:
            self._abort_spoof(packet, connection, "outbound after fake schedule")
            return
        if tcp.syn and not tcp.ack and not tcp.rst and not tcp.fin and not tcp.payload:
            if tcp.ack_num != 0:
                self._abort_spoof(packet, connection, "SYN has ACK number")
                return
            connection.syn_seq = tcp.seq_num
            self._send(packet, False)
            return
        if tcp.ack and not tcp.syn and not tcp.rst and not tcp.fin and not tcp.payload:
            if connection.syn_seq == -1 or tcp.seq_num != ((connection.syn_seq + 1) & 0xFFFFFFFF):
                self._abort_spoof(packet, connection, "handshake ACK sequence mismatch")
                return
            if connection.syn_ack_seq == -1 or tcp.ack_num != ((connection.syn_ack_seq + 1) & 0xFFFFFFFF):
                self._abort_spoof(packet, connection, "handshake ACK number mismatch")
                return
            self._send(packet, False)
            connection.fake_scheduled = True
            self.fake_pool.submit(self._fake_send, packet, connection)
            return
        self._abort_spoof(packet, connection, "unexpected outbound packet")

    def _inject(self, packet: Packet) -> None:
        try:
            if packet.is_inbound:
                key = (packet.ip.dst_addr, packet.tcp.dst_port, packet.ip.src_addr, packet.tcp.src_port)
            elif packet.is_outbound:
                key = (packet.ip.src_addr, packet.tcp.src_port, packet.ip.dst_addr, packet.tcp.dst_port)
            else:
                self._send(packet, False)
                return
            connection = self._lookup(key)
            if not connection:
                self._send(packet, False)
                return
            with connection.lock:
                if not connection.monitor:
                    self._send(packet, False)
                    return
                if packet.is_inbound:
                    self._inbound(packet, connection)
                else:
                    self._outbound(packet, connection)
        except Exception as exc:
            self.log(f"PATTERN packet recovery: {type(exc).__name__}: {exc}")
            try:
                self._send(packet, False)
            except Exception:
                pass


class PatternSniCore:
    """Local 127.0.0.1 TLS forwarder powered by Patterniha wrong-seq injection."""

    UPSTREAM_DEFAULT_IP = "104.18.32.47"

    def __init__(self, log: LogFn, traffic: TrafficFn | None = None) -> None:
        self.log = log
        self.traffic = traffic or (lambda _up, _down: None)
        self.upload = 0
        self.download = 0
        self._last_traffic_emit = 0.0
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._server_error: Exception | None = None
        self._server_sock: socket.socket | None = None
        self._server_thread: threading.Thread | None = None
        self._injector: PacketInjector | None = None
        self._connections: dict[tuple, InjectiveConnection] = {}
        self._registry_lock = threading.Lock()
        self._profile = None
        self._quality = Quality()
        self._interface_ip = ""
        self._edges: list[str] = []
        self._preferred_edge: str | None = None
        self._failed_until: dict[str, float] = {}
        self._fake_sni = "chatgpt.com"
        self._strategy_override = "wrong_seq"
        self._session_sem: asyncio.Semaphore | None = None
        self._edge_lock: asyncio.Lock | None = None

    @property
    def running(self) -> bool:
        return bool(self._server_sock) and not self._stop.is_set() and bool(self._injector)

    @property
    def active_edge(self) -> str:
        """The edge selected by the live Pattern route, or an empty string."""
        return self._preferred_edge or ""

    @staticmethod
    def _fake_sni_bytes(value: str) -> bytes:
        try:
            encoded = value.strip().encode("idna")
        except UnicodeError as exc:
            raise ValueError("Pattern Fake SNI is invalid") from exc
        if not encoded or len(encoded) > 219 or b"." not in encoded:
            raise ValueError("Pattern Fake SNI must be a valid hostname up to 219 bytes")
        return encoded

    def _build_edges(self, profile, tuning) -> list[str]:
        configured = str(getattr(tuning, "pattern_connect_ip", self.UPSTREAM_DEFAULT_IP) or "")
        fallbacks = str(getattr(tuning, "pattern_fallback_ips", "188.114.99.0,104.18.8.83,104.18.9.83") or "")
        raw = [configured, *fallbacks.replace(";", ",").split(",")]
        if bool(getattr(tuning, "pattern_use_profile_edges", False)):
            raw = [profile.address, profile.fallback_address, *raw]
        edges = list(dict.fromkeys(ip for value in raw if (ip := _valid_ipv4(value))))
        if not edges:
            raise ValueError("Pattern core has no valid IPv4 edge")
        return edges

    def _packet_filter(self) -> str:
        outbound_edges = " or ".join(f"ip.DstAddr == {edge}" for edge in self._edges)
        inbound_edges = " or ".join(f"ip.SrcAddr == {edge}" for edge in self._edges)
        port = int(self._profile.port)
        return (f"tcp and !impostor and tcp.PayloadLength == 0 and "
                f"(tcp.Syn or tcp.Ack or tcp.Rst or tcp.Fin) and "
                f"((ip.SrcAddr == {self._interface_ip} and tcp.DstPort == {port} and ({outbound_edges})) "
                f"or (ip.DstAddr == {self._interface_ip} and tcp.SrcPort == {port} and ({inbound_edges})))")

    def start(self, profile, tuning, forced_strategy: str | None = None) -> None:
        self.stop()
        if os.name != "nt":
            raise RuntimeError("Pattern core currently requires Windows/WinDivert")
        self._profile = profile
        self._strategy_override = str(forced_strategy or "wrong_seq").strip().lower()
        self._quality = Quality.from_tuning(tuning)
        self._fake_sni = str(getattr(tuning, "pattern_fake_sni", "chatgpt.com") or profile.sni)
        self._fake_sni_bytes(self._fake_sni)
        self._edges = self._build_edges(profile, tuning)
        self._interface_ip = default_interface_ipv4(self._edges[0])
        if not self._interface_ip:
            raise RuntimeError("Pattern core could not detect the active IPv4 interface")
        self.upload = self.download = 0
        self._stop.clear()
        self._ready.clear()
        self._server_error = None
        self._preferred_edge = None
        self._failed_until.clear()

        self._injector = PacketInjector(self._packet_filter(), self._connections, self._registry_lock,
                                        self._quality.inject_delay_ms, self.log)
        try:
            self._injector.start()
            self._server_thread = threading.Thread(target=self._server_runner, name="pattern-core", daemon=True)
            self._server_thread.start()
            if not self._ready.wait(4):
                raise RuntimeError("Pattern core listener startup timed out")
            if self._server_error:
                raise RuntimeError(f"Pattern core listener failed: {self._server_error}")
        except Exception:
            self.stop()
            raise
        self.log(f"PATTERN CORE ready 127.0.0.1:{profile.config_port} "
                 f"{self._strategy_override} fakeSni={self._fake_sni}")
        self.log(f"PATTERN QUALITY preset={getattr(tuning, 'pattern_quality_preset', 'upload')} "
                 f"relay={self._quality.relay_buffer_kb}KiB socket={self._quality.socket_buffer_kb}KiB "
                 f"handshakes={self._quality.max_sessions} edges={','.join(self._edges)}")

    def _server_runner(self) -> None:
        try:
            asyncio.run(self._serve())
        except Exception as exc:
            if not self._stop.is_set():
                self._server_error = exc
                self.log(f"PATTERN listener error: {exc}")
        finally:
            self._ready.set()

    async def _serve(self) -> None:
        loop = asyncio.get_running_loop()
        self._session_sem = asyncio.Semaphore(self._quality.max_sessions)
        self._edge_lock = asyncio.Lock()
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.setblocking(False)
        server.bind(("127.0.0.1", int(self._profile.config_port)))
        server.listen(256)
        self._server_sock = server
        self._ready.set()
        try:
            while not self._stop.is_set():
                try:
                    incoming, _address = await loop.sock_accept(server)
                except (OSError, asyncio.CancelledError):
                    break
                incoming.setblocking(False)
                self._tune_socket(incoming)
                asyncio.create_task(self._handle(incoming))
        finally:
            try:
                server.close()
            except OSError:
                pass
            self._server_sock = None

    def _ordered_edges(self) -> list[str]:
        now = time.monotonic()



        healthy = [edge for edge in self._edges if self._failed_until.get(edge, 0) <= now]
        healthy.sort(key=lambda edge: (edge != self._preferred_edge, self._edges.index(edge)))
        return healthy

    def _tune_socket(self, sock: socket.socket) -> None:
        size = self._quality.socket_buffer_kb * 1024


        send_size = size if self._quality.upload_optimized else min(size, 256 * 1024)
        for option, option_size in ((socket.SO_SNDBUF, send_size), (socket.SO_RCVBUF, size)):
            try:
                sock.setsockopt(socket.SOL_SOCKET, option, option_size)
            except OSError:
                pass
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,
                            1 if self._quality.upload_optimized else 0)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except OSError:
            pass
        for name, value in (("TCP_KEEPIDLE", self._quality.keepalive_idle_s),
                            ("TCP_KEEPINTVL", self._quality.keepalive_interval_s),
                            ("TCP_KEEPCNT", self._quality.keepalive_count)):
            option = getattr(socket, name, None)
            if option is not None:
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, option, value)
                except OSError:
                    pass

    def _register(self, connection: InjectiveConnection) -> None:
        with self._registry_lock:
            self._connections[connection.id] = connection

    def _unregister(self, connection: InjectiveConnection) -> None:
        connection.monitor = False
        with self._registry_lock:
            self._connections.pop(connection.id, None)

    async def _connect_edge(self, incoming: socket.socket) -> socket.socket | None:




        if self._edge_lock is None:
            return await self._connect_edge_unlocked(incoming)
        while True:
            preferred = self._preferred_edge
            if preferred:
                outgoing = await self._connect_edge_unlocked(incoming, (preferred,))
                if outgoing is not None:
                    return outgoing
            async with self._edge_lock:



                if self._preferred_edge:
                    continue
                return await self._connect_edge_unlocked(incoming)

    async def _connect_edge_unlocked(self, incoming: socket.socket,
                                     edges: tuple[str, ...] | list[str] | None = None
                                     ) -> socket.socket | None:
        loop = asyncio.get_running_loop()
        candidates = self._ordered_edges() if edges is None else edges



        if self._strategy_override == "tls_sni_records":
            for edge in candidates:
                outgoing = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                outgoing.setblocking(False)
                self._tune_socket(outgoing)
                try:
                    await asyncio.wait_for(
                        loop.sock_connect(outgoing, (edge, int(self._profile.port))),
                        self._quality.connect_timeout_ms / 1000,
                    )
                    previous_edge = self._preferred_edge
                    self._preferred_edge = edge
                    self._failed_until.pop(edge, None)
                    if previous_edge != edge:
                        self.log(f"PATTERN EDGE active {edge}:{self._profile.port} "
                                 f"mode={self._strategy_override}")
                    return outgoing
                except (OSError, asyncio.TimeoutError) as exc:
                    self._failed_until[edge] = (
                        time.monotonic() + self._quality.edge_failure_cooldown_s
                    )
                    try:
                        outgoing.close()
                    except OSError:
                        pass
                    self.log(f"PATTERN EDGE retry {edge} {self._strategy_override}: "
                             f"{type(exc).__name__}")
            return None
        fake_data = ClientHelloMaker.get_client_hello_with(
            os.urandom(32), os.urandom(32), self._fake_sni_bytes(self._fake_sni), os.urandom(32))
        for edge in candidates:
            outgoing = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            outgoing.setblocking(False)
            self._tune_socket(outgoing)
            connection = None
            try:
                outgoing.bind((self._interface_ip, 0))
                source_port = int(outgoing.getsockname()[1])
                connection = InjectiveConnection(outgoing, incoming, self._interface_ip, edge, source_port,
                                                  int(self._profile.port), fake_data, loop)
                self._register(connection)
                await asyncio.wait_for(loop.sock_connect(outgoing, (edge, int(self._profile.port))),
                                       self._quality.connect_timeout_ms / 1000)
                await asyncio.wait_for(connection.event.wait(), self._quality.ack_timeout_ms / 1000)
                if connection.result != "fake_data_ack_recv":
                    raise ConnectionError(connection.result or "wrong-seq acknowledgement failed")
                self._unregister(connection)
                previous_edge = self._preferred_edge
                self._preferred_edge = edge
                self._failed_until.pop(edge, None)
                if previous_edge != edge:
                    self.log(f"PATTERN EDGE active {edge}:{self._profile.port}")
                return outgoing
            except (OSError, asyncio.TimeoutError, ConnectionError) as exc:
                if connection:
                    self._unregister(connection)
                self._failed_until[edge] = (time.monotonic()
                                            + self._quality.edge_failure_cooldown_s)
                if self._preferred_edge == edge:
                    self._preferred_edge = None
                try:
                    outgoing.close()
                except OSError:
                    pass
                self.log(f"PATTERN EDGE retry {edge}: {type(exc).__name__}")
        return None

    async def _handle(self, incoming: socket.socket) -> None:
        assert self._session_sem is not None
        async with self._session_sem:
            outgoing = await self._connect_edge(incoming)
        if not outgoing:
            incoming.close()
            return
        if self._strategy_override == "tls_sni_records":



            loop = asyncio.get_running_loop()
            try:
                first = await asyncio.wait_for(loop.sock_recv(incoming, 65535), 2.0)
                if not first:
                    incoming.close()
                    outgoing.close()
                    return
                expected = (5 + int.from_bytes(first[3:5], "big")
                            if len(first) >= 5 and first[0] == 0x16 else len(first))
                while len(first) < expected:
                    chunk = await asyncio.wait_for(
                        loop.sock_recv(incoming, expected - len(first)), 1.0
                    )
                    if not chunk:
                        break
                    first += chunk
                pieces = fragments(first, "tls_sni_records")
                for index, piece in enumerate(pieces):
                    await loop.sock_sendall(outgoing, piece)
                    self.upload += len(piece)
                    if index + 1 < len(pieces):
                        await asyncio.sleep(0.001)
                self._emit_traffic()
            except (OSError, asyncio.TimeoutError):
                incoming.close()
                outgoing.close()
                return
        await self._relay_pair(incoming, outgoing)

    async def _pump(self, source: socket.socket, destination: socket.socket, upload: bool) -> None:
        loop = asyncio.get_running_loop()
        chunk_size = self._quality.relay_buffer_kb * 1024
        while not self._stop.is_set():
            data = await loop.sock_recv(source, chunk_size)
            if not data:
                try:
                    destination.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return


            await loop.sock_sendall(destination, data)
            if upload:
                self.upload += len(data)
            else:
                self.download += len(data)
            self._emit_traffic()

    async def _relay_pair(self, incoming: socket.socket, outgoing: socket.socket) -> None:
        tasks = {asyncio.create_task(self._pump(incoming, outgoing, True)),
                 asyncio.create_task(self._pump(outgoing, incoming, False))}
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                try:
                    await task
                except (OSError, ConnectionError, asyncio.CancelledError):
                    pass


            if pending:
                done2, pending = await asyncio.wait(pending, timeout=0.35)
                for task in done2:
                    try:
                        await task
                    except (OSError, ConnectionError, asyncio.CancelledError):
                        pass
            for task in pending:
                task.cancel()
        finally:
            for sock in (incoming, outgoing):
                try:
                    sock.close()
                except OSError:
                    pass
            self._emit_traffic(force=True)

    def _emit_traffic(self, force: bool = False) -> None:
        now = time.monotonic()
        if force or now - self._last_traffic_emit >= 0.2:
            self._last_traffic_emit = now
            self.traffic(self.upload, self.download)

    def stop(self) -> None:
        self._stop.set()
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None
        with self._registry_lock:
            connections = list(self._connections.values())
            self._connections.clear()
        for connection in connections:
            connection.monitor = False
            connection.signal("stopped")
            for sock in (connection.sock, connection.peer_sock):
                try:
                    sock.close()
                except OSError:
                    pass
        if self._injector:
            self._injector.stop()
            self._injector = None
        if self._server_thread and self._server_thread is not threading.current_thread():
            self._server_thread.join(timeout=2)
        self._server_thread = None
        self._ready.clear()
