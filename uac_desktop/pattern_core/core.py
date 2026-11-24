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
import ctypes
import ipaddress
import json
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Callable

from pydivert import Flag, Packet, WinDivert

from .packet_templates import ClientHelloMaker
from ..tls_tools import fragments, gene_plan_from_ops


LogFn = Callable[[str], None]
TrafficFn = Callable[[int, int], None]
IP_UNICAST_IF = 31
TLS_FRAGMENT_STRATEGIES = frozenset({
    "plain", "tls_sni_records", "full5", "full10", "full20", "multi64",
    "sni_boundary", "sni_split", "sni_chars", "primitive",
    "sni_midcut", "sni_midcut3", "sni_hostcut", "outer_rewrite",
    # MCI scanner/FragmentProxy winners (tls_tools.fragments); no WinDivert.
    "coal_2x_zero_v0304", "coal_zero_v0304", "coal_zero_v0303",
    "coal_zero_v0302", "coal_5x_zero_v0302", "coal_2x_zero_then_split",
})
# MCI kills contiguous outer SNI cloudflare-ech.com. TCP urgent-data (OOB) with a
# TTL=1 decoy byte bypasses that filter (proven PASS on AS197207). No WinDivert.
OOB_STRATEGIES = frozenset({
    "disoob_byte0", "disoob", "ech_disoob", "oob_insni5", "oob_insni",
    "ech_oob", "ech_oob_insni", "oob_byte0_ttl1", "oob_insni5_ttl1",
    # ultra-kossher PASS_SH winners (MCI)
    "oob2_snitag_host4", "oob2_snitag_host4_1ms", "oob_rec_hdr_b5",
    "oob2_snilen_namelen", "oob_host_char_04",
})
ECH_OUTER_ALIASES = frozenset({
    "ech_mci", "wrong_seq_frag", "ech_hybrid", "ttl_desync",
    "ech_mci2", "ech_ttl_rewrite", "ech_outer_rewrite",
}) | OOB_STRATEGIES


def default_interface_ipv4(destination: str) -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((destination, 53))
        return str(probe.getsockname()[0])
    finally:
        probe.close()


class _SockaddrIn(ctypes.Structure):
    _fields_ = [
        ("sin_family", ctypes.c_ushort),
        ("sin_port", ctypes.c_ushort),
        ("sin_addr", ctypes.c_ubyte * 4),
        ("sin_zero", ctypes.c_ubyte * 8),
    ]


def best_interface_index(destination: str) -> int:
    address = _SockaddrIn()
    address.sin_family = socket.AF_INET
    for index, value in enumerate(socket.inet_aton(destination)):
        address.sin_addr[index] = value
    interface = ctypes.c_ulong()
    result = ctypes.windll.iphlpapi.GetBestInterfaceEx(
        ctypes.byref(address),
        ctypes.byref(interface),
    )
    if result:
        raise OSError(int(result), "GetBestInterfaceEx failed")
    return int(interface.value)


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
                 inject_delay_ms: int, fake_repeat: int, log: LogFn,
                 decoy_ttl: int = 0) -> None:
        self.packet_filter = packet_filter
        self.connections = connections
        self.registry_lock = registry_lock
        self.inject_delay_ms = inject_delay_ms
        self.fake_repeat = max(1, int(fake_repeat))
        self.decoy_ttl = max(0, min(64, int(decoy_ttl or 0)))
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
            if self.decoy_ttl > 0:
                packet.tcp.seq_num = (connection.syn_seq + 1) & 0xFFFFFFFF
                if packet.ipv4:
                    packet.ipv4.ttl = self.decoy_ttl
            else:
                packet.tcp.seq_num = (connection.syn_seq + 1 - len(connection.fake_data)) & 0xFFFFFFFF
            for index in range(self.fake_repeat):
                if not connection.monitor or self.stop_event.is_set():
                    return
                self._send(packet, True)
                if index + 1 < self.fake_repeat and self.inject_delay_ms:
                    time.sleep(self.inject_delay_ms / 1000)
            connection.fake_sent = True
            if self.decoy_ttl > 0:
                connection.monitor = False
                connection.signal("ttl_decoy_sent")

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




def _oob_offset(data: bytes, mode: str) -> int:
    """Byte index for the urgent-data decoy (never past last byte)."""
    mode = (mode or "").strip().lower()
    if mode in {"oob_insni5", "oob_insni", "ech_oob_insni", "oob_insni5_ttl1"}:
        from ..tls_tools import locate_sni
        loc = locate_sni(data)
        if loc:
            start, length = loc
            return min(len(data) - 1, start + min(5, max(0, length - 1)))
        needle = b"cloudflare-ech.com"
        at = data.find(needle)
        if at >= 0:
            return min(len(data) - 1, at + 5)
    return 0


def send_oob_client_hello(sock: socket.socket, data: bytes, mode: str, log: LogFn | None = None) -> str:
    """Send ClientHello with MCI OOB desync. Supports ultra-kossher multi-offset winners."""
    if not data:
        return "empty"
    mode = (mode or "disoob_byte0").strip().lower()
    if mode in {"ech_oob", "ech_disoob", "disoob", "oob_byte0_ttl1"}:
        mode = "disoob_byte0"
    if mode in {"oob_insni", "ech_oob_insni"}:
        mode = "oob_insni5"
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    try:
        sock.setblocking(True)
    except OSError:
        pass

    def _send_oob_injections(payload: bytes, pts: list[tuple[int, int]], delay_ms: float = 0.0) -> None:
        """ultra-kossher LowLevelSocketTransmitter.send_oob_at_offsets."""
        sorted_pts = sorted(pts, key=lambda x: x[0])
        cursor = 0
        for offset, ghost in sorted_pts:
            if offset <= cursor or offset > len(payload):
                continue
            # Exact ultra-kossher send_oob_at_offsets (no TTL kill on data bytes).
            chunk = payload[cursor:offset] + bytes([ghost & 0xFF])
            sock.send(chunk, socket.MSG_OOB)
            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)
            cursor = offset
        if cursor < len(payload):
            sock.sendall(payload[cursor:])

    used = mode
    from ..tls_tools import locate_sni
    loc = locate_sni(data)

    if mode in {"oob2_snitag_host4", "oob2_snitag_host4_1ms"} and loc:
        name_off, name_len = loc
        sni_ext = name_off - 9  # type(2)+len(2)+list(2)+ntype(1)+nlen(2)
        pts = [(sni_ext + 1, 0x78), (name_off + 4, 0x2D)]
        delay = 1.0 if mode.endswith("_1ms") else 0.0
        _send_oob_injections(data, pts, delay)
        used = mode
        if log:
            log(f"PATTERN OOB desync mode={used} pts={pts} bytes={len(data)}")
    elif mode == "oob2_snilen_namelen" and loc:
        name_off, _ = loc
        # sni_length_offset+1 ~= name_off-6 (ext_len lo), name_len+1 ~= name_off-1
        pts = [(name_off - 6, 0xFF), (name_off - 1, 0xFF)]
        _send_oob_injections(data, pts, 0.0)
        used = mode
        if log:
            log(f"PATTERN OOB desync mode={used} pts={pts} bytes={len(data)}")
    elif mode == "oob_rec_hdr_b5":
        # MSG_OOB at hs_type index 5 with ghost; then rest
        _send_oob_injections(data, [(5, 0x16)], 0.0)
        used = mode
        if log:
            log(f"PATTERN OOB desync mode={used} off=5 bytes={len(data)}")
    elif mode == "oob_host_char_04" and loc:
        name_off, _ = loc
        _send_oob_injections(data, [(name_off + 4, 0x2D)], 0.0)
        used = mode
        if log:
            log(f"PATTERN OOB desync mode={used} off={name_off + 4} bytes={len(data)}")
    else:
        off = _oob_offset(data, mode)
        if off <= 0:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
                sock.send(data[0:1], socket.MSG_OOB)
            finally:
                try:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 64)
                except OSError:
                    pass
            time.sleep(0.05)
            sock.sendall(data)
            used = "disoob_byte0"
        else:
            if off:
                sock.sendall(data[:off])
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
                sock.send(data[off:off + 1], socket.MSG_OOB)
            finally:
                try:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 64)
                except OSError:
                    pass
            time.sleep(0.03)
            sock.sendall(data[off:])
            used = "oob_insni5"
        if log:
            log(f"PATTERN OOB desync mode={used} off={off if mode != 'disoob_byte0' else 0} bytes={len(data)}")

    try:
        sock.setblocking(False)
    except OSError:
        pass
    return used


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
        self._interface_index = 0
        self._edges: list[str] = []
        self._preferred_edge: str | None = None
        self._failed_until: dict[str, float] = {}
        self._fake_sni = "chatgpt.com"
        self._strategy_override = "wrong_seq"
        self._handshake_failover = False
        self._decoy_ttl = 0
        self._ttl_desync = False
        self._hybrid_fake_fragment = False
        self._fragment_delay_s = 0.0
        self._post_fake_delay_s = 0.0
        self._oob_mode = ""
        self._session_sem: asyncio.Semaphore | None = None
        self._edge_lock: asyncio.Lock | None = None

    @property
    def running(self) -> bool:
        injection_required = (
            (self._strategy_override == "wrong_seq" or self._hybrid_fake_fragment
             or getattr(self, "_ttl_desync", False))
            and self._strategy_override not in OOB_STRATEGIES
            and not getattr(self, "_oob_mode", "")
        )
        transport_ready = (
            bool(self._injector) if injection_required
            else (
                self._strategy_override in TLS_FRAGMENT_STRATEGIES
                or self._strategy_override in OOB_STRATEGIES
                or bool(getattr(self, "_oob_mode", ""))
            )
        )
        return bool(self._server_sock) and not self._stop.is_set() and transport_ready

    @property
    def active_edge(self) -> str:
        """The edge selected by the live Pattern route, or an empty string."""
        return self._preferred_edge or ""

    @property
    def edge_addresses(self) -> tuple[str, ...]:
        return tuple(self._edges)

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
        # Gene Lab strategy edges (imported working IPs) go first; the normal
        # list stays behind them as failover.
        # Auto clean-IP picks go right after gene edges (or first without a gene).
        gene_edges = str(getattr(tuning, "pattern_gene_edges", "") or "")
        clean_edges = str(getattr(tuning, "pattern_clean_edges", "") or "")
        try:
            from ..clean_ip import order_edges
            raw = order_edges(gene_edges, clean_edges, [str(v or "") for v in raw],
                              str(getattr(tuning, "pattern_session_edge", "") or ""))
        except Exception:
            if gene_edges.strip():
                raw = [*gene_edges.replace(";", ",").split(","), *raw]
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
                f"((tcp.DstPort == {port} and ({outbound_edges})) "
                f"or (tcp.SrcPort == {port} and ({inbound_edges})))")

    def start(self, profile, tuning, forced_strategy: str | None = None) -> None:
        self.stop()
        if os.name != "nt":
            raise RuntimeError("Pattern core currently requires Windows/WinDivert")
        self._profile = profile
        self._strategy_override = str(forced_strategy or "wrong_seq").strip().lower()
        # ECH-on-MCI: outer SNI cloudflare-ech.com is filtered. Prefer TCP OOB+TTL=1
        # (disoob_byte0 / oob_insni5) which PASS on AS197207; legacy wrong_seq/TTL
        # decoy/fragment aliases remain for fallback experiments.
        self._oob_mode = ""
        ech_hybrid = self._strategy_override in ECH_OUTER_ALIASES
        self._decoy_ttl = 0
        if self._strategy_override in OOB_STRATEGIES or self._strategy_override in {
                "ech_mci", "ech_mci2", "ech_oob"}:
            # Keep an explicit OOB method if the caller forced one; only aliases
            # (ech_mci / ech_oob) fall back to tuning / disoob_byte0.
            concrete = {"disoob_byte0", "oob_insni5", "oob_byte0_ttl1", "oob_insni5_ttl1",
                        "disoob", "oob_insni", "ech_disoob", "ech_oob_insni",
                        "oob2_snitag_host4", "oob2_snitag_host4_1ms", "oob_rec_hdr_b5",
                        "oob2_snilen_namelen", "oob_host_char_04"}
            if self._strategy_override in concrete:
                if self._strategy_override in {"disoob", "ech_disoob", "oob_byte0_ttl1"}:
                    self._strategy_override = "disoob_byte0"
                elif self._strategy_override in {"oob_insni", "ech_oob_insni", "oob_insni5_ttl1"}:
                    self._strategy_override = "oob_insni5"
            else:
                pref = str(getattr(tuning, "pattern_ech_fragment", "") or "").strip().lower()
                if pref in OOB_STRATEGIES:
                    self._strategy_override = pref
                elif pref in {"oob_insni5", "insni", "sni"}:
                    self._strategy_override = "oob_insni5"
                else:
                    self._strategy_override = "disoob_byte0"
            self._oob_mode = self._strategy_override
            ech_hybrid = False
        elif ech_hybrid or self._strategy_override == "ttl_desync":
            self._decoy_ttl = max(0, min(64, int(getattr(tuning, "pattern_decoy_ttl", 5) or 5)))
        if ech_hybrid and self._strategy_override != "ttl_desync":
            frag = str(getattr(tuning, "pattern_ech_fragment", "") or "none").strip().lower()
            if frag in OOB_STRATEGIES:
                self._strategy_override = frag
                self._oob_mode = frag
                self._decoy_ttl = 0
                ech_hybrid = False
            elif frag in {"", "none", "off", "wrong_seq"}:
                self._strategy_override = "wrong_seq"
            elif frag in TLS_FRAGMENT_STRATEGIES and frag != "plain":
                self._strategy_override = frag
            else:
                self._strategy_override = "wrong_seq"
        if self._strategy_override == "ttl_desync":
            self._strategy_override = "wrong_seq"
        if self._strategy_override not in ({"wrong_seq"} | TLS_FRAGMENT_STRATEGIES | OOB_STRATEGIES):
            self._strategy_override = "wrong_seq"
        self._quality = Quality.from_tuning(tuning)
        self._handshake_failover = (
            getattr(profile, "origin", "") == "builtin"
            and str(getattr(tuning, "carrier_mode", "")).lower() == "mci"
        )
        self._ttl_desync = self._decoy_ttl > 0
        self._hybrid_fake_fragment = (
            (ech_hybrid and self._strategy_override in TLS_FRAGMENT_STRATEGIES)
            or (self._handshake_failover and self._strategy_override == "full5")
        )
        if self._handshake_failover or self._hybrid_fake_fragment:
            self._fragment_delay_s = {
                "full20": 0.003,
                "full5": 0.015,
                "tls_sni_records": 0.012,
                "sni_split": 0.008,
                "sni_boundary": 0.008,
                "sni_chars": 0.004,
            }.get(self._strategy_override, 0.008 if self._hybrid_fake_fragment else 0.0)
        else:
            self._fragment_delay_s = 0.0
        if self._fragment_delay_s <= 0 and self._strategy_override in TLS_FRAGMENT_STRATEGIES:
            tuned_delay = int(getattr(tuning, "sni_split_delay_ms", 0) or 0)
            if self._strategy_override in {"full5", "full10", "full20", "multi", "multi64"}:
                tuned_delay = int(getattr(tuning, "multi_delay_ms", tuned_delay) or tuned_delay)
            if tuned_delay > 0:
                self._fragment_delay_s = max(0, min(80, tuned_delay)) / 1000
        self._post_fake_delay_s = (
            max(0, min(20, int(getattr(tuning, "pattern_inject_delay_ms", 0))))
            / 1000
            if self._hybrid_fake_fragment else 0.0
        )
        self._fake_sni = str(getattr(tuning, "pattern_fake_sni", "chatgpt.com") or profile.sni)
        self._fake_sni_bytes(self._fake_sni)
        self._gene_ops = []
        self._gene_plan_logged = False
        self._gene_strict = bool(getattr(tuning, "pattern_gene_strict", False))
        raw_ops = str(getattr(tuning, "pattern_gene_ops", "") or "").strip()
        if raw_ops:
            try:
                parsed = json.loads(raw_ops)
                if isinstance(parsed, list):
                    self._gene_ops = [x for x in parsed if isinstance(x, dict)]
            except (TypeError, ValueError, json.JSONDecodeError):
                self._gene_ops = []
        self._edges = self._build_edges(profile, tuning)
        self._interface_ip = default_interface_ipv4(self._edges[0])
        self._interface_index = best_interface_index(self._edges[0])
        if not self._interface_ip or self._interface_index <= 0:
            raise RuntimeError("Pattern core could not detect the active IPv4 interface")
        self.upload = self.download = 0
        self._stop.clear()
        self._ready.clear()
        self._server_error = None
        self._preferred_edge = None
        self._failed_until.clear()

        self._injector = None
        try:
            if ((self._strategy_override == "wrong_seq" or self._hybrid_fake_fragment
                    or getattr(self, "_ttl_desync", False))
                    and self._strategy_override not in OOB_STRATEGIES
                    and not getattr(self, "_oob_mode", "")):
                self._injector = PacketInjector(
                    self._packet_filter(), self._connections,
                    self._registry_lock, self._quality.inject_delay_ms,
                    getattr(tuning, "pattern_fake_repeat", 1),
                    self.log,
                    decoy_ttl=getattr(self, "_decoy_ttl", 0),
                )
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
        hybrid = " hybridFake+frag" if self._hybrid_fake_fragment else ""
        ttl_note = f" decoyTTL={self._decoy_ttl}" if getattr(self, "_ttl_desync", False) else ""
        oob_note = f" oob={self._oob_mode}" if getattr(self, "_oob_mode", "") else ""
        self.log(f"PATTERN CORE ready 127.0.0.1:{profile.config_port} "
                 f"{self._strategy_override}{hybrid}{ttl_note}{oob_note} fakeSni={self._fake_sni}")
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
                except asyncio.CancelledError:
                    break
                except OSError:
                    if self._stop.is_set():
                        break
                    raise
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
        if not healthy:
            healthy = list(self._edges)
        healthy.sort(key=lambda edge: (edge != self._preferred_edge, self._edges.index(edge)))
        return healthy

    def _tune_socket(self, sock: socket.socket, pin_interface: bool = False) -> None:
        size = self._quality.socket_buffer_kb * 1024


        if pin_interface and self._interface_index:
            sock.setsockopt(
                socket.IPPROTO_IP,
                IP_UNICAST_IF,
                struct.pack("!I", self._interface_index),
            )
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

    def _tune_outgoing_socket(self, sock: socket.socket, edge: str) -> None:
        try:
            self._tune_socket(sock, True)
        except OSError:
            interface_ip = default_interface_ipv4(edge)
            if ipaddress.ip_address(interface_ip) in ipaddress.ip_network("172.19.0.0/30"):
                raise
            interface_index = best_interface_index(edge)
            if not interface_ip or interface_index <= 0:
                raise RuntimeError("Pattern core could not refresh the active IPv4 interface")
            self._interface_ip = interface_ip
            self._interface_index = interface_index
            self._tune_socket(sock, True)

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



        if ((self._strategy_override in TLS_FRAGMENT_STRATEGIES
                or self._strategy_override in OOB_STRATEGIES
                or bool(getattr(self, "_oob_mode", "")))
                and not self._hybrid_fake_fragment):
            for edge in candidates:
                outgoing = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                outgoing.setblocking(False)
                try:
                    self._tune_outgoing_socket(outgoing, edge)
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
                except (OSError, asyncio.TimeoutError, RuntimeError) as exc:
                    self._failed_until[edge] = (
                        time.monotonic() + self._quality.edge_failure_cooldown_s
                    )
                    if self._preferred_edge == edge:
                        self._preferred_edge = None
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
            connection = None
            try:
                self._tune_outgoing_socket(outgoing, edge)
                outgoing.bind((self._interface_ip, 0))
                source_port = int(outgoing.getsockname()[1])
                connection = InjectiveConnection(outgoing, incoming, self._interface_ip, edge, source_port,
                                                  int(self._profile.port), fake_data, loop)
                self._register(connection)
                await asyncio.wait_for(loop.sock_connect(outgoing, (edge, int(self._profile.port))),
                                       self._quality.connect_timeout_ms / 1000)
                await asyncio.wait_for(connection.event.wait(), self._quality.ack_timeout_ms / 1000)
                if connection.result not in {"fake_data_ack_recv", "ttl_decoy_sent"}:
                    raise ConnectionError(connection.result or "wrong-seq acknowledgement failed")
                self._unregister(connection)
                previous_edge = self._preferred_edge
                self._preferred_edge = edge
                self._failed_until.pop(edge, None)
                if previous_edge != edge:
                    self.log(f"PATTERN EDGE active {edge}:{self._profile.port}")
                return outgoing
            except (OSError, asyncio.TimeoutError, ConnectionError, RuntimeError) as exc:
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
        outgoing = None
        try:
            assert self._session_sem is not None
            async with self._session_sem:
                outgoing = await self._connect_edge(incoming)
                if not outgoing:
                    return
                if (self._strategy_override in OOB_STRATEGIES
                        or bool(getattr(self, "_oob_mode", ""))):
                    loop = asyncio.get_running_loop()
                    try:
                        try:
                            outgoing.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        except OSError:
                            pass
                        first = await asyncio.wait_for(loop.sock_recv(incoming, 65535), 2.0)
                        if not first:
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
                        mode = getattr(self, "_oob_mode", "") or self._strategy_override
                        await loop.run_in_executor(
                            None, send_oob_client_hello, outgoing, first, mode, self.log
                        )
                        self.upload += len(first)
                        self._emit_traffic()
                        # Short peek only to confirm SH, then relay (ios/517B path).
                        try:
                            peek = await asyncio.wait_for(loop.sock_recv(outgoing, 65535), 3.0)
                        except (OSError, asyncio.TimeoutError):
                            peek = b""
                        if peek:
                            sh = len(peek) > 5 and peek[0] == 0x16 and peek[5] == 0x02
                            self.log(
                                f"PATTERN OOB peek {len(peek)} head={peek[:8].hex()} "
                                f"sh={'yes' if sh else 'no'}"
                            )
                            await loop.sock_sendall(incoming, peek)
                            self.download += len(peek)
                            self._emit_traffic()
                        else:
                            self.log("PATTERN OOB peek empty; relay")
                    except (OSError, asyncio.TimeoutError) as exc:
                        self.log(f"PATTERN OOB handshake error: {type(exc).__name__}")
                        return
                elif self._strategy_override in TLS_FRAGMENT_STRATEGIES:
                    loop = asyncio.get_running_loop()
                    try:
                        if self._hybrid_fake_fragment or self._fragment_delay_s > 0:
                            try:
                                outgoing.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                            except OSError:
                                pass
                        if self._post_fake_delay_s:
                            await asyncio.sleep(self._post_fake_delay_s)
                        first = await asyncio.wait_for(loop.sock_recv(incoming, 65535), 2.0)
                        if not first:
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
                        piece_delays: list[int] | None = None
                        if self._strategy_override == "primitive":
                            plan = gene_plan_from_ops(
                                first, getattr(self, "_gene_ops", None),
                                strict=bool(getattr(self, "_gene_strict", False)),
                            )
                            pieces = [p for p in plan.pieces if p] or [first]
                            piece_delays = list(plan.delays_ms) if len(pieces) == len(plan.pieces) else None
                            if not getattr(self, "_gene_plan_logged", False):
                                self._gene_plan_logged = True
                                self.log(
                                    f"PATTERN GENE ops applied={','.join(plan.applied) or '-'} "
                                    f"skipped={','.join(plan.skipped) or '-'} pieces={len(pieces)} "
                                    f"delays={piece_delays}"
                                    + (f" parseFallback={plan.error}" if plan.error else "")
                                )
                        else:
                            pieces = fragments(
                                first,
                                self._strategy_override,
                                ops=getattr(self, "_gene_ops", None),
                            )
                        attempts = 3 if self._handshake_failover else 1
                        for attempt in range(attempts):
                            if outgoing is None:
                                outgoing = await self._connect_edge(incoming)
                                if outgoing is None:
                                    return
                            for index, piece in enumerate(pieces):
                                await loop.sock_sendall(outgoing, piece)
                                self.upload += len(piece)
                                if piece_delays is not None:
                                    gene_delay = piece_delays[index] if index < len(piece_delays) else 0
                                    if gene_delay > 0:
                                        await asyncio.sleep(gene_delay / 1000)
                                elif index + 1 < len(pieces):
                                    delay = (
                                        self._fragment_delay_s
                                        if self._fragment_delay_s > 0
                                        else 0.001
                                        if self._strategy_override == "tls_sni_records"
                                        else 0.0
                                    )
                                    if delay:
                                        await asyncio.sleep(delay)
                            self._emit_traffic()
                            if not self._handshake_failover:
                                break
                            try:
                                response = await asyncio.wait_for(
                                    loop.sock_recv(outgoing, 65535),
                                    max(
                                        1.8,
                                        min(
                                            6.0 if self._handshake_failover else 3.2,
                                            self._quality.ack_timeout_ms / 1000,
                                        ),
                                    ),
                                )
                                if not response:
                                    raise ConnectionError("empty TLS response")
                                await loop.sock_sendall(incoming, response)
                                self.download += len(response)
                                self._emit_traffic()
                                break
                            except (OSError, asyncio.TimeoutError, ConnectionError):
                                try:
                                    edge = str(outgoing.getpeername()[0])
                                except OSError:
                                    edge = self._preferred_edge or ""
                                if edge:
                                    self._failed_until[edge] = time.monotonic() + 1.5
                                    if self._preferred_edge == edge:
                                        self._preferred_edge = None
                                    self.log(
                                        f"PATTERN TLS retry {edge} "
                                        f"{attempt + 1}/{attempts}"
                                    )
                                outgoing.close()
                                outgoing = None
                                if attempt + 1 >= attempts:
                                    return
                    except (OSError, asyncio.TimeoutError):
                        return
            await self._relay_pair(incoming, outgoing)
        except (OSError, ConnectionError, asyncio.TimeoutError, RuntimeError):
            return
        finally:
            for sock in (incoming, outgoing):
                if sock is not None:
                    try:
                        close = getattr(sock, "close", None)
                        if callable(close):
                            close()
                    except OSError:
                        pass

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
                # ECH/OOB tunnels need a longer drain; 3s was cutting proxied HTTP.
                drain = 12.0 if getattr(self, "_oob_mode", "") else 3.0
                done2, pending = await asyncio.wait(pending, timeout=drain)
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
