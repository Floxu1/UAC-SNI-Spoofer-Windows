"""High-resilience Tor bridge fetcher:
- Parallel unpoisoned DNS (Google/Cloudflare DoH by bare IP, DoT/853, Alt-Port 5353/9953, TCP/53)
- UAC native OOB Desync (disoob_byte0_ttl1, oob_insni5_ttl1, oob2_snitag_host4)
- Mutator non-fragment DPI bypasses (VEC-01/VEC-15 OOB+400B stride, VEC-21 Phantom Seam OOB,
  VEC-26 FastPath Alternating-Version OOB, VEC-24 RFC 4-Record SNI-dot + KeyShare)
- Cloudflare Worker Relay & CDN mirrors (Moat, jsDelivr, GitHub, GitLab, BridgeDB, pt_config.json)
"""
from __future__ import annotations

import concurrent.futures
import gzip
import ipaddress
import json
import random
import re
import socket
import ssl
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import quote, urlsplit

from ..paths import BIN
from ..pow.config import relay_urls

LogFn = Callable[[str], None]

MOAT_BUILTIN_URL = "https://bridges.torproject.org/moat/circumvention/builtin"
MOAT_SETTINGS_URL = "https://bridges.torproject.org/moat/circumvention/settings"
BRIDGEDB_URL = "https://bridges.torproject.org/bridges?transport={transport}"

OFFICIAL_BRIDGE_LISTS = {
    "webtunnel": (
        "https://cdn.jsdelivr.net/gh/torproject/tor-browser-build@main/projects/common/bridges_list.webtunnel.txt",
        "https://raw.githubusercontent.com/torproject/tor-browser-build/main/projects/common/bridges_list.webtunnel.txt",
        "https://gitlab.torproject.org/tpo/applications/tor-browser-build/-/raw/main/projects/common/bridges_list.webtunnel.txt",
    ),
    "obfs4": (
        "https://cdn.jsdelivr.net/gh/torproject/tor-browser-build@main/projects/common/bridges_list.obfs4.txt",
        "https://raw.githubusercontent.com/torproject/tor-browser-build/main/projects/common/bridges_list.obfs4.txt",
        "https://gitlab.torproject.org/tpo/applications/tor-browser-build/-/raw/main/projects/common/bridges_list.obfs4.txt",
    ),
    "snowflake": (
        "https://cdn.jsdelivr.net/gh/torproject/tor-browser-build@main/projects/common/bridges_list.snowflake.txt",
        "https://raw.githubusercontent.com/torproject/tor-browser-build/main/projects/common/bridges_list.snowflake.txt",
        "https://gitlab.torproject.org/tpo/applications/tor-browser-build/-/raw/main/projects/common/bridges_list.snowflake.txt",
    ),
}

DEFAULT_SNOWFLAKE_BRIDGES = (
    "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
    "fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
    "url=https://1098762253.rsc.cdn77.org/ "
    "fronts=www.cdn77.com,www.phpmyadmin.net "
    "ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,"
    "stun:stun.dus.net:3478,stun:stun.epygi.com:3478,stun:stun.sonetel.com:3478,"
    "stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478 "
    "utls-imitate=hellorandomizedalpn",
    "snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA "
    "fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA "
    "url=https://1098762253.rsc.cdn77.org/ "
    "fronts=www.cdn77.com,www.phpmyadmin.net "
    "ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,"
    "stun:stun.dus.net:3478,stun:stun.epygi.com:3478,stun:stun.sonetel.com:3478,"
    "stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478 "
    "utls-imitate=hellorandomizedalpn",
)

# Iranian ISP hijack/sinkhole ranges to reject
_POISON_NETS = (
    ipaddress.ip_network("10.10.34.0/24"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
)
_BRIDGE_LINE_RE = re.compile(
    r"^(?:bridge\s+)?(webtunnel|obfs4|snowflake|meek_lite|conjure)\s+\S+:\d+\s+[0-9A-Fa-f]{40}\b.*$",
    re.I,
)
_DNS_MEM_CACHE: dict[str, tuple[float, list[str]]] = {}
_DNS_LOCK = threading.Lock()


@dataclass(frozen=True)
class BridgeFetchResult:
    bridges: tuple[str, ...] = ()
    transport: str = ""
    method: str = ""
    source: str = ""
    detail: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.bridges)


# =====================================================================
# Bridge line parsing & validation
# =====================================================================

def normalize_bridge_line(raw: str) -> str:
    line = " ".join(str(raw or "").strip().split())
    if not line or line.startswith("#"):
        return ""
    if line.lower().startswith("bridge "):
        line = line[7:].strip()
    if _BRIDGE_LINE_RE.match(line):
        return line
    return ""


def bridge_transport(line: str) -> str:
    clean = normalize_bridge_line(line)
    return clean.split(" ", 1)[0].lower() if clean else ""


def bridge_endpoint(line: str) -> tuple[str, int] | None:
    clean = normalize_bridge_line(line)
    if not clean:
        return None
    parts = clean.split()
    if len(parts) < 2:
        return None
    addr = parts[1]
    if addr.startswith("["):
        host, _, port_s = addr[1:].partition("]:")
    else:
        host, _, port_s = addr.rpartition(":")
    try:
        port = int(port_s)
        if host and 1 <= port <= 65535:
            return host, port
    except ValueError:
        pass
    return None


def extract_bridges_from_text(text: str, wanted_transport: str = "") -> list[str]:
    wanted = str(wanted_transport or "").strip().lower()
    out: list[str] = []
    seen: set[str] = set()
    cleaned = re.sub(r"<[^>]+>", "\n", str(text or ""))
    cleaned = cleaned.replace("&amp;", "&").replace("&#x2F;", "/").replace("&quot;", '"')
    for raw in cleaned.splitlines():
        line = normalize_bridge_line(raw)
        if not line:
            continue
        if wanted and bridge_transport(line) != wanted:
            continue
        if line not in seen:
            seen.add(line)
            out.append(line)
    return out


def summarize_bridge_counts(lines: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for raw in lines:
        tr = bridge_transport(raw)
        if tr:
            counts[tr] = counts.get(tr, 0) + 1
    return counts


# =====================================================================
# Parallel unpoisoned DNS resolver (defeats ISP UDP/53 hijacking)
# =====================================================================

def _is_valid_public_ipv4(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip_str).strip())
    except ValueError:
        return False
    if addr.version != 4:
        return False
    if any(addr in net for net in _POISON_NETS):
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved)


def _doh_json_by_ip(host: str, resolver_ip: str, path: str, sni: str, timeout: float = 2.5) -> list[str]:
    """Raw-socket JSON DoH directly to 8.8.8.8 / 8.8.4.4 / 1.1.1.1 / 1.0.0.1 (no proxy, no OS DNS)."""
    sock = None
    try:
        sock = socket.create_connection((resolver_ip, 443), timeout=timeout)
        sock.settimeout(timeout)
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(sock, server_hostname=sni) as tls:
            sock = None
            req = (
                f"GET {path}?name={quote(host)}&type=A HTTP/1.1\r\n"
                f"Host: {sni}\r\n"
                "Accept: application/dns-json\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            tls.sendall(req)
            buf = bytearray()
            while len(buf) < 65536:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                buf.extend(chunk)
        hdr, sep, body = bytes(buf).partition(b"\r\n\r\n")
        if not sep:
            return []
        if b"transfer-encoding: chunked" in hdr.lower():
            body = _decode_chunked(body)
        doc = json.loads(body.decode("utf-8", errors="replace"))
        ips = []
        for item in doc.get("Answer") or []:
            if isinstance(item, dict) and int(item.get("type", 0) or 0) == 1:
                ip_s = str(item.get("data", "")).strip()
                if _is_valid_public_ipv4(ip_s) and ip_s not in ips:
                    ips.append(ip_s)
        return ips
    except Exception:
        return []
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _dns_wire_query(host: str) -> tuple[int, bytes]:
    tx = random.randint(1, 65535)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in host.rstrip(".").split(".")) + b"\x00"
    return tx, struct.pack("!HHHHHH", tx, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def _dns_wire_extract_a(packet: bytes, expected_tx: int) -> list[str]:
    if len(packet) < 12:
        return []
    tx, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", packet[:12])
    if tx != expected_tx or (flags & 0x000F) != 0 or an == 0:
        return []
    pos = 12
    try:
        for _ in range(qd):
            while pos < len(packet) and packet[pos] != 0:
                if (packet[pos] & 0xC0) == 0xC0:
                    pos += 2
                    break
                pos += 1 + packet[pos]
            else:
                pos += 1
            pos += 4
        ips = []
        for _ in range(an):
            if pos >= len(packet):
                break
            if (packet[pos] & 0xC0) == 0xC0:
                pos += 2
            else:
                while pos < len(packet) and packet[pos] != 0:
                    pos += 1 + packet[pos]
                pos += 1
            if pos + 10 > len(packet):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", packet[pos:pos + 10])
            pos += 10
            if rtype == 1 and rdlen == 4 and pos + 4 <= len(packet):
                ip_s = socket.inet_ntoa(packet[pos:pos + 4])
                if _is_valid_public_ipv4(ip_s) and ip_s not in ips:
                    ips.append(ip_s)
            pos += rdlen
        return ips
    except Exception:
        return []


def _udp_dns_port(host: str, server: str, port: int, timeout: float = 2.0) -> list[str]:
    tx, wire = _dns_wire_query(host)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(wire, (server, port))
            reply, _ = s.recvfrom(4096)
            return _dns_wire_extract_a(reply, tx)
    except OSError:
        return []


def _tcp_or_dot_dns(host: str, server: str, port: int, *, use_tls: bool = False, sni: str = "", timeout: float = 2.5) -> list[str]:
    tx, wire = _dns_wire_query(host)
    sock = None
    try:
        sock = socket.create_connection((server, port), timeout=timeout)
        sock.settimeout(timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            conn = ctx.wrap_socket(sock, server_hostname=sni or server)
            sock = None
        else:
            conn = sock
            sock = None
        with conn:
            conn.sendall(struct.pack("!H", len(wire)) + wire)
            hdr = _recv_exact(conn, 2)
            size = struct.unpack("!H", hdr)[0]
            if not 12 <= size <= 4096:
                return []
            reply = _recv_exact(conn, size)
            return _dns_wire_extract_a(reply, tx)
    except Exception:
        return []
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    out = bytearray()
    while len(out) < count:
        chunk = sock.recv(count - len(out))
        if not chunk:
            raise OSError("EOF")
        out.extend(chunk)
    return bytes(out)


def resolve_unpoisoned_ipv4(
    host: str,
    timeout: float = 3.2,
    *,
    disk_cache: dict[str, list[str]] | None = None,
    save_cache: Callable[[str, list[str]], None] | None = None,
) -> list[str]:
    """Race multiple censorship-resistant DNS paths in parallel and reject poisoned IPs."""
    host = str(host or "").strip().lower()
    if not host:
        return []
    try:
        addr = ipaddress.ip_address(host)
        return [str(addr)] if addr.version == 4 else []
    except ValueError:
        pass

    now = time.monotonic()
    with _DNS_LOCK:
        cached = _DNS_MEM_CACHE.get(host)
        if cached and now - cached[0] < 600:
            return list(cached[1])

    probes = (
        lambda: _doh_json_by_ip(host, "8.8.8.8", "/resolve", "dns.google", timeout),
        lambda: _doh_json_by_ip(host, "8.8.4.4", "/resolve", "dns.google", timeout),
        lambda: _doh_json_by_ip(host, "1.1.1.1", "/dns-query", "cloudflare-dns.com", timeout),
        lambda: _doh_json_by_ip(host, "1.0.0.1", "/dns-query", "cloudflare-dns.com", timeout),
        lambda: _udp_dns_port(host, "208.67.222.222", 5353, min(2.2, timeout)),
        lambda: _udp_dns_port(host, "9.9.9.9", 9953, min(2.2, timeout)),
        lambda: _tcp_or_dot_dns(host, "8.8.8.8", 853, use_tls=True, sni="dns.google", timeout=timeout),
        lambda: _tcp_or_dot_dns(host, "1.1.1.1", 853, use_tls=True, sni="cloudflare-dns.com", timeout=timeout),
        lambda: _tcp_or_dot_dns(host, "8.8.8.8", 53, timeout=min(2.2, timeout)),
        lambda: _tcp_or_dot_dns(host, "1.1.1.1", 53, timeout=min(2.2, timeout)),
        lambda: _udp_dns_port(host, "8.8.8.8", 53, min(1.8, timeout)),
    )

    found: list[str] = []
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=len(probes), thread_name_prefix="tor-dns")
    try:
        futs = [pool.submit(fn) for fn in probes]
        deadline = time.monotonic() + timeout
        pending = set(futs)
        while pending and time.monotonic() < deadline:
            done, pending = concurrent.futures.wait(
                pending, timeout=max(0.05, deadline - time.monotonic()),
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            for fut in done:
                try:
                    ips = fut.result()
                except Exception:
                    ips = []
                if ips:
                    found = list(dict.fromkeys(ips))
                    break
            if found:
                break
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    # Final fallback: OS resolver (strictly filtered against 10.10.34.0/24)
    if not found:
        try:
            for _fam, _k, _pr, _cn, sa in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM):
                if _is_valid_public_ipv4(sa[0]) and sa[0] not in found:
                    found.append(sa[0])
        except OSError:
            pass

    if not found and disk_cache and host in disk_cache:
        found = [ip for ip in disk_cache[host] if _is_valid_public_ipv4(ip)]

    if found:
        with _DNS_LOCK:
            _DNS_MEM_CACHE[host] = (time.monotonic(), list(found))
        if save_cache is not None:
            try:
                save_cache(host, found)
            except Exception:
                pass
    return found


# =====================================================================
# TLS ClientHello DPI-Bypass Mutators (UAC OOB + mutator.py vectors)
# =====================================================================

def _locate_sni_4tuple(payload: bytes) -> tuple[int, int, int, int] | None:
    """Returns (ext_type_offset, ext_len_offset, host_start_offset, host_end_offset)."""
    n = len(payload)
    if n < 48 or payload[0] != 0x16 or payload[5] != 0x01:
        return None
    try:
        pos = 43
        pos += 1 + payload[pos]
        pos += 2 + struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 1 + payload[pos]
        ext_total = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2
        limit = min(n, pos + ext_total)
        while pos + 4 <= limit:
            ext_type = struct.unpack("!H", payload[pos:pos + 2])[0]
            ext_len = struct.unpack("!H", payload[pos + 2:pos + 4])[0]
            if ext_type == 0x0000 and pos + 9 <= limit:
                name_len = struct.unpack("!H", payload[pos + 7:pos + 9])[0]
                h_start = pos + 9
                h_end = min(limit, h_start + name_len)
                if h_end > h_start:
                    return pos, pos + 2, h_start, h_end
            pos += 4 + ext_len
    except Exception:
        pass
    return None


def _locate_keyshare_pivot(payload: bytes, fallback: int) -> int:
    n = len(payload)
    if n < 56 or payload[0] != 0x16 or payload[5] != 0x01:
        return fallback
    try:
        pos = 43
        pos += 1 + payload[pos]
        pos += 2 + struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 1 + payload[pos]
        ext_total = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2
        limit = min(n, pos + ext_total)
        while pos + 4 <= limit:
            ext_type = struct.unpack("!H", payload[pos:pos + 2])[0]
            ext_len = struct.unpack("!H", payload[pos + 2:pos + 4])[0]
            if ext_type in (0x0033, 0x002B, 0x000D) and pos > fallback:
                return pos
            pos += 4 + ext_len
    except Exception:
        pass
    return fallback


def _reframe_handshake_records(
    hs_body: bytes,
    chunk_sizes: list[int],
    outer_version: int = 0x0303,
    alternating_versions: tuple[int, int] | None = None,
) -> list[bytes]:
    frames: list[bytes] = []
    pos = 0
    total = len(hs_body)
    idx = 0
    for sz in chunk_sizes:
        if pos >= total:
            break
        step = max(1, min(int(sz), total - pos))
        ver = alternating_versions[idx % len(alternating_versions)] if alternating_versions else outer_version
        frames.append(struct.pack("!BHH", 0x16, ver, step) + hs_body[pos:pos + step])
        pos += step
        idx += 1
    if pos < total:
        rem = total - pos
        ver = alternating_versions[idx % len(alternating_versions)] if alternating_versions else outer_version
        frames.append(struct.pack("!BHH", 0x16, ver, rem) + hs_body[pos:])
    return frames


def _send_oob_segment(sock: socket.socket, segment: bytes, oob_byte: int) -> None:
    if not segment:
        return
    sock.sendall(segment)
    try:
        sock.send(bytes([oob_byte & 0xFF]), socket.MSG_OOB)
    except OSError:
        pass


def transmit_client_hello(
    sock: socket.socket,
    hello: bytes,
    method: str,
    *,
    stride_bytes: int = 400,
    jitter_bytes: int = 20,
) -> None:
    """Transmit TLS ClientHello using UAC native OOB or mutator.py non-fragment bypass vectors."""
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass

    sni = _locate_sni_4tuple(hello)

    # --- 1. UAC Native OOB: disoob_byte0_ttl1 (from pattern_core/core.py) ---
    if method == "uac_disoob_byte0_ttl1":
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
            sock.send(hello[0:1], socket.MSG_OOB)
        finally:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 64)
            except OSError:
                pass
        time.sleep(0.05)
        sock.sendall(hello)
        return

    # --- 2. UAC Native OOB: oob_insni5_ttl1 (from pattern_core/core.py) ---
    if method == "uac_oob_insni5_ttl1":
        off = min(len(hello) - 1, sni[2] + min(5, max(0, (sni[3] - sni[2]) - 1))) if sni else 16
        if off > 0:
            sock.sendall(hello[:off])
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
            sock.send(hello[off:off + 1], socket.MSG_OOB)
        finally:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 64)
            except OSError:
                pass
        time.sleep(0.03)
        sock.sendall(hello[off:])
        return

    # --- 3. UAC Native Dual-OOB: oob2_snitag_host4 (from pattern_core/core.py) ---
    if method == "uac_oob2_snitag_host4" and sni is not None:
        ext_pos, _len_pos, h_start, h_end = sni
        pts = sorted([(ext_pos + 1, 0x78), (min(h_end - 1, h_start + 4), 0x2D)], key=lambda x: x[0])
        cursor = 0
        for off, ghost in pts:
            if off <= cursor or off > len(hello):
                continue
            sock.send(hello[cursor:off] + bytes([ghost]), socket.MSG_OOB)
            time.sleep(0.002)
            cursor = off
        if cursor < len(hello):
            sock.sendall(hello[cursor:])
        return

    # --- 4. mutator.py VEC-01 / VEC-15: OOB at sni_tag + 400B Stride Cut ---
    if method in ("mutator_vec01_oob_400", "mutator_vec15_oob_stride"):
        pre = bytes([0x16, 0x03, 0x04, 0x00, 0x00]) if method == "mutator_vec15_oob_stride" else b""
        mutated = bytearray(hello)
        if len(mutated) >= 5 and mutated[0] == 0x16:
            mutated[1:3] = b"\x03\x04"
        urg_cut = (sni[0] + 2) if sni is not None else min(len(mutated) // 2, 52)
        full_wire = pre + bytes(mutated)
        shifted = urg_cut + len(pre)
        if 0 < shifted < len(full_wire):
            _send_oob_segment(sock, full_wire[:shifted], random.randint(0x41, 0x5A))
            rem = full_wire[shifted:]
            jit = random.randint(-jitter_bytes, jitter_bytes) if jitter_bytes > 0 else 0
            stride = max(120, int(stride_bytes) + jit)
            if len(rem) > stride:
                sock.sendall(rem[:stride])
                time.sleep(0.002)
                sock.sendall(rem[stride:])
            else:
                sock.sendall(rem)
        else:
            sock.sendall(full_wire)
        return

    # --- 5. mutator.py VEC-21: Phantom Seam OOB (3-record SNI envelope + OOB seam) ---
    if method == "mutator_vec21_phantom_oob" and len(hello) > 48 and hello[0] == 0x16:
        hs = hello[5:]
        if sni is not None:
            hs_s = max(4, sni[2] - 5)
            hs_e = max(hs_s + 2, sni[3] - 5)
            half = max(1, (hs_e - hs_s) // 2)
            frames = _reframe_handshake_records(hs, [hs_s, half, max(1, (hs_e - hs_s) - half)], 0x0303)
        else:
            frames = _reframe_handshake_records(hs, [37, 24, 32], 0x0303)
        _send_oob_segment(sock, frames[0], random.randint(0x61, 0x7A))
        sock.sendall(b"".join(frames[1:]))
        return

    # --- 6. mutator.py VEC-26: FastPath Offload Bypass (alternating 0x0301/0x0303 + SO_SNDBUF + OOB) ---
    if method == "mutator_vec26_fastpath_oob" and len(hello) > 48 and hello[0] == 0x16:
        hs = hello[5:]
        if sni is not None:
            hs_s = max(4, sni[2] - 5)
            hs_e = max(hs_s + 2, sni[3] - 5)
            mid = (hs_s + hs_e) // 2
            frames = _reframe_handshake_records(
                hs, [hs_s, max(1, mid - hs_s), max(1, hs_e - mid)], 0x0303, alternating_versions=(0x0301, 0x0303)
            )
        else:
            frames = _reframe_handshake_records(hs, [37, 19, 29], 0x0303, alternating_versions=(0x0301, 0x0303))
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        except OSError:
            pass
        _send_oob_segment(sock, frames[0], random.randint(0x41, 0x5A))
        for fr in frames[1:]:
            sock.sendall(fr)
        return

    # --- 7. mutator.py VEC-24: RFC 4-Record SNI-Dot + KeyShare Framing (pure RFC, no fragment) ---
    if method == "mutator_vec24_rfc_4rec" and len(hello) > 48 and hello[0] == 0x16:
        hs = hello[5:]
        if sni is not None:
            hs_start = max(1, sni[2] - 5)
            hs_end = max(hs_start + 2, sni[3] - 5)
            host_bytes = hs[hs_start:hs_end]
            dots = [i for i, b in enumerate(host_bytes) if b == 0x2E]
            cuts: list[int] = []
            if len(dots) >= 2:
                c1, c2 = hs_start + dots[0] + 1, hs_start + dots[-1]
                if c1 > 0:
                    cuts.append(c1)
                if c2 > c1:
                    cuts.append(c2 - c1)
            else:
                cuts.append(hs_start + max(1, len(host_bytes) // 2))
            consumed = sum(cuts)
            ks_off = _locate_keyshare_pivot(hello, sni[3]) - 5
            if (consumed + 8) < ks_off < (len(hs) - 8):
                cuts.append(ks_off - consumed)
            elif hs_end > consumed:
                cuts.append(hs_end - consumed)
            frames = _reframe_handshake_records(hs, cuts, 0x0303)
        else:
            frames = _reframe_handshake_records(hs, [42, 28, 64], 0x0303)
        if len(frames) >= 2:
            sock.sendall(frames[0] + frames[1])
            if len(frames) > 2:
                sock.sendall(b"".join(frames[2:]))
        else:
            sock.sendall(b"".join(frames))
        return

    # Default direct
    sock.sendall(hello)


def _decode_chunked(body: bytes) -> bytes:
    out = bytearray()
    pos = 0
    while pos < len(body):
        nl = body.find(b"\r\n", pos)
        if nl < 0:
            break
        size_hex = body[pos:nl].split(b";", 1)[0].strip()
        try:
            size = int(size_hex, 16)
        except ValueError:
            break
        if size <= 0:
            break
        start = nl + 2
        end = start + size
        out.extend(body[start:end])
        pos = end + 2
    return bytes(out)


def custom_https_request(
    url: str,
    *,
    method: str = "uac_disoob_byte0_ttl1",
    stride_bytes: int = 400,
    http_method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 6.5,
    resolved_ips: list[str] | None = None,
    upstream_proxy: str = "",
    max_bytes: int = 2 * 1024 * 1024,
) -> tuple[int, dict[str, str], bytes]:
    """Perform HTTPS via MemoryBIO + custom DPI bypass (or upstream proxy if configured)."""
    if upstream_proxy:
        import requests

        sess = requests.Session()
        sess.trust_env = False
        try:
            resp = sess.request(
                http_method,
                url,
                data=body,
                headers={"User-Agent": "Mozilla/5.0 UAC-Tor/1.0", **(headers or {})},
                proxies={"http": upstream_proxy, "https": upstream_proxy},
                timeout=timeout,
            )
            return resp.status_code, {k.lower(): v for k, v in resp.headers.items()}, resp.content[:max_bytes]
        finally:
            sess.close()

    parsed = urlsplit(url)
    host = parsed.hostname or ""
    port = parsed.port or 443
    path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
    targets = list(resolved_ips) if resolved_ips else resolve_unpoisoned_ipv4(host, timeout=min(3.0, timeout))
    if not targets:
        raise OSError(f"Unpoisoned DNS failed for {host}")

    last_exc: Exception | None = None
    for target_ip in targets[:2]:
        sock = None
        try:
            sock = socket.create_connection((target_ip, port), timeout=min(3.5, timeout))
            sock.settimeout(timeout)
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(["http/1.1"])
            inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
            tls = ctx.wrap_bio(inc, out, server_hostname=host)
            first_flight = True
            deadline = time.monotonic() + timeout
            while True:
                if time.monotonic() > deadline:
                    raise TimeoutError("TLS handshake timed out")
                try:
                    tls.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    pass
                pending = out.read()
                if pending:
                    if first_flight:
                        transmit_client_hello(sock, pending, method, stride_bytes=stride_bytes)
                        first_flight = False
                    else:
                        sock.sendall(pending)
                chunk = sock.recv(65536)
                if not chunk:
                    raise ConnectionResetError("Peer closed during TLS handshake")
                inc.write(chunk)
            tail = out.read()
            if tail:
                sock.sendall(tail)

            req_headers = {
                "Host": host,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) UAC-Tor/1.0",
                "Accept": "*/*",
                "Accept-Encoding": "gzip",
                "Connection": "close",
            }
            if headers:
                req_headers.update(headers)
            payload = body or b""
            if payload:
                req_headers.setdefault("Content-Length", str(len(payload)))
            head = f"{http_method} {path} HTTP/1.1\r\n" + "".join(
                f"{k}: {v}\r\n" for k, v in req_headers.items()
            ) + "\r\n"
            tls.write(head.encode("ascii") + payload)
            sock.sendall(out.read())

            raw_resp = bytearray()
            while time.monotonic() <= deadline and len(raw_resp) < max_bytes:
                try:
                    data = tls.read(65536)
                    if not data:
                        break
                    raw_resp.extend(data)
                except ssl.SSLWantReadError:
                    wire = sock.recv(65536)
                    if not wire:
                        break
                    inc.write(wire)
                except ssl.SSLZeroReturnError:
                    break

            header_blob, sep, resp_body = bytes(raw_resp).partition(b"\r\n\r\n")
            if not sep:
                raise OSError("Incomplete HTTP response")
            lines = header_blob.decode("iso-8859-1", errors="replace").split("\r\n")
            status_parts = lines[0].split(" ", 2)
            status_code = int(status_parts[1]) if len(status_parts) >= 2 and status_parts[1].isdigit() else 0
            resp_headers = {}
            for hdr in lines[1:]:
                if ":" in hdr:
                    k, v = hdr.split(":", 1)
                    resp_headers[k.strip().lower()] = v.strip()
            if resp_headers.get("transfer-encoding", "").lower() == "chunked":
                resp_body = _decode_chunked(resp_body)
            if resp_headers.get("content-encoding", "").lower() == "gzip":
                try:
                    resp_body = gzip.decompress(resp_body)
                except OSError:
                    pass
            return status_code, resp_headers, resp_body
        except Exception as exc:
            last_exc = exc
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    raise OSError(f"{method} -> {host} failed: {last_exc}")


def load_local_pt_bridges(transport: str) -> list[str]:
    from .binaries import find_tor_asset
    pt_path = find_tor_asset("pt_config.json")
    if pt_path is None or not pt_path.is_file():
        return []
    try:
        doc = json.loads(pt_path.read_text(encoding="utf-8"))
        items = (doc.get("bridges") or {}).get(transport.lower(), [])
        return [line for raw in items if (line := normalize_bridge_line(str(raw)))]
    except (OSError, ValueError, AttributeError):
        return []


def _parse_moat_json(payload: bytes, transport: str) -> list[str]:
    try:
        doc = json.loads(payload.decode("utf-8", errors="replace"))
    except ValueError:
        return []
    found: list[str] = []
    if isinstance(doc, dict):
        direct_list = doc.get(transport)
        if isinstance(direct_list, list):
            for item in direct_list:
                line = normalize_bridge_line(str(item))
                if line:
                    found.append(line)
        for entry in doc.get("settings") or []:
            if not isinstance(entry, dict):
                continue
            br = entry.get("bridges") or {}
            if isinstance(br, dict) and str(br.get("type", "")).lower() == transport:
                for item in br.get("bridge_strings") or []:
                    line = normalize_bridge_line(str(item))
                    if line:
                        found.append(line)
    return list(dict.fromkeys(found))


def _sources_for_transport(transport: str) -> list[tuple[str, str, str, bytes | None, dict[str, str] | None]]:
    sources: list[tuple[str, str, str, bytes | None, dict[str, str] | None]] = [
        ("moat-builtin", MOAT_BUILTIN_URL, "GET", None, None),
        (
            "moat-settings",
            MOAT_SETTINGS_URL,
            "POST",
            json.dumps({"country": "ir", "transports": [transport]}).encode("utf-8"),
            {"Content-Type": "application/json"},
        ),
    ]
    for idx, url in enumerate(OFFICIAL_BRIDGE_LISTS.get(transport, ()), 1):
        sources.append((f"mirror-{idx}", url, "GET", None, None))
    if transport in ("webtunnel", "obfs4"):
        sources.append(("bridgedb", BRIDGEDB_URL.format(transport=transport), "GET", None, None))
    return sources


def _pre_resolve_hosts(
    urls: list[str],
    *,
    disk_cache: dict[str, list[str]] | None,
    save_cache: Callable[[str, list[str]], None] | None,
    log: LogFn,
) -> dict[str, list[str]]:
    hosts = list(dict.fromkeys((urlsplit(u).hostname or "").lower() for u in urls if urlsplit(u).hostname))
    resolved: dict[str, list[str]] = {}
    if not hosts:
        return resolved
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(hosts), thread_name_prefix="tor-dns-pre") as pool:
        futs = {
            pool.submit(resolve_unpoisoned_ipv4, h, 3.5, disk_cache=disk_cache, save_cache=save_cache): h
            for h in hosts
        }
        for fut in concurrent.futures.as_completed(futs):
            h = futs[fut]
            try:
                ips = fut.result()
            except Exception:
                ips = []
            if ips:
                resolved[h] = ips
    log(f"Tor DNS pre-resolve: {len(resolved)}/{len(hosts)} hosts resolved unpoisoned")
    return resolved


def _methods_for_mode(mode: str, last_winner: str = "") -> list[str]:
    mode = str(mode or "auto").strip().lower()
    groups = {
        "uac_oob": ["uac_disoob_byte0_ttl1", "uac_oob_insni5_ttl1", "uac_oob2_snitag_host4"],
        "mutator_oob_stride": ["mutator_vec01_oob_400", "mutator_vec15_oob_stride"],
        "mutator_phantom": ["mutator_vec21_phantom_oob"],
        "mutator_fastpath": ["mutator_vec26_fastpath_oob"],
        "mutator_rfc4rec": ["mutator_vec24_rfc_4rec"],
        "direct": ["direct"],
        "relay": [],
    }
    if mode in groups:
        return groups[mode]
    ordered = [
        "uac_disoob_byte0_ttl1",
        "mutator_vec01_oob_400",
        "mutator_vec21_phantom_oob",
        "uac_oob_insni5_ttl1",
        "mutator_vec15_oob_stride",
        "mutator_vec26_fastpath_oob",
        "mutator_vec24_rfc_4rec",
        "uac_oob2_snitag_host4",
        "direct",
    ]
    if last_winner in ordered:
        ordered.remove(last_winner)
        ordered.insert(0, last_winner)
    return ordered


def _fetch_via_relay(
    transport: str,
    custom_relay: str,
    data_dir: Path | None,
    cancel: threading.Event,
    log: LogFn,
    *,
    stride_bytes: int = 400,
    upstream_proxy: str = "",
    timeout: float = 7.0,
) -> BridgeFetchResult | None:
    relays = []
    if custom_relay and custom_relay.lower().startswith("https://"):
        relays.append(custom_relay.strip())
    for url in relay_urls(data_dir):
        if url not in relays:
            relays.append(url)
    for base in relays:
        if cancel.is_set():
            return None
        targets = [base] if base.lower().endswith((".txt", ".json")) else [
            f"{base.rstrip('/')}/tor-bridges?transport={quote(transport)}",
            f"{base.rstrip('/')}/?url={quote(MOAT_BUILTIN_URL, safe='')}",
        ]
        for url in targets:
            if cancel.is_set():
                return None
            for delivery in ("direct", "uac_disoob_byte0_ttl1", "mutator_vec01_oob_400"):
                try:
                    code, _rh, raw = custom_https_request(
                        url, method=delivery, stride_bytes=stride_bytes,
                        upstream_proxy=upstream_proxy, timeout=timeout,
                    )
                    if 200 <= code < 300:
                        lines = _parse_moat_json(raw, transport) or extract_bridges_from_text(
                            raw.decode("utf-8", errors="replace"), transport
                        )
                        if lines:
                            log(f"Tor bridges: fetched {len(lines)} {transport} bridge(s) via relay ({delivery})")
                            return BridgeFetchResult(tuple(lines), transport, f"relay:{delivery}", base, f"HTTP {code}")
                except Exception:
                    continue
    return None


def auto_fetch_bridges(
    transport: str,
    *,
    source: str = "auto",
    mode: str = "auto",
    stride_bytes: int = 400,
    custom_relay: str = "",
    upstream_proxy: str = "",
    data_dir: Path | None = None,
    last_winner: str = "",
    dns_cache: dict[str, list[str]] | None = None,
    save_dns_cache: Callable[[str, list[str]], None] | None = None,
    cancel: threading.Event | None = None,
    log: LogFn | None = None,
    timeout: float = 6.0,
) -> BridgeFetchResult:
    """Fetch bridges from chosen source (auto/moat/mirrors/relay/bundled) with silent OOB/Mutator bypass."""
    transport = str(transport or "webtunnel").strip().lower()
    if transport not in ("webtunnel", "obfs4", "snowflake"):
        transport = "webtunnel"
    source = str(source or "auto").strip().lower()
    cancel = cancel or threading.Event()
    log = log or (lambda _m: None)

    log(f"Tor bridge fetch: transport={transport} source={source}")

    if source == "bundled":
        local_lines = load_local_pt_bridges(transport)
        if local_lines:
            return BridgeFetchResult(tuple(local_lines), transport, "bundled", "bundled", "local pt_config.json")
        if transport == "snowflake":
            return BridgeFetchResult(DEFAULT_SNOWFLAKE_BRIDGES, "snowflake", "builtin", "bundled", "snowflake default")
        return BridgeFetchResult(transport=transport, detail="No bundled bridges for this transport")

    if source == "relay":
        rel_res = _fetch_via_relay(
            transport, custom_relay, data_dir, cancel, log,
            stride_bytes=stride_bytes, upstream_proxy=upstream_proxy, timeout=timeout,
        )
        return rel_res if (rel_res and rel_res.ok) else BridgeFetchResult(transport=transport, detail="Relay unavailable")

    all_sources = _sources_for_transport(transport)
    if source == "moat":
        chosen_sources = [s for s in all_sources if s[0].startswith("moat") or s[0] == "bridgedb"]
    elif source == "mirrors":
        chosen_sources = [s for s in all_sources if s[0].startswith("mirror")]
    else:
        chosen_sources = all_sources

    resolved_map = {} if upstream_proxy else _pre_resolve_hosts(
        [u for _n, u, _v, _b, _h in chosen_sources],
        disk_cache=dns_cache,
        save_cache=save_dns_cache,
        log=log,
    )

    # Silent automatic DPI bypass ladder (prioritizes fastest proven non-fragment vectors)
    silent_methods = ["proxy"] if upstream_proxy else [
        "mutator_vec26_fastpath_oob",
        "mutator_vec24_rfc_4rec",
        "mutator_vec15_oob_stride",
        "mutator_vec01_oob_400",
        "uac_disoob_byte0_ttl1",
        "uac_oob_insni5_ttl1",
        "mutator_vec21_phantom_oob",
        "direct",
    ]
    if last_winner in silent_methods:
        silent_methods.remove(last_winner)
        silent_methods.insert(0, last_winner)

    collected: list[str] = []
    win_method = ""
    win_source = ""
    for method in silent_methods:
        if cancel.is_set():
            return BridgeFetchResult(transport=transport, detail="cancelled")
        for src_name, url, verb, body, hdrs in chosen_sources:
            if cancel.is_set():
                return BridgeFetchResult(transport=transport, detail="cancelled")
            host = (urlsplit(url).hostname or "").lower()
            ips = resolved_map.get(host, [])
            if not upstream_proxy and not ips:
                continue
            try:
                code, _rh, raw = custom_https_request(
                    url,
                    method=method,
                    stride_bytes=stride_bytes,
                    http_method=verb,
                    body=body,
                    headers=hdrs,
                    resolved_ips=ips,
                    upstream_proxy=upstream_proxy,
                    timeout=timeout,
                )
                if 200 <= code < 300:
                    lines = (
                        _parse_moat_json(raw, transport)
                        if src_name.startswith("moat")
                        else extract_bridges_from_text(raw.decode("utf-8", errors="replace"), transport)
                    )
                    if lines:
                        if not win_method:
                            win_method = method
                            win_source = src_name
                        for ln in lines:
                            if ln not in collected:
                                collected.append(ln)
                        log(f"Tor bridges: +{len(lines)} {transport} bridge(s) from {src_name}")
                        # Stop early once we have a healthy pool (>= 4) or non-auto single source
                        if len(collected) >= 4 or source != "auto":
                            return BridgeFetchResult(tuple(collected), transport, win_method, win_source, f"HTTP {code}")
            except Exception:
                continue
        if collected:
            return BridgeFetchResult(tuple(collected), transport, win_method, win_source, "OK")

    if source == "auto" and not cancel.is_set():
        rel_res = _fetch_via_relay(
            transport, custom_relay, data_dir, cancel, log,
            stride_bytes=stride_bytes, upstream_proxy=upstream_proxy, timeout=timeout,
        )
        if rel_res and rel_res.ok:
            return rel_res

    local_lines = load_local_pt_bridges(transport)
    if local_lines:
        log(f"Tor bridges: using {len(local_lines)} bundled {transport} bridge(s)")
        return BridgeFetchResult(tuple(local_lines), transport, "bundled", "bundled", "local fallback")

    if transport == "snowflake":
        return BridgeFetchResult(DEFAULT_SNOWFLAKE_BRIDGES, "snowflake", "builtin", "bundled", "fallback")

    return BridgeFetchResult(transport=transport, detail=f"No {transport} bridges could be fetched")

def rank_reachable_bridges(
    bridges: list[str],
    *,
    timeout: float = 2.5,
    max_workers: int = 12,
    cancel: threading.Event | None = None,
) -> list[tuple[str, int]]:
    cancel = cancel or threading.Event()
    results: list[tuple[str, int]] = []

    def check(line: str) -> tuple[str, int]:
        if cancel.is_set():
            return line, 0
        tr = bridge_transport(line)
        if tr == "snowflake":
            return line, 1
        ep = bridge_endpoint(line)
        if ep is None:
            return line, 0
        host, port = ep
        if tr == "webtunnel":
            m = re.search(r"\burl=https?://([^/\s:]+)(?::(\d+))?", line)
            if m:
                host = m.group(1)
                port = int(m.group(2) or 443)
                ips = resolve_unpoisoned_ipv4(host, timeout=min(2.2, timeout))
                if ips:
                    host = ips[0]
        started = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return line, max(1, int((time.perf_counter() - started) * 1000))
        except OSError:
            return line, 0

    if not bridges:
        return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, len(bridges))) as pool:
        for line, ms in pool.map(check, bridges):
            if ms > 0:
                results.append((line, ms))
    results.sort(key=lambda item: item[1])
    return results
