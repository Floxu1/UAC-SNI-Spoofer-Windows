"""Optional UAC PoW speed features (all off by default).

- ``StickyRouter``: a loopback SOCKS5 front that spreads connections across
  several MASQUE sessions (parallel aether instances). The destination host
  decides the session (hash), so one site/video stays on one session; a
  session that refuses a connection is skipped for a while (failover).
- Clean-IP latency helpers: measure TCP connect RTT to saved clean MASQUE
  HTTP/2 addresses and keep the saved list ordered lowest-RTT first. The core
  tries that list in order, so the next connect starts on the fastest one.
"""

from __future__ import annotations

import json
import re
import socket
import threading
import time
import zlib
from pathlib import Path
from typing import Callable, Iterable

# ---------------------------------------------------------------------------
# Clean-IP latency
# ---------------------------------------------------------------------------

CLEAN_H2_FILENAME = "uac-pow-clean-h2.json"
#: Extra time the lowest-latency pick may add to a connect.
RANK_CAP_S = 2.0
#: How long connect waits for network detection before using "default".
NETWORK_WAIT_S = 0.8
#: Background re-measure period while connected.
REMEASURE_PERIOD_S = 240.0
POOL_LIMIT = 12

_ACCEPT_RE = re.compile(
    r"^(?:Accepted|Saved clean HTTP/2 address|Saved clean address accepted|Selected)\s+(\[[0-9a-fA-F:]+\]:\d+|\d{1,3}(?:\.\d{1,3}){3}:\d+)"
)


def accepted_peer(line: str) -> str:
    """Peer from a core line that reports an accepted MASQUE HTTP/2 address."""
    match = _ACCEPT_RE.match((line or "").strip())
    return match.group(1) if match else ""


def harvest_core_log(data_dir: Path, limit: int = 16, tail_bytes: int = 1_500_000) -> list[str]:
    """Clean HTTP/2 addresses the core accepted in earlier scans (newest first).

    The core keeps only the winner in its saved list, so a network that
    connects on the saved address never produces a second one. Its own log
    still lists every gateway an earlier scan accepted.
    """
    path = Path(data_dir) / "aether-core.log"
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            handle.seek(max(0, size - tail_bytes))
            text = handle.read().decode("utf-8", "replace")
    except OSError:
        return []
    found: list[str] = []
    for line in reversed(text.splitlines()):
        body = line[10:].strip() if len(line) > 10 and line[2:3] == ":" and line[5:6] == ":" else line.strip()
        peer = accepted_peer(body)
        if peer and peer not in found:
            found.append(peer)
            if len(found) >= limit:
                break
    return found


def split_peer(peer: str) -> tuple[str, int] | None:
    text = (peer or "").strip()
    try:
        if text.startswith("["):
            host, _, port = text[1:].partition("]:")
        else:
            host, _, port = text.rpartition(":")
        return (host, int(port)) if host and port else None
    except ValueError:
        return None


def tcp_rtt_ms(peer: str, timeout: float = RANK_CAP_S) -> int:
    parts = split_peer(peer)
    if parts is None:
        return 0
    started = time.monotonic()
    try:
        with socket.create_connection(parts, timeout=timeout):
            return max(1, int((time.monotonic() - started) * 1000))
    except OSError:
        return 0


def rank_peers(
    peers: Iterable[str],
    cap_s: float = RANK_CAP_S,
    probe: Callable[[str, float], int] = tcp_rtt_ms,
) -> list[tuple[str, int]]:
    """Probe peers in parallel within ``cap_s``; answered peers, lowest RTT first."""
    unique = list(dict.fromkeys(p for p in peers if p))
    results: dict[str, int] = {}
    lock = threading.Lock()

    def _one(peer: str) -> None:
        rtt = probe(peer, cap_s)
        if rtt > 0:
            with lock:
                results[peer] = rtt

    threads = [threading.Thread(target=_one, args=(p,), daemon=True) for p in unique]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + cap_s
    for thread in threads:
        thread.join(max(0.0, deadline - time.monotonic()))
    with lock:
        return sorted(results.items(), key=lambda item: item[1])


def clean_h2_path(data_dir: Path) -> Path:
    return Path(data_dir) / CLEAN_H2_FILENAME


def read_clean_list(data_dir: Path) -> list[str]:
    try:
        doc = json.loads(clean_h2_path(data_dir).read_text(encoding="utf-8"))
        return [str(p) for p in doc.get("peers", []) if split_peer(str(p))]
    except Exception:
        return []


def write_clean_list(data_dir: Path, peers: list[str]) -> None:
    path = clean_h2_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"peers": list(dict.fromkeys(peers))[:16]}), encoding="utf-8")
    tmp.replace(path)


def ordered_clean_list(saved: list[str], ranked: list[tuple[str, int]]) -> list[str]:
    """Ranked (answered) peers first by RTT, then the rest in their saved order."""
    first = [peer for peer, _ in ranked]
    return first + [peer for peer in saved if peer not in first]


# ---------------------------------------------------------------------------
# Sticky SOCKS5 router (parallel MASQUE)
# ---------------------------------------------------------------------------

ROUTER_PORT = 1825
EXTRA_PORTS = (1830, 1831)
_DOWN_FOR_S = 30.0
_BUFFER = 65536


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("closed")
        data += chunk
    return data


def _read_request(sock: socket.socket) -> tuple[bytes, str]:
    """Read a SOCKS5 request. Returns (raw bytes, destination host key)."""
    head = _recv_exact(sock, 4)
    if head[0] != 0x05:
        raise OSError("not socks5")
    atyp = head[3]
    if atyp == 0x01:
        addr = _recv_exact(sock, 4)
        host = socket.inet_ntoa(addr)
    elif atyp == 0x03:
        length = _recv_exact(sock, 1)
        addr = length + _recv_exact(sock, length[0])
        host = addr[1:].decode("ascii", "replace").lower()
    elif atyp == 0x04:
        addr = _recv_exact(sock, 16)
        host = socket.inet_ntop(socket.AF_INET6, addr)
    else:
        raise OSError("bad address type")
    port = _recv_exact(sock, 2)
    return head + addr + port, host


def _read_reply(sock: socket.socket) -> bytes:
    head = _recv_exact(sock, 4)
    atyp = head[3]
    if atyp == 0x01:
        rest = _recv_exact(sock, 4 + 2)
    elif atyp == 0x04:
        rest = _recv_exact(sock, 16 + 2)
    elif atyp == 0x03:
        length = _recv_exact(sock, 1)
        rest = length + _recv_exact(sock, length[0] + 2)
    else:
        raise OSError("bad reply")
    return head + rest


def sticky_index(host: str, count: int) -> int:
    """Same host -> same session, stable across connections."""
    if count <= 1:
        return 0
    key = host.lower()
    # Keep subdomains of one site together (www.x.com / i.x.com / x.com).
    labels = key.split(".")
    if len(labels) > 2 and not key.replace(".", "").isdigit():
        key = ".".join(labels[-2:])
    return zlib.crc32(key.encode("utf-8")) % count


class StickyRouter:
    """Loopback SOCKS5 server that forwards each connection to one upstream
    SOCKS5 (an aether session) chosen by destination host."""

    def __init__(
        self,
        listen_port: int,
        upstream_ports: list[int],
        log: Callable[[str], None] | None = None,
    ) -> None:
        self.listen_port = listen_port
        self.upstreams = list(upstream_ports)
        self._log = log or (lambda _m: None)
        self._down: dict[int, float] = {}
        self._stop = threading.Event()
        self._server: socket.socket | None = None
        self._lock = threading.Lock()
        self.counts = [0] * len(self.upstreams)

    def start(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", self.listen_port))
        server.listen(128)
        server.settimeout(0.5)
        self._server = server
        threading.Thread(target=self._accept_loop, name="pow-sticky-router", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        server, self._server = self._server, None
        if server is not None:
            try:
                server.close()
            except OSError:
                pass

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            server = self._server
            if server is None:
                return
            try:
                client, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    def add_upstream(self, port: int) -> None:
        """Add a session; only new connections can land on it (sticky)."""
        with self._lock:
            if port not in self.upstreams:
                self.upstreams.append(port)
                self.counts.append(0)

    def order_for(self, host: str) -> list[int]:
        with self._lock:
            count = len(self.upstreams)
        first = sticky_index(host, count)
        order = [first] + [i for i in range(count) if i != first]
        now = time.monotonic()
        with self._lock:
            healthy = [i for i in order if self._down.get(i, 0.0) <= now]
        return healthy + [i for i in order if i not in healthy]

    def _serve(self, client: socket.socket) -> None:
        upstream = None
        try:
            client.settimeout(15)
            greeting = _recv_exact(client, 2)
            _recv_exact(client, greeting[1])
            client.sendall(b"\x05\x00")
            request, host = _read_request(client)
            reply = b""
            for index in self.order_for(host):
                try:
                    upstream = socket.create_connection(("127.0.0.1", self.upstreams[index]), timeout=10)
                    upstream.sendall(b"\x05\x01\x00")
                    if _recv_exact(upstream, 2) != b"\x05\x00":
                        raise OSError("upstream refused auth")
                    upstream.sendall(request)
                    reply = _read_reply(upstream)
                    if reply[1] != 0x00:
                        raise OSError(f"upstream connect failed ({reply[1]})")
                    with self._lock:
                        self.counts[index] += 1
                        self._down.pop(index, None)
                    break
                except OSError:
                    with self._lock:
                        self._down[index] = time.monotonic() + _DOWN_FOR_S
                    if upstream is not None:
                        try:
                            upstream.close()
                        except OSError:
                            pass
                    upstream = None
                    reply = reply or b""
            if upstream is None:
                client.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            client.sendall(reply)
            # Sticky for the whole connection: never re-routed, no idle timeout.
            from .forwarder import make_long_lived

            make_long_lived(client, upstream)
            self._pipe(client, upstream)
        except Exception:
            pass
        finally:
            for sock in (client, upstream):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass

    def _pipe(self, a: socket.socket, b: socket.socket) -> None:
        def _copy(src: socket.socket, dst: socket.socket) -> None:
            try:
                while not self._stop.is_set():
                    chunk = src.recv(_BUFFER)
                    if not chunk:
                        break
                    dst.sendall(chunk)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        other = threading.Thread(target=_copy, args=(b, a), daemon=True)
        other.start()
        _copy(a, b)
        other.join()


# ---------------------------------------------------------------------------
# Exit / session info (Cloudflare trace through a local SOCKS5)
# ---------------------------------------------------------------------------

#: Cloudflare colo (IATA) -> country, for the edges users here usually land on.
COLO_COUNTRY = {
    "FRA": "DE", "DUS": "DE", "HAM": "DE", "MUC": "DE", "TXL": "DE", "BER": "DE", "STR": "DE",
    "AMS": "NL", "LHR": "GB", "MAN": "GB", "EDI": "GB", "CDG": "FR", "MRS": "FR", "LYS": "FR",
    "VIE": "AT", "ZRH": "CH", "GVA": "CH", "MXP": "IT", "FCO": "IT", "PMO": "IT", "MAD": "ES",
    "BCN": "ES", "LIS": "PT", "BRU": "BE", "CPH": "DK", "ARN": "SE", "GOT": "SE", "OSL": "NO",
    "HEL": "FI", "WAW": "PL", "PRG": "CZ", "BUD": "HU", "OTP": "RO", "SOF": "BG", "BEG": "RS",
    "ATH": "GR", "SKG": "GR", "KBP": "UA", "KIV": "MD", "RIX": "LV", "VNO": "LT", "TLL": "EE",
    "DUB": "IE", "KEF": "IS", "IST": "TR", "ADB": "TR", "ESB": "TR", "TLV": "IL", "AMM": "JO",
    "DXB": "AE", "FJR": "AE", "AUH": "AE", "DOH": "QA", "BAH": "BH", "KWI": "KW", "MCT": "OM",
    "RUH": "SA", "JED": "SA", "DMM": "SA", "BGW": "IQ", "BSR": "IQ", "EBL": "IQ", "ISU": "IQ",
    "NJF": "IQ", "XNH": "IQ", "TBS": "GE", "EVN": "AM", "GYD": "AZ", "ALA": "KZ", "NQZ": "KZ",
    "TAS": "UZ", "KHI": "PK", "LHE": "PK", "ISB": "PK", "BOM": "IN", "DEL": "IN", "MAA": "IN",
    "BLR": "IN", "HYD": "IN", "CCU": "IN", "SIN": "SG", "HKG": "HK", "NRT": "JP", "KIX": "JP",
    "ICN": "KR", "TPE": "TW", "KUL": "MY", "BKK": "TH", "CGK": "ID", "MNL": "PH", "SYD": "AU",
    "MEL": "AU", "AKL": "NZ", "IAD": "US", "EWR": "US", "ORD": "US", "DFW": "US", "LAX": "US",
    "SJC": "US", "SEA": "US", "ATL": "US", "MIA": "US", "YYZ": "CA", "YUL": "CA", "GRU": "BR",
    "EZE": "AR", "SCL": "CL", "MEX": "MX", "JNB": "ZA", "CPT": "ZA", "CAI": "EG", "LOS": "NG",
    "NBO": "KE",
}

TRACE_HOST = "www.cloudflare.com"


def parse_trace(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key in ("ip", "loc", "colo", "warp"):
            out[key] = value.strip()
    return out


def colo_country(colo: str) -> str:
    return COLO_COUNTRY.get((colo or "").strip().upper(), "")


def cf_trace(socks_port: int, timeout: float = 8.0) -> dict[str, str]:
    """GET https://www.cloudflare.com/cdn-cgi/trace through a local SOCKS5.

    Returns ip/loc/colo of the egress that carried the request, {} on failure.
    One small request; callers cache the result per connect.
    """
    import ssl

    try:
        raw = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
    except OSError:
        return {}
    try:
        raw.settimeout(timeout)
        raw.sendall(b"\x05\x01\x00")
        if _recv_exact(raw, 2) != b"\x05\x00":
            return {}
        name = TRACE_HOST.encode("ascii")
        raw.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + (443).to_bytes(2, "big"))
        reply = _read_reply(raw)
        if reply[1] != 0x00:
            return {}
        context = ssl.create_default_context()
        with context.wrap_socket(raw, server_hostname=TRACE_HOST) as tls:
            tls.sendall(
                f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {TRACE_HOST}\r\n"
                "User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode("ascii")
            )
            data = b""
            while len(data) < 16384:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                data += chunk
        body = data.split(b"\r\n\r\n", 1)[-1].decode("utf-8", "replace")
        return parse_trace(body)
    except Exception:
        return {}
    finally:
        try:
            raw.close()
        except OSError:
            pass
