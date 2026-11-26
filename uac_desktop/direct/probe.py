from __future__ import annotations

import http.client
import ipaddress
import secrets
import socket
import ssl
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from io import BytesIO
from statistics import median
from urllib.parse import urlsplit

import dns.exception
import dns.message
import dns.rdatatype

from .carrier import ensure_active
from .resolvers import RESOLVERS, Resolver

PROBE_URLS = (
    "https://m.youtube.com/robots.txt", "https://x.com/robots.txt",
    "https://www.google.com/robots.txt", "https://www.cloudflare.com/cdn-cgi/trace",
)




@dataclass(frozen=True)
class ProbeResult:
    ok: bool
    detail: str


def recv_exact(sock: socket.socket, count: int) -> bytes:
    received = bytearray()
    while len(received) < count:
        part = sock.recv(count - len(received))
        if not part:
            raise OSError("Unexpected EOF")
        received.extend(part)
    return bytes(received)


def _socks_endpoint(host: str, port: int) -> bytes:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        name = host.encode("idna")
        target = bytes((3, len(name))) + name
    else:
        target = bytes((1 if address.version == 4 else 4,)) + address.packed
    return target + struct.pack("!H", port)


def _read_socks_endpoint(kind, read) -> tuple[str, int]:
    if kind == 3:
        host = read(read(1)[0]).decode("idna")
    elif kind in (1, 4):
        host = str(ipaddress.ip_address(read(4 if kind == 1 else 16)))
    else:
        raise OSError("Unsupported SOCKS address type")
    return host, int.from_bytes(read(2), "big")


def _socks_request(port, command, host, target_port, timeout):
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise OSError("SOCKS authentication rejected")
        sock.sendall(bytes((5, command, 0)) + _socks_endpoint(host, target_port))
        version, reply, _, kind = recv_exact(sock, 4)
        if version != 5 or reply:
            raise OSError(f"SOCKS request failed code={reply}")
        endpoint = _read_socks_endpoint(kind, lambda count: recv_exact(sock, count))
        return sock, endpoint
    except BaseException:
        sock.close()
        raise


def connect_socks(port: int, host: str, target_port: int, timeout: float) -> socket.socket:
    sock, _ = _socks_request(port, 1, host, target_port, timeout)
    return sock


class _HTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, socks_port: int, timeout: float, context: ssl.SSLContext) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._socks_port = socks_port

    def connect(self) -> None:
        if not self._socks_port:
            super().connect()
            return
        raw = connect_socks(self._socks_port, self.host, self.port, self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def _query(host: str, transaction: int) -> bytes:
    query = dns.message.make_query(host, dns.rdatatype.A, id=transaction)
    return query.to_wire()


def answers_with_public_ipv4(query: bytes, response: bytes) -> bool:
    if len(query) < 12 or not len(query) <= len(response) <= 4096:
        return False
    tx, flags, questions = struct.unpack_from("!HHH", response)
    if tx != struct.unpack_from("!H", query)[0] or flags & 0xFA0F != 0x8000 or questions != 1:
        return False
    if query[12:] != response[12:len(query)]:
        return False
    try:
        message = dns.message.from_wire(response)
    except (dns.exception.DNSException, ValueError):
        return False
    for answer in message.answer:
        if answer.rdclass != 1 or answer.rdtype != dns.rdatatype.A:
            continue
        for item in answer:
            a, b, _, _ = ipaddress.IPv4Address(item.address).packed
            if (1 <= a <= 223 and a not in (10, 127)
                    and (a, b) not in ((169, 254), (192, 168)) and not (a == 172 and 16 <= b <= 31)):
                return True
    return False


_DNS_TEST_HOSTS = ("www.google.com", "m.youtube.com")


@dataclass(frozen=True)
class ResolverMeasurement:
    resolver: Resolver
    samples: tuple[int, ...]
    attempts: int

    @property
    def latency(self) -> int | None:
        return int(median(self.samples)) if self.samples else None

    @property
    def rank(self) -> tuple[int, int]:
        return (-len(self.samples), self.latency or 0)


def _tcp_dns_exchange(host, port, socks_port, query):
    connection = (connect_socks(socks_port, host, port, 2.5) if socks_port
                  else socket.create_connection((host, port), timeout=2.5))
    with connection as sock:
        sock.sendall(struct.pack("!H", len(query)) + query)
        size = struct.unpack("!H", recv_exact(sock, 2))[0]
        return recv_exact(sock, size) if 12 <= size <= 4096 else b""


def _udp_exchange(host, port, payload, limit):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2.5)
        sock.connect((host, port))
        sock.sendall(payload)
        return sock.recv(limit)


def _udp_dns_exchange(host, port, socks_port, query):
    if not socks_port:
        return _udp_exchange(host, port, query, 4097)
    control, (relay_host, relay_port) = _socks_request(socks_port, 3, "0.0.0.0", 0, 2.5)
    with control:
        if relay_host in ("0.0.0.0", "::", "localhost"):
            relay_host = control.getpeername()[0]
        if not relay_port or not ipaddress.ip_address(relay_host).is_loopback:
            raise OSError("SOCKS UDP relay is not on loopback")
        payload = b"\0\0\0" + _socks_endpoint(host, port) + query
        response = _udp_exchange(relay_host, relay_port, payload, 4360)
    if len(response) < 10 or response[:3] != b"\0\0\0":
        raise OSError("Invalid SOCKS UDP response")
    data = BytesIO(response[4:])
    if _read_socks_endpoint(response[3], data.read) != (host, port):
        raise OSError("SOCKS UDP response came from another destination")
    return data.read()


def _dns_exchange(resolver: Resolver, socks_port: int, query: bytes, context: ssl.SSLContext) -> bytes:
    target = urlsplit(resolver.url)
    if resolver.protocol == "TCP":
        return _tcp_dns_exchange(resolver.host, target.port or 53, socks_port, query)
    if resolver.protocol == "UDP":
        port = target.port or 53
        reply = _udp_dns_exchange(resolver.host, port, socks_port, query)
        if len(reply) >= 4 and reply[:2] == query[:2] and reply[2] & 0x82 == 0x82:
            return _tcp_dns_exchange(resolver.host, port, socks_port, query)
        return reply
    connection = _HTTPSConnection(resolver.host, target.port or 443, socks_port, 2.5, context)
    try:
        path = target.path + ("?" + target.query if target.query else "")
        connection.request("POST", path, body=query, headers={
            "Accept": "application/dns-message", "Content-Type": "application/dns-message",
            "Connection": "close",
        })
        with connection.getresponse() as response:
            kind = (response.getheader("Content-Type") or "").partition(";")[0].strip().lower()
            return response.read(4097) if response.status == 200 and kind == "application/dns-message" else b""
    finally:
        connection.close()


def scan_dns(resolvers, socks_port: int, cancel: threading.Event, *, rounds=2, progress=None) -> list[ResolverMeasurement]:
    if not resolvers:
        return []
    context = ssl.create_default_context()
    hosts = _DNS_TEST_HOSTS * rounds

    def measure(resolver: Resolver) -> ResolverMeasurement:
        samples = []
        for host in hosts:
            ensure_active(cancel)
            query = _query(host, secrets.randbelow(65536))
            started = time.monotonic()
            try:
                reply = _dns_exchange(resolver, socks_port, query, context)
                if answers_with_public_ipv4(query, reply):
                    samples.append(max(1, round((time.monotonic() - started) * 1000)))
            except (OSError, http.client.HTTPException, ValueError):
                continue
        return ResolverMeasurement(resolver, tuple(samples), len(hosts))

    pool = ThreadPoolExecutor(max_workers=min(8, len(resolvers)))
    results = []
    try:
        futures = [pool.submit(measure, resolver) for resolver in resolvers]
        for future in as_completed(futures):
            ensure_active(cancel)
            result = future.result()
            results.append(result)
            if progress:
                progress(result)
        ensure_active(cancel)
    finally:
        pool.shutdown(cancel_futures=True)
    return sorted(results, key=lambda item: item.rank)


def select_dns(socks_port: int, cancel: threading.Event, resolvers=RESOLVERS) -> tuple[Resolver, int] | None:
    results = scan_dns(resolvers, socks_port, cancel, rounds=1)
    return next(((result.resolver, result.latency) for result in results
                 if len(result.samples) == result.attempts), None)


def verify_dns(socks_port: int, server: str, timeout: float = 4) -> ProbeResult:
    started = time.monotonic()
    transaction = secrets.randbelow(65536)
    query = _query("connectivitycheck.gstatic.com", transaction)
    try:
        connection = (connect_socks(socks_port, server, 53, timeout) if socks_port
                      else socket.create_connection((server, 53), timeout=timeout))
        with connection as sock:
            sock.sendall(struct.pack("!H", len(query)) + query)
            length = struct.unpack("!H", recv_exact(sock, 2))[0]
            if not 12 <= length <= 4096:
                raise OSError("Invalid DNS response length")
            data = recv_exact(sock, length)
        tx, flags, _, answers = struct.unpack_from("!HHHH", data)
        if tx != transaction:
            raise OSError("DNS transaction mismatch")
        elapsed = int((time.monotonic() - started) * 1000)
        rcode = flags & 15
        return ProbeResult(bool(flags & 0x8000 and rcode == 0 and answers),
                           f"DNS rcode={rcode} answers={answers} elapsed_ms={elapsed}")
    except (OSError, ValueError) as error:
        return ProbeResult(False, f"DNS={error}")


def verify_https(url: str, socks_port: int, timeout: float = 4, *,
                 context: ssl.SSLContext | None = None) -> ProbeResult:
    target = urlsplit(url)
    started = time.monotonic()
    connection = _HTTPSConnection(target.hostname, target.port or 443, socks_port, timeout,
                                  context or ssl.create_default_context())
    try:
        path = target.path or "/"
        if target.query:
            path += "?" + target.query
        connection.request("GET", path, headers={"Connection": "close"})
        with connection.getresponse() as response:
            payload = response.read1(256) if 200 <= response.status <= 299 else b""
            elapsed = int((time.monotonic() - started) * 1000)
            return ProbeResult(bool(payload), f"{target.hostname}={response.status}/{len(payload)}B/{elapsed}ms")
    except (OSError, http.client.HTTPException) as error:
        detail = str(error).partition("\n")[0][:120] or type(error).__name__
        return ProbeResult(False, f"{target.hostname}={detail}")
    finally:
        connection.close()


def verify_payload(socks_port: int, dns_server: str, cancel: threading.Event) -> ProbeResult:
    ensure_active(cancel)
    context = ssl.create_default_context()
    with ThreadPoolExecutor(max_workers=1 + len(PROBE_URLS)) as pool:
        dns_probe = pool.submit(verify_dns, socks_port, dns_server)
        https_probes = [pool.submit(verify_https, url, socks_port, context=context) for url in PROBE_URLS]
        dns_result = dns_probe.result()
        https_results = [probe.result() for probe in https_probes]
    ensure_active(cancel)
    return ProbeResult(dns_result.ok and any(result.ok for result in https_results),
                       dns_result.detail + "; " + " ".join(result.detail for result in https_results))


def trace(socks_port: int, timeout: float = 5) -> dict[str, str]:
    host = "www.cloudflare.com"
    connection = _HTTPSConnection(host, 443, socks_port, timeout, ssl.create_default_context())
    try:
        connection.request("GET", "/cdn-cgi/trace", headers={"Connection": "close"})
        with connection.getresponse() as response:
            if response.status != 200:
                raise OSError(f"Exit check returned HTTP {response.status}")
            text = response.read(4096).decode("ascii", errors="replace")
        return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    finally:
        connection.close()


def verify_http_proxy(port: int, timeout: float = 4) -> ProbeResult:
    host = "www.cloudflare.com"
    connection = http.client.HTTPSConnection("127.0.0.1", port, timeout=timeout)
    connection.set_tunnel(host, 443)
    try:
        connection.request("GET", "/cdn-cgi/trace", headers={"Connection": "close"})
        with connection.getresponse() as response:
            valid = 200 <= response.status <= 299 and bool(response.read1(256))
            return ProbeResult(valid, f"HTTP CONNECT payload HTTP {response.status}")
    except (OSError, http.client.HTTPException) as error:
        return ProbeResult(False, f"HTTP CONNECT failed: {error}")
    finally:
        connection.close()
