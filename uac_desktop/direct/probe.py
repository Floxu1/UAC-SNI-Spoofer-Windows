from __future__ import annotations

import http.client
import ipaddress
import secrets
import socket
import ssl
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from urllib.parse import urlsplit

import dns.exception
import dns.message
import dns.rdatatype

from .carrier import ensure_active

PROBE_URLS = (
    "https://m.youtube.com/robots.txt", "https://x.com/robots.txt",
    "https://www.google.com/robots.txt", "https://www.cloudflare.com/cdn-cgi/trace",
)


@dataclass(frozen=True)
class Resolver:
    key: str
    label: str
    host: str
    bootstrap: tuple[str, ...] = ()

    @property
    def url(self) -> str:
        return f"https://{self.host}/dns-query"


RESOLVERS = (
    Resolver("cloudflare", "Cloudflare", "cloudflare-dns.com", ("1.1.1.1", "1.0.0.1")),
    Resolver("google", "Google", "dns.google", ("8.8.8.8", "8.8.4.4")),
    Resolver("quad9", "Quad9", "dns.quad9.net", ("9.9.9.9", "149.112.112.112")),
    Resolver("adguard", "AdGuard unfiltered", "unfiltered.adguard-dns.com", ("94.140.14.140", "94.140.14.141")),
    Resolver("opendns", "OpenDNS", "doh.opendns.com", ("208.67.222.222", "208.67.220.220")),
    Resolver("rethink-sky", "ReThinkDNS Sky", "sky.rethinkdns.com"),
    Resolver("rethink-max", "ReThinkDNS Max", "max.rethinkdns.com"),
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


def connect_socks(port: int, host: str, target_port: int, timeout: float) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise OSError("SOCKS authentication rejected")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            name = host.encode("idna")
            target = bytes((3, len(name))) + name
        else:
            target = bytes((1 if address.version == 4 else 4,)) + address.packed
        sock.sendall(b"\x05\x01\x00" + target + struct.pack("!H", target_port))
        version, reply, _, kind = recv_exact(sock, 4)
        if version != 5 or reply:
            raise OSError(f"SOCKS CONNECT failed code={reply}")
        if kind == 3:
            size = recv_exact(sock, 1)[0]
        elif kind in (1, 4):
            size = 4 if kind == 1 else 16
        else:
            raise OSError("Unsupported SOCKS address type")
        recv_exact(sock, size + 2)
        return sock
    except BaseException:
        sock.close()
        raise


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


def select_dns(socks_port: int, cancel: threading.Event) -> tuple[Resolver, int] | None:
    context = ssl.create_default_context()

    def measure(resolver: Resolver) -> tuple[Resolver, int] | None:
        total = 0
        for host in ("www.google.com", "m.youtube.com"):
            ensure_active(cancel)
            query = _query(host, 0)
            connection = _HTTPSConnection(resolver.host, 443, socks_port, 2.5, context)
            started = time.monotonic()
            try:
                connection.request("POST", "/dns-query", body=query, headers={
                    "Accept": "application/dns-message", "Content-Type": "application/dns-message",
                    "Connection": "close",
                })
                with connection.getresponse() as response:
                    content_type = (response.getheader("Content-Type") or "").partition(";")[0].strip().lower()
                    if response.status != 200 or content_type != "application/dns-message":
                        return None
                    if not answers_with_public_ipv4(query, response.read(4097)):
                        return None
            except (OSError, http.client.HTTPException):
                return None
            finally:
                connection.close()
            total += max(1, int((time.monotonic() - started) * 1000))
        return resolver, total // 2

    with ThreadPoolExecutor(max_workers=len(RESOLVERS)) as pool:
        passed = [result for result in pool.map(measure, RESOLVERS) if result is not None]
    ensure_active(cancel)
    return min(passed, key=lambda result: result[1], default=None)


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
