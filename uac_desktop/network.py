from __future__ import annotations

import concurrent.futures
import socket
import ssl
import time
from dataclasses import asdict, dataclass

import requests


@dataclass
class ScanResult:
    domain: str
    resolved_ip: str = "N/A"
    cf_ip: str = ""
    colo: str = ""
    country: str = ""
    ray: str = ""
    ping_ms: int = 9999
    stability: int = 0
    score: int = -9999
    success: bool = False
    tls_accepted_count: int = 0
    early_close_count: int = 0
    first_byte_ms: int = 9999
    first_two_second_bytes: int = 0
    consecutive_successes: int = 0
    handshake_ms: int = 9999
    tested_at: float = 0.0
    carrier: str = ""
    edge: str = ""
    edge_verified: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def tcp_ping(host: str, port: int, timeout: float = 3) -> tuple[bool, float]:
    started = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True, (time.perf_counter() - started) * 1000
    except OSError:
        return False, 0.0


def profile_ping(address: str, port: int, sni: str, timeout: float = 4) -> tuple[bool, float]:
    """Match the mobile ConfigPinger: TLS to spoof address using the selected fake SNI."""
    started = time.perf_counter()
    raw = None
    wrapped = None
    try:
        raw = socket.create_connection((address, port), timeout=timeout)
        raw.settimeout(timeout)
        context = ssl.create_default_context()
        wrapped = context.wrap_socket(raw, server_hostname=sni)
        request = f"HEAD / HTTP/1.1\r\nHost: {sni}\r\nUser-Agent: UAC-Spoofer-Desktop\r\nConnection: close\r\n\r\n"
        wrapped.sendall(request.encode("ascii"))
        first = wrapped.recv(128)
        elapsed = (time.perf_counter() - started) * 1000
        return bool(first.startswith(b"HTTP/") or first), elapsed
    except OSError:
        return False, 0.0
    finally:
        for sock in (wrapped, raw):
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass


def _trace_once(domain: str, timeout: float, edge_ip: str | None = None) -> dict:
    """Measure ``domain`` through an optional, explicit TLS edge.

    ``edge_ip`` changes only the TCP destination.  TLS SNI and the HTTP Host
    header intentionally remain ``domain`` so an edge-aware scan measures the
    exact SNI/edge pair rather than the edge's reverse-DNS identity.
    """
    started = time.perf_counter()
    context = ssl.create_default_context()
    result = {"tls": False, "early": False, "handshake": 9999, "first": 9999,
              "bytes": 0, "ping": 9999, "body": "", "edge": ""}
    raw = None
    sock = None
    try:
        raw = socket.create_connection((edge_ip or domain, 443), timeout=min(timeout, 5))
        try:
            result["edge"] = str(raw.getpeername()[0])
        except (OSError, AttributeError, IndexError, TypeError):
            
            
            pass
        raw.settimeout(timeout)
        tls_start = time.perf_counter()
        sock = context.wrap_socket(raw, server_hostname=domain)
        result["tls"] = True
        result["handshake"] = int((time.perf_counter() - tls_start) * 1000)
        request = f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: UAC-Spoofer-Desktop\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode("ascii"))
        chunks, total = [], 0
        first = None
        deadline = time.perf_counter() + min(2, timeout)
        while time.perf_counter() < deadline and total < 96 * 1024:
            sock.settimeout(max(0.05, deadline - time.perf_counter()))
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            if first is None:
                first = time.perf_counter()
            chunks.append(chunk)
            total += len(chunk)
        result.update(first=int(((first or time.perf_counter()) - started) * 1000), bytes=total,
                      ping=int((time.perf_counter() - started) * 1000),
                      body=b"".join(chunks).decode("latin-1", "ignore"))
        result["early"] = total < 16
    except OSError:
        result["early"] = result["tls"]
    finally:
        for connection in (sock, raw):
            if connection:
                try:
                    connection.close()
                except OSError:
                    pass
    return result


def scan_domain(domain: str, tries: int = 3, timeout: int = 12, cancelled=None,
                edge_ip: str | None = None) -> ScanResult:
    """Measure one candidate and cooperate with scan cancellation between tries."""
    out = ScanResult(domain=domain)
    if cancelled and cancelled():
        return out
    try:
        out.resolved_ip = socket.gethostbyname(domain)
    except OSError:
        pass
    ok = 0
    pings: list[int] = []
    firsts: list[int] = []
    handshakes: list[int] = []
    byte_counts: list[int] = []
    streak = longest = 0
    for _ in range(max(1, tries)):
        if cancelled and cancelled():
            break
        
        
        
        trace = (_trace_once(domain, timeout, edge_ip) if edge_ip
                 else _trace_once(domain, timeout))
        measured_edge = str(trace.get("edge", "") or "").strip()
        if trace["tls"]:
            out.tls_accepted_count += 1
            handshakes.append(trace["handshake"])
        if trace["early"]:
            out.early_close_count += 1
        body = trace["body"]
        success = "ip=" in body
        if success:
            
            
            
            if measured_edge and not out.edge:
                out.edge = measured_edge
                out.edge_verified = bool(edge_ip)
            ok += 1
            streak += 1
            longest = max(longest, streak)
            pings.append(trace["ping"]); firsts.append(trace["first"]); byte_counts.append(trace["bytes"])
            values = {}
            for line in body.splitlines():
                if "=" in line:
                    key, value = line.split("=", 1); values[key.strip()] = value.strip()
            out.cf_ip, out.colo, out.country = values.get("ip", ""), values.get("colo", ""), values.get("loc", "")
        else:
            streak = 0
    out.stability = int(ok / max(1, tries) * 100)
    out.ping_ms = sum(pings) // len(pings) if pings else 9999
    out.first_byte_ms = sum(firsts) // len(firsts) if firsts else 9999
    out.first_two_second_bytes = sum(byte_counts) // len(byte_counts) if byte_counts else 0
    out.handshake_ms = sum(handshakes) // len(handshakes) if handshakes else 9999
    out.consecutive_successes = longest
    out.success = ok > 0
    tls_ratio = int(out.tls_accepted_count / max(1, tries) * 100)
    ok_ratio = int(ok / max(1, tries) * 100)
    out.score = (tls_ratio * 4 + ok_ratio * 6 + out.stability * 3 + min(260, longest * 90)
                 + min(350, out.first_two_second_bytes // 96) - min(450, out.first_byte_ms // 3)
                 - min(350, out.ping_ms // 5) - min(220, out.handshake_ms // 5)
                 - out.early_close_count * 180)
    return out


def scan_domains(domains: list[str], threads: int, tries: int, timeout: int, progress, cancelled,
                 edge_ip: str | None = None) -> list[ScanResult]:
    results: list[ScanResult] = []
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(100, threads)))
    
    
    captured_edge = str(edge_ip or "").strip() or None
    futures = {
        pool.submit(scan_domain, domain, tries, timeout, cancelled, captured_edge): domain
        for domain in domains
    }
    was_cancelled = False
    try:
        done = 0
        pending = set(futures)
        while pending:
            if cancelled():
                was_cancelled = True
                break
            completed, pending = concurrent.futures.wait(
                pending,
                timeout=0.05,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            for future in completed:
                if cancelled():
                    was_cancelled = True
                    break
                domain = futures[future]
                try:
                    result = future.result()
                except Exception:
                    
                    result = ScanResult(domain=domain)
                done += 1
                if result.success:
                    results.append(result)
                progress(done, len(domains), result)
            if was_cancelled:
                break
    finally:
        if was_cancelled or cancelled():
            for future in futures:
                future.cancel()
            
            
            
            pool.shutdown(wait=True, cancel_futures=True)
        else:
            pool.shutdown(wait=True)
    return sorted(results, key=lambda x: (-x.score, -x.stability, x.first_byte_ms, x.ping_ms, x.domain))


def current_ip(proxy: bool = False) -> str:
    proxies = {"http": "http://127.0.0.1:20809", "https": "http://127.0.0.1:20809"} if proxy else None
    response = requests.get("https://api.ipify.org?format=json", proxies=proxies, timeout=8)
    return response.json().get("ip", "unknown")
