from __future__ import annotations

import threading
import time

from uac_desktop import network


def _failed_trace() -> dict:
    return {
        "tls": False,
        "early": False,
        "handshake": 9999,
        "first": 9999,
        "bytes": 0,
        "ping": 9999,
        "body": "",
    }


def test_scan_domain_cancelled_before_dns_skips_network(monkeypatch):
    def unexpected_resolution(_domain):
        raise AssertionError("DNS must not start after cancellation")

    monkeypatch.setattr(network.socket, "gethostbyname", unexpected_resolution)

    result = network.scan_domain("cancelled.example", cancelled=lambda: True)

    assert result.domain == "cancelled.example"
    assert result.success is False


def test_trace_explicit_edge_keeps_candidate_sni_and_records_peer(monkeypatch):
    calls = {"request": b""}

    class RawSocket:
        def settimeout(self, _timeout):
            pass

        def getpeername(self):
            # The actual peer is authoritative, even if it differs from the
            # requested anycast address.
            return ("104.18.8.84", 443)

        def close(self):
            pass

    class TlsSocket:
        def __init__(self):
            self.responses = [
                b"HTTP/1.1 200 OK\r\n\r\nip=203.0.113.77\ncolo=FRA\nloc=DE\n",
                b"",
            ]

        def sendall(self, payload):
            calls["request"] = payload

        def settimeout(self, _timeout):
            pass

        def recv(self, _size):
            return self.responses.pop(0)

        def close(self):
            pass

    class Context:
        def wrap_socket(self, raw, server_hostname):
            assert isinstance(raw, RawSocket)
            calls["sni"] = server_hostname
            return TlsSocket()

    def create_connection(address, timeout):
        calls["address"] = address
        calls["timeout"] = timeout
        return RawSocket()

    monkeypatch.setattr(network.socket, "create_connection", create_connection)
    monkeypatch.setattr(network.ssl, "create_default_context", Context)

    trace = network._trace_once("candidate.example", 3, "104.18.8.83")

    assert calls["address"] == ("104.18.8.83", 443)
    assert calls["sni"] == "candidate.example"
    assert b"Host: candidate.example\r\n" in calls["request"]
    assert trace["edge"] == "104.18.8.84"
    assert "ip=203.0.113.77" in trace["body"]


def test_scan_domain_keeps_public_trace_ip_separate_from_edge(monkeypatch):
    monkeypatch.setattr(network.socket, "gethostbyname", lambda _domain: "192.0.2.10")

    def trace(domain, timeout, edge_ip):
        assert (domain, timeout, edge_ip) == ("candidate.example", 2, "104.18.8.83")
        return {
            "tls": True, "early": False, "handshake": 20, "first": 40,
            "bytes": 512, "ping": 50,
            "body": "ip=203.0.113.77\ncolo=FRA\nloc=DE\n",
            "edge": "104.18.8.84",
        }

    monkeypatch.setattr(network, "_trace_once", trace)

    result = network.scan_domain("candidate.example", tries=1, timeout=2,
                                 edge_ip="104.18.8.83")

    assert result.success is True
    assert result.resolved_ip == "192.0.2.10"
    assert result.edge == "104.18.8.84"
    assert result.cf_ip == "203.0.113.77"


def test_scan_domain_binds_the_peer_that_returned_valid_trace(monkeypatch):
    monkeypatch.setattr(network.socket, "gethostbyname", lambda _domain: "192.0.2.10")
    traces = [
        {
            "tls": True, "early": True, "handshake": 20, "first": 9999,
            "bytes": 0, "ping": 9999, "body": "", "edge": "104.18.8.83",
        },
        {
            "tls": True, "early": False, "handshake": 22, "first": 45,
            "bytes": 512, "ping": 55, "body": "ip=203.0.113.77\n",
            "edge": "104.18.9.83",
        },
    ]
    monkeypatch.setattr(network, "_trace_once", lambda *_args: traces.pop(0))

    result = network.scan_domain("candidate.example", tries=2, timeout=2,
                                 edge_ip="104.18.8.83")

    assert result.success is True
    assert result.edge == "104.18.9.83"


def test_scan_domains_passes_one_captured_edge_to_every_worker(monkeypatch):
    received = []

    def scan(domain, tries, timeout, cancelled, edge_ip):
        received.append((domain, tries, timeout, edge_ip))
        return network.ScanResult(domain=domain, success=True, edge=edge_ip or "")

    monkeypatch.setattr(network, "scan_domain", scan)
    progress = []
    results = network.scan_domains(
        ["one.example", "two.example"], threads=2, tries=2, timeout=4,
        progress=lambda done, total, result: progress.append((done, total, result.edge)),
        cancelled=lambda: False, edge_ip=" 104.18.8.83 ",
    )

    assert sorted(received) == [
        ("one.example", 2, 4, "104.18.8.83"),
        ("two.example", 2, 4, "104.18.8.83"),
    ]
    assert {result.edge for result in results} == {"104.18.8.83"}
    assert len(progress) == 2


def test_cancelled_scan_waits_until_running_workers_exit(monkeypatch):
    cancel = threading.Event()
    all_workers_started = threading.Barrier(4)
    state_lock = threading.Lock()
    active_workers = 0
    slow_workers_finished = 0

    monkeypatch.setattr(network.socket, "gethostbyname", lambda _domain: "1.1.1.1")

    def trace(domain, _timeout):
        nonlocal active_workers, slow_workers_finished
        with state_lock:
            active_workers += 1
        try:
            all_workers_started.wait(timeout=1)
            if domain != "fast.example":
                # A cancelled controller must wait for every in-flight probe,
                # not merely the first worker that happens to finish afterward.
                assert cancel.wait(timeout=1)
                delay = {"one.example": 0.02, "two.example": 0.06, "three.example": 0.10}[domain]
                time.sleep(delay)
            return _failed_trace()
        finally:
            with state_lock:
                active_workers -= 1
                if domain != "fast.example":
                    slow_workers_finished += 1

    monkeypatch.setattr(network, "_trace_once", trace)

    progress_calls = []

    def progress(done, total, result):
        progress_calls.append((done, total, result.domain))
        cancel.set()

    results = network.scan_domains(
        ["fast.example", "one.example", "two.example", "three.example"],
        threads=4,
        tries=1,
        timeout=1,
        progress=progress,
        cancelled=cancel.is_set,
    )

    with state_lock:
        assert active_workers == 0
        assert slow_workers_finished == 3
    assert results == []
    assert progress_calls == [(1, 4, "fast.example")]


def test_current_location_uses_tunnel_proxy_and_returns_geo_country(monkeypatch):
    calls = []

    class Response:
        ok = True

        def json(self):
            return {
                "success": True, "ip": "8.221.169.111",
                "country": "Japan", "country_code": "JP", "city": "Tokyo",
            }

    class Session:
        trust_env = True

        def get(self, url, **kwargs):
            calls.append((url, kwargs))
            return Response()

        def close(self):
            pass

    monkeypatch.setattr(network.requests, "Session", Session)

    result = network.current_location(proxy=True, timeout=3.5)

    assert result == network.GeoLocation(
        ip="8.221.169.111", country_code="JP", country="Japan",
        city="Tokyo", source="ipwho.is",
    )
    assert calls[0][1]["proxies"]["https"] == "http://127.0.0.1:20809"
    assert calls[0][1]["timeout"] == 3.5
