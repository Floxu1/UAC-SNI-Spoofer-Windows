"""Check DNS warming and page probes against a loopback SOCKS peer."""

import socketserver
import threading
from io import StringIO

from uac_desktop.pow import warmup
from uac_desktop.pow.store import PowStore
from uac_desktop.pow.tun_guard import SiteLog


def test_path_probe_requires_a_real_http_header_and_warms_names(tmp_path):
    class Peer(socketserver.StreamRequestHandler):
        def handle(self):
            assert self.rfile.read(3) == b"\x05\x01\x00"
            self.wfile.write(b"\x05")
            self.wfile.write(b"\x00")
            assert self.rfile.read(4) == b"\x05\x01\x00\x03"
            host = self.rfile.read(self.rfile.read(1)[0]).decode("ascii")
            port = int.from_bytes(self.rfile.read(2), "big")
            self.server.destinations.append((host, port))
            self.wfile.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
            if port == 80:
                assert self.rfile.readline() == b"GET /test HTTP/1.1\r\n"
                if host != "empty.example":
                    self.wfile.write(b"HTTP/1.1 204 No Content\r\n\r\n")

    stop = threading.Event()
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Peer) as peer:
        peer.daemon_threads = True
        peer.destinations = []
        worker = threading.Thread(target=peer.serve_forever, daemon=True)
        worker.start()
        try:
            port = peer.server_address[1]
            targets = (("good.example", "/test"), ("empty.example", "/test"))
            assert warmup.measure_path(port, stop, targets=targets, quorum=2, timeout=1) == 0
            assert warmup.measure_path(port, stop, targets=targets, quorum=1, timeout=1) > 0
            assert warmup._probe(port, "dns.example", 1, stop) > 0
            assert ("dns.example", 443) in peer.destinations
            stop.set()
            assert warmup._probe(port, "cancel.example", 1, stop) == 0
            assert ("cancel.example", 443) not in peer.destinations
        finally:
            peer.shutdown()
            worker.join(timeout=2)


def test_only_tunneled_domains_are_learned_and_forget_clears_memory(tmp_path):
    store = PowStore(tmp_path)
    path = warmup.PathWarmup(store, lambda _message: None)
    lines = StringIO(
        "INFO [1 8ms] outbound/socks[proxy]: outbound connection to learn.example:443\n"
        "INFO [2 9ms] outbound/socks[proxy]: outbound connection to learn.example:443\n"
        "INFO [3 4ms] outbound/direct[direct]: outbound connection to ignore.example:443\n"
        "INFO [4 3ms] outbound/socks[proxy]: outbound connection to 192.0.2.3:443\n"
    )
    log = SiteLog(lines, lambda _message: None, observe_tunnel_host=path.note)
    log.thread.join(2)
    path.flush()
    assert PowStore(tmp_path).dns_warm_hosts() == ["learn.example"]
    assert store._doc["dns_warm_hosts"]["learn.example"] == 2
    path.note("pending.example")
    path.forget()
    path.flush()
    assert PowStore(tmp_path).dns_warm_hosts() == []
