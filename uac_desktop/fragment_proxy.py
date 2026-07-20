from __future__ import annotations

import select
import socket
import threading
import time
import concurrent.futures
from collections.abc import Callable

from .models import ProxyProfile, Tuning
from .tls_tools import find_sni, fragments, make_client_hello


LogFn = Callable[[str], None]
TrafficFn = Callable[[int, int], None]


class FragmentProxy:
    """Desktop port of the mobile 127.0.0.1:40443 adaptive TLS fragment proxy."""

    def __init__(self, log: LogFn, traffic: TrafficFn | None = None) -> None:
        self.log = log
        self.traffic = traffic or (lambda up, down: None)
        self._stop = threading.Event()
        self._server: socket.socket | None = None
        self._profile: ProxyProfile | None = None
        self._tuning = Tuning()
        self._threads: set[threading.Thread] = set()
        self._preferred: dict[str, str] = {}
        self._preferred_host: dict[str, str] = {}
        self._preferred_carrier: str | None = None
        self._failed_until: dict[str, float] = {}
        self._state_lock = threading.Lock()
        self._route_discovery_lock = threading.Lock()
        self._carrier_discovery_lock = threading.Lock()
        self._dial_slots = threading.BoundedSemaphore(10)
        self._failure_count = 0
        self._failure_log_at = 0.0
        self._last_route_log: tuple[str, str, str] | None = None
        self._last_route_log_at = 0.0
        self._last_traffic_emit = 0.0
        self.upload = 0
        self.download = 0
        self._forced_strategy: str | None = None

    @property
    def running(self) -> bool:
        return bool(self._server) and not self._stop.is_set()

    def start(self, profile: ProxyProfile, tuning: Tuning, forced_strategy: str | None = None) -> None:
        self.stop()
        self._profile, self._tuning = profile, tuning
        self._forced_strategy = forced_strategy
        self.upload = self.download = 0
        self._stop.clear()
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", profile.config_port))
        server.listen(128)
        server.settimeout(0.5)
        self._server = server
        threading.Thread(target=self._accept_loop, name="fragment-accept", daemon=True).start()
        self.log(f"FRAGMENT proxy listening 127.0.0.1:{profile.config_port}")
        route_text = " + ".join(f"{name}({','.join(hosts)})" for name, hosts in self._routes())
        self.log(f"Route {route_text}:{profile.port} fakeSni={profile.sni} strategy={forced_strategy or 'adaptive'}")
        if tuning.warm_tcp_pool_enabled:
            threading.Thread(target=self._prewarm, name="fragment-warm", daemon=True).start()

    def _detail(self, message: str) -> None:
        if self._tuning.log_level != "minimal":
            self.log(message)

    def _route_failure(self, message: str) -> None:
        self._failure_count += 1
        now = time.monotonic()
        if self._tuning.log_level != "minimal" or now - self._failure_log_at >= 3:
            self._failure_log_at = now
            self.log(f"ROUTE_FAILURES count={self._failure_count} last={message}")

    @staticmethod
    def _tune_socket(sock: socket.socket) -> None:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        for option in (socket.SO_RCVBUF, socket.SO_SNDBUF):
            try:
                sock.setsockopt(socket.SOL_SOCKET, option, 1024 * 1024)
            except OSError:
                pass

    def _emit_traffic(self, force: bool = False) -> None:
        now = time.monotonic()
        if force or now - self._last_traffic_emit >= 0.2:
            self._last_traffic_emit = now
            self.traffic(self.upload, self.download)

    def stop(self) -> None:
        self._stop.set()
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass
        self._server = None
        for thread in list(self._threads):
            thread.join(timeout=0.05)
        self._threads.clear()

    def _accept_loop(self) -> None:
        while not self._stop.is_set() and self._server:
            try:
                client, address = self._server.accept()
                self._tune_socket(client)
                worker = threading.Thread(target=self._handle, args=(client, address), daemon=True)
                self._threads.add(worker)
                worker.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _prewarm(self) -> None:
        profile = self._profile
        if not profile:
            return
        targets = []
        for _, hosts in self._routes():
            targets.extend(hosts)
        for host in dict.fromkeys(targets):
            try:
                sock = socket.create_connection((host, profile.port), timeout=2)
                sock.close()
                self._detail(f"WARM route ready {host}:{profile.port}")
            except OSError:
                pass

    def _read_first_tls_packet(self, client: socket.socket) -> bytes:
        client.settimeout(12)
        first = client.recv(65535)
        if not first:
            return b""
        if len(first) >= 5 and first[0] == 0x16:
            expected = 5 + int.from_bytes(first[3:5], "big")
            while len(first) < expected:
                chunk = client.recv(expected - len(first))
                if not chunk:
                    break
                first += chunk
        return first

    def _routes(self) -> list[tuple[str, list[str]]]:
        profile = self._profile
        carrier = self._tuning.carrier_mode
        if carrier == "mci":
            return [("mci", ["104.18.8.83", "104.18.9.83"])]
        if carrier == "irancell":


            return [("irancell", ["104.19.229.21", "104.19.230.21", "104.18.8.83", "104.18.9.83"])]

        return [("mci", ["104.18.8.83", "104.18.9.83"]),
                ("irancell", ["104.19.229.21", "104.19.230.21"])]

    def _strategies(self, carrier: str, host: str) -> list[tuple[str, int]]:
        t = self._tuning
        if self._forced_strategy:
            delays = {"raw": 0, "full20": 1, "full10": 2, "full5": 5,
                      "multi64": 0, "sni_boundary": 0,
                      "sni_split": max(1, t.sni_split_delay_ms),
                      "tls_record_frag": max(1, t.tls_record_delay_ms),
                      "half": max(1, t.half_delay_ms)}
            names = [self._forced_strategy]



            if carrier == "irancell" and self._forced_strategy in {"raw", "half"}:
                names.append("half" if self._forced_strategy == "raw" else "raw")
            preferred = self._preferred.get(host)
            names = list(dict.fromkeys(names)); names.sort(key=lambda name: name != preferred)
            return [(name, delays.get(name, 0)) for name in names]
        if carrier == "mci":
            sni_delay = max(t.sni_split_delay_ms, 3)
            record_delay = max(t.tls_record_delay_ms, 3)
            base = [("full20", 1), ("full10", 2), ("full5", 5), ("full5", 15),
                    ("sni_boundary", max(1, sni_delay // 2)),
                    ("sni_split", sni_delay), ("tls_record_frag", record_delay),
                    ("tls_sni_records", record_delay), ("half", max(t.half_delay_ms, 3)), ("raw", 0)]
        elif carrier == "irancell":
            sni_delay = min(max(t.sni_split_delay_ms, 1), 8)
            record_delay = min(max(t.tls_record_delay_ms, 1), 6)
            base = [("multi64", 0), ("sni_boundary", 0), ("tls_record_frag", 1),
                    ("sni_split", sni_delay), ("sni_boundary", max(1, sni_delay // 2)),
                    ("tls_record_frag", record_delay), ("multi64", min(max(t.multi_delay_ms, 0), 2)),
                    ("half", min(max(t.half_delay_ms, 1), 6)), ("raw", 0)]
        else:
            base = [("sni_split", t.sni_split_delay_ms), ("sni_boundary", max(1, t.sni_split_delay_ms // 2)),
                    ("tls_sni_records", t.tls_record_delay_ms), ("tls_record_frag", t.tls_record_delay_ms),
                    ("multi", t.multi_delay_ms), ("sni_chars", t.multi_delay_ms), ("half", t.half_delay_ms)]
        preferred = self._preferred.get(host)
        if preferred:
            base.sort(key=lambda x: x[0] != preferred)
        return base

    def _send_fake_probe(self, host: str) -> None:
        profile = self._profile
        if not profile:
            return
        try:
            hello = make_client_hello(profile.sni)
            probe = socket.create_connection((host, profile.port), timeout=0.5)
            probe.sendall(hello)
            probe.close()
            self.log(f"FAKE_SNI probe {profile.sni} {len(hello)} B")
        except OSError:
            pass

    def _attempt(self, carrier: str, host: str, first: bytes, strategy: str, delay_ms: int,
                 race_stop: threading.Event | None = None) -> tuple[socket.socket, bytes] | None:
        profile = self._profile
        if not profile:
            return None
        source_timeout = self._tuning.route_probe_timeout_ms
        timeout_ms = min(max(source_timeout, 3000), 6000) if carrier == "mci" else min(max(source_timeout, 800), 1100)
        connect_timeout = max(2.0, timeout_ms / 1000) if carrier == "mci" else max(0.9, timeout_ms / 1000)
        remote = socket.create_connection((host, profile.port), timeout=connect_timeout)
        self._tune_socket(remote)
        remote.settimeout(min(4.5, max(1.2, timeout_ms / 1000)) if carrier == "mci" else max(0.9, timeout_ms / 1000))
        pieces = fragments(first, strategy, self._tuning.multi_fragment_size)
        self._detail(f"FRAGMENT {strategy} {len(pieces)} pieces: " + ", ".join(f"{len(x)} B" for x in pieces[:12]))
        for index, piece in enumerate(pieces):
            remote.sendall(piece)
            if index + 1 < len(pieces) and delay_ms:
                time.sleep(delay_ms / 1000)
        response = remote.recv(16384)
        if race_stop and race_stop.is_set():
            remote.close()
            return None
        first_byte = response[0] if response else -1


        if not response or first_byte == 0x15 or (len(response) < 8 and first_byte in {0x14, 0x16, 0x17}):
            self.log(f"STRATEGY_REJECT {carrier}/{host} {strategy} response={len(response)}B first=0x{first_byte & 0xff:02x}")
            remote.close()
            return None
        return remote, response

    def _race_strategies(self, carrier: str, host: str, first: bytes,
                         attempts: list[tuple[str, int]]):
        stop = threading.Event()
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=len(attempts), thread_name_prefix=f"{carrier}-strategy")
        futures = {pool.submit(self._attempt, carrier, host, first, strategy, delay, stop): strategy
                   for strategy, delay in attempts}
        winner = None
        winner_future = None
        try:
            for future in concurrent.futures.as_completed(futures, timeout=5.5):
                result = future.result()
                if result:
                    winner = result[0], result[1], futures[future]
                    winner_future = future
                    stop.set()
                    break
        except concurrent.futures.TimeoutError:
            pass
        finally:
            if not winner:
                stop.set()
            for future in futures:
                if future is not winner_future and future.done() and not future.cancelled():
                    try:
                        result = future.result()
                        if result:
                            result[0].close()
                    except Exception:
                        pass
                future.cancel()
            pool.shutdown(wait=False, cancel_futures=True)
        return winner

    def _ordered_hosts(self, carrier: str, hosts: list[str]) -> list[str]:
        now = time.monotonic()
        with self._state_lock:
            preferred = self._preferred_host.get(carrier)
            healthy = [host for host in hosts if self._failed_until.get(host, 0) <= now]
        if not healthy:
            healthy = list(hosts)
        healthy.sort(key=lambda host: (host != preferred, hosts.index(host)))
        return healthy

    def _host_failed(self, carrier: str, host: str) -> None:
        with self._state_lock:
            self._failed_until[host] = time.monotonic() + 1.5
            if self._preferred_host.get(carrier) == host:
                self._preferred_host.pop(carrier, None)

    def _host_succeeded(self, carrier: str, host: str) -> None:
        with self._state_lock:
            self._preferred_host[carrier] = host
            self._failed_until.pop(host, None)

    def _connect_host(self, carrier: str, host: str, first: bytes,
                      race_stop: threading.Event | None = None):
        profile = self._profile
        if not profile:
            return None
        if race_stop and race_stop.is_set():
            return None
        combined = "combined" in (profile.method or "").lower() or "fake" in (profile.method or "").lower()



        probe_count = (max(1, self._tuning.fake_probe_count) if combined else self._tuning.fake_probe_count) if self._tuning.fake_probe_enabled else 0
        if probe_count:
            for _ in range(probe_count):
                self._send_fake_probe(host)
                time.sleep(max(3, self._tuning.fake_probe_delay_ms) / 1000)
        strategies = self._strategies(carrier, host)
        if self._tuning.initial_race_enabled and len(strategies) >= 3:
            raced = self._race_strategies(carrier, host, first, strategies[:3])
            if raced:
                remote, response, strategy = raced
                self._preferred[host] = strategy
                self._host_succeeded(carrier, host)
                return remote, response, strategy, carrier, host
            strategies = strategies[3:]
        for strategy, delay in strategies:
            if self._stop.is_set() or (race_stop and race_stop.is_set()):
                return None
            try:
                connected = self._attempt(carrier, host, first, strategy, delay, race_stop)
            except OSError as exc:
                self._route_failure(f"{carrier}/{host} {strategy}: {exc}")
                connected = None
            if connected:
                if race_stop and race_stop.is_set():
                    connected[0].close()
                    return None
                self._preferred[host] = strategy
                self._host_succeeded(carrier, host)
                return connected[0], connected[1], strategy, carrier, host
        self._host_failed(carrier, host)
        return None

    def _race_hosts(self, carrier: str, hosts: list[str], first: bytes):
        stop = threading.Event(); pool = concurrent.futures.ThreadPoolExecutor(max_workers=len(hosts), thread_name_prefix=f"{carrier}-edge")
        futures = {pool.submit(self._connect_host, carrier, host, first, stop): host for host in hosts}
        winner = None; winner_future = None
        try:
            for future in concurrent.futures.as_completed(futures, timeout=2.2):
                result = future.result()
                if result:
                    winner, winner_future = result, future; stop.set(); break
        except concurrent.futures.TimeoutError:
            pass
        finally:
            if not winner: stop.set()
            for future in futures:
                if future is not winner_future and future.done() and not future.cancelled():
                    try:
                        result = future.result()
                        if result: result[0].close()
                    except Exception:
                        pass
                future.cancel()
            pool.shutdown(wait=False, cancel_futures=True)
        return winner

    def _connect_route(self, carrier: str, hosts: list[str], first: bytes,
                       race_stop: threading.Event | None = None):
        profile = self._profile
        if not profile:
            return None
        ordered = self._ordered_hosts(carrier, hosts)
        with self._state_lock:
            preferred = self._preferred_host.get(carrier)
        if carrier == "irancell" and self._tuning.carrier_mode == "irancell" and self._tuning.initial_race_enabled and not preferred:
            if self._route_discovery_lock.acquire(timeout=2.3):
                try:
                    with self._state_lock:
                        preferred = self._preferred_host.get(carrier)
                    if not preferred:
                        raced = self._race_hosts(carrier, ordered[:2], first)
                        if raced:
                            return raced
                finally:
                    self._route_discovery_lock.release()
                ordered = self._ordered_hosts(carrier, hosts)
        for host in ordered:
            connected = self._connect_host(carrier, host, first, race_stop)
            if connected:
                return connected
            self._detail(f"FAILOVER {carrier} next route after {host}:{profile.port}")
        return None

    def _connect_auto(self, routes: list[tuple[str, list[str]]], first: bytes):
        with self._state_lock:
            preferred = self._preferred_carrier
        if preferred:
            ordered = sorted(routes, key=lambda route: route[0] != preferred)
            for carrier, hosts in ordered:
                connected = self._connect_route(carrier, hosts, first)
                if connected:
                    with self._state_lock: self._preferred_carrier = carrier
                    return connected
            return None

        if not self._carrier_discovery_lock.acquire(timeout=4.5):
            with self._state_lock: preferred = self._preferred_carrier
            if preferred:
                route = next((route for route in routes if route[0] == preferred), routes[0])
                return self._connect_route(route[0], route[1], first)
            return None
        try:
            with self._state_lock: preferred = self._preferred_carrier
            if preferred:
                route = next((route for route in routes if route[0] == preferred), routes[0])
                return self._connect_route(route[0], route[1], first)
            self.log("AUTO_CARRIER discovery race")
            race_stop = threading.Event(); pool = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="carrier-discovery")
            futures = [pool.submit(self._connect_route, carrier, hosts, first, race_stop) for carrier, hosts in routes]
            winner = None; winner_future = None
            try:
                for future in concurrent.futures.as_completed(futures, timeout=4.5):
                    result = future.result()
                    if result:
                        winner, winner_future = result, future; race_stop.set(); break
            except concurrent.futures.TimeoutError:
                pass
            finally:
                race_stop.set()
                for future in futures:
                    if future is not winner_future and future.done() and not future.cancelled():
                        try:
                            result = future.result()
                            if result: result[0].close()
                        except Exception:
                            pass
                    future.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
            if winner:
                with self._state_lock: self._preferred_carrier = winner[3]
            return winner
        finally:
            self._carrier_discovery_lock.release()

    def _handle(self, client: socket.socket, address) -> None:
        profile = self._profile
        try:
            if not profile:
                return
            first = self._read_first_tls_packet(client)
            if not first:
                return
            self._detail(f"TLS real_sni={find_sni(first) or 'unknown'} size={len(first)} B")
            connected = None; routes = self._routes()
            if not self._dial_slots.acquire(timeout=6):
                self._route_failure("dial queue saturated")
                return
            try:
                connected = self._connect_route(routes[0][0], routes[0][1], first) if len(routes) == 1 else self._connect_auto(routes, first)
            finally:
                self._dial_slots.release()
            if not connected:
                self._route_failure("remote accepted TLS but closed before usable page traffic")
                return
            remote, initial_response, chosen, carrier, host = connected
            client.sendall(initial_response)
            self.download += len(initial_response)
            route_key = (carrier, host, chosen); now = time.monotonic()
            if route_key != self._last_route_log or now - self._last_route_log_at >= 30:
                self.log(f"AUTO_CARRIER_WIN {carrier} target={host}:{profile.port} strategy={chosen}")
                self._last_route_log, self._last_route_log_at = route_key, now
            self._relay(client, remote)
        except (OSError, ValueError) as exc:
            self.log(f"Connection closed: {exc}")
        finally:
            try:
                client.close()
            except OSError:
                pass
            self._threads.discard(threading.current_thread())

    def _relay(self, client: socket.socket, remote: socket.socket) -> None:
        sockets = [client, remote]
        for sock in sockets:
            sock.setblocking(True)
        started = time.monotonic()
        try:
            while not self._stop.is_set():
                readable, _, errored = select.select(sockets, [], sockets, 1.0)
                if errored:
                    break
                for src in readable:
                    data = src.recv(262144)
                    if not data:
                        return
                    dst = remote if src is client else client
                    dst.sendall(data)
                    if src is client:
                        self.upload += len(data)
                    else:
                        self.download += len(data)
                    self._emit_traffic()
        finally:
            remote.close()
            alive = int((time.monotonic() - started) * 1000)
            self._emit_traffic(force=True)
            if self._tuning.log_level != "minimal" or alive < 2000:
                self.log(f"VPN DIAG route closed alive={alive}ms up={self.upload} down={self.download}")
