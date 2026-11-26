"""Session traffic in client directions, measured at one data-plane layer."""

import json
import socket
import subprocess
from contextlib import ExitStack


def loopback_ports(count, *, exclude=()):
    ports = []
    with ExitStack() as stack:
        while len(ports) < count:
            sock = stack.enter_context(socket.socket())
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
            if port not in exclude:
                ports.append(port)
    return tuple(ports)


def enable_xray_traffic(config, port, probe_socks=0, probe_http=0):
    config["api"] = {"tag": "traffic-stats", "listen": f"127.0.0.1:{port}", "services": ["StatsService"]}
    config["stats"] = {}
    config.setdefault("policy", {}).setdefault("system", {}).update(
        statsInboundUplink=True, statsInboundDownlink=True,
    )
    probes = {"socks-in": probe_socks, "http-in": probe_http}
    for inbound in config["inbounds"][:]:
        tag = inbound.get("tag")
        if not probes.get(tag):
            continue
        probe_tag = f"probe-{tag}"
        config["inbounds"].append({**inbound, "tag": probe_tag, "port": probes[tag]})
        for rule in config["routing"]["rules"]:
            if tag in rule.get("inboundTag", []):
                rule["inboundTag"].append(probe_tag)


def xray_traffic(binary, port):
    """Read only user-facing inbounds, never API or downstream transport counters."""
    if not port:
        return None
    try:
        output = subprocess.run(
            [str(binary), "api", "statsquery", f"--server=127.0.0.1:{port}", "-pattern", "inbound>>>"],
            capture_output=True, text=True, encoding="utf-8", timeout=2,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if output.returncode:
            return None
        counters = {item["name"]: int(item.get("value", 0)) for item in json.loads(output.stdout).get("stat", [])}
        return tuple(
            sum(max(0, counters.get(f"inbound>>>{tag}>>>traffic>>>{direction}", 0))
                for tag in ("socks-in", "http-in"))
            for direction in ("uplink", "downlink")
        )
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
        return None


class SessionTraffic:
    """Accumulate per-source deltas across output changes and worker replacement."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.previous = {}
        self.upload = self.download = 0

    def update(self, sources):
        for owner, (upload, download) in sources.items():
            prev_up, prev_down = self.previous.get(owner, (upload, download))
            self.upload += max(0, upload - prev_up)
            self.download += max(0, download - prev_down)
        self.previous = sources
        return self.upload, self.download
