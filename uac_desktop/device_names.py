from __future__ import annotations

import concurrent.futures
import ipaddress
import os
import re
import secrets
import socket
import struct
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Callable


_DEVICE_SUFFIXES = (
    ".localdomain",
    ".home.arpa",
    ".local",
    ".lan",
    ".home",
)
_GENERIC_NAMES = {
    "",
    "android",
    "localhost",
    "localhost.localdomain",
    "unknown",
    "unknown device",
}
_VENDOR_LABELS = (
    ("xiaomi", "Xiaomi device"),
    ("apple", "Apple device"),
    ("samsung", "Samsung device"),
    ("huawei", "Huawei device"),
    ("honor", "Honor device"),
    ("oppo", "OPPO device"),
    ("vivo", "Vivo device"),
    ("oneplus", "OnePlus device"),
    ("realme", "Realme device"),
    ("lg ", "LG device"),
    ("lg electronics", "LG device"),
    ("lg innotek", "LG device"),
    ("sony", "Sony device"),
    ("microsoft", "Microsoft device"),
    ("intel", "Intel device"),
    ("amazon", "Amazon device"),
    ("google", "Google device"),
    ("dreame", "Dreame device"),
    ("roborock", "Roborock device"),
    ("tuya", "Tuya device"),
    ("tp-link", "TP-Link device"),
    ("d-link", "D-Link device"),
)


@dataclass(frozen=True, slots=True)
class DeviceNameResult:
    name: str
    source: str
    priority: int


def normalize_device_name(value: object) -> str:
    name = str(value or "").replace("\x00", "").strip().strip(".")
    name = re.sub(r"\s+", " ", name)
    lowered = name.casefold()
    for suffix in _DEVICE_SUFFIXES:
        if lowered.endswith(suffix) and len(name) > len(suffix):
            name = name[:-len(suffix)].rstrip(". ")
            lowered = name.casefold()
            break
    if lowered in _GENERIC_NAMES:
        return ""
    if not name or len(name) > 64:
        return ""
    if not any(character.isalnum() for character in name):
        return ""
    return name


def decode_dhcp_fqdn(value: object) -> str:
    if isinstance(value, str):
        raw = value.encode("latin-1", "replace")
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
    else:
        return ""
    if len(raw) < 4:
        return ""
    domain = raw[3:]
    if raw[0] & 0x04:
        labels = []
        cursor = 0
        while cursor < len(domain):
            length = domain[cursor]
            cursor += 1
            if length == 0:
                break
            end = cursor + length
            if length > 63 or end > len(domain):
                return ""
            labels.append(domain[cursor:end].decode("utf-8", "replace"))
            cursor = end
        return normalize_device_name(".".join(labels))
    return normalize_device_name(domain.decode("utf-8", "replace"))


def _encode_dns_name(value: str) -> bytes:
    encoded = bytearray()
    for label in value.rstrip(".").split("."):
        raw = label.encode("ascii")
        if not raw or len(raw) > 63:
            raise ValueError("Invalid DNS name")
        encoded.append(len(raw))
        encoded.extend(raw)
    encoded.append(0)
    return bytes(encoded)


def _read_dns_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    cursor = int(offset)
    consumed: int | None = None
    visited: set[int] = set()
    for _ in range(64):
        if cursor >= len(packet) or cursor in visited:
            raise ValueError("Invalid DNS name")
        visited.add(cursor)
        length = packet[cursor]
        if length == 0:
            cursor += 1
            return ".".join(labels), consumed if consumed is not None else cursor
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(packet):
                raise ValueError("Invalid DNS pointer")
            pointer = ((length & 0x3F) << 8) | packet[cursor + 1]
            if consumed is None:
                consumed = cursor + 2
            cursor = pointer
            continue
        if length & 0xC0 or cursor + 1 + length > len(packet):
            raise ValueError("Invalid DNS label")
        cursor += 1
        labels.append(packet[cursor:cursor + length].decode("utf-8", "replace"))
        cursor += length
    raise ValueError("DNS name is too deep")


def _ptr_answers(packet: bytes) -> list[str]:
    if len(packet) < 12:
        return []
    _, _, questions, answers, authorities, additional = struct.unpack(
        "!HHHHHH",
        packet[:12],
    )
    offset = 12
    try:
        for _ in range(questions):
            _, offset = _read_dns_name(packet, offset)
            offset += 4
        result: list[str] = []
        for _ in range(answers + authorities + additional):
            _, offset = _read_dns_name(packet, offset)
            if offset + 10 > len(packet):
                break
            record_type, _, _, length = struct.unpack(
                "!HHIH",
                packet[offset:offset + 10],
            )
            offset += 10
            end = offset + length
            if end > len(packet):
                break
            if record_type == 12:
                name, _ = _read_dns_name(packet, offset)
                normalized = normalize_device_name(name)
                if normalized and normalized not in result:
                    result.append(normalized)
            offset = end
        return result
    except (UnicodeError, ValueError, struct.error):
        return []


def _reverse_name(address: str) -> str:
    return ".".join(reversed(address.split("."))) + ".in-addr.arpa"


def _dns_ptr(
    address: str,
    server: str,
    port: int,
    timeout: float,
    multicast: bool = False,
) -> str:
    ipaddress.IPv4Address(address)
    ipaddress.IPv4Address(server)
    transaction = 0 if multicast else secrets.randbelow(65535) + 1
    flags = 0 if multicast else 0x0100
    query = (
        struct.pack("!HHHHHH", transaction, flags, 1, 0, 0, 0)
        + _encode_dns_name(_reverse_name(address))
        + struct.pack("!HH", 12, 1)
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
        channel.settimeout(max(0.1, float(timeout)))
        if multicast:
            channel.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        channel.sendto(query, (server, int(port)))
        deadline = time.monotonic() + max(0.1, float(timeout))
        while time.monotonic() < deadline:
            try:
                packet, _ = channel.recvfrom(8192)
            except (TimeoutError, socket.timeout):
                return ""
            if len(packet) < 2:
                continue
            response_id = struct.unpack("!H", packet[:2])[0]
            if not multicast and response_id != transaction:
                continue
            answers = _ptr_answers(packet)
            if answers:
                return answers[0]
    return ""


def router_dhcp_name(address: str, gateway: str, timeout: float = 0.45) -> str:
    if not gateway:
        return ""
    try:
        return _dns_ptr(address, gateway, 53, timeout)
    except (OSError, ValueError):
        return ""


def mdns_name(address: str, timeout: float = 0.45) -> str:
    try:
        return _dns_ptr(address, "224.0.0.251", 5353, timeout, multicast=True)
    except (OSError, ValueError):
        return ""


def netbios_name(address: str, timeout: float = 1.2) -> str:
    if os.name != "nt":
        return ""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        completed = subprocess.run(
            ["nbtstat.exe", "-A", address],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=max(0.5, float(timeout)),
            check=False,
            creationflags=flags,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    for line in completed.stdout.splitlines():
        match = re.match(r"^\s*(.{1,15}?)\s+<00>\s+UNIQUE\b", line, re.I)
        if not match:
            continue
        name = normalize_device_name(match.group(1))
        if name and name.casefold() not in {"workgroup", "__msbrowse__"}:
            return name
    return ""


def mac_vendor_name(mac: str) -> str:
    if not mac:
        return ""
    try:
        first = int(mac.split(":", 1)[0], 16)
    except (TypeError, ValueError):
        return ""
    if first & 0x02:
        return ""
    try:
        from scapy.config import conf

        vendor = normalize_device_name(conf.manufdb._get_manuf(mac))
    except Exception:
        return ""
    lowered = f"{vendor.casefold()} "
    for token, label in _VENDOR_LABELS:
        if token in lowered:
            return label
    vendor = re.sub(
        r"\s+(?:co\.?,?\s*ltd\.?|corporation|corp\.?|inc\.?|limited|technology).*$",
        "",
        vendor,
        flags=re.I,
    ).strip(" ,.-")
    return f"{vendor} device" if vendor else ""


class DeviceNameResolver:
    def __init__(
        self,
        router_lookup: Callable[[str, str], str] = router_dhcp_name,
        mdns_lookup: Callable[[str], str] = mdns_name,
        netbios_lookup: Callable[[str], str] = netbios_name,
        vendor_lookup: Callable[[str], str] = mac_vendor_name,
    ) -> None:
        self.router_lookup = router_lookup
        self.mdns_lookup = mdns_lookup
        self.netbios_lookup = netbios_lookup
        self.vendor_lookup = vendor_lookup
        self._cache: dict[tuple[str, str, str], tuple[DeviceNameResult, float]] = {}
        self._lock = threading.Lock()

    def resolve(self, address: str, mac: str, gateway: str = "") -> DeviceNameResult | None:
        key = (str(address), str(mac).casefold(), str(gateway))
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(key)
            if cached is not None and cached[1] > now:
                return cached[0]
        probes = (
            ("dhcp", 100, lambda: self.router_lookup(address, gateway)),
            ("mdns", 90, lambda: self.mdns_lookup(address)),
            ("netbios", 85, lambda: self.netbios_lookup(address)),
            ("vendor", 20, lambda: self.vendor_lookup(mac)),
        )
        result = None
        for source, priority, probe in probes:
            try:
                name = normalize_device_name(probe())
            except Exception:
                name = ""
            if name:
                result = DeviceNameResult(name, source, priority)
                break
        if result is not None:
            ttl = 3600.0 if result.priority >= 80 else 120.0
            with self._lock:
                self._cache[key] = result, now + ttl
        return result

    def resolve_many(
        self,
        devices: dict[str, str],
        gateway: str = "",
    ) -> dict[str, DeviceNameResult]:
        values = dict(devices or {})
        if not values:
            return {}
        result: dict[str, DeviceNameResult] = {}
        workers = max(1, min(8, len(values)))
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="gateway-device-name",
        ) as executor:
            futures = {
                executor.submit(self.resolve, address, mac, gateway): address
                for address, mac in values.items()
            }
            for future, address in futures.items():
                try:
                    value = future.result()
                except Exception:
                    value = None
                if value is not None:
                    result[address] = value
        return result


__all__ = [
    "decode_dhcp_fqdn",
    "DeviceNameResolver",
    "DeviceNameResult",
    "mac_vendor_name",
    "mdns_name",
    "netbios_name",
    "normalize_device_name",
    "router_dhcp_name",
]
