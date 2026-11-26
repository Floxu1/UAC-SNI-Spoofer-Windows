"""Read the Iran entries from Xray's local GeoSite and GeoIP resources."""
from ipaddress import ip_address, ip_network
from pathlib import Path


PRIVATE_IPV4_NETWORKS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
LOCAL_IPV4_NETWORKS = (*PRIVATE_IPV4_NETWORKS, "169.254.0.0/16")
_LOCAL_IPV4 = tuple(map(ip_network, LOCAL_IPV4_NETWORKS))


def is_local_ipv4(host: str) -> bool:
    try:
        address = ip_address(host)
    except ValueError:
        return False
    return address.version == 4 and any(address in network for network in _LOCAL_IPV4)


def _varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            break
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7f) << shift
        if byte < 128:
            return value, offset
    raise ValueError("Invalid routing file varint")


def _fields(data):
    offset = 0
    while offset < len(data):
        tag, offset = _varint(data, offset)
        field, kind = tag >> 3, tag & 7
        if kind == 0:
            value, offset = _varint(data, offset)
            yield field, value
        elif kind == 2:
            size, offset = _varint(data, offset)
            end = offset + size
            if end > len(data):
                raise ValueError("Truncated routing file")
            yield field, data[offset:end]
            offset = end
        else:
            raise ValueError("Unsupported routing file field")


def _category(path: Path, name: str):
    key = name.upper().encode("ascii")
    for field, group in _fields(path.read_bytes()):
        if field != 1 or not isinstance(group, bytes):
            continue
        fields = iter(_fields(group))
        for index, value in fields:
            if index == 1 and isinstance(value, bytes):
                if value.upper() == key:
                    yield from (entry for tag, entry in fields if tag == 2 and isinstance(entry, bytes))
                break


def geosite_entries(path: Path, name: str):
    for entry in _category(path, name):
        fields = dict(_fields(entry))
        if isinstance(value := fields.get(2), bytes):
            yield fields.get(1, 0), value.decode("utf-8")


def geoip_entries(path: Path, name: str):
    for entry in _category(path, name):
        fields = dict(_fields(entry))
        if isinstance(address := fields.get(1), bytes) and len(address) in (4, 16):
            yield str(ip_network((ip_address(address), fields.get(2, 0)), strict=False))
