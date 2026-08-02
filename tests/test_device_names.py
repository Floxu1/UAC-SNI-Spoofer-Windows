import struct

from uac_desktop.device_names import (
    DeviceNameResolver,
    _encode_dns_name,
    _ptr_answers,
    decode_dhcp_fqdn,
    normalize_device_name,
)


def test_normalize_device_name_removes_network_suffixes():
    assert normalize_device_name("Rayane-Phone.local.") == "Rayane-Phone"
    assert normalize_device_name(b"") == ""
    assert normalize_device_name("unknown") == ""


def test_decode_dhcp_fqdn_supports_wire_and_ascii_names():
    wire = b"\x04\x00\x00\x0cRayane-Phone\x05local"
    ascii_name = b"\x00\x00\x00Living-TV.home"

    assert decode_dhcp_fqdn(wire) == "Rayane-Phone"
    assert decode_dhcp_fqdn(ascii_name) == "Living-TV"


def test_ptr_answer_parser_reads_compressed_response():
    query = _encode_dns_name("136.70.168.192.in-addr.arpa")
    target = _encode_dns_name("Xiaomi-13.local")
    packet = (
        struct.pack("!HHHHHH", 123, 0x8180, 1, 1, 0, 0)
        + query
        + struct.pack("!HH", 12, 1)
        + b"\xc0\x0c"
        + struct.pack("!HHIH", 12, 1, 120, len(target))
        + target
    )

    assert _ptr_answers(packet) == ["Xiaomi-13"]


def test_resolver_prefers_router_dhcp_name():
    calls = []
    resolver = DeviceNameResolver(
        router_lookup=lambda address, gateway: (
            calls.append(("router", address, gateway)) or "Living-TV"
        ),
        mdns_lookup=lambda address: calls.append(("mdns", address)) or "mDNS",
        netbios_lookup=lambda address: calls.append(("netbios", address)) or "NB",
        vendor_lookup=lambda mac: calls.append(("vendor", mac)) or "Vendor",
    )

    result = resolver.resolve(
        "192.168.70.136",
        "aa:bb:cc:dd:ee:ff",
        "192.168.70.1",
    )

    assert result is not None
    assert result.name == "Living-TV"
    assert result.source == "dhcp"
    assert result.priority == 100
    assert calls == [("router", "192.168.70.136", "192.168.70.1")]


def test_resolver_uses_vendor_without_crashing_on_lookup_failures():
    def broken(*_values):
        raise OSError("offline")

    resolver = DeviceNameResolver(
        router_lookup=broken,
        mdns_lookup=broken,
        netbios_lookup=broken,
        vendor_lookup=lambda _mac: "Xiaomi device",
    )

    result = resolver.resolve(
        "192.168.70.136",
        "9c:9e:d5:93:63:83",
        "192.168.70.1",
    )

    assert result is not None
    assert result.name == "Xiaomi device"
    assert result.source == "vendor"
