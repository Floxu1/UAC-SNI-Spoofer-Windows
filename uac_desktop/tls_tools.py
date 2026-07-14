from __future__ import annotations

import os
import ssl
import struct


def locate_sni(data: bytes) -> tuple[int, int] | None:
    """Return the byte range of the first host_name inside a TLS ClientHello."""
    try:
        if len(data) < 9 or data[0] != 0x16:
            return None
        record_end = min(len(data), 5 + int.from_bytes(data[3:5], "big"))
        pos = 5
        if data[pos] != 0x01:
            return None
        pos += 4 + 2 + 32
        session_len = data[pos]
        pos += 1 + session_len
        cipher_len = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2 + cipher_len
        compression_len = data[pos]
        pos += 1 + compression_len
        extensions_len = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        end = min(record_end, pos + extensions_len)
        while pos + 4 <= end:
            ext_type = int.from_bytes(data[pos:pos + 2], "big")
            ext_len = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4
            if ext_type == 0 and pos + ext_len <= end:
                q = pos + 2
                names_end = pos + ext_len
                while q + 3 <= names_end:
                    name_type = data[q]
                    name_len = int.from_bytes(data[q + 1:q + 3], "big")
                    q += 3
                    if name_type == 0 and q + name_len <= names_end:
                        return q, name_len
                    q += name_len
            pos += ext_len
    except (IndexError, ValueError):
        return None
    return None


def find_sni(data: bytes) -> str:
    located = locate_sni(data)
    if not located:
        return ""
    start, length = located
    return data[start:start + length].decode("ascii", "ignore")


def tls_record(version: bytes, payload: bytes) -> bytes:
    return b"\x16" + version + struct.pack(">H", len(payload)) + payload


def fragments(data: bytes, strategy: str, chunk_size: int = 5) -> list[bytes]:
    if len(data) < 2:
        return [data]
    location = locate_sni(data)
    if strategy == "half":
        cut = max(1, len(data) // 2)
        return [data[:cut], data[cut:]]
    if strategy in {"multi", "full5", "full10", "full20", "multi64"}:
        fixed = {"full5": 5, "full10": 10, "full20": 20, "multi64": 64}
        size = max(1, fixed.get(strategy, chunk_size))
        return [data[i:i + size] for i in range(0, len(data), size)]
    if strategy in {"sni_split", "sni_boundary"} and location:
        start, length = location
        cut = start + (max(1, length // 2) if strategy == "sni_split" else 0)
        cut = max(1, min(len(data) - 1, cut))
        return [data[:cut], data[cut:]]
    if strategy == "sni_chars" and location:
        start, length = location
        out = [data[:start]] if start else []
        out.extend(data[start + i:start + i + 1] for i in range(length))
        if start + length < len(data):
            out.append(data[start + length:])
        return [x for x in out if x]
    if strategy in {"tls_record_frag", "tls_sni_records"} and data[0] == 0x16 and len(data) > 5:
        payload = data[5:]
        version = data[1:3]
        if strategy == "tls_sni_records" and location:
            split = max(1, min(len(payload) - 1, location[0] - 5))
        else:
            split = max(1, len(payload) // 2)
        return [tls_record(version, payload[:split]), tls_record(version, payload[split:])]
    return [data]


def make_client_hello(hostname: str) -> bytes:
    """Let Windows/OpenSSL create a valid ClientHello for a disposable fake probe."""
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    context = ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1"])
    ssl_obj = context.wrap_bio(incoming, outgoing, server_side=False, server_hostname=hostname)
    try:
        ssl_obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def random_padding(size: int) -> bytes:
    return os.urandom(max(0, size))
