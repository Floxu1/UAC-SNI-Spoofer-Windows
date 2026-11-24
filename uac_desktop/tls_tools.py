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




def rewrite_outer_sni(data: bytes, new_hostname: str) -> bytes:
    """Replace outer SNI hostname and fix TLS length fields. Same-length preferred."""
    loc = locate_sni(data)
    if not loc or not new_hostname:
        return data
    start, length = loc
    new_bytes = new_hostname.encode("ascii", "ignore")
    if not new_bytes:
        return data
    if len(new_bytes) == length:
        return data[:start] + new_bytes + data[start + length:]
    # Length-changing rewrite: patch name_len, list_len, ext_len, handshake, record.
    delta = len(new_bytes) - length
    out = bytearray(data[:start] + new_bytes + data[start + length:])
    # name_len at start-2
    name_len_pos = start - 2
    if name_len_pos >= 0:
        out[name_len_pos:name_len_pos + 2] = struct.pack(">H", len(new_bytes))
    # server_name list length at start-5 (2 bytes list len after ext header + name type)
    list_len_pos = start - 5
    if list_len_pos >= 2:
        old_list = int.from_bytes(out[list_len_pos:list_len_pos + 2], "big")
        out[list_len_pos:list_len_pos + 2] = struct.pack(">H", max(0, old_list + delta))
    # extension length at start-9
    ext_len_pos = start - 9
    if ext_len_pos >= 0:
        old_ext = int.from_bytes(out[ext_len_pos:ext_len_pos + 2], "big")
        out[ext_len_pos:ext_len_pos + 2] = struct.pack(">H", max(0, old_ext + delta))
    # handshake length at bytes 6..8 (record=5, hs_type=1, hs_len=3)
    if len(out) >= 9 and out[0] == 0x16 and out[5] == 0x01:
        old_hs = int.from_bytes(out[6:9], "big")
        out[6:9] = struct.pack(">I", max(0, old_hs + delta))[1:]
        old_rec = int.from_bytes(out[3:5], "big")
        out[3:5] = struct.pack(">H", max(0, old_rec + delta))
    return bytes(out)


def caseflip_sni(data: bytes) -> bytes:
    """Mixed-case outer SNI to defeat exact-match DPI (TLS accepts case-insensitive)."""
    loc = locate_sni(data)
    if not loc:
        return data
    start, length = loc
    host = bytearray(data[start:start + length])
    for i, b in enumerate(host):
        if 97 <= b <= 122 and (i % 2 == 0):
            host[i] = b - 32
        elif 65 <= b <= 90 and (i % 2 == 1):
            host[i] = b + 32
    return data[:start] + bytes(host) + data[start + length:]

def find_sni(data: bytes) -> str:
    located = locate_sni(data)
    if not located:
        return ""
    start, length = located
    return data[start:start + length].decode("ascii", "ignore")


def tls_record(version: bytes, payload: bytes) -> bytes:
    return b"\x16" + version + struct.pack(">H", len(payload)) + payload


def _permute_indices(n: int, seed: int) -> list[int]:
    order = list(range(max(0, int(n))))
    if len(order) <= 1:
        return order
    state = int(seed) & 0xFFFFFFFF or 1
    for i in range(len(order) - 1, 0, -1):
        state = (1103515245 * state + 12345) & 0xFFFFFFFF
        j = state % (i + 1)
        order[i], order[j] = order[j], order[i]
    return order


def fragments_from_ops(data: bytes, ops: list | None) -> list[bytes]:
    """Gene Lab primitive ops on the live ClientHello (see gene_ops.build_plan).

    Live-safe subset: record_cut, sni_cut, tcp_frag, delay. Use
    gene_plan_from_ops() when per-piece delays are needed.
    """
    if not data:
        return [data]
    return [p for p in gene_plan_from_ops(data, ops).pieces if p] or [data]


def gene_plan_from_ops(data: bytes, ops: list | None, strict: bool = False):
    from .gene_ops import build_plan
    return build_plan(data, [op for op in (ops or []) if isinstance(op, dict)], strict=strict)


def fragments(data: bytes, strategy: str, chunk_size: int = 5, ops: list | None = None) -> list[bytes]:
    if len(data) < 2:
        return [data]
    if strategy == "primitive":
        return fragments_from_ops(data, ops)
    if strategy == "plain":
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
    if strategy in {"sni_midcut", "sni_midcut3", "sni_hostcut"} and location:
        start, length = location
        if strategy == "sni_hostcut" and length >= 12:
            cuts = [start + 5, start + 11]  # cloud|flare|-ech.com style
        elif strategy == "sni_midcut3":
            cuts = [start + max(1, length // 4), start + max(2, length // 2),
                    start + max(3, (3 * length) // 4)]
        else:
            cuts = [start + max(1, length // 3), start + max(2, (2 * length) // 3)]
        cuts = sorted({c for c in cuts if 0 < c < len(data)})
        pieces = []
        prev = 0
        for cut in cuts:
            pieces.append(data[prev:cut])
            prev = cut
        pieces.append(data[prev:])
        return [p for p in pieces if p]
    if strategy == "outer_rewrite":
        # Applied in Pattern core before fragments; keep as plain here.
        return [data]
    # MCI-only coalesce / zero-length TLS records (scanner winners). Irancell never selects these.
    if strategy in {"coal_2x_zero_v0304", "coal_zero_v0304", "coal_zero_v0303", "coal_5x_zero_v0302", "coal_zero_v0302"}:
        pre = {
            "coal_2x_zero_v0304": bytes.fromhex("16030400001603040000"),
            "coal_zero_v0304": bytes.fromhex("1603040000"),
            "coal_zero_v0303": bytes.fromhex("1603030000"),
            "coal_zero_v0302": bytes.fromhex("1603020000"),
            "coal_5x_zero_v0302": bytes.fromhex("1603020000") * 5,
        }[strategy]
        # Single send: empty record(s) + original ClientHello (matches scanner 1xSend).
        return [pre + data]
    if strategy == "coal_2x_zero_then_split" and data[0] == 0x16 and len(data) > 10:
        pre = bytes.fromhex("16030400001603040000")
        cut = max(1, len(data) // 2)
        return [pre + data[:cut], data[cut:]]
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
