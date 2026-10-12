"""Gene Lab primitive ops applied to the LIVE ClientHello Pattern gets from xray.

Vendored from Gene Lab gene_core/primitives.py + tls_hello.py (no cross-project
import). Two modes:

* strict=True  : byte-for-byte Gene Lab semantics (pad/shuffle/grease rewrite,
  record_cut, sni_cut, junk_record prefix, tcp_frag, reorder_send, delays).
  Used for parity tests and opt-in experiments.
* strict=False (default for the live tunnel): only transforms that keep a real
  TLS session valid. Rewriting ClientHello bytes (pad/shuffle/grease) breaks the
  TLS 1.3 transcript hash (client Finished mismatch -> server aborts), a junk
  record before the hello makes the server alert, and reorder_send over a plain
  stream socket delivers scrambled bytes to the server. Gene Lab only "confirms"
  those genes on a handshake probe that also accepts a TLS alert as success.
  Live mode therefore runs record_cut, sni_cut, tcp_frag, delay and per-piece
  delays, and skips the rest (reported in GenePlan.skipped).

ttl / checksum_mode on junk_record need raw sockets / WinDivert; ignored here
exactly like Gene Lab's plain-socket sender.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Sequence

KINDS = frozenset({"tcp_frag", "delay", "record_cut", "pad_ext", "shuffle_ext",
                   "grease", "sni_cut", "junk_record", "reorder_send"})
REWRITE_KINDS = frozenset({"pad_ext", "shuffle_ext", "grease"})
LIVE_UNSAFE_KINDS = frozenset({"pad_ext", "shuffle_ext", "grease", "junk_record", "reorder_send"})

EXT_NAMES = {0x0000: "sni", 0x000A: "supported_groups", 0x000B: "ec_point_formats",
             0x000D: "signature_algorithms", 0x0010: "alpn", 0x0015: "padding",
             0x0017: "extended_master_secret", 0x002B: "supported_versions"}
EXT_GREASE_A = 0x0A0A
EXT_PSK = 0x0029


def _clamp(v: Any, lo: int, hi: int, default: int) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


@dataclass
class Op:
    kind: str = "tcp_frag"
    size: int = 5
    delay_ms: int = 0
    offset: int = 0
    content_type: int = 0x17
    ttl: int = 0
    checksum_mode: str = "valid"

    @classmethod
    def from_any(cls, raw: Any) -> "Op | None":
        if isinstance(raw, Op):
            return raw
        if not isinstance(raw, dict):
            return None
        kind = str(raw.get("kind", "tcp_frag") or "tcp_frag").strip().lower()
        kind = kind if kind in KINDS else "tcp_frag"
        size = _clamp(raw.get("size", 5), 0, 2048, 5)
        offset = _clamp(raw.get("offset", 0), 0, 4096, 0)
        if kind == "tcp_frag":
            size = _clamp(size, 1, 512, 5)
        elif kind == "record_cut":
            size = _clamp(size, 1, 1024, 64)
        elif kind == "pad_ext":
            size = _clamp(size, 0, 512, 0)
        elif kind == "sni_cut":
            offset = _clamp(offset, 0, 64, 0)
        elif kind == "junk_record":
            size = _clamp(size, 0, 256, 0)
        mode = str(raw.get("checksum_mode", "valid") or "valid").lower()
        return cls(kind, size, _clamp(raw.get("delay_ms", 0), 0, 80, 0), offset,
                   _clamp(raw.get("content_type", 0x17), 0, 255, 0x17),
                   _clamp(raw.get("ttl", 0), 0, 255, 0),
                   mode if mode in {"valid", "corrupt", "zero"} else "valid")


def normalize_ops(ops: Sequence[Any] | None) -> list[Op]:
    return [o for o in (Op.from_any(x) for x in (ops or [])) if o is not None]


def permute_indices(n: int, seed: int) -> list[int]:
    order = list(range(max(0, int(n))))
    if len(order) <= 1:
        return order
    state = int(seed) & 0xFFFFFFFF or 1
    for i in range(len(order) - 1, 0, -1):
        state = (1103515245 * state + 12345) & 0xFFFFFFFF
        j = state % (i + 1)
        order[i], order[j] = order[j], order[i]
    return order


def shuffle_order(seed: int, base: Sequence[str]) -> list[str]:
    order = list(base)
    state = int(seed) & 0xFFFFFFFF
    for i in range(len(order) - 1, 0, -1):
        state = (1103515245 * state + 12345) & 0xFFFFFFFF
        j = state % (i + 1)
        order[i], order[j] = order[j], order[i]
    return order


# ---------------------------------------------------------------- TLS parsing
@dataclass
class ParsedHello:
    record_version: bytes
    prefix: bytes            # handshake body up to (not incl.) extensions length
    extensions: list[tuple[int, bytes]]
    sni: str


def unwrap_records(wire: bytes) -> tuple[bytes, bytes]:
    """Concatenate handshake fragments of consecutive 0x16 records."""
    out = bytearray()
    i = 0
    version = b"\x03\x01"
    first = True
    while i + 5 <= len(wire):
        if wire[i] != 0x16:
            raise ValueError("not a handshake record")
        if first:
            version = wire[i + 1:i + 3]
            first = False
        n = int.from_bytes(wire[i + 3:i + 5], "big")
        if i + 5 + n > len(wire):
            raise ValueError("truncated record")
        out += wire[i + 5:i + 5 + n]
        i += 5 + n
    if i != len(wire) or not out:
        raise ValueError("trailing bytes")
    return bytes(out), version


def parse_client_hello(wire: bytes) -> ParsedHello:
    hs, version = unwrap_records(wire)
    if hs[0] != 0x01:
        raise ValueError("not ClientHello")
    blen = int.from_bytes(hs[1:4], "big")
    body = hs[4:4 + blen]
    if len(body) != blen:
        raise ValueError("truncated hello")
    p = 2 + 32
    p += 1 + body[p]
    p += 2 + int.from_bytes(body[p:p + 2], "big")
    p += 1 + body[p]
    if p + 2 > len(body):
        raise ValueError("no extensions")
    elen = int.from_bytes(body[p:p + 2], "big")
    ext_blob = body[p + 2:p + 2 + elen]
    if len(ext_blob) != elen or p + 2 + elen != len(body):
        raise ValueError("bad extensions length")
    exts: list[tuple[int, bytes]] = []
    q = 0
    sni = ""
    while q < len(ext_blob):
        if q + 4 > len(ext_blob):
            raise ValueError("bad extension header")
        t = int.from_bytes(ext_blob[q:q + 2], "big")
        n = int.from_bytes(ext_blob[q + 2:q + 4], "big")
        data = ext_blob[q + 4:q + 4 + n]
        if len(data) != n:
            raise ValueError("bad extension body")
        if t == 0 and len(data) >= 5 and data[2] == 0:
            hl = int.from_bytes(data[3:5], "big")
            sni = data[5:5 + hl].decode("ascii", "replace")
        exts.append((t, data))
        q += 4 + n
    return ParsedHello(version, body[:p], exts, sni)


def build_hello(parsed: ParsedHello, exts: Sequence[tuple[int, bytes]]) -> bytes:
    blob = b"".join(struct.pack("!HH", t, len(d)) + d for t, d in exts)
    body = parsed.prefix + struct.pack("!H", len(blob)) + blob
    return b"\x01" + struct.pack("!I", len(body))[1:] + body


def wrap_records(hs: bytes, sizes: Sequence[int] | None, first_version: bytes = b"\x03\x01") -> bytes:
    """Gene Lab wrap_tls_records: first record 0x0301, rest 0x0303."""
    clean = [max(1, int(s)) for s in (sizes or []) if int(s) > 0] or [len(hs)]
    chunks, off = [], 0
    for s in clean:
        if off >= len(hs):
            break
        chunks.append(hs[off:off + s])
        off += len(chunks[-1])
    if off < len(hs):
        chunks.append(hs[off:])
    out = bytearray()
    for c in chunks:
        ver = first_version if not out else b"\x03\x03"
        out += b"\x16" + ver + struct.pack("!H", len(c)) + c
    return bytes(out)


def rewrite_extensions(parsed: ParsedHello, pad: int, grease: bool, shuffle_seed: int | None) -> list[tuple[int, bytes]]:
    """Gene Lab extension semantics on an existing hello.

    Extensions are named (unknown -> hex), 'padding' slot appended if absent,
    shuffled with Gene Lab's LCG, GREASE 0x0A0A (body 0x00) put first, padding
    emitted with `pad` zero bytes (dropped when pad==0). pre_shared_key stays last.
    """
    names: list[str] = []
    by_name: dict[str, bytes] = {}
    psk = None
    for t, d in parsed.extensions:
        if t == EXT_PSK:
            psk = d
            continue
        name = EXT_NAMES.get(t, f"x{t:04x}")
        if name in by_name:
            name = f"{name}#{len(names)}"
        names.append(name)
        by_name[name] = d
    if "padding" not in names:
        names.append("padding")
    order = shuffle_order(shuffle_seed, names) if shuffle_seed is not None else list(names)
    if grease and "grease" not in order and not any(t == EXT_GREASE_A for t, _ in parsed.extensions):
        order.insert(0, "grease")
    rev = {v: k for k, v in EXT_NAMES.items()}
    out: list[tuple[int, bytes]] = []
    for name in order:
        if name == "grease":
            out.append((EXT_GREASE_A, b"\x00"))
        elif name == "padding":
            if pad > 0:
                out.append((0x0015, b"\x00" * min(pad, 2048)))
        else:
            base = name.split("#", 1)[0]
            t = rev[base] if base in rev else int(base[1:], 16)
            out.append((t, by_name[name]))
    if psk is not None:
        out.append((EXT_PSK, psk))
    return out


# ---------------------------------------------------------------- plan
@dataclass
class GenePlan:
    pieces: list[bytes]
    delays_ms: list[int]          # delay AFTER each piece (last is 0)
    wire: bytes                   # transformed ClientHello wire (no junk)
    applied: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    error: str = ""


def _split(data: bytes, sizes: Sequence[int]) -> list[bytes]:
    clean = [max(1, int(s)) for s in sizes if int(s) > 0]
    if not clean:
        return [data]
    out, off = [], 0
    for s in clean:
        if off >= len(data):
            break
        out.append(data[off:off + s])
        off += len(out[-1])
    if off < len(data):
        out.append(data[off:])
    return out or [data]


def build_plan(data: bytes, ops: Sequence[Any] | None, *, strict: bool = False) -> GenePlan:
    ops_n = normalize_ops(ops)
    skipped: list[str] = []
    if not strict:
        for o in ops_n:
            if o.kind in LIVE_UNSAFE_KINDS and o.kind not in skipped:
                skipped.append(o.kind)
        ops_n = [o for o in ops_n if o.kind not in LIVE_UNSAFE_KINDS]
    pad, grease, shuffle_seed, reorder_seed = 0, False, None, None
    record_sizes, tcp_sizes, tcp_delays, sni_cuts, junk = [], [], [], [], []
    for op in ops_n:
        k = op.kind
        if k == "pad_ext":
            pad = op.size
        elif k == "grease":
            grease = op.size > 0
        elif k == "shuffle_ext":
            shuffle_seed = op.size or op.offset or 1
        elif k == "record_cut":
            record_sizes.append(op.size)
        elif k == "tcp_frag":
            tcp_sizes.append(op.size)
            tcp_delays.append(op.delay_ms)
        elif k == "delay" and tcp_delays:
            tcp_delays[-1] = max(tcp_delays[-1], op.delay_ms)
        elif k == "sni_cut":
            sni_cuts.append(op.offset)
        elif k == "junk_record":
            junk.append(op)
        elif k == "reorder_send" and op.size > 0:
            reorder_seed = op.size
    applied = sorted({o.kind for o in ops_n})

    wire = data
    error = ""
    hostname = ""
    needs_parse = bool(record_sizes or sni_cuts or pad or grease or shuffle_seed is not None)
    if needs_parse:
        try:
            parsed = parse_client_hello(data)
            hostname = parsed.sni
            exts = parsed.extensions
            if pad or grease or shuffle_seed is not None:
                exts = rewrite_extensions(parsed, pad, grease, shuffle_seed)
            hs = build_hello(parsed, exts)
            if record_sizes or exts is not parsed.extensions:
                wire = wrap_records(hs, record_sizes or None, b"\x03\x01" if strict else parsed.record_version)
            parse_client_hello(wire)  # sanity
        except Exception as exc:  # noqa: BLE001 - graceful fallback to split-only
            error = f"{type(exc).__name__}: {exc}"
            wire = data
            for k in ("pad_ext", "grease", "shuffle_ext", "record_cut", "sni_cut"):
                if k in applied:
                    applied.remove(k)
                    skipped.append(k)
            sni_cuts = []

    if hostname and sni_cuts:
        needle = hostname.encode("ascii", "ignore")
        idx = wire.find(needle)
        if idx >= 0:
            length = max(1, len(needle))
            cuts = sorted({idx + max(0, min(length, o)) for o in sni_cuts if 0 <= o <= length})
            from_cuts, prev = [], 0
            for c in cuts:
                if c > prev:
                    from_cuts.append(c - prev)
                    prev = c
            if from_cuts:
                tcp_sizes = from_cuts + tcp_sizes
                tcp_delays = [0] * len(from_cuts) + tcp_delays

    junk_pieces = [(bytes([j.content_type & 0xFF]) + b"\x03\x03" + struct.pack("!H", j.size) + b"\x00" * j.size,
                    j.delay_ms) for j in junk]
    chunks = _split(wire, tcp_sizes)
    hello = []
    for i, c in enumerate(chunks):
        d = 0 if i >= len(chunks) - 1 else (tcp_delays[i] if i < len(tcp_delays) else 0)
        hello.append((c, d))
    if reorder_seed is not None and len(hello) >= 2:
        hello = [hello[i] for i in permute_indices(len(hello), reorder_seed)]
        hello[-1] = (hello[-1][0], 0)
    allp = junk_pieces + hello
    return GenePlan([p for p, _ in allp], [d for _, d in allp], wire, applied, skipped, error)
