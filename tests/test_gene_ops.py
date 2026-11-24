from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

from uac_desktop.gene_ops import build_plan, parse_client_hello, permute_indices
from uac_desktop.tls_tools import fragments, make_client_hello

GENELAB = Path(r"E:\desktop\Generic project updated")
D90 = [
    {"kind": "grease", "size": 1}, {"kind": "pad_ext", "size": 37},
    {"kind": "pad_ext", "size": 37}, {"kind": "shuffle_ext", "size": 2048},
    {"kind": "tcp_frag", "size": 3, "delay_ms": 2}, {"kind": "tcp_frag", "size": 27, "delay_ms": 4},
    {"kind": "tcp_frag", "size": 11, "delay_ms": 0}, {"kind": "reorder_send", "size": 2048},
]


def _genelab():
    if not (GENELAB / "gene_core").is_dir():
        pytest.skip("Gene Lab not present")
    if str(GENELAB) not in sys.path:
        sys.path.insert(0, str(GENELAB))
    return importlib.import_module("gene_core.primitives"), importlib.import_module("gene_core.tls_hello")


def _hello() -> bytes:
    return make_client_hello("www.speedtest.net")


def test_gene_live_reassembles_same_sni():
    hello = _hello()
    ops = [{"kind": "record_cut", "size": 27}, {"kind": "sni_cut", "offset": 3},
           {"kind": "tcp_frag", "size": 4, "delay_ms": 5}] + D90
    plan = build_plan(hello, ops)
    wire = b"".join(plan.pieces)
    assert wire == plan.wire
    assert parse_client_hello(wire).sni == "www.speedtest.net"
    assert set(plan.skipped) >= {"grease", "pad_ext", "shuffle_ext", "reorder_send"}
    assert "record_cut" in plan.applied and "sni_cut" in plan.applied
    assert plan.delays_ms[-1] == 0 and any(d > 0 for d in plan.delays_ms)


def test_gene_strict_rewrite_valid_and_changed():
    hello = _hello()
    plan = build_plan(hello, D90, strict=True)
    joined = b"".join(sorted(plan.pieces, key=lambda p: plan.wire.find(p)))
    parsed = parse_client_hello(plan.wire)
    assert parsed.sni == "www.speedtest.net"
    types = [t for t, _ in parsed.extensions]
    assert types[0] == 0x0A0A and 0x0015 in types
    assert dict(parsed.extensions)[0x0015] == b"\x00" * 37
    assert plan.wire != hello and len(joined) == len(plan.wire)


def test_gene_delays_and_reorder_deterministic():
    hello = _hello()
    a = build_plan(hello, D90, strict=True)
    b = build_plan(hello, D90, strict=True)
    assert a.pieces == b.pieces and a.delays_ms == b.delays_ms
    assert len(a.delays_ms) == len(a.pieces) and a.delays_ms[-1] == 0
    live = build_plan(hello, D90)
    assert live.delays_ms == [2, 4, 0, 0]
    assert [len(p) for p in live.pieces[:3]] == [3, 27, 11]


def test_gene_permute_matches_genelab():
    prim, _ = _genelab()
    for n in range(1, 9):
        for seed in (1, 660, 804, 2045, 2048, 9999):
            assert permute_indices(n, seed) == prim._permute_indices(n, seed)


def test_gene_parse_failure_falls_back():
    junk = b"\x16\x03\x01\x00\x10" + b"\xff" * 16
    plan = build_plan(junk, [{"kind": "record_cut", "size": 4}, {"kind": "tcp_frag", "size": 5}])
    assert b"".join(plan.pieces) == junk and plan.error and "record_cut" in plan.skipped


def test_gene_legacy_unchanged():
    hello = _hello()
    assert fragments(hello, "full5") == [hello[i:i + 5] for i in range(0, len(hello), 5)]
    assert fragments(hello, "plain") == [hello]


def test_gene_parity_with_genelab_d90():
    prim, tls = _genelab()
    data = json.loads((GENELAB / "data" / "strategies2.json").read_text(encoding="utf-8"))
    genes = data if isinstance(data, list) else data.get("strategies", [])
    gene = next(g for g in genes if g.get("id") == "gene_d90e5ffbd5cf")
    rnd = bytes(range(32))
    host = "www.speedtest.net"
    lab = prim.apply_primitives(host, prim.normalize_ops(gene["ops"]), random_bytes=rnd)
    base = tls.build_wire_client_hello(host, random_bytes=rnd)  # untouched hello
    uac = build_plan(base, gene["ops"], strict=True)
    assert uac.wire == lab.wire
    assert uac.pieces == [p.data for p in lab.pieces]
    assert uac.delays_ms == [p.delay_ms_after for p in lab.pieces]
