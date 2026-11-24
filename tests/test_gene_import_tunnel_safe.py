from __future__ import annotations

import json
from pathlib import Path

from uac_desktop.gene_import import load_strategies_file


def _gene(gid: str, ops: list, **extra) -> dict:
    base = {
        "id": gid, "name": gid, "method": "primitive", "genome": "primitive", "ops": ops,
        "fake_sni": "chatgpt.com", "fake_repeat": 1, "inject_delay_ms": 1,
        "score": 0.9, "success_rate": 1.0, "tests": 3, "avg_ms": 100,
        "confirmed": True, "mode": "live", "confirmed_ips": ["1.1.1.1", "1.0.0.1", "8.8.8.8"],
    }
    base.update(extra)
    return base


def test_gene_import_only_tunnel_safe_primitives(tmp_path: Path):
    safe_ops = [{"kind": "record_cut", "size": 27}, {"kind": "sni_cut", "offset": 3},
                {"kind": "tcp_frag", "size": 3, "delay_ms": 2}, {"kind": "delay", "delay_ms": 4}]
    payload = {"strategies": [
        _gene("safe", safe_ops, tunnel_safe=True),
        _gene("safe_noflag", [{"kind": "tcp_frag", "size": 5}]),
        _gene("reorder", [{"kind": "tcp_frag", "size": 3}, {"kind": "reorder_send", "size": 2048}]),
        _gene("pad", [{"kind": "pad_ext", "size": 37}, {"kind": "tcp_frag", "size": 3}], tunnel_safe=True),
        _gene("flag_false", [{"kind": "tcp_frag", "size": 4}], tunnel_safe=False),
        {"id": "legacy", "name": "legacy", "method": "full5", "fake_sni": "chatgpt.com",
         "score": 0.5, "success_rate": 1.0, "tests": 3, "confirmed": True, "mode": "live",
         "confirmed_ips": ["1.1.1.1"]},
    ]}
    path = tmp_path / "strategies.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    ids = {s["id"] for s in load_strategies_file(path)}
    assert ids == {"safe", "safe_noflag", "legacy"}
