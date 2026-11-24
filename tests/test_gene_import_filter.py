from __future__ import annotations

import json
from pathlib import Path

from uac_desktop.gene_import import load_strategies_file


def test_import_skips_unconfirmed(tmp_path: Path):
    payload = {
        "strategies": [
            {
                "id": "a", "name": "bad", "method": "full5",
                "fake_sni": "chatgpt.com", "fake_repeat": 1,
                "inject_delay_ms": 1, "fragment_delay_ms": 5, "chunk_size": 5,
                "score": 0.9, "success_rate": 1.0, "tests": 1, "avg_ms": 100,
                "confirmed": False, "recommended": True, "mode": "live",
            },
            {
                "id": "b", "name": "good", "method": "wrong_seq",
                "fake_sni": "chatgpt.com", "fake_repeat": 1,
                "inject_delay_ms": 1, "fragment_delay_ms": 0, "chunk_size": 5,
                "score": 0.8, "success_rate": 1.0, "tests": 3, "avg_ms": 120,
                "confirmed": True, "recommended": True, "mode": "live",
                "confirmed_ips": ["1.1.1.1", "1.0.0.1", "8.8.8.8"],
            },
        ]
    }
    path = tmp_path / "strategies.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    imported = load_strategies_file(path)
    assert len(imported) == 1
    assert imported[0]["id"] == "b"
    assert imported[0]["confirmed"] is True
