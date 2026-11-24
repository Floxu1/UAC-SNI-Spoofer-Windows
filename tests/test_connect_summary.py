from uac_desktop.connect_summary import (
    edge_source, format_connected_block, format_fail_line, split_ops)


def test_block_gene_primitive():
    gene = {"id": "gene_abc", "name": "frag", "method": "primitive"}
    out = format_connected_block("US-1", gene, "primitive", "chatgpt.com", "104.18.1.201",
                                 "gene", "mci", False, True,
                                 '[{"kind":"tcp_frag"},{"kind":"pad_ext"}]')
    assert out.splitlines()[0] == "===== CONNECTED ====="
    assert "Strategy : frag | primitive | 0% (gene_abc)" in out
    assert "applied=tcp_frag skipped=pad_ext" in out
    assert "Edge IP  : 104.18.1.201  (from: gene)" in out
    assert "Lock: off  Multi-gene: on" in out
    out.encode("ascii")


def test_block_builtin_and_fail():
    out = format_connected_block("X", None, "wrong_seq", "a.com", "1.1.1.1", "settings", "mci", True, False)
    assert "Strategy : built-in (wrong_seq)" in out and "ops applied" not in out
    line = format_fail_line("X", None, "full5", "timeout\n  x" * 50)
    assert line.startswith("CONNECT FAIL: X strategy=built-in (full5) reason=timeout x")
    assert len(line) < 200


def test_edge_source_and_ops():
    assert edge_source("1.1.1.1", "1.1.1.1,2.2.2.2") == "gene"
    assert edge_source("3.3.3.3", "", ["3.3.3.3"], True) == "profile"
    assert edge_source("3.3.3.3", "", ["3.3.3.3"], False) == "settings"
    assert split_ops("bad") == ([], [])


def test_gene_label_matches_dropdown():
    gene = {"id": "gene_5b0efdbb761c", "name": "mci_first/rec16+tcp4", "method": "primitive",
            "success_rate": 1.0, "confirmed": True}
    out = format_connected_block("US", gene, "primitive", "a.com", "1.1.1.1", "gene", "mci", False, True)
    assert "Strategy : mci_first/rec16+tcp4 | primitive | 100% (gene_5b0efdbb761c)" in out
    line = format_fail_line("US", gene, "primitive", "timeout")
    assert line == ("CONNECT FAIL: US strategy=mci_first/rec16+tcp4 | primitive | 100% "
                    "(gene_5b0efdbb761c) reason=timeout")
