"""ASCII connection summary lines for the engine-1 connect log."""
from __future__ import annotations

import json

try:
    from .gene_import import TUNNEL_SAFE_KINDS
except Exception:  # pragma: no cover
    TUNNEL_SAFE_KINDS = frozenset({"tcp_frag", "delay", "record_cut", "sni_cut"})


def _ascii(value) -> str:
    return str(value if value is not None else "").encode("ascii", "replace").decode("ascii").strip()


def _split(csv) -> list:
    return [x.strip() for x in str(csv or "").split(",") if x.strip()]


def split_ops(ops_json) -> tuple:
    try:
        ops = json.loads(ops_json) if isinstance(ops_json, str) and ops_json else ops_json
    except ValueError:
        ops = None
    applied, skipped = [], []
    for op in ops if isinstance(ops, list) else []:
        kind = str((op or {}).get("kind", "") if isinstance(op, dict) else "").strip().lower()
        if kind:
            (applied if kind in TUNNEL_SAFE_KINDS else skipped).append(kind)
    return applied, skipped


def edge_source(edge, gene_edges="", profile_edges=(), use_profile_edges=False) -> str:
    edge = str(edge or "").strip()
    if not edge:
        return "unknown"
    if edge in _split(gene_edges):
        return "gene"
    if use_profile_edges and edge in [str(e).strip() for e in profile_edges]:
        return "profile"
    return "settings"


def gene_label(gene) -> str:
    """ASCII form of the gene dropdown label plus id, e.g. 'name | primitive | 100% (gene_x)'."""
    if not isinstance(gene, dict) or not gene:
        return ""
    gid = _ascii(gene.get("id", ""))
    try:
        from .gene_import import display_label
        label = str(display_label(gene, "en") or "")
    except Exception:
        label = str(gene.get("name", "") or gene.get("method", "") or "")
    label = label.replace("\u00b7", "|").strip()
    if label.startswith("* "):
        label = label[2:]
    label = " ".join(_ascii(label).split())
    if not label:
        return gid or "gene"
    return "%s (%s)" % (label, gid) if gid else label


def strategy_label(gene, method) -> str:
    if isinstance(gene, dict) and gene:
        return gene_label(gene)
    return "built-in (%s)" % _ascii(method)


def format_connected_block(config, gene, method, fake_sni, edge, edge_from,
                           carrier, lock, multi_gene, ops_json="", ech_state="") -> str:
    method_line = _ascii(method)
    if str(method).lower() == "primitive":
        applied, skipped = split_ops(ops_json)
        method_line += "  (ops applied=%s skipped=%s)" % (
            ",".join(applied) or "-", ",".join(skipped) or "-")
    lines = [
        "===== CONNECTED =====",
        "  Config   : " + _ascii(config),
        "  Strategy : " + strategy_label(gene, method),
        "  Method   : " + method_line,
        "  Fake SNI : " + (_ascii(fake_sni) or "-"),
        "  Edge IP  : %s  (from: %s)" % (_ascii(edge) or "-", _ascii(edge_from)),
        "  Carrier  : %s  Lock: %s  Multi-gene: %s" % (
            _ascii(carrier), "on" if lock else "off", "on" if multi_gene else "off"),
        "=====================",
    ]
    if ech_state:
        key = {"fresh": "key fresh", "cached": "key cached", "raw": "key from config",
               "fallback": "key built-in fallback"}.get(
            str(ech_state), "key via xray")
        lines.insert(-1, "  ECH      : on \u00b7 " + key)
    return "\n".join(lines)


def format_fail_line(config, gene, method, reason) -> str:
    reason = " ".join(_ascii(reason).split())
    if len(reason) > 120:
        reason = reason[:117] + "..."
    return "CONNECT FAIL: %s strategy=%s reason=%s" % (
        _ascii(config), strategy_label(gene, method), reason or "unknown")
