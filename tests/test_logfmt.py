from dataclasses import dataclass

from uac_desktop import logfmt as L

SESSION = [
    "Speed options on: parallel MASQUE, lowest-latency clean IP",
    "Outer attempt 1/1: MASQUE (120s, balanced)",
    "Key: saved WARP key and MASQUE certificate found; skipping the key request",
    "Connecting MASQUE over HTTP/2 · IP scan both · balanced",
    "MASQUE start via HTTP/2 with 2 known gateway(s)",
    *[f"Scan 162.159.199.{i}:443 trying" for i in range(12)],
    "Rejected 172.65.251.213:443: tls: h2 tls handshake failed",
    "Saved clean HTTP/2 address 162.159.199.95:443",
    "MASQUE is carrying the outer leg",
    "Psiphon connected via F",
    "UAC PoW ready · Tunnel through Psiphon over MASQUE",
    "Exit IP 172.105.251.210 (DE)",
    "Parallel MASQUE: session to 162.159.198.177:443 is up on 1826; 2 sessions, new connections are spread per site",
    "Parallel MASQUE: session to 162.159.199.192:443 is up on 1827; 3 sessions, new connections are spread per site",
]


def _model(lines=SESSION, start=1000.0):
    model = L.LogModel()
    for i, line in enumerate(lines):
        model.add(line, f"18:00:{i:02d}", now=start + i)
    return model


def test_classify_tags_and_levels():
    assert L.classify("Key fetch done in 6s via ECH").cat == "KEY"
    scan = L.classify("Scan 1.2.3.4:443 trying")
    assert scan.cat == "SCAN" and scan.noise and scan.level == "muted"
    drop = L.classify("UAC PoW path lost: outer leg exited")
    assert drop.cat == "DROP" and drop.level == "error" and drop.event == "drop"
    assert drop.en == "Connection dropped: outer leg exited"
    ready = L.classify("UAC PoW ready · Tunnel through Psiphon over MASQUE")
    assert ready.cat == "STATE" and ready.level == "success" and ready.event == "connected"
    assert L.classify("Parallel MASQUE: trying extra sessions to 1.1.1.1:443").cat == "PARALLEL"
    assert L.classify("HTTP/3 on Irancell: HTTP/3 won").cat == "H3"
    assert L.classify("Direct Psiphon first: direct Psiphon won in 3.1s").cat == "DIRECT"
    assert L.classify("Lowest-latency IP: 3 known clean address(es)").cat == "LOWLAT"
    assert L.classify("Psiphon strategy F (direct through WARP)").cat == "PSIPHON"
    assert L.classify("[17:57:49] Engine switched to pow").stamp == "17:57:49"


def test_fallback_is_highlighted():
    entry = L.classify("WireGuard did not connect; fell back to MASQUE, which is carrying the outer leg")
    assert entry.event == "fallback" and entry.level == "warning"
    assert entry.en == "WireGuard failed → MASQUE"
    html = L.render_html(L.LogModel().rows() or [L.Row("entry", entry, 1, entry.phase, entry.stamp, "k")])
    assert "background-color:#2b2412" in html


def test_noise_folds_into_one_pulse_row_unless_details():
    model = _model()
    rows = [r for r in model.rows() if r.kind != "section"]
    pulses = [r for r in rows if r.kind == "pulse"]
    assert len(pulses) == 1 and pulses[0].count == 13  # 12 trying + 1 rejected
    assert not any("MASQUE start via" in r.entry.raw for r in rows)  # core echo hidden
    detailed = [r for r in model.rows(details=True) if r.kind != "section"]
    assert any(r.entry.raw.startswith("Scan 162.159.199.3") for r in detailed)
    assert any("MASQUE start via" in r.entry.raw for r in detailed)


def test_identical_lines_collapse_with_count():
    model = _model(["Psiphon: notice A", "Network: x", "Network: x", "Network: x", "Engine switched to pow"])
    rows = [r for r in model.rows() if r.kind == "entry"]
    net = [r for r in rows if r.entry.raw == "Network: x"]
    assert len(net) == 1 and net[0].count == 3
    assert "×3" in L.render_text(model.rows())


def test_sections_group_phases_without_spraying_headers():
    model = _model()
    sections = [r.phase for r in model.rows() if r.kind == "section"]
    assert sections[0] == "speed"
    assert "key" in sections and "scan" in sections and "connected" in sections
    # No two headers in a row and no empty sections.
    rows = model.rows()
    assert all(not (a.kind == b.kind == "section") for a, b in zip(rows, rows[1:]))


def test_summary_state_tracks_connect_exit_parallel_and_drop():
    model = _model()
    state = model.state
    assert state.status == "connected"
    assert state.route == "Psiphon over MASQUE"
    assert (state.exit_ip, state.exit_country) == ("172.105.251.210", "DE")
    assert state.parallel == 3
    assert state.uptime(now=state.connected_at + 75) == "01:15"
    model.add("UAC PoW path lost: outer leg exited", "18:30:00", now=3000)
    assert state.status == "dropped" and state.last_drop == "outer leg exited"
    assert state.last_drop_stamp == "18:30:00" and state.parallel == 0 and state.uptime() == ""
    model.add("Speed options on: parallel MASQUE", "18:30:05", now=3005)
    assert state.status == "connecting"


def test_connected_row_shows_exit_and_parallel_count_with_flag():
    model = _model()
    connected = next(r for r in model.rows() if r.kind == "entry" and r.entry.event == "connected")
    text, _ = L.row_text(connected)
    assert text == "Connected: Psiphon over MASQUE · exit 172.105.251.210 · 3 parallel sessions"
    html = L.render_html(model.rows(), flag_path=lambda cc: f"/flags/{cc.lower()}.png")
    assert '<img src="/flags/de.png"' in html


def test_setting_changes_lines():
    @dataclass
    class S:
        parallel_masque: bool = False
        outer_transport: str = "auto"
        firewall_profile: str = "mci"

    lines = L.setting_changes(S(), S(parallel_masque=True, outer_transport="wireguard"), connected=True)
    assert "Setting changed: Parallel MASQUE on (applies on next connect)" in lines
    assert "Setting changed: Transport auto → wireguard (applies on next connect)" in lines
    assert L.setting_changes(S(), S(), connected=False) == []
    assert L.setting_changes(S(), S(parallel_masque=True), connected=False) == ["Setting changed: Parallel MASQUE on"]
    entry = L.classify(lines[0])
    assert entry.cat == "SET" and entry.event == "setting"
    assert entry.fa.startswith("تغییر تنظیم:")


def test_persian_keeps_ips_and_ports_intact():
    entry = L.classify("Saved clean HTTP/2 address 162.159.199.95:443")
    row = L.Row("entry", entry, 1, entry.phase, "18:00:00", "k")
    html = L.render_html([row], "fa")
    assert 'dir="rtl"' in html
    assert "162.159.199.95:443" in html and 'dir="ltr"' in html
    # Untranslated technical lines stay LTR in Persian.
    raw = L.classify("Psiphon strategy F (direct through WARP) region=DE")
    html = L.render_html([L.Row("entry", raw, 1, raw.phase, "18:00:00", "k")], "fa")
    assert 'dir="ltr"' in html


def test_filter_and_cap():
    model = _model()
    rows = [r for r in model.rows(query="exit ip") if r.kind != "section"]
    assert [r.entry.raw for r in rows] == ["Exit IP 172.105.251.210 (DE)"]
    big = L.LogModel(limit=50)
    for i in range(200):
        big.add(f"Network: {i}", "18:00:00", now=0)
    assert len(big.entries) == 50
