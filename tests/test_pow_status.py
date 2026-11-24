"""PoW steps-store tests — port of the mobile step/scan semantics."""

from __future__ import annotations

from uac_desktop.pow.status import (
    PowPhase,
    PowStepState,
    PowStatusStore,
    scan_pulse,
    stage_line,
)


def test_note_dedupes_and_marks_previous_done():
    store = PowStatusStore()
    store.note("Connecting MASQUE")
    store.note("Connecting MASQUE")
    snapshot = store.snapshot()
    assert len(snapshot.steps) == 1
    store.note("Scanning gateways")
    snapshot = store.snapshot()
    assert len(snapshot.steps) == 2
    assert snapshot.steps[0].state == PowStepState.DONE
    assert snapshot.steps[1].state == PowStepState.RUNNING


def test_steps_capped_at_24():
    store = PowStatusStore()
    for index in range(30):
        store.note(f"line {index}")
    assert len(store.snapshot().steps) == 24


def test_connected_and_failed_finish_last_step():
    store = PowStatusStore()
    store.note("Connecting MASQUE")
    store.update(PowPhase.CONNECTED, 100, "UAC PoW ready")
    assert store.snapshot().steps[-1].state == PowStepState.DONE
    store.note("Retrying")
    store.update(PowPhase.FAILED, 0, "boom")
    assert store.snapshot().steps[-1].state == PowStepState.FAILED


def test_scan_replaces_running_scan_line():
    store = PowStatusStore()
    store.scan("Scan 1.2.3.4 trying", "trying")
    store.scan("Scan 1.2.3.4 400", "400")
    snapshot = store.snapshot()
    assert len(snapshot.steps) == 1
    assert snapshot.steps[0].state == PowStepState.FAILED


def test_scan_pulse_outcomes():
    assert scan_pulse("Scanning 1.2.3.4:443 via HTTP/2") == "Scan 1.2.3.4:443 trying"
    assert scan_pulse("Rejected 1.2.3.4:443: masque: status 400").endswith("400")
    assert scan_pulse("Rejected 1.2.3.4:443: [TLSV1_ALERT_ACCESS_DENIED]").endswith(
        "access-denied"
    )
    assert scan_pulse("Rejected 1.2.3.4:443: h2 verify timeout").endswith("timeout")
    assert scan_pulse("Rejected 1.2.3.4:443: reset by peer").endswith("reset")
    assert scan_pulse("hello") is None


def test_stage_line_maps_native_logs():
    assert stage_line("Key: already saved") == "Key already saved"
    assert stage_line("MASQUE identity refused; requesting") == (
        "Certificate refused. Requesting a new one."
    )
    assert stage_line("New MASQUE certificate issued; retrying") == (
        "New certificate issued. Retrying the gateways."
    )
    assert stage_line("MASQUE accepted 1.2.3.4:443") == "MASQUE accepted 1.2.3.4:443"
    assert stage_line("No usable MASQUE gateway (x); retrying").startswith(
        "No usable MASQUE"
    )
    assert stage_line("random debug line") is None
