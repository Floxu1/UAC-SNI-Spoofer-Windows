"""Connect-steps store — port of mobile ``PowStatusStore``.

Thread-safe; UI subscribes via ``add_listener`` and receives a snapshot dict.
Step text mirrors the mobile stage/scan lines so behaviour stays identical.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class PowPhase(str, Enum):
    IDLE = "idle"
    STARTING = "starting"
    OUTER = "outer"
    INNER = "inner"
    BRIDGING = "bridging"
    CONNECTED = "connected"
    FAILED = "failed"


class PowStepState(str, Enum):
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


@dataclass
class PowStep:
    text: str
    state: PowStepState = PowStepState.RUNNING


@dataclass
class PowUiStatus:
    phase: PowPhase = PowPhase.IDLE
    progress: int = 0
    detail: str = ""
    outer_label: str = ""
    exit_region: str = ""
    steps: list[PowStep] = field(default_factory=list)


def scan_pulse(message: str) -> str | None:
    """Map a native scan line to a ``Scan <addr> <outcome>`` step line."""
    text = message.strip()
    if text.startswith("Scanning "):
        rest = text[len("Scanning ") :]
        if " via " in rest:
            addr = rest.split(" via ")[0].strip()
        else:
            addr = rest.split()[0] if rest.split() else rest
        return f"Scan {addr} trying"
    if not text.startswith("Rejected "):
        return None
    body = text[len("Rejected ") :]
    if ": " in body:
        addr, _sep, _reason = body.partition(": ")
    else:
        addr = body.split()[0] if body.split() else body
    addr = addr.strip()
    if "status 400" in text:
        why = "400"
    elif "ACCESS_DENIED" in text:
        why = "access-denied"
    elif "CERTIFICATE" in text:
        why = "certificate"
    elif "timeout" in text.lower():
        why = "timeout"
    elif "reset" in text.lower():
        why = "reset"
    elif "unexpected EOF" in text:
        why = "eof"
    else:
        why = "other"
    return f"Scan {addr} {why}"


def stage_line(message: str) -> str | None:
    """Map a native log line to a user-facing step line (mobile parity)."""
    text = (message or "").strip()
    if text.startswith("Key:"):
        return "Key " + text[len("Key:") :].strip()
    if text.startswith("Cert:"):
        return "Cert " + text[len("Cert:") :].strip()
    if text.startswith("Clean HTTP/2 list:"):
        return text
    if text.startswith("Clean HTTP/2 list is empty. Starting"):
        return "Clean list empty. HTTP/2 scan is starting."
    if text.startswith("Trying saved clean address"):
        return text
    if text.startswith("Saved clean address accepted"):
        return text
    if text.startswith("Saved clean address rejected"):
        return text
    if text.startswith("Every saved address failed. Scan was not started"):
        return text
    if text.startswith("Every saved address failed. Starting"):
        return "Saved addresses failed. HTTP/2 scan is starting."
    if text.startswith("Scanning HTTP/2"):
        return text
    if text.startswith("Saved clean HTTP/2 address"):
        return text
    if text.startswith("Scanning ") or text.startswith("Rejected "):
        return scan_pulse(text)
    if text.startswith("HTTP/2 selected"):
        return "HTTP/2 started"
    if text.startswith("MASQUE accepted"):
        return text
    if text.startswith("MASQUE start"):
        return text
    if text.startswith("Tunnel did not stay up"):
        return text
    if text.startswith("MASQUE: dialing known gateways on UDP/1701"):
        return "Trying UDP/1701"
    if text.startswith("MASQUE: no known gateway accepted UDP/1701"):
        return "UDP/1701 did not answer"
    if text.startswith("MASQUE: UDP/1701 did not answer"):
        return "UDP/1701 did not answer, trying TCP"
    if text.startswith("No usable MASQUE"):
        return text
    if text.startswith("MASQUE identity refused"):
        return "Certificate refused. Requesting a new one."
    if text.startswith("Certificate "):
        return text
    if text.startswith("This certificate was refused"):
        return text
    if text.startswith("New certificate saved"):
        return text
    if text.startswith("New MASQUE certificate issued"):
        return "New certificate issued. Retrying the gateways."
    if text.startswith("Could not refresh the MASQUE certificate"):
        return text
    if text.startswith("PSIPHON "):
        return text
    return None


class PowStatusStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._status = PowUiStatus()
        self._listeners: list[Callable[[PowUiStatus], None]] = []

    def add_listener(self, listener: Callable[[PowUiStatus], None]) -> None:
        with self._lock:
            self._listeners.append(listener)

    def snapshot(self) -> PowUiStatus:
        with self._lock:
            current = self._status
            return PowUiStatus(
                phase=current.phase,
                progress=current.progress,
                detail=current.detail,
                outer_label=current.outer_label,
                exit_region=current.exit_region,
                steps=list(current.steps),
            )

    def _emit(self) -> None:
        snapshot = self.snapshot()
        for listener in list(self._listeners):
            try:
                listener(snapshot)
            except Exception:
                pass

    def update(
        self,
        phase: PowPhase,
        progress: int = 0,
        detail: str = "",
        outer_label: str | None = None,
        exit_region: str | None = None,
    ) -> None:
        with self._lock:
            current = self._status
            self._status = PowUiStatus(
                phase=phase,
                progress=max(0, min(100, progress)),
                detail=detail,
                outer_label=current.outer_label if outer_label is None else outer_label,
                exit_region=current.exit_region if exit_region is None else exit_region,
                steps=current.steps,
            )
            changed = False
            if detail.strip():
                changed = self._note_locked(detail) or changed
            if phase == PowPhase.CONNECTED:
                changed = self._finish_locked(PowStepState.DONE) or changed
            if phase == PowPhase.FAILED:
                changed = self._finish_locked(PowStepState.FAILED) or changed
        self._emit()

    def pulse(self, text: str) -> None:
        clean = (text or "").strip()[:180]
        if not clean:
            return
        with self._lock:
            steps = list(self._status.steps)
            last = steps[-1] if steps else None
            if (
                last is not None
                and last.state == PowStepState.RUNNING
                and last.text.startswith("Scan ")
            ):
                if last.text == clean:
                    return
                steps[-1] = PowStep(clean, last.state)
                self._status = PowUiStatus(
                    phase=self._status.phase,
                    progress=self._status.progress,
                    detail=self._status.detail,
                    outer_label=self._status.outer_label,
                    exit_region=self._status.exit_region,
                    steps=steps,
                )
            else:
                if self._note_locked(clean):
                    pass
                else:
                    return
        self._emit()

    def scan(self, text: str, outcome: str) -> None:
        clean = (text or "").strip()[:180]
        if not clean:
            return
        state = (
            PowStepState.RUNNING
            if outcome == "trying"
            else PowStepState.DONE if outcome == "accepted" else PowStepState.FAILED
        )
        with self._lock:
            steps = list(self._status.steps)
            last = steps[-1] if steps else None
            if (
                last is not None
                and last.state == PowStepState.RUNNING
                and last.text.startswith("Scan ")
            ):
                steps[-1] = PowStep(clean, state)
            else:
                if last is not None and last.state == PowStepState.RUNNING:
                    steps[-1] = PowStep(last.text, PowStepState.DONE)
                steps.append(PowStep(clean, state))
                steps = steps[-24:]
            self._status = PowUiStatus(
                phase=self._status.phase,
                progress=self._status.progress,
                detail=self._status.detail,
                outer_label=self._status.outer_label,
                exit_region=self._status.exit_region,
                steps=steps,
            )
        self._emit()

    def note(self, text: str, failed: bool = False) -> None:
        with self._lock:
            changed = self._note_locked(text, failed)
        if changed:
            self._emit()

    def _note_locked(self, text: str, failed: bool = False) -> bool:
        clean = (text or "").strip()[:180]
        if not clean:
            return False
        steps = list(self._status.steps)
        last = steps[-1] if steps else None
        if last is not None and last.text == clean:
            return False
        if last is not None and last.state == PowStepState.RUNNING:
            steps[-1] = PowStep(last.text, PowStepState.DONE)
        steps.append(
            PowStep(clean, PowStepState.FAILED if failed else PowStepState.RUNNING)
        )
        self._status = PowUiStatus(
            phase=self._status.phase,
            progress=self._status.progress,
            detail=self._status.detail,
            outer_label=self._status.outer_label,
            exit_region=self._status.exit_region,
            steps=steps[-24:],
        )
        return True

    def _finish_locked(self, state: PowStepState) -> bool:
        steps = list(self._status.steps)
        if not steps or steps[-1].state != PowStepState.RUNNING:
            return False
        steps[-1] = PowStep(steps[-1].text, state)
        self._status = PowUiStatus(
            phase=self._status.phase,
            progress=self._status.progress,
            detail=self._status.detail,
            outer_label=self._status.outer_label,
            exit_region=self._status.exit_region,
            steps=steps,
        )
        return True

    def reset(self) -> None:
        with self._lock:
            self._status = PowUiStatus()
        self._emit()
