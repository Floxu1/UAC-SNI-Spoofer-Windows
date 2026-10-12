"""WARP identity reader — port of mobile ``PowIdentityStatus.read``."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .config import identity_path


@dataclass
class IdentityStatus:
    present: bool = False
    enrolled: bool = False
    device_id: str = ""
    ipv4: str = ""
    ipv6: str = ""
    endpoint: str = ""
    organization: str = ""
    masque_certificate: bool = False
    issued_at_epoch_sec: int = 0
    peer_public_prefix: str = ""

    def issued_label(self) -> str:
        if self.issued_at_epoch_sec <= 0:
            return ""
        age_days = max(
            0, (int(time.time()) - self.issued_at_epoch_sec) // 86_400
        )
        left = max(0, 365 - age_days)
        try:
            day = datetime.fromtimestamp(
                self.issued_at_epoch_sec, tz=timezone.utc
            ).strftime("%Y-%m-%d")
        except (OverflowError, OSError, ValueError):
            day = ""
        return f"{day} · {left}d" if day else ""

    @property
    def state_label(self) -> tuple[str, str]:
        """(fa, en) status line mirroring the mobile key card."""
        if self.enrolled and self.masque_certificate:
            return ("گرفته شده", "Saved")
        if self.enrolled:
            return ("فقط کلید وارپ", "WARP key only")
        if self.present:
            return ("ناقص", "Incomplete")
        return ("گرفته نشده", "Not saved")


def parse_toml_scalars(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    in_multiline = False
    current_key = ""
    chunks: list[str] = []
    for raw in text.splitlines():
        if in_multiline:
            if raw.strip().endswith('"""'):
                chunks.append(raw.strip()[: -len('"""')])
                out[current_key] = "\n".join(chunks)
                in_multiline = False
            else:
                chunks.append(raw)
            continue
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("["):
            continue
        eq = stripped.find("=")
        if eq <= 0:
            continue
        key = stripped[:eq].strip()
        value = stripped[eq + 1 :].strip()
        if value.startswith('"""'):
            rest = value[len('"""') :]
            if rest.endswith('"""') and len(rest) >= len('"""'):
                out[key] = rest[: -len('"""')]
            else:
                in_multiline = True
                current_key = key
                chunks = [rest] if rest else []
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out[key] = value
    return out


def short_id(device_id: str) -> str:
    text = (device_id or "").strip()
    if len(text) <= 12:
        return text
    return f"{text[:8]}…{text[-4:]}"


def read_identity(data_dir: Path) -> IdentityStatus:
    path = identity_path(data_dir)
    if not path.is_file():
        return IdentityStatus()
    try:
        fields = parse_toml_scalars(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return IdentityStatus()
    token = fields.get("access_token", "")
    private_key = fields.get("wg_private_key", "")
    cert = fields.get("cert_pem", "")
    peer = fields.get("wg_peer_public_key", "")
    try:
        issued_at = int(fields.get("cert_issued_at", "0") or "0")
    except ValueError:
        issued_at = 0
    return IdentityStatus(
        present=True,
        enrolled=len(token) > 8 and len(private_key) > 20,
        device_id=fields.get("device_id", ""),
        ipv4=fields.get("ipv4", ""),
        ipv6=fields.get("ipv6", ""),
        endpoint=fields.get("assigned_endpoint", ""),
        organization=fields.get("organization", ""),
        masque_certificate="BEGIN CERTIFICATE" in cert,
        issued_at_epoch_sec=issued_at,
        peer_public_prefix=peer[:16],
    )


def forget_identity(data_dir: Path) -> bool:
    path = identity_path(data_dir)
    try:
        if path.is_file():
            path.unlink()
            return True
    except OSError:
        pass
    return False


def read_clean_h2_peers(data_dir: Path) -> list[str]:
    from .config import clean_h2_path

    path = clean_h2_path(data_dir)
    if not path.is_file():
        return []
    try:
        import json

        doc = json.loads(path.read_text(encoding="utf-8"))
        peers = doc.get("peers", [])
    except Exception:
        return []
    return [str(peer) for peer in peers if "." in str(peer) or ":" in str(peer)]
