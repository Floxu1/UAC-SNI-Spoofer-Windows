from __future__ import annotations

import socket
import subprocess
import sys


def detect_network_id() -> str:
    """Best-effort local network label for separating result buckets."""
    host = socket.gethostname() or "host"
    gateway = ""
    if sys.platform.startswith("win"):
        try:
            completed = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop"],
                capture_output=True, text=True, timeout=4, check=False,
            )
            gateway = (completed.stdout or "").strip()
        except (OSError, subprocess.SubprocessError):
            gateway = ""
    label = f"{host}"
    if gateway:
        label = f"{host}/{gateway}"
    return label[:80] or "unknown"
