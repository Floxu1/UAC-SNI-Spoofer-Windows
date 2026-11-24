from __future__ import annotations

import http.client
import threading
import time
from pathlib import Path
from typing import Callable

from ..pow.config import psiphon_config, strategy_ladder
from ..pow.psiphon import PsiphonProcess
from .carrier import ensure_active
from .probe import trace


def start_country(directory: Path, carrier_port: int, port: int, region: str,
                  cancel: threading.Event, log: Callable[[str], None]) -> PsiphonProcess:
    region = region.upper()
    last_error = ""
    for strategy in strategy_ladder(direct=False):
        ensure_active(cancel)
        process = PsiphonProcess()
        succeeded = False
        try:
            log(f"Direct country exit {region} trying Psiphon strategy {strategy.name}")
            process.start(psiphon_config(port, str(directory), region, strategy, upstream_port=carrier_port), directory)
            deadline = time.monotonic() + 30
            while process.running and time.monotonic() < deadline:
                ensure_active(cancel)
                if process.connected.is_set() and process.socks_port is not None:
                    break
                cancel.wait(0.1)
            ensure_active(cancel)
            if not process.running or not process.connected.is_set() or process.socks_port is None:
                raise OSError(f"Psiphon did not connect to {region}: {process.last_diagnostic}")
            if process.socks_port != port:
                raise OSError("Psiphon bound an unexpected SOCKS port")
            observed = trace(port).get("loc")
            ensure_active(cancel)
            if observed != region:
                raise OSError(f"Requested exit {region}, verified {observed or 'no country'}")
            if not process.running or not process.connected.is_set():
                raise OSError("Psiphon stopped during the country check")
            log(f"Direct country exit verified {region}")
            succeeded = True
            return process
        except (OSError, RuntimeError, http.client.HTTPException) as error:
            ensure_active(cancel)
            last_error = str(error)
            log(f"Direct country exit {strategy.name} failed: {last_error}")
        finally:
            if not succeeded:
                process.stop()
    raise RuntimeError(f"Could not verify the selected exit {region}. {last_error}")
