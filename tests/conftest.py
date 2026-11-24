"""Shared test guards."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_real_net_keyfetch(monkeypatch):
    """Never let a unit test launch the real keyfetch-net.ps1 lane.

    That lane registers real WARP devices over the network. Tests that cover
    it opt back in with ``monkeypatch.delenv("UAC_NET_KEYFETCH")`` and fakes.
    """
    monkeypatch.setenv("UAC_NET_KEYFETCH", "0")
    monkeypatch.delenv("UAC_NET_KEYFETCH_FORCE", raising=False)
