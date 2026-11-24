from __future__ import annotations

from .schema import GeneStrategy, KNOWN_FAKE_SNIS


def seed_strategies(network_id: str = "unknown") -> list[GeneStrategy]:
    """Known-good neighborhoods already used by UAC Spoofer Pattern routes."""
    seeds: list[GeneStrategy] = []

    def add(**kwargs) -> None:
        seeds.append(GeneStrategy(network_id=network_id, **kwargs))

    add(name="wrong_seq/chatgpt", method="wrong_seq", fake_sni="chatgpt.com",
        fake_repeat=1, inject_delay_ms=1, fragment_delay_ms=0, notes="MCI-style seed")
    add(name="wrong_seq/cf", method="wrong_seq", fake_sni="www.cloudflare.com",
        fake_repeat=1, inject_delay_ms=0, fragment_delay_ms=0)
    add(name="full5/chatgpt", method="full5", fake_sni="chatgpt.com",
        fake_repeat=1, inject_delay_ms=1, fragment_delay_ms=5, chunk_size=5,
        notes="Irancell-style seed")
    add(name="full5/ms", method="full5", fake_sni="www.microsoft.com",
        fake_repeat=1, inject_delay_ms=0, fragment_delay_ms=8, chunk_size=5)
    add(name="sni_boundary/chatgpt", method="sni_boundary", fake_sni="chatgpt.com",
        fake_repeat=1, inject_delay_ms=1, fragment_delay_ms=3)
    add(name="sni_split/chatgpt", method="sni_split", fake_sni="chatgpt.com",
        fake_repeat=1, inject_delay_ms=1, fragment_delay_ms=5)
    add(name="tls_sni_records/chatgpt", method="tls_sni_records", fake_sni="chatgpt.com",
        fake_repeat=1, inject_delay_ms=1, fragment_delay_ms=10)
    add(name="full20/chatgpt", method="full20", fake_sni="chatgpt.com",
        fake_repeat=1, inject_delay_ms=0, fragment_delay_ms=3, chunk_size=20)
    add(name="full10/chatgpt", method="full10", fake_sni="chatgpt.com",
        fake_repeat=1, inject_delay_ms=1, fragment_delay_ms=4, chunk_size=10)
    add(name="multi64/chatgpt", method="multi64", fake_sni="chatgpt.com",
        fake_repeat=1, inject_delay_ms=0, fragment_delay_ms=0, chunk_size=64)
    add(name="plain/baseline", method="plain", fake_sni="chatgpt.com",
        fake_repeat=1, inject_delay_ms=0, fragment_delay_ms=0,
        notes="Baseline control — usually filtered")

    # Extra SNI variants around top methods.
    for sni in KNOWN_FAKE_SNIS[1:4]:
        add(name=f"wrong_seq/{sni.split('.')[1] if '.' in sni else sni}",
            method="wrong_seq", fake_sni=sni, fake_repeat=1, inject_delay_ms=1)
        add(name=f"full5/{sni.split('.')[1] if '.' in sni else sni}",
            method="full5", fake_sni=sni, fake_repeat=1, inject_delay_ms=1,
            fragment_delay_ms=5, chunk_size=5)

    return seeds
