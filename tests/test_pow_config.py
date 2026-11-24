"""PoW config parity tests — port of mobile ``PowEngineIsolationTest``.

Locks the Windows engine-3 dial to the mobile one: same plans, same
budgets, same JSON keys, same Psiphon strategies.
"""

from __future__ import annotations

import json

from uac_desktop.pow import config as C


def test_hamrah_plan_is_masque_h2_both():
    settings = C.PowSettings()
    plan = C.outer_plan(settings, mci=True)
    assert plan.protocols == ["masque"]
    assert plan.ip_for("masque") == "both"
    assert plan.ip_for("wireguard") == "both"
    assert plan.masque_transport == "h2"
    assert plan.fixed_order is True


def test_irancell_plan_is_h3_ladder_v4():
    settings = C.PowSettings()
    plan = C.outer_plan(settings, mci=False)
    assert plan.protocols == ["masque", "gool", "wireguard"]
    assert plan.ip_for("masque") == "v4"
    assert plan.masque_transport == "h3"
    assert plan.fixed_order is False


def test_explicit_recipes_ignore_firewall():
    settings = C.PowSettings(link_recipe=C.RECIPE_MASQUE_H2_SAVED)
    for mci in (True, False):
        plan = C.outer_plan(settings, mci=mci)
        assert plan.protocols == ["masque"]
        assert plan.masque_transport == "h2"
        assert plan.ip_for("masque") == "both"
    split = C.PowSettings(link_recipe=C.RECIPE_MASQUE_H2_SPLIT).validated()
    plan = C.outer_plan(split, mci=True)
    assert plan.fragment is True
    assert plan.ip_for("masque") == "v4"


def test_outer_budgets_match_mobile():
    assert C.outer_budget_ms("wireguard") == 36_000
    assert C.outer_budget_ms("masque") == 120_000
    assert C.outer_budget_ms("masque", scan_mode="thorough") == 180_000
    assert C.outer_budget_ms("wireguard", scan_mode="thorough") == 55_000
    assert C.outer_budget_ms("masque", scan_mode="turbo") == 90_000
    assert C.outer_budget_ms("masque", retune=True) == 14_000


def test_validation_falls_back_to_safe_defaults():
    settings = C.PowSettings(
        link_recipe="nope", firewall_profile="mtn", key_fetch="weird",
        outer_transport="bogus",
    ).validated()
    assert settings.link_recipe == C.RECIPE_AUTO
    assert settings.firewall_profile == C.FIREWALL_AUTO
    assert settings.key_fetch == C.KEY_AUTO
    assert settings.outer_transport == C.OUTER_AUTO
    assert C.PowSettings.DEFAULT.chain_psiphon is True
    assert C.PowSettings.DEFAULT.key_fetch == C.KEY_AUTO


def test_auto_firewall_selects_strict_plan_on_desktop():
    assert C.uses_mci_firewall(C.PowSettings()) is True
    assert C.uses_mci_firewall(C.PowSettings(firewall_profile="mci")) is True
    assert C.uses_mci_firewall(C.PowSettings(firewall_profile="irancell")) is False


def test_chain_outer_json_keys(tmp_path):
    settings = C.PowSettings()
    payload = json.loads(C.chain_outer_json(tmp_path, "masque", settings, mci=True))
    assert payload["listen"] == f"127.0.0.1:{C.CHAIN_SOCKS_PORT}"
    assert payload["protocol"] == "masque"
    assert payload["masque_transport"] == "h2"
    assert payload["ip_scan"] == "both"
    assert payload["api_camo"] == "auto"
    assert payload["scan_mode"] == "balanced"
    assert payload["config_path"].endswith("uac-pow.toml")


def test_saved_recipe_uses_clean_discovery(tmp_path):
    settings = C.PowSettings(link_recipe=C.RECIPE_MASQUE_H2_SAVED)
    payload = json.loads(C.chain_outer_json(tmp_path, "masque", settings, mci=True))
    assert payload["endpoint_discovery"] == "clean"


def test_key_request_follows_setting_and_cert_renew_forces_new(tmp_path):
    assert json.loads(C.key_request_json(tmp_path, C.PowSettings(), "masque"))["api_camo"] == C.KEY_AUTO
    settings = C.PowSettings(key_fetch=C.KEY_FRAGMENT)
    key = json.loads(C.key_request_json(tmp_path, settings, "masque"))
    assert key["api_camo"] == C.KEY_FRAGMENT
    assert "renew_masque" not in key
    renewed = json.loads(C.cert_renew_json(tmp_path, settings))
    assert renewed["renew_masque"] is True
    assert renewed["protocol"] == "masque"


def test_psiphon_strategies_match_mobile():
    assert C.strategy_signature() == "A,F"
    assert len(C.STRATEGY_LADDER) == 2
    assert C.STRATEGY_LADDER[0].preferred_protocols == C.FRONTED


def test_psiphon_chained_config_points_at_outer_leg(tmp_path):
    raw = C.psiphon_config(
        socks_port=C.PSIPHON_SOCKS_PORT,
        data_directory=str(tmp_path),
        preferred_region=None,
        strategy=C.STRATEGY_A,
    )
    config = json.loads(raw)
    assert config["UpstreamProxyURL"] == f"socks5://127.0.0.1:{C.CHAIN_SOCKS_PORT}"
    assert config["LocalSocksProxyPort"] == C.PSIPHON_SOCKS_PORT
    assert config["LimitTunnelProtocols"] == C.FRONTED
    assert config["DeviceRegion"] == "IR"
    assert "ServerEntriesPath" not in config


def test_psiphon_direct_meek_config(tmp_path):
    raw = C.psiphon_config(
        socks_port=C.PSIPHON_SOCKS_PORT,
        data_directory=str(tmp_path),
        preferred_region=None,
        strategy=C.STRATEGY_A,
        direct=True,
    )
    config = json.loads(raw)
    assert "UpstreamProxyURL" not in config
    assert config["LimitTunnelProtocols"] == ["FRONTED-MEEK-OSSH", "FRONTED-MEEK-HTTP-OSSH"]
    assert config["EstablishTunnelTimeoutSeconds"] == 90
    assert config["MeekSNIServerName"] == "cdnjs.cloudflare.com"
    assert "DNSResolverPreferredAlternateServers" not in config


def test_psiphon_region_pins_egress(tmp_path):
    raw = C.psiphon_config(
        socks_port=C.PSIPHON_SOCKS_PORT,
        data_directory=str(tmp_path),
        preferred_region="de",
        strategy=C.STRATEGY_F,
    )
    config = json.loads(raw)
    assert config["EgressRegion"] == "DE"
    assert config["EstablishTunnelTimeoutSeconds"] == C.REGION_PHASE_TIMEOUT_SECONDS
    assert config["LimitTunnelProtocols"] == C.FAST_DIRECT
    assert config["InitialLimitTunnelProtocols"] == C.FAST_DIRECT
    assert config["ConnectionWorkerPoolSize"] == 6


def test_last_connect_describe():
    assert C.LastConnect().describe() == ""
    assert C.LastConnect(protocol="psiphon").describe() == "Psiphon"
    text = C.LastConnect(
        protocol="masque", transport="h2", ip="both",
        peer="162.159.199.1:443", through_psiphon=True,
    ).describe()
    assert "MASQUE" in text and "HTTP/2" in text and "Psiphon" in text


def test_chained_ladder_light_first_direct_unchanged():
    chained = C.strategy_ladder(direct=False)
    assert [s.name for s in chained] == ["F", "A"]
    assert chained[0].timeout_seconds == C.CHAINED_LIGHT_TIMEOUT_SECONDS == 20
    assert [s.name for s in C.strategy_ladder(direct=True)] == ["A", "F"]
    assert C.strategy_signature() == "A,F"


def test_start_index_prefers_lower_rtt_then_remembered():
    ladder = C.strategy_ladder(direct=False)
    assert C.start_index(ladder, None, {}) == 0
    assert C.start_index(ladder, 1, {}) == 1
    assert C.start_index(ladder, 1, {"F": 200}) == 1
    assert C.start_index(ladder, 0, {"F": 800, "A": 300}) == 1


def test_auto_bias_region_prefers_remembered_nearby():
    assert C.auto_bias_region(None, []) == "DE"
    assert C.auto_bias_region("nl", ["DE", "NL", "US"]) == "NL"
    assert C.auto_bias_region("US", ["US", "SE"]) == "SE"
    assert C.auto_bias_region(None, ["US", "JP"]) is None
    assert C.auto_bias_region(None, [], remembered_only=True) is None


def test_region_bias_keeps_protocols_with_short_window(tmp_path):
    raw = C.psiphon_config(
        socks_port=C.PSIPHON_SOCKS_PORT,
        data_directory=str(tmp_path),
        preferred_region="DE",
        strategy=C.strategy_ladder(direct=False)[0],
        region_bias=True,
    )
    config = json.loads(raw)
    assert config["EgressRegion"] == "DE"
    assert config["EstablishTunnelTimeoutSeconds"] == C.NEARBY_PHASE_TIMEOUT_SECONDS
    assert config["InitialLimitTunnelProtocols"] == C.FAST_DIRECT
    assert config["EstablishTunnelServerAffinityGracePeriodMilliseconds"] == C.SERVER_AFFINITY_GRACE_MS
