from types import SimpleNamespace

import uac_desktop.engine as engine_module
from uac_desktop.engine import Engine, build_singbox_tun_config


class RunningProcess:
    pid = 9042
    stdout = None

    def poll(self):
        return None


class ProxyRuntime:
    def __init__(self):
        self.has_pending_restore = True
        self.calls = []

    def suspend_for_tun(self):
        self.calls.append("suspend")

    def resume(self):
        self.calls.append("resume")


def test_gateway_tun_keeps_xray_loopback_hop_off_the_physical_binding():
    config = build_singbox_tun_config(
        gateway_networks=["192.168.70.0/24"],
        gateway_host_addresses=["192.168.70.151"],
        gateway_interface="Ethernet",
    )
    rules = config["route"]["rules"]
    local_rule_index = next(
        index for index, rule in enumerate(rules)
        if "127.0.0.0/8" in rule.get("ip_cidr", ())
        and rule.get("outbound") == "local-direct"
    )
    physical_rule_index = next(
        index for index, rule in enumerate(rules)
        if rule.get("process_name") == ["xray.exe"]
        and rule.get("outbound") == "direct"
    )
    outbounds = {
        outbound["tag"]: outbound
        for outbound in config["outbounds"]
    }

    assert local_rule_index < physical_rule_index
    assert outbounds["local-direct"] == {
        "type": "direct",
        "tag": "local-direct",
    }
    assert outbounds["direct"] == {
        "type": "direct",
        "tag": "direct",
    }


def test_gateway_split_tun_keeps_its_scope_when_proxy_mode_is_reapplied(
        monkeypatch, tmp_path):
    engine = Engine(lambda _line: None, lambda _running: None,
                    lambda _up, _down: None)
    engine._active = True
    engine.process = RunningProcess()
    engine.system_proxy = ProxyRuntime()
    engine._proxy_enabled = True

    monkeypatch.setattr(
        engine_module,
        "SING_BOX_CONFIG",
        tmp_path / "sing-box-tun.json",
    )
    monkeypatch.setattr(
        engine_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout="",
            stderr="",
        ),
    )
    monkeypatch.setattr(
        engine,
        "ensure_tun_available",
        lambda: tmp_path / "sing-box.exe",
    )
    monkeypatch.setattr(engine, "_create_tun_job", lambda: object())
    monkeypatch.setattr(
        engine,
        "_spawn_tun_in_job",
        lambda *_args, **_kwargs: RunningProcess(),
    )
    monkeypatch.setattr(engine, "_resume_tun_process", lambda _process: None)
    monkeypatch.setattr(
        engine,
        "_write_singbox_owner_record",
        lambda _process: None,
    )

    engine.acquire_tun(
        owner="gateway",
        expected_run_id=engine.run_id,
        gateway_networks=["192.168.70.151/24"],
        gateway_host_addresses=["192.168.70.151"],
        gateway_interface="Wi-Fi",
    )

    assert engine._tun_gateway_networks == ("192.168.70.0/24",)

    engine.enable_system_proxy(expected_run_id=engine.run_id)

    assert engine._proxy_enabled is True
    assert engine.system_proxy.calls == []
