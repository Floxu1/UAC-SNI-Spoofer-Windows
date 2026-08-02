from __future__ import annotations

import base64
import threading
import time
import urllib.parse

import pytest

import uac_desktop.sni_maker as maker_module
from uac_desktop.models import ProxyProfile, parse_many
from uac_desktop.network import GeoLocation
from uac_desktop.sni_maker import (
    SniConfigMaker,
    SniProbeResult,
    config_signature,
    convert_to_sni,
    country_flag,
    decode_config_payload,
    dedupe_profiles,
    group_healthy_by_country,
    is_sni_config,
    normalize_repository_url,
)


def _profile(uri: str) -> ProxyProfile:
    return parse_many(uri)[0]


def _uri(index: int, fragment: str = "") -> str:
    return (
        f"vless://00000000-0000-0000-0000-{index:012d}@node{index}.example:443"
        f"?security=tls&type=ws&host=node{index}.example&sni=node{index}.example"
        f"&path=%2Fws#{fragment or f'node-{index}'}"
    )


def test_direct_vless_input_is_detected_without_rewriting():
    uri = _uri(1, "VLESS-direct")

    decoded = decode_config_payload(uri)
    result = SniConfigMaker().import_text(uri)

    assert decoded.input_format == "direct"
    assert decoded.text == uri
    assert result.input_format == "direct"
    assert result.detected_count == 1
    assert result.profiles[0].source_uri == uri


def test_direct_trojan_input_is_detected_without_rewriting():
    uri = (
        "trojan://secret@example.com:443/original"
        "?security=tls&type=ws&path=%2Fedge%3Fa%3D1&sni=example.com"
        "#Trojan%20Direct"
    )

    decoded = decode_config_payload(uri)
    result = SniConfigMaker().import_text(uri)

    assert decoded.input_format == "direct"
    assert decoded.text == uri
    assert result.input_format == "direct"
    assert result.detected_count == 1
    assert result.profiles[0].source_uri == uri


def test_standard_base64_subscription_is_decoded():
    payload = f"\ufeff{_uri(2)}\r\n{_uri(3)}\r\n"
    encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")

    decoded = decode_config_payload(encoded)
    result = SniConfigMaker().import_text(encoded)

    assert decoded.input_format == "base64"
    assert decoded.config_count == 2
    assert result.input_format == "base64"
    assert result.detected_count == 2
    assert result.added_count == 2


def test_urlsafe_base64_with_internal_whitespace_is_decoded():
    payload = f"💩\n{_uri(4, 'urlsafe')}"
    encoded = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii")
    assert "-" in encoded or "_" in encoded
    wrapped = f"  {encoded[:17]}\n{encoded[17:41]} \r\n {encoded[41:]}  "

    decoded = decode_config_payload(wrapped)
    result = SniConfigMaker().import_text(wrapped)

    assert decoded.input_format == "base64"
    assert result.input_format == "base64"
    assert result.added_count == 1


def test_base64_without_padding_is_decoded():
    uri = _uri(5, "no-padding")
    encoded = base64.b64encode(uri.encode("utf-8")).decode("ascii").rstrip("=")

    result = SniConfigMaker().import_text(encoded)

    assert result.input_format == "base64"
    assert result.detected_count == 1
    assert result.profiles[0].source_uri == uri


@pytest.mark.parametrize("value", ["ordinary text", "%%%broken%%%", "abcd=", "A"])
def test_invalid_or_ordinary_input_is_not_misdetected_as_base64(value):
    decoded = decode_config_payload(value)
    result = SniConfigMaker().import_text(value)

    assert decoded.input_format == "none"
    assert decoded.config_count == 0
    assert result.input_format == "none"
    assert result.added_count == 0


def test_valid_base64_without_supported_configs_is_rejected():
    encoded = base64.b64encode(
        b"https://example.com/subscription\nplain text"
    ).decode("ascii")

    decoded = decode_config_payload(encoded)
    result = SniConfigMaker().import_text(encoded)

    assert decoded.input_format == "none"
    assert decoded.text == encoded
    assert result.input_format == "none"
    assert result.added_count == 0


def test_import_text_uses_parse_many_dedupes_and_reports_unsupported():
    first = (
        "vless://00000000-0000-0000-0000-000000000001@one.example:443"
        "?security=tls&type=ws&sni=one.example&path=%2F#one"
    )
    duplicate = (
        "vless://00000000-0000-0000-0000-000000000001@ONE.example:443"
        "?path=%2F&sni=one.example&type=ws&security=tls#renamed"
    )
    second = (
        "trojan://secret@two.example:443"
        "?security=tls&type=httpupgrade&sni=two.example#two"
    )
    text = "\n".join(
        [
            first,
            duplicate,
            second,
            "vless://?security=tls",
            "vmess://ZXhhbXBsZQ==",
            "ss://YWVzLTI1Ni1nY206cGFzcw==@three.example:443",
        ]
    )

    result = SniConfigMaker().import_text(text)

    assert result.parsed_count == 3
    assert result.added_count == 2
    assert result.duplicate_count == 1
    assert result.invalid_count == 1
    assert result.unsupported_count == 2
    assert result.unsupported_by_protocol == {"ss": 1, "vmess": 1}
    assert len(result.unsupported_uris) == 2


def test_import_thousands_and_cross_batch_dedupe_remains_exact():
    values = [_uri(index) for index in range(1, 2001)]
    maker = SniConfigMaker()

    first = maker.import_text("\n".join([*values, *values[:250]]))
    second = maker.import_text("\n".join(values))

    assert first.parsed_count == 2250
    assert first.added_count == 2000
    assert first.duplicate_count == 250
    assert second.added_count == 0
    assert second.duplicate_count == 2000
    assert len(maker.profiles) == 2000


def test_signature_ignores_fragment_and_query_order_only():
    one = _profile(
        "trojan://secret@EXAMPLE.com:443?security=tls&type=ws&sni=a.example#first"
    )
    same = _profile(
        "trojan://secret@example.com?SNI=a.example&type=ws&security=tls#second"
    )
    different = _profile(
        "trojan://other@example.com?security=tls&type=ws&sni=a.example#first"
    )

    assert config_signature(one) == config_signature(same)
    assert config_signature(one) != config_signature(different)
    assert dedupe_profiles([one, same, different]) == [one, different]


def test_conversion_preserves_credentials_query_path_and_fragment():
    uri = (
        "trojan://OD90375861@busy-hermit.rooster465.autos:8443/original"
        "?allowInsecure=0&security=tls&sni=busy-hermit.rooster465.autos"
        "&x-custom=a%2Bb&type=ws&path=%2Fedge#Germany%20Original"
    )
    original = _profile(uri)
    original_id = original.id

    result = convert_to_sni(
        original,
        edge="104.19.229.21",
        fallback_edge="104.19.230.21",
        fake_sni="static.cloudflare.com",
    )

    assert result.status == "converted"
    assert result.profile is not None
    converted = result.profile
    before = urllib.parse.urlsplit(uri)
    after = urllib.parse.urlsplit(converted.source_uri)
    assert original.source_uri == uri
    assert original.id == original_id
    assert after.username == before.username
    assert after.hostname == "127.0.0.1"
    assert after.port == 40443
    assert after.path == before.path
    assert after.query == before.query
    assert after.fragment == before.fragment
    assert converted.address == "104.19.229.21"
    assert converted.fallback_address == "104.19.230.21"
    assert converted.port == 8443
    assert converted.sni == "busy-hermit.rooster465.autos"
    assert converted.spoof_fake_sni == "static.cloudflare.com"
    assert converted.verified_spoof is False
    assert converted.id != original.id
    assert converted.method == "full5"


def test_conversion_preserves_an_ipv4_source_edge():
    profile = _profile(
        "vless://00000000-0000-4000-8000-000000000001@104.16.1.1:443"
        "?security=tls&type=ws&sni=edge.example&host=edge.example&path=%2Fws"
    )

    result = convert_to_sni(profile, edge="104.19.229.21")

    assert result.profile is not None
    assert result.profile.address == "104.16.1.1"
    assert result.profile.method == "full5"


def test_conversion_rejects_removed_insecure_tls_and_invalid_vless_uuid():
    insecure = _profile(
        "vless://00000000-0000-4000-8000-000000000001@example.com:443"
        "?security=tls&type=ws&sni=example.com&allowInsecure=1"
    )
    missing_uuid = _profile(
        "vless://@example.com:443?security=tls&type=ws&sni=example.com"
    )
    invalid_uuid = _profile(
        "vless://Telegram-NUFiLTER@example.com:443"
        "?security=tls&type=ws&sni=example.com"
    )
    invalid_encryption = _profile(
        "vless://00000000-0000-4000-8000-000000000001@example.com:443"
        "?security=tls&type=ws&sni=example.com&encryption=none%3D%40channel"
    )

    assert convert_to_sni(insecure).error == "Unsupported insecure TLS option"
    assert convert_to_sni(missing_uuid).error == "Missing VLESS UUID"
    assert convert_to_sni(invalid_uuid).error == "Invalid VLESS UUID"
    assert convert_to_sni(invalid_encryption).error == "Unsupported VLESS encryption"


def test_existing_sni_config_is_copied_without_rewrite():
    profile = _profile(
        "vless://00000000-0000-0000-0000-000000000001@127.0.0.1:40443"
        "?security=tls&type=ws&sni=route.example&host=route.example#existing"
    )

    result = convert_to_sni(profile)

    assert is_sni_config(profile) is True
    assert result.status == "already_sni"
    assert result.profile is not profile
    assert result.profile == profile


def test_vmess_uri_style_is_rejected_by_sni_maker():
    uri = (
        "vmess://00000000-0000-0000-0000-000000000001@vmess.example:443"
        "?security=tls&type=ws&sni=vmess.example&host=vmess.example"
        "&path=%2Fvmess&aid=0&scy=auto#vmess"
    )
    maker = SniConfigMaker()

    imported = maker.import_text(uri)
    assert imported.added_count == 0
    assert imported.unsupported_count == 1
    assert imported.unsupported_by_protocol == {"vmess": 1}


def test_reality_config_is_excluded_from_sni_candidates():
    uri = (
        "vless://7b81d175-d180-4ec8-bbc5-dfe80e8d3b68@22.27.26.51:443"
        "?type=grpc&headerType=none&security=reality&encryption=none"
        "&sni=drafttest-rrew.ru&fp=firefox&pbk=xRD8N2qL8TcYKc7iQQuaqoZS_2dYsiNRmL3CdW8ZtgM"
        "&sid=d9662905&serviceName=nexusGrpc&spx=%2Fedge"
        "#Japan%20MIFA"
    )
    source = _profile(uri)

    result = convert_to_sni(source)

    assert result.status == "incompatible"
    assert result.success is False
    assert result.profile is None
    assert result.error == "Unsupported security: reality"


def test_saved_reality_profile_without_route_metadata_is_migrated():
    profile = ProxyProfile.from_dict({
        "source_uri": (
            "vless://00000000-0000-0000-0000-000000000001@one.example:443"
            "?security=reality&type=tcp&sni=cover.example"
        ),
    })

    assert profile.route_mode == "reality-direct"


@pytest.mark.parametrize("network", ["grpc", "xhttp", "tcp", "httpupgrade"])
def test_tls_extended_transports_are_convertible_without_query_loss(network):
    uri = (
        "trojan://secret@one.example:8443/original"
        f"?security=tls&type={network}&sni=route.example"
        "&host=edge.example&path=%2Fedge%3Fa%3D1&serviceName=maker"
        "#Extended%20Transport"
    )

    result = convert_to_sni(_profile(uri))

    assert result.status == "converted"
    assert result.success is True
    assert result.profile is not None
    before = urllib.parse.urlsplit(uri)
    after = urllib.parse.urlsplit(result.profile.source_uri)
    assert after.hostname == "127.0.0.1"
    assert after.port == 40443
    assert after.path == before.path
    assert after.query == before.query
    assert after.fragment == before.fragment


def test_security_none_remains_incompatible():
    uri = (
        "vless://00000000-0000-0000-0000-000000000001@one.example:80"
        "?security=none&type=tcp&encryption=none#Plain"
    )

    result = convert_to_sni(_profile(uri))

    assert result.status == "incompatible"
    assert result.success is False
    assert result.profile is None
    assert result.error == "Unsupported security: none"


def test_conversion_batch_keeps_only_sni_candidates():
    reality = _profile(
        "vless://00000000-0000-0000-0000-000000000001@reality.example:443"
        "?security=reality&type=grpc&sni=cover.example&fp=chrome"
        "&pbk=xRD8N2qL8TcYKc7iQQuaqoZS_2dYsiNRmL3CdW8ZtgM&sid=01234567&serviceName=maker#Reality"
    )
    grpc_tls = _profile(
        "trojan://secret@grpc.example:443"
        "?security=tls&type=grpc&sni=grpc.example&serviceName=maker#TLS"
    )
    plain = _profile(
        "vless://00000000-0000-0000-0000-000000000002@plain.example:80"
        "?security=none&type=tcp#Plain"
    )

    batch = SniConfigMaker().convert_many([reality, grpc_tls, plain])

    assert [result.status for result in batch.results] == [
        "incompatible",
        "converted",
        "incompatible",
    ]
    assert [result.success for result in batch.results] == [False, True, False]
    assert batch.profiles == [batch.results[1].profile]


def test_file_and_github_blob_url_import(tmp_path):
    text = _uri(1)
    source_file = tmp_path / "configs.txt"
    source_file.write_text(text, encoding="utf-8")
    maker = SniConfigMaker()

    file_result = maker.import_file(source_file)

    assert file_result.added_count == 1
    assert file_result.source == str(source_file)

    class Response:
        status_code = 200
        content = _uri(2).encode()
        encoding = "utf-8"
        headers = {"ETag": '"source-v1"'}

        def raise_for_status(self):
            return None

    class Session:
        def __init__(self):
            self.calls = []

        def get(self, url, **kwargs):
            self.calls.append((url, kwargs))
            return Response()

    session = Session()
    blob_url = (
        "https://github.com/Delta-Kronecker/Sub/blob/refs/heads/main/"
        "config/sni/all_configs_sni.txt"
    )
    url_result = maker.import_url(blob_url, etag='"old"', session=session)

    assert normalize_repository_url(blob_url) == (
        "https://raw.githubusercontent.com/Delta-Kronecker/Sub/"
        "refs/heads/main/config/sni/all_configs_sni.txt"
    )
    assert maker_module.DEFAULT_REPOSITORY_URL == "https://mifa.world/vless"
    assert session.calls[0][0] == normalize_repository_url(blob_url)
    assert session.calls[0][1]["headers"]["If-None-Match"] == '"old"'
    assert url_result.added_count == 1
    assert url_result.etag == '"source-v1"'


def test_url_import_supports_etag_not_modified():
    class Response:
        status_code = 304
        headers = {"ETag": '"same"'}

    class Session:
        def get(self, _url, **_kwargs):
            return Response()

    result = SniConfigMaker().import_url(etag='"same"', session=Session())

    assert result.not_modified is True
    assert result.added_count == 0
    assert result.etag == '"same"'


def test_default_preflight_probe_is_concurrent_and_does_not_invent_country(monkeypatch):
    active = 0
    peak = 0
    lock = threading.Lock()

    def ping(_address, _port, _sni, timeout):
        nonlocal active, peak
        assert timeout == 1.5
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.015)
        with lock:
            active -= 1
        return True, 24.5

    monkeypatch.setattr(maker_module, "profile_ping", ping)
    profiles = [_profile(_uri(index)) for index in range(1, 9)]
    profiles[0].country_code = "DE"
    progress = []

    batch = SniConfigMaker().test_many(
        profiles,
        max_workers=8,
        timeout=1.5,
        progress=lambda done, total, result: progress.append(
            (done, total, result.status)
        ),
    )

    assert peak > 1
    assert batch.tested_count == 8
    assert len(batch.successful) == 8
    assert batch.healthy == []
    assert all(result.status == "preflight_ok" for result in batch.results)
    assert all(result.country_code == "" for result in batch.results)
    assert batch.results[0].country_hint == "DE"
    assert len(progress) == 8


def test_live_probe_records_observed_country_and_groups_by_real_result():
    profiles = [_profile(_uri(index)) for index in range(1, 5)]
    locations = {
        profiles[0].id: ("DE", "Germany", "Berlin", "203.0.113.1", 82.0),
        profiles[1].id: ("JP", "Japan", "Tokyo", "203.0.113.2", 122.0),
        profiles[2].id: ("DE", "Germany", "Frankfurt", "203.0.113.3", 51.0),
        profiles[3].id: ("CH", "Switzerland", "Zurich", "203.0.113.4", 70.0),
    }

    def probe(profile, _timeout, _cancelled):
        code, name, city, ip, ping = locations[profile.id]
        return SniProbeResult(
            True,
            ping,
            GeoLocation(
                ip=ip,
                country_code=code,
                country=name,
                city=city,
                source="live-tunnel",
            ),
            stage="live",
            route_verified=True,
        )

    batch = SniConfigMaker().test_many(
        profiles,
        probe=probe,
        max_workers=4,
    )

    assert len(batch.healthy) == 4
    assert list(batch.healthy_by_country) == ["CH", "DE", "JP"]
    assert [result.ping_ms for result in batch.healthy_by_country["DE"]] == [51.0, 82.0]
    swiss = batch.healthy_by_country["CH"][0]
    assert swiss.country_name == "Switzerland"
    assert swiss.city == "Zurich"
    assert swiss.exit_ip == "203.0.113.4"
    assert swiss.geo_source == "live-tunnel"
    assert swiss.geo_confidence == "live"
    assert swiss.profile.country_code == "CH"
    assert swiss.profile.observed_country_name == "Switzerland"
    assert swiss.profile.verified_spoof is True
    assert swiss.country_flag == country_flag("CH")


def test_non_live_location_is_not_accepted_as_country():
    profile = _profile(_uri(1))

    def probe(_profile, _timeout, _cancelled):
        return SniProbeResult(
            True,
            30,
            GeoLocation(
                ip="198.51.100.2",
                country_code="FR",
                country="France",
                source="endpoint-hint",
            ),
            stage="preflight",
            route_verified=False,
        )

    result = SniConfigMaker().test_many([profile], probe=probe).results[0]

    assert result.country_code == ""
    assert result.country_name == ""
    assert result.exit_ip == ""
    assert result.geo_confidence == ""


def test_cancellation_stops_scheduling_results_and_returns_quickly():
    cancel = threading.Event()
    profiles = [_profile(_uri(index)) for index in range(1, 13)]

    def probe(profile, _timeout, cancelled):
        if profile is not None and profile.name == "node-1":
            return SniProbeResult(True, 10)
        while not cancelled():
            time.sleep(0.005)
        return SniProbeResult(False, error="Cancelled")

    def progress(_done, _total, _result):
        cancel.set()

    started = time.perf_counter()
    batch = SniConfigMaker().test_many(
        profiles,
        probe=probe,
        max_workers=4,
        progress=progress,
        cancelled=cancel,
    )
    elapsed = time.perf_counter() - started

    assert elapsed < 0.5
    assert batch.cancelled is True
    assert batch.tested_count == 1


def test_grouping_excludes_failed_preflight_and_unknown_country():
    profiles = [_profile(_uri(index)) for index in range(1, 5)]
    outcomes = iter(
        [
            SniProbeResult(
                True,
                40,
                GeoLocation(country_code="DE", country="Germany"),
                stage="live",
                route_verified=True,
            ),
            SniProbeResult(True, 20),
            SniProbeResult(False, error="failed"),
            SniProbeResult(True, 15, stage="live", route_verified=True),
        ]
    )

    batch = SniConfigMaker().test_many(
        profiles,
        probe=lambda *_args: next(outcomes),
        max_workers=1,
    )

    grouped = group_healthy_by_country(batch.results)
    assert list(grouped) == ["DE"]
    assert len(grouped["DE"]) == 1
