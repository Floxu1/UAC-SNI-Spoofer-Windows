from dataclasses import replace
from urllib.parse import parse_qsl, urlsplit

import pytest
from PySide6.QtWidgets import QApplication, QDialog

from uac_desktop.engine import build_xray_config
from uac_desktop.models import default_profiles, parse_outbound, parse_uri
from uac_desktop.paths import BIN
from uac_desktop.profile_dialog import ProfileDialog


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.mark.parametrize("index", (0, 5))
def test_unchanged_release_profiles_keep_route_security_and_metadata(app, index):
    original = replace(default_profiles()[index], name="Local label", last_ping_ok=True,
                       last_ping_ms=147, verified_route=True, maker_meta={"route": "example"})
    dialog = ProfileDialog(None, original, "en")
    assert dialog._fields["host"].text() == original.config_host
    assert dialog._fields["port"].text() == str(original.config_port)
    assert dialog._fields["uac_address"].text() == original.address
    assert dialog._fields["uac_port"].text() == str(original.port)
    dialog._validate_accept()
    result = dialog.result_profile()
    assert result == original and result is not original
    assert build_xray_config(result) == build_xray_config(original)


@pytest.mark.parametrize("protocol,credential", (
    ("vless", "30980fc4-8789-42df-80d1-0c8e5cd26881"),
    ("trojan", "private%40%3Apass%21"),
))
def test_field_and_uri_edits_round_trip_without_losing_query_entries(app, monkeypatch, protocol, credential):
    if not (BIN / "xray.exe").exists() and not (BIN / "xray").exists():
        monkeypatch.setattr(ProfileDialog, "_validate_core", lambda *_: None)
    original = parse_uri(
        f"{protocol}://{credential}@original.example:40443?security=tls&network=ws&"
        "sni=server.example&host=host.example&path=unchanged&fp=chrome&allowInsecure=1&"
        "plugin=one%2bTWO&plugin=other&empty=&tag#note%20one",
        trim_prose=False,
    )
    dialog = ProfileDialog(None, original, "en")
    dialog._fields["uac_port"].setText("8443")
    dialog._fields["uac_address"].setText("192.0.2.4")
    dialog._fields["uac_spoof_fake_sni"].setText("cover.example")
    dialog._fields["host"].setText("2001:db8::123")
    dialog._fields["path"].setText("/next?x=1")
    text = dialog.uri.text()
    assert "plugin=one%2bTWO&plugin=other&empty=&tag" in text and text.endswith("#note%20one")
    assert "allowInsecure=1" in text and "network=ws" in text
    assert "path=%2Fnext%3Fx%3D1" in text
    assert "[2001:db8::123]:40443" in text
    dialog.uri.setText(text.replace("server.example", "new-name.example"))
    assert dialog._fields["sni"].text() == "new-name.example"
    assert dialog._fields["uac_port"].text() == "8443"
    dialog._validate_accept()
    result = dialog.result_profile()
    assert result is not None, dialog.validation.text()
    parsed_again = parse_uri(result.source_uri, trim_prose=False)
    assert parsed_again.port == result.port == 8443
    assert parsed_again.config_port == result.config_port == 40443
    assert parsed_again.address == result.address == "192.0.2.4"
    assert parsed_again.spoof_fake_sni == result.spoof_fake_sni == "cover.example"
    assert parse_outbound(parsed_again)["user"] == parse_outbound(original)["user"]
    assert parse_outbound(parsed_again)["path"] == "/next?x=1"
    pairs = parse_qsl(urlsplit(parsed_again.source_uri).query, keep_blank_values=True)
    assert [value for key, value in pairs if key == "plugin"] == ["one+TWO", "other"]
    assert original.port == 443 and original.config_host == "original.example"


def test_dynamic_fields_and_invalid_input_leave_original_unchanged(app):
    original = default_profiles()[0]
    before = original.to_dict()
    dialog = ProfileDialog(None, original, "en")
    assert dialog.uri.isHidden()
    assert dialog._fields["user"].echoMode() == dialog._fields["user"].EchoMode.Password
    transport = dialog._fields["network"]
    transport.setCurrentIndex(transport.findData("grpc"))
    assert dialog._rows["host_header"].isHidden() and not dialog._rows["service_name"].isHidden()
    assert "host=" in dialog.uri.text()
    dialog._fields["port"].setText("0")
    dialog._validate_accept()
    assert dialog.result() == QDialog.Rejected and dialog.validation.text()
    dialog.reject()
    assert dialog.result_profile() is None and original.to_dict() == before
