"""Run the staged Aether exe against local, controlled transport endpoints."""

import base64
import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest


@pytest.fixture
def native(tmp_path):
    configured = os.environ.get("UAC_TEST_AETHER")
    openssl = os.environ.get("UAC_TEST_OPENSSL") or shutil.which("openssl")
    if not configured or not openssl:
        pytest.skip("Set UAC_TEST_AETHER and UAC_TEST_OPENSSL for real native tests")
    binary = Path(configured).resolve(strict=True)
    cert, key = (tmp_path / name for name in ("test-cert.pem", "test-key.pem"))
    subprocess.run([
        openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-nodes", "-days", "1", "-subj", "/CN=localhost",
        "-keyout", str(key), "-out", str(cert),
    ], check=True, capture_output=True, timeout=15)
    identity = tmp_path / "uac-pow.toml"
    fields = dict(
        device_id="fixture", access_token="fixture", ipv4="172.16.0.2/32", ipv6="fd00::2/128",
        wg_private_key=base64.b64encode(bytes(32)).decode(),
        wg_peer_public_key=base64.b64encode(bytes(32)).decode(),
        cert_pem=cert.read_text(), key_pem=key.read_text(),
    )
    identity.write_text(
        "".join(f"{name} = {json.dumps(value)}\n" for name, value in fields.items())
        + f"cert_issued_at = {int(time.time())}\n",
        encoding="utf-8",
    )
    return binary, {
        "config_path": str(identity), "protocol": "masque", "listen": "127.0.0.1:0",
        "scan_mode": "turbo", "endpoint_discovery": "clean", "api_camo": "external",
        "ip_scan": "v4", "ip_scan_strict": True,
    }


def test_native_prepare_reads_existing_masque_fixture(native, tmp_path):
    binary, config = native
    path = tmp_path / "session.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    run = subprocess.run([binary, "--prepare-only", "--pow-config", path], text=True,
                         capture_output=True, timeout=10)
    assert run.returncode == 0, run.stderr
    assert json.loads(run.stdout.splitlines()[-1])["ipv4"] == "172.16.0.2"


@pytest.mark.parametrize("mode", ["h3-experimental", "h3-over-h2"])
def test_native_opens_transport_and_never_reports_ready_on_unverified_peer(native, tmp_path, mode):
    binary, config = native
    datagram = mode == "h3-experimental"
    with socket.socket(type=socket.SOCK_DGRAM if datagram else socket.SOCK_STREAM) as endpoint:
        endpoint.bind(("127.0.0.1", 0))
        endpoint.settimeout(10)
        if not datagram:
            endpoint.listen()
        peer = f"127.0.0.1:{endpoint.getsockname()[1]}"
        (tmp_path / "uac-pow-clean-h2.json").write_text(json.dumps({"peers": [peer]}), encoding="utf-8")
        config.update(masque_transport=mode, forced_peer=peer)
        path = tmp_path / "session.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        process = subprocess.Popen([binary, "--pow-config", path], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
        try:
            if datagram:
                deadline = time.monotonic() + 8
                found_initial = False
                while time.monotonic() < deadline:
                    endpoint.settimeout(max(0.1, deadline - time.monotonic()))
                    packet, _ = endpoint.recvfrom(4096)
                    if len(packet) >= 1200 and packet[0] & 0x80:
                        found_initial = True
                        break
                assert found_initial  # QUIC Initial
            else:
                client, _ = endpoint.accept()
                with client:
                    client.settimeout(5)
                    assert client.recv(5)[:2] == bytes((0x16, 0x03))  # TLS handshake record
        finally:
            process.terminate()
            output, errors = process.communicate(timeout=5)
        assert '"status":"connected"' not in output + errors
