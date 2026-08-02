import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QLabel

from uac_desktop.ui import GatewayDevicesPopup


@pytest.fixture(scope="module")
def app():
    instance = QApplication.instance() or QApplication([])
    yield instance


def test_gateway_popup_lists_current_snapshot_with_green_checks(app):
    popup = GatewayDevicesPopup("en")
    assert popup.testAttribute(Qt.WA_StyledBackground)
    assert not popup.testAttribute(Qt.WA_TranslucentBackground)
    assert popup.windowOpacity() == 1.0
    popup.update_devices(
        {
            "192.168.70.136": "aa:bb:cc:dd:ee:02",
            "192.168.70.20": "aa:bb:cc:dd:ee:01",
        },
        {
            "192.168.70.136": "Living Room TV",
            "192.168.70.20": "Rayane Phone",
        },
    )

    assert popup.count.text() == "2 online"
    assert [
        label.text()
        for label in popup.findChildren(QLabel, "gatewayDeviceIp")
    ] == ["192.168.70.20", "192.168.70.136"]
    assert [
        label.toolTip()
        for label in popup.findChildren(QLabel, "gatewayDeviceName")
    ] == ["Rayane Phone", "Living Room TV"]
    checks = popup.findChildren(QLabel, "gatewayDeviceCheck")
    assert len(checks) == 2
    assert all(not check.pixmap().isNull() for check in checks)


def test_gateway_popup_renders_empty_and_persian_states(app):
    empty = GatewayDevicesPopup("en")
    empty.update_devices({})
    assert empty.count.text() == "0 online"
    assert empty.findChild(QLabel, "gatewayDeviceEmptyText").text() == (
        "No device detected yet"
    )

    persian = GatewayDevicesPopup("fa")
    persian.update_devices({"192.168.1.7": "12:34:56:78:90:ab"})
    assert persian.title.text() == "دستگاه‌های متصل"
    assert persian.count.text() == "1 متصل"
    assert persian.findChild(QLabel, "gatewayDeviceState").text() == "متصل"
