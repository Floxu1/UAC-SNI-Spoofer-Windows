import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import time
from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication, QFrame, QMainWindow, QStyle, QStyleOptionButton
from uac_desktop import ip_info as I
from uac_desktop.fonts import load_fonts

APP = QApplication.instance() or QApplication([])
load_fonts()


def pump(ms=200):
    end = time.time() + ms / 1000
    while time.time() < end:
        APP.processEvents(); time.sleep(0.01)


def test_fallback_chain_uses_next_source():
    calls = []
    def get(url, port):
        calls.append((url, port))
        if "ipinfo" in url:
            raise OSError("blocked")
        return {"success": True, "ip": "5.6.7.8", "country_code": "de", "city": "Frankfurt",
                "connection": {"asn": 24940, "org": "Hetzner", "isp": "Example ISP"}, "timezone": {"id": "Europe/Berlin"}}
    info = I.fetch_details(20809, get=get)
    assert info["ip"] == "5.6.7.8" and info["country"] == "DE" and info["asn"] == "AS24940"
    assert info["source"] == "ipwho.is" and all(p == 20809 for _u, p in calls)
    assert (info["isp"], info["org"]) == ("Example ISP", "Hetzner")


def test_ipinfo_parse():
    info = I._norm_ipinfo({"ip": "1.1.1.1", "org": "AS13335 Cloudflare", "country": "US", "hostname": "one.one"})
    assert info["asn"] == "AS13335" and info["org"] == "Cloudflare"


def test_direct_identity_prefers_vote_over_transit_geo():
    info = I.direct_identity(identity_fn=lambda: {"family": "mci", "fa": "همراه اول", "en": "MCI", "country": "", "asn": "AS197207"},
                             details_fn=lambda _p: {"ip": "5.1.1.1", "country": "AZ", "source": "ipinfo.io"})
    assert info["country"] == "IR" and info["geo_country"] == "AZ" and info["mode"] == "direct"
    sub = I.card_subtitle(info, True)
    assert "ایران" in sub and "همراه اول" in sub and "،" in sub and sub.startswith("\u200f")


def test_subtitle_direct_without_carrier_and_tunnel():
    assert "اتصال مستقیم" in I.card_subtitle({"mode": "direct", "country": "IR"}, True)
    assert I.card_subtitle({"mode": "xray", "country": "DE"}, False, "Xray tunnel") == "Germany · Xray tunnel"


def test_dialog_states_and_copy():
    d = I.SharedIpDetailsDialog(None, True, lambda: {"ip": "9.9.9.9", "country": "DE", "city": "Berlin", "asn": "AS1", "org": "X", "source": "ipinfo.io"}, "مستقیم")
    assert d.layoutDirection() == Qt.RightToLeft
    pump(400)
    assert d.big.text().strip("\u200f\u2068\u2069") == "9.9.9.9" and d.panel.isVisibleTo(d) and d.copy_btn.isEnabled()
    d._copy_feedback.setInterval(10)
    d.copy_ip()
    assert QApplication.clipboard().text() == "9.9.9.9"
    assert d.copy_btn.text() == "کپی شد ✓"
    pump(50)
    assert d.copy_btn.text() == "کپی آی‌پی"
    e = I.SharedIpDetailsDialog(None, True, lambda: (_ for _ in ()).throw(RuntimeError("x")))
    pump(400)
    assert e.retry_btn.isVisibleTo(e) and "ناموفق" in e.status.text()


def test_clickable_card_hover_and_click():
    from PySide6.QtCore import QEvent, QPointF
    from PySide6.QtGui import QMouseEvent
    card = QFrame(); card.setObjectName("metricCard"); card.resize(100, 60)
    hits = []
    I.ClickableCard(card, lambda: hits.append(1))
    assert card.cursor().shape() == Qt.PointingHandCursor
    APP.sendEvent(card, QEvent(QEvent.Enter)); assert card.property("ipHot") is True
    ev = QMouseEvent(QEvent.MouseButtonRelease, QPointF(10, 10), QPointF(10, 10), Qt.LeftButton, Qt.NoButton, Qt.NoModifier)
    APP.sendEvent(card, ev); pump(50)
    assert hits == [1]


def test_v2_rows_persian_location_asn_chip_and_hidden_hostname():
    info = {"ip": "91.251.102.144", "city": "Karaj", "region": "Alborz Province", "country": "IR",
            "carrier_fa": "همراه اول", "asn": "AS197207", "org": "Mobile Communication Company of Iran",
            "timezone": "Asia/Tehran", "hostname": ""}
    assert I.location_text(info, True) == "\u200fکرج، البرز، ایران"
    assert I.timezone_text("Asia/Tehran", True) == "\u200fتهران \u2066(UTC+3:30)\u2069"
    d = I.SharedIpDetailsDialog(None, True, lambda: info, "x")
    pump(400)
    texts = [w.text() for w in d.panel.findChildren(I.QLabel)]
    assert any(t == "AS197207" for t in texts)               # ASN chip
    assert not d.host_row.isVisibleTo(d.panel)
    vals = [w for w in d.panel.findChildren(I.QLabel) if w.objectName() == "ipVal"]
    assert vals and all(v.alignment() & Qt.AlignLeft for v in vals)
    assert d.values["location"].text().startswith("\u200f")


def test_shared_dialog_themes_and_long_values():
    info = {
        "ip": "abcd:abcd:abcd:abcd:abcd:abcd:255.255.255.255",
        "country": "DE", "city": "Frankfurt", "isp": "M247", "org": "M" * 300,
        "asn": "AS9009", "timezone": "Europe/Berlin", "source": "ipwho.is",
    }
    for fa in (True, False):
        reference = None
        for engine, accent in (("xray", "#46DCE8"), ("pow", "#37E9AC"), ("direct", "#FF974D")):
            d = I.SharedIpDetailsDialog(None, fa, lambda: info, "اتصال مستقیم" if fa else "Direct connection", engine=engine)
            d.show()
            pump(60)
            assert d.width() == 460
            assert d.big.text().replace("\n", "") == info["ip"] and d.family.text() == "Public IPv6"
            assert all(d.big.fontMetrics().horizontalAdvance(line) <= d.big.width()
                       for line in d.big.text().splitlines())
            assert d.values["org"].toolTip().strip("\u200f\u2068\u2069") == info["org"]
            assert d.flag.isVisible() and "ipwho.is" in d.source.text()
            assert d.copy_btn.palette().color(QPalette.Button) == QColor(accent)
            geometry = tuple((w.mapTo(d, QPoint()), w.size())
                             for w in (d, d.header, d.hero, d.panel, d.copy_btn))
            if reference is None:
                reference = geometry
            assert geometry == reference
            d.close()


def test_dialog_close_button_fits_under_the_main_window_theme():
    from uac_desktop.ui import combined_app_style

    owner = QMainWindow()
    owner.setProperty("engine", "pow")
    original_style = APP.styleSheet()
    APP.setStyleSheet(combined_app_style("fa"))
    try:
        dialog = I.SharedIpDetailsDialog(owner, True, lambda: {"ip": "9.9.9.9"}, engine="pow")
        dialog.show()
        pump(50)
        button = dialog.close_btn
        option = QStyleOptionButton()
        button.initStyleOption(option)
        contents = button.style().subElementRect(QStyle.SE_PushButtonContents, option, button)
        assert (button.width(), button.height()) == (26, 26)
        assert contents.width() >= 16 and contents.height() >= 16
        assert abs(button.geometry().center().y() - dialog.header.rect().center().y()) <= 1
        button.click()
        assert not dialog.isVisible()
    finally:
        APP.setStyleSheet(original_style)
