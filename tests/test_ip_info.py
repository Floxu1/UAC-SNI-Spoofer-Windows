import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import time
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QFrame
from uac_desktop import ip_info as I

APP = QApplication.instance() or QApplication([])


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
                "connection": {"asn": 24940, "org": "Hetzner"}, "timezone": {"id": "Europe/Berlin"}}
    info = I.fetch_details(20809, get=get)
    assert info["ip"] == "5.6.7.8" and info["country"] == "DE" and info["asn"] == "AS24940"
    assert info["source"] == "ipwho.is" and all(p == 20809 for _u, p in calls)


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
    d = I.IpDetailsDialog(None, True, lambda: {"ip": "9.9.9.9", "country": "DE", "city": "Berlin", "asn": "AS1", "org": "X", "source": "ipinfo.io"}, "مستقیم")
    assert d.layoutDirection() == Qt.RightToLeft
    pump(400)
    assert d.big.text().strip("\u200f\u2068\u2069") == "9.9.9.9" and d.panel.isVisibleTo(d) and d.copy_btn.isEnabled()
    d.copy_ip(); assert QApplication.clipboard().text() == "9.9.9.9"
    e = I.IpDetailsDialog(None, True, lambda: (_ for _ in ()).throw(RuntimeError("x")))
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
    d = I.IpDetailsDialog(None, True, lambda: info, "x")
    pump(400)
    texts = [w.text() for w in d.panel.findChildren(I.QLabel)]
    assert any(t == "AS197207" for t in texts)               # ASN chip
    assert not any("نام میزبان" in t for t in texts)          # empty hostname hidden
    vals = [w for w in d.panel.findChildren(I.QLabel) if w.objectName() == "ipVal"]
    assert vals and all(v.text().startswith("\u200f") and v.alignment() & Qt.AlignRight for v in vals)
