import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from types import SimpleNamespace

from PySide6.QtWidgets import QApplication

from uac_desktop import first_run_wizard as wiz

APP = QApplication.instance() or QApplication([])


def test_should_show_and_mark_seen():
    s = {}
    assert wiz.should_show(s, "1.1.0")
    wiz.mark_seen(s, "1.1.0")
    assert not wiz.should_show(s, "1.1.0")
    assert wiz.should_show(s, "1.2.0")


def test_analyze_log_states():
    assert wiz.analyze_log("")["state"] == "none"
    failing = "[1:00] ===== CONNECTED =====\n[1:01] CONNECT FAIL: x\n[1:02] CONNECT FAIL: y\n"
    r = wiz.analyze_log(failing)
    assert r["state"] == "failing" and r["fail"] == 2 and r["ok"] == 1
    assert wiz.analyze_log("[1:01] CONNECT FAIL: x\n[1:05] ===== CONNECTED =====\n")["state"] == "working"


def test_classify_by_behaviour_not_asn():
    # Irancell ASN but MCI-like behaviour (fragmented hello killed) -> sni
    assert wiz.classify_dpi(6, 0, "irancell")["dpi"] == "sni"
    # MCI ASN but fragment-friendly behaviour -> ip
    assert wiz.classify_dpi(6, 5, "mci")["dpi"] == "ip"
    low = wiz.classify_dpi(0, 0, "irancell")
    assert low["dpi"] == "ip" and low["by"] == "asn"
    assert wiz.classify_dpi(1, 0, "tci")["dpi"] == "sni"


def test_carrier_from_asn_labels():
    assert wiz.carrier_from_asn("AS197207")["family"] == "mci"
    assert wiz.carrier_from_asn("44244")["en"] == "Irancell"
    assert wiz.carrier_from_asn("58224")["family"] == "tci"
    assert wiz.carrier_from_asn("", "Hamrah-e-Aval")["family"] == "mci"
    assert wiz.carrier_from_asn("", "Some ISP")["fa"] == "Some ISP"
    assert wiz.cache_carrier("tci", "sni") == "mci"
    assert wiz.cache_carrier("isp", "ip") == "irancell"


def test_identity_vote_real_mci_sample():
    # captured on the user's MCI SIM: HTTPS geo-IP said Azerbaijan, http transit said TCI
    bodies = {
        "sdk": '{"ipAddress":"91.251.102.144","ispName":"Hamrah-e-Aval","location":{"countryCode":"IR"}}',
        "https_xml": '<client ip="91.251.102.144" isp="Mobile Communication Company of Iran" country="IR" />',
        "ipapi": '{"isp":"Mobile Communication Company of Iran","as":"AS197207 Mobile Communication Company of Iran PLC","countryCode":"IR"}',
        "http_xml": '<client ip="151.234.172.19" isp="Iran Telecommunication Company PJS" country="IR" />',
        "ipwho": '{"country_code":"AZ","connection":{"asn":29049,"isp":"Delta Telecom Ltd"}}',
    }
    order = ["sdk", "https_xml", "ipapi", "http_xml", "ipwho"]
    urls = {src[0]: bodies[k] for src, k in zip(wiz.IDENTITY_SOURCES, order)}
    info = wiz.lookup_identity(get=lambda url: urls[url])
    assert info["family"] == "mci" and info["en"] == "MCI"


def test_dpi_probe_counts():
    def probe(ip, sni, chunk):
        return chunk == 0  # reachable, but fragmented hello killed (MCI)
    r = wiz.dpi_probe(["1.1.1.1", "1.0.0.1", "1.1.1.2"], probe)
    assert r["reachable"] == 3 and r["frag_ok"] == 0
    assert wiz.classify_dpi(r["reachable"], r["frag_ok"])["dpi"] == "sni"


class FakeHost:
    def __init__(self):
        self.started = None; self.stopped = False
    def wizard_config_count(self): return 3
    def wizard_tunnel_active(self): return True
    def wizard_log_path(self): return ""
    def wizard_start_flow(self, kind, wizard, carrier): self.started = (kind, carrier)
    def wizard_stop_flow(self): self.stopped = True


def _wait(cond, ms=3000):
    import time
    end = time.time() + ms / 1000
    while time.time() < end and not cond():
        APP.processEvents(); time.sleep(0.01)
    return cond()


def test_wizard_flow_end_to_end_with_fake_host():
    host = FakeHost()
    ident = lambda: wiz.carrier_from_asn("197207")
    w = wiz.FirstRunWizard(None, host=host, language="fa", identity=ident,
                           probe=lambda *a: False)
    w.start_check()
    assert _wait(lambda: w.stack.currentIndex() == w.PAGE_VERDICT)
    assert w.kind == "sni" and w.carrier_key == "mci"
    w.go_btn.click()
    assert host.started == ("sni", "mci") and w.stack.currentIndex() == w.PAGE_RUN
    w.flow_step("fetch", "ok", "83"); w.flow_progress(30, 83, 12)
    w.run_log._flush(); assert "۳۰" in w.run_log.counter.text() and "۸۳" in w.run_log.counter.text()
    w.flow_log("raw line"); assert not w.run_log.raw.isVisible()
    w.flow_finished(True, "done", "body")
    assert _wait(lambda: w.stack.currentIndex() == w.PAGE_DONE)
    w.close()


def test_wizard_english_and_stop_calls_host():
    host = FakeHost()
    w = wiz.FirstRunWizard(None, host=host, language="en", identity=lambda: wiz.carrier_from_asn("44244"),
                           probe=lambda *a: False)
    assert w.hello_btn.text().startswith("Let's")
    w.facts = {"dpi": {"dpi": "ip", "by": "probe"}, "carrier": wiz.carrier_from_asn("44244"), "configs": 0,
               "history": {"state": "failing", "fail": 3, "ok": 0}}
    w.show_verdict(); assert "Uh-oh" in w.v_title.text()
    w.start_flow(); assert host.started == ("ip", "irancell")
    # regression: Irancell-type must still fetch/test/add Patterniha configs
    assert {"scan", "fetch", "test", "add"} <= set(w.run_log.rows)
    w.reject(); assert host.stopped


def test_failure_offers_retry_never_fake_success():
    host = FakeHost()
    w = wiz.FirstRunWizard(None, host=host, language="fa", identity=lambda: wiz.carrier_from_asn("197207"),
                           probe=lambda *a: False)
    w.facts = {"dpi": {"dpi": "sni", "by": "probe"}, "carrier": wiz.carrier_from_asn("197207"), "configs": 0,
               "history": {"state": "none"}}
    w.start_flow(); host.started = None
    w.flow_finished(False, "x", "y")
    assert "دوباره" in w.done_btn.text()
    w.done_btn.click()
    assert host.started == ("sni", "mci") and w.stack.currentIndex() == w.PAGE_RUN
    w.close()


def test_host_reports_zero_added_as_failure(monkeypatch):
    from uac_desktop import ui
    calls = {}
    class Wiz:
        def flow_step(self, *a, **k): pass
        def flow_progress(self, *a, **k): pass
        def flow_note(self, *a, **k): pass
        def flow_progress(self, *a, **k): pass
        def flow_note(self, *a, **k): pass
        def flow_finished(self, ok, title, body=""): calls["ok"] = ok
    model = SimpleNamespace(healthy_results=lambda: [1, 2], rowCount=lambda: 2)
    stub = SimpleNamespace(_wizard=Wiz(), _wizard_phase="test", maker_model=model,
                           storage=SimpleNamespace(profiles=[]), tr=lambda fa, en=None: fa,
                           _maker_add_results=lambda mode: None, _append_log=lambda *_: None,
                           user_config_list=SimpleNamespace(count=lambda: 0),
                           _wizard_saved_on_disk=lambda ids: 0, _wizard_user_config_count=lambda: 0)
    ui.MainWindow._wizard_on_done(stub, {"cancelled": False}, 1)
    assert calls["ok"] is False


def test_default_sni_maker_url_is_patterniha():
    from uac_desktop import ui
    assert ui.DEFAULT_SNI_MAKER_URL == wiz.PATTERNIHA_URL


def test_fa_text_isolates_latin_and_uses_persian_digits():
    out = wiz.fa_text("سرور HK · h2.whuiy.xyz با پینگ 680 و IP 104.16.1.2")
    assert wiz.FSI + "HK · h2.whuiy.xyz" + wiz.PDI in out
    assert "۶۸۰" in out and wiz.FSI + "IP 104.16.1.2" + wiz.PDI in out
    assert out.startswith(wiz.RLM) and "·" not in out.replace("HK · h2", "")
    assert wiz.ms_label(680) == "۶۸۰ میلی‌ثانیه" and wiz.ms_label(680, "en") == "680 ms"


def test_feed_is_friendly_never_raw():
    w = wiz.FirstRunWizard(None, host=FakeHost(), language="fa", identity=lambda: wiz.carrier_from_asn("197207"),
                           probe=lambda *a: False)
    w.facts = {"dpi": {"dpi": "sni", "by": "probe"}, "carrier": wiz.carrier_from_asn("197207"), "configs": 0,
               "history": {"state": "none"}}
    w.start_flow()
    w.flow_log("SNI MAKER XRAY 2026/10/12 20:21:38 accepted //api.country.is:443 [maker-in-69 -> maker-out-69]")
    w.flow_result(True, "🇩🇪", "آلمان", "Germany", 680)
    w.flow_result(False, "🇯🇵", "ژاپن", "Japan", 0)
    w.flow_progress(30, 237, 12)
    w.run_log._flush()
    lines = [w.run_log.raw.item(i).text() for i in range(w.run_log.raw.count())]
    assert len(lines) == 2 and not any("XRAY" in l or "maker-in" in l for l in lines)
    assert "آلمان" in lines[0] and "۶۸۰ میلی‌ثانیه" in lines[0] and "ژاپن" in lines[1]
    assert w.run_log.best.isVisibleTo(w) and "۳۰" in w.run_log.counter.text()
    assert "۳۰" in w.r_sub.text() and "۲۳۷" in w.r_sub.text()
    w.close()


def test_wizard_host_does_not_pipe_raw_log():
    import inspect
    from uac_desktop import ui
    assert "self.bridge.log, self._wizard_on_log" not in inspect.getsource(ui.MainWindow._open_wizard)
