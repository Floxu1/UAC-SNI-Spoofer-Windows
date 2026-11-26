import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import pytest
from PySide6.QtWidgets import QApplication

from uac_desktop.models import Tuning
from uac_desktop import ui


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


GENES = [{"id": "gene_a", "name": "g1", "method": "primitive", "success_rate": 1.0, "confirmed": True}]


@pytest.mark.parametrize("lang", ["fa", "en"])
def test_settings_page_round_trips_all_values(app, lang):
    tunings = {}
    for carrier in ("auto", "mci", "irancell"):
        t = Tuning.carrier_preset(carrier)
        if carrier != "mci":
            t.pattern_connect_ip = "104.16.8.34"; t.pattern_fallback_ips = "1.2.3.4,5.6.7.8"
            t.pattern_fake_sni = "registry.npmjs.org"; t.pattern_use_profile_edges = True
        tunings[carrier] = Tuning.enforce_carrier(t, carrier)
    d = ui.XraySettingsPage(None, tunings["irancell"], lang, "https://github.com/a/b", tunings,
                        GENES, "", True, True, "", False, None)
    vals = d.values()
    for carrier, t in tunings.items():
        assert vals[carrier].to_dict() == Tuning.enforce_carrier(t, carrier).to_dict()
    assert d.gene_selection() == (GENES, "")
    assert d.strategy_lock_enabled() is True and d.multi_gene_enabled_value() is True
    assert d.auto_clean_ip_value() is False
    assert d.update_repo_url() == "https://github.com/a/b"
    assert d.tabs.count() == 3 and d.tabs.currentIndex() == 0
    text, warning = d._strategy_state_text()
    assert warning                             # 'No gene' + Multi-gene on is flagged
    d.multi_gene.setChecked(False)
    assert d._strategy_state_text()[1] is False
