from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QMimeData, QUrl, Qt
from PySide6.QtWidgets import QApplication

from uac_desktop.sni_maker_widgets import (
    ConfigDropEdit,
    CountryRail,
    ISO2_CODES,
    MakerColumns,
    MakerFilterProxy,
    MakerResultsModel,
    MakerRoles,
    country_badge_icon,
    normalize_country_code,
)


@pytest.fixture(scope="module")
def app():
    instance = QApplication.instance() or QApplication([])
    yield instance


def test_country_badges_cover_every_iso2_and_unknown(app):
    assert len(ISO2_CODES) >= 249
    for code in ISO2_CODES:
        icon = country_badge_icon(code)
        assert not icon.isNull()
        assert not icon.pixmap(32, 22).isNull()
        assert normalize_country_code(code.lower()) == code
    assert normalize_country_code("bad") == "XX"
    assert not country_badge_icon("bad").isNull()


def test_model_batch_append_update_check_and_summaries(app):
    rows = [
        {
            "key": f"id-{index}",
            "uri": f"vless://user-{index}@edge.example:443#route-{index}",
            "status": "queued",
            "country_code": "DE" if index % 2 else "JP",
        }
        for index in range(1500)
    ]
    model = MakerResultsModel()
    inserted = model.append_batch(rows)

    assert inserted == list(range(1500))
    assert model.rowCount() == 1500
    assert model.columnCount() == 5
    assert model.data(model.index(1, MakerColumns.COUNTRY)) == "DE"
    assert model.data(model.index(1, MakerColumns.URI), MakerRoles.UriRole).startswith("vless://")

    changed = model.update_batch(
        [
            {"key": "id-1", "status": "healthy", "ping_ms": 81.4, "checked": True},
            {"key": "id-2", "status": "failed", "error": "timeout"},
            (3, {"status": "healthy", "ping": 120, "country": "CH"}),
        ]
    )

    assert changed == 3
    assert model.data(model.index(1, MakerColumns.STATUS)) == "Healthy"
    assert model.data(model.index(1, MakerColumns.PING)) == "81 ms"
    assert model.data(model.index(3, MakerColumns.COUNTRY)) == "CH"
    assert model.checked_uris() == [rows[1]["uri"]]
    assert len(model.healthy_results()) == 2
    assert len(model.healthy_results("CH")) == 1
    assert model.country_summary()["CH"]["healthy"] == 1

    check_index = model.index(4, MakerColumns.MARK)
    assert model.setData(check_index, Qt.CheckState.Checked, Qt.ItemDataRole.CheckStateRole)
    assert model.data(check_index, Qt.ItemDataRole.CheckStateRole) == Qt.CheckState.Checked
    assert model.set_all_checked(True) == 1498
    assert len(model.checked_results()) == 1500


def test_model_deduplication_and_duplicate_keys_are_stable(app):
    model = MakerResultsModel()
    model.append_batch(["trojan://one@example.com", "trojan://one@example.com"])
    assert model.rowCount() == 2
    assert model.result_at(0).key == "trojan://one@example.com"
    assert model.result_at(1).key == "trojan://one@example.com~2"

    model.append_batch(["trojan://one@example.com"], deduplicate=True)
    assert model.rowCount() == 2


def test_filter_proxy_combines_country_status_and_search(app):
    model = MakerResultsModel(
        [
            {"key": "de-fast", "uri": "vless://alpha@example.com", "status": "healthy", "country": "DE", "ping": 72},
            {"key": "de-dead", "uri": "vless://beta@example.com", "status": "failed", "country": "DE"},
            {"key": "jp-fast", "uri": "trojan://gamma@example.com", "status": "healthy", "country": "JP", "ping": 145},
        ]
    )
    proxy = MakerFilterProxy()
    proxy.setSourceModel(model)

    proxy.set_country("DE")
    assert proxy.rowCount() == 2
    proxy.set_statuses({"healthy"})
    assert proxy.rowCount() == 1
    assert proxy.data(proxy.index(0, MakerColumns.URI), MakerRoles.KeyRole) == "de-fast"
    proxy.set_search("gamma")
    assert proxy.rowCount() == 0
    proxy.set_country("*")
    assert proxy.rowCount() == 1
    assert proxy.data(proxy.index(0, MakerColumns.URI), MakerRoles.KeyRole) == "jp-fast"
    proxy.clear_filters()
    assert proxy.rowCount() == 3


def test_drop_edit_ingests_files_text_and_clipboard(app, tmp_path: Path):
    first = tmp_path / "first.txt"
    second = tmp_path / "second.conf"
    first.write_text("vless://one@example.com\n", encoding="utf-8")
    second.write_text("trojan://two@example.com\n", encoding="utf-8")
    mime = QMimeData()
    mime.setUrls([QUrl.fromLocalFile(str(first)), QUrl.fromLocalFile(str(second))])
    editor = ConfigDropEdit()

    payload, paths = editor.ingest_mime_data(mime)

    assert "vless://one@example.com" in payload
    assert "trojan://two@example.com" in payload
    assert paths == [str(first), str(second)]
    assert editor.configuration_lines() == [
        "vless://one@example.com",
        "trojan://two@example.com",
    ]

    QApplication.clipboard().setText("ss://clipboard-config")
    assert editor.paste_from_clipboard()
    assert editor.configuration_lines()[-1] == "ss://clipboard-config"


def test_country_rail_keeps_counts_selection_and_unknown(app):
    rail = CountryRail()
    selected = []
    rail.countrySelected.connect(selected.append)
    rail.set_country_counts(
        {
            "DE": {"healthy": 8, "total": 11, "testing": 1},
            "JP": (3, 5),
            "invalid": 2,
        },
        labels={"DE": "Germany", "JP": "Japan", "XX": "Unknown"},
        selected="JP",
    )

    assert rail.count() == 4
    assert rail.selected_country() == "JP"
    assert rail.find_country("DE").data(CountryRail.HealthyCountRole) == 8
    assert rail.find_country("invalid").data(CountryRail.CountryCodeRole) == "XX"
    assert rail.select_country("DE")
    assert rail.selected_country() == "DE"
    assert selected[-1] == "DE"
