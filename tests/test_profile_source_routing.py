from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QListWidgetItem

import uac_desktop.ui as ui_module
from uac_desktop.models import ProxyProfile, Tuning, default_profiles
from uac_desktop.ui import MainWindow, USER_CONFIG_ORIGIN


class ListStub:
    def __init__(self):
        self.items = []
        self.current = None

    def clear(self):
        self.items.clear()
        self.current = None

    def addItem(self, item):
        self.items.append(item)

    def setCurrentItem(self, item):
        self.current = item

    def currentItem(self):
        return self.current

    def count(self):
        return len(self.items)


class IndexStub:
    def __init__(self, index=0):
        self.index = index
        self.enabled = True

    def currentIndex(self):
        return self.index

    def setCurrentIndex(self, index):
        self.index = index

    def setEnabled(self, enabled):
        self.enabled = bool(enabled)


class LabelStub:
    def __init__(self):
        self.text = ""
        self.visible = True

    def setText(self, text):
        self.text = text

    def setVisible(self, visible):
        self.visible = bool(visible)


class ViewStub:
    def setLayoutDirection(self, _direction):
        pass

    def setMinimumWidth(self, _width):
        pass

    def setIconSize(self, _size):
        pass

    def setTextElideMode(self, _mode):
        pass

    def setSpacing(self, _spacing):
        pass


class ComboStub:
    def __init__(self, current="ALL"):
        self.items = []
        self.index = -1
        self.initial = current
        self.enabled = True
        self.visible = True
        self._view = ViewStub()

    def currentData(self):
        if 0 <= self.index < len(self.items):
            return self.items[self.index][2]
        return self.initial

    def blockSignals(self, _blocked):
        pass

    def clear(self):
        self.items.clear()
        self.index = -1

    def setLayoutDirection(self, _direction):
        pass

    def view(self):
        return self._view

    def addItem(self, icon, text, data):
        self.items.append((icon, text, data))

    def findData(self, data):
        return next(
            (index for index, item in enumerate(self.items) if item[2] == data),
            -1,
        )

    def setCurrentIndex(self, index):
        self.index = index

    def setEnabled(self, enabled):
        self.enabled = bool(enabled)

    def setVisible(self, visible):
        self.visible = bool(visible)


class StorageStub:
    def __init__(self, profiles, *, selected_id="", settings=None):
        self.profiles = list(profiles)
        self.selected_id = selected_id
        self.settings = dict(settings or {})
        self.tuning = Tuning(carrier_mode="irancell")
        self.saved_profiles = 0
        self.saved_settings = 0

    def selected(self):
        return next(
            (profile for profile in self.profiles if profile.id == self.selected_id),
            None,
        )

    def save_profiles(self):
        self.saved_profiles += 1

    def save_settings(self):
        self.saved_settings += 1


def profile(
    profile_id,
    *,
    origin,
    country="",
    country_name="",
    verified=False,
    ping=None,
):
    return ProxyProfile(
        id=profile_id,
        name=profile_id.replace("-", " ").title(),
        source_uri=f"trojan://password@{profile_id}.example:443#{profile_id}",
        protocol="trojan",
        config_host=f"{profile_id}.example",
        config_port=443,
        address="104.19.229.21",
        port=443,
        sni=f"{profile_id}.example",
        spoof_fake_sni="static.cloudflare.com",
        origin=origin,
        country_code=country,
        observed_country_code=country,
        observed_country_name=country_name,
        verified_spoof=verified,
        last_ping_ok=ping is not None,
        last_ping_ms=float(ping or 0),
    )


def routing_dummy(storage, source_index=0, country="ALL"):
    dummy = SimpleNamespace(
        storage=storage,
        route_source_tabs=IndexStub(source_index),
        country_combo=ComboStub(country),
        bridge=SimpleNamespace(
            log=SimpleNamespace(emit=lambda *_args: None),
            latency=SimpleNamespace(emit=lambda *_args: None),
        ),
    )
    dummy._selected_route_source = lambda: MainWindow._selected_route_source(dummy)
    dummy._selected_country_code = lambda: MainWindow._selected_country_code(dummy)
    dummy._route_source_profiles = (
        lambda verified_only=False: MainWindow._route_source_profiles(
            dummy, verified_only
        )
    )
    return dummy


def refresh_dummy(storage):
    manual = ListStub()
    user_config = ListStub()
    suggested = ListStub()
    dummy = SimpleNamespace(
        storage=storage,
        language="en",
        manual_list=manual,
        user_config_list=user_config,
        suggested_list=suggested,
        profile_tabs=IndexStub(0),
        sync_btn=SimpleNamespace(setEnabled=lambda _enabled: None),
        config_count_label=LabelStub(),
        active_profile=LabelStub(),
        route_card=SimpleNamespace(set_secondary=lambda _text: None),
        tr=lambda _fa, en=None: en or _fa,
        _refresh_country_selector=lambda: None,
        _update_config_actions=lambda: None,
        _profile_route_label=lambda item, _carrier=None: (
            item.target_label if item is not None else ""
        ),
    )
    dummy._country_metadata = lambda code: MainWindow._country_metadata(dummy, code)
    return dummy


def item_ids(widget):
    return [
        item.data(Qt.UserRole)
        for item in widget.items
        if item.data(Qt.UserRole + 1) != "country-header"
    ]


def header_texts(widget):
    return [
        item.text()
        for item in widget.items
        if item.data(Qt.UserRole + 1) == "country-header"
    ]


def test_configs_page_keeps_manual_user_config_and_suggested_separate(monkeypatch):
    manual = profile("manual-one", origin="user")
    maker = profile(
        "maker-one",
        origin=USER_CONFIG_ORIGIN,
        country="GB",
        country_name="United Kingdom",
        verified=True,
        ping=55,
    )
    suggested = profile(
        "suggested-one", origin="github", country="DE", verified=True, ping=70
    )
    storage = StorageStub([suggested, maker, manual], selected_id=maker.id)
    dummy = refresh_dummy(storage)
    monkeypatch.setattr(ui_module, "country_flag_icon", lambda *_args: QIcon())
    monkeypatch.setattr(ui_module, "cyber_icon", lambda *_args: QIcon())

    MainWindow.refresh_profiles(dummy)

    assert item_ids(dummy.manual_list) == [manual.id]
    assert item_ids(dummy.user_config_list) == [maker.id]
    assert item_ids(dummy.suggested_list) == [suggested.id]
    assert dummy.user_config_list.current.data(Qt.UserRole) == maker.id


def test_auto_user_config_uses_only_verified_profiles(monkeypatch):
    healthy = profile(
        "healthy-user-config",
        origin=USER_CONFIG_ORIGIN,
        country="GB",
        verified=True,
        ping=43,
    )
    unverified = profile(
        "untested-user-config",
        origin=USER_CONFIG_ORIGIN,
        country="GB",
        verified=False,
    )
    suggested = profile(
        "verified-suggested",
        origin="verified",
        country="GB",
        verified=True,
        ping=20,
    )
    manual = profile("manual-one", origin="user")
    storage = StorageStub([unverified, suggested, manual, healthy])
    dummy = routing_dummy(storage, source_index=1)
    monkeypatch.setattr(ui_module, "profile_ping", lambda *_args: (True, 10.0))

    ordered = MainWindow._ordered_profiles(
        dummy,
        "static.cloudflare.com",
        threading.Event(),
        auto_enabled=True,
    )

    assert ordered == [healthy]


def test_auto_user_config_accepts_verified_reality_route(monkeypatch):
    reality = profile(
        "healthy-reality",
        origin=USER_CONFIG_ORIGIN,
        country="DE",
        verified=False,
        ping=52,
    )
    reality.route_mode = "reality-direct"
    reality.verified_route = True
    storage = StorageStub([reality])
    dummy = routing_dummy(storage, source_index=1)
    monkeypatch.setattr(ui_module, "profile_ping", lambda *_args: (True, 10.0))

    ordered = MainWindow._ordered_profiles(
        dummy,
        reality.sni,
        threading.Event(),
        auto_enabled=True,
    )

    assert ordered == [reality]


def test_auto_user_config_never_falls_back_to_unverified_profiles(monkeypatch):
    unverified = profile(
        "untested-user-config",
        origin=USER_CONFIG_ORIGIN,
        country="GB",
        verified=False,
    )
    storage = StorageStub([unverified])
    dummy = routing_dummy(storage, source_index=1)
    monkeypatch.setattr(ui_module, "profile_ping", lambda *_args: (True, 10.0))

    ordered = MainWindow._ordered_profiles(
        dummy,
        "static.cloudflare.com",
        threading.Event(),
        auto_enabled=True,
    )

    assert ordered == []


def test_manual_mode_restores_last_user_config_after_auto_runtime_selection():
    first = profile(
        "maker-first",
        origin=USER_CONFIG_ORIGIN,
        country="CH",
        verified=True,
        ping=49,
    )
    preferred = profile(
        "maker-preferred",
        origin=USER_CONFIG_ORIGIN,
        country="DE",
        verified=True,
        ping=38,
    )
    auto_winner = profile(
        "suggested-winner",
        origin="verified",
        country="FR",
        verified=True,
        ping=25,
    )
    storage = StorageStub(
        [first, auto_winner, preferred],
        selected_id=auto_winner.id,
        settings={
            "direct_source": "user-config",
            "last_user_config_profile_id": preferred.id,
        },
    )
    dummy = SimpleNamespace(
        storage=storage,
        manual_list=ListStub(),
        user_config_list=ListStub(),
    )

    selected = MainWindow._select_manual_profile(dummy)

    assert selected is preferred
    assert storage.selected_id == preferred.id
    assert storage.settings["direct_source"] == "user-config"


def test_pick_best_in_manual_mode_uses_persisted_user_config_source(monkeypatch):
    manual = profile("manual-one", origin="user")
    first = profile(
        "maker-one",
        origin=USER_CONFIG_ORIGIN,
        country="CH",
        verified=True,
        ping=61,
    )
    second = profile(
        "maker-two",
        origin=USER_CONFIG_ORIGIN,
        country="DE",
        verified=True,
        ping=39,
    )
    storage = StorageStub(
        [manual, first, second],
        selected_id=manual.id,
        settings={"direct_source": "user-config"},
    )
    dummy = routing_dummy(storage, source_index=0)
    monkeypatch.setattr(ui_module, "profile_ping", lambda *_args: (True, 10.0))

    ordered = MainWindow._ordered_profiles(
        dummy,
        "static.cloudflare.com",
        threading.Event(),
        auto_enabled=False,
        manual_only=True,
    )

    assert {item.id for item in ordered} == {first.id, second.id}
    assert all(item.origin == USER_CONFIG_ORIGIN for item in ordered)


@pytest.mark.parametrize("origin", ["user", USER_CONFIG_ORIGIN, "github"])
def test_direct_profile_selection_overrides_auto_source_and_country(
    monkeypatch, origin
):
    clicked = profile(
        f"clicked-{origin}",
        origin=origin,
        country="GB",
        verified=origin != "user",
        ping=40,
    )
    auto_candidate = profile(
        "auto-candidate",
        origin="verified",
        country="DE",
        verified=True,
        ping=15,
    )
    storage = StorageStub(
        [auto_candidate, clicked],
        selected_id=clicked.id,
        settings={"selected_country": "DE"},
    )
    dummy = routing_dummy(storage, source_index=0, country="DE")
    monkeypatch.setattr(ui_module, "profile_ping", lambda *_args: (True, 10.0))

    ordered = MainWindow._ordered_profiles(
        dummy,
        "static.cloudflare.com",
        threading.Event(),
        auto_enabled=True,
        forced_profile=clicked,
    )

    assert ordered == [clicked]
    assert storage.selected_id == clicked.id


def test_active_auto_connection_click_keeps_exact_profile_for_restart():
    clicked = profile(
        "clicked-user-config",
        origin=USER_CONFIG_ORIGIN,
        country="GB",
        verified=True,
        ping=38,
    )
    storage = StorageStub([clicked])
    queued = []
    item = QListWidgetItem(clicked.name)
    item.setData(Qt.UserRole, clicked.id)
    dummy = SimpleNamespace(
        storage=storage,
        connecting=False,
        engine=SimpleNamespace(running=True),
        _profile_switch_waiting=False,
        active_profile=LabelStub(),
        route_card=SimpleNamespace(set_secondary=lambda _text: None),
        _profile_route_label=lambda _profile: "route",
        _update_config_actions=lambda: None,
        _queue_profile_switch=queued.append,
    )

    MainWindow._profile_clicked(dummy, item)

    assert storage.selected_id == clicked.id
    assert queued == [clicked.id]


def test_dynamic_countries_are_preserved_named_and_sorted_in_selector(monkeypatch):
    brazil = profile(
        "brazil-route",
        origin=USER_CONFIG_ORIGIN,
        country="BR",
        country_name="Brazil",
        verified=False,
    )
    britain = profile(
        "britain-route",
        origin=USER_CONFIG_ORIGIN,
        country="GB",
        country_name="United Kingdom",
        verified=True,
        ping=52,
    )
    storage = StorageStub(
        [britain, brazil],
        settings={
            "route_source": "user-config",
            "selected_country_user-config": "BR",
            "known_country_codes": ["BR", "GB"],
        },
    )
    combo = ComboStub()
    count = LabelStub()
    dummy = routing_dummy(storage, source_index=1)
    dummy.country_combo = combo
    dummy.country_count = count
    dummy.language = "en"
    dummy.tr = lambda _fa, en=None: en or _fa
    dummy._country_metadata = lambda code: MainWindow._country_metadata(dummy, code)
    dummy._country_profiles = (
        lambda code=None: MainWindow._country_profiles(dummy, code)
    )
    monkeypatch.setattr(ui_module, "country_flag_icon", lambda *_args: QIcon())
    monkeypatch.setattr(ui_module, "cyber_icon", lambda *_args: QIcon())

    MainWindow._refresh_country_selector(dummy)

    codes = [data for _icon, _text, data in combo.items if data != "ALL"]
    expected = sorted(
        codes,
        key=lambda code: (
            MainWindow._country_metadata(dummy, code)[1].lower(),
            code,
        ),
    )
    labels = {data: text for _icon, text, data in combo.items}
    assert codes == expected
    assert combo.currentData() == "BR"
    assert labels["BR"] == "Brazil  (0)"
    assert labels["GB"] == "United Kingdom  (1)"
    assert count.text == "0 verified configs"


def test_suggested_selector_shows_only_original_configs(monkeypatch):
    storage = StorageStub(
        default_profiles(),
        settings={"route_source": "suggested", "selected_country": "DE"},
    )
    dummy = routing_dummy(storage, source_index=0, country="DE")
    dummy.country_combo = ComboStub("DE")
    dummy.original_configs_label = LabelStub()
    dummy.country_count = LabelStub()
    dummy.language = "en"
    dummy.tr = lambda _fa, en=None: en or _fa
    monkeypatch.setattr(ui_module, "cyber_icon", lambda *_args: QIcon())

    MainWindow._refresh_country_selector(dummy)

    assert dummy.country_combo.visible is False
    assert dummy.original_configs_label.visible is True
    assert dummy.country_combo.items[0][1:] == (
        "UAC Spoof Original Configs", "ALL"
    )
    assert dummy.country_count.text == "6 original configs"
    assert MainWindow._selected_country_code(dummy) == ""


def test_user_config_country_groups_sort_by_country_then_real_ping(monkeypatch):
    gb_slow = profile(
        "gb-slow",
        origin=USER_CONFIG_ORIGIN,
        country="GB",
        country_name="United Kingdom",
        verified=True,
        ping=90,
    )
    brazil = profile(
        "br-fast",
        origin=USER_CONFIG_ORIGIN,
        country="BR",
        country_name="Brazil",
        verified=True,
        ping=44,
    )
    gb_fast = profile(
        "gb-fast",
        origin=USER_CONFIG_ORIGIN,
        country="GB",
        country_name="United Kingdom",
        verified=True,
        ping=35,
    )
    swiss = profile(
        "ch-fast",
        origin=USER_CONFIG_ORIGIN,
        country="CH",
        verified=True,
        ping=30,
    )
    storage = StorageStub([gb_slow, swiss, gb_fast, brazil])
    dummy = refresh_dummy(storage)
    monkeypatch.setattr(ui_module, "country_flag_icon", lambda *_args: QIcon())
    monkeypatch.setattr(ui_module, "cyber_icon", lambda *_args: QIcon())

    MainWindow.refresh_profiles(dummy)

    assert header_texts(dummy.user_config_list) == [
        "Brazil  ·  1 configs",
        "Switzerland  ·  1 configs",
        "United Kingdom  ·  2 configs",
    ]
    assert item_ids(dummy.user_config_list) == [
        brazil.id,
        swiss.id,
        gb_fast.id,
        gb_slow.id,
    ]
