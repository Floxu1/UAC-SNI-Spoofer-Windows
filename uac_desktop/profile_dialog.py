"""The Xray editor for shared links and their separate UAC route."""

from dataclasses import replace
import ipaddress
import json
import os
import re
import subprocess
import urllib.parse
import uuid

from PySide6.QtCore import QSignalBlocker, Qt
from PySide6.QtGui import QIntValidator
from PySide6.QtWidgets import (
    QApplication, QComboBox, QDialog, QFrame, QGridLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QScrollArea, QToolButton, QVBoxLayout, QWidget,
)

from .fonts import persian_ui_text
from .icons import icon, pixmap
from .engine import build_xray_config
from .models import (
    ProxyProfile, Tuning, UAC_LINK_FIELDS, UAC_ROUTE_METHODS, edit_profile_uri, parse_outbound, parse_uri,
)
from .paths import BIN


NETWORKS = {
    "ws": "WebSocket (WS)", "httpupgrade": "HTTP Upgrade", "raw": "TCP (RAW)",
    "grpc": "gRPC", "xhttp": "XHTTP",
}
PROTOCOLS = {"vless": "VLESS", "trojan": "Trojan", "vmess": "VMess"}
SECURITY = {"tls": "TLS", "reality": "REALITY", "none": "None"}


class ProfileDialog(QDialog):
    def __init__(self, parent, profile: ProxyProfile | None = None, language="fa", fake_sni=""):
        super().__init__(parent)
        self.setObjectName("profileDialog")
        self.language = language
        self.setWindowTitle(self._t("ویرایش کانفیگ", "Edit config") if profile else
                            self._t("افزودن کانفیگ", "Add config"))
        self.setLayoutDirection(Qt.RightToLeft if language == "fa" else Qt.LeftToRight)
        self.setMinimumSize(650, 470)
        self.resize(900, 758)
        self.setStyleSheet(STYLE)
        self._original = profile
        self._accepted = None
        self._base_uri = profile.source_uri if profile else "vless://"
        self._base_fields = {}
        self._fields = {}
        self._rows = {}
        self._valid_link = True
        self._loading = False

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        header = self._bar("editHeader", root)
        mark = QLabel()
        mark.setObjectName("editIcon")
        mark.setPixmap(pixmap("edit", "#46DCE8", 22))
        mark.setAlignment(Qt.AlignCenter)
        mark.setFixedSize(40, 40)
        header.addWidget(mark)
        heading = QVBoxLayout()
        heading.setSpacing(2)
        title = QLabel(self.windowTitle())
        title.setObjectName("editTitle")
        heading.addWidget(title)
        heading.addWidget(QLabel(self._t("مشخصات سرور و مسیر اتصال را تغییر دهید.",
                                        "Edit the server and connection route.")))
        header.addLayout(heading, 1)
        self._protocol_badge = QLabel()
        self._protocol_badge.setObjectName("editProtocol")
        self._protocol_badge.setAlignment(Qt.AlignCenter)
        self._protocol_badge.setFixedHeight(32)
        header.addWidget(self._protocol_badge, 0, Qt.AlignVCenter)

        scroll = QScrollArea()
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        body = QWidget()
        body.setObjectName("editBody")
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(12, 10, 12, 10)
        body_layout.setSpacing(8)
        grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        body_layout.addLayout(grid)

        identity = self._panel(grid, 0, 0, "server", "مشخصات کانفیگ", "Config details")
        self._field(identity, 0, 0, "name", "نام کانفیگ", "Config name", technical=False)
        self._field(identity, 0, 1, "host", "آدرس سرور", "Server address")
        self._field(identity, 1, 0, "protocol", "نوع پروتکل", "Protocol",
                    choices=PROTOCOLS)
        self._field(identity, 1, 1, "port", "پورت سرور", "Server port", port=True)
        self._credential_label = self._field(identity, 2, 0, "user", "شناسه VLESS", "VLESS UUID", span=2)
        credential = self._fields["user"]
        self._password_reveal = credential.addAction(icon("eye", "#87bcce", 15), QLineEdit.TrailingPosition)
        self._password_reveal.setToolTip(self._t("نمایش یا پنهان کردن رمز", "Show or hide password"))
        self._password_reveal.triggered.connect(self._toggle_password)
        self._field(identity, 3, 0, "flow", "جریان اتصال", "Flow")
        self._field(identity, 3, 1, "encryption", "رمزنگاری VLESS", "VLESS encryption")
        self._field(identity, 3, 0, "alter_id", "شناسه جایگزین", "Alter ID")
        self._field(identity, 3, 1, "user_security", "رمزنگاری VMess", "VMess cipher")

        route = self._panel(grid, 0, 1, "route", "مسیر اتصال UAC", "UAC connection route")
        self._field(route, 0, 0, "uac_address", "آی‌پی اصلی", "Primary IP", span=2)
        self._field(route, 1, 0, "uac_fallback_address", "آی‌پی جایگزین", "Fallback IP", span=2)
        self._field(route, 2, 0, "uac_method", "روش اتصال", "Connection method",
                    choices={method: method.replace("_", " ").title() for method in UAC_ROUTE_METHODS})
        self._field(route, 2, 1, "uac_port", "پورت مسیر UAC", "UAC route port", port=True)
        self._route_note = QLabel(self._t("این مسیر با آدرس و پورت سرور داخل لینک فرق دارد.",
                                         "This route uses its own IP and port."))
        self._route_note.setWordWrap(True)
        route.addWidget(self._route_note, 3, 0, 1, 2)

        transport = self._panel(grid, 1, 0, "network", "تنظیمات انتقال", "Transport")
        self._field(transport, 0, 0, "network", "نوع انتقال", "Network", span=2, choices=NETWORKS)
        self._field(transport, 1, 0, "host_header", "دامنهٔ میزبان (Host)", "Host header", span=2)
        self._field(transport, 2, 0, "path", "مسیر (Path)", "Path", span=2)
        self._field(transport, 3, 0, "service_name", "نام سرویس", "Service name", span=2)
        self._field(transport, 4, 0, "authority", "میزبان gRPC", "gRPC authority", span=2)
        self._field(transport, 3, 0, "mode", "حالت XHTTP", "XHTTP mode", span=2,
                    choices={"": "Default", "auto": "Auto", "packet-up": "Packet-up",
                             "stream-up": "Stream-up", "stream-one": "Stream-one"})
        self._field(transport, 4, 0, "extra", "پارامترهای XHTTP (JSON)", "XHTTP extra (JSON)", span=2)
        self._field(transport, 1, 0, "header_type", "نوع هدر TCP", "TCP header type", span=2,
                    choices={"none": "None", "http": "HTTP"})

        security = self._panel(grid, 1, 1, "shield", "امنیت و SNI", "Security and SNI")
        self._field(security, 0, 0, "security", "نوع امنیت", "Security type", choices=SECURITY)
        self._field(security, 0, 1, "fingerprint", "اثر انگشت TLS", "Fingerprint")
        self._field(security, 1, 0, "sni", "دامنهٔ اصلی (SNI)", "Server name (SNI)", span=2)
        self._field(security, 2, 0, "uac_spoof_fake_sni", "دامنهٔ جعلی (Fake SNI)", "Fake SNI", span=2)
        fake = self._fields["uac_spoof_fake_sni"]
        fake.setPlaceholderText(fake_sni)
        fake.setToolTip(self._t("گزینهٔ پیشنهادی برای مسیر UAC. سیاست اپراتور می‌تواند اولویت دیگری تعیین کند.",
                                "Preferred name for the UAC route. Carrier settings can take priority."))
        self._field(security, 3, 0, "alpn", "پروتکل‌های ALPN", "ALPN")
        self._field(security, 4, 0, "reality_public_key", "کلید عمومی REALITY", "REALITY public key", span=2)
        self._field(security, 5, 0, "reality_short_id", "شناسهٔ کوتاه", "Short ID")
        self._field(security, 5, 1, "reality_spider_x", "مسیر SpiderX", "SpiderX")
        self._tls_details = self._expander("تنظیمات گواهی و ECH", "Certificate and ECH settings")
        security.addWidget(self._tls_details, 3, 1, Qt.AlignBottom | Qt.AlignLeading)
        self._field(security, 5, 0, "pinned", "اثر SHA-256 گواهی", "Certificate SHA-256", span=2)
        self._field(security, 6, 0, "verify_name", "نام معتبر گواهی", "Certificate name", span=2)
        self._field(security, 7, 0, "ech", "پیکربندی ECH", "ECH configuration", span=2)
        self._tls_details.toggled.connect(self._update_fields)

        link_panel = QFrame()
        link_panel.setObjectName("editPanel")
        link_box = QVBoxLayout(link_panel)
        link_box.setContentsMargins(8, 5, 8, 7)
        link_box.setSpacing(4)
        link_row = QHBoxLayout()
        show_link = self._expander("لینک کامل کانفیگ", "Full config link")
        link_row.addWidget(show_link)
        link_row.addStretch(1)
        copy = QPushButton(self._t("کپی لینک", "Copy link"))
        copy.setIcon(icon("copy", "#9dc9df", 14))
        copy.clicked.connect(self._copy_link)
        link_row.addWidget(copy)
        link_box.addLayout(link_row)
        self.uri = QLineEdit(self._base_uri if profile else "")
        self.uri.setLayoutDirection(Qt.LeftToRight)
        self.uri.setProperty("technical", True)
        self.uri.setPlaceholderText("vless://…  /  trojan://…  /  vmess://…")
        self.uri.setAccessibleName(self._t("لینک کامل کانفیگ", "Full config link"))
        self.uri.setVisible(False)
        show_link.toggled.connect(self.uri.setVisible)
        self.uri.textChanged.connect(self._on_link_changed)
        link_box.addWidget(self.uri)
        body_layout.addStretch(1)
        scroll.setWidget(body)
        root.addWidget(scroll, 1)
        link_wrap = QVBoxLayout()
        link_wrap.setContentsMargins(12, 0, 12, 8)
        link_wrap.addWidget(link_panel)
        root.addLayout(link_wrap)

        footer = self._bar("editFooter", root)
        self.validation = QLabel()
        self.validation.setObjectName("editValidation")
        self.validation.setWordWrap(True)
        footer.addWidget(self.validation, 1)
        cancel = QPushButton(self._t("انصراف", "Cancel"))
        cancel.clicked.connect(self.reject)
        save = QPushButton(self._t("ذخیره تغییرات", "Save changes"))
        save.setObjectName("editSave")
        save.setIcon(icon("save", "#071f2a", 15))
        save.setDefault(True)
        save.clicked.connect(self._validate_accept)
        footer.addWidget(cancel)
        footer.addWidget(save)

        parsed = parse_uri(self._base_uri, trim_prose=False)
        self._fill(parsed, profile or ProxyProfile())
        if profile is not None and parsed is None:
            self._valid_link = False
            self.validation.setText(self._t("لینک کانفیگ معتبر نیست.", "The config link is invalid."))

    def _t(self, fa, en):
        return persian_ui_text(fa) if self.language == "fa" else en

    def _bar(self, name, parent):
        frame = QFrame()
        frame.setObjectName(name)
        row = QHBoxLayout(frame)
        row.setContentsMargins(12, 9, 12, 9)
        row.setSpacing(8)
        parent.addWidget(frame)
        return row

    def _panel(self, grid, row, column, glyph, fa, en):
        frame = QFrame()
        frame.setObjectName("editPanel")
        box = QVBoxLayout(frame)
        box.setContentsMargins(0, 0, 0, 0)
        box.setSpacing(0)
        heading = self._bar("editPanelHeading", box)
        heading.setContentsMargins(10, 7, 10, 7)
        badge = QLabel()
        badge.setPixmap(pixmap(glyph, "#46DCE8", 15))
        heading.addWidget(badge)
        title = QLabel(self._t(fa, en))
        title.setObjectName("editSectionTitle")
        heading.addWidget(title)
        heading.addStretch()
        fields = QGridLayout()
        fields.setContentsMargins(10, 6, 10, 7)
        fields.setHorizontalSpacing(8)
        fields.setVerticalSpacing(5)
        fields.setColumnStretch(0, 1)
        fields.setColumnStretch(1, 1)
        box.addLayout(fields)
        box.addStretch(1)
        grid.addWidget(frame, row, column)
        return fields

    def _field(self, grid, row, column, key, fa, en, *, span=1, choices=None, technical=True, port=False):
        wrapper = QWidget()
        layout = QVBoxLayout(wrapper)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(3)
        label = QLabel(self._t(fa, en))
        if choices is None:
            control = QLineEdit()
            if port:
                control.setValidator(QIntValidator(1, 65535, control))
            control.textChanged.connect(self._on_form_changed)
        else:
            control = QComboBox()
            for value, title in choices.items():
                control.addItem(title if value else self._t("پیش‌فرض", title), value)
            control.currentIndexChanged.connect(self._on_form_changed)
        control.setObjectName("profile_" + key)
        control.setFixedHeight(34)
        if technical:
            control.setLayoutDirection(Qt.LeftToRight)
            control.setProperty("technical", True)
        label.setBuddy(control)
        control.setAccessibleName(label.text())
        layout.addWidget(label)
        layout.addWidget(control)
        grid.addWidget(wrapper, row, column, 1, span)
        self._fields[key] = control
        self._rows[key] = wrapper
        return label

    def _expander(self, fa, en):
        button = QToolButton()
        button.setObjectName("editExpander")
        button.setText(self._t(fa, en))
        button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        button.setCheckable(True)
        closed = icon("chevron-left" if self.language == "fa" else "chevron-right", "#96dceb", 13)
        opened = icon("arrow-down", "#96dceb", 13)
        button.setIconSize(closed.actualSize(button.iconSize()))
        button.setIcon(closed)
        button.toggled.connect(lambda checked: button.setIcon(opened if checked else closed))
        return button

    def _values(self):
        return {key: (field.currentData() if isinstance(field, QComboBox) else
                      field.text() if key == "user" else field.text().strip())
                for key, field in self._fields.items()}

    def _fill(self, source, route):
        values = parse_outbound(source) if source else {"protocol": "vless", "security": "tls",
                                                        "network": "ws", "port": 443, "encryption": "none"}
        values["name"] = route.name if self._original or source else ""
        values["alpn"] = ", ".join(values.get("alpn", []))
        for field_name in UAC_LINK_FIELDS:
            values["uac_" + field_name] = getattr(route, field_name)
        self._loading = True
        try:
            for key, field in self._fields.items():
                value = str(values.get(key, ""))
                if isinstance(field, QComboBox):
                    index = field.findData(value)
                    if index < 0:
                        field.addItem(value, value)
                        index = field.count() - 1
                    field.setCurrentIndex(index)
                else:
                    field.setText(value)
            self._base_fields = self._values()
        finally:
            self._loading = False
        self._update_fields(reset_password=True)

    def _update_fields(self, *_args, reset_password=False):
        data = self._values()
        protocol, network, security = data["protocol"], data["network"], data["security"]
        trojan = protocol == "trojan"
        self._protocol_badge.setText(protocol.upper())
        self._credential_label.setText(
            self._t("رمز اتصال (Password)", "Password") if trojan else
            self._t(f"شناسه {protocol.upper()}", f"{protocol.upper()} UUID")
        )
        credential = self._fields["user"]
        credential.setAccessibleName(self._credential_label.text())
        if reset_password or not trojan or not self._password_reveal.isVisible():
            credential.setEchoMode(QLineEdit.Password if trojan else QLineEdit.Normal)
        self._password_reveal.setVisible(trojan)
        tls = security == "tls"
        reality = security == "reality"
        direct = reality or bool(data["ech"])
        network_picker = self._fields["network"]
        for index in range(network_picker.count()):
            option = network_picker.itemData(index)
            network_picker.model().item(index).setEnabled(
                option in NETWORKS and (not reality or option in ("raw", "grpc", "xhttp"))
            )
        tls_details = tls and self._tls_details.isChecked()
        visible = {
            "flow": protocol == "vless", "encryption": protocol == "vless",
            "alter_id": protocol == "vmess", "user_security": protocol == "vmess",
            "host_header": network in ("ws", "httpupgrade", "xhttp"),
            "path": network in ("ws", "httpupgrade", "xhttp"),
            "service_name": network == "grpc", "authority": network == "grpc",
            "mode": network == "xhttp", "extra": network == "xhttp", "header_type": network == "raw",
            "sni": tls or reality, "fingerprint": tls or reality, "alpn": tls,
            "uac_spoof_fake_sni": tls and not data["ech"],
            "reality_public_key": reality, "reality_short_id": reality, "reality_spider_x": reality,
            "pinned": tls_details, "verify_name": tls_details, "ech": tls_details,
        }
        for key, shown in visible.items():
            self._rows[key].setVisible(shown)
        self._tls_details.setVisible(tls)
        for key in ("address", "fallback_address", "port", "method"):
            self._fields[f"uac_{key}"].setEnabled(not direct)
        self._route_note.setText(
            self._t("این کانفیگ مستقیماً از آدرس سرور استفاده می‌کند.", "This config connects to the server directly.")
            if direct else
            self._t("این مسیر با آدرس و پورت سرور داخل لینک فرق دارد.", "This route uses its own IP and port.")
        )

    def _toggle_password(self):
        field = self._fields["user"]
        field.setEchoMode(QLineEdit.Normal if field.echoMode() == QLineEdit.Password else QLineEdit.Password)

    def _on_form_changed(self, *_args):
        if self._loading:
            return
        self._update_fields()
        if not self._valid_link:
            return
        data = self._values()
        changes = {key: value for key, value in data.items() if value != self._base_fields[key]}
        with QSignalBlocker(self.uri):
            self.uri.setText(edit_profile_uri(self._base_uri, changes))
        self.validation.clear()

    def _on_link_changed(self, raw):
        source = parse_uri(raw, trim_prose=False)
        self._valid_link = bool(source and not re.search(r"\s", raw.strip()))
        if not self._valid_link:
            self.validation.setText(self._t("یک لینک کانفیگ معتبر وارد کنید.", "Enter a valid config link."))
            return
        route = replace(source)
        present = urllib.parse.parse_qs(urllib.parse.urlsplit(source.source_uri).query.lower(), keep_blank_values=True)
        current = self._values()
        for field_name, parameter in UAC_LINK_FIELDS.items():
            if parameter.lower() not in present:
                value = current["uac_" + field_name]
                if field_name == "port":
                    value = int(value) if value.isdecimal() else source.port
                setattr(route, field_name, value)
        self._base_uri = source.source_uri
        self._fill(source, route)
        self.validation.clear()

    def _copy_link(self):
        if self.uri.text():
            QApplication.clipboard().setText(self.uri.text())

    def _validate_accept(self):
        try:
            result = self._validated_profile()
            if self._original is None or result.source_uri != self._original.source_uri:
                self._validate_core(result)
        except ValueError as error:
            self.validation.setText(str(error))
            return
        self._accepted = result
        self.accept()

    def _validate_core(self, profile):
        binary = BIN / ("xray.exe" if os.name == "nt" else "xray")
        config = build_xray_config(profile, tuning=Tuning(iran_direct=False), direct_edge=False)
        try:
            result = subprocess.run(
                [str(binary), "run", "-test", "-config", "stdin:"],
                input=json.dumps(config).encode("utf-8"),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError(self._t("اعتبارسنجی با هستهٔ Xray در دسترس نیست.",
                                     "Could not check the config with the Xray core.")) from error
        if result.returncode != 0:
            raise ValueError(self._t("هستهٔ Xray این تنظیمات را نپذیرفت. نوع انتقال و امنیت را بررسی کنید.",
                                     "Xray rejected these settings. Check the network and security options."))

    def _validated_profile(self):
        data = self._values()
        raw = self.uri.text().strip()
        parsed = parse_uri(raw, trim_prose=False) if self._valid_link else None
        if parsed is None or re.search(r"\s", raw):
            raise ValueError(self._t("لینک کانفیگ معتبر نیست.", "The config link is invalid."))
        wire = parse_outbound(parsed)
        original = self._original
        if (not _host_valid(data["host"].removeprefix("[").removesuffix("]")) or
                not _port_valid(data["port"]) or urllib.parse.urlsplit(raw).port == 0):
            raise ValueError(self._t("آدرس یا پورت سرور معتبر نیست.", "Enter a valid server address and port."))
        if not _credential_valid(wire["user"], parsed.protocol):
            raise ValueError(self._t("شناسهٔ اتصال یا رمز را بررسی کنید.", "Check the UUID or password."))
        if data["network"] not in NETWORKS or data["security"] not in SECURITY:
            raise ValueError(self._t("نوع انتقال یا امنیت پشتیبانی نمی‌شود.", "Choose a supported network and security type."))
        if parsed.protocol == "vmess" and not (data["alter_id"].isascii() and data["alter_id"].isdecimal()):
            raise ValueError(self._t("شناسهٔ جایگزین باید یک عدد باشد.", "Alter ID must be a number."))
        if data["network"] == "raw" and data["header_type"] not in ("none", "http"):
            raise ValueError(self._t("نوع هدر TCP پشتیبانی نمی‌شود.", "Choose a supported TCP header type."))
        if data["security"] == "reality":
            if data["network"] not in ("raw", "grpc", "xhttp"):
                raise ValueError(self._t("برای REALITY از TCP، gRPC یا XHTTP استفاده کنید.",
                                         "Use TCP, gRPC or XHTTP with REALITY."))
            key = data["reality_public_key"]
            short_id = data["reality_short_id"]
            if not re.fullmatch(r"[A-Za-z0-9_-]{43}", key) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,8}", short_id):
                raise ValueError(self._t("کلید عمومی یا شناسهٔ کوتاه REALITY معتبر نیست.",
                                         "Check the REALITY public key and short ID."))
        if data["network"] == "xhttp" and data["extra"]:
            try:
                valid_extra = isinstance(json.loads(data["extra"]), dict)
            except ValueError:
                valid_extra = False
            if not valid_extra:
                raise ValueError(self._t("پارامترهای XHTTP باید یک شیء JSON باشند.", "XHTTP extra must be a JSON object."))

        route = {field_name: data["uac_" + field_name] for field_name in UAC_LINK_FIELDS}
        if not _port_valid(route["port"]):
            raise ValueError(self._t("پورت مسیر UAC باید بین ۱ و ۶۵۵۳۵ باشد.", "UAC route port must be between 1 and 65535."))
        route["port"] = int(route["port"])
        if route["method"] not in UAC_ROUTE_METHODS:
            raise ValueError(self._t("روش اتصال UAC معتبر نیست.", "Choose a supported UAC connection method."))
        if self._fields["uac_address"].isEnabled():
            if not _ip_valid(route["address"]) or (route["fallback_address"] and not all(
                    _ip_valid(ip.strip()) for ip in route["fallback_address"].split(","))):
                raise ValueError(self._t("آی‌پی اصلی یا جایگزین معتبر نیست.", "Enter valid primary and fallback IP addresses."))
        if data["security"] != "none" and not _host_valid(wire["sni"]):
            raise ValueError(self._t("دامنهٔ اصلی SNI معتبر نیست.", "Enter a valid SNI hostname."))
        if route["spoof_fake_sni"] and not _host_valid(route["spoof_fake_sni"]):
            raise ValueError(self._t("دامنهٔ جعلی SNI معتبر نیست.", "Enter a valid fake SNI hostname."))

        if original is None:
            return replace(parsed, **route, name=data["name"] or parsed.name, origin="user")
        if raw == original.source_uri:
            return replace(original, name=data["name"] or original.name)

        old = parse_outbound(original)
        new = parse_outbound(parsed)
        old.pop("insecure")
        new.pop("insecure")
        route_changed = old != new or any(value != getattr(original, key) for key, value in route.items())
        sni = parsed.sni if old["sni"] != new["sni"] else original.sni
        updated = replace(
            original, **route, name=data["name"] or parsed.name, source_uri=parsed.source_uri, sni=sni,
            config_host=parsed.config_host if old["host"] != new["host"] else original.config_host,
            config_port=parsed.config_port if old["port"] != new["port"] else original.config_port,
            protocol=parsed.protocol if old["protocol"] != new["protocol"] else original.protocol,
            route_mode=parsed.route_mode if (old["ech"], old["security"]) != (new["ech"], new["security"])
            else original.route_mode,
        )
        if route_changed:
            updated = replace(updated, last_ping_ok=False, last_ping_ms=0.0, country_code="",
                              country_latency_ms=0, verified_spoof=False, verified_route=False, rotating_exit=False,
                              observed_exit_ip="", observed_country_code="", observed_country_name="",
                              country_verified_at=0.0, country_source="")
        return updated

    def result_profile(self):
        return self._accepted


def _ip_valid(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _port_valid(value):
    return len(value) <= 5 and value.isascii() and value.isdecimal() and 1 <= int(value) <= 65535


def _host_valid(value):
    if _ip_valid(value):
        return True
    try:
        dns = value.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError:
        return False
    return (0 < len(dns) <= 253 and all(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", part)
                                       for part in dns.split(".")))


def _credential_valid(value, protocol):
    if not value or any(ord(char) < 32 for char in value):
        return False
    if protocol == "trojan":
        return True
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        # Xray also accepts a short custom VLESS ID and maps it to a UUID.
        return protocol == "vless" and 1 <= len(value.encode("utf-8")) <= 30


STYLE = """
QDialog#profileDialog, QWidget#editBody, QDialog#profileDialog QScrollArea { background: #07111E; border: 0; }
QDialog#profileDialog QLabel { color: #a9c2d5; background: transparent; font-size: 12px; font-weight: 500; }
QDialog#profileDialog QLabel#editTitle { color: #e5f0f9; font-size: 23px; font-weight: 600; }
QDialog#profileDialog QLabel#editSectionTitle { color: #dcebf6; font-size: 13px; font-weight: 600; }
QDialog#profileDialog QLabel#editIcon, QDialog#profileDialog QLabel#editProtocol {
    background: #123442; border: 1px solid #265366; border-radius: 7px; color: #6ce5ec;
}
QDialog#profileDialog QLabel#editProtocol { padding: 5px 11px; font-weight: 600; }
QFrame#editHeader, QFrame#editFooter { background: #0B1B2D; }
QFrame#editHeader { border-bottom: 1px solid #1E4057; }
QFrame#editFooter { border-top: 1px solid #1E4057; }
QFrame#editPanel { background: #0B1B2D; border: 1px solid #1E4057; border-radius: 8px; }
QFrame#editPanelHeading {
    background: #102538; border: 0; border-bottom: 1px solid #1E4057;
    border-top-left-radius: 8px; border-top-right-radius: 8px;
}
QDialog#profileDialog QLineEdit, QDialog#profileDialog QComboBox {
    background: #081725; border: 1px solid #2a485d; border-radius: 6px;
    padding: 1px 8px; min-height: 28px; color: #e3edf6; font-size: 12px; font-weight: 500;
}
QDialog#profileDialog QLineEdit[technical="true"], QDialog#profileDialog QComboBox[technical="true"] {
    font-family: "Inter", "Segoe UI", "Vazirmatn UI FD";
}
QDialog#profileDialog QLineEdit:focus, QDialog#profileDialog QComboBox:focus { border-color: #46DCE8; }
QDialog#profileDialog QLineEdit:disabled, QDialog#profileDialog QComboBox:disabled { color: #7694ad; }
QDialog#profileDialog QComboBox { padding-right: 30px; }
QDialog#profileDialog QPushButton {
    min-height: 30px; padding: 0 11px; border: 1px solid #2a485d; border-radius: 6px;
    background: #0d2134; color: #dbeef7; font-size: 12px; font-weight: 600;
}
QDialog#profileDialog QPushButton:hover, QDialog#profileDialog QPushButton:focus {
    border-color: #46DCE8; background: #153547;
}
QDialog#profileDialog QPushButton#editSave {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #20dacd,stop:1 #38cce5);
    border-color: #68e8ee; color: #071f2a;
}
QDialog#profileDialog QPushButton#editSave:hover, QDialog#profileDialog QPushButton#editSave:focus {
    background: #69e6ec;
}
QDialog#profileDialog QToolButton#editExpander {
    background: transparent; border: 1px solid transparent; color: #96dceb;
    padding: 4px; font-size: 12px; font-weight: 500;
}
QDialog#profileDialog QToolButton#editExpander:hover, QDialog#profileDialog QToolButton#editExpander:focus {
    border-color: #2a485d; border-radius: 5px;
}
QDialog#profileDialog QLabel#editValidation { color: #ffaab5; }
"""
