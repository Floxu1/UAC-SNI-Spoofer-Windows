"""Spoof profiles that passed the local end-to-end Patterniha probe.

The fragment of every URI records only its stable sequence and exit-country
label.  Profiles still get tested again before a real connection is selected.
"""

VERIFIED_SPOOF_EDGE = "104.19.229.21"
VERIFIED_SPOOF_FAKE_SNI = "static.cloudflare.com"




ROTATING_SPOOF_SEQUENCES = {4, 5, 7, 8, 11, 18, 26, 47}

COUNTRIES = {
    "AT": ("🇦🇹", "Austria", "اتریش"),
    "DE": ("🇩🇪", "Germany", "آلمان"),
    "FI": ("🇫🇮", "Finland", "فنلاند"),
    "FR": ("🇫🇷", "France", "فرانسه"),
    "JP": ("🇯🇵", "Japan", "ژاپن"),
    "NL": ("🇳🇱", "Netherlands", "هلند"),
    "PL": ("🇵🇱", "Poland", "لهستان"),
    "SG": ("🇸🇬", "Singapore", "سنگاپور"),
    "US": ("🇺🇸", "United States", "آمریکا"),
}

VERIFIED_SPOOF_CONFIGS = """vless://7e544a9d-7667-413b-bbb0-b3bb1aac6d77@127.0.0.1:40443?path=/rsedgws&security=tls&encryption=none&insecure=0&host=shegeftihaaa.net&fp=chrome&type=ws&allowInsecure=0&sni=shegeftihaaa.net#SPOOF-001-NL
trojan://humanity@127.0.0.1:40443?path=/assignment&security=tls&insecure=0&host=www.creationlong.org&fp=chrome&type=ws&allowInsecure=0&sni=www.creationlong.org#SPOOF-002-PL
trojan://humanity@127.0.0.1:40443?path=/assignment&security=tls&insecure=0&host=www.creationlong.org&type=ws&allowInsecure=0&sni=www.creationlong.org#SPOOF-003-PL
vless://eeb6823c-b926-4ea2-866a-5542edd26e59@127.0.0.1:40443?path=/&security=tls&encryption=none&insecure=0&fp=chrome&type=ws&allowInsecure=0&sni=t1s1.rittbo.kdns.fr#SPOOF-004-DE
vless://eeb6823c-b926-4ea2-866a-5542edd26e59@127.0.0.1:40443?encryption=none&security=tls&sni=t1s1.rittbo.kdns.fr&fp=chrome&insecure=0&allowInsecure=0&ech=cloudflare-ech.com+https://dns.alidns.com/dns-query&type=ws&host=t1s1.rittbo.kdns.fr&path=/#SPOOF-005-DE
vless://14b59caf-a196-4ec2-8c70-c7b388062f5b@127.0.0.1:40443?path=%2Frdfgtws&security=tls&encryption=none&insecure=0&host=vangoghhh.info&type=ws&allowInsecure=0&sni=vangoghhh.info#SPOOF-006-NL
vless://eeb6823c-b926-4ea2-866a-5542edd26e59@127.0.0.1:40443?path=/?TELEGRAM-MARAMBASHI_MARAMBASHI_MARAMBASHI_MARAMBASHI_MARAMBASHI?ed=2560&security=tls&encryption=none&insecure=0&host=t1s1.rittbo.kdns.fr&fp=chrome&type=ws&allowInsecure=0&sni=t1s1.rittbo.kdns.fr#SPOOF-007-DE
vless://eeb6823c-b926-4ea2-866a-5542edd26e59@127.0.0.1:40443?path=/&security=tls&encryption=none&insecure=0&host=t1s1.rittbo.kdns.fr&type=ws&allowInsecure=0&sni=t1s1.rittbo.kdns.fr#SPOOF-008-DE
vless://7e544a9d-7667-413b-bbb0-b3bb1aac6d77@127.0.0.1:40443?path=/rsedgws&security=tls&encryption=none&insecure=0&host=shegeftihaaa.net&type=ws&allowInsecure=0&sni=shegeftihaaa.net#SPOOF-009-NL
trojan://humanity@127.0.0.1:40443/?type=ws&host=www.gossipglove.com&path=%2Fassignment&security=tls&sni=www.gossipglove.com#SPOOF-010-FR
vless://eeb6823c-b926-4ea2-866a-5542edd26e59@127.0.0.1:40443?path=/fp&security=tls&encryption=none&insecure=0&host=t1s1.rittbo.kdns.fr&type=ws&allowInsecure=0&sni=t1s1.rittbo.kdns.fr#SPOOF-011-DE
vless://eeb6823c-b926-4ea2-866a-5542edd26e59@127.0.0.1:40443?path=/?TELEGRAM-MARAMBASHI_MARAMBASHI_MARAMBASHI_MARAMBASHI_MARAMBASHI?ed&security=tls&encryption=none&insecure=0&host=t1s1.rittbo.kdns.fr&fp=chrome&type=ws&allowInsecure=0&sni=t1s1.rittbo.kdns.fr#SPOOF-012-DE
vless://72d1797c-cef8-410a-b8fd-db9104dc3cb0@127.0.0.1:40443?encryption=none&host=amooaliii.net&path=/jdhfyws&security=tls&sni=amooaliii.net&type=ws#SPOOF-013-DE
vless://14b59caf-a196-4ec2-8c70-c7b388062f5b@127.0.0.1:40443?path=%2Frdfgtws&security=tls&encryption=none&insecure=0&host=vangoghhh.info&fp=chrome&type=ws&allowInsecure=0&sni=vangoghhh.info#SPOOF-014-NL
vless://9a3de3e0-2a6e-4bb2-81bd-1a4e51dfa110@127.0.0.1:40443?encryption=none&fp=chrome&host=vpn.renshengxuanze.ccwu.cc&path=%2F&security=tls&sni=vpn.renshengxuanze.ccwu.cc&type=ws#SPOOF-015-DE
vless://8ad6f598-cd8d-4fca-848e-05fc9be15ff3@127.0.0.1:40443?path=/sea&security=tls&encryption=none&insecure=0&host=deicl.redstone-vex.sbs&fp=chrome&type=ws&allowInsecure=0&sni=deicl.redstone-vex.sbs#SPOOF-016-FR
vless://8ad6f598-cd8d-4fca-848e-05fc9be15ff3@127.0.0.1:40443?&security=tls&fp=chrome&sni=fosae.starriverway-milo.sbs&type=ws&headerType=none&host=fosae.starriverway-milo.sbs&path=/sea#SPOOF-017-DE
vless://663cf772-829c-4bc6-893d-b7d021d42f5b@127.0.0.1:40443?path=/&security=tls&encryption=none&insecure=0&host=vp1.cc.cd&fp=chrome&type=ws&allowInsecure=0&sni=vp1.cc.cd#SPOOF-018-DE
vless://14b59caf-a196-4ec2-8c70-c7b388062f5b@127.0.0.1:40443?path=/rdfgtws?ELiV2ray--ELiV2ray--ELiV2ray--ELiV2ray&security=tls&encryption=none&host=vangoghhh.info&type=ws&sni=vangoghhh.info#SPOOF-019-NL
vless://72d1797c-cef8-410a-b8fd-db9104dc3cb0@127.0.0.1:40443?encryption=none&fp=chrome&host=amooaliii.net&path=/jdhfyws&security=tls&sni=amooaliii.net&type=ws#SPOOF-020-DE
vless://e911c552-3a98-41e0-b5fb-0dd3879887b7@127.0.0.1:40443?encryption=none&security=tls&sni=vod.ensf.top&alpn=http/1.1&insecure=0&allowInsecure=0&type=ws&host=vod.ensf.top&path=/api/v1/irc#SPOOF-021-AT
vless://073d1d50-8478-47bf-a828-7a1b381931d5@127.0.0.1:40443?encryption=none&security=tls&sni=octopusss.net&fp=chrome&insecure=0&allowInsecure=0&type=ws&host=octopusss.net&path=/odiyfws#SPOOF-022-FR
vless://89c5493f-9485-85e5-c43f-df0600000000@127.0.0.1:40443?path=/vasl&security=tls&encryption=none&insecure=0&fp=chrome&type=ws&allowInsecure=0&sni=nameless-moon-7c4d.shafmrhjlos23.workers.dev#SPOOF-023-NL
trojan://humanity@127.0.0.1:40443?path=/assignment&security=tls&insecure=0&host=www.gossipglove.com&fp=chrome&type=ws&allowInsecure=0&sni=www.gossipglove.com#SPOOF-024-FR
vless://8ad6f598-cd8d-4fca-848e-05fc9be15ff3@127.0.0.1:40443?path=/sea&security=tls&encryption=none&insecure=0&host=gioub.moonleafbox-kilo.info&fp=chrome&type=ws&allowInsecure=0&sni=gioub.moonleafbox-kilo.info#SPOOF-025-FR
vless://4a1441b0-7bc8-4906-85cf-6b59c256b480@127.0.0.1:40443?encryption=none&fp=chrome&host=edt2.yfqh08811.ccwu.cc&path=/&security=tls&sni=edt2.yfqh08811.ccwu.cc&type=ws#SPOOF-026-DE
trojan://humanity@127.0.0.1:40443?host=www.ignitelimit.com&path=%2Fassignment&sni=www.ignitelimit.com&type=ws#SPOOF-027-FR
vless://073d1d50-8478-47bf-a828-7a1b381931d5@127.0.0.1:40443?encryption=none&security=tls&sni=octopusss.net&fp=chrome&insecure=0&allowInsecure=0&type=ws&host=octopusss.net&path=%2Fodiyfws%23%2F%3FTELEGRAM-MARAMBASHI_MARAMBASHI_MARAMBASHI_MARAMBASHI_MARAMBASHI%3Fed%3D2048#SPOOF-028-FR
trojan://humanity@127.0.0.1:40443?path=/assignment&security=tls&insecure=0&fp=chrome&type=ws&allowInsecure=0&sni=www.calmlunch.com#SPOOF-029-FR
vless://bfbc48f0-1781-4f29-9206-6325908bea10@127.0.0.1:40443?&security=tls&fp=firefox&sni=mesh1.mashadiebod.org&type=ws&headerType=none&host=mesh1.mashadiebod.org&path=%2Fmashdi#SPOOF-030-NL
trojan://humanity@127.0.0.1:40443?host=www.multiplydose.com&path=%2Fassignment&sni=www.multiplydose.com&type=ws#SPOOF-031-NL
trojan://humanity@127.0.0.1:40443?host=www.multiplydose.com&path=%2F%252Fassignment&sni=www.multiplydose.com&type=ws#SPOOF-032-NL
vless://cf39fab0-bb85-42cb-9945-2ad69d78e575@127.0.0.1:40443?path=%2FGOrbEh%23TELEGRAM-MARAMBASHI_MARAMBASHI_MARAMBASHI_MARAMBASHI_MARAMBASHI%3Fed%3D512&security=tls&encryption=none&insecure=0&host=rubifen.adaspoloandco.com&fp=chrome&type=ws&allowInsecure=0&sni=rubifen.adaspoloandco.com#SPOOF-033-DE
trojan://humanity@127.0.0.1:40443?path=/assignment&security=tls&insecure=0&host=www.multiplydose.com&fp=chrome&type=ws&allowInsecure=0&sni=www.multiplydose.com#SPOOF-034-NL
trojan://humanity@127.0.0.1:40443?Telegram=@GozargahAzad,@GozargahAzad,@GozargahAzad,@GozargahAzad,@GozargahAzad,@GozargahAzad,@GozargahAzad&path=//assignment&security=tls&insecure=0&host=www.multiplydose.com&type=ws&allowInsecure=0&sni=www.multiplydose.com#SPOOF-035-NL
trojan://humanity@127.0.0.1:40443?path=%2Fassignment&security=tls&insecure=0&ech=ip.gs%2Budp%3A%2F%2F8.8.8.8&type=ws&allowInsecure=0&sni=www.ignitelimit.com#SPOOF-036-FR
trojan://humanity@127.0.0.1:40443?path=/assignment&security=tls&insecure=0&type=ws&allowInsecure=0&sni=www.multiplydose.com#SPOOF-037-NL
trojan://humanity@127.0.0.1:40443?path=/assignment&security=tls&insecure=0&fp=chrome&type=ws&allowInsecure=0&sni=www.multiplydose.com#SPOOF-038-NL
trojan://humanity@127.0.0.1:40443?path=assignment&security=tls&insecure=0&type=ws&allowInsecure=0&sni=www.ignitelimit.com#SPOOF-039-FR
vless://8ad6f598-cd8d-4fca-848e-05fc9be15ff3@127.0.0.1:40443?path=%2Fsea%23TELEGRAM-MARAMBASHI_MARAMBASHI_MARAMBASHI_MARAMBASHI_MARAMBASHI%3Fed%3D512&security=tls&encryption=none&insecure=0&host=deicl.redstone-vex.sbs&type=ws&allowInsecure=0&sni=deicl.redstone-vex.sbs#SPOOF-040-FR
vless://07c87117-8472-41f6-bea8-ddcb012b9b41@127.0.0.1:40443?ed=2048&eh=Sec-WebSocket-Protocol&encryption=none&fp=chrome&host=edge-267487d0.pages.dev&path=%2F&security=tls&sni=edge-267487d0.pages.dev&type=ws#SPOOF-041-SG
vless://4feb7818-dc02-46cd-b985-abf3fdd0cdc5@127.0.0.1:40443?encryption=none&fp=chrome&host=edge-4cb23bf6.pages.dev&path=%2F%40https%3A%2F%2Ft.me%2FQiangLieTuiJian&security=tls&sni=edge-4cb23bf6.pages.dev&type=ws#SPOOF-042-SG
vless://65d3f9b3-d289-4a8e-9c87-90bba156de30@127.0.0.1:40443?encryption=none&host=ld.235231.xyz&path=%2F&security=tls&sni=ld.235231.xyz&type=ws#SPOOF-043-SG
vless://4a1441b0-7bc8-4906-85cf-6b59c256b480@127.0.0.1:40443?encryption=none&fp=chrome&host=edt2.yfqh08811.ccwu.cc&path=%2Ffp%3Dchrome&security=tls&sni=edt2.yfqh08811.ccwu.cc&type=ws#SPOOF-044-JP
vless://4feb7818-dc02-46cd-b985-abf3fdd0cdc5@127.0.0.1:40443?encryption=none&host=edge-4cb23bf6.pages.dev&path=/Telegram%F0%9F%87%A8%F0%9F%87%B3+@WangCai2&security=tls&sni=edge-4cb23bf6.pages.dev&type=ws#SPOOF-045-SG
vless://b08562b0-dbc0-47d1-860d-9435133b25c9@127.0.0.1:40443?path=/QiangLieTuiJian?ed&security=tls&encryption=none&insecure=0&host=cfoo-146.pages.dev&type=ws&allowInsecure=0&sni=cfoo-146.pages.dev#SPOOF-046-JP
vless://eeb6823c-b926-4ea2-866a-5542edd26e59@127.0.0.1:40443?path=%2Ffp&security=tls&encryption=none&insecure=0&host=t1s1.rittbo.kdns.fr&fp=chrome&type=ws&allowInsecure=0&sni=t1s1.rittbo.kdns.fr#SPOOF-047-DE
vless://03707fb7-0990-440f-88f6-b0e0f7242a38@127.0.0.1:40443?&security=tls&fp=chrome&alpn=http%2F1.1&sni=fn-2.ariyuz.org&type=ws&headerType=none&host=fn-2.ariyuz.org&path=%2F#SPOOF-048-FI
vless://eeb6823c-b926-4ea2-866a-5542edd26e59@127.0.0.1:40443?encryption=none&security=tls&sni=t1s1.rittbo.kdns.fr&insecure=0&allowInsecure=0&type=ws&host=t1s1.rittbo.kdns.fr&path=/?TELEGRAM-MARAMBASHI_MARAMBASHI_MARAMBASHI_MARAMBASHI_MARAMBASHI?ed=2048#SPOOF-049-JP
vless://eeb6823c-b926-4ea2-866a-5542edd26e59@127.0.0.1:40443?encryption=none&host=t1s1.rittbo.kdns.fr&path=%2Ffp%3Dchrome&security=tls&sni=t1s1.rittbo.kdns.fr&type=ws#SPOOF-050-JP
vless://cf39fab0-bb85-42cb-9945-2ad69d78e575@127.0.0.1:40443?encryption=none&security=tls&sni=rubifen.adaspoloandco.com&fp=chrome&insecure=0&allowInsecure=0&type=ws&host=rubifen.adaspoloandco.com&path=/GOrbEh#SPOOF-051-DE
trojan://humanity@127.0.0.1:40443?path=/assignment&security=tls&insecure=0&fp=chrome&type=ws&allowInsecure=0&sni=www.ignitelimit.com#SPOOF-052-FR
trojan://humanity@127.0.0.1:40443?path=/assignment&security=tls&alpn=h3,h2,http/1.1&insecure=0&host=www.multiplydose.com&fp=chrome&type=ws&allowInsecure=0&sni=www.multiplydose.com#SPOOF-053-NL
vless://7968c546-02dc-4f8c-b791-934591a94cb2@127.0.0.1:40443?path=/cbasur&security=tls&encryption=none&insecure=0&host=hhvl.hhapp.kdns.fr&type=ws&allowInsecure=0&sni=hhvl.hhapp.kdns.fr#SPOOF-054-US"""
