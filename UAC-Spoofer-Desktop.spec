# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_data_files

datas = [('assets', 'assets'), ('bin', 'bin'),
         ('third_party/patterniha_sni_spoofing', 'third_party/patterniha_sni_spoofing')]
datas += collect_data_files('pydivert.windivert_dll')

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'kivy', 'kivymd', 'pygame', 'arcade', 'playwright'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='UAC-Spoofer-Desktop',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    icon='assets/icon.png',
    # Start unelevated so main.py can restore a stale HKCU proxy before the
    # UAC prompt. main.py then relaunches the foreground app as administrator
    # for WinDivert.
    uac_admin=False,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='UAC-Spoofer-Desktop',
)
