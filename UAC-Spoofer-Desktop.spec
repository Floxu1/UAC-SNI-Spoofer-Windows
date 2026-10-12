from PyInstaller.utils.hooks import collect_data_files, collect_submodules

datas = [
    ('assets', 'assets'),

    ('bin/xray.exe', 'bin'),
    ('bin/geoip.dat', 'bin'),
    ('bin/geosite.dat', 'bin'),

    ('bin/sing-box.exe', 'bin'),
    ('bin/libcronet.dll', 'bin'),
    ('bin/sing-box-LICENSE', 'bin'),

    ('bin/aether.exe', 'bin'),
    ('bin/uac-psiphon.exe', 'bin'),

    ('wizard guider', 'wizard guider'),
    (
        'third_party/patterniha_sni_spoofing',
        'third_party/patterniha_sni_spoofing',
    ),
]
datas += collect_data_files('pydivert.windivert_dll')

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=collect_submodules('dns'),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter', 'kivy', 'kivymd', 'pygame', 'arcade', 'playwright',
        'numpy', 'matplotlib', 'IPython', 'pytest', 'PIL', 'cryptography',
        'bcrypt', 'pygments', 'jedi',
    ],
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
    upx=False,
    console=False,
    icon='assets/icon.png',
    uac_admin=True,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='UAC-Spoofer-Desktop',
)

