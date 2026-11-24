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
    ('core/aether/SOURCE.json', 'licenses/aether'),
    ('core/aether/LICENSE', 'licenses/aether'),
    ('core/quiche/COPYING', 'licenses/quiche'),
    ('bin/keyfetch-net.ps1', 'bin'),
    ('bin/uac-psiphon.exe', 'bin'),
    ('bin/uac-pow-guard.exe', 'bin'),
    ('bin/uac-direct.exe', 'bin'),
    ('bin/uac-direct-xray.exe', 'bin'),
    ('bin/uac-direct-xray-LICENSE', 'licenses/direct-xray'),
    ('bin/uac-direct-mask.exe', 'bin'),
    ('bin/uac-direct-guard.exe', 'bin'),
    ('core/direct/SOURCE.json', 'licenses/direct'),
    ('core/direct/LICENSE', 'licenses/direct'),
    ('core/direct/BYEDPI-LICENSE', 'licenses/direct'),

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

