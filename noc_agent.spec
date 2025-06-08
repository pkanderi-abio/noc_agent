python
# -*- mode: python ; coding: utf-8 -*-
block_cipher = None

from PyInstaller.__main__ import run

# Analysis
a = Analysis(
    ['agent/agent.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['scapy.all', 'nmap', 'pyshark'],
    hookspath=[],
    runtime_hooks=[],
    excludes=[]
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='noc_agent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    name='noc_agent'
)