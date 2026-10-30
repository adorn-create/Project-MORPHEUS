from pathlib import Path

project_root = Path(SPECPATH)
hiddenimports = [
    "morpheus.firewall",
    "morpheus.firewall_worker",
    "pywintypes",
    "win32con",
    "win32event",
    "win32file",
    "win32pipe",
    "win32security",
    "win32service",
    "win32serviceutil",
    "win32timezone",
    "winerror",
]

analysis = Analysis(
    [str(project_root / "firewall_worker_entry.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pip", "pytest", "setuptools"],
    noarchive=False,
)
pyz = PYZ(analysis.pure)
executable = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="morpheus-firewall-worker",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
)
COLLECT(
    executable,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=True,
    name="morpheus-firewall-worker",
)
