from pathlib import Path

from PyInstaller.utils.hooks import collect_all

project_root = Path(SPECPATH)
datas = [
    (str(project_root / "morpheus" / "templates"), "morpheus/templates"),
    (str(project_root / "config.json"), "."),
]
binaries = []
hiddenimports = []
hiddenimports.append("morpheus.main")
hiddenimports += ["win32con", "win32file", "win32pipe", "pywintypes"]

for package in (
    "fastapi",
    "starlette",
    "uvicorn",
    "jinja2",
    "multipart",
    "psutil",
    "pydantic",
    "pydantic_core",
):
    package_datas, package_binaries, package_hiddenimports = collect_all(package)
    datas += package_datas
    binaries += package_binaries
    hiddenimports += package_hiddenimports

analysis = Analysis(
    [str(project_root / "backend_entry.py")],
    pathex=[str(project_root)],
    binaries=binaries,
    datas=datas,
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
    name="morpheus-backend",
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
    name="morpheus-backend",
)
