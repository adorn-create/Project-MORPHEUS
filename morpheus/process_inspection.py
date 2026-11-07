import ctypes
import hashlib
import os
from pathlib import Path

import psutil


PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
MAX_MEMORY_BYTES_PER_PROCESS = 16 * 1024 * 1024
MAX_MEMORY_CHUNK = 64 * 1024

_MEMORY_MARKERS = (
    b"virtualallocex",
    b"writeprocessmemory",
    b"createremotethread",
    b"powershell.exe",
    b"mimikatz",
    b"frombase64string",
)


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]


def is_elevated() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def capability_status() -> dict:
    elevated = is_elevated()
    return {
        "elevated": elevated,
        "memory_inspection": os.name == "nt",
        "executable_inspection": True,
        "memory_access_mode": "SeDebug/token-dependent Windows user mode" if not elevated else "elevated Windows process access",
        "limitation": (
            "Protected processes, PPL processes, access-denied regions, and transient contents may remain inaccessible."
        ),
    }


def _read_process_memory(pid: int, markers=_MEMORY_MARKERS) -> dict:
    if os.name != "nt":
        return {"available": False, "reason": "Windows-only process memory inspection"}

    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        return {"available": False, "reason": "process access denied"}

    try:
        address = 0
        read_bytes = 0
        matched = set()
        executable_pages = False
        mbi = MEMORY_BASIC_INFORMATION()
        while read_bytes < MAX_MEMORY_BYTES_PER_PROCESS:
            if kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
                break
            if mbi.State != MEM_COMMIT or mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD):
                address += mbi.RegionSize or 0x1000
                continue

            executable_pages = executable_pages or bool(mbi.Protect & 0xF0)
            remaining = MAX_MEMORY_BYTES_PER_PROCESS - read_bytes
            region_size = min(mbi.RegionSize, remaining)
            offset = 0
            while offset < region_size and read_bytes < MAX_MEMORY_BYTES_PER_PROCESS:
                chunk_size = min(MAX_MEMORY_CHUNK, region_size - offset, MAX_MEMORY_BYTES_PER_PROCESS - read_bytes)
                buffer = ctypes.create_string_buffer(chunk_size)
                bytes_read = ctypes.c_size_t()
                ok = kernel32.ReadProcessMemory(
                    handle,
                    ctypes.c_void_p(address + offset),
                    buffer,
                    chunk_size,
                    ctypes.byref(bytes_read),
                )
                if ok and bytes_read.value:
                    lower = buffer.raw[:bytes_read.value].lower()
                    matched.update(marker.decode("ascii") for marker in markers if marker in lower)
                    read_bytes += bytes_read.value
                offset += max(chunk_size, 1)
                if not ok:
                    break
            address += mbi.RegionSize or 0x1000
        return {
            "available": True,
            "bytes_read": read_bytes,
            "executable_pages_observed": executable_pages,
            "markers": sorted(matched),
        }
    finally:
        kernel32.CloseHandle(handle)


def inspect_executable(path: str | None, max_bytes: int = 32 * 1024 * 1024) -> dict:
    if not path:
        return {"available": False, "reason": "executable path unavailable"}
    try:
        executable = Path(path)
        size = executable.stat().st_size
        if size > max_bytes:
            return {"available": True, "size": size, "scanned_bytes": 0, "sha256": None, "reason": "executable exceeds inspection limit"}
        digest = hashlib.sha256()
        marker_matches = set()
        scanned = 0
        with executable.open("rb") as stream:
            while scanned < size:
                chunk = stream.read(min(1024 * 1024, size - scanned))
                if not chunk:
                    break
                digest.update(chunk)
                lower = chunk.lower()
                marker_matches.update(marker.decode("ascii") for marker in _MEMORY_MARKERS if marker in lower)
                scanned += len(chunk)
        return {
            "available": True,
            "size": size,
            "scanned_bytes": scanned,
            "sha256": digest.hexdigest(),
            "markers": sorted(marker_matches),
        }
    except (OSError, ValueError, psutil.AccessDenied):
        return {"available": False, "reason": "executable contents access denied or unavailable"}

