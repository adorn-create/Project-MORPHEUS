import ctypes
import hashlib
import os
import math
import struct
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
    b"mimikatz",
    b"frombase64string",
    b"invoke-mimikatz",
    b"lsass.exe",
    b"secretsdump",
    b"procdump",
)

EXECUTABLE_PROTECTIONS = 0x10 | 0x20 | 0x40 | 0x80


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts if count)


def _inspect_pe(path: Path, size: int) -> dict:
    findings = {"is_pe": False, "sections": [], "high_entropy_sections": [], "rwx_sections": [], "suspicious": []}
    try:
        with path.open("rb") as stream:
            header = stream.read(4096)
            if len(header) < 64 or header[:2] != b"MZ":
                return findings
            pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
            stream.seek(pe_offset)
            pe_signature = stream.read(4)
            if pe_signature != b"PE\0\0":
                return findings
            if pe_offset + 24 > size:
                return findings
            stream.seek(pe_offset + 4)
            coff = stream.read(20)
            if len(coff) < 20:
                return findings
            machine, section_count, _, _, _, optional_size, characteristics = struct.unpack_from("<HHIIIHH", coff)
            findings["is_pe"] = True
            findings["machine"] = hex(machine)
            findings["characteristics"] = hex(characteristics)
            stream.seek(pe_offset + 24 + optional_size)
            for index in range(min(section_count, 96)):
                raw_header = stream.read(40)
                if len(raw_header) < 40:
                    break
                name = raw_header[:8].split(b"\0", 1)[0].decode("ascii", errors="replace")
                virtual_address = struct.unpack_from("<I", raw_header, 12)[0]
                raw_size = struct.unpack_from("<I", raw_header, 16)[0]
                raw_offset = struct.unpack_from("<I", raw_header, 20)[0]
                flags = struct.unpack_from("<I", raw_header, 36)[0]
                executable = bool(flags & 0x20000000)
                writable = bool(flags & 0x80000000)
                sample_size = min(raw_size, 1024 * 1024)
                stream.seek(raw_offset)
                section_data = stream.read(sample_size)
                entropy = _entropy(section_data)
                section = {
                    "name": name or f".section{index}",
                    "virtual_address": hex(virtual_address),
                    "raw_size": raw_size,
                    "entropy": round(entropy, 3),
                    "executable": executable,
                    "writable": writable,
                }
                findings["sections"].append(section)
                if entropy >= 7.2 and len(section_data) >= 1024:
                    findings["high_entropy_sections"].append(section["name"])
                if executable and writable:
                    findings["rwx_sections"].append(section["name"])
            if findings["rwx_sections"]:
                findings["suspicious"].append("writable_executable_sections")
            return findings
    except (OSError, ValueError, struct.error):
        return findings


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

            executable_pages = executable_pages or bool(mbi.Protect & EXECUTABLE_PROTECTIONS)
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
        pe_findings = _inspect_pe(executable, size)
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
            "pe": pe_findings,
        }
    except (OSError, ValueError, psutil.AccessDenied):
        return {"available": False, "reason": "executable contents access denied or unavailable"}
