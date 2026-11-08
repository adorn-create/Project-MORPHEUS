import struct

from morpheus.process_inspection import _inspect_pe, inspect_executable


def test_pe_parser_detects_writable_executable_section(tmp_path):
    path = tmp_path / "sample.exe"
    pe_offset = 128
    content = bytearray(max(pe_offset + 24 + 20 + 40 + 1024, 2048))
    content[:2] = b"MZ"
    struct.pack_into("<I", content, 0x3C, pe_offset)
    content[pe_offset:pe_offset + 4] = b"PE\0\0"
    # COFF: machine, sections, timestamps, symbols, symbol size, optional size, characteristics
    struct.pack_into("<HHIIIHH", content, pe_offset + 4, 0x8664, 1, 0, 0, 0, 0, 0x0102)
    section_offset = pe_offset + 24
    section = content[section_offset:section_offset + 40]
    section[:8] = b".test\0\0\0\0"
    struct.pack_into("<I", section, 12, 0x1000)
    struct.pack_into("<I", section, 16, 1024)
    struct.pack_into("<I", section, 20, 1024)
    struct.pack_into("<I", section, 36, 0x20000000 | 0x80000000)
    content[section_offset:section_offset + 40] = section
    content[1024:1024 + 1024] = b"\0" * 1024
    path.write_bytes(content)

    result = _inspect_pe(path, path.stat().st_size)

    assert result["is_pe"] is True
    assert result["rwx_sections"] == [".test"]
    assert "writable_executable_sections" in result["suspicious"]


def test_inspect_executable_returns_sha256_and_pe(tmp_path):
    path = tmp_path / "plain.bin"
    path.write_bytes(b"plain executable contents")

    result = inspect_executable(str(path))

    assert result["available"] is True
    assert len(result["sha256"]) == 64
    assert result["pe"]["is_pe"] is False
