from morpheus.scanner import StaticScanner
from morpheus.scanner import ProtectedSystemPathError

def test_static_scanner(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + b"A" * 4096)
    result = StaticScanner().scan_file(sample)
    assert result["sha256"]
    assert result["size"] == 4098
    assert "executable_or_script_type" in result["reasons"]


def test_static_scanner_reads_large_files_and_checks_markers_past_100_mb(tmp_path):
    sample = tmp_path / "large.bin"
    with sample.open("wb") as stream:
        stream.seek(100 * 1024 * 1024)
        stream.write(b"powershell.exe")

    result = StaticScanner().scan_file(sample)

    assert result["size"] > 100 * 1024 * 1024
    assert "suspicious_native_marker" in result["reasons"]


def test_static_scanner_reads_large_stream_without_loading_it_all():
    class LargeStream:
        def __init__(self):
            self.remaining = 100 * 1024 * 1024 + len(b"powershell.exe")

        def read(self, size):
            if not self.remaining:
                return b""
            length = min(size, self.remaining)
            self.remaining -= length
            if not self.remaining:
                return b"powershell.exe"
            return b"x" * length

    result = StaticScanner().scan_stream(LargeStream(), "large.bin")

    assert result["size"] == 100 * 1024 * 1024 + len(b"powershell.exe")
    assert "suspicious_native_marker" in result["reasons"]


def test_static_scanner_rejects_protected_system_paths(tmp_path, monkeypatch):
    protected = tmp_path / "Windows"
    protected.mkdir()
    sample = protected / "system.exe"
    sample.write_bytes(b"MZ")
    monkeypatch.setattr("morpheus.scanner.protected_system_roots", lambda: [protected])

    try:
        StaticScanner().scan_file(sample)
    except ProtectedSystemPathError as exc:
        assert "excluded" in str(exc)
    else:
        raise AssertionError("A protected system file was scanned")


def test_static_scanner_reads_each_file_once(tmp_path, monkeypatch):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + b"A" * 4096)
    original_open = type(sample).open
    reads = []

    def tracked_open(path, *args, **kwargs):
        if path == sample:
            reads.append(path)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(type(sample), "open", tracked_open)

    result = StaticScanner().scan_file(sample)

    assert result["size"] == sample.stat().st_size
    assert reads == [sample]


def test_folder_scan_skips_protected_system_subfolders(tmp_path, monkeypatch):
    protected = tmp_path / "System Volume Information"
    protected.mkdir()
    (protected / "system.bin").write_bytes(b"system")
    user_folder = tmp_path / "Documents"
    user_folder.mkdir()
    (user_folder / "notes.txt").write_text("user file", encoding="utf-8")
    monkeypatch.setattr("morpheus.scanner.protected_system_roots", lambda: [])

    result = StaticScanner().scan_folder(tmp_path)

    assert result["skipped_system_paths"] == 1
    assert [item["path"] for item in result["results"]] == [str(user_folder / "notes.txt")]


def test_folder_scan_skips_system_files_at_drive_root(tmp_path, monkeypatch):
    protected_file = tmp_path / "pagefile.sys"
    protected_file.write_bytes(b"system")
    user_file = tmp_path / "notes.txt"
    user_file.write_text("user file", encoding="utf-8")
    monkeypatch.setattr("morpheus.scanner.protected_system_roots", lambda: [])

    result = StaticScanner().scan_folder(tmp_path)

    assert result["skipped_system_paths"] == 1
    assert [item["path"] for item in result["results"]] == [str(user_file)]
