import io
import zipfile
from types import SimpleNamespace

import py7zr
import pyzipper

from morpheus.scanner import SCAN_CHUNK_SIZE, StaticScanner
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


def test_static_scanner_detects_local_antivirus_test_signature_across_chunks():
    signature = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    content = b"A" * (SCAN_CHUNK_SIZE - 8) + signature

    result = StaticScanner().scan_bytes(content, "sample.txt")

    assert result["signature_matches"] == [{
        "id": "eicar-antivirus-test",
        "name": "EICAR antivirus test file",
        "classification": "antivirus_test",
        "description": "Recognized antivirus test content, not a virus.",
    }]
    assert "known_test_signature" in result["reasons"]


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


def test_folder_scan_is_bounded_and_reports_truncation(tmp_path, monkeypatch):
    for name in ("first.txt", "second.txt"):
        (tmp_path / name).write_text(name, encoding="utf-8")
    monkeypatch.setattr("morpheus.scanner.MAX_FOLDER_SCAN_FILES", 1)
    monkeypatch.setattr("morpheus.scanner.protected_system_roots", lambda: [])

    result = StaticScanner().scan_folder(tmp_path)

    assert len(result["results"]) == 1
    assert result["truncated"] is True


def test_static_scanner_enforces_configurable_file_limit(tmp_path):
    sample = tmp_path / "large.bin"
    sample.write_bytes(b"12345")

    try:
        StaticScanner().scan_file(sample, max_bytes=4)
    except ValueError as exc:
        assert "scan limit" in str(exc)
    else:
        raise AssertionError("The configurable file limit was not enforced")


def test_static_scanner_supports_cancelled_stream():
    class OneChunkStream:
        def read(self, size):
            return b"x" * size

    try:
        StaticScanner().scan_stream(
            OneChunkStream(),
            "cancelled.bin",
            is_cancelled=lambda: True,
        )
    except InterruptedError as exc:
        assert "cancelled" in str(exc)
    else:
        raise AssertionError("Cancellation was not propagated")

def test_zip_scan_streams_plaintext_entries_without_extracting(tmp_path):
    archive_path = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("payload.txt", b"powershell.exe")

    result = StaticScanner().scan_zip(archive_path, "")

    assert result["entries_scanned"] == 1
    assert result["encrypted_entries"] == 0
    assert "suspicious_native_marker" in result["results"][0]["reasons"]
    assert not (tmp_path / "payload.txt").exists()
    assert "not saved or executed" in result["message"]

def test_zip_scan_requires_owner_password_and_rejects_bad_password(tmp_path, monkeypatch):
    archive_path = tmp_path / "encrypted.zip"
    archive_path.write_bytes(b"synthetic test archive")
    member = SimpleNamespace(
        filename="payload.txt",
        file_size=6,
        flag_bits=0x1,
        compress_type=0,
        is_dir=lambda: False,
    )

    class FakeArchive:
        def __init__(self, path):
            assert str(path).endswith(".zip")

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return exc_type is None and exc_value is None and traceback is None

        def infolist(self):
            return [member]

        def open(self, info, *, pwd):
            assert info is member
            if pwd != b"owner-secret":
                raise RuntimeError("Bad password for file")
            return io.BytesIO(b"sample")

    monkeypatch.setattr("morpheus.scanner.pyzipper.AESZipFile", FakeArchive)
    scanner = StaticScanner()

    try:
        scanner.scan_zip(archive_path, "")
    except ValueError as exc:
        assert "Enter the archive password" in str(exc)
    else:
        raise AssertionError("Encrypted entries must require an owner-supplied password")

    try:
        scanner.scan_zip(archive_path, "wrong")
    except ValueError as exc:
        assert "could not decrypt" in str(exc)
    else:
        raise AssertionError("An incorrect password must fail clearly")

    result = scanner.scan_zip(archive_path, "owner-secret")
    assert result["encrypted_entries"] == 1
    assert result["entries_scanned"] == 1

def test_zip_scan_enforces_uncompressed_entry_limit(tmp_path):
    archive_path = tmp_path / "large-entry.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("payload.txt", b"12345")

    try:
        StaticScanner().scan_zip(archive_path, "", max_file_bytes=4)
    except ValueError as exc:
        assert "file limit" in str(exc)
    else:
        raise AssertionError("ZIP entry size limit was not enforced")

def test_zip_scan_supports_aes_encrypted_archives(tmp_path):
    archive_path = tmp_path / "aes.zip"
    with pyzipper.AESZipFile(
        str(archive_path),
        "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as archive:
        archive.setpassword(b"owner-secret")
        archive.writestr("payload.txt", b"powershell.exe")

    result = StaticScanner().scan_zip(archive_path, "owner-secret")

    assert result["encrypted_entries"] == 1
    assert "suspicious_native_marker" in result["results"][0]["reasons"]

    try:
        StaticScanner().scan_zip(archive_path, "wrong-password")
    except ValueError as exc:
        assert "could not decrypt" in str(exc)
    else:
        raise AssertionError("An incorrect ZIP password must fail clearly")

def test_7z_scan_decrypts_into_bounded_memory_and_checks_entries(tmp_path):
    source_directory = tmp_path / "source"
    source_directory.mkdir()
    source = source_directory / "payload.txt"
    source.write_bytes(b"powershell.exe")
    archive_path = tmp_path / "sample.7z"
    with py7zr.SevenZipFile(archive_path, "w", password="owner-secret") as archive:
        archive.write(source, arcname="payload.txt")

    result = StaticScanner().scan_7z(archive_path, "owner-secret")

    assert result["entries_scanned"] == 1
    assert result["encrypted_entries"] == 1
    assert "suspicious_native_marker" in result["results"][0]["reasons"]
    assert "not written to disk" in result["message"]
    assert not (tmp_path / "payload.txt").exists()

    try:
        StaticScanner().scan_7z(archive_path, "wrong-password")
    except ValueError as exc:
        assert "password is incorrect" in str(exc)
    else:
        raise AssertionError("An incorrect 7z password must fail clearly")

def test_7z_scan_handles_unencrypted_entries_and_enforces_memory_limit(tmp_path):
    source = tmp_path / "plain.txt"
    source.write_bytes(b"sample-data")
    archive_path = tmp_path / "plain.7z"
    with py7zr.SevenZipFile(archive_path, "w") as archive:
        archive.write(source, arcname="plain.txt")

    result = StaticScanner().scan_7z(archive_path, "")

    assert result["entries_scanned"] == 1
    assert result["encrypted_entries"] == 0

    try:
        StaticScanner().scan_7z(archive_path, "", max_total_bytes=4)
    except ValueError as exc:
        assert "bounded in-memory" in str(exc)
    else:
        raise AssertionError("7z expanded-size limits must be enforced")

def test_folder_scan_reports_cancellation_instead_of_a_per_file_failure(tmp_path, monkeypatch):
    sample = tmp_path / "sample.txt"
    sample.write_text("sample", encoding="utf-8")
    monkeypatch.setattr("morpheus.scanner.protected_system_roots", lambda: [])
    result = StaticScanner().scan_folder(
        tmp_path,
        is_cancelled=lambda: True,
    )

    assert result["truncated"] is True
    assert result["failures"] == [
        {"name": str(tmp_path), "message": "Scan was cancelled."}
    ]
