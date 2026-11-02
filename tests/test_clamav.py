from types import SimpleNamespace

import pytest

import morpheus.clamav as clamav
from morpheus.clamav import ClamAVScanner
from morpheus.scanner import ProtectedSystemPathError


def _scanner(tmp_path):
    executable = tmp_path / "clamscan.exe"
    executable.write_bytes(b"test executable")
    scanner = ClamAVScanner(executable)
    return scanner


def test_status_reads_engine_and_signature_database_version(tmp_path, monkeypatch):
    scanner = _scanner(tmp_path)
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(
            returncode=0,
            stdout="ClamAV 1.4.3/27900/Mon Nov  2 08:00:00 2026\n",
            stderr="",
        )

    monkeypatch.setattr(clamav.subprocess, "run", run)

    status = scanner.status(force=True)

    assert status["available"] is True
    assert status["engine_version"] == "1.4.3"
    assert status["database_version"] == "27900"
    assert status["database_updated"] == "Mon Nov  2 08:00:00 2026"
    assert status["database_age_days"] is not None
    assert calls == [[str(scanner.executable), "--version"]]


def test_scan_file_parses_clean_and_detected_results(tmp_path, monkeypatch):
    scanner = _scanner(tmp_path)
    target = tmp_path / "sample.exe"
    target.write_bytes(b"sample")
    replies = iter([
        SimpleNamespace(
            returncode=0,
            stdout="ClamAV 1.4.3/27900/Mon Nov  2 08:00:00 2026\n",
            stderr="",
        ),
        SimpleNamespace(returncode=0, stdout=f"{target}: OK\n", stderr=""),
        SimpleNamespace(
            returncode=1,
            stdout=f"{target}: Win.Test.Detection FOUND\n",
            stderr="",
        ),
    ])
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        return next(replies)

    monkeypatch.setattr(clamav.subprocess, "run", run)

    clean = scanner.scan_file(target)
    detected = scanner.scan_file(target)

    assert clean["verdict"] == "clean"
    assert clean["detections"] == []
    assert detected["verdict"] == "infected"
    assert detected["detections"] == ["Win.Test.Detection"]
    assert commands[1][1:3] == ["--stdout", "--no-summary"]


def test_scan_rejects_protected_paths_and_directories(tmp_path, monkeypatch):
    scanner = _scanner(tmp_path)
    monkeypatch.setattr(scanner, "_find_executable", lambda: scanner.executable)
    monkeypatch.setattr(
        clamav.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="ClamAV 1.4.3/27900/Mon Nov  2 08:00:00 2026",
            stderr="",
        ),
    )
    protected = tmp_path / "Windows"
    protected.mkdir()
    protected_file = protected / "system.exe"
    protected_file.write_bytes(b"system")
    monkeypatch.setattr(
        "morpheus.clamav.is_protected_system_path",
        lambda *args, **kwargs: True,
    )

    with pytest.raises(ProtectedSystemPathError):
        scanner.scan_file(protected_file)
    monkeypatch.setattr("morpheus.clamav.is_protected_system_path", lambda *args, **kwargs: False)
    with pytest.raises(ValueError, match="single existing file"):
        scanner.scan_file(protected)


def test_scan_fails_closed_on_ambiguous_clamav_result(tmp_path, monkeypatch):
    scanner = _scanner(tmp_path)
    target = tmp_path / "sample.exe"
    target.write_bytes(b"sample")
    monkeypatch.setattr(scanner, "_find_executable", lambda: scanner.executable)
    replies = iter([
        SimpleNamespace(
            returncode=0,
            stdout="ClamAV 1.4.3/27900/Mon Nov  2 08:00:00 2026",
            stderr="",
        ),
        SimpleNamespace(returncode=0, stdout="", stderr=""),
    ])
    monkeypatch.setattr(clamav.subprocess, "run", lambda *args, **kwargs: next(replies))

    with pytest.raises(RuntimeError, match="conclusive"):
        scanner.scan_file(target)


def test_missing_clamav_is_reported_as_unavailable(tmp_path, monkeypatch):
    scanner = ClamAVScanner(tmp_path / "missing.exe")
    status = scanner.status(force=True)

    assert status["available"] is False
    assert "not installed" in status["message"]


def test_stale_signature_database_is_visible_without_disabling_scans(tmp_path, monkeypatch):
    scanner = _scanner(tmp_path)
    monkeypatch.setattr(
        clamav.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="ClamAV 1.4.3/27900/Mon Nov  2 08:00:00 2000",
            stderr="",
        ),
    )

    status = scanner.status(force=True)

    assert status["available"] is True
    assert status["database_age_days"] > 7
    assert "run FreshClam" in status["message"]


def test_freshclam_update_runs_only_when_explicitly_invoked(tmp_path, monkeypatch):
    scanner = _scanner(tmp_path)
    updater = tmp_path / "freshclam.exe"
    updater.write_bytes(b"test updater")
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if command[0] == str(updater):
            return SimpleNamespace(returncode=0, stdout="Current at database version.", stderr="")
        return SimpleNamespace(
            returncode=0,
            stdout="ClamAV 1.4.3/27900/Mon Nov  2 08:00:00 2026",
            stderr="",
        )

    monkeypatch.setattr(scanner, "_find_updater", lambda: updater)
    monkeypatch.setattr(clamav.subprocess, "run", run)

    result = scanner.update_signatures()

    assert calls[0] == [str(updater), "--stdout"]
    assert result["completed"] is True
    assert result["status"]["available"] is True


def test_freshclam_update_reports_errors_without_a_success_fallback(tmp_path, monkeypatch):
    scanner = _scanner(tmp_path)
    updater = tmp_path / "freshclam.exe"
    updater.write_bytes(b"test updater")
    monkeypatch.setattr(scanner, "_find_updater", lambda: updater)
    monkeypatch.setattr(
        clamav.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="signature database update failed",
        ),
    )

    with pytest.raises(RuntimeError, match="signature database update failed"):
        scanner.update_signatures()
