from pathlib import Path

from morpheus.database import Database
from morpheus.downloads import DownloadMonitor
from morpheus.integrity import EvidenceJournal


class FakeScanner:
    def __init__(self):
        self.scanned = []

    def scan_file(self, path: Path):
        self.scanned.append(path)
        return {"confidence": 0.8, "reasons": ["high_entropy"]}


class FakeQuarantine:
    def __init__(self):
        self.quarantined = []

    def quarantine(self, path: Path):
        self.quarantined.append(path)
        return {"quarantine_path": "isolated/sample.quarantine"}


def test_download_monitor_ignores_existing_and_quarantines_new_suspicious_files(tmp_path):
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    existing = downloads / "already-here.exe"
    existing.write_bytes(b"old")
    scanner = FakeScanner()
    quarantine = FakeQuarantine()
    database = Database(tmp_path / "events.db")
    journal = EvidenceJournal(tmp_path / "journal")
    monitor = DownloadMonitor(scanner, quarantine, database, journal)
    config = {
        "download_monitoring": True,
        "download_directory": str(downloads),
        "download_confidence_threshold": 0.6,
        "automatic_quarantine_downloads": True,
    }

    assert monitor.scan_new_downloads(config) == []
    assert scanner.scanned == []

    new_file = downloads / "new.exe"
    new_file.write_bytes(b"new")
    assert monitor.scan_new_downloads(config) == []
    assert monitor.scan_new_downloads(config) == []
    detections = monitor.scan_new_downloads(config)

    assert len(detections) == 1
    assert detections[0]["kind"] == "download_suspicious"
    assert detections[0]["response"] == "quarantined:isolated/sample.quarantine"
    assert scanner.scanned == [new_file]
    assert quarantine.quarantined == [new_file]
    assert database.list_events()[0]["target"] == "new.exe"


def test_download_monitor_does_nothing_without_explicit_consent(tmp_path):
    scanner = FakeScanner()
    monitor = DownloadMonitor(
        scanner,
        FakeQuarantine(),
        Database(tmp_path / "events.db"),
        EvidenceJournal(tmp_path / "journal"),
    )

    assert monitor.scan_new_downloads({"download_monitoring": False}) == []
    assert scanner.scanned == []


def test_download_monitor_never_scans_a_protected_system_directory(tmp_path, monkeypatch):
    protected = tmp_path / "Windows"
    protected.mkdir()
    (protected / "new.exe").write_bytes(b"system")
    scanner = FakeScanner()
    monitor = DownloadMonitor(
        scanner,
        FakeQuarantine(),
        Database(tmp_path / "events.db"),
        EvidenceJournal(tmp_path / "journal"),
    )
    monkeypatch.setattr("morpheus.scanner.protected_system_roots", lambda: [protected])

    assert monitor.scan_new_downloads({
        "download_monitoring": True,
        "download_directory": str(protected),
    }) == []
    assert scanner.scanned == []
