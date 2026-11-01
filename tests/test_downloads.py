from pathlib import Path

from morpheus.database import Database
from morpheus.downloads import DownloadMonitor
from morpheus.integrity import EvidenceJournal


class FakeScanner:
    def __init__(self):
        self.scanned = []

    def scan_file(self, path: Path):
        self.scanned.append(path)
        return {"confidence": 0.8, "reasons": ["high_entropy"], "entropy": 7.5}


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


def test_folder_monitor_scans_new_and_changed_supported_files_in_subfolders(tmp_path):
    watched = tmp_path / "Documents"
    nested = watched / "Projects"
    nested.mkdir(parents=True)
    scanner = FakeScanner()
    database = Database(tmp_path / "events.db")
    monitor = DownloadMonitor(
        scanner,
        FakeQuarantine(),
        database,
        EvidenceJournal(tmp_path / "journal"),
    )
    config = {"download_monitoring": True, "download_directory": str(watched)}
    assert monitor.scan_new_downloads(config) == []

    sample = nested / "report.docx"
    sample.write_bytes(b"first version")
    for _ in range(3):
        monitor.scan_new_downloads(config)
    assert scanner.scanned == [sample]

    sample.write_bytes(b"updated version with new content")
    for _ in range(3):
        monitor.scan_new_downloads(config)
    assert scanner.scanned == [sample, sample]


def test_eicar_test_signature_is_alerted_but_never_auto_quarantined(tmp_path):
    class TestSignatureScanner:
        def scan_file(self, path):
            return {
                "confidence": 0.0,
                "reasons": ["known_test_signature"],
                "signature_matches": [{
                    "id": "eicar-antivirus-test",
                    "name": "EICAR antivirus test file",
                    "classification": "antivirus_test",
                    "description": "Recognized antivirus test content, not a virus.",
                }],
            }

    watched = tmp_path / "Downloads"
    watched.mkdir()
    quarantine = FakeQuarantine()
    monitor = DownloadMonitor(
        TestSignatureScanner(),
        quarantine,
        Database(tmp_path / "events.db"),
        EvidenceJournal(tmp_path / "journal"),
    )
    config = {
        "download_monitoring": True,
        "download_directory": str(watched),
        "automatic_quarantine_downloads": True,
    }
    monitor.scan_new_downloads(config)
    (watched / "eicar.txt").write_text("test", encoding="ascii")
    for _ in range(2):
        assert monitor.scan_new_downloads(config) == []
    events = monitor.scan_new_downloads(config)

    assert [event["kind"] for event in events] == ["download_signature_test"]
    assert events[0]["response"] == "test_signature_detected_review_only"
    assert quarantine.quarantined == []


def test_bulk_high_entropy_file_changes_create_review_only_alert(tmp_path, monkeypatch):
    class HighEntropyScanner:
        def scan_file(self, path):
            return {
                "confidence": 0.0,
                "reasons": [],
                "entropy": 7.5,
                "signature_matches": [],
            }

    watched = tmp_path / "Documents"
    watched.mkdir()
    files = []
    for index in range(25):
        path = watched / f"document-{index}.txt"
        path.write_text("original", encoding="utf-8")
        files.append(path)
    database = Database(tmp_path / "events.db")
    monitor = DownloadMonitor(
        HighEntropyScanner(),
        FakeQuarantine(),
        database,
        EvidenceJournal(tmp_path / "journal"),
    )
    config = {"download_monitoring": True, "download_directory": str(watched)}
    monitor.scan_new_downloads(config)

    for path in files:
        path.write_text("changed and encrypted-looking content", encoding="utf-8")
    for _ in range(3):
        monitor.scan_new_downloads(config)

    events = database.list_events()
    bulk_alerts = [event for event in events if event["kind"] == "bulk_file_change_review"]
    assert len(bulk_alerts) == 1
    assert bulk_alerts[0]["response"] == "review_required_no_automatic_action"


def test_folder_monitor_records_when_file_limit_is_exceeded(tmp_path, monkeypatch):
    import morpheus.downloads as downloads

    watched = tmp_path / "Documents"
    watched.mkdir()
    (watched / "one.txt").write_text("one", encoding="utf-8")
    (watched / "two.txt").write_text("two", encoding="utf-8")
    database = Database(tmp_path / "events.db")
    monitor = DownloadMonitor(
        FakeScanner(),
        FakeQuarantine(),
        database,
        EvidenceJournal(tmp_path / "journal"),
    )
    monkeypatch.setattr(downloads, "MAX_MONITORED_FILES", 1)

    monitor.scan_new_downloads({
        "download_monitoring": True,
        "download_directory": str(watched),
    })

    events = database.list_events()
    assert len(events) == 1
    assert events[0]["kind"] == "folder_monitor_limit"
    assert events[0]["response"] == "folder_monitor_limit"
