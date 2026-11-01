import json
import logging
import os
import time
from pathlib import Path

from .collector import utcnow
from . import scanner as scanner_module
from .scanner import StaticScanner, is_protected_system_path

LOGGER = logging.getLogger(__name__)
MONITORED_FILE_EXTENSIONS = {
    ".exe", ".msi", ".dll", ".scr", ".com", ".bat", ".cmd",
    ".ps1", ".js", ".vbs", ".hta", ".jar", ".doc", ".docx", ".xls",
    ".xlsx", ".ppt", ".pptx", ".pdf", ".rtf", ".odt", ".ods", ".odp",
    ".txt", ".csv", ".jpg", ".jpeg", ".png", ".zip", ".7z", ".rar",
}
MAX_MONITORED_FILES = 5000
BULK_CHANGE_WINDOW_SECONDS = 60
BULK_CHANGE_FILE_THRESHOLD = 25
BULK_CHANGE_HIGH_ENTROPY_THRESHOLD = 5

class DownloadMonitor:
    def __init__(self, scanner: StaticScanner, quarantine, database, journal):
        self.scanner = scanner
        self.quarantine = quarantine
        self.database = database
        self.journal = journal
        self._observed: dict[Path, tuple[int, int, int]] = {}
        self._known: dict[Path, tuple[int, int]] = {}
        self._initialized_roots: set[Path] = set()
        self._warned_protected_roots: set[Path] = set()
        self._recent_changes: dict[Path, tuple[float, float]] = {}
        self._last_bulk_alert_at: float | None = None
        self._warned_monitor_limits: set[Path] = set()

    def scan_new_downloads(self, config: dict) -> list[dict]:
        if not config.get("download_monitoring", False):
            return []

        root = Path(config.get("download_directory") or Path.home() / "Downloads").expanduser()
        try:
            root = root.resolve(strict=True)
        except (FileNotFoundError, OSError):
            return []
        if root == Path(root.anchor) or is_protected_system_path(root):
            if root not in self._warned_protected_roots:
                LOGGER.warning("Folder monitoring will not inspect a drive root or protected system directory %s", root)
                self._warned_protected_roots.add(root)
            return []
        if not root.is_dir():
            return []

        detections = []
        paths, limit_reached = self._folder_files(root)
        if limit_reached and root not in self._warned_monitor_limits:
            LOGGER.warning(
                "Folder monitoring is limited to %d supported files per check in %s",
                MAX_MONITORED_FILES,
                root,
            )
            self._record(
                root,
                0.0,
                [f"Monitoring is limited to {MAX_MONITORED_FILES} supported files per check."],
                "folder_monitor_limit",
            )
            self._warned_monitor_limits.add(root)
        if root not in self._initialized_roots:
            for path in paths:
                try:
                    stat = path.stat()
                    self._known[path] = (stat.st_size, stat.st_mtime_ns)
                except OSError:
                    LOGGER.exception("Unable to establish folder-monitor baseline for %s", path)
            self._initialized_roots.add(root)
            return detections

        for path in paths:
            try:
                resolved = path.resolve(strict=True)
                stat = resolved.stat()
                signature = (stat.st_size, stat.st_mtime_ns)
                if resolved.suffix.lower() not in MONITORED_FILE_EXTENSIONS:
                    continue
                known_signature = self._known.get(resolved)
                if known_signature == signature:
                    continue
                previous = self._observed.get(resolved)
                stable_checks = previous[2] + 1 if previous and previous[:2] == signature else 0
                self._observed[resolved] = (*signature, stable_checks)
                if stable_checks < 2:
                    continue
                self._known[resolved] = signature
                self._observed.pop(resolved, None)

                try:
                    result = self.scanner.scan_file(resolved)
                except ValueError as exc:
                    self._record(resolved, 0.0, [str(exc)], f"download_scan_skipped:{exc}")
                    continue
                except (OSError, PermissionError) as exc:
                    self._record(resolved, 0.0, [str(exc)], f"download_scan_failed:{exc}")
                    continue

                signature_matches = result.get("signature_matches", [])
                if signature_matches:
                    event = {
                        "timestamp": utcnow(),
                        "kind": "download_signature_test",
                        "severity": "low",
                        "source": "Selected folder",
                        "target": resolved.name,
                        "confidence": 0.0,
                        "evidence": json.dumps(signature_matches),
                        "response": "test_signature_detected_review_only",
                    }
                    self._write_event(event)
                    detections.append(event)

                threshold = config.get("download_confidence_threshold", 0.60)
                if not signature_matches and result["confidence"] >= threshold:
                    response = "flagged_pending_review"
                    if config.get("automatic_quarantine_downloads", False):
                        try:
                            quarantined = self.quarantine.quarantine(resolved)
                            response = f"quarantined:{quarantined['quarantine_path']}"
                        except (OSError, FileNotFoundError) as exc:
                            response = f"quarantine_failed:{exc}"
                            LOGGER.exception("Unable to quarantine flagged download %s", resolved)

                    event = {
                        "timestamp": utcnow(),
                        "kind": "download_suspicious",
                        "severity": "high" if result["confidence"] >= 0.70 else "medium",
                        "source": "Selected folder",
                        "target": resolved.name,
                        "confidence": result["confidence"],
                        "evidence": json.dumps(result["reasons"]),
                        "response": response,
                    }
                    self._write_event(event)
                    detections.append(event)

                self._observe_bulk_change(resolved, result, detections)
            except FileNotFoundError:
                continue
            except OSError:
                LOGGER.exception("Unable to inspect download %s", path)
        return detections

    def _folder_files(self, root: Path) -> tuple[list[Path], bool]:
        files = []
        system_roots = scanner_module.protected_system_roots()

        def record_walk_error(error: OSError) -> None:
            LOGGER.warning("Unable to inspect monitored folder path %s: %s", error.filename or root, error)

        for current, directories, filenames in os.walk(
            root, followlinks=False, onerror=record_walk_error
        ):
            current_path = Path(current)
            retained = []
            for directory in directories:
                candidate = current_path / directory
                if self._is_link_or_junction(candidate) or is_protected_system_path(
                    candidate, protected_roots=system_roots, resolve=False
                ):
                    continue
                retained.append(directory)
            directories[:] = retained
            for filename in filenames:
                candidate = current_path / filename
                if candidate.suffix.lower() not in MONITORED_FILE_EXTENSIONS:
                    continue
                if self._is_link_or_junction(candidate) or is_protected_system_path(
                    candidate, protected_roots=system_roots, resolve=False
                ):
                    continue
                files.append(candidate)
                if len(files) > MAX_MONITORED_FILES:
                    return files[:MAX_MONITORED_FILES], True
        return files, False

    @staticmethod
    def _is_link_or_junction(path: Path) -> bool:
        return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())

    def _observe_bulk_change(self, path: Path, result: dict, detections: list[dict]) -> None:
        now = time.monotonic()
        self._recent_changes[path] = (now, result.get("entropy", 0.0))
        self._recent_changes = {
            changed_path: observation
            for changed_path, observation in self._recent_changes.items()
            if now - observation[0] <= BULK_CHANGE_WINDOW_SECONDS
        }
        high_entropy_changes = sum(
            entropy >= 7.0 for _, entropy in self._recent_changes.values()
        )
        if (
            len(self._recent_changes) < BULK_CHANGE_FILE_THRESHOLD
            or high_entropy_changes < BULK_CHANGE_HIGH_ENTROPY_THRESHOLD
            or (
                self._last_bulk_alert_at is not None
                and now - self._last_bulk_alert_at < BULK_CHANGE_WINDOW_SECONDS
            )
        ):
            return

        event = {
            "timestamp": utcnow(),
            "kind": "bulk_file_change_review",
            "severity": "medium",
            "source": "Selected folder",
            "target": path.parent.name or str(path.parent),
            "confidence": None,
            "evidence": json.dumps({
                "changed_files_in_window": len(self._recent_changes),
                "high_entropy_files": high_entropy_changes,
                "window_seconds": BULK_CHANGE_WINDOW_SECONDS,
            }),
            "response": "review_required_no_automatic_action",
        }
        self._write_event(event)
        detections.append(event)
        self._last_bulk_alert_at = now

    def _write_event(self, event: dict) -> None:
        self.database.add(event)
        self.journal.append(event)

    def _record(self, path: Path, confidence: float, reasons: list[str], response: str):
        kind = "folder_monitor_limit" if response == "folder_monitor_limit" else "download_scan_error"
        event = {
            "timestamp": utcnow(),
            "kind": kind,
            "severity": "low",
            "source": "Selected folder",
            "target": path.name or str(path),
            "confidence": confidence,
            "evidence": json.dumps(reasons),
            "response": response,
        }
        self._write_event(event)
