import json
import logging
from pathlib import Path

from .collector import utcnow
from .scanner import StaticScanner, is_protected_system_path

LOGGER = logging.getLogger(__name__)
DOWNLOAD_EXTENSIONS = {
    ".exe", ".msi", ".dll", ".scr", ".com", ".bat", ".cmd",
    ".ps1", ".js", ".vbs", ".hta", ".jar",
}

class DownloadMonitor:
    def __init__(self, scanner: StaticScanner, quarantine, database, journal):
        self.scanner = scanner
        self.quarantine = quarantine
        self.database = database
        self.journal = journal
        self._observed: dict[Path, tuple[int, int, int]] = {}
        self._known: set[Path] = set()
        self._initialized_roots: set[Path] = set()
        self._warned_protected_roots: set[Path] = set()

    def scan_new_downloads(self, config: dict) -> list[dict]:
        if not config.get("download_monitoring", False):
            return []

        root = Path(config.get("download_directory") or Path.home() / "Downloads").expanduser()
        try:
            root = root.resolve(strict=True)
        except (FileNotFoundError, OSError):
            return []
        if is_protected_system_path(root):
            if root not in self._warned_protected_roots:
                LOGGER.warning("Downloads monitoring will not inspect protected system directory %s", root)
                self._warned_protected_roots.add(root)
            return []
        if not root.is_dir():
            return []

        if root not in self._initialized_roots:
            self._known.update(path.resolve() for path in root.iterdir() if path.is_file())
            self._initialized_roots.add(root)

        detections = []
        try:
            paths = tuple(root.iterdir())
        except OSError:
            LOGGER.exception("Unable to inspect Downloads folder %s", root)
            return detections

        for path in paths:
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                resolved = path.resolve(strict=True)
                if resolved in self._known:
                    continue
                if resolved.suffix.lower() not in DOWNLOAD_EXTENSIONS:
                    continue

                stat = resolved.stat()
                signature = (stat.st_size, stat.st_mtime_ns)
                previous = self._observed.get(resolved)
                stable_checks = previous[2] + 1 if previous and previous[:2] == signature else 0
                self._observed[resolved] = (*signature, stable_checks)
                if stable_checks < 2:
                    continue
                self._known.add(resolved)
                self._observed.pop(resolved, None)

                try:
                    result = self.scanner.scan_file(resolved)
                except ValueError as exc:
                    self._record(resolved, 0.0, [str(exc)], f"download_scan_skipped:{exc}")
                    continue
                except (OSError, PermissionError) as exc:
                    self._record(resolved, 0.0, [str(exc)], f"download_scan_failed:{exc}")
                    continue

                threshold = config.get("download_confidence_threshold", 0.60)
                if result["confidence"] < threshold:
                    continue

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
                    "source": "Downloads folder",
                    "target": resolved.name,
                    "confidence": result["confidence"],
                    "evidence": json.dumps(result["reasons"]),
                    "response": response,
                }
                self.database.add(event)
                self.journal.append(event)
                detections.append(event)
            except FileNotFoundError:
                continue
            except OSError:
                LOGGER.exception("Unable to inspect download %s", path)
        return detections

    def _record(self, path: Path, confidence: float, reasons: list[str], response: str):
        event = {
            "timestamp": utcnow(),
            "kind": "download_scan_error",
            "severity": "low",
            "source": "Downloads folder",
            "target": path.name,
            "confidence": confidence,
            "evidence": json.dumps(reasons),
            "response": response,
        }
        self.database.add(event)
        self.journal.append(event)
