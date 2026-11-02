import logging
import os
import threading
import time
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from .downloads import MONITORED_FILE_EXTENSIONS
from .scanner import is_protected_system_path

LOGGER = logging.getLogger(__name__)
SETTLE_SECONDS = 1.0
STABILITY_SCAN_ATTEMPTS = 3


class _FileChangeHandler(FileSystemEventHandler):
    def __init__(self, changed: threading.Event, wakeup: threading.Event):
        self.changed = changed
        self.wakeup = wakeup

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.event_type not in {"created", "modified", "moved", "closed"}:
            return
        if event.is_directory and event.event_type not in {"created", "moved"}:
            return
        if event.is_directory:
            self.changed.set()
            self.wakeup.set()
            return
        path = Path(getattr(event, "dest_path", "") or event.src_path)
        if path.suffix.casefold() not in MONITORED_FILE_EXTENSIONS:
            return
        self.changed.set()
        self.wakeup.set()


class SelectedFolderEventMonitor:
    def __init__(self):
        self._observer: Observer | None = None
        self._root: Path | None = None
        self._changed = threading.Event()
        self._next_scan_at: float | None = None
        self._scan_attempts = 0
        self._last_error: str | None = None
        self._message = "Off. Enable selected-folder monitoring to watch file changes."

    def poll(self, config: dict, wakeup: threading.Event) -> bool:
        if not config.get("download_monitoring", False):
            self.stop()
            self._last_error = None
            self._message = "Off. Enable selected-folder monitoring to watch file changes."
            return False

        configured_root = config.get("download_directory") or Path.home() / "Downloads"
        try:
            root = Path(configured_root).expanduser().resolve(strict=True)
            if not root.is_dir():
                raise NotADirectoryError(f"Selected monitoring path is not a folder: {root}")
            if root == Path(root.anchor) or is_protected_system_path(root, resolve=False):
                raise PermissionError("Drive roots and protected Windows folders cannot be monitored.")
        except (OSError, RuntimeError) as exc:
            self.stop()
            self._last_error = str(exc)
            self._message = f"Real-time file events unavailable: {self._last_error}"
            return False

        if (
            self._observer is None
            or self._root != root
            or not self._observer.is_alive()
        ):
            self.stop()
            try:
                observer = Observer()
                observer.schedule(
                    _FileChangeHandler(self._changed, wakeup),
                    str(root),
                    recursive=True,
                )
                observer.start()
            except (OSError, RuntimeError) as exc:
                self._last_error = str(exc)
                self._message = f"Real-time file events unavailable: {self._last_error}"
                LOGGER.warning("Could not start selected-folder filesystem watcher: %s", exc)
                return False
            self._observer = observer
            self._root = root
            self._last_error = None
            self._message = f"Watching {root} for supported file changes."

        if self._changed.is_set():
            self._changed.clear()
            self._next_scan_at = time.monotonic() + SETTLE_SECONDS
            self._scan_attempts = 0

        if self._next_scan_at is None or time.monotonic() < self._next_scan_at:
            return False

        self._scan_attempts += 1
        if self._scan_attempts >= STABILITY_SCAN_ATTEMPTS:
            self._next_scan_at = None
        else:
            self._next_scan_at = time.monotonic() + SETTLE_SECONDS
        return True

    def seconds_until_scan(self) -> float | None:
        if self._next_scan_at is None:
            return None
        return max(0.0, self._next_scan_at - time.monotonic())

    def status(self, enabled: bool) -> dict:
        return {
            "enabled": enabled,
            "available": self._last_error is None,
            "active": self._observer is not None and self._observer.is_alive(),
            "directory": str(self._root) if self._root is not None else None,
            "message": self._message,
            "last_error": self._last_error,
        }

    def stop(self) -> None:
        observer, self._observer = self._observer, None
        self._root = None
        self._next_scan_at = None
        self._scan_attempts = 0
        self._changed.clear()
        if observer is not None:
            observer.stop()
            observer.join(timeout=3)
            if observer.is_alive():
                self._last_error = "The filesystem watcher did not stop within three seconds."
                LOGGER.error(self._last_error)
