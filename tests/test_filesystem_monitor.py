import threading
from types import SimpleNamespace

import morpheus.filesystem_monitor as filesystem_monitor
from morpheus.filesystem_monitor import SelectedFolderEventMonitor


class FakeObserver:
    def __init__(self):
        self.handler = None
        self.path = None
        self.recursive = False
        self.started = False
        self.stopped = False

    def schedule(self, handler, path, recursive):
        self.handler = handler
        self.path = path
        self.recursive = recursive

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True

    def join(self, timeout=None):
        return None

    def is_alive(self):
        return self.started and not self.stopped


def test_watcher_starts_recursively_and_schedules_stability_scans(tmp_path, monkeypatch):
    observers = []
    monkeypatch.setattr(
        filesystem_monitor,
        "Observer",
        lambda: observers.append(FakeObserver()) or observers[-1],
    )
    now = [100.0]
    monkeypatch.setattr(filesystem_monitor.time, "monotonic", lambda: now[0])
    monitor = SelectedFolderEventMonitor()
    wakeup = threading.Event()
    config = {"download_monitoring": True, "download_directory": str(tmp_path)}

    assert monitor.poll(config, wakeup) is False
    observer = observers[0]
    assert observer.started is True
    assert observer.path == str(tmp_path)
    assert observer.recursive is True

    observer.handler.on_any_event(SimpleNamespace(
        is_directory=False,
        event_type="modified",
        src_path=str(tmp_path / "new.exe"),
        dest_path=None,
    ))
    assert wakeup.is_set()
    assert monitor.poll(config, wakeup) is False

    now[0] += 1
    assert monitor.poll(config, wakeup) is True
    now[0] += 1
    assert monitor.poll(config, wakeup) is True
    now[0] += 1
    assert monitor.poll(config, wakeup) is True
    assert monitor.poll(config, wakeup) is False
    assert monitor.status(True)["active"] is True


def test_watcher_ignores_unsupported_files_and_stops_when_disabled(tmp_path, monkeypatch):
    observers = []
    monkeypatch.setattr(
        filesystem_monitor,
        "Observer",
        lambda: observers.append(FakeObserver()) or observers[-1],
    )
    monitor = SelectedFolderEventMonitor()
    wakeup = threading.Event()
    config = {"download_monitoring": True, "download_directory": str(tmp_path)}

    assert monitor.poll(config, wakeup) is False
    observer = observers[0]
    observer.handler.on_any_event(SimpleNamespace(
        is_directory=False,
        event_type="modified",
        src_path=str(tmp_path / "notes.md"),
        dest_path=None,
    ))
    assert wakeup.is_set() is False

    assert monitor.poll({"download_monitoring": False}, wakeup) is False
    assert observer.stopped is True
    assert monitor.status(False)["active"] is False


def test_watcher_rejects_protected_directories(tmp_path, monkeypatch):
    observers = []
    monkeypatch.setattr(
        filesystem_monitor,
        "Observer",
        lambda: observers.append(FakeObserver()) or observers[-1],
    )
    monkeypatch.setattr(
        filesystem_monitor,
        "is_protected_system_path",
        lambda *args, **kwargs: True,
    )
    monitor = SelectedFolderEventMonitor()

    assert monitor.poll(
        {"download_monitoring": True, "download_directory": str(tmp_path)},
        threading.Event(),
    ) is False
    assert observers == []
    assert monitor.status(True)["available"] is False


def test_watcher_surfaces_start_failure_and_retains_periodic_fallback(tmp_path, monkeypatch):
    class BrokenObserver(FakeObserver):
        def start(self):
            raise OSError("watch service unavailable")

    monkeypatch.setattr(filesystem_monitor, "Observer", BrokenObserver)
    monitor = SelectedFolderEventMonitor()

    assert monitor.poll(
        {"download_monitoring": True, "download_directory": str(tmp_path)},
        threading.Event(),
    ) is False
    assert monitor.status(True)["available"] is False
    assert "watch service unavailable" in monitor.status(True)["message"]
