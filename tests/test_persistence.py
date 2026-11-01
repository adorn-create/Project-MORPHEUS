from morpheus.persistence import AUTOSTART_KEYS, inspect_autostart_registry


class FakeRegistry:
    HKEY_CURRENT_USER = "HKCU"
    HKEY_LOCAL_MACHINE = "HKLM"

    def __init__(self, values):
        self.values = values

    def OpenKey(self, root, subkey):
        if (root, subkey) not in self.values:
            raise FileNotFoundError(subkey)
        return FakeKey(self.values[(root, subkey)])

    @staticmethod
    def QueryInfoKey(key):
        return (0, len(key.values), 0)

    @staticmethod
    def EnumValue(key, index):
        return key.values[index]


class FakeKey:
    def __init__(self, values):
        self.values = values

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def test_autostart_inventory_is_read_only_and_returns_scoped_entries():
    location = AUTOSTART_KEYS[0][1]
    registry = FakeRegistry({
        ("HKCU", location): [
            ("Example", '"C:\\Program Files\\Example\\app.exe" --start', 1),
        ],
    })

    report = inspect_autostart_registry(registry)

    assert report["available"] is True
    assert report["failures"] == []
    assert report["entries"] == [{
        "scope": "current_user",
        "location": f"current_user\\{location}",
        "name": "Example",
        "command": '"C:\\Program Files\\Example\\app.exe" --start',
        "command_truncated": False,
    }]
    assert "not malware verdicts" in report["message"]


def test_autostart_inventory_reports_read_errors_without_silently_omitting_them():
    class DeniedRegistry(FakeRegistry):
        def OpenKey(self, root, subkey):
            if (root, subkey) == ("HKLM", AUTOSTART_KEYS[2][1]):
                raise PermissionError("access denied")
            return super().OpenKey(root, subkey)

    report = inspect_autostart_registry(DeniedRegistry({}))

    assert report["available"] is True
    assert report["entries"] == []
    assert report["failures"] == [{
        "location": f"local_machine\\{AUTOSTART_KEYS[2][1]}",
        "message": "access denied",
    }]


def test_autostart_inventory_caps_long_commands():
    location = AUTOSTART_KEYS[0][1]
    registry = FakeRegistry({
        ("HKCU", location): [
            ("Example", "x" * 5000, 1),
        ],
    })

    report = inspect_autostart_registry(registry)

    assert len(report["entries"][0]["command"]) == 4096
    assert report["entries"][0]["command_truncated"] is True


def test_autostart_inventory_caps_total_entries(monkeypatch):
    import morpheus.persistence as persistence

    registry = FakeRegistry({
        ("HKCU", AUTOSTART_KEYS[0][1]): [
            ("First", "first.exe", 1),
            ("Second", "second.exe", 1),
        ],
    })
    monkeypatch.setattr(persistence, "MAX_AUTOSTART_ENTRIES", 1)

    report = inspect_autostart_registry(registry)

    assert len(report["entries"]) == 1
    assert report["truncated"] is True


def test_non_windows_autostart_review_reports_unavailable(monkeypatch):
    monkeypatch.setattr("morpheus.persistence.os.name", "posix")

    report = inspect_autostart_registry()

    assert report["available"] is False
    assert report["entries"] == []
    assert "only on Windows" in report["message"]
