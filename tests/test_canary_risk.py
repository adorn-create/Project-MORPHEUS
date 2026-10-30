import json
from datetime import datetime, timedelta, timezone

from morpheus.canary import CANARY_CONTENTS, CanaryMonitor
from morpheus.risk import explainable_risk


class EventStore:
    def __init__(self):
        self.events = []

    def add(self, event):
        self.events.append(event)


class Journal:
    def __init__(self):
        self.events = []

    def append(self, event):
        self.events.append(event)


def test_canary_monitor_creates_only_in_managed_folder_and_records_change(tmp_path):
    root = tmp_path / "morpheus-data" / "canaries"
    monitor = CanaryMonitor(root)
    db = EventStore()
    journal = Journal()

    assert monitor.poll(db, journal) == []
    assert {path.name for path in root.iterdir()} == {
        *CANARY_CONTENTS,
        ".morpheus-canary-initialized",
    }

    target_name = next(iter(CANARY_CONTENTS))
    (root / target_name).write_text("changed", encoding="utf-8")
    alerts = monitor.poll(db, journal)

    assert len(alerts) == 1
    assert alerts[0]["kind"] == "canary_file_change"
    assert json.loads(alerts[0]["evidence"])["state"] == "modified"
    assert alerts[0]["response"] == "review_required_manual_approval"
    assert db.events == journal.events == alerts
    assert monitor.poll(db, journal) == []


def test_explainable_risk_correlates_recent_unique_alert_types():
    now = datetime.now(timezone.utc)
    events = [
        {"kind": "dns_entropy", "timestamp": now.isoformat()},
        {"kind": "process_tree_review", "timestamp": (now - timedelta(minutes=2)).isoformat()},
        {"kind": "dns_entropy", "timestamp": now.isoformat()},
        {"kind": "canary_file_change", "timestamp": (now - timedelta(minutes=30)).isoformat()},
    ]

    result = explainable_risk(events, now)

    assert result["score"] == 60
    assert result["level"] == "elevated"
    assert {signal["kind"] for signal in result["signals"]} == {
        "dns_entropy",
        "process_tree_review",
    }
    assert "not a probability" in result["explanation"]
