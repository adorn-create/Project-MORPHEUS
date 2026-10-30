from morpheus.database import Database

def test_database_round_trip(tmp_path):
    db = Database(tmp_path / "test.db")
    db.add({
        "timestamp": "2026-01-01T00:00:00+00:00",
        "kind": "test",
        "severity": "medium",
        "source": "203.0.113.10",
        "target": "test.exe",
        "confidence": 0.8,
        "evidence": '["test"]',
        "response": "observation_only",
    })
    events = db.list_events()
    assert len(events) == 1
    assert events[0]["target"] == "test.exe"
