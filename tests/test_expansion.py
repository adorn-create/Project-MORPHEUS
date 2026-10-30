import json
from types import SimpleNamespace

import morpheus.expansion as expansion
from morpheus.expansion import (
    DnsEntropyMonitor,
    PowerShellLogMonitor,
    inspect_dns_name,
    inspect_script_block,
    shannon_entropy,
)


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


def test_dns_entropy_review_flags_only_long_random_labels():
    random_label = "x7Qp9Lm2vR4bN8zK1sT6wY3c"

    assert shannon_entropy("aaaaaaaa") == 0
    assert inspect_dns_name(f"{random_label}.example.com") == {
        "domain": f"{random_label}.example.com".lower(),
        "unusual_labels": [{
            "label": random_label.lower(),
            "entropy_bits_per_character": 4.585,
        }],
    }
    assert inspect_dns_name("www.example.com") is None


def test_script_block_finding_excludes_script_contents():
    script = "powershell -EncodedCommand [Convert]::FromBase64String('encoded-data')"

    finding = inspect_script_block(script, 123)

    assert finding["record_id"] == 123
    assert finding["script_sha256"]
    assert "encoded_command" in finding["indicators"]
    assert "base64_decode" in finding["indicators"]
    assert script not in json.dumps(finding)
    assert inspect_script_block("Get-Process", 124) is None


def test_dns_monitor_baselines_current_cache_and_records_new_entropy_alert(monkeypatch):
    monkeypatch.setattr(expansion, "os", SimpleNamespace(name="nt"))
    responses = [
        json.dumps(["www.example.com"]),
        json.dumps(["www.example.com", "x7Qp9Lm2vR4bN8zK1sT6wY3c.example.com"]),
    ]

    def fake_run(command, **kwargs):
        assert "-ExpandProperty Name" in command[-1]
        return SimpleNamespace(
            returncode=0,
            stdout=responses.pop(0),
            stderr="",
        )

    monkeypatch.setattr(
        expansion.subprocess,
        "run",
        fake_run,
    )
    times = iter([100.0, 131.0])
    monkeypatch.setattr(expansion.time, "monotonic", lambda: next(times))
    monitor = DnsEntropyMonitor()
    db = EventStore()
    journal = Journal()

    assert monitor.poll(db, journal) == []
    alerts = monitor.poll(db, journal)

    assert len(alerts) == 1
    assert alerts[0]["kind"] == "dns_entropy"
    assert alerts[0]["response"] == "review_required_manual_approval"
    assert db.events == journal.events == alerts


def test_powershell_monitor_skips_existing_records_and_stores_hash_only(monkeypatch):
    namespace = "http://schemas.microsoft.com/win/2004/08/events/event"
    baseline = (
        f'<Event xmlns="{namespace}"><System><EventRecordID>20</EventRecordID></System></Event>'
    )
    script = "powershell -EncodedCommand [Convert]::FromBase64String('encoded-data')"
    new_event = (
        f'<Event xmlns="{namespace}"><System><EventRecordID>21</EventRecordID></System>'
        f'<EventData><Data Name="ScriptBlockText">{script}</Data></EventData></Event>'
    )
    responses = [[expansion.ET.fromstring(baseline)], [expansion.ET.fromstring(new_event)]]
    monitor = PowerShellLogMonitor()
    monkeypatch.setattr(monitor, "_query", lambda *args, **kwargs: responses.pop(0))
    times = iter([100.0, 116.0])
    monkeypatch.setattr(expansion.time, "monotonic", lambda: next(times))
    db = EventStore()
    journal = Journal()

    assert monitor.poll(db, journal) == []
    alerts = monitor.poll(db, journal)

    assert len(alerts) == 1
    assert alerts[0]["kind"] == "powershell_script_block"
    assert script not in alerts[0]["evidence"]
    assert "script_sha256" in alerts[0]["evidence"]
    assert db.events == journal.events == alerts
