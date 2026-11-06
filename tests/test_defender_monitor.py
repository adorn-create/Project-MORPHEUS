import json

import morpheus.defender_monitor as defender_monitor
from morpheus.defender_monitor import DefenderHealthMonitor, parse_defender_status


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


def _status(**overrides):
    data = {
        "AMServiceEnabled": True,
        "AntivirusEnabled": True,
        "AntispywareEnabled": True,
        "RealTimeProtectionEnabled": True,
        "BehaviorMonitorEnabled": True,
        "IoavProtectionEnabled": True,
        "AntivirusSignatureAge": 1,
        "AntivirusSignatureLastUpdated": "2026-11-01T10:00:00Z",
    }
    data.update(overrides)
    return data


def test_parse_defender_status_reports_disabled_protection_and_stale_signatures():
    health = parse_defender_status(_status(
        RealTimeProtectionEnabled=False,
        AntivirusSignatureAge=8,
    ))

    assert health["healthy"] is False
    assert health["issues"] == [
        "Real-time protection is disabled",
        "Antivirus signatures are more than seven days old",
    ]
    assert health["signature_age_days"] == 8


def test_parse_defender_status_requires_complete_typed_response():
    data = _status()
    del data["AntispywareEnabled"]
    try:
        parse_defender_status(data)
    except ValueError as exc:
        assert "AntispywareEnabled" in str(exc)
    else:
        raise AssertionError("A missing Defender status field must be rejected.")

    for invalid_age in (True, -1, "1"):
        try:
            parse_defender_status(_status(AntivirusSignatureAge=invalid_age))
        except ValueError:
            continue
        raise AssertionError("An invalid signature age must be rejected.")


def test_monitor_records_degraded_and_recovered_transitions_once(monkeypatch):
    monkeypatch.setattr(defender_monitor.os, "name", "nt")
    healthy = parse_defender_status(_status())
    degraded = parse_defender_status(_status(RealTimeProtectionEnabled=False))
    responses = iter([healthy, degraded, degraded, healthy])
    monitor = DefenderHealthMonitor(query=lambda: next(responses))
    times = iter([100.0, 161.0, 222.0, 283.0])
    monkeypatch.setattr(defender_monitor.time, "monotonic", lambda: next(times))
    database = EventStore()
    journal = Journal()

    assert monitor.poll(database, journal) == []
    alerts = monitor.poll(database, journal)
    assert len(alerts) == 1
    assert alerts[0]["kind"] == "defender_protection_degraded"
    assert alerts[0]["severity"] == "high"
    assert "Real-time protection is disabled" in json.loads(alerts[0]["evidence"])["issues"]
    assert monitor.poll(database, journal) == []
    recovered = monitor.poll(database, journal)
    assert recovered[0]["kind"] == "defender_protection_restored"
    assert database.events == journal.events


def test_signature_only_stale_state_is_medium_and_duplicate_alert_is_suppressed(monkeypatch):
    monkeypatch.setattr(defender_monitor.os, "name", "nt")
    stale = parse_defender_status(_status(AntivirusSignatureAge=8))
    responses = iter([stale, stale])
    monitor = DefenderHealthMonitor(query=lambda: next(responses))
    times = iter([100.0, 161.0])
    monkeypatch.setattr(defender_monitor.time, "monotonic", lambda: next(times))
    database = EventStore()
    journal = Journal()

    event = monitor.poll(database, journal)[0]

    assert event["kind"] == "defender_protection_degraded"
    assert event["severity"] == "medium"
    assert monitor.poll(database, journal) == []
    assert len(database.events) == 1


def test_query_failure_is_visible_without_claiming_protection_is_off(monkeypatch):
    monkeypatch.setattr(defender_monitor.os, "name", "nt")
    monitor = DefenderHealthMonitor(query=lambda: (_ for _ in ()).throw(
        RuntimeError("Get-MpComputerStatus unavailable")
    ))
    monkeypatch.setattr(defender_monitor.time, "monotonic", lambda: 100.0)

    assert monitor.poll(EventStore(), Journal()) == []
    status = monitor.status()

    assert status["available"] is False
    assert status["healthy"] is None
    assert "Get-MpComputerStatus unavailable" in status["message"]


def test_query_only_reads_defender_status(monkeypatch):
    monkeypatch.setattr(defender_monitor.os, "name", "nt")
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return type("Result", (), {
            "returncode": 0,
            "stdout": json.dumps(_status()),
            "stderr": "",
        })()

    monkeypatch.setattr(defender_monitor.subprocess, "run", fake_run)

    result = defender_monitor.query_defender_status()

    assert result["healthy"] is True
    script = calls[0][-1]
    assert "Get-MpComputerStatus" in script
    assert "Set-MpPreference" not in script
    assert "DisableRealtimeMonitoring" not in script


def test_non_windows_status_is_explicit_and_never_queries(monkeypatch):
    monkeypatch.setattr(defender_monitor.os, "name", "posix")
    monitor = DefenderHealthMonitor(query=lambda: (_ for _ in ()).throw(
        AssertionError("Non-Windows systems must not query Defender.")
    ))

    assert monitor.poll(EventStore(), Journal()) == []
    assert monitor.status()["supported"] is False


def test_defender_file_scan_uses_custom_scan_and_never_quarantines(tmp_path, monkeypatch):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    monkeypatch.setattr(defender_monitor.os, "name", "nt")
    monkeypatch.setattr(defender_monitor, "find_defender_command", lambda: "C:/Program Files/Windows Defender/MpCmdRun.exe")
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(defender_monitor.subprocess, "run", fake_run)

    result = defender_monitor.scan_file_with_defender(sample)

    assert result["verdict"] == "clean"
    assert "-ScanType" in calls[0]
    assert "3" in calls[0]
    assert "-File" in calls[0]
    assert str(sample) in calls[0]


def test_defender_scan_enforces_configurable_file_limit(tmp_path, monkeypatch):
    sample = tmp_path / "large.bin"
    sample.write_bytes(b"12345")
    monkeypatch.setattr(defender_monitor.os, "name", "nt")

    try:
        defender_monitor.scan_file_with_defender(sample, max_bytes=4)
    except ValueError as exc:
        assert "scan limit" in str(exc)
    else:
        raise AssertionError("The Defender file limit was not enforced")
