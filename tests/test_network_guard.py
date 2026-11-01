import morpheus.network_guard as network_guard
from morpheus.network_guard import WindowsFirewallLogMonitor
from morpheus.firewall_worker import scan_block_rule_name


FIELDS = (
    "#Fields: date time action protocol src-ip dst-ip src-port dst-port size "
    "tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path\n"
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


class Firewall:
    def __init__(self, result=True):
        self.result = result
        self.blocked = []

    def block_inbound_remote(self, remote_ip):
        self.blocked.append(remote_ip)
        return self.result


def _row(source, destination, port, action="DROP", protocol="TCP"):
    return (
        f"2026-11-01 10:00:00 {action} {protocol} {source} {destination} "
        f"42000 {port} 60 - 1 0 65535 - - - RECEIVE\n"
    )


def _start_monitor(path, monkeypatch):
    monkeypatch.setattr(network_guard.os, "name", "nt")
    monitor = WindowsFirewallLogMonitor(
        path,
        address_provider=lambda: {"192.168.1.25"},
    )
    path.write_text(FIELDS, encoding="ascii")
    assert monitor.poll(
        {"automatic_inbound_scan_blocking": True},
        Firewall(),
        EventStore(),
        Journal(),
    ) == []
    return monitor


def test_inbound_scan_is_detected_and_public_ip_blocked_only_when_opted_in(tmp_path, monkeypatch):
    path = tmp_path / "pfirewall.log"
    monitor = _start_monitor(path, monkeypatch)
    with path.open("a", encoding="ascii") as stream:
        for port in range(20, 30):
            stream.write(_row("1.2.3.4", "192.168.1.25", port))
    firewall = Firewall()
    database = EventStore()
    journal = Journal()

    events = monitor.poll(
        {"automatic_inbound_scan_blocking": True},
        firewall,
        database,
        journal,
    )

    assert len(events) == 1
    assert events[0]["kind"] == "inbound_port_scan"
    assert events[0]["source"] == "1.2.3.4"
    assert "10 distinct ports" in events[0]["evidence"]
    assert events[0]["response"] == f"blocked_inbound:{scan_block_rule_name('1.2.3.4')}"
    assert firewall.blocked == ["1.2.3.4"]
    assert database.events == journal.events == events


def test_disabled_monitor_does_not_read_log_or_block(tmp_path, monkeypatch):
    path = tmp_path / "pfirewall.log"
    monitor = WindowsFirewallLogMonitor(path, address_provider=lambda: {"192.168.1.25"})
    firewall = Firewall()

    assert monitor.poll({}, firewall, EventStore(), Journal()) == []
    assert monitor._offset is None
    assert firewall.blocked == []


def test_existing_log_entries_are_baseline_and_not_blocked(tmp_path, monkeypatch):
    path = tmp_path / "pfirewall.log"
    monitor = WindowsFirewallLogMonitor(path, address_provider=lambda: {"192.168.1.25"})
    path.write_text(
        FIELDS + "".join(
            _row("1.2.3.4", "192.168.1.25", port) for port in range(20, 40)
        ),
        encoding="ascii",
    )
    monkeypatch.setattr(network_guard.os, "name", "nt")
    firewall = Firewall()

    assert monitor.poll(
        {"automatic_inbound_scan_blocking": True},
        firewall,
        EventStore(),
        Journal(),
    ) == []
    assert firewall.blocked == []


def test_non_dropped_nonlocal_or_private_sources_are_ignored(tmp_path, monkeypatch):
    path = tmp_path / "pfirewall.log"
    monitor = _start_monitor(path, monkeypatch)
    rows = []
    for port in range(20, 32):
        rows.extend((
            _row("1.2.3.4", "192.168.1.25", port, action="ALLOW"),
            _row("192.168.1.10", "192.168.1.25", port),
            _row("1.2.3.4", "192.168.1.99", port),
        ))
    with path.open("a", encoding="ascii") as stream:
        stream.writelines(rows)
    firewall = Firewall()

    assert monitor.poll(
        {"automatic_inbound_scan_blocking": True},
        firewall,
        EventStore(),
        Journal(),
    ) == []
    assert firewall.blocked == []


def test_allowlisted_source_is_alerted_but_not_blocked_again(tmp_path, monkeypatch):
    path = tmp_path / "pfirewall.log"
    monitor = _start_monitor(path, monkeypatch)
    with path.open("a", encoding="ascii") as stream:
        for port in range(20, 30):
            stream.write(_row("1.2.3.4", "192.168.1.25", port))
    firewall = Firewall()
    database = EventStore()

    events = monitor.poll({
        "automatic_inbound_scan_blocking": True,
        "inbound_scan_allowlist": ["1.2.3.4"],
    }, firewall, database, Journal())

    assert len(events) == 1
    assert events[0]["response"] == "owner_allowlisted_no_block"
    assert firewall.blocked == []


def test_partial_log_line_waits_for_completion(tmp_path, monkeypatch):
    path = tmp_path / "pfirewall.log"
    monitor = _start_monitor(path, monkeypatch)
    rows = "".join(_row("1.2.3.4", "192.168.1.25", port) for port in range(20, 29))
    with path.open("a", encoding="ascii") as stream:
        stream.write(rows)
        stream.write("2026-11-01 10:00:00 DROP TCP 1.2.3.4")
    firewall = Firewall()
    assert monitor.poll(
        {"automatic_inbound_scan_blocking": True},
        firewall,
        EventStore(),
        Journal(),
    ) == []
    with path.open("a", encoding="ascii") as stream:
        stream.write(" 192.168.1.25 42000 29 60 - 1 0 65535 - - - RECEIVE\n")

    events = monitor.poll(
        {"automatic_inbound_scan_blocking": True},
        firewall,
        EventStore(),
        Journal(),
    )

    assert len(events) == 1
    assert firewall.blocked == ["1.2.3.4"]


def test_firewall_block_failure_keeps_detection_and_reports_failure(tmp_path, monkeypatch):
    path = tmp_path / "pfirewall.log"
    monitor = _start_monitor(path, monkeypatch)
    with path.open("a", encoding="ascii") as stream:
        for port in range(20, 30):
            stream.write(_row("1.2.3.4", "192.168.1.25", port))

    events = monitor.poll(
        {"automatic_inbound_scan_blocking": True},
        Firewall(result=False),
        EventStore(),
        Journal(),
    )

    assert len(events) == 1
    assert events[0]["response"] == "scan_detected_firewall_block_failed"


def test_missing_firewall_log_reports_protection_unavailable(tmp_path):
    monitor = WindowsFirewallLogMonitor(tmp_path / "missing.log")

    status = monitor.status(True)

    assert status["enabled"] is True
    assert status["available"] is False
    assert "will not enable logging" in status["message"]
