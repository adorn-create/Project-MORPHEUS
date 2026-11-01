import sqlite3
import threading

import Advancement
from scapy.all import ARP, DNS, DNSQR, Ether, IP, UDP

from Advancement import ComprehensiveReviewSystem, shannon_entropy


def test_ledger_hash_chain_verifies_multiple_entries(tmp_path):
    system = ComprehensiveReviewSystem(
        db_name=tmp_path / "ledger.db",
        canary_dir=tmp_path / "canaries",
    )

    genesis = system._get_last_block_hash()
    system.log_audit_node("first", 4, "first review")
    first_hash = system._get_last_block_hash()
    system.log_audit_node("second", 7, "second review")

    assert genesis == "0" * 64
    assert isinstance(first_hash, str)
    assert len(first_hash) == 64
    assert system.verify_ledger() == {"valid": True, "checked": 2}


def test_ledger_detects_modified_row(tmp_path):
    db_path = tmp_path / "ledger.db"
    system = ComprehensiveReviewSystem(db_name=db_path, canary_dir=tmp_path / "canaries")
    system.log_audit_node("first", 4, "first review")

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE security_ledger SET evidence_explanation = ? WHERE id = 1",
            ("edited",),
        )

    assert system.verify_ledger() == {"valid": False, "checked": 0}


def test_concurrent_ledger_writes_preserve_chain(tmp_path):
    system = ComprehensiveReviewSystem(
        db_name=tmp_path / "ledger.db",
        canary_dir=tmp_path / "canaries",
    )
    threads = [
        threading.Thread(
            target=system.log_audit_node,
            args=(f"module-{index}", index % 10, f"review-{index}"),
        )
        for index in range(12)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert system.verify_ledger() == {"valid": True, "checked": 12}


def test_canary_monitor_reports_missing_marker_once(tmp_path):
    system = ComprehensiveReviewSystem(
        db_name=tmp_path / "ledger.db",
        canary_dir=tmp_path / "canaries",
    )
    target = tmp_path / "canaries" / "morpheus-decoy-notes.txt"
    target.unlink()

    system.check_canaries()
    first_count = system._get_last_block_hash()
    system.check_canaries()
    second_count = system._get_last_block_hash()

    assert first_count == second_count
    assert system.verify_ledger() == {"valid": True, "checked": 1}


def test_entropy_and_command_pattern_edge_cases():
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    finding = ComprehensiveReviewSystem._command_indicators(
        "powershell.exe",
        ["powershell.exe", "-NoProfile", "-WindowStyle", "Hidden"],
    )

    assert finding is not None
    assert "hidden_window" in finding[0]
    assert finding[1]


def test_process_host_snapshot_checks_every_running_process(tmp_path, monkeypatch):
    system = ComprehensiveReviewSystem(
        db_name=tmp_path / "ledger.db",
        canary_dir=tmp_path / "canaries",
    )
    visited = 0

    class Process:
        def __init__(self, pid):
            self.info = {
                "pid": pid,
                "name": "notepad.exe",
                "cmdline": ["notepad.exe"],
            }

    def process_iter(_fields):
        nonlocal visited
        for pid in range(1, 5002):
            visited += 1
            yield Process(pid)

    monkeypatch.setattr(Advancement.psutil, "process_iter", process_iter)

    assert system.process_host_snapshot() == []
    assert visited == 5001


def test_dns_packet_review_alerts_on_high_entropy_label_without_storing_name(tmp_path):
    system = ComprehensiveReviewSystem(
        db_name=tmp_path / "ledger.db",
        canary_dir=tmp_path / "canaries",
    )
    alerts = []
    system.process_threat_vector = lambda *args: alerts.append(args)
    qname = "x7Qp9Lm2vR4bN8zK1sT6wY3c.example.com"
    packet = Ether() / IP() / UDP() / DNS(qd=DNSQR(qname=qname))

    system.process_network_packet(packet)

    assert len(alerts) == 1
    assert alerts[0][0] == "DNS Query Entropy Review"
    assert qname not in alerts[0][2]
    assert "SHA-256" in alerts[0][2]


def test_arp_packet_review_requires_a_changed_ip_to_mac_mapping(tmp_path):
    system = ComprehensiveReviewSystem(
        db_name=tmp_path / "ledger.db",
        canary_dir=tmp_path / "canaries",
    )
    alerts = []
    system.process_threat_vector = lambda *args: alerts.append(args)
    first = Ether() / ARP(op=2, psrc="192.0.2.10", hwsrc="00:11:22:33:44:55")
    changed = Ether() / ARP(op=2, psrc="192.0.2.10", hwsrc="00:11:22:33:44:66")

    system.process_network_packet(first)
    assert alerts == []
    system.process_network_packet(changed)

    assert len(alerts) == 1
    assert alerts[0][0] == "ARP Address Mapping Change Review"
    assert "legitimate network changes" in alerts[0][2]


def test_network_capture_is_filtered_scoped_and_not_started_implicitly(tmp_path, monkeypatch):
    import scapy.all

    system = ComprehensiveReviewSystem(
        db_name=tmp_path / "ledger.db",
        canary_dir=tmp_path / "canaries",
    )
    assert system._network_thread is None
    monkeypatch.setattr(
        ComprehensiveReviewSystem,
        "network_interfaces",
        staticmethod(lambda: ["test-interface"]),
    )
    captured = []

    def fake_sniff(**kwargs):
        captured.append(kwargs)
        system._network_stop_event.set()

    monkeypatch.setattr(scapy.all, "sniff", fake_sniff)
    system.start_network_monitor("test-interface")
    system._network_thread.join(timeout=3)

    assert not system._network_thread.is_alive()
    assert captured[0]["iface"] == "test-interface"
    assert captured[0]["filter"] == "udp port 53 or tcp port 53 or arp"
    assert captured[0]["store"] is False
    assert captured[0]["timeout"] == 1


def test_network_capture_requires_explicit_valid_interface(tmp_path, monkeypatch):
    system = ComprehensiveReviewSystem(
        db_name=tmp_path / "ledger.db",
        canary_dir=tmp_path / "canaries",
    )
    monkeypatch.setattr(
        ComprehensiveReviewSystem,
        "network_interfaces",
        staticmethod(lambda: ["test-interface"]),
    )

    try:
        system.start_network_monitor("other-interface")
    except ValueError as exc:
        assert "Unknown interface" in str(exc)
    else:
        raise AssertionError("An unlisted interface must not be captured.")
