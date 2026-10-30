import json
from morpheus.integrity import EvidenceJournal
from morpheus.rules import RuleEngine
from morpheus.models import ConfigUpdate

def test_journal_integrity(tmp_path):
    journal = EvidenceJournal(tmp_path)
    journal.append({"kind": "test", "confidence": 0.8})
    assert journal.verify()["valid"] is True


def test_journal_appends_to_existing_chain_and_status_does_not_verify_again(tmp_path, monkeypatch):
    journal = EvidenceJournal(tmp_path)
    journal.append({"kind": "first"})
    assert journal.verify() == {"valid": True, "count": 1}
    journal.append({"kind": "second"})
    assert journal.status() == {"checked": False, "valid": None, "verified_records": 0}

    reopened = EvidenceJournal(tmp_path)
    reopened.append({"kind": "third"})
    assert reopened.status() == {"checked": False, "valid": None, "verified_records": 0}
    assert reopened.verify() == {"valid": True, "count": 3}


def test_journal_streaming_verification_detects_tampering(tmp_path):
    journal = EvidenceJournal(tmp_path)
    journal.append({"kind": "test"})
    journal.path.write_text(journal.path.read_text(encoding="utf-8").replace('"kind":"test"', '"kind":"changed"'), encoding="utf-8")

    assert journal.verify() == {"valid": False, "count": 0}


def test_rule_engine_maps_powershell():
    matches = RuleEngine().evaluate("powershell.exe", {"unexpected_sensitive_connection": True}, 2)
    assert matches
    assert "T1059.001" in matches[0]["techniques"]


def test_config_validation_bounds():
    config = ConfigUpdate(high_confidence_threshold=0.95, poll_interval_seconds=5)
    assert config.high_confidence_threshold == 0.95
