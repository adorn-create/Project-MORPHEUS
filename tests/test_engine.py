import json

import morpheus.engine as engine_module
from morpheus.engine import DefenseEngine


def test_automatic_quarantine_is_reversible_and_does_not_block_network(tmp_path, monkeypatch):
    executable = tmp_path / "suspicious.exe"
    executable.write_bytes(b"MZ" + b"A" * 2048)
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({
            "automatic_quarantine": True,
            "automatic_high_confidence": False,
            "high_confidence_threshold": 0.95,
            "excluded_processes": [],
            "protected_roots": [],
        }),
        encoding="utf-8",
    )
    engine = DefenseEngine(tmp_path / "data", config_path)
    monkeypatch.setattr(engine_module.psutil, "Process", lambda pid: object())
    monkeypatch.setattr(
        engine_module,
        "snapshot_processes",
        lambda excluded: [{
            "pid": 42,
            "name": "powershell.exe",
            "connections": [{"remote_ip": "203.0.113.10"}],
            "remote_connections": 1,
        }],
    )
    monkeypatch.setattr(
        engine_module,
        "executable_signals",
        lambda proc, connections: (
            {
                "unsigned_temp_executable": True,
                "many_remote_connections": True,
                "high_cpu": True,
                "new_executable": True,
                "unexpected_sensitive_connection": True,
            },
            executable,
        ),
    )
    monkeypatch.setattr(
        engine.firewall,
        "block_remote",
        lambda remote_ip: (_ for _ in ()).throw(AssertionError("quarantine-only mode must not block IPs")),
    )

    detections = engine.evaluate_once()

    assert len(detections) == 1
    assert "quarantined:" in detections[0]["response"]
    assert "blocked_remote:" not in detections[0]["response"]
    assert not executable.exists()
    quarantine_path = next((tmp_path / "data" / "quarantine").glob("*.quarantine"))
    metadata = json.loads(quarantine_path.with_suffix(".json").read_text(encoding="utf-8"))
    restored = engine.quarantine.restore(metadata["token"])
    assert restored["restored"] == str(executable)
    assert executable.is_file()


def test_known_tool_is_reported_once_while_running_without_auto_action(tmp_path, monkeypatch):
    executable = tmp_path / "nmap.exe"
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({
        "automatic_quarantine": True,
        "automatic_high_confidence": True,
        "high_confidence_threshold": 0.95,
        "excluded_processes": [],
        "protected_roots": [],
    }), encoding="utf-8")
    engine = DefenseEngine(tmp_path / "data", config_path)
    process_snapshot = [{
        "pid": 42,
        "name": "nmap.exe",
        "exe": str(executable),
        "connections": [],
        "remote_connections": 0,
    }]
    monkeypatch.setattr(engine_module.psutil, "Process", lambda pid: object())
    monkeypatch.setattr(engine_module, "snapshot_processes", lambda excluded: process_snapshot)
    monkeypatch.setattr(engine_module, "executable_signals", lambda proc, connections: ({}, executable))
    monkeypatch.setattr(engine.firewall, "block_remote", lambda remote_ip: True)
    monkeypatch.setattr(engine.quarantine, "quarantine", lambda path: (_ for _ in ()).throw(
        AssertionError("a tool-name match must not trigger automatic quarantine")
    ))

    first = engine.evaluate_once()
    second = engine.evaluate_once()

    assert len(first) == 1
    assert first[0]["kind"] == "known_security_tool"
    assert first[0]["severity"] == "medium"
    assert first[0]["response"] == "review_required_no_automatic_action"
    assert json.loads(first[0]["evidence"])["tool"] == "Nmap"
    assert second == []
    assert engine.db.count() == 1

    process_snapshot.clear()
    engine.evaluate_once()
    process_snapshot.append({
        "pid": 42,
        "name": "nmap.exe",
        "exe": str(executable),
        "connections": [],
        "remote_connections": 0,
    })
    assert engine.evaluate_once()[0]["kind"] == "known_security_tool"


def test_process_tree_review_is_recorded_once_without_automatic_action(tmp_path, monkeypatch):
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({
        "process_tree_monitoring": True,
        "excluded_processes": [],
    }), encoding="utf-8")
    engine = DefenseEngine(tmp_path / "data", config_path)
    monkeypatch.setattr(engine_module, "snapshot_processes", lambda excluded: [
        {"pid": 10, "ppid": 1, "name": "WINWORD.EXE", "connections": []},
        {"pid": 20, "ppid": 10, "name": "powershell.exe", "connections": []},
    ])
    monkeypatch.setattr(engine_module, "identify_known_tool", lambda *args: None)
    monkeypatch.setattr(engine_module.psutil, "Process", lambda pid: object())
    monkeypatch.setattr(engine_module, "executable_signals", lambda *args: ({}, None))
    monkeypatch.setattr(engine.model, "score", lambda signals: (0.0, []))

    first = engine.evaluate_once()
    second = engine.evaluate_once()

    assert len(first) == 1
    assert first[0]["kind"] == "process_tree_review"
    assert first[0]["response"] == "review_required_manual_approval"
    assert second == []
    assert engine.db.count() == 1


def test_lolbin_command_pattern_is_review_only_and_does_not_store_arguments(tmp_path, monkeypatch):
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({
        "process_tree_monitoring": False,
        "excluded_processes": [],
    }), encoding="utf-8")
    engine = DefenseEngine(tmp_path / "data", config_path)
    secret_argument = "this-secret-argument-must-not-be-recorded"
    monkeypatch.setattr(engine_module, "snapshot_processes", lambda excluded: [{
        "pid": 42,
        "name": "powershell.exe",
        "exe": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
        "command_line": ["powershell.exe", "-EncodedCommand", secret_argument],
        "connections": [],
        "remote_connections": 0,
    }])
    monkeypatch.setattr(engine_module, "identify_known_tool", lambda *args: None)
    monkeypatch.setattr(engine_module.psutil, "Process", lambda pid: object())
    monkeypatch.setattr(engine_module, "executable_signals", lambda *args: ({}, None))
    monkeypatch.setattr(engine.model, "score", lambda signals: (0.0, []))

    events = engine.evaluate_once()

    assert len(events) == 1
    assert events[0]["kind"] == "lolbin_command_pattern"
    assert events[0]["response"] == "review_required_manual_approval"
    assert secret_argument not in events[0]["evidence"]
    assert secret_argument not in events[0]["target"]
