import morpheus.collector as collector


class FakeProcess:
    def __init__(self, info):
        self.info = info

    def cmdline(self):
        if self.info.get("cmdline_access_denied"):
            raise collector.psutil.AccessDenied(self.info["pid"])
        return self.info.get("cmdline", [])


def test_snapshot_groups_remote_connections_by_process_once(monkeypatch):
    processes = [
        FakeProcess({"pid": 10, "name": "browser.exe", "exe": None, "username": "owner"}),
        FakeProcess({"pid": 20, "name": "terminal.exe", "exe": None, "username": "owner"}),
    ]
    connections = [
        {"pid": 10, "remote_ip": "8.8.8.8", "remote_port": 443},
        {"pid": 10, "remote_ip": "1.1.1.1", "remote_port": 443},
        {"pid": 20, "remote_ip": "9.9.9.9", "remote_port": 443},
    ]
    monkeypatch.setattr(collector, "remote_connections", lambda: connections)
    monkeypatch.setattr(collector.psutil, "process_iter", lambda fields: processes)

    snapshot = collector.snapshot_processes()

    assert [item["remote_connections"] for item in snapshot] == [2, 1]
    assert snapshot[0]["connections"] == connections[:2]
    assert snapshot[1]["connections"] == connections[2:]


def test_snapshot_keeps_process_when_command_line_access_is_denied(monkeypatch):
    process = FakeProcess({
        "pid": 10,
        "ppid": 1,
        "name": "protected.exe",
        "exe": None,
        "username": "SYSTEM",
        "cmdline_access_denied": True,
    })
    monkeypatch.setattr(collector, "remote_connections", lambda: [])
    monkeypatch.setattr(collector.psutil, "process_iter", lambda fields: [process])

    snapshot = collector.snapshot_processes()

    assert len(snapshot) == 1
    assert snapshot[0]["name"] == "protected.exe"
    assert snapshot[0]["command_line"] == []


def test_process_tree_marks_document_app_launching_script_host_for_review():
    snapshot = collector.process_tree_snapshot([
        {"pid": 10, "ppid": 1, "name": "WINWORD.EXE"},
        {"pid": 20, "ppid": 10, "name": "powershell.exe"},
        {"pid": 30, "ppid": 10, "name": "notepad.exe"},
    ])

    assert snapshot["total_processes"] == 3
    assert len(snapshot["edges"]) == 2
    reviewed = [edge for edge in snapshot["edges"] if edge["review"]]
    assert len(reviewed) == 1
    assert reviewed[0]["parent_pid"] == 10
    assert reviewed[0]["child_pid"] == 20
    assert "review" in reviewed[0]["reason"].lower()


def test_lolbin_command_patterns_return_indicators_without_raw_arguments():
    arguments = ["powershell.exe", "-EncodedCommand", "sensitive-command-content"]

    finding = collector.inspect_lolbin_command_line("powershell.exe", arguments)

    assert finding["indicators"] == ["powershell_encoded_command"]
    assert finding["command_line_sha256"]
    assert "sensitive-command-content" not in str(finding)
    assert collector.inspect_lolbin_command_line("notepad.exe", ["notepad.exe"]) is None
