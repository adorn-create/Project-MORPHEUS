from fastapi.testclient import TestClient

from morpheus import main


def test_favicon_is_served():
    response = TestClient(main.app).get("/favicon.ico")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")
    assert "<svg" in response.text


def test_dashboard_renders_background_monitoring_and_folder_picker():
    response = TestClient(main.app).get("/")

    assert response.status_code == 200
    assert 'id="monitoringState"' in response.text
    assert 'id="automaticQuarantine"' in response.text
    assert 'id="folderInput"' in response.text
    assert 'id="reviewCodeButton"' in response.text
    assert 'id="defenderScanButton"' not in response.text
    assert 'id="downloadDirectoryPath"' in response.text
    assert 'id="browseDownloadFolderButton"' in response.text
    assert 'id="firewallRules"' in response.text
    assert 'id="settingsPasswordButton"' in response.text
    assert 'id="dnsEntropyMonitoring"' in response.text
    assert 'id="powershellLogMonitoring"' in response.text
    assert 'id="canaryMonitoring"' in response.text
    assert 'id="processTree"' in response.text
    assert 'id="riskLevel"' in response.text
    assert "30 GB total scan limit" in response.text


def test_scan_endpoint_returns_detection_results(monkeypatch):
    detections = [{"kind": "suspicious_process", "severity": "medium"}]
    monkeypatch.setattr(main.engine, "evaluate_once", lambda: detections)

    with TestClient(main.app) as client:
        response = client.post("/api/scan")

    assert response.status_code == 200
    assert response.json() == {"detected": detections}

def test_code_review_endpoint_returns_local_rule_findings(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text('api_key = "example-secret-value"\n', encoding="utf-8")

    response = TestClient(main.app).post("/api/review-code", json={"path": str(source)})

    assert response.status_code == 200
    result = response.json()
    assert result["files_scanned"] == 1
    assert result["ruleset"] == "Morpheus local rules v1"
    assert result["findings"][0]["rule_id"] == "hardcoded-credential"
    assert result["findings"][0]["line"] == 1
    assert "example-secret-value" not in response.text


def test_code_review_endpoint_rejects_non_source_file(tmp_path):
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ")

    response = TestClient(main.app).post("/api/review-code", json={"path": str(target)})

    assert response.status_code == 400
    assert "Unsupported source-code file type" in response.json()["detail"]


def test_removed_defender_scan_endpoint_is_not_available(tmp_path):
    response = TestClient(main.app).post(
        "/api/defender/scan",
        json={"path": str(tmp_path)},
    )

    assert response.status_code == 404


def test_folder_upload_scans_selected_file():
    content = b"MZ" + b"A" * 4096
    response = TestClient(main.app).post(
        "/api/scan-upload",
        files={"file": ("tools/sample.exe", content, "application/octet-stream")},
    )

    assert response.status_code == 200
    result = response.json()
    assert result["path"] == "tools/sample.exe"
    assert result["size"] == len(content)
    assert result["sha256"]
    assert "executable_or_script_type" in result["reasons"]


def test_folder_upload_rejects_oversized_file(monkeypatch):
    monkeypatch.setattr(main, "MAX_UPLOAD_SIZE", 4)
    response = TestClient(main.app).post(
        "/api/scan-upload",
        files={"file": ("large.bin", b"12345", "application/octet-stream")},
    )

    assert response.status_code == 413
    assert response.json()["detail"] == "File exceeds the 1 MB per-file scan limit."


def test_folder_upload_rejects_protected_system_paths():
    response = TestClient(main.app).post(
        "/api/scan-upload",
        files={"file": ("Windows/System32/sample.exe", b"MZ" + b"A" * 2048, "application/octet-stream")},
    )

    assert response.status_code == 403
    assert "excluded" in response.json()["detail"]


def test_automatic_quarantine_is_opt_in(monkeypatch, tmp_path):
    config_path = tmp_path / "config.json"
    config_path.write_text('{"automatic_quarantine": false}', encoding="utf-8")
    monkeypatch.setattr(main, "CONFIG_PATH", config_path)
    with TestClient(main.app) as client:
        response = client.post("/api/config", json={"automatic_quarantine": True})

    assert response.status_code == 200
    assert response.json()["automatic_quarantine"] is True


def test_owner_password_protects_security_settings(monkeypatch, tmp_path):
    password_path = tmp_path / "settings-password.json"
    config_path = tmp_path / "config.json"
    config_path.write_text('{"automatic_quarantine": false}', encoding="utf-8")
    monkeypatch.setattr(main, "SETTINGS_PASSWORD_PATH", password_path)
    monkeypatch.setattr(main, "CONFIG_PATH", config_path)
    client = TestClient(main.app)

    setup = client.post("/api/settings-password", json={"password": "a-strong-owner-password"})
    assert setup.status_code == 200
    assert "a-strong-owner-password" not in password_path.read_text(encoding="utf-8")

    denied = client.post("/api/config", json={"automatic_quarantine": True})
    assert denied.status_code == 401
    accepted = client.post(
        "/api/config",
        headers={"X-Morpheus-Settings-Password": "a-strong-owner-password"},
        json={"automatic_quarantine": True},
    )
    assert accepted.status_code == 200
    assert accepted.json()["automatic_quarantine"] is True


def test_settings_password_requires_current_password_to_change(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "SETTINGS_PASSWORD_PATH", tmp_path / "settings-password.json")
    client = TestClient(main.app)
    client.post("/api/settings-password", json={"password": "a-strong-owner-password"})

    denied = client.post("/api/settings-password", json={"password": "a-different-owner-password"})
    accepted = client.post(
        "/api/settings-password",
        json={
            "password": "a-different-owner-password",
            "current_password": "a-strong-owner-password",
        },
    )

    assert denied.status_code == 401
    assert accepted.status_code == 200


def test_settings_password_accepts_ten_characters_and_rejects_nine(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "SETTINGS_PASSWORD_PATH", tmp_path / "settings-password.json")
    client = TestClient(main.app)

    rejected = client.post("/api/settings-password", json={"password": "Abcdef123"})
    accepted = client.post("/api/settings-password", json={"password": "Abcdef1234"})

    assert rejected.status_code == 422
    assert accepted.status_code == 200


def test_status_reports_background_monitoring(monkeypatch):
    monkeypatch.setattr(main.engine, "evaluate_once", lambda: [])
    with TestClient(main.app) as client:
        response = client.get("/api/status")

    assert response.status_code == 200
    assert response.json()["monitoring"]["running"] is True
    assert response.json()["monitoring"]["last_scan_at"]
    assert response.json()["tool_watch"]["catalog_entries"] > 0
    assert "running process" in response.json()["tool_watch"]["scope"]
    assert "transient command-pattern checks" in response.json()["tool_watch"]["scope"]
    assert response.json()["expansion"]["dns"]["enabled"] is False
    assert response.json()["expansion"]["powershell"]["enabled"] is False
    assert response.json()["expansion"]["process_tree_enabled"] is True
    assert response.json()["expansion"]["canary"]["enabled"] is False


def test_risk_summary_endpoint_returns_explainable_score(monkeypatch):
    now = main.datetime.now(main.timezone.utc).isoformat()
    monkeypatch.setattr(main.engine.db, "list_events", lambda limit: [
        {"kind": "dns_entropy", "timestamp": now},
    ])

    response = TestClient(main.app).get("/api/risk")

    assert response.status_code == 200
    assert response.json()["score"] == 25
    assert response.json()["signals"][0]["kind"] == "dns_entropy"


def test_process_tree_endpoint_returns_current_snapshot(monkeypatch):
    snapshot = {
        "nodes": [{"pid": 10, "parent_pid": 1, "name": "explorer.exe"}],
        "edges": [],
        "truncated": False,
        "total_processes": 1,
    }
    monkeypatch.setattr(main.engine, "latest_process_tree", snapshot)

    response = TestClient(main.app).get("/api/process-tree")

    assert response.status_code == 200
    assert response.json() == snapshot


def test_status_does_not_run_full_journal_verification(monkeypatch):
    monkeypatch.setattr(main.engine.journal, "verify", lambda: (_ for _ in ()).throw(
        AssertionError("dashboard status must not scan the full audit journal")
    ))

    response = TestClient(main.app).get("/api/status")

    assert response.status_code == 200
    assert response.json()["journal"]["checked"] is False


def test_firewall_enumeration_timeout_is_reported(monkeypatch):
    from morpheus.firewall import FirewallWorkerError

    monkeypatch.setattr(
        main.engine.firewall,
        "list_morpheus_rules",
        lambda: (_ for _ in ()).throw(FirewallWorkerError("timed out")),
    )

    response = TestClient(main.app).get("/api/firewall")

    assert response.status_code == 503
    assert response.json()["detail"] == "timed out"
