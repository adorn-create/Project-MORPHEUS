from pathlib import Path

import pytest

from morpheus import quarantine


def test_encrypted_file_is_rejected_before_isolation(tmp_path, monkeypatch):
    source = tmp_path / "encrypted.txt"
    source.write_text("secret", encoding="utf-8")
    monkeypatch.setattr(quarantine, "_windows_encrypted_attributes", lambda path: True)
    manager = quarantine.QuarantineManager(tmp_path / "isolated")

    with pytest.raises(ValueError, match="Encrypted EFS"):
        manager.quarantine(source)

    assert source.exists()


def test_isolated_acl_denies_authenticated_users_and_everyone(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(quarantine.os, "name", "nt")

    def fake_run(command, **kwargs):
        calls.append(command)
        return type("Result", (), {"returncode": 0})()

    monkeypatch.setattr(quarantine.subprocess, "run", fake_run)
    destination = tmp_path / "sample.quarantine"
    destination.write_bytes(b"sample")

    quarantine._harden_isolated_acl(destination, folder=False)

    command = calls[0]
    assert "*S-1-5-11:(F)" in command
    assert "*S-1-1-0:(F)" in command
    assert "*S-1-5-18:(F)" in command
    assert "*S-1-5-32-544:(F)" in command


def test_isolated_acl_failure_is_not_silently_accepted(tmp_path, monkeypatch):
    monkeypatch.setattr(quarantine.os, "name", "nt")
    monkeypatch.setattr(
        quarantine.subprocess,
        "run",
        lambda command, **kwargs: type("Result", (), {"returncode": 1, "stderr": b"access denied"})(),
    )

    destination = tmp_path / "sample.quarantine"
    destination.write_bytes(b"sample")

    with pytest.raises(OSError, match="access denied"):
        quarantine._harden_isolated_acl(destination, folder=False)
