import json
from types import SimpleNamespace

from fastapi.testclient import TestClient

from morpheus import main
from morpheus.passkeys import PasskeyManager


ORIGIN = "http://localhost:8080"


def new_manager(tmp_path, monkeypatch):
    manager = PasskeyManager(tmp_path / "passkeys.json", main._write_json_file)
    monkeypatch.setattr(main, "passkey_manager", manager)
    monkeypatch.setattr(main, "WEBAUTHN_ORIGIN", ORIGIN)
    return manager


def webauthn_client():
    return TestClient(main.app, base_url=ORIGIN)


def test_passkey_challenge_is_expiring_single_use_and_client_bound(tmp_path):
    manager = PasskeyManager(tmp_path / "passkeys.json", main._write_json_file)
    ceremony_id = manager.create_challenge("authentication", b"challenge", "owner", now=10)

    assert manager.consume_challenge(ceremony_id, "authentication", "other", now=11) is None
    assert manager.consume_challenge(ceremony_id, "authentication", "owner", now=11) is None

    expired = manager.create_challenge("authentication", b"expired", "owner", now=10)
    assert manager.consume_challenge(expired, "authentication", "owner", now=130) is None


def test_recovery_codes_are_hashed_single_use_and_replenished_on_new_enrollment(tmp_path):
    manager = PasskeyManager(tmp_path / "passkeys.json", main._write_json_file)
    codes = manager.add_credential({
        "credential_id": "AQ",
        "public_key": "Ag",
        "sign_count": 0,
    })

    assert len(codes) == 10
    assert codes[0] not in (tmp_path / "passkeys.json").read_text(encoding="utf-8")
    assert manager.consume_recovery_code(codes[0])
    assert not manager.consume_recovery_code(codes[0])
    assert manager.status()["recovery_codes_remaining"] == 9

    for code in codes[1:]:
        assert manager.consume_recovery_code(code)
    assert manager.status()["recovery_codes_remaining"] == 0
    replenished = manager.add_credential({
        "credential_id": "Aw",
        "public_key": "BA",
        "sign_count": 0,
    })
    assert len(replenished) == 10
    assert manager.status()["recovery_codes_remaining"] == 10


def test_sensitive_authorization_expires_is_client_bound_and_single_use(tmp_path):
    manager = PasskeyManager(tmp_path / "passkeys.json", main._write_json_file)
    token = manager.issue_grant("owner", now=20)

    assert not manager.consume_grant(token, "other", now=21)
    assert not manager.consume_grant(token, "owner", now=21)

    expired = manager.issue_grant("owner", now=20)
    assert not manager.consume_grant(expired, "owner", now=80)

def test_authenticator_sign_counter_rejects_replayed_or_rolled_back_values(tmp_path):
    manager = PasskeyManager(tmp_path / "passkeys.json", main._write_json_file)
    manager.add_credential({
        "credential_id": "AQ",
        "public_key": "Ag",
        "sign_count": 0,
    })

    assert manager.update_sign_count("AQ", 4)
    assert not manager.update_sign_count("AQ", 4)
    assert not manager.update_sign_count("AQ", 0)
    assert manager.get_credential("AQ")["sign_count"] == 4


def test_registration_requires_trusted_localhost_origin(tmp_path, monkeypatch):
    new_manager(tmp_path, monkeypatch)
    client = webauthn_client()

    response = client.post(
        "/api/passkeys/registration/options",
        headers={"Origin": "http://127.0.0.1:8080"},
        json={},
    )

    assert response.status_code == 403


def test_registration_requires_bootstrap_password_when_one_is_configured(
    tmp_path, monkeypatch
):
    new_manager(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "SETTINGS_PASSWORD_PATH", tmp_path / "settings-password.json")
    client = webauthn_client()
    assert client.post(
        "/api/settings-password",
        json={"password": "a-strong-owner-password"},
    ).status_code == 200

    denied = client.post(
        "/api/passkeys/registration/options",
        headers={"Origin": ORIGIN},
        json={},
    )
    allowed = client.post(
        "/api/passkeys/registration/options",
        headers={"Origin": ORIGIN},
        json={"bootstrap_password": "a-strong-owner-password"},
    )

    assert denied.status_code == 401
    assert allowed.status_code == 200
    assert allowed.json()["public_key"]["rp"]["id"] == "localhost"
    assert allowed.json()["public_key"]["authenticatorSelection"]["userVerification"] == "required"


def test_registration_stores_credential_and_returns_recovery_codes(
    tmp_path, monkeypatch
):
    manager = new_manager(tmp_path, monkeypatch)
    monkeypatch.setattr(
        main,
        "verify_registration_response",
        lambda **kwargs: SimpleNamespace(
            credential_id=b"\x01",
            credential_public_key=b"\x02",
            sign_count=0,
            user_verified=True,
        ),
    )
    client = webauthn_client()
    options = client.post(
        "/api/passkeys/registration/options",
        headers={"Origin": ORIGIN},
        json={},
    )
    result = client.post(
        "/api/passkeys/registration/verify",
        headers={"Origin": ORIGIN},
        json={
            "ceremony_id": options.json()["ceremony_id"],
            "credential": {"rawId": "AQ"},
        },
    )

    assert result.status_code == 200
    assert len(result.json()["recovery_codes"]) == 10
    assert manager.status()["credential_count"] == 1
    record = json.loads(manager.path.read_text(encoding="utf-8"))
    assert record["credentials"] == [{
        "credential_id": "AQ",
        "public_key": "Ag",
        "sign_count": 0,
    }]


def test_passkey_approval_authorizes_one_sensitive_action_only(
    tmp_path, monkeypatch
):
    manager = new_manager(tmp_path, monkeypatch)
    manager.add_credential({
        "credential_id": "AQ",
        "public_key": "Ag",
        "sign_count": 0,
    })
    monkeypatch.setattr(
        main,
        "verify_authentication_response",
        lambda **kwargs: SimpleNamespace(
            user_verified=True,
            new_sign_count=1,
        ),
    )
    config_path = tmp_path / "config.json"
    config_path.write_text('{"automatic_quarantine": false}', encoding="utf-8")
    monkeypatch.setattr(main, "CONFIG_PATH", config_path)
    client = webauthn_client()
    options = client.post(
        "/api/passkeys/authentication/options",
        headers={"Origin": ORIGIN},
    )
    approval = client.post(
        "/api/passkeys/authentication/verify",
        headers={"Origin": ORIGIN},
        json={
            "ceremony_id": options.json()["ceremony_id"],
            "credential": {"rawId": "AQ"},
        },
    )
    authorization = approval.json()["authorization"]
    change = client.post(
        "/api/config",
        headers={"X-Morpheus-Authorization": authorization},
        json={"automatic_quarantine": True},
    )
    replay = client.post(
        "/api/config",
        headers={"X-Morpheus-Authorization": authorization},
        json={"automatic_quarantine": False},
    )

    assert approval.status_code == 200
    assert change.status_code == 200
    assert change.json()["automatic_quarantine"] is True
    assert replay.status_code == 401
