import base64
import hashlib
import json

from morpheus.auth import (
    AUTH_FAILURE_LIMIT,
    AUTH_LOCKOUT_BASE_SECONDS,
    AUTH_LOCKOUT_MAX_SECONDS,
    AuthFailureLimiter,
    hash_owner_password,
    owner_password_needs_rehash,
    verify_owner_password,
)


def test_owner_password_hash_uses_argon2id_and_rejects_mismatch():
    encoded_hash = hash_owner_password("sample-owner-password")

    assert encoded_hash.startswith("$argon2id$")
    assert verify_owner_password("sample-owner-password", encoded_hash)
    assert not verify_owner_password("wrong-password", encoded_hash)
    assert not owner_password_needs_rehash(encoded_hash)


def test_owner_password_verifier_rejects_malformed_hash():
    assert not verify_owner_password("sample-owner-password", "not-a-valid-hash")
    assert owner_password_needs_rehash("not-a-valid-hash")


def test_auth_failure_limiter_exponentially_backs_off_and_resets():
    limiter = AuthFailureLimiter()
    now = 100.0
    for attempt in range(AUTH_FAILURE_LIMIT):
        limiter.record_failure("owner", now=now + attempt)

    assert limiter.seconds_until_allowed(
        "owner",
        now=now + AUTH_FAILURE_LIMIT,
    ) == AUTH_LOCKOUT_BASE_SECONDS - 1

    first_lockout_ends = now + AUTH_FAILURE_LIMIT - 1 + AUTH_LOCKOUT_BASE_SECONDS
    for attempt in range(AUTH_FAILURE_LIMIT):
        limiter.record_failure("owner", now=first_lockout_ends + attempt)

    second_lockout_started = first_lockout_ends + AUTH_FAILURE_LIMIT - 1
    assert limiter.seconds_until_allowed("owner", now=second_lockout_started) == (
        AUTH_LOCKOUT_BASE_SECONDS * 2
    )
    assert limiter.seconds_until_allowed(
        "owner",
        now=first_lockout_ends + AUTH_FAILURE_LIMIT + AUTH_LOCKOUT_MAX_SECONDS,
    ) == 0

    limiter.record_success("owner")
    assert limiter.seconds_until_allowed("owner", now=now + 10_000) == 0


def test_legacy_pbkdf2_owner_password_hash_is_upgraded_during_passkey_bootstrap(
    tmp_path, monkeypatch
):
    from fastapi.testclient import TestClient

    from morpheus import main

    password = "legacy-owner-password"
    salt = b"legacy-salt-for-tests"
    iterations = 100_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    password_path = tmp_path / "settings-password.json"
    password_path.write_text(
        json.dumps({
            "algorithm": "pbkdf2_sha256",
            "iterations": iterations,
            "salt": base64.b64encode(salt).decode("ascii"),
            "hash": base64.b64encode(digest).decode("ascii"),
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(main, "SETTINGS_PASSWORD_PATH", password_path)
    monkeypatch.setattr(main, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(main, "WEBAUTHN_ORIGIN", "http://localhost:8080")
    monkeypatch.setattr(
        main,
        "passkey_manager",
        main.PasskeyManager(tmp_path / "passkeys.json", main._write_json_file),
    )

    response = TestClient(main.app, base_url="http://localhost:8080").post(
        "/api/passkeys/registration/options",
        headers={"Origin": "http://localhost:8080"},
        json={"bootstrap_password": password},
    )

    assert response.status_code == 200
    record = json.loads(password_path.read_text(encoding="utf-8"))
    assert record["algorithm"] == "argon2id"
    assert verify_owner_password(password, record["hash"])
