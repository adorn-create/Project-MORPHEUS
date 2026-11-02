import hashlib
import hmac
import json
import secrets
import threading
import time
from pathlib import Path
from typing import Callable


PASSKEY_CHALLENGE_TTL_SECONDS = 120
PASSKEY_GRANT_TTL_SECONDS = 60
PASSKEY_CHALLENGE_LIMIT = 128
PASSKEY_GRANT_LIMIT = 128
RECOVERY_CODE_COUNT = 10


class PasskeyManager:
    def __init__(
        self,
        path: Path,
        write_json: Callable[[Path, dict], None],
    ):
        self.path = path
        self._write_json = write_json
        self._lock = threading.Lock()
        self._challenges: dict[str, tuple[str, bytes, float, str]] = {}
        self._grants: dict[str, tuple[float, str]] = {}

    def _read(self) -> dict:
        if not self.path.exists():
            return {
                "version": 1,
                "credentials": [],
                "recovery_code_hashes": [],
            }
        record = json.loads(self.path.read_text(encoding="utf-8"))
        if (
            not isinstance(record, dict)
            or record.get("version") != 1
            or not isinstance(record.get("credentials"), list)
            or not isinstance(record.get("recovery_code_hashes"), list)
        ):
            raise ValueError("The local passkey record is invalid.")
        if any(
            not isinstance(item, dict)
            or not isinstance(item.get("credential_id"), str)
            or not isinstance(item.get("public_key"), str)
            or not isinstance(item.get("sign_count"), int)
            or isinstance(item.get("sign_count"), bool)
            or item["sign_count"] < 0
            for item in record["credentials"]
        ):
            raise ValueError("The local passkey credential data is invalid.")
        if any(
            not isinstance(code_hash, str)
            or len(code_hash) != 64
            or any(character not in "0123456789abcdef" for character in code_hash)
            for code_hash in record["recovery_code_hashes"]
        ):
            raise ValueError("The local passkey recovery data is invalid.")
        return record

    def status(self) -> dict:
        with self._lock:
            record = self._read()
            return {
                "configured": bool(record["credentials"]),
                "credential_count": len(record["credentials"]),
                "recovery_codes_remaining": len(record["recovery_code_hashes"]),
            }

    def create_challenge(
        self,
        ceremony: str,
        challenge: bytes,
        client: str,
        *,
        now: float | None = None,
    ) -> str:
        current = time.monotonic() if now is None else now
        with self._lock:
            self._expire(current)
            if len(self._challenges) >= PASSKEY_CHALLENGE_LIMIT:
                oldest = min(self._challenges, key=lambda key: self._challenges[key][2])
                self._challenges.pop(oldest, None)
            ceremony_id = secrets.token_urlsafe(24)
            self._challenges[ceremony_id] = (
                ceremony,
                challenge,
                current + PASSKEY_CHALLENGE_TTL_SECONDS,
                client,
            )
            return ceremony_id

    def consume_challenge(
        self,
        ceremony_id: str,
        ceremony: str,
        client: str,
        *,
        now: float | None = None,
    ) -> bytes | None:
        current = time.monotonic() if now is None else now
        with self._lock:
            entry = self._challenges.pop(ceremony_id, None)
            if entry is None:
                return None
            expected_ceremony, challenge, expires_at, expected_client = entry
            if (
                current >= expires_at
                or expected_ceremony != ceremony
                or not hmac.compare_digest(expected_client, client)
            ):
                return None
            return challenge

    def _expire(self, now: float) -> None:
        for key, (_, _, expires_at, _) in list(self._challenges.items()):
            if now >= expires_at:
                self._challenges.pop(key, None)
        for key, (expires_at, _) in list(self._grants.items()):
            if now >= expires_at:
                self._grants.pop(key, None)

    def credentials(self) -> list[dict]:
        with self._lock:
            return list(self._read()["credentials"])

    def get_credential(self, credential_id: str) -> dict | None:
        with self._lock:
            return next(
                (
                    dict(item)
                    for item in self._read()["credentials"]
                    if item.get("credential_id") == credential_id
                ),
                None,
            )

    def add_credential(self, credential: dict) -> list[str]:
        with self._lock:
            record = self._read()
            if any(
                item.get("credential_id") == credential["credential_id"]
                for item in record["credentials"]
            ):
                raise ValueError("This passkey is already registered.")
            if len(record["credentials"]) >= 5:
                raise ValueError("The maximum of five passkeys has been reached.")
            record["credentials"].append(credential)
            recovery_codes: list[str] = []
            if not record["recovery_code_hashes"]:
                for _ in range(RECOVERY_CODE_COUNT):
                    code = secrets.token_hex(16).upper()
                    recovery_codes.append(
                        "-".join(code[index:index + 4] for index in range(0, len(code), 4))
                    )
                record["recovery_code_hashes"] = [
                    self._recovery_hash(code) for code in recovery_codes
                ]
            self._write_json(self.path, record)
            return recovery_codes

    @staticmethod
    def _normalize_recovery_code(code: str) -> str:
        return code.replace("-", "").replace(" ", "").upper()

    @classmethod
    def _recovery_hash(cls, code: str) -> str:
        return hashlib.sha256(cls._normalize_recovery_code(code).encode("ascii")).hexdigest()

    def consume_recovery_code(self, code: str) -> bool:
        normalized = self._normalize_recovery_code(code)
        if len(normalized) != 32 or any(character not in "0123456789ABCDEF" for character in normalized):
            return False
        candidate = self._recovery_hash(normalized)
        with self._lock:
            record = self._read()
            remaining = []
            matched = False
            for stored_hash in record["recovery_code_hashes"]:
                equal = hmac.compare_digest(candidate, stored_hash)
                matched = matched or equal
                if not equal:
                    remaining.append(stored_hash)
            if matched:
                record["recovery_code_hashes"] = remaining
                self._write_json(self.path, record)
            return matched

    def update_sign_count(self, credential_id: str, sign_count: int) -> bool:
        with self._lock:
            record = self._read()
            for credential in record["credentials"]:
                if credential.get("credential_id") != credential_id:
                    continue
                current = int(credential.get("sign_count", 0))
                if current > 0 and sign_count <= current:
                    return False
                credential["sign_count"] = max(current, sign_count)
                self._write_json(self.path, record)
                return True
        return False

    def issue_grant(self, client: str, *, now: float | None = None) -> str:
        current = time.monotonic() if now is None else now
        with self._lock:
            self._expire(current)
            if len(self._grants) >= PASSKEY_GRANT_LIMIT:
                oldest = min(self._grants, key=lambda key: self._grants[key][0])
                self._grants.pop(oldest, None)
            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
            self._grants[token_hash] = (current + PASSKEY_GRANT_TTL_SECONDS, client)
            return token

    def consume_grant(self, token: str | None, client: str, *, now: float | None = None) -> bool:
        if not token:
            return False
        current = time.monotonic() if now is None else now
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._lock:
            entry = self._grants.pop(token_hash, None)
            if entry is None:
                return False
            expires_at, expected_client = entry
            return current < expires_at and hmac.compare_digest(expected_client, client)
