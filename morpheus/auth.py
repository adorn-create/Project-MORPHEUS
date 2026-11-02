import threading
import time

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

PASSWORD_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,
    parallelism=2,
    hash_len=32,
    salt_len=16,
)

AUTH_FAILURE_WINDOW_SECONDS = 600
AUTH_FAILURE_LIMIT = 5
AUTH_LOCKOUT_BASE_SECONDS = 15
AUTH_LOCKOUT_MAX_SECONDS = 900
AUTH_TRACKED_CLIENT_LIMIT = 1024


def hash_owner_password(password: str) -> str:
    return PASSWORD_HASHER.hash(password)


def verify_owner_password(password: str, encoded_hash: str) -> bool:
    try:
        return PASSWORD_HASHER.verify(encoded_hash, password)
    except (InvalidHashError, VerificationError, VerifyMismatchError):
        return False


def owner_password_needs_rehash(encoded_hash: str) -> bool:
    try:
        return PASSWORD_HASHER.check_needs_rehash(encoded_hash)
    except (InvalidHashError, VerificationError):
        return True


class AuthFailureLimiter:
    def __init__(self):
        self._lock = threading.Lock()
        self._failures: dict[str, tuple[int, float, float]] = {}

    def seconds_until_allowed(self, client: str, *, now: float | None = None) -> float:
        current = time.monotonic() if now is None else now
        with self._lock:
            state = self._failures.get(client)
            if state is None:
                return 0.0
            _, last_failure, locked_until = state
            if current - last_failure >= AUTH_FAILURE_WINDOW_SECONDS:
                self._failures.pop(client, None)
                return 0.0
            return max(0.0, locked_until - current)

    def record_failure(self, client: str, *, now: float | None = None) -> None:
        current = time.monotonic() if now is None else now
        with self._lock:
            for key, (_, last_failure, _) in list(self._failures.items()):
                if current - last_failure >= AUTH_FAILURE_WINDOW_SECONDS:
                    self._failures.pop(key, None)

            prior = self._failures.get(client)
            failures = prior[0] + 1 if prior else 1
            lockout_seconds = 0.0
            if failures >= AUTH_FAILURE_LIMIT:
                exponent = (failures - AUTH_FAILURE_LIMIT) // AUTH_FAILURE_LIMIT
                lockout_seconds = min(
                    AUTH_LOCKOUT_BASE_SECONDS * (2**min(exponent, 6)),
                    AUTH_LOCKOUT_MAX_SECONDS,
                )
            self._failures[client] = (
                failures,
                current,
                current + lockout_seconds,
            )

            if len(self._failures) > AUTH_TRACKED_CLIENT_LIMIT:
                oldest = min(
                    self._failures,
                    key=lambda key: self._failures[key][1],
                )
                self._failures.pop(oldest, None)

    def record_success(self, client: str) -> None:
        with self._lock:
            self._failures.pop(client, None)
