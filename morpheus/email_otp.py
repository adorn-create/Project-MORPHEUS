import hashlib
import hmac
import secrets
import threading
import time


class EmailOtpManager:
    def __init__(self, write_file, profile_path, grant_manager):
        self.write_file = write_file
        self.profile_path = profile_path
        self.grant_manager = grant_manager
        self._lock = threading.Lock()
        self._challenge = None

    def read_profile(self):
        try:
            import json
            record = json.loads(self.profile_path.read_text(encoding="utf-8"))
            email = str(record.get("email") or "").strip().lower()
            return email if "@" in email else None
        except (OSError, json.JSONDecodeError, AttributeError, TypeError, ValueError):
            return None

    def set_profile(self, email):
        email = str(email).strip().lower()
        if len(email) > 320 or email.count("@") != 1:
            raise ValueError("Enter a valid owner email address.")
        local, domain = email.rsplit("@", 1)
        if not local or "." not in domain or any(char.isspace() for char in email):
            raise ValueError("Enter a valid owner email address.")
        self.write_file(self.profile_path, {"email": email})
        return email

    def status(self):
        email = self.read_profile()
        masked = None
        if email:
            local, domain = email.rsplit("@", 1)
            masked = f"{local[:2]}{'*' * max(2, len(local) - 2)}@{domain}"
        return {"configured": bool(email), "email_masked": masked}

    def request_otp(self, client, ttl_seconds=300):
        email = self.read_profile()
        if not email:
            raise ValueError("Configure the owner's email address first.")
        otp = f"{secrets.randbelow(1_000_000):06d}"
        with self._lock:
            self._challenge = {
                "client": client,
                "email": email,
                "otp_hash": hashlib.sha256(otp.encode("ascii")).hexdigest(),
                "expires_at": time.monotonic() + ttl_seconds,
                "attempts": 0,
            }
        return otp, email

    def verify_otp(self, otp, client, now=None):
        candidate = str(otp).strip()
        if not candidate.isascii():
            return None
        if len(candidate) != 6:
            return None
        with self._lock:
            challenge = self._challenge
            if challenge is None:
                return None
            current_time = time.monotonic() if now is None else now
            if current_time >= challenge["expires_at"] or challenge["client"] != client:
                self._challenge = None
                return None
            if challenge["attempts"] >= 5:
                self._challenge = None
                return None
            challenge["attempts"] += 1
            candidate_hash = hashlib.sha256(candidate.encode("ascii")).hexdigest()
            if not hmac.compare_digest(candidate_hash, challenge["otp_hash"]):
                return None
            self._challenge = None
        return self.grant_manager.issue_grant(client)
