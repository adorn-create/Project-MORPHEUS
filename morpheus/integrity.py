import hashlib
import json
import hmac
import os
from pathlib import Path


_UNLOADED = object()


class EvidenceJournal:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = root / "audit.jsonl"
        key = os.environ.get("MORPHEUS_AUDIT_KEY")
        if not key:
            key_path = root / "audit.key"
            if key_path.exists():
                key = key_path.read_text(encoding="ascii").strip()
            else:
                key = hashlib.sha256(os.urandom(32)).hexdigest()
                key_path.write_text(key, encoding="ascii")
        self.key = key.encode("ascii")
        self._last_hash_cache = _UNLOADED
        self._last_verification = None

    def append(self, event: dict):
        payload = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature = hmac.new(self.key, payload, hashlib.sha256).hexdigest()
        previous_hash = self._last_hash()
        record = {"previous_hash": previous_hash, "payload_sha256": hashlib.sha256(payload).hexdigest(), "signature": signature, "event": event}
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        with self.path.open("ab") as stream:
            stream.write(encoded + b"\n")
        self._last_hash_cache = record["payload_sha256"]
        self._last_verification = None
        return record["payload_sha256"]

    def verify(self):
        previous = None
        count = 0
        try:
            stream = self.path.open("rb")
        except FileNotFoundError:
            result = {"valid": True, "count": 0}
            self._last_verification = result
            return result
        with stream:
            for line in stream:
                try:
                    record = json.loads(line)
                    if record["previous_hash"] != previous:
                        result = {"valid": False, "count": count}
                        self._last_verification = result
                        return result
                    payload = json.dumps(record["event"], sort_keys=True, separators=(",", ":")).encode("utf-8")
                    if record["payload_sha256"] != hashlib.sha256(payload).hexdigest():
                        result = {"valid": False, "count": count}
                        self._last_verification = result
                        return result
                    expected = hmac.new(self.key, payload, hashlib.sha256).hexdigest()
                    if not hmac.compare_digest(record["signature"], expected):
                        result = {"valid": False, "count": count}
                        self._last_verification = result
                        return result
                    previous = record["payload_sha256"]
                    count += 1
                except (json.JSONDecodeError, KeyError, TypeError):
                    result = {"valid": False, "count": count}
                    self._last_verification = result
                    return result
        self._last_hash_cache = previous
        result = {"valid": True, "count": count}
        self._last_verification = result
        return result

    def status(self):
        if self._last_verification is None:
            return {"checked": False, "valid": None, "verified_records": 0}
        return {
            "checked": True,
            "valid": self._last_verification["valid"],
            "verified_records": self._last_verification["count"],
        }

    def _last_hash(self):
        if self._last_hash_cache is not _UNLOADED:
            return self._last_hash_cache
        try:
            with self.path.open("rb") as stream:
                stream.seek(0, os.SEEK_END)
                position = stream.tell() - 1
                while position >= 0:
                    stream.seek(position)
                    if stream.read(1) != b"\n":
                        break
                    position -= 1
                while position >= 0:
                    stream.seek(position)
                    if stream.read(1) == b"\n":
                        position += 1
                        break
                    position -= 1
                stream.seek(position + 1 if position < 0 else position)
                line = stream.readline()
            value = json.loads(line)["payload_sha256"] if line.strip() else None
        except FileNotFoundError:
            value = None
        self._last_hash_cache = value
        return value
