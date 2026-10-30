import hashlib
import json
import shutil
import subprocess
import uuid
from pathlib import Path

class QuarantineManager:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def _sha256(self, path: Path):
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""): digest.update(chunk)
        return digest.hexdigest()

    def quarantine(self, source: Path) -> dict:
        source = Path(source).resolve()
        if not source.is_file():
            raise FileNotFoundError(source)
        token = uuid.uuid4().hex
        destination = self.root / f"{token}.quarantine"
        metadata_path = self.root / f"{token}.json"
        sha256 = self._sha256(source)
        shutil.copy2(source, destination)
        if self._sha256(destination) != sha256:
            destination.unlink(missing_ok=True)
            raise OSError("Quarantine copy failed integrity check")
        metadata = {"original": str(source), "quarantine_path": str(destination), "sha256": sha256, "token": token}
        metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        subprocess.run(["icacls", str(destination), "/deny", "*S-1-1-0:(X)"], check=False, capture_output=True)
        source.unlink()
        return metadata

    def restore(self, token: str) -> dict:
        safe_token = token.strip().replace("/", "").replace("\\", "")
        metadata_path = self.root / f"{safe_token}.json"
        if not metadata_path.is_file(): raise FileNotFoundError("Unknown quarantine item")
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        destination = Path(metadata["original"])
        source = Path(metadata["quarantine_path"])
        if not source.is_file(): raise FileNotFoundError(source)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        if self._sha256(destination) != metadata["sha256"]: raise OSError("Quarantined file failed integrity check")
        source.unlink()
        metadata_path.unlink()
        return {"restored": str(destination), "sha256": metadata["sha256"]}

    def delete(self, token: str) -> dict:
        safe_token = token.strip().replace("/", "").replace("\\", "")
        source = self.root / f"{safe_token}.quarantine"
        metadata = self.root / f"{safe_token}.json"
        if source.exists(): source.unlink()
        if metadata.exists(): metadata.unlink()
        return {"deleted": safe_token}
