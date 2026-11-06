import hashlib
import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path

class QuarantineManager:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        for category in ("files", "apps", "folders"):
            (self.root / category).mkdir(parents=True, exist_ok=True)
        self._migrate_legacy_items()

    def _migrate_legacy_items(self) -> None:
        legacy = self.root.parent / "quarantine"
        if not legacy.is_dir() or legacy.resolve() == self.root.resolve():
            return
        for metadata_path in list(legacy.glob("*.json")):
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                token = metadata["token"]
                source = Path(metadata["quarantine_path"])
                category = "apps" if Path(metadata["original"]).suffix.casefold() in {".exe", ".dll", ".sys", ".com"} else "files"
                category_root = self.root / category
                if source.is_file():
                    destination = category_root / f"{token}.quarantine"
                    if not destination.exists():
                        shutil.move(str(source), str(destination))
                    metadata["quarantine_path"] = str(destination)
                    metadata["category"] = category
                    (category_root / f"{token}.json").write_text(
                        json.dumps(metadata, indent=2),
                        encoding="utf-8",
                    )
            except (KeyError, OSError, json.JSONDecodeError):
                continue
            metadata_path.unlink(missing_ok=True)

    def _sha256(self, path: Path):
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""): digest.update(chunk)
        return digest.hexdigest()

    def _folder_manifest(self, folder: Path) -> dict[str, str]:
        manifest: dict[str, str] = {}
        for path in sorted(folder.rglob("*")):
            if path.is_file():
                try:
                    manifest[path.relative_to(folder).as_posix()] = self._sha256(path)
                except OSError:
                    continue
        return manifest

    def quarantine_folder(self, source: Path) -> dict:
        source = Path(source).resolve()
        if not source.is_dir():
            raise FileNotFoundError("Isolation requires an existing folder.")
        if source == self.root or self.root in source.parents:
            raise ValueError("The Morpheus isolated folder cannot be isolated.")
        if source == source.anchor:
            raise ValueError("A drive root cannot be isolated.")

        token = uuid.uuid4().hex
        category_root = self.root / "folders"
        destination = category_root / f"{token}.folder"
        metadata_path = category_root / f"{token}.json"
        manifest = self._folder_manifest(source)
        shutil.move(str(source), str(destination))
        if not destination.is_dir():
            raise OSError("Folder isolation move failed.")
        if os.name == "nt":
            subprocess.run(
                ["icacls", str(destination), "/inheritance:r", "/deny", "*S-1-1-0:(OI)(CI)(X)"],
                check=False,
                capture_output=True,
                timeout=10,
            )
        metadata = {
            "original": str(source),
            "quarantine_path": str(destination),
            "sha256": manifest,
            "token": token,
            "category": "folders",
            "kind": "folder",
        }
        metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        return metadata

    def quarantine(self, source: Path, category: str | None = None) -> dict:
        source = Path(source).resolve()
        if not source.is_file():
            raise FileNotFoundError(source)
        if category is None:
            category = "apps" if source.suffix.casefold() in {".exe", ".dll", ".sys", ".com"} else "files"
        if category not in {"files", "apps", "folders"}:
            raise ValueError("Invalid isolation category")
        token = uuid.uuid4().hex
        category_root = self.root / category
        destination = category_root / f"{token}.quarantine"
        metadata_path = category_root / f"{token}.json"
        sha256 = self._sha256(source)
        shutil.copy2(source, destination)
        if self._sha256(destination) != sha256:
            destination.unlink(missing_ok=True)
            raise OSError("Quarantine copy failed integrity check")
        metadata = {
            "original": str(source),
            "quarantine_path": str(destination),
            "sha256": sha256,
            "token": token,
            "category": category,
        }
        metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        if os.name == "nt":
            subprocess.run(
                ["icacls", str(destination), "/inheritance:r", "/deny", "*S-1-1-0:(X)"],
                check=False,
                capture_output=True,
                timeout=10,
            )
        source.unlink()
        return metadata

    def restore(self, token: str) -> dict:
        safe_token = token.strip().replace("/", "").replace("\\", "")
        metadata_path = next(self.root.rglob(f"{safe_token}.json"), None)
        if metadata_path is None or not metadata_path.is_file(): raise FileNotFoundError("Unknown quarantine item")
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        destination = Path(metadata["original"])
        source = Path(metadata["quarantine_path"])
        if metadata.get("kind") == "folder":
            if not source.is_dir():
                raise FileNotFoundError(source)
            if destination.exists():
                raise FileExistsError(destination)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(source), str(destination))
            if os.name == "nt":
                subprocess.run(
                    ["icacls", str(destination), "/reset"],
                    check=False,
                    capture_output=True,
                    timeout=10,
                )
            source_manifest = self._folder_manifest(destination)
            if source_manifest != metadata["sha256"]:
                raise OSError("Isolated folder failed integrity check")
            metadata_path.unlink()
            return {"restored": str(destination), "kind": "folder"}
        if not source.is_file(): raise FileNotFoundError(source)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            subprocess.run(
                ["icacls", str(source), "/reset"],
                check=False,
                capture_output=True,
                timeout=10,
            )
        shutil.copy2(source, destination)
        if self._sha256(destination) != metadata["sha256"]: raise OSError("Quarantined file failed integrity check")
        source.unlink()
        metadata_path.unlink()
        return {"restored": str(destination), "sha256": metadata["sha256"]}

    def delete(self, token: str) -> dict:
        safe_token = token.strip().replace("/", "").replace("\\", "")
        source = next(
            (path for suffix in ("*.quarantine", "*.folder") for path in self.root.rglob(suffix)
             if path.stem == safe_token),
            None,
        )
        metadata = next(self.root.rglob(f"{safe_token}.json"), None)
        if source is not None and source.is_dir():
            shutil.rmtree(source)
        elif source is not None and source.exists():
            source.unlink()
        if metadata is not None and metadata.exists(): metadata.unlink()
        return {"deleted": safe_token}
