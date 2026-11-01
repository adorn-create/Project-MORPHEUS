import hashlib
import io
import math
import os
from collections import Counter
from pathlib import Path

SCAN_CHUNK_SIZE = 1024 * 1024
PROTECTED_DIRECTORY_NAMES = {
    "$recycle.bin", "$winreagent", "boot", "config.msi", "efi",
    "msocache", "program files", "program files (x86)", "programdata",
    "recovery", "system volume information", "windows",
}
PROTECTED_SYSTEM_FILE_NAMES = {
    "boot.ini", "bootmgr", "bootnxt", "hiberfil.sys", "ntldr",
    "pagefile.sys", "swapfile.sys",
}
PROTECTED_UPLOAD_DIRECTORY_NAMES = {
    "system32", "syswow64", "winsxs", "systemapps", "driverstore",
    "softwaredistribution",
}


class ProtectedSystemPathError(ValueError):
    pass


def protected_system_roots() -> list[Path]:
    values = (
        os.environ.get("WINDIR"),
        os.environ.get("SystemRoot"),
        os.environ.get("ProgramFiles"),
        os.environ.get("ProgramFiles(x86)"),
        os.environ.get("ProgramW6432"),
        os.environ.get("ProgramData"),
    )
    roots = []
    for value in values:
        if value:
            root = Path(os.path.expandvars(value)).resolve()
            if root not in roots:
                roots.append(root)
    if os.name == "nt" and not any(root.name.casefold() == "windows" for root in roots):
        roots.append(Path(os.environ.get("WINDIR", "C:/Windows")).resolve())
    return roots


def is_protected_system_path(
    path: Path,
    *,
    protected_roots: list[Path] | None = None,
    resolve: bool = True,
) -> bool:
    candidate = Path(path)
    resolved = candidate.resolve() if resolve or not candidate.is_absolute() else candidate
    roots = protected_roots if protected_roots is not None else protected_system_roots()
    for root in roots:
        try:
            resolved.relative_to(root)
            return True
        except ValueError:
            continue
    return (
        any(os.path.normcase(part) in PROTECTED_DIRECTORY_NAMES for part in resolved.parts)
        or resolved.name.casefold() in PROTECTED_SYSTEM_FILE_NAMES
    )


def has_protected_folder_name(path: str) -> bool:
    parts = Path(path.replace("\\", "/")).parts
    return any(
        part.casefold() in PROTECTED_DIRECTORY_NAMES
        or part.casefold() in PROTECTED_SYSTEM_FILE_NAMES
        or part.casefold() in PROTECTED_UPLOAD_DIRECTORY_NAMES
        for part in parts
    )

class StaticScanner:
    def __init__(self):
        try:
            import yara
            self.yara = yara
        except ImportError:
            self.yara = None

    def scan_file(self, path: Path, *, protected_roots: list[Path] | None = None) -> dict:
        path = Path(path)
        if is_protected_system_path(path, protected_roots=protected_roots):
            raise ProtectedSystemPathError("Windows system and protected application files are excluded from file scans.")
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(path)
        with path.open("rb") as stream:
            return self.scan_stream(stream, str(path), suffix=path.suffix.lower())

    def scan_stream(self, stream, name: str, *, suffix: str | None = None) -> dict:
        if has_protected_folder_name(name):
            raise ProtectedSystemPathError("Windows system and protected application files are excluded from file scans.")
        digest = hashlib.sha256()
        entropy_counts = Counter()
        sample = bytearray()
        marker_bytes = (
            b"virtualallocex",
            b"writeprocessmemory",
            b"powershell.exe",
            b"cmd.exe /c",
            b"create remotethread",
        )
        matched_markers = set()
        overlap = b""
        size = 0
        try:
            for chunk in iter(lambda: stream.read(SCAN_CHUNK_SIZE), b""):
                size += len(chunk)
                digest.update(chunk)
                entropy_counts.update(chunk)
                if len(sample) < 10_000_000:
                    sample.extend(chunk[:10_000_000 - len(sample)])
                searchable = overlap + chunk.lower()
                matched_markers.update(
                    marker for marker in marker_bytes if marker in searchable
                )
                overlap = searchable[-max(map(len, marker_bytes)):]
        except MemoryError as exc:
            raise OSError("Insufficient memory to scan this file.") from exc
        value = self._entropy_from_counts(entropy_counts, size)
        return self._result(
            name,
            suffix if suffix is not None else Path(name).suffix.lower(),
            size,
            value,
            digest.hexdigest(),
            bytes(sample).lower(),
            marker_count=len(matched_markers),
        )

    def scan_folder(self, path: Path) -> dict:
        root = Path(path).resolve()
        system_roots = protected_system_roots()
        if is_protected_system_path(root, protected_roots=system_roots, resolve=False):
            raise ProtectedSystemPathError("Windows system and protected application folders cannot be scanned.")
        if not root.exists() or not root.is_dir():
            raise FileNotFoundError(root)

        results = []
        failures = []
        skipped = 0

        def record_walk_error(error: OSError) -> None:
            failures.append({
                "name": str(getattr(error, "filename", None) or root),
                "message": str(error),
            })

        for current, directories, filenames in os.walk(
            root, followlinks=False, onerror=record_walk_error
        ):
            current_path = Path(current).resolve()
            retained_directories = []
            for directory in directories:
                candidate_directory = current_path / directory
                if self._is_link_or_junction(candidate_directory) or is_protected_system_path(
                    candidate_directory, protected_roots=system_roots, resolve=False
                ):
                    skipped += 1
                else:
                    retained_directories.append(directory)
            directories[:] = retained_directories
            for filename in filenames:
                candidate = current_path / filename
                if self._is_link_or_junction(candidate) or is_protected_system_path(
                    candidate, protected_roots=system_roots, resolve=False
                ):
                    skipped += 1
                    continue
                try:
                    results.append(self.scan_file(candidate, protected_roots=system_roots))
                except (OSError, ValueError) as exc:
                    failures.append({"name": str(candidate), "message": str(exc)})
        return self._folder_result(results, failures, skipped)

    @staticmethod
    def _is_link_or_junction(path: Path) -> bool:
        return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())

    @staticmethod
    def _folder_result(results, failures, skipped, message=None):
        return {
            "results": results,
            "failures": failures,
            "skipped_system_paths": skipped,
            "message": message,
        }

    def scan_bytes(self, content: bytes, name: str) -> dict:
        return self.scan_stream(io.BytesIO(content), name)

    @staticmethod
    def _entropy_from_counts(counts: Counter, sample_size: int) -> float:
        if sample_size == 0:
            return 0.0
        return -sum(
            (count / sample_size) * math.log2(count / sample_size)
            for count in counts.values()
        )

    @staticmethod
    def _result(
        name: str,
        suffix: str,
        size: int,
        value: float,
        digest: str,
        sample: bytes,
        *,
        marker_count: int | None = None,
    ) -> dict:
        score = 0.0
        reasons = []
        if suffix in {".exe", ".dll", ".scr", ".com", ".ps1", ".js", ".vbs", ".hta"}:
            score += 0.15
            reasons.append("executable_or_script_type")
        if size > 0 and value >= 7.7:
            score += 0.35
            reasons.append("high_entropy")
        if suffix in {".exe", ".dll"} and size < 2048:
            score += 0.20
            reasons.append("implausibly_small_native_file")
        suspicious_markers = (b"virtualallocex", b"writeprocessmemory", b"powershell.exe", b"cmd.exe /c", b"create remotethread")
        if marker_count is None:
            marker_count = sum(marker in sample for marker in suspicious_markers)
        if marker_count:
            score += min(marker_count * 0.12, 0.48)
            reasons.append("suspicious_native_marker")
        return {
            "path": name,
            "sha256": digest,
            "size": size,
            "entropy": round(value, 3),
            "confidence": min(score, 1.0),
            "reasons": reasons,
        }
