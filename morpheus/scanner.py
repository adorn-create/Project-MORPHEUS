import hashlib
import math
import os
from collections import Counter
from pathlib import Path

MAX_SCAN_FILE_SIZE = 100 * 1024 * 1024
MAX_FOLDER_SCAN_FILES = 10_000
MAX_FOLDER_SCAN_BYTES = 30 * 1024 * 1024 * 1024
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
        digest = hashlib.sha256()
        entropy_counts = Counter()
        entropy_size = 0
        sample = bytearray()
        size = 0
        try:
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    size += len(chunk)
                    if size > MAX_SCAN_FILE_SIZE:
                        limit_mb = MAX_SCAN_FILE_SIZE // (1024 * 1024)
                        raise ValueError(f"File exceeds the {limit_mb} MB per-file scan limit.")
                    digest.update(chunk)
                    if entropy_size < 2_000_000:
                        entropy_chunk = chunk[:2_000_000 - entropy_size]
                        entropy_counts.update(entropy_chunk)
                        entropy_size += len(entropy_chunk)
                    if len(sample) < 10_000_000:
                        sample.extend(chunk[:10_000_000 - len(sample)])
        except MemoryError as exc:
            raise OSError("Insufficient memory to scan this file.") from exc
        value = self._entropy_from_counts(entropy_counts, entropy_size)
        return self._result(str(path), path.suffix.lower(), size, value, digest.hexdigest(), bytes(sample).lower())

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
        total_bytes = 0
        visited_entries = 0
        for current, directories, filenames in os.walk(root, followlinks=False):
            current_path = Path(current).resolve()
            visited_entries += len(directories) + len(filenames)
            if visited_entries > MAX_FOLDER_SCAN_FILES * 2:
                return self._folder_result(results, failures, skipped, "Folder scan stopped at the 10,000-file limit.")
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
                if len(results) + len(failures) >= MAX_FOLDER_SCAN_FILES:
                    return self._folder_result(results, failures, skipped, "Folder scan stopped at the 10,000-file limit.")
                try:
                    size = candidate.stat().st_size
                    if size > MAX_SCAN_FILE_SIZE:
                        failures.append({"name": str(candidate), "message": "File exceeds the 100 MB per-file scan limit."})
                        continue
                    if total_bytes + size > MAX_FOLDER_SCAN_BYTES:
                        return self._folder_result(results, failures, skipped, "Folder scan stopped at the 30 GB total scan limit.")
                    total_bytes += size
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
        if len(content) > MAX_SCAN_FILE_SIZE:
            limit_mb = MAX_SCAN_FILE_SIZE // (1024 * 1024)
            raise ValueError(f"File exceeds the {limit_mb} MB per-file scan limit.")
        if has_protected_folder_name(name):
            raise ProtectedSystemPathError("Windows system and protected application files are excluded from file scans.")
        entropy_sample = content[:2_000_000]
        value = self._entropy_from_counts(Counter(entropy_sample), len(entropy_sample))
        return self._result(
            name,
            Path(name).suffix.lower(),
            len(content),
            value,
            hashlib.sha256(content).hexdigest(),
            content[:10_000_000].lower(),
        )

    @staticmethod
    def _entropy_from_counts(counts: Counter, sample_size: int) -> float:
        if sample_size == 0:
            return 0.0
        return -sum(
            (count / sample_size) * math.log2(count / sample_size)
            for count in counts.values()
        )

    @staticmethod
    def _result(name: str, suffix: str, size: int, value: float, digest: str, sample: bytes) -> dict:
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
