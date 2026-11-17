import hashlib
import io
import json
import lzma
import math
import os
import threading
import time
from collections import Counter
from pathlib import Path

import py7zr
import pyzipper
from py7zr.exceptions import (
    Bad7zFile,
    CrcError,
    DecompressionBombError,
    DecompressionError,
    PasswordRequired,
    UnsupportedCompressionMethodError,
)

SCAN_CHUNK_SIZE = 1024 * 1024
MAX_FOLDER_SCAN_FILES = 5000
MAX_FOLDER_SCAN_DIRECTORIES = 20_000
MAX_SCAN_FILE_BYTES = 300 * 1024 * 1024
DEFAULT_MAX_FILE_BYTES = MAX_SCAN_FILE_BYTES
DEFAULT_MAX_FOLDER_BYTES = 5 * 1024 * 1024 * 1024
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


class _SevenZipMemoryWriter(py7zr.Py7zIO):
    def __init__(self, factory):
        self.factory = factory
        self.buffer = io.BytesIO()

    def write(self, s):
        if self.factory.is_cancelled is not None and self.factory.is_cancelled():
            raise InterruptedError("7z scan was cancelled.")
        if time.monotonic() >= self.factory.deadline:
            raise TimeoutError("7z scan timed out.")
        position = self.buffer.tell()
        current_size = self.buffer.getbuffer().nbytes
        new_size = max(current_size, position + len(s))
        if new_size > self.factory.max_file_bytes:
            raise ValueError("A 7z entry exceeds the configured per-file scan limit.")
        with self.factory.lock:
            added_size = new_size - current_size
            if self.factory.total_bytes + added_size > self.factory.max_total_bytes:
                raise ValueError("7z archive exceeds the bounded in-memory scan limit.")
            self.factory.total_bytes += added_size
        return self.buffer.write(s)

    def read(self, size=None):
        return self.buffer.read(size)

    def seek(self, offset, whence=0):
        return self.buffer.seek(offset, whence)

    def flush(self):
        self.buffer.flush()

    def size(self):
        return self.buffer.getbuffer().nbytes

    def close(self):
        pass


class _SevenZipMemoryWriterFactory(py7zr.WriterFactory):
    def __init__(self, max_file_bytes, max_total_bytes, deadline, is_cancelled):
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.deadline = deadline
        self.is_cancelled = is_cancelled
        self.total_bytes = 0
        self.lock = threading.Lock()
        self.products = []

    def create(self, filename):
        writer = _SevenZipMemoryWriter(self)
        self.products.append((filename, writer))
        return writer


class StaticScanner:
    def __init__(self):
        try:
            import yara
            self.yara = yara
        except ImportError:
            self.yara = None
        signature_path = Path(__file__).with_name("rules") / "file_signatures.json"
        document = json.loads(signature_path.read_text(encoding="utf-8"))
        if (
            not isinstance(document, dict)
            or document.get("schema_version") != 1
            or not isinstance(document.get("signatures"), list)
        ):
            raise ValueError(f"Invalid file signature catalog: {signature_path}")
        self.signatures = []
        seen_ids = set()
        for signature in document["signatures"]:
            if not isinstance(signature, dict):
                raise ValueError(f"Invalid entry in file signature catalog: {signature_path}")
            signature_id = signature.get("id")
            try:
                pattern = bytes.fromhex(signature["pattern_hex"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"Invalid pattern in file signature catalog: {signature_path}") from exc
            if (
                not isinstance(signature_id, str)
                or not signature_id
                or signature_id in seen_ids
                or not pattern
                or not isinstance(signature.get("name"), str)
                or not isinstance(signature.get("description"), str)
                or signature.get("classification") not in {"antivirus_test", "suspicious"}
            ):
                raise ValueError(f"Invalid entry in file signature catalog: {signature_path}")
            seen_ids.add(signature_id)
            self.signatures.append({**signature, "pattern": pattern})

    def scan_file(
        self,
        path: Path,
        *,
        protected_roots: list[Path] | None = None,
        max_bytes: int = DEFAULT_MAX_FILE_BYTES,
        timeout_seconds: float = 180.0,
        is_cancelled=None,
    ) -> dict:
        max_bytes = min(max_bytes, MAX_SCAN_FILE_BYTES)
        path = Path(path)
        if is_protected_system_path(path, protected_roots=protected_roots):
            raise ProtectedSystemPathError("Windows system and protected application files are excluded from file scans.")
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(path)
        size = path.stat().st_size
        if size > max_bytes:
            raise ValueError(f"File exceeds the configured scan limit of {max_bytes} bytes.")
        with path.open("rb") as stream:
            return self.scan_stream(
                stream,
                str(path),
                suffix=path.suffix.lower(),
                max_bytes=max_bytes,
                timeout_seconds=timeout_seconds,
                is_cancelled=is_cancelled,
            )

    def scan_zip(
        self,
        path: Path,
        password: str,
        *,
        max_archive_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_total_bytes: int = DEFAULT_MAX_FOLDER_BYTES,
        max_files: int = MAX_FOLDER_SCAN_FILES,
        timeout_seconds: float = 180.0,
        is_cancelled=None,
    ) -> dict:
        max_archive_bytes = min(max_archive_bytes, MAX_SCAN_FILE_BYTES)
        max_file_bytes = min(max_file_bytes, MAX_SCAN_FILE_BYTES)
        target = Path(path).expanduser()
        try:
            resolved = target.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise FileNotFoundError(f"Could not resolve the selected ZIP archive: {exc}") from exc
        if is_protected_system_path(resolved):
            raise ProtectedSystemPathError(
                "Windows system and protected application files are excluded from file scans."
            )
        if not resolved.is_file():
            raise ValueError("ZIP scanning requires a single existing file.")
        if resolved.suffix.casefold() != ".zip":
            raise ValueError("Only ZIP archives are supported by this scan operation.")
        if resolved.stat().st_size > max_archive_bytes:
            raise ValueError(f"ZIP archive exceeds the configured {max_archive_bytes}-byte limit.")

        password_bytes = password.encode("utf-8") if password else None
        started_at = time.monotonic()
        try:
            with pyzipper.AESZipFile(str(resolved)) as archive:
                files = [info for info in archive.infolist() if not info.is_dir()]
                if len(files) > max_files:
                    raise ValueError(f"ZIP archive exceeds the configured {max_files}-file limit.")
                encrypted_files = sum(bool(info.flag_bits & 0x1) for info in files)
                if encrypted_files and password_bytes is None:
                    raise ValueError("Enter the archive password to scan its encrypted entries.")

                results = []
                total_uncompressed_bytes = 0
                for info in files:
                    if info.file_size > max_file_bytes:
                        raise ValueError(
                            f"ZIP entry {info.filename!r} exceeds the configured "
                            f"{max_file_bytes}-byte file limit."
                        )
                    remaining_total = max_total_bytes - total_uncompressed_bytes
                    if info.file_size > remaining_total:
                        raise ValueError(
                            f"ZIP archive exceeds the configured {max_total_bytes}-byte "
                            "total uncompressed limit."
                        )
                    remaining_timeout = timeout_seconds - (time.monotonic() - started_at)
                    if remaining_timeout <= 0:
                        raise TimeoutError("ZIP scan timed out.")
                    if is_cancelled is not None and is_cancelled():
                        raise InterruptedError("ZIP scan was cancelled.")

                    member_password = password_bytes if info.flag_bits & 0x1 else None
                    with archive.open(info, pwd=member_password) as stream:
                        result = self.scan_stream(
                            stream,
                            f"{resolved.name}!/{info.filename}",
                            suffix=Path(info.filename).suffix.lower(),
                            max_bytes=min(max_file_bytes, remaining_total),
                            timeout_seconds=remaining_timeout,
                            is_cancelled=is_cancelled,
                        )
                    total_uncompressed_bytes += result["size"]
                    results.append(result)
        except NotImplementedError as exc:
            raise ValueError(
                "This ZIP encryption or compression method is not supported."
            ) from exc
        except RuntimeError as exc:
            if any(
                marker in str(exc).casefold()
                for marker in ("bad password", "bad hmac")
            ):
                raise ValueError("The supplied password could not decrypt the ZIP entries.") from exc
            raise
        except pyzipper.BadZipFile as exc:
            raise ValueError("The ZIP archive is invalid, corrupt, or could not be decrypted.") from exc

        return {
            "path": str(resolved),
            "entries_scanned": len(results),
            "encrypted_entries": encrypted_files,
            "results": results,
            "message": (
                "ZIP entries were scanned locally as streams; decrypted files were not saved or executed. "
                "These heuristic results are not a malware verdict."
            ),
        }

    def scan_7z(
        self,
        path: Path,
        password: str,
        *,
        max_archive_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_total_bytes: int = DEFAULT_MAX_FOLDER_BYTES,
        max_files: int = MAX_FOLDER_SCAN_FILES,
        timeout_seconds: float = 180.0,
        is_cancelled=None,
    ) -> dict:
        max_archive_bytes = min(max_archive_bytes, MAX_SCAN_FILE_BYTES)
        max_file_bytes = min(max_file_bytes, MAX_SCAN_FILE_BYTES)
        target = Path(path).expanduser()
        try:
            resolved = target.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise FileNotFoundError(f"Could not resolve the selected 7z archive: {exc}") from exc
        if is_protected_system_path(resolved):
            raise ProtectedSystemPathError(
                "Windows system and protected application files are excluded from file scans."
            )
        if not resolved.is_file():
            raise ValueError("7z scanning requires a single existing file.")
        if resolved.suffix.casefold() != ".7z":
            raise ValueError("Only 7z archives are supported by this scan operation.")
        if resolved.stat().st_size > max_archive_bytes:
            raise ValueError(f"7z archive exceeds the configured {max_archive_bytes}-byte limit.")

        started_at = time.monotonic()
        memory_limit = min(max_total_bytes, DEFAULT_MAX_FILE_BYTES)
        try:
            with resolved.open("rb") as archive_stream:
                with py7zr.SevenZipFile(
                    archive_stream,
                    mode="r",
                    password=password or None,
                    max_extract_size=memory_limit,
                ) as archive:
                    files = [info for info in archive.list() if not info.is_directory]
                    if len(files) > max_files:
                        raise ValueError(f"7z archive exceeds the configured {max_files}-file limit.")
                    encrypted_files = len(files) if archive.needs_password() else 0
                    if encrypted_files and not password:
                        raise ValueError("Enter the archive password to scan its encrypted entries.")
                    total_declared_bytes = 0
                    for info in files:
                        if info.uncompressed > max_file_bytes:
                            raise ValueError(
                                f"7z entry {info.filename!r} exceeds the configured "
                                f"{max_file_bytes}-byte file limit."
                            )
                        total_declared_bytes += info.uncompressed
                        if total_declared_bytes > memory_limit:
                            raise ValueError("7z archive exceeds the bounded in-memory scan limit.")

                    factory = _SevenZipMemoryWriterFactory(
                        max_file_bytes,
                        memory_limit,
                        started_at + timeout_seconds,
                        is_cancelled,
                    )
                    archive.extractall(factory=factory)
                    if len(factory.products) != len(files):
                        raise ValueError("7z extraction did not produce a complete member list.")

                    results = []
                    total_uncompressed_bytes = 0
                    for (name, writer), info in zip(factory.products, files):
                        remaining_total = memory_limit - total_uncompressed_bytes
                        remaining_timeout = timeout_seconds - (time.monotonic() - started_at)
                        if remaining_timeout <= 0:
                            raise TimeoutError("7z scan timed out.")
                        if is_cancelled is not None and is_cancelled():
                            raise InterruptedError("7z scan was cancelled.")
                        writer.seek(0)
                        result = self.scan_stream(
                            writer,
                            f"{resolved.name}!/{name}",
                            suffix=Path(name).suffix.lower(),
                            max_bytes=min(max_file_bytes, remaining_total),
                            timeout_seconds=remaining_timeout,
                            is_cancelled=is_cancelled,
                        )
                        if result["size"] != info.uncompressed:
                            raise ValueError(f"7z entry {name!r} was not completely decrypted.")
                        total_uncompressed_bytes += result["size"]
                        results.append(result)
        except PasswordRequired as exc:
            raise ValueError("Enter the archive password to scan its encrypted entries.") from exc
        except (lzma.LZMAError, CrcError, DecompressionError) as exc:
            raise ValueError(
                "The 7z password is incorrect, or the archive is corrupt."
            ) from exc
        except Bad7zFile as exc:
            raise ValueError("The 7z archive is invalid, corrupt, or could not be decrypted.") from exc
        except DecompressionBombError as exc:
            raise ValueError("7z archive exceeds the bounded in-memory scan limit.") from exc
        except UnsupportedCompressionMethodError as exc:
            raise ValueError("This 7z compression method is not supported.") from exc

        return {
            "path": str(resolved),
            "entries_scanned": len(results),
            "encrypted_entries": encrypted_files,
            "results": results,
            "message": (
                "7z entries were decrypted into bounded local memory for scanning; "
                "plaintext files were not written to disk or executed. "
                "These heuristic results are not a malware verdict."
            ),
        }

    def scan_stream(
        self,
        stream,
        name: str,
        *,
        suffix: str | None = None,
        max_bytes: int = DEFAULT_MAX_FILE_BYTES,
        timeout_seconds: float = 180.0,
        is_cancelled=None,
    ) -> dict:
        max_bytes = min(max_bytes, MAX_SCAN_FILE_BYTES)
        if has_protected_folder_name(name):
            raise ProtectedSystemPathError("Windows system and protected application files are excluded from file scans.")
        digest = hashlib.sha256()
        entropy_counts = Counter()
        sample = bytearray()
        started_at = time.monotonic()
        marker_bytes = (
            b"virtualallocex",
            b"writeprocessmemory",
            b"powershell.exe",
            b"cmd.exe /c",
            b"create remotethread",
        )
        matched_markers = set()
        matched_signatures = set()
        maximum_pattern_length = max(
            [len(marker) for marker in marker_bytes]
            + [len(signature["pattern"]) for signature in self.signatures]
        )
        overlap = b""
        size = 0
        try:
            for chunk in iter(lambda: stream.read(SCAN_CHUNK_SIZE), b""):
                size += len(chunk)
                if size > max_bytes:
                    raise ValueError(f"File exceeds the configured scan limit of {max_bytes} bytes.")
                if is_cancelled is not None and is_cancelled():
                    raise InterruptedError("Scan was cancelled.")
                if time.monotonic() - started_at > timeout_seconds:
                    raise TimeoutError("Scan timed out.")
                digest.update(chunk)
                entropy_counts.update(chunk)
                if len(sample) < 10_000_000:
                    sample.extend(chunk[:10_000_000 - len(sample)])
                searchable = overlap + chunk.lower()
                matched_markers.update(
                    marker for marker in marker_bytes if marker in searchable
                )
                matched_signatures.update(
                    signature["id"]
                    for signature in self.signatures
                    if signature["pattern"].lower() in searchable
                )
                overlap = searchable[-(maximum_pattern_length - 1):]
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
            signature_matches=[
                {
                    "id": signature["id"],
                    "name": signature["name"],
                    "classification": signature["classification"],
                    "description": signature["description"],
                }
                for signature in self.signatures
                if signature["id"] in matched_signatures
            ],
        )

    def scan_folder(
        self,
        path: Path,
        *,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_folder_bytes: int = DEFAULT_MAX_FOLDER_BYTES,
        max_files: int | None = None,
        timeout_seconds: float = 180.0,
        is_cancelled=None,
    ) -> dict:
        max_file_bytes = min(max_file_bytes, MAX_SCAN_FILE_BYTES)
        if max_files is None:
            max_files = MAX_FOLDER_SCAN_FILES
        root = Path(path).resolve()
        system_roots = protected_system_roots()
        if is_protected_system_path(root, protected_roots=system_roots, resolve=False):
            raise ProtectedSystemPathError("Windows system and protected application folders cannot be scanned.")
        if not root.exists() or not root.is_dir():
            raise FileNotFoundError(root)

        results = []
        failures = []
        skipped = 0
        files_attempted = 0
        directories_visited = 0
        truncated = False
        folder_bytes = 0
        started_at = time.monotonic()

        def record_walk_error(error: OSError) -> None:
            failures.append({
                "name": str(getattr(error, "filename", None) or root),
                "message": str(error),
            })

        for current, directories, filenames in os.walk(
            root, followlinks=False, onerror=record_walk_error
        ):
            if is_cancelled is not None and is_cancelled():
                return self._folder_result(results, failures + [{"name": str(root), "message": "Scan was cancelled."}], skipped, truncated=True)
            if time.monotonic() - started_at > timeout_seconds:
                return self._folder_result(results, failures + [{"name": str(root), "message": "Scan timed out."}], skipped, truncated=True)
            directories_visited += 1
            if directories_visited > MAX_FOLDER_SCAN_DIRECTORIES:
                truncated = True
                break
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
                if files_attempted >= max_files:
                    truncated = True
                    directories[:] = []
                    break
                files_attempted += 1
                try:
                    file_size = candidate.stat().st_size
                except OSError as exc:
                    failures.append({"name": str(candidate), "message": str(exc)})
                    continue
                if file_size > max_file_bytes:
                    failures.append({
                        "name": str(candidate),
                        "message": f"File exceeds the configured {max_file_bytes}-byte limit.",
                    })
                    continue
                if folder_bytes + file_size > max_folder_bytes:
                    truncated = True
                    directories[:] = []
                    break
                folder_bytes += file_size
                try:
                    results.append(self.scan_file(
                        candidate,
                        protected_roots=system_roots,
                        max_bytes=max_file_bytes,
                        timeout_seconds=timeout_seconds,
                        is_cancelled=is_cancelled,
                    ))
                except InterruptedError as exc:
                    return self._folder_result(
                        results,
                        failures + [{"name": str(candidate), "message": str(exc)}],
                        skipped,
                        truncated=True,
                    )
                except TimeoutError as exc:
                    return self._folder_result(
                        results,
                        failures + [{"name": str(candidate), "message": str(exc)}],
                        skipped,
                        truncated=True,
                    )
                except (OSError, ValueError) as exc:
                    failures.append({"name": str(candidate), "message": str(exc)})
            if truncated:
                break
        return self._folder_result(results, failures, skipped, truncated=truncated)

    @staticmethod
    def _is_link_or_junction(path: Path) -> bool:
        return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())

    @staticmethod
    def _folder_result(results, failures, skipped, message=None, *, truncated=False):
        return {
            "results": results,
            "failures": failures,
            "skipped_system_paths": skipped,
            "message": message,
            "truncated": truncated,
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
        signature_matches: list[dict] | None = None,
    ) -> dict:
        score = 0.0
        reasons = []
        signature_matches = signature_matches or []
        if signature_matches:
            reasons.append("known_test_signature")
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
            "signature_matches": signature_matches,
        }
