import os
import re
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path

from .scanner import ProtectedSystemPathError, is_protected_system_path

STATUS_CACHE_SECONDS = 60
SCAN_TIMEOUT_SECONDS = 180
UPDATE_TIMEOUT_SECONDS = 300
STALE_DATABASE_DAYS = 7
VERSION_PATTERN = re.compile(r"^ClamAV\s+(.+?)(?:/(\d+)/(.+))?$")


class ClamAVScanner:
    def __init__(
        self,
        executable: str | Path | None = None,
        *,
        binary_directory: str | Path | None = None,
        data_directory: str | Path | None = None,
    ):
        self.executable = Path(executable) if executable else None
        self.binary_directory = Path(binary_directory) if binary_directory else None
        self.data_directory = Path(data_directory) if data_directory else None
        self._checked_at: float | None = None
        self._status = {
            "available": False,
            "executable": None,
            "engine_version": None,
            "database_version": None,
            "database_updated": None,
            "database_age_days": None,
            "database_ready": False,
            "updater_available": False,
            "message": "ClamAV is unavailable.",
            "last_error": None,
        }

    def _find_executable(self) -> Path | None:
        if self.executable is not None:
            return self.executable if self.executable.is_file() else None
        if self.binary_directory is not None:
            bundled = self.binary_directory / "clamscan.exe"
            if bundled.is_file():
                return bundled.resolve()
        for candidate in (
            shutil.which("clamscan.exe"),
            shutil.which("clamscan"),
            str(Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "ClamAV" / "clamscan.exe"),
            str(Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "ClamAV" / "clamscan.exe"),
        ):
            if candidate:
                path = Path(candidate)
                if path.is_file():
                    return path.resolve()
        return None

    def _find_updater(self) -> Path | None:
        if self.binary_directory is not None:
            bundled = self.binary_directory / "freshclam.exe"
            if bundled.is_file():
                return bundled.resolve()
        for candidate in (
            shutil.which("freshclam.exe"),
            shutil.which("freshclam"),
            str(Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "ClamAV" / "freshclam.exe"),
            str(Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "ClamAV" / "freshclam.exe"),
        ):
            if candidate:
                path = Path(candidate)
                if path.is_file():
                    return path.resolve()
        return None

    def _uses_bundled_tools(self, executable: Path | None) -> bool:
        return (
            executable is not None
            and self.binary_directory is not None
            and executable.parent == self.binary_directory.resolve()
        )

    def _database_files_present(self) -> bool:
        if self.data_directory is None or not self.data_directory.is_dir():
            return False
        return any(
            path.is_file()
            for pattern in ("*.cvd", "*.cld")
            for path in self.data_directory.glob(pattern)
        )

    def _database_arguments(self, executable: Path) -> list[str]:
        if self._uses_bundled_tools(executable) and self.data_directory is not None:
            return ["--database", str(self.data_directory)]
        return []

    def status(self, *, force: bool = False) -> dict:
        now = time.monotonic()
        if (
            not force
            and self._checked_at is not None
            and now - self._checked_at < STATUS_CACHE_SECONDS
        ):
            return dict(self._status)
        self._checked_at = now
        executable = self._find_executable()
        updater = self._find_updater()
        updater_available = updater is not None
        if executable is None:
            self._status = {
                "available": False,
                "executable": None,
                "engine_version": None,
                "database_version": None,
                "database_updated": None,
                "database_age_days": None,
                "database_ready": False,
                "updater_available": updater_available,
                "message": "ClamAV is not installed or clamscan.exe is not on PATH.",
                "last_error": None,
            }
            return dict(self._status)
        try:
            result = subprocess.run(
                [str(executable), "--version", *self._database_arguments(executable)],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode:
                detail = result.stderr.strip() or "ClamAV version check failed."
                raise RuntimeError(detail[:500])
            output = result.stdout.strip()
            match = VERSION_PATTERN.fullmatch(output)
            if match is None:
                raise RuntimeError("ClamAV returned an unrecognized version and signature-database status.")
            engine_version, database_version, database_updated = match.groups()
            database_age_days = None
            if database_updated:
                try:
                    updated_at = datetime.strptime(database_updated, "%a %b %d %H:%M:%S %Y")
                except ValueError:
                    pass
                else:
                    database_age_days = max(0, (datetime.now() - updated_at).days)
            if database_age_days is None:
                database_message = "No signature database has been reported yet."
            elif database_age_days > STALE_DATABASE_DAYS:
                database_message = (
                    f"Signature database is {database_age_days} days old; run FreshClam to update it."
                )
            else:
                database_message = (
                    f"Signature database {database_version}, updated {database_updated}."
                )
            database_ready = (
                self._database_files_present()
                if self._uses_bundled_tools(executable)
                else database_version is not None
            )
            available = not self._uses_bundled_tools(executable) or database_ready
            if self._uses_bundled_tools(executable) and not database_ready:
                database_message = (
                    "Download the initial signature database with Update ClamAV signatures before scanning."
                )
            self._status = {
                "available": available,
                "executable": str(executable),
                "engine_version": engine_version,
                "database_version": database_version,
                "database_updated": database_updated,
                "database_age_days": database_age_days,
                "database_ready": database_ready,
                "updater_available": updater_available,
                "message": (
                    f"ClamAV {engine_version} is ready. {database_message}"
                    if available
                    else f"ClamAV {engine_version} is installed, but signatures are not ready. {database_message}"
                ),
                "last_error": None,
            }
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            self._status = {
                "available": False,
                "executable": str(executable),
                "engine_version": None,
                "database_version": None,
                "database_updated": None,
                "database_age_days": None,
                "database_ready": False,
                "updater_available": updater_available,
                "message": f"ClamAV is installed but unavailable: {exc}",
                "last_error": str(exc)[:500],
            }
        return dict(self._status)

    def update_signatures(self) -> dict:
        updater = self._find_updater()
        if updater is None:
            raise RuntimeError("FreshClam is not installed or freshclam.exe is not on PATH.")
        command = [str(updater), "--stdout"]
        if self._uses_bundled_tools(updater):
            if self.data_directory is None:
                raise RuntimeError("The bundled ClamAV signature database directory is not configured.")
            try:
                self.data_directory.mkdir(parents=True, exist_ok=True)
                config_file = self.data_directory / "freshclam.conf"
                database_path = str(self.data_directory.resolve()).replace("\\", "/")
                config_file.write_text(
                    f'DatabaseDirectory "{database_path}"\n'
                    "DatabaseMirror database.clamav.net\n",
                    encoding="utf-8",
                )
            except OSError as exc:
                raise RuntimeError(f"Could not prepare the ClamAV signature directory: {exc}") from exc
            command.insert(1, f"--config-file={config_file}")
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=UPDATE_TIMEOUT_SECONDS,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"FreshClam signature update timed out after {UPDATE_TIMEOUT_SECONDS} seconds."
            ) from exc
        except OSError as exc:
            raise RuntimeError(f"Could not run FreshClam: {exc}") from exc
        if result.returncode:
            detail = result.stderr.strip() or result.stdout.strip() or "FreshClam could not update its signature database."
            raise RuntimeError(detail[-500:])
        status = self.status(force=True)
        return {
            "completed": True,
            "message": "FreshClam update check completed. Review the reported database version and update time.",
            "status": status,
        }

    def scan_file(self, path: Path) -> dict:
        target = Path(path).expanduser()
        try:
            resolved = target.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise FileNotFoundError(f"Could not resolve the selected scan path: {exc}") from exc
        if is_protected_system_path(resolved, resolve=False):
            raise ProtectedSystemPathError(
                "Windows system and protected application files are excluded from antivirus scans."
            )
        if not resolved.is_file():
            raise ValueError("ClamAV scan requires a single existing file.")

        status = self.status()
        if not status["available"]:
            raise RuntimeError(status["message"])
        executable = status["executable"]
        database_arguments = self._database_arguments(Path(executable))
        try:
            result = subprocess.run(
                [executable, "--stdout", "--no-summary", *database_arguments, str(resolved)],
                capture_output=True,
                text=True,
                timeout=SCAN_TIMEOUT_SECONDS,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"ClamAV scan timed out after {SCAN_TIMEOUT_SECONDS} seconds."
            ) from exc
        except OSError as exc:
            raise RuntimeError(f"Could not run ClamAV: {exc}") from exc

        if result.returncode not in (0, 1):
            detail = result.stderr.strip() or result.stdout.strip() or "ClamAV could not scan this file."
            raise RuntimeError(detail[:500])
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        results = [
            line.rsplit(": ", 1)
            for line in lines
            if ": " in line
        ]
        findings = [
            result
            for _, result in results
            if result.endswith(" FOUND")
        ]
        clean_lines = [
            result for _, result in results
            if result == "OK"
        ]
        if result.returncode == 1 and not findings:
            detail = result.stderr.strip() or "ClamAV reported a detection without a parseable result."
            raise RuntimeError(detail[:500])
        if result.returncode == 0 and not clean_lines:
            detail = result.stderr.strip() or "ClamAV did not return a conclusive file result."
            raise RuntimeError(detail[:500])

        return {
            "path": str(resolved),
            "verdict": "infected" if findings else "clean",
            "detections": [finding[:-6] for finding in findings],
            "engine_version": status["engine_version"],
            "database_version": status["database_version"],
            "database_updated": status["database_updated"],
            "database_age_days": status["database_age_days"],
            "message": (
                "ClamAV detected one or more signatures. Review the result; Morpheus did not change the file."
                if findings
                else "ClamAV found no matching signatures. This does not prove the file is safe."
            ),
        }
