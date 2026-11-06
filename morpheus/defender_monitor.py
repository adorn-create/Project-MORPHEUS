import json
import logging
import os
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from .collector import utcnow

POLL_INTERVAL_SECONDS = 60
STALE_SIGNATURE_DAYS = 7
LOGGER = logging.getLogger(__name__)

_PROTECTION_FIELDS = {
    "AMServiceEnabled": "Antimalware service is disabled",
    "AntivirusEnabled": "Antivirus protection is disabled",
    "AntispywareEnabled": "Antispyware protection is disabled",
    "RealTimeProtectionEnabled": "Real-time protection is disabled",
    "BehaviorMonitorEnabled": "Behavior monitoring is disabled",
    "IoavProtectionEnabled": "Download and attachment scanning is disabled",
}


def find_defender_command() -> str | None:
    if os.name != "nt":
        return None
    candidates = [
        Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Windows Defender" / "MpCmdRun.exe",
        Path(os.environ.get("ProgramW6432", "C:/Program Files")) / "Windows Defender" / "MpCmdRun.exe",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate.resolve())
    return None


def scan_file_with_defender(path: Path, *, max_bytes: int = 512 * 1024 * 1024) -> dict:
    if os.name != "nt":
        raise RuntimeError("Microsoft Defender command-line scanning is available only on Windows.")
    resolved = Path(path).expanduser().resolve(strict=True)
    if not resolved.is_file():
        raise ValueError("Microsoft Defender scan requires a single existing file.")
    if resolved.stat().st_size > max_bytes:
        raise ValueError(f"File exceeds the configured scan limit of {max_bytes} bytes.")
    executable = find_defender_command()
    if executable is None:
        raise RuntimeError("Microsoft Defender MpCmdRun.exe was not found.")
    result = subprocess.run(
        [executable, "-Scan", "-ScanType", "3", "-File", str(resolved)],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode not in {0, 2}:
        detail = result.stderr.strip() or result.stdout.strip() or "Microsoft Defender returned no result."
        raise RuntimeError(detail[:500])
    return {
        "path": str(resolved),
        "verdict": "infected" if result.returncode == 2 else "clean",
        "message": (
            "Microsoft Defender detected a threat during the custom file scan."
            if result.returncode == 2
            else "Microsoft Defender found no matching threat during the custom file scan."
        ),
    }


def update_defender_signatures() -> dict:
    if os.name != "nt":
        raise RuntimeError("Microsoft Defender updates are available only on Windows.")
    executable = find_defender_command()
    if executable is None:
        raise RuntimeError("Microsoft Defender MpCmdRun.exe was not found.")
    result = subprocess.run(
        [executable, "-SignatureUpdate"],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "Signature update failed."
        raise RuntimeError(detail[:500])
    return {
        "completed": True,
        "message": "Microsoft Defender signature update completed.",
    }


def parse_defender_status(data: object) -> dict:
    if not isinstance(data, dict):
        raise ValueError("Windows returned an invalid Microsoft Defender status response.")

    missing = [
        name for name in (*_PROTECTION_FIELDS, "AntivirusSignatureAge")
        if name not in data
    ]
    if missing:
        raise ValueError(
            "Microsoft Defender status is missing required fields: "
            + ", ".join(missing)
        )

    protection = {}
    for field in _PROTECTION_FIELDS:
        value = data[field]
        if not isinstance(value, bool):
            raise ValueError(f"Microsoft Defender returned an invalid {field} value.")
        protection[field] = value

    signature_age = data["AntivirusSignatureAge"]
    if type(signature_age) is not int or signature_age < 0:
        raise ValueError("Microsoft Defender returned an invalid signature age.")

    issues = [
        issue for field, issue in _PROTECTION_FIELDS.items()
        if not protection[field]
    ]
    if signature_age > STALE_SIGNATURE_DAYS:
        issues.append("Antivirus signatures are more than seven days old")

    updated = data.get("AntivirusSignatureLastUpdated")
    if updated is not None and not isinstance(updated, str):
        raise ValueError("Microsoft Defender returned an invalid signature update time.")

    return {
        "healthy": not issues,
        "issues": issues,
        "signature_age_days": signature_age,
        "signature_last_updated": updated,
    }


def query_defender_status() -> dict:
    if os.name != "nt":
        raise RuntimeError("Microsoft Defender status monitoring is available only on Windows.")

    command = [
        "powershell.exe",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        (
            "$ErrorActionPreference = 'Stop'; "
            "Get-MpComputerStatus -ErrorAction Stop | "
            "Select-Object AMServiceEnabled, AntivirusEnabled, AntispywareEnabled, "
            "RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, "
            "AntivirusSignatureAge, AntivirusSignatureLastUpdated | "
            "ConvertTo-Json -Compress"
        ),
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Microsoft Defender status check timed out after 15 seconds.") from exc
    except OSError as exc:
        raise RuntimeError(f"Could not start the Microsoft Defender status check: {exc}") from exc

    if result.returncode:
        detail = result.stderr.strip() or "Windows could not read Microsoft Defender status."
        raise RuntimeError(detail[:500])
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Windows returned malformed Microsoft Defender status JSON.") from exc
    return parse_defender_status(data)


class DefenderHealthMonitor:
    def __init__(self, query: Callable[[], dict] | None = None):
        self._query = query or query_defender_status
        self._last_poll: float | None = None
        self._health: dict | None = None
        self._checked_at: str | None = None
        self._last_error: str | None = None
        self._last_issues: tuple[str, ...] | None = None

    def poll(self, database, journal) -> list[dict]:
        if os.name != "nt":
            return []

        now = time.monotonic()
        if self._last_poll is not None and now - self._last_poll < POLL_INTERVAL_SECONDS:
            return []
        self._last_poll = now

        try:
            health = self._query()
        except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
            self._last_error = str(exc)[:500]
            LOGGER.warning("Could not check Microsoft Defender status: %s", self._last_error)
            return []

        if not isinstance(health, dict) or not isinstance(health.get("healthy"), bool):
            self._last_error = "Microsoft Defender status check returned an invalid health result."
            LOGGER.error(self._last_error)
            return []
        issues = health.get("issues")
        if (
            not isinstance(issues, list)
            or any(not isinstance(issue, str) or not issue for issue in issues)
            or type(health.get("signature_age_days")) is not int
            or health["signature_age_days"] < 0
            or health["healthy"] != (not issues)
        ):
            self._last_error = "Microsoft Defender status check returned invalid protection details."
            LOGGER.error(self._last_error)
            return []

        self._health = health
        self._checked_at = utcnow()
        self._last_error = None
        current_issues = tuple(sorted(issues))
        previous_issues = self._last_issues
        self._last_issues = current_issues
        if current_issues == previous_issues:
            return []
        if not current_issues and previous_issues is None:
            return []

        restored = not current_issues
        event = {
            "timestamp": self._checked_at,
            "kind": "defender_protection_restored" if restored else "defender_protection_degraded",
            "severity": (
                "low" if restored
                else "high" if any(issue != "Antivirus signatures are more than seven days old" for issue in issues)
                else "medium"
            ),
            "source": "Microsoft Defender status",
            "target": "Antivirus protection",
            "confidence": None,
            "evidence": json.dumps({
                "issues": list(current_issues),
                "signature_age_days": health["signature_age_days"],
            }, sort_keys=True),
            "response": "review_required_manual_approval",
        }
        database.add(event)
        journal.append(event)
        return [event]

    def status(self) -> dict:
        if os.name != "nt":
            return {
                "supported": False,
                "available": False,
                "healthy": None,
                "checked_at": self._checked_at,
                "signature_age_days": None,
                "issues": [],
                "message": "Microsoft Defender health monitoring is available only on Windows.",
                "last_error": None,
            }

        if self._health is None:
            message = self._last_error or "Waiting for the first read-only Microsoft Defender status check."
        elif self._last_error:
            message = f"Latest status check failed; showing last known state. {self._last_error}"
        elif self._health["healthy"]:
            message = "Microsoft Defender protections are on and signatures are current."
        else:
            message = "Microsoft Defender needs attention: " + "; ".join(self._health["issues"]) + "."

        return {
            "supported": True,
            "available": self._health is not None and self._last_error is None,
            "healthy": self._health["healthy"] if self._health is not None else None,
            "checked_at": self._checked_at,
            "signature_age_days": (
                self._health["signature_age_days"] if self._health is not None else None
            ),
            "issues": self._health["issues"] if self._health is not None else [],
            "message": message,
            "last_error": self._last_error,
        }
