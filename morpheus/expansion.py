import hashlib
import json
import math
import os
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from collections import Counter

from .collector import utcnow

DNS_CACHE_INTERVAL_SECONDS = 30
POWERSHELL_POLL_INTERVAL_SECONDS = 15
MAX_DNS_CACHE_ENTRIES = 2000
MAX_EVENT_RECORDS = 25
MAX_SCRIPT_BLOCK_LENGTH = 100_000
POWERSHELL_LOG = "Microsoft-Windows-PowerShell/Operational"
BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])")

_PS_INDICATORS = {
    "encoded_command": ("-encodedcommand", "-enc "),
    "base64_decode": ("frombase64string",),
    "dynamic_execution": ("invoke-expression", "iex "),
    "remote_download": ("downloadstring", "invoke-webrequest", "start-bitstransfer"),
    "amsi_tampering": ("amsiutils", "amsiinitfailed"),
    "execution_policy_bypass": ("-executionpolicy bypass",),
}


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def inspect_dns_name(name: str) -> dict | None:
    normalized = name.strip().rstrip(".").lower()
    if not normalized or len(normalized) > 253:
        return None
    labels = normalized.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        return None

    unusual = [
        {"label": label, "entropy_bits_per_character": round(shannon_entropy(label), 3)}
        for label in labels[:-1]
        if len(label) >= 24 and shannon_entropy(label) >= 3.5
    ]
    if not unusual:
        return None
    return {"domain": normalized, "unusual_labels": unusual}


def inspect_script_block(script: str, record_id: int) -> dict | None:
    if not script:
        return None
    analyzed_script = script[:MAX_SCRIPT_BLOCK_LENGTH]
    lowered = analyzed_script.lower()
    indicators = [
        name
        for name, tokens in _PS_INDICATORS.items()
        if any(token in lowered for token in tokens)
    ]
    high_entropy_token = any(
        shannon_entropy(match.group(0)) >= 4.2
        for match in BASE64_TOKEN.finditer(analyzed_script)
    )
    if "amsi_tampering" not in indicators and len(indicators) < 2 and not high_entropy_token:
        return None
    return {
        "record_id": record_id,
        "script_sha256": hashlib.sha256(script.encode("utf-8", errors="replace")).hexdigest(),
        "script_length": len(script),
        "indicators": indicators,
        "high_entropy_token_observed": high_entropy_token,
    }


def _event(
    *,
    kind: str,
    severity: str,
    source: str,
    target: str,
    evidence: dict,
) -> dict:
    return {
        "timestamp": utcnow(),
        "kind": kind,
        "severity": severity,
        "source": source,
        "target": target,
        "confidence": None,
        "evidence": json.dumps(evidence, sort_keys=True),
        "response": "review_required_manual_approval",
    }


def _xml_events(output: str) -> list[ET.Element]:
    if not output.strip():
        return []
    output = re.sub(r"<\?xml[^?]*\?>", "", output, count=1, flags=re.IGNORECASE)
    try:
        root = ET.fromstring(f"<Events>{output}</Events>")
    except ET.ParseError as exc:
        raise RuntimeError("Windows returned malformed PowerShell event-log XML.") from exc
    return list(root)


def _event_value(event: ET.Element, path: str) -> str | None:
    current = event
    for name in path.split("/"):
        current = next(
            (child for child in current if child.tag.rsplit("}", 1)[-1] == name),
            None,
        )
        if current is None:
            return None
    return current.text


class _WindowsEventLog:
    def __init__(self):
        self._last_record_id: int | None = None
        self._last_poll = 0.0
        self.last_error: str | None = None
        self.last_status = "Waiting for the first event-log check."

    @staticmethod
    def _query(query: str, limit: int, reverse: bool = True) -> list[ET.Element]:
        if os.name != "nt":
            raise RuntimeError("Windows event-log monitoring is available only on Windows.")
        command = [
            "wevtutil.exe",
            "qe",
            POWERSHELL_LOG,
            f"/q:{query}",
            f"/c:{limit}",
            f"/rd:{'true' if reverse else 'false'}",
            "/f:xml",
        ]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode:
            detail = result.stderr.strip() or "Windows could not read the PowerShell Operational event log."
            raise RuntimeError(detail[:500])
        return _xml_events(result.stdout)

    def _write(self, event: dict, db, journal):
        db.add(event)
        journal.append(event)


class DnsEntropyMonitor(_WindowsEventLog):
    def __init__(self):
        super().__init__()
        self._last_cache_poll = 0.0
        self._seen_names: set[str] = set()
        self._initialized = False

    def poll(self, db, journal):
        now = time.monotonic()
        if now - self._last_cache_poll < DNS_CACHE_INTERVAL_SECONDS:
            return []
        self._last_cache_poll = now
        if os.name != "nt":
            self.last_status = "DNS cache monitoring is available only on Windows."
            return []
        command = [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-DnsClientCache -ErrorAction Stop | Select-Object -First 2000 -ExpandProperty Name | Sort-Object -Unique | ConvertTo-Json -Compress",
        ]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode:
                detail = result.stderr.strip() or "Windows could not read the DNS client cache."
                raise RuntimeError(detail[:500])
            names = json.loads(result.stdout) if result.stdout.strip() else []
            if names is None:
                names = []
            if isinstance(names, str):
                names = [names]
            if not isinstance(names, list) or any(not isinstance(name, str) for name in names):
                raise RuntimeError("Windows returned an invalid DNS cache response.")
            if len(names) > MAX_DNS_CACHE_ENTRIES:
                names = names[:MAX_DNS_CACHE_ENTRIES]
            current_names = {name.strip().rstrip(".").lower() for name in names if name.strip()}
            if not self._initialized:
                self._seen_names = current_names
                self._initialized = True
                self.last_status = (
                    "Monitoring Windows' DNS cache. Existing cache entries were used as the baseline."
                )
                self.last_error = None
                return []

            events = []
            for name in sorted(current_names - self._seen_names):
                finding = inspect_dns_name(name)
                if finding:
                    event = _event(
                        kind="dns_entropy",
                        severity="medium",
                        source="Windows DNS client cache",
                        target=name,
                        evidence=finding,
                    )
                    self._write(event, db, journal)
                    events.append(event)
            self._seen_names = current_names
            self.last_status = "Monitoring new entries in the Windows DNS cache."
            self.last_error = None
            return events
        except Exception as exc:
            self.last_error = str(exc)
            self.last_status = "DNS cache monitoring could not read the Windows DNS client cache."
            raise

    def status(self, enabled: bool) -> dict:
        return {
            "enabled": enabled,
            "available": os.name == "nt",
            "message": self.last_error or (
                self.last_status if enabled else "Off. Enable this to review new cached DNS names locally."
            ),
        }

    def suspend(self):
        self._initialized = False
        self._seen_names.clear()
        self._last_cache_poll = 0.0


class PowerShellLogMonitor(_WindowsEventLog):
    def poll(self, db, journal):
        now = time.monotonic()
        if now - self._last_poll < POWERSHELL_POLL_INTERVAL_SECONDS:
            return []
        self._last_poll = now
        try:
            if self._last_record_id is None:
                latest = self._query("*[System]", 1)
                if latest:
                    self._last_record_id = int(_event_value(latest[0], "System/EventRecordID") or "0")
                else:
                    self._last_record_id = 0
                self.last_status = (
                    "Baseline set. Waiting for new event 4104 records; Script Block Logging must already be enabled."
                )
                self.last_error = None
                return []

            query = f"*[System[(EventID=4104) and (EventRecordID > {self._last_record_id})]]"
            records = self._query(query, MAX_EVENT_RECORDS, reverse=False)
            events = []
            record_ids = []
            for record in records:
                record_id_value = _event_value(record, "System/EventRecordID")
                if not record_id_value:
                    continue
                record_id = int(record_id_value)
                record_ids.append(record_id)
                script = None
                for data in record.iter():
                    if (
                        data.tag.rsplit("}", 1)[-1] == "Data"
                        and data.attrib.get("Name") == "ScriptBlockText"
                    ):
                        script = data.text or ""
                        break
                if script is None:
                    continue
                finding = inspect_script_block(script, record_id)
                if finding:
                    event = _event(
                        kind="powershell_script_block",
                        severity="medium",
                        source=f"PowerShell event 4104 (record {record_id})",
                        target="PowerShell script block",
                        evidence=finding,
                    )
                    self._write(event, db, journal)
                    events.append(event)
            if record_ids:
                self._last_record_id = max(record_ids)
            self.last_status = (
                "No new suspicious script-block patterns found."
                if not events
                else f"Recorded {len(events)} script-block review alert(s)."
            )
            self.last_error = None
            return events
        except Exception as exc:
            self.last_error = str(exc)
            self.last_status = "PowerShell Operational event log could not be read."
            raise

    def status(self, enabled: bool) -> dict:
        return {
            "enabled": enabled,
            "available": os.name == "nt",
            "message": self.last_error or (
                self.last_status if enabled else "Off. Requires Script Block Logging (event 4104) to be configured."
            ),
        }

    def suspend(self):
        self._last_record_id = None
        self._last_poll = 0.0
