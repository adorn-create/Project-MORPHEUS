import ipaddress
import logging
import os
import time
from collections import defaultdict, deque
from pathlib import Path

import psutil

from .collector import utcnow
from .firewall import FirewallWorkerError
from .firewall_worker import parse_public_ip, scan_block_rule_name

LOGGER = logging.getLogger(__name__)
DEFAULT_FIREWALL_LOG = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "LogFiles" / "Firewall" / "pfirewall.log"
SCAN_WINDOW_SECONDS = 60
SCAN_DISTINCT_PORT_THRESHOLD = 10
MAX_LOG_BYTES_PER_POLL = 1024 * 1024
MAX_LOG_LINE_BYTES = 16 * 1024
MAX_TRACKED_SOURCES = 1024
DEFAULT_FIELDS = (
    "date", "time", "action", "protocol", "src-ip", "dst-ip",
    "src-port", "dst-port", "size", "tcpflags", "tcpsyn",
    "tcpack", "tcpwin", "icmptype", "icmpcode", "info", "path",
)


def local_ip_addresses() -> set[str]:
    addresses = set()
    for interface_addresses in psutil.net_if_addrs().values():
        for item in interface_addresses:
            try:
                address = ipaddress.ip_address(item.address.split("%", 1)[0])
            except ValueError:
                continue
            if not address.is_unspecified and not address.is_loopback:
                addresses.add(str(address))
    return addresses


class WindowsFirewallLogMonitor:
    def __init__(self, log_path: Path | None = None, address_provider=local_ip_addresses):
        self.log_path = Path(log_path) if log_path is not None else DEFAULT_FIREWALL_LOG
        self.address_provider = address_provider
        self._offset: int | None = None
        self._pending_line = b""
        self._fields = DEFAULT_FIELDS
        self._ports_by_source: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._last_alert_by_source: dict[str, float] = {}
        self.last_error: str | None = None
        self.last_status = "Inbound scan protection is off."

    def status(self, enabled: bool) -> dict:
        if not enabled:
            return {
                "enabled": False,
                "available": True,
                "message": "Off. Morpheus is not monitoring inbound firewall logs.",
                "last_error": None,
            }
        try:
            available = self.log_path.is_file()
        except OSError as exc:
            available = False
            self.last_error = str(exc)
        if not available:
            return {
                "enabled": True,
                "available": False,
                "message": (
                    "Windows Firewall log is unavailable. Morpheus will not enable logging. "
                    "Enable dropped-packet logging yourself in Windows Defender Firewall with Advanced Security, "
                    "then restart Morpheus monitoring."
                ),
                "last_error": self.last_error,
            }
        if self.last_status == "Inbound scan protection is off.":
            return {
                "enabled": True,
                "available": True,
                "message": "Waiting for new Windows Firewall log entries; existing entries are not processed.",
                "last_error": self.last_error,
            }
        return {
            "enabled": True,
            "available": self.last_error is None,
            "message": self.last_status,
            "last_error": self.last_error,
        }

    def poll(self, config: dict, firewall, database, journal) -> list[dict]:
        if not config.get("automatic_inbound_scan_blocking", False):
            self.last_status = "Off. Morpheus is not monitoring inbound firewall logs."
            return []
        if os.name != "nt" and self.log_path == DEFAULT_FIREWALL_LOG:
            self.last_status = "Windows Firewall log monitoring is available only on Windows."
            return []
        try:
            stat = self.log_path.stat()
            if self._offset is None:
                self._offset = stat.st_size
                self.last_status = (
                    "Waiting for new Windows Firewall log entries. Existing entries are not processed."
                )
                self.last_error = None
                return []
            if stat.st_size < self._offset:
                self._offset = 0
                self._pending_line = b""
                self._fields = DEFAULT_FIELDS
            with self.log_path.open("rb") as stream:
                stream.seek(self._offset)
                chunk = stream.read(MAX_LOG_BYTES_PER_POLL)
                self._offset = stream.tell()
        except FileNotFoundError:
            self.last_error = f"Windows Firewall log not found: {self.log_path}"
            self.last_status = self.last_error
            return []
        except OSError as exc:
            self.last_error = f"Cannot read Windows Firewall log: {exc}"
            self.last_status = self.last_error
            LOGGER.warning(self.last_error)
            return []

        if not chunk:
            self.last_status = "Monitoring new Windows Firewall log entries."
            self.last_error = None
            return []

        data = self._pending_line + chunk
        lines = data.split(b"\n")
        self._pending_line = lines.pop()
        if len(self._pending_line) > MAX_LOG_LINE_BYTES:
            LOGGER.warning("Discarding an oversized partial Windows Firewall log line.")
            self._pending_line = b""
        local_addresses = self.address_provider()
        now = time.monotonic()
        detections = []
        for raw_line in lines:
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            if line.startswith("#Fields:"):
                self._fields = tuple(line.partition(":")[2].strip().lower().split())
                continue
            if line.startswith("#"):
                continue
            source, destination, port = self._parse_inbound_drop(line, local_addresses)
            if source is None or destination is None or port is None:
                continue
            if len(self._ports_by_source) >= MAX_TRACKED_SOURCES and source not in self._ports_by_source:
                oldest = min(
                    self._ports_by_source,
                    key=lambda key: self._ports_by_source[key][-1][0]
                    if self._ports_by_source[key] else 0,
                )
                self._ports_by_source.pop(oldest, None)
                self._last_alert_by_source.pop(oldest, None)
            observations = self._ports_by_source[source]
            observations.append((now, port))
            while observations and now - observations[0][0] > SCAN_WINDOW_SECONDS:
                observations.popleft()
            distinct_ports = {observed_port for _, observed_port in observations}
            last_alert = self._last_alert_by_source.get(source)
            if len(distinct_ports) < SCAN_DISTINCT_PORT_THRESHOLD:
                continue
            if last_alert is not None and now - last_alert < SCAN_WINDOW_SECONDS:
                continue

            allowlist = {
                str(normalized)
                for value in config.get("inbound_scan_allowlist", [])
                if (normalized := parse_public_ip(value)) is not None
            }
            if source in allowlist:
                event = self._scan_event(source, destination, distinct_ports)
                event["severity"] = "medium"
                event["response"] = "owner_allowlisted_no_block"
            else:
                event = self._scan_event(source, destination, distinct_ports)
            if source not in allowlist and config.get("automatic_inbound_scan_blocking", False):
                try:
                    if firewall.block_inbound_remote(source):
                        event["response"] = f"blocked_inbound:{scan_block_rule_name(source)}"
                    else:
                        event["response"] = "scan_detected_firewall_block_failed"
                except (FirewallWorkerError, OSError) as exc:
                    event["response"] = "scan_detected_firewall_block_failed"
                    event["evidence"] += f"; firewall error: {exc}"
                    LOGGER.exception("Could not automatically block inbound port-scan source %s", source)
            database.add(event)
            journal.append(event)
            detections.append(event)
            self._last_alert_by_source[source] = now

        self.last_error = None
        self.last_status = (
            f"Monitoring Windows Firewall drops; auto-block "
            f"{'on' if config.get('automatic_inbound_scan_blocking', False) else 'off'}."
        )
        return detections

    def _parse_inbound_drop(
        self, line: str, local_addresses: set[str]
    ) -> tuple[str | None, str | None, int | None]:
        values = line.split()
        if len(values) != len(self._fields):
            return None, None, None
        row = dict(zip(self._fields, values))
        if row.get("action", "").upper() != "DROP":
            return None, None, None
        if row.get("protocol", "").upper() not in {"TCP", "UDP", "6", "17"}:
            return None, None, None
        try:
            source_ip = ipaddress.ip_address(row["src-ip"].split("%", 1)[0])
            destination_ip = ipaddress.ip_address(row["dst-ip"].split("%", 1)[0])
            destination_port = int(row["dst-port"])
        except (KeyError, ValueError):
            return None, None, None
        source = parse_public_ip(str(source_ip))
        destination = str(destination_ip)
        if source is None or destination not in local_addresses or not 1 <= destination_port <= 65535:
            return None, None, None
        return str(source), destination, destination_port

    @staticmethod
    def _scan_event(source: str, destination: str, ports: set[int]) -> dict:
        return {
            "timestamp": utcnow(),
            "kind": "inbound_port_scan",
            "severity": "high",
            "source": source,
            "target": destination,
            "confidence": None,
            "evidence": (
                f"Windows Firewall dropped probes to {len(ports)} distinct ports "
                f"within {SCAN_WINDOW_SECONDS} seconds."
            ),
            "response": "review_required_manual_approval",
        }
