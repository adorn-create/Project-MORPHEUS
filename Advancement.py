import hashlib
import hmac
import argparse
import ipaddress
import json
import math
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil


DB_NAME = "fortress_passive_ledger.db"
CANARY_DIR = Path.cwd() / "Morpheus_Canaries"
GENESIS_HASH = "0" * 64
CANARY_CONTENTS = {
    "morpheus-decoy-notes.txt": (
        "MORPHEUS HARMLESS CANARY FILE\n"
        "Synthetic marker only. No credentials or personal data.\n"
    ).encode("utf-8"),
    "morpheus-decoy-budget.txt": (
        "MORPHEUS HARMLESS CANARY FILE\n"
        "Synthetic marker only. No financial or personal data.\n"
    ).encode("utf-8"),
}
POLL_INTERVAL_SECONDS = 3.0
MAX_PROCESSES_PER_POLL = 5000
NETWORK_CAPTURE_FILTER = "udp port 53 or tcp port 53 or arp"
DNS_LABEL_MIN_LENGTH = 24
DNS_LABEL_ENTROPY_THRESHOLD = 3.5

COMMAND_INDICATORS = {
    "powershell_encoded_command": re.compile(
        r"^\s*(?:-|/)e(?:nc(?:odedcommand)?)?\s*$", re.IGNORECASE
    ),
    "hidden_window": re.compile(
        r"(?:^|\s)-(?:w|windowstyle)\s+hidden\b", re.IGNORECASE
    ),
    "certutil_urlcache": re.compile(r"\bcertutil(?:\.exe)?\b.*\s-urlcache\b", re.IGNORECASE),
    "bitsadmin_transfer": re.compile(r"\bbitsadmin(?:\.exe)?\b.*\s/transfer\b", re.IGNORECASE),
    "mshta_remote_content": re.compile(
        r"\bmshta(?:\.exe)?\b.*(?:https?://|javascript:)", re.IGNORECASE
    ),
}


def shannon_entropy(value):
    if not value:
        return 0.0
    counts = {character: value.count(character) for character in set(value)}
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


class ComprehensiveReviewSystem:
    """Local review monitor with optional DNS/ARP-only packet capture."""

    def __init__(
        self,
        db_name=DB_NAME,
        canary_dir=CANARY_DIR,
        poll_interval=POLL_INTERVAL_SECONDS,
    ):
        self.db_path = Path(db_name)
        self.canary_dir = Path(canary_dir)
        self.poll_interval = max(0.5, float(poll_interval))
        self.connection_history = {}
        self._db_lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread = None
        self._network_thread = None
        self._network_stop_event = threading.Event()
        self._network_interface = None
        self.network_capture_error = None
        self._arp_ip_to_mac = {}
        self._reported_dns_names = set()
        self._reported_process_signals = set()
        self._reported_canary_states = {}

        self._initialize_tamper_proof_ledger()
        self._deploy_canary_honeytokens()
        self._canary_hashes = {
            name: self._file_hash(self.canary_dir / name)
            for name in CANARY_CONTENTS
        }

    def _connect(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        return sqlite3.connect(self.db_path, timeout=10)

    def _initialize_tamper_proof_ledger(self):
        with self._db_lock, self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS security_ledger (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    module_name TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    evidence_explanation TEXT NOT NULL,
                    current_block_hash TEXT NOT NULL,
                    previous_block_hash TEXT NOT NULL
                )
                """
            )

    def _get_last_block_hash(self, conn=None):
        if conn is not None:
            row = conn.execute(
                "SELECT current_block_hash FROM security_ledger ORDER BY id DESC LIMIT 1"
            ).fetchone()
            return row[0] if row else GENESIS_HASH
        with self._db_lock, self._connect() as connection:
            return self._get_last_block_hash(connection)

    @staticmethod
    def _calculate_block_hash(timestamp, module, score, explanation, previous_hash):
        block_data = f"{timestamp}|{module}|{score}|{explanation}|{previous_hash}"
        return hashlib.sha256(block_data.encode("utf-8")).hexdigest()

    def log_audit_node(self, module, score, explanation):
        score = float(score)
        if not math.isfinite(score) or not 0 <= score <= 10:
            raise ValueError("Risk score must be a finite number from 0 to 10.")
        if not isinstance(module, str) or not module.strip():
            raise ValueError("Module name must not be empty.")
        if not isinstance(explanation, str):
            raise TypeError("Evidence explanation must be text.")

        timestamp = datetime.now(timezone.utc).isoformat()
        with self._db_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            previous_hash = self._get_last_block_hash(conn)
            current_hash = self._calculate_block_hash(
                timestamp, module, score, explanation, previous_hash
            )
            conn.execute(
                """
                INSERT INTO security_ledger (
                    timestamp, module_name, risk_score, evidence_explanation,
                    current_block_hash, previous_block_hash
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (timestamp, module, score, explanation, current_hash, previous_hash),
            )

        print(
            f"\n[REVIEW ALERT] {module.upper()} -> Review priority: {score:.1f}/10\n"
            f"    Evidence: {explanation}\n"
            f"    Ledger hash: ...{current_hash[-8:]} (previous ...{previous_hash[-8:]})"
        )
        return current_hash

    def verify_ledger(self):
        expected_previous = GENESIS_HASH
        checked = 0
        with self._db_lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT timestamp, module_name, risk_score, evidence_explanation,
                       current_block_hash, previous_block_hash
                FROM security_ledger ORDER BY id ASC
                """
            ).fetchall()
        for timestamp, module, score, explanation, current_hash, previous_hash in rows:
            if previous_hash != expected_previous:
                return {"valid": False, "checked": checked}
            calculated = self._calculate_block_hash(
                timestamp, module, score, explanation, previous_hash
            )
            if not hmac.compare_digest(calculated, current_hash):
                return {"valid": False, "checked": checked}
            expected_previous = current_hash
            checked += 1
        return {"valid": True, "checked": checked}

    def _deploy_canary_honeytokens(self):
        self.canary_dir.mkdir(parents=True, exist_ok=True)
        for name, contents in CANARY_CONTENTS.items():
            path = self.canary_dir / name
            try:
                with path.open("xb") as stream:
                    stream.write(contents)
            except FileExistsError:
                continue

    @staticmethod
    def _file_hash(path):
        try:
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(64 * 1024), b""):
                    digest.update(chunk)
            return digest.hexdigest()
        except OSError:
            return None

    def check_canaries(self):
        for name, expected_contents in CANARY_CONTENTS.items():
            path = self.canary_dir / name
            current_hash = self._file_hash(path)
            expected_hash = hashlib.sha256(expected_contents).hexdigest()
            if current_hash == expected_hash:
                self._reported_canary_states.pop(name, None)
                continue

            state = "missing" if current_hash is None else "modified"
            if self._reported_canary_states.get(name) == state:
                continue
            self._reported_canary_states[name] = state
            self.process_threat_vector(
                "Canary File Review",
                7.0,
                f"The Morpheus-managed synthetic marker {name} is {state}. "
                "It contains no credentials or personal data.",
            )

    @staticmethod
    def _command_indicators(name, arguments):
        command = " ".join(str(argument) for argument in arguments)[:16_384]
        if not command:
            return None
        matches = []
        lowered_name = (name or "").casefold()
        if lowered_name in {"powershell.exe", "pwsh.exe"}:
            if any(
                token in command.casefold()
                for token in ("-encodedcommand", "-enc ", "-nop", "-w hidden")
            ):
                matches.append("powershell_suspicious_option")
        for indicator, pattern in COMMAND_INDICATORS.items():
            if pattern.search(command):
                matches.append(indicator)
        if not matches:
            return None
        command_hash = hashlib.sha256(command.encode("utf-8", errors="replace")).hexdigest()
        return sorted(set(matches)), command_hash

    def process_host_snapshot(self):
        active_signals = set()
        detected = []
        processes = psutil.process_iter(["pid", "ppid", "name", "cmdline"])
        for index, proc in enumerate(processes):
            if index >= MAX_PROCESSES_PER_POLL:
                break
            try:
                info = proc.info
                name = (info.get("name") or "").casefold()
                pid = info.get("pid")
                if not pid:
                    continue
                arguments = info.get("cmdline") or []
                finding = self._command_indicators(name, arguments)
                if finding:
                    indicators, command_hash = finding
                    identity = (pid, command_hash)
                    active_signals.add(identity)
                    if identity not in self._reported_process_signals:
                        self.process_threat_vector(
                            "Built-in Tool Command Review",
                            7.0,
                            f"Process {name} (PID {pid}) matched review patterns: "
                            f"{', '.join(indicators)}. Raw command text was not stored. "
                            f"Command hash: {command_hash}.",
                        )
                        detected.append(identity)
                        self._reported_process_signals.add(identity)

                if name in {"cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe"}:
                    parent = proc.parent()
                    if parent:
                        parent_name = (parent.name() or "").casefold()
                        if parent_name in {
                            "winword.exe",
                            "excel.exe",
                            "powerpnt.exe",
                            "outlook.exe",
                            "acrord32.exe",
                        }:
                            identity = (pid, f"parent:{parent.pid()}")
                            active_signals.add(identity)
                            if identity not in self._reported_process_signals:
                                self.process_threat_vector(
                                    "Process Relationship Review",
                                    7.0,
                                    f"Document process {parent_name} started {name} "
                                    f"(PID {pid}). This can be legitimate; verify the activity.",
                                )
                                detected.append(identity)
                                self._reported_process_signals.add(identity)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        self._reported_process_signals.intersection_update(active_signals)
        return detected

    def process_threat_vector(self, module, score, details):
        return self.log_audit_node(module, score, details)

    @staticmethod
    def network_interfaces():
        try:
            from scapy.all import get_if_list
        except ImportError as exc:
            raise RuntimeError(
                "Optional Scapy support is missing. Install Morpheus with "
                "the network-monitoring extra to enable packet review."
            ) from exc
        return get_if_list()

    def process_network_packet(self, packet):
        try:
            from scapy.all import ARP, DNSQR
        except ImportError as exc:
            raise RuntimeError("Scapy is required for DNS/ARP packet review.") from exc

        if packet.haslayer(DNSQR):
            raw_name = packet[DNSQR].qname
            if isinstance(raw_name, bytes):
                qname = raw_name.decode("utf-8", errors="ignore").rstrip(".").lower()
            else:
                qname = str(raw_name).rstrip(".").lower()
            labels = qname.split(".")
            unusual = [
                (label, shannon_entropy(label))
                for label in labels[:-1]
                if len(label) >= DNS_LABEL_MIN_LENGTH
                and shannon_entropy(label) >= DNS_LABEL_ENTROPY_THRESHOLD
            ]
            if unusual:
                name_hash = hashlib.sha256(qname.encode("utf-8")).hexdigest()
                if name_hash not in self._reported_dns_names:
                    if len(self._reported_dns_names) >= 10_000:
                        self._reported_dns_names.clear()
                    self._reported_dns_names.add(name_hash)
                    label, entropy = max(unusual, key=lambda item: item[1])
                    self.process_threat_vector(
                        "DNS Query Entropy Review",
                        6.0,
                        f"A DNS query contained a long, high-entropy label "
                        f"({len(label)} characters; entropy {entropy:.2f} bits/character). "
                        f"The queried name is not stored; SHA-256: {name_hash}. "
                        "This heuristic can flag legitimate services.",
                    )

        if packet.haslayer(ARP):
            arp = packet[ARP]
            if int(arp.op) != 2:
                return
            sender_ip = str(arp.psrc)
            sender_mac = str(arp.hwsrc).casefold()
            try:
                address = ipaddress.ip_address(sender_ip)
            except ValueError:
                return
            if address.is_unspecified or address.is_multicast or not sender_mac:
                return

            previous_mac = self._arp_ip_to_mac.get(sender_ip)
            self._arp_ip_to_mac[sender_ip] = sender_mac
            if len(self._arp_ip_to_mac) > 4096:
                self._arp_ip_to_mac.pop(next(iter(self._arp_ip_to_mac)))
            if previous_mac and previous_mac != sender_mac:
                self.process_threat_vector(
                    "ARP Address Mapping Change Review",
                    5.0,
                    f"ARP sender IP {sender_ip} changed its observed hardware address "
                    f"from {previous_mac} to {sender_mac}. This can occur after legitimate "
                    "network changes; verify the device before taking action.",
                )

    def start_network_monitor(self, interface):
        if not isinstance(interface, str) or not interface.strip():
            raise ValueError("Choose one network interface to monitor.")
        if self._network_thread and self._network_thread.is_alive():
            if interface != self._network_interface:
                raise RuntimeError("Stop the current capture before selecting another interface.")
            return

        interfaces = self.network_interfaces()
        if interface not in interfaces:
            raise ValueError(
                f"Unknown interface {interface!r}. Available interfaces: "
                + ", ".join(interfaces)
            )
        self._network_interface = interface
        self.network_capture_error = None
        self._network_stop_event.clear()
        self._network_thread = threading.Thread(
            target=self._network_capture_loop,
            name="morpheus-dns-arp-review",
            daemon=True,
        )
        self._network_thread.start()

    def _network_capture_loop(self):
        try:
            from scapy.all import sniff
        except ImportError as exc:
            self.network_capture_error = (
                "Scapy support is missing. Install the optional network-monitoring dependency."
            )
            print(f"[NETWORK REVIEW ERROR] {self.network_capture_error}")
            return

        try:
            while not self._network_stop_event.is_set():
                sniff(
                    iface=self._network_interface,
                    filter=NETWORK_CAPTURE_FILTER,
                    store=False,
                    prn=self.process_network_packet,
                    timeout=1,
                )
        except Exception as exc:
            self.network_capture_error = (
                f"DNS/ARP capture stopped: {type(exc).__name__}: {exc}"
            )
            print(f"[NETWORK REVIEW ERROR] {self.network_capture_error}")

    def stop_network_monitor(self):
        self._network_stop_event.set()
        if self._network_thread and self._network_thread.is_alive():
            self._network_thread.join(timeout=3)

    def process_host_heuristics(self):
        while not self._stop_event.is_set():
            try:
                self.process_host_snapshot()
                self.check_canaries()
            except (OSError, sqlite3.Error) as exc:
                print(f"[REVIEW ERROR] Local monitoring could not complete: {exc}")
            self._stop_event.wait(self.poll_interval)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self.process_host_heuristics,
            name="morpheus-local-review",
            daemon=True,
        )
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        self.stop_network_monitor()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=max(2.0, self.poll_interval + 1.0))


def main():
    parser = argparse.ArgumentParser(description="Local Morpheus review monitor")
    parser.add_argument(
        "--capture-network",
        action="store_true",
        help="Opt in to passive DNS/ARP review on one selected interface.",
    )
    parser.add_argument(
        "--interface",
        help="Interface name from Scapy's interface list; required with --capture-network.",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List capture interface names, then exit.",
    )
    args = parser.parse_args()
    if args.list_interfaces:
        for interface in ComprehensiveReviewSystem.network_interfaces():
            print(interface)
        return
    if args.capture_network and not args.interface:
        parser.error("--interface is required with --capture-network.")
    if args.interface and not args.capture_network:
        parser.error("--interface requires --capture-network.")

    system = ComprehensiveReviewSystem()
    print("Local host and canary review monitoring started.")
    if args.capture_network:
        system.start_network_monitor(args.interface)
        print(
            f"Passive capture enabled on {args.interface!r}; filter is "
            f"{NETWORK_CAPTURE_FILTER!r}. Raw packets are not stored."
        )
    else:
        print("Network capture is off. Use --capture-network --interface NAME to opt in.")
    system.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping local review monitoring...")
    finally:
        system.stop()
        print(f"Ledger verification: {system.verify_ledger()}")


if __name__ == "__main__":
    main()
