import json
import psutil
from pathlib import Path

from .collector import inspect_lolbin_command_line, process_tree_snapshot, snapshot_processes, utcnow
from .database import Database
from .detector import OwnBehaviorModel, executable_signals
from .quarantine import QuarantineManager
from .firewall import FirewallController, FirewallWorkerError
from .integrity import EvidenceJournal
from .rules import RuleEngine
from .scanner import is_protected_system_path
from .tool_catalog import identify_known_tool

class DefenseEngine:
    def __init__(self, root: Path, config_path: Path):
        self.root = root
        self.config_path = config_path
        self.db = Database(root / "morpheus.db")
        self.model = OwnBehaviorModel()
        self.quarantine = QuarantineManager(root / "quarantine")
        self.firewall = FirewallController()
        self.journal = EvidenceJournal(root)
        self.rules = RuleEngine()
        self._reported_tool_processes: set[tuple[int, str]] = set()
        self._reported_tree_edges: set[tuple[int, int]] = set()
        self._reported_lolbin_processes: set[tuple[int, str]] = set()
        self.latest_process_tree = {
            "nodes": [],
            "edges": [],
            "truncated": False,
            "total_processes": 0,
        }
        self.last_process_count = 0

    def config(self):
        return json.loads(self.config_path.read_text(encoding="utf-8"))

    def evaluate_once(self):
        config = self.config()
        detected = []
        active_tool_processes = set()
        active_lolbin_processes = set()
        processes = snapshot_processes(config.get("excluded_processes", []))
        self.last_process_count = len(processes)
        tree_enabled = config.get("process_tree_monitoring", True)
        lineage_processes = set()
        if tree_enabled:
            self.latest_process_tree = process_tree_snapshot(processes)
            active_tree_edges = set()
            for edge in self.latest_process_tree["edges"]:
                if not edge["review"]:
                    continue
                lineage_processes.add(edge["child_pid"])
                identity = (edge["parent_pid"], edge["child_pid"])
                active_tree_edges.add(identity)
                if identity in self._reported_tree_edges:
                    continue
                event = {
                    "timestamp": utcnow(),
                    "kind": "process_tree_review",
                    "severity": "medium",
                    "source": f"{edge['parent_name']} (PID {edge['parent_pid']})",
                    "target": f"{edge['child_name']} (PID {edge['child_pid']})",
                    "confidence": None,
                    "evidence": json.dumps({
                        "parent_pid": edge["parent_pid"],
                        "child_pid": edge["child_pid"],
                        "reason": edge["reason"],
                    }),
                    "response": "review_required_manual_approval",
                }
                self.db.add(event)
                self.journal.append(event)
                detected.append(event)
                self._reported_tree_edges.add(identity)
            self._reported_tree_edges.intersection_update(active_tree_edges)
        else:
            self.latest_process_tree = {
                "nodes": [],
                "edges": [],
                "truncated": False,
                "total_processes": 0,
            }
            self._reported_tree_edges.clear()

        for item in processes:
            pid = item["pid"]
            process_name = item.get("name") or ""
            executable_path = item.get("exe") or ""
            command_finding = inspect_lolbin_command_line(
                process_name,
                item.get("command_line", []),
            )
            if command_finding:
                identity = (pid, command_finding["command_line_sha256"])
                active_lolbin_processes.add(identity)
                if identity not in self._reported_lolbin_processes:
                    event = {
                        "timestamp": utcnow(),
                        "kind": "lolbin_command_pattern",
                        "severity": "medium",
                        "source": f"Process command pattern (PID {pid})",
                        "target": str(executable_path) if executable_path else process_name,
                        "confidence": None,
                        "evidence": json.dumps(command_finding),
                        "response": "review_required_manual_approval",
                    }
                    self.db.add(event)
                    self.journal.append(event)
                    detected.append(event)
                    self._reported_lolbin_processes.add(identity)
            tool = identify_known_tool(process_name, executable_path)
            if tool:
                identity = (pid, str(executable_path).casefold() or process_name.casefold())
                active_tool_processes.add(identity)
                if identity not in self._reported_tool_processes:
                    event = {
                        "timestamp": utcnow(),
                        "kind": "known_security_tool",
                        "severity": "medium",
                        "source": f"Running process (PID {pid})",
                        "target": str(executable_path) if executable_path else process_name,
                        "confidence": 0.65,
                        "evidence": json.dumps({
                            "tool": tool["name"],
                            "category": tool["category"],
                            "matched_process_name": tool["process_name"],
                            "legitimate_use_possible": True,
                        }),
                        "response": "review_required_no_automatic_action",
                    }
                    self.db.add(event)
                    self.journal.append(event)
                    detected.append(event)
                    self._reported_tool_processes.add(identity)
            try:
                proc = psutil.Process(pid)
                signals, exe = executable_signals(proc, item["connections"])
                signals["suspicious_process_lineage"] = pid in lineage_processes
                confidence, reasons = self.model.score(signals)
                if confidence < 0.40:
                    continue
                severity = "critical" if confidence >= config["high_confidence_threshold"] else "high" if confidence >= 0.70 else "medium"
                source_ips = [c["remote_ip"] for c in item["connections"]]
                response_parts = []

                above_response_threshold = confidence >= config["high_confidence_threshold"]
                quarantine_enabled = config.get("automatic_quarantine", False) or config.get("automatic_high_confidence", False)
                firewall_enabled = config.get("automatic_high_confidence", False)
                if above_response_threshold and (quarantine_enabled or firewall_enabled):
                    protected_roots = [Path(p).resolve() for p in config.get("protected_roots", []) if p]
                    is_protected = bool(exe and (
                        is_protected_system_path(exe)
                        or any(exe.resolve().is_relative_to(root) for root in protected_roots)
                    ))
                    if exe and not is_protected:
                        if quarantine_enabled:
                            try:
                                result = self.quarantine.quarantine(exe)
                                response_parts.append(f"quarantined:{result['quarantine_path']}")
                            except (OSError, FileNotFoundError) as exc:
                                response_parts.append(f"quarantine_failed:{exc}")
                    if firewall_enabled:
                        for ip in source_ips:
                            try:
                                if self.firewall.block_remote(ip):
                                    response_parts.append(f"blocked_remote:{ip}")
                            except FirewallWorkerError as exc:
                                response_parts.append(f"firewall_worker_failed:{exc}")
                    if not response_parts:
                        response_parts.append("flagged_pending_review")
                else:
                    response_parts.append("observation_only")

                event = {
                    "timestamp": utcnow(),
                    "kind": "suspicious_process",
                    "severity": severity,
                    "source": ",".join(source_ips) if source_ips else str(pid),
                    "target": str(exe) if exe else item["name"],
                    "confidence": confidence,
                    "evidence": json.dumps(reasons),
                    "response": ";".join(response_parts),
                }
                rule_matches = self.rules.evaluate(item["name"] if item.get("name") else "", signals, item["remote_connections"])
                if rule_matches:
                    event["evidence"] = json.dumps(json.loads(event["evidence"]) + [{"techniques": r["techniques"], "description": r["description"]} for r in rule_matches])
                self.db.add(event)
                self.journal.append(event)
                detected.append(event)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        self._reported_tool_processes.intersection_update(active_tool_processes)
        self._reported_lolbin_processes.intersection_update(active_lolbin_processes)
        return detected
