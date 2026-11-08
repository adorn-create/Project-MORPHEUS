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
from .process_inspection import _read_process_memory, inspect_executable

class DefenseEngine:
    def __init__(self, root: Path, config_path: Path):
        self.root = root
        self.config_path = config_path
        self.db = Database(root / "morpheus.db")
        self.model = OwnBehaviorModel()
        self.quarantine = QuarantineManager(root / "Isolated")
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
        self.containment_failures = 0
        self._reported_isolation_access_attempts: set[tuple[int, str]] = set()

    @staticmethod
    def isolate_process(process, executable: Path) -> str:
        """Terminate a process only when its executable still matches the target."""
        try:
            process_executable = Path(process.exe()).resolve()
            target_executable = Path(executable).resolve()
        except (OSError, psutil.Error, TypeError, ValueError):
            return "isolated_process_match_failed"

        if process_executable != target_executable:
            return "isolated_process_not_matching"
        if not process.is_running():
            return "isolated_process_not_running"

        process.terminate()
        try:
            process.wait(timeout=3)
        except (psutil.Error, psutil.TimeoutExpired, AttributeError):
            process.kill()
        return "isolated_process_terminated"

    def check_isolation_access_attempts(self, process_snapshot: list[dict] | None = None) -> list[dict]:
        root = self.quarantine.root.resolve()
        detections = []
        active_attempts = set()
        if process_snapshot is not None:
            process_iterator = [
                {
                    "pid": item.get("pid"),
                    "name": item.get("name"),
                    "exe": item.get("exe"),
                    "cmdline": item.get("command_line"),
                }
                for item in process_snapshot
            ]
            snapshot_mode = True
        else:
            try:
                process_iterator = psutil.process_iter(["pid", "name", "exe", "cmdline"])
                snapshot_mode = False
            except (AttributeError, OSError, psutil.Error):
                return detections

        for process in process_iterator:
            try:
                if snapshot_mode:
                    info = process
                    pid = int(info.get("pid") or 0)
                else:
                    info = process.info if hasattr(process, "info") else {}
                    pid = int(info.get("pid") or process.pid)
                name = str(info.get("name") or "")
                candidates = []
                executable = info.get("exe")
                if executable:
                    candidates.append(str(executable))
                candidates.extend(str(value) for value in (info.get("cmdline") or []) if value)

                matched_path = None
                for candidate in candidates:
                    try:
                        candidate_path = Path(candidate).expanduser().resolve()
                        if candidate_path == root or root in candidate_path.parents:
                            matched_path = str(candidate_path)
                            break
                    except (OSError, RuntimeError, TypeError, ValueError):
                        continue
                if matched_path is None:
                    continue

                identity = (pid, matched_path)
                active_attempts.add(identity)
                countermeasure = "isolated_access_detected"
                if identity not in self._reported_isolation_access_attempts:
                    try:
                        process_handle = psutil.Process(pid) if snapshot_mode else process
                        process_handle.terminate()
                        try:
                            process_handle.wait(timeout=2)
                        except (AttributeError, psutil.TimeoutExpired, psutil.Error):
                            process_handle.kill()
                        countermeasure = f"countermeasure_process_terminated:{pid}"
                    except (AttributeError, OSError, psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        self.containment_failures += 1
                        countermeasure = f"countermeasure_failed:{pid}"

                    event = {
                        "timestamp": utcnow(),
                        "kind": "isolated_content_access_attempt",
                        "severity": "critical",
                        "source": f"Process (PID {pid})",
                        "target": matched_path,
                        "confidence": 1.0,
                        "evidence": json.dumps({
                            "process_name": name,
                            "path": matched_path,
                            "countermeasure": countermeasure,
                        }),
                        "response": countermeasure,
                    }
                    self.db.add(event)
                    self.journal.append(event)
                    detections.append(event)
                    self._reported_isolation_access_attempts.add(identity)
            except (AttributeError, OSError, psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, ValueError):
                continue

        self._reported_isolation_access_attempts.intersection_update(active_attempts)
        return detections

    def config(self):
        return json.loads(self.config_path.read_text(encoding="utf-8"))

    def evaluate_once(self):
        config = self.config()
        detected = []
        active_tool_processes = set()
        active_lolbin_processes = set()
        processes = snapshot_processes(config.get("excluded_processes", []))
        if config.get("process_memory_inspection", True):
            for process in processes[:256]:
                pid = process.get("pid")
                if not isinstance(pid, int):
                    continue
                memory = _read_process_memory(pid)
                executable = inspect_executable(process.get("exe"))
                suspicious_markers = sorted(set(memory.get("markers") or []) | set(executable.get("markers") or []))
                pe_findings = executable.get("pe") or {}
                pe_suspicious = pe_findings.get("suspicious") or []
                if pe_suspicious:
                    suspicious_markers = sorted(set(suspicious_markers) | set(pe_suspicious))
                if memory.get("available") or executable.get("available"):
                    evidence = {
                        "process_name": process.get("name"),
                        "pid": pid,
                        "memory_bytes_read": memory.get("bytes_read"),
                        "memory_markers": memory.get("markers"),
                        "executable": executable,
                    }
                    event = {
                        "timestamp": utcnow(),
                        "kind": "process_content_inspection",
                        "severity": "high" if suspicious_markers else "medium",
                        "source": f"Process memory (PID {pid})",
                        "target": process.get("exe") or process.get("name") or "unknown",
                        "confidence": 0.55 if suspicious_markers else None,
                        "evidence": json.dumps(evidence, sort_keys=True),
                        "response": "review_required_user_mode_inspection",
                    }
                    if suspicious_markers:
                        self.db.add(event)
                        self.journal.append(event)
                        detected.append(event)
        detected.extend(self.check_isolation_access_attempts(processes))
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
