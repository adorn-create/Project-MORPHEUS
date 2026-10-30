import psutil
import ipaddress
import hashlib
import re
from datetime import datetime, timezone

def utcnow():
    return datetime.now(timezone.utc).isoformat()

def remote_connections():
    result = []
    for connection in psutil.net_connections(kind="inet"):
        if connection.status != psutil.CONN_ESTABLISHED or not connection.raddr:
            continue
        ip = connection.raddr.ip
        try:
            address = ipaddress.ip_address(ip)
            if address.is_global:
                result.append({"pid": connection.pid, "remote_ip": ip, "remote_port": connection.raddr.port})
        except ValueError:
            continue
    return result

def snapshot_processes(excluded=None):
    excluded = set(excluded or [])
    snapshot = []
    connections = remote_connections()
    connections_by_pid = {}
    for item in connections:
        if item["pid"]:
            connections_by_pid.setdefault(item["pid"], []).append(item)
    for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "username"]):
        try:
            info = proc.info
            if info["name"] in excluded:
                continue
            try:
                command_line = proc.cmdline()
            except psutil.AccessDenied:
                command_line = []
            snapshot.append({
                **info,
                "ppid": info.get("ppid"),
                "command_line": command_line,
                "remote_connections": len(connections_by_pid.get(info["pid"], ())),
                "connections": connections_by_pid.get(info["pid"], []),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return snapshot


_LOLBIN_COMMAND_PATTERNS = (
    ("certutil_remote_cache", re.compile(r"\bcertutil(?:\.exe)?\b.*\s-urlcache\b", re.IGNORECASE)),
    ("bitsadmin_transfer", re.compile(r"\bbitsadmin(?:\.exe)?\b.*\s/transfer\b", re.IGNORECASE)),
    ("mshta_remote_content", re.compile(r"\bmshta(?:\.exe)?\b.*(?:https?://|javascript:)", re.IGNORECASE)),
    ("powershell_encoded_command", re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b.*\s-(?:encodedcommand|enc)\b", re.IGNORECASE)),
)


def inspect_lolbin_command_line(name, arguments):
    if not isinstance(arguments, (list, tuple)) or not arguments:
        return None
    command_line = " ".join(str(argument) for argument in arguments)[:16_384]
    matched = [
        indicator
        for indicator, pattern in _LOLBIN_COMMAND_PATTERNS
        if pattern.search(command_line)
    ]
    if not matched:
        return None
    return {
        "indicators": matched,
        "command_line_sha256": hashlib.sha256(command_line.encode("utf-8", errors="replace")).hexdigest(),
    }


_SUSPICIOUS_CHILDREN = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
}
_SCRIPT_LAUNCH_PARENTS = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "acrord32.exe",
}


def process_tree_snapshot(processes, limit=2000):
    included = processes[:limit]
    by_pid = {item["pid"]: item for item in included if item.get("pid") is not None}
    nodes = []
    edges = []
    for item in included:
        pid = item.get("pid")
        parent_pid = item.get("ppid")
        name = item.get("name") or "unknown"
        parent = by_pid.get(parent_pid)
        node = {"pid": pid, "parent_pid": parent_pid, "name": name}
        nodes.append(node)
        if parent is None:
            continue
        parent_name = parent.get("name") or "unknown"
        child_name = name.casefold()
        parent_name_folded = parent_name.casefold()
        suspicious = (
            parent_name_folded in _SCRIPT_LAUNCH_PARENTS
            and child_name in _SUSPICIOUS_CHILDREN
        )
        edge = {
            "parent_pid": parent_pid,
            "parent_name": parent_name,
            "child_pid": pid,
            "child_name": name,
            "review": suspicious,
        }
        if suspicious:
            edge["reason"] = "Review: an Office/document process started a command or script host."
        edges.append(edge)
    return {
        "nodes": nodes,
        "edges": edges,
        "truncated": len(processes) > limit,
        "total_processes": len(processes),
    }
