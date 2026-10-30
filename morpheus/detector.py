import os
import psutil
import hashlib
import math
from collections import Counter
from pathlib import Path

class OwnBehaviorModel:
    """Small explainable local model. Replace weights after training; this is not a malware signature."""
    def __init__(self):
        self.weights = {
            "unsigned_temp_executable": 0.34,
            "many_remote_connections": 0.20,
            "high_cpu": 0.16,
            "new_executable": 0.12,
            "unexpected_sensitive_connection": 0.13,
        }

    def score(self, signals: dict) -> tuple[float, list[str]]:
        score, reasons = 0.0, []
        for signal, weight in self.weights.items():
            if signals.get(signal):
                score += weight
                reasons.append(signal)
        return min(score, 1.0), reasons

def sha256(path: Path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def entropy(path: Path) -> float:
    try:
        with path.open("rb") as stream:
            data = stream.read(2_000_000)
        if not data:
            return 0.0
        return -sum((count / len(data)) * math.log2(count / len(data)) for count in Counter(data).values())
    except (OSError, MemoryError):
        return 0.0

def executable_signals(proc, remote_connections=None, temp_exes=None):
    try:
        exe = Path(proc.exe())
        name = exe.name.lower()
        temp = str(exe).lower().startswith((os.environ.get("TEMP", "\\temp").lower(), os.environ.get("TMP", "\\tmp").lower()))
        connections = remote_connections or []
        cpu = proc.cpu_percent(interval=None)
        return {
            "unsigned_temp_executable": temp and exe.suffix.lower() in (".exe", ".dll", ".scr", ".com"),
            "many_remote_connections": len(connections) >= 8,
            "high_cpu": cpu >= 70,
            "new_executable": str(exe) in (temp_exes or set()),
            "unexpected_sensitive_connection": len(connections) >= 2 and name in {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
        }, exe
    except (OSError, psutil.NoSuchProcess, psutil.AccessDenied):
        return {}, None
