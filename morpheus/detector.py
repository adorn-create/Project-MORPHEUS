import os
import psutil
import hashlib
import math
from collections import Counter
from pathlib import Path

from .threat_matrix import THREAT_MATRIX


class OwnBehaviorModel:
    """Fast, explainable scorer backed by the local JSON threat matrix."""

    def score(self, signals: dict) -> tuple[float, list[str]]:
        return THREAT_MATRIX.score_process(signals)

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
        executable_path = os.path.normcase(os.path.abspath(str(exe)))
        temporary_roots = (
            os.environ.get("TEMP"),
            os.environ.get("TMP"),
        )
        temp = False
        for root in temporary_roots:
            if not root:
                continue
            normalized_root = os.path.normcase(os.path.abspath(os.path.expandvars(root)))
            try:
                if os.path.commonpath((executable_path, normalized_root)) == normalized_root:
                    temp = True
                    break
            except ValueError:
                continue
        connections = remote_connections or []
        cpu = proc.cpu_percent(interval=None)
        return {
            "temporary_program_location": temp and exe.suffix.lower() in (".exe", ".dll", ".scr", ".com"),
            "many_remote_connections": len(connections) >= 8,
            "high_cpu": cpu >= 70,
            "new_executable": str(exe) in (temp_exes or set()),
            "unexpected_sensitive_connection": len(connections) >= 2 and name in {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
        }, exe
    except (OSError, psutil.NoSuchProcess, psutil.AccessDenied):
        return {}, None
