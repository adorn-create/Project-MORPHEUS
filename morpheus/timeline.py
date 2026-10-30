from datetime import datetime, timezone
from pathlib import Path
import json

MITRE_MAP = {
    "powershell.exe": ("T1059.001", "PowerShell"),
    "cmd.exe": ("T1059.003", "Windows Command Shell"),
    "wscript.exe": ("T1059.005", "Visual Basic"),
    "cscript.exe": ("T1059.005", "Visual Basic"),
    "mshta.exe": ("T1218.005", "Mshta"),
}

class AttackTimeline:
    def __init__(self, db):
        self.db = db

    def reconstruct(self, event: dict):
        process = Path(event.get("target", "unknown.exe")).name.lower()
        technique = MITRE_MAP.get(process)
        return {
            "event_id": None,
            "timestamp": event["timestamp"],
            "attack_stage": "Execution",
            "technique_id": technique[0] if technique else "T1204",
            "technique_name": technique[1] if technique else "User Execution",
            "evidence": json.loads(event["evidence"]),
            "source": event["source"],
            "target": event["target"],
            "confidence": event["confidence"],
            "response": event["response"],
        }
