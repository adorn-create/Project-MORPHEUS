import json
from pathlib import Path

MITRE_RULES = {
    "credential_dumping": {
        "techniques": ["T1003"], "severity": "critical",
        "description": "Process behavior consistent with credential access.",
    },
    "powershell_download": {
        "techniques": ["T1059.001", "T1105"], "severity": "high",
        "description": "PowerShell paired with a remote connection.",
    },
    "script_execution": {
        "techniques": ["T1059.005", "T1059.007"], "severity": "high",
        "description": "Script interpreter executed with network activity.",
    },
}

class RuleEngine:
    def evaluate(self, process_name: str, signals: dict, remote_count: int) -> list[dict]:
        name = Path(process_name).name.lower()
        matches = []
        if name == "powershell.exe" and signals.get("unexpected_sensitive_connection"):
            matches.append(MITRE_RULES["powershell_download"])
        if name in {"wscript.exe", "cscript.exe"}:
            matches.append(MITRE_RULES["script_execution"])
        if name in {"procdump.exe", "mimikatz.exe", "rundll32.exe"} and signals.get("high_cpu"):
            matches.append(MITRE_RULES["credential_dumping"])
        return matches
