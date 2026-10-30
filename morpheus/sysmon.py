import subprocess
from pathlib import Path

class SysmonStatus:
    def status(self):
        candidates = [Path("C:/Windows/Sysmon64.exe"), Path("C:/Windows/Sysmon.exe")]
        executable = next((path for path in candidates if path.exists()), None)
        return {"installed": executable is not None, "executable": str(executable) if executable else None}

    def install_help(self):
        return "Deploy Microsoft Sysmon and Microsoft-provided event forwarding after reviewing the organization’s logging and privacy policy."
