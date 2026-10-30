from pathlib import Path, PureWindowsPath


_TOOLS_BY_PROCESS = {
    "Credential and password tools": {
        "hashcat.exe": "Hashcat",
        "john.exe": "John the Ripper",
        "lazagne.exe": "LaZagne",
        "mimikatz.exe": "Mimikatz",
        "nanodump.exe": "NanoDump",
        "ophcrack.exe": "Ophcrack",
        "procdump.exe": "ProcDump",
        "procdump64.exe": "ProcDump",
        "pwdump.exe": "Pwdump",
        "rubeus.exe": "Rubeus",
    },
    "Network discovery and scanning": {
        "advanced_ip_scanner.exe": "Advanced IP Scanner",
        "angryipscanner.exe": "Angry IP Scanner",
        "arp-scan.exe": "arp-scan",
        "masscan.exe": "Masscan",
        "nbtscan.exe": "NBTScan",
        "netdiscover.exe": "Netdiscover",
        "nmap.exe": "Nmap",
        "zmap.exe": "ZMap",
    },
    "Security testing and exploitation": {
        "burp.exe": "Burp Suite",
        "burpsuite.exe": "Burp Suite",
        "crackmapexec.exe": "CrackMapExec",
        "evil-winrm.exe": "Evil-WinRM",
        "hydra.exe": "THC Hydra",
        "medusa.exe": "Medusa",
        "metasploit.exe": "Metasploit",
        "msfconsole.exe": "Metasploit",
        "msfvenom.exe": "Metasploit",
        "netexec.exe": "NetExec",
        "nikto.exe": "Nikto",
        "responder.exe": "Responder",
        "sqlmap.exe": "sqlmap",
        "zaproxy.exe": "OWASP ZAP",
    },
    "Packet capture and wireless analysis": {
        "airodump-ng.exe": "Aircrack-ng",
        "aircrack-ng.exe": "Aircrack-ng",
        "bettercap.exe": "Bettercap",
        "dumpcap.exe": "Wireshark capture utility",
        "ettercap.exe": "Ettercap",
        "kismet.exe": "Kismet",
        "tshark.exe": "TShark",
        "wireshark.exe": "Wireshark",
    },
    "Tunneling and remote shells": {
        "chisel.exe": "Chisel",
        "cloudflared.exe": "Cloudflared tunnel",
        "frpc.exe": "FRP client",
        "frps.exe": "FRP server",
        "ligolo-ng.exe": "Ligolo-ng",
        "ncat.exe": "Ncat",
        "nc.exe": "Netcat",
        "netcat.exe": "Netcat",
        "ngrok.exe": "Ngrok",
        "plink.exe": "PuTTY Link",
        "socat.exe": "Socat",
    },
    "Remote access and administration": {
        "aeroadmin.exe": "AeroAdmin",
        "anydesk.exe": "AnyDesk",
        "dwagent.exe": "DWService Agent",
        "meshagent.exe": "MeshAgent",
        "radmin.exe": "Radmin",
        "remoteutilities.exe": "Remote Utilities",
        "rustdesk.exe": "RustDesk",
        "screenconnect.clientservice.exe": "ConnectWise ScreenConnect",
        "teamviewer.exe": "TeamViewer",
        "teamviewer_service.exe": "TeamViewer",
        "tightvnc.exe": "TightVNC",
        "ultravnc.exe": "UltraVNC",
        "vncserver.exe": "VNC server",
        "winvnc.exe": "VNC server",
    },
    "Remote execution and system administration": {
        "paexec.exe": "PAExec",
        "psexec.exe": "PsExec",
        "psexec64.exe": "PsExec",
        "processhacker.exe": "Process Hacker",
        "systeminformer.exe": "System Informer",
    },
}


def _process_basename(value: str) -> str:
    path_type = PureWindowsPath if "\\" in value else Path
    return path_type(value).name.casefold()


TOOL_CATALOG = tuple(
    {
        "process_name": process_name,
        "name": tool_name,
        "category": category,
    }
    for category, tools in _TOOLS_BY_PROCESS.items()
    for process_name, tool_name in tools.items()
)


def identify_known_tool(process_name: str | None, executable_path: str | None = None) -> dict | None:
    candidates = []
    if process_name:
        candidates.append(_process_basename(process_name))
    if executable_path:
        executable_name = _process_basename(executable_path)
        if executable_name not in candidates:
            candidates.append(executable_name)

    for category, tools in _TOOLS_BY_PROCESS.items():
        for candidate in candidates:
            if candidate in tools:
                return {
                    "name": tools[candidate],
                    "category": category,
                    "process_name": candidate,
                }
    return None
