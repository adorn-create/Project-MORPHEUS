import re


_INTENTS = (
    (
        ("firewall", "internet address", "block address", "outbound block"),
        "Morpheus's firewall controls can add a manual outbound block for an IP "
        "address you choose, and optional inbound scan protection can add blocks "
        "for public addresses that show repeated probing behavior. Morpheus does "
        "not control another computer, freeze a remote device, or prove who owns "
        "an address. A wrong rule can disrupt websites or apps.",
    ),
    (
        ("inbound scan", "dropped packet", "dropped-packet", "10 or more distinct", "allow this ip"),
        "Inbound scan protection uses Windows Firewall dropped-packet logging. "
        "Morpheus reviews logged drops and can alert when 10 or more distinct local "
        "ports receive probes within 60 seconds, then requires passkey approval for "
        "an outbound-scoped review workflow. The heuristic does not prove an attack. "
        "Use Allow this IP in the alert to remove a block and prevent a future "
        "automatic block for that address.",
    ),
    (
        (
            "malware get into", "malware get in", "malware can get in",
            "malware enter", "how malware", "malware infection",
            "infect my pc", "infect my computer",
        ),
        "Malware commonly reaches a PC through convincing phishing links or attachments, "
        "unsafe downloads, malicious ads or websites, unpatched software, infected USB "
        "drives, or stolen account credentials. It may also arrive bundled with software "
        "from an untrusted source. Keep Microsoft Defender and Windows security updates "
        "enabled, download apps only from sources you trust, avoid unexpected attachments "
        "and prompts, use a standard (non-administrator) account for everyday work, and "
        "keep backups of important files. Morpheus's heuristic checks can miss threats "
        "and raise false alarms; they do not replace antivirus protection.",
    ),
    (
        ("clamav", "signature feed", "signature database", "freshclam"),
        "The Windows installer includes the ClamAV scanner and FreshClam updater "
        "for on-demand and selected-folder scans. After installing Morpheus, use "
        "Update ClamAV signatures to download the initial database from its "
        "official mirror; this requires internet access and passkey approval. "
        "In development mode, install ClamAV separately. Morpheus does not "
        "automatically quarantine ClamAV findings. A clean result is not proof "
        "that a file is safe.",
    ),
    (
        ("defender", "antivirus protection", "real-time protection", "security health"),
        "Morpheus can read Microsoft Defender's protection status and alert if "
        "key protections are off or signatures are more than seven days old. "
        "This check is read-only: Morpheus does not change Defender settings. "
        "Morpheus is not a replacement antivirus engine.",
    ),
    (
        ("ollama", "model", "ai", "artificial intelligence"),
        "Morpheus uses a small built-in offline helper and local review rules. "
        "It does not need Ollama or an internet connection. This helper uses "
        "prepared guidance; it is not a generative AI model and cannot answer "
        "every question.",
    ),
    (
        ("code review", "review code", "source code", "programming", "developer"),
        "Code review checks supported source files for a limited set of common "
        "security mistakes, such as embedded credentials, unsafe deserialization, "
        "and risky shell or HTML operations. It reads files locally. It cannot "
        "understand every program or prove code is safe.",
    ),
    (
        ("quarantine", "holding area", "restore file", "held file"),
        "Quarantine moves a flagged file into Morpheus's holding area so it is "
        "less likely to be opened accidentally. Review the file before restoring "
        "it. Morpheus does not prove a file is harmful.",
    ),
    (
        ("privacy", "private", "data", "upload", "internet", "online"),
        "Morpheus's built-in checks run on this computer. File and source-code "
        "checks do not send file contents to an online AI service. Local event "
        "records are stored on this device.",
    ),
    (
        ("download", "downloads"),
        "Selected-folder monitoring is optional. It periodically checks new "
        "or changed supported files in the selected folder and subfolders, "
        "using existing files as a baseline. It has a 5,000-file-per-check "
        "limit and does not inspect every file type or location.",
    ),
    (
        ("process", "running app", "running program", "scan apps"),
        "The running-app check reviews process details and a few activity "
        "patterns. It does not scan files. Use the separate file or folder "
        "controls to check files.",
    ),
    (
        ("file", "folder", "virus", "malware", "infected", "safe", "scan"),
        "File checks use local heuristics and a small bundled signature catalog "
        "that includes the harmless EICAR antivirus test string, not a current "
        "malware feed. A bulk-change alert is also a heuristic, not ransomware "
        "identification. These checks are not a full antivirus scan or a "
        "replacement for Microsoft Defender.",
    ),
    (
        ("alert", "warning", "risk", "score", "detection", "found"),
        "An alert means Morpheus noticed a pattern worth reviewing. It is not "
        "proof of infection. Check the plain-language explanation and confirm "
        "whether you recognize the app or activity.",
    ),
    (
        ("help", "feature", "what can", "how do", "how does"),
        "Morpheus can check running-app activity, scan selected files and folders "
        "offline for a limited test signature and heuristic warning patterns, "
        "monitor selected folders, scan files with an optional installed ClamAV "
        "engine, review supported source code, "
        "explain alerts. These checks can miss threats and do not replace "
        "Microsoft Defender.",
    ),
    (
        ("hello", "hi", "hey", "good morning", "good afternoon"),
        "Hello! I can explain Morpheus alerts, file checks, code review, "
        "and quarantine. I work offline and cannot change "
        "settings or take actions for you.",
    ),
)


class OfflineAssistant:
    """Fast, offline guidance for common Morpheus questions; not a language model."""

    def status(self) -> dict[str, object]:
        return {
            "available": True,
            "ready": True,
            "mode": "built-in offline helper",
            "message": (
                "Morpheus's built-in offline helper is ready. No Ollama setup or "
                "internet connection is needed."
            ),
        }

    def chat(self, message: str) -> str:
        normalized = re.sub(r"[^a-z0-9]+", " ", message.casefold()).strip()
        padded = f" {normalized} "
        best_score = 0
        best_answer = None

        for phrases, answer in _INTENTS:
            score = sum(
                f" {re.sub(r'[^a-z0-9]+', ' ', phrase.casefold()).strip()} " in padded
                for phrase in phrases
            )
            if score > best_score:
                best_score = score
                best_answer = answer

        return best_answer or (
            "I can answer common questions about Morpheus, but this built-in "
            "offline helper is not a general-purpose AI. Try asking about an "
            "alert, running apps, file scans, code review, privacy, quarantine, "
            "or quarantine."
        )
