import re


_INTENTS = (
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
        ("firewall", "block address", "block ip", "internet address"),
        "The firewall control can block this computer from connecting out to an "
        "address you enter. It does not control another computer. A wrong address "
        "can interrupt apps or websites, so only block an address you understand.",
    ),
    (
        ("privacy", "private", "data", "upload", "internet", "online"),
        "Morpheus's built-in checks run on this computer. File and source-code "
        "checks do not send file contents to an online AI service. Local event "
        "records are stored on this device.",
    ),
    (
        ("download", "downloads"),
        "Download monitoring is optional. When enabled, Morpheus checks new "
        "supported files in the selected folder; it does not inspect every "
        "existing file, archive, or download location.",
    ),
    (
        ("process", "running app", "running program", "scan apps"),
        "The running-app check reviews process details and a few activity "
        "patterns. It does not scan files. Use the separate file or folder "
        "controls to check files.",
    ),
    (
        ("file", "folder", "virus", "malware", "infected", "safe", "scan"),
        "File checks look for a few local warning patterns and calculate file "
        "details. They are not a full antivirus scan. A clean result cannot "
        "guarantee that a file is safe; keep Microsoft Defender enabled.",
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
        "for simple warning patterns, review supported source code, and explain "
        "alerts. These checks can miss threats and do not replace Microsoft Defender.",
    ),
    (
        ("hello", "hi", "hey", "good morning", "good afternoon"),
        "Hello! I can explain Morpheus alerts, file checks, code review, "
        "quarantine, and firewall controls. I work offline and cannot change "
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
            "or the firewall."
        )
