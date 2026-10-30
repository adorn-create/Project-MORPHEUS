import hashlib
import json
from pathlib import Path

from .collector import utcnow


CANARY_CONTENTS = {
    "decoy-project-notes.txt": (
        "MORPHEUS HARMLESS CANARY FILE\n"
        "This is a decoy marker created by Morpheus Defense. It contains no credentials.\n"
    ).encode("utf-8"),
    "decoy-budget-draft.txt": (
        "MORPHEUS HARMLESS CANARY FILE\n"
        "This synthetic file contains no personal or financial information.\n"
    ).encode("utf-8"),
}


class CanaryMonitor:
    def __init__(self, root: Path):
        self.root = root
        self._reported: set[str] = set()
        self._initialized = False

    def prepare(self):
        self.root.mkdir(parents=True, exist_ok=True)
        marker = self.root / ".morpheus-canary-initialized"
        if not marker.exists() and not marker.is_symlink():
            for name, contents in CANARY_CONTENTS.items():
                path = self.root / name
                try:
                    with path.open("xb") as stream:
                        stream.write(contents)
                except FileExistsError:
                    continue
            marker.touch(exist_ok=True)
        self._initialized = True

    def poll(self, db, journal):
        if not self._initialized:
            self.prepare()
        alerts = []
        for name, expected in CANARY_CONTENTS.items():
            path = self.root / name
            try:
                if path.is_symlink() or path.stat().st_size != len(expected):
                    state = "modified"
                else:
                    actual = path.read_bytes()
                    state = "modified" if hashlib.sha256(actual).digest() != hashlib.sha256(expected).digest() else "intact"
            except FileNotFoundError:
                state = "missing"
            except OSError as exc:
                state = f"unreadable:{type(exc).__name__}"

            if state == "intact":
                self._reported.discard(name)
                continue
            if name in self._reported:
                continue

            event = {
                "timestamp": utcnow(),
                "kind": "canary_file_change",
                "severity": "medium",
                "source": "Morpheus-managed canary directory",
                "target": name,
                "confidence": None,
                "evidence": json.dumps({
                    "state": state,
                    "directory": str(self.root),
                    "note": "The marker is synthetic and contains no credentials.",
                }),
                "response": "review_required_manual_approval",
            }
            db.add(event)
            journal.append(event)
            alerts.append(event)
            self._reported.add(name)
        return alerts

    def status(self, enabled: bool) -> dict:
        return {
            "enabled": enabled,
            "directory": str(self.root),
            "files": len(CANARY_CONTENTS),
            "message": (
                "Monitoring harmless decoy markers in the Morpheus-managed data folder."
                if enabled
                else "Off. Enabling creates harmless marker files only in the Morpheus-managed data folder."
            ),
        }
