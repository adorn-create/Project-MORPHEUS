import json
import math
from pathlib import Path
from typing import Any


MATRIX_PATH = Path(__file__).with_name("rules") / "threat_matrix.json"


def _positive_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value > 0


class ThreatMatrix:
    def __init__(self, path: Path = MATRIX_PATH):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Could not load threat matrix from {path}: {exc}") from exc
        if not isinstance(data, dict) or data.get("schema_version") != 1:
            raise ValueError(f"Unsupported threat matrix schema in {path}.")

        process = data.get("process")
        events = data.get("events")
        if not isinstance(process, dict) or not isinstance(events, dict):
            raise ValueError(f"Threat matrix in {path} is missing process or event scoring.")
        if not _positive_number(process.get("normalization_max")):
            raise ValueError("Process normalization_max must be a positive number.")
        if not _positive_number(events.get("normalization_max")):
            raise ValueError("Event normalization_max must be a positive number.")
        process_weights = process.get("weights")
        event_weights = events.get("weights")
        if (
            not isinstance(process_weights, dict)
            or not process_weights
            or any(not _positive_number(weight) for weight in process_weights.values())
        ):
            raise ValueError("Threat matrix process weights must be positive finite numbers.")
        if (
            not isinstance(event_weights, dict)
            or not event_weights
            or any(
                not isinstance(item, dict)
                or not isinstance(item.get("label"), str)
                or not item["label"]
                or not _positive_number(item.get("weight"))
                for item in event_weights.values()
            )
        ):
            raise ValueError("Threat matrix event weights need a label and positive finite weight.")
        bonus = process.get("lineage_correlation_bonus")
        event_bonus = events.get("multiple_signal_bonus")
        if not isinstance(bonus, (int, float)) or not math.isfinite(bonus) or bonus < 0:
            raise ValueError("Process lineage correlation bonus must be a non-negative number.")
        if not isinstance(event_bonus, (int, float)) or not math.isfinite(event_bonus) or event_bonus < 0:
            raise ValueError("Event multiple-signal bonus must be a non-negative number.")
        if not isinstance(process.get("lineage_signal"), str) or not process["lineage_signal"]:
            raise ValueError("Threat matrix needs a process lineage signal name.")

        levels = data.get("risk_levels")
        if (
            not isinstance(levels, list)
            or not levels
            or any(
                not isinstance(item, dict)
                or not isinstance(item.get("level"), str)
                or not _positive_number(item.get("below"))
                for item in levels
            )
            or [item["below"] for item in levels] != sorted(item["below"] for item in levels)
        ):
            raise ValueError("Threat matrix risk levels must have increasing positive thresholds.")

        self.process_weights = process_weights
        self.process_max = float(process["normalization_max"])
        self.lineage_bonus = float(bonus)
        self.lineage_signal = process["lineage_signal"]
        self.event_weights = event_weights
        self.event_max = float(events["normalization_max"])
        self.multiple_signal_bonus = float(event_bonus)
        self.risk_levels = levels

    def score_process(self, signals: dict) -> tuple[float, list[str]]:
        reasons = [
            name for name in self.process_weights
            if signals.get(name)
        ]
        points = sum(self.process_weights[name] for name in reasons)
        if signals.get(self.lineage_signal) and reasons:
            points += self.lineage_bonus
            reasons.append(self.lineage_signal)
        normalized = min(points / self.process_max, 1.0)
        return normalized * self.process_max, reasons

    def score_events(self, event_kinds: set[str]) -> tuple[int, list[dict]]:
        matched = [
            {
                "kind": kind,
                "label": self.event_weights[kind]["label"],
                "points": self.event_weights[kind]["weight"],
            }
            for kind in sorted(event_kinds)
            if kind in self.event_weights
        ]
        total = sum(item["points"] for item in matched)
        if len(matched) > 1:
            total += self.multiple_signal_bonus
        normalized = min(total / self.event_max, 1.0)
        return round(normalized * self.event_max), matched

    def risk_level(self, score: int) -> str:
        for item in self.risk_levels:
            if score < item["below"]:
                return item["level"]
        return self.risk_levels[-1]["level"]


THREAT_MATRIX = ThreatMatrix()
