from datetime import datetime, timedelta, timezone

from .threat_matrix import THREAT_MATRIX

RISK_WINDOW = timedelta(minutes=15)


def explainable_risk(events, now: datetime | None = None) -> dict:
    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=timezone.utc)
    cutoff = current_time - RISK_WINDOW
    latest_by_kind: dict[str, datetime] = {}
    for event in events:
        kind = event.get("kind")
        if kind not in THREAT_MATRIX.event_weights:
            continue
        timestamp = event.get("timestamp")
        if not isinstance(timestamp, str):
            continue
        try:
            observed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            continue
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=timezone.utc)
        if cutoff <= observed <= current_time:
            kind = event["kind"]
            if observed > latest_by_kind.get(kind, cutoff):
                latest_by_kind[kind] = observed

    score, signals = THREAT_MATRIX.score_events(set(latest_by_kind))
    for signal in signals:
        signal["latest_at"] = latest_by_kind[signal["kind"]].isoformat()
    level = THREAT_MATRIX.risk_level(score)
    return {
        "score": score,
        "level": level,
        "window_minutes": int(RISK_WINDOW.total_seconds() // 60),
        "signals": signals,
        "explanation": (
            "This is a transparent review-priority score from recent alert types, not a probability or malware verdict."
        ),
    }
