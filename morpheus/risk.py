from datetime import datetime, timedelta, timezone


RISK_WINDOW = timedelta(minutes=15)
SIGNAL_WEIGHTS = {
    "dns_entropy": ("Unusually random new DNS name", 25),
    "powershell_script_block": ("PowerShell script-block review pattern", 30),
    "process_tree_review": ("Document application started a script host", 25),
    "canary_file_change": ("Morpheus canary file changed or disappeared", 35),
    "suspicious_process": ("Suspicious process behavior alert", 25),
    "lolbin_command_pattern": ("Potentially unusual built-in tool command pattern", 25),
    "known_security_tool": ("Known dual-use security tool is running", 10),
}


def explainable_risk(events, now: datetime | None = None) -> dict:
    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=timezone.utc)
    cutoff = current_time - RISK_WINDOW
    latest_by_kind: dict[str, datetime] = {}
    for event in events:
        weight_entry = SIGNAL_WEIGHTS.get(event.get("kind"))
        timestamp = event.get("timestamp")
        if weight_entry is None or not isinstance(timestamp, str):
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

    signals = [
        {
            "kind": kind,
            "label": SIGNAL_WEIGHTS[kind][0],
            "points": SIGNAL_WEIGHTS[kind][1],
            "latest_at": observed.isoformat(),
        }
        for kind, observed in sorted(latest_by_kind.items())
    ]
    score = min(100, sum(signal["points"] for signal in signals) + (10 if len(signals) > 1 else 0))
    level = (
        "normal" if score < 20
        else "guarded" if score < 40
        else "elevated" if score < 70
        else "high"
    )
    return {
        "score": score,
        "level": level,
        "window_minutes": int(RISK_WINDOW.total_seconds() // 60),
        "signals": signals,
        "explanation": (
            "This is a transparent review-priority score from recent alert types, not a probability or malware verdict."
        ),
    }
