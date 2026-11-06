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


def protection_summary(
    *,
    config: dict,
    defender: dict,
    clamav: dict,
    monitoring_running: bool,
    passkey_configured: bool,
    risk: dict,
    isolation_item_count: int = 0,
    containment_failures: int = 0,
) -> dict:
    score = 0
    factors = []

    defender_healthy = defender.get("available") is True and defender.get("healthy") is True
    if defender_healthy:
        score += 25
        factors.append({"name": "Microsoft Defender", "status": "healthy", "points": 25})
    elif defender.get("supported") is True:
        factors.append({"name": "Microsoft Defender", "status": "needs attention", "points": 0})
    else:
        factors.append({"name": "Microsoft Defender", "status": "not available on this device", "points": 0})

    clamav_ready = clamav.get("available") is True and clamav.get("database_ready") is True
    if clamav_ready:
        score += 20
        factors.append({"name": "ClamAV signatures", "status": "ready", "points": 20})
    elif clamav.get("available") is True:
        score += 5
        factors.append({"name": "ClamAV signatures", "status": "update needed", "points": 5})
    else:
        factors.append({"name": "ClamAV signatures", "status": "not available", "points": 0})

    if monitoring_running:
        score += 15
        factors.append({"name": "Background monitoring", "status": "running", "points": 15})
    else:
        factors.append({"name": "Background monitoring", "status": "stopped", "points": 0})

    if passkey_configured:
        score += 10
        factors.append({"name": "Owner approval", "status": "passkey enrolled", "points": 10})
    else:
        factors.append({"name": "Owner approval", "status": "passkey not enrolled", "points": 0})

    if config.get("process_tree_monitoring", True):
        score += 5
        factors.append({"name": "Process relationships", "status": "enabled", "points": 5})

    if config.get("automatic_quarantine", False):
        score += 10
        factors.append({"name": "Automatic process isolation", "status": "enabled", "points": 10})
    else:
        factors.append({"name": "Automatic process isolation", "status": "review-only", "points": 0})

    if config.get("download_monitoring", False):
        score += 10
        factors.append({"name": "Selected-folder monitoring", "status": "enabled", "points": 10})
    else:
        factors.append({"name": "Selected-folder monitoring", "status": "not enabled", "points": 0})

    if config.get("automatic_inbound_scan_blocking", False):
        score += 5
        factors.append({"name": "Inbound scan protection", "status": "enabled", "points": 5})
    else:
        factors.append({"name": "Inbound scan protection", "status": "not enabled", "points": 0})

    risk_score = max(0, min(100, int(risk.get("score", 0))))
    penalty = min(30, risk_score // 2 + min(10, len(risk.get("signals", []))))
    if containment_failures:
        penalty += min(20, containment_failures * 5)
    score = max(0, min(100, score - penalty))

    if score >= 85 and risk_score < 50 and containment_failures == 0:
        level = "strong"
    elif score >= 65 and risk_score < 75:
        level = "moderate"
    elif score >= 40:
        level = "limited"
    else:
        level = "weak"

    return {
        "score": score,
        "level": level,
        "risk_level": risk.get("level", "normal"),
        "risk_score": risk_score,
        "isolation_item_count": max(0, int(isolation_item_count)),
        "containment_failures": max(0, int(containment_failures)),
        "factors": factors,
        "explanation": (
            "Protection coverage combines enabled checks, health results, owner approval, "
            "isolation activity, and recent review-priority signals. It is not an antivirus guarantee."
        ),
    }
