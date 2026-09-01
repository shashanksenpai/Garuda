from sqlalchemy.orm import Session

from . import models

SEVERITY_WEIGHT = {"low": 10, "medium": 25, "high": 40, "critical": 55}


def compute_risk(db: Session, incident: models.Incident) -> models.Incident:
    detections = db.query(models.Detection).filter(models.Detection.incident_id == incident.incident_id).all()
    if not detections:
        incident.risk_score = 0.0
        incident.risk_factors = {}
        return incident

    max_severity_score = max(SEVERITY_WEIGHT.get(d.severity, 15) for d in detections)
    avg_confidence = sum(d.confidence for d in detections) / len(detections)
    confidence_score = avg_confidence * 20

    stage_count = len({d.threat_type for d in detections})
    progression_score = min(stage_count * 8, 24)

    compromise_confirmed = any(d.threat_type == "Possible Credential Compromise" for d in detections)
    compromise_score = 10 if compromise_confirmed else 0

    privesc = any(d.threat_type == "Privilege Escalation" for d in detections)
    c2 = any("Outbound" in d.threat_type for d in detections)
    escalation_score = (8 if privesc else 0) + (8 if c2 else 0)

    total = max_severity_score + confidence_score + progression_score + compromise_score + escalation_score
    total = round(min(total, 100), 1)

    incident.risk_score = total
    incident.risk_factors = {
        "max_detection_severity": max_severity_score,
        "avg_confidence_pct": round(avg_confidence * 100, 1),
        "attack_stages": stage_count,
        "successful_compromise": compromise_confirmed,
        "privilege_escalation": privesc,
        "command_and_control": c2,
    }

    if total >= 85:
        incident.severity = "critical"
    elif total >= 60:
        incident.severity = "high"
    elif total >= 35:
        incident.severity = "medium"
    else:
        incident.severity = "low"

    return incident


def classify(score: float) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"
