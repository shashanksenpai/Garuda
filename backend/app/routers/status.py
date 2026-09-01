from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models
from ..database import get_db
from ..scenarios.player import player

router = APIRouter(prefix="/api", tags=["status"])


@router.get("/status")
def status(db: Session = Depends(get_db)):
    incidents = db.query(models.Incident).all()
    events_count = db.query(models.Event).count()

    active = [i for i in incidents if i.investigation_status != "complete"]
    severity_dist = Counter(i.severity for i in incidents)
    threat_dist = Counter()
    for i in incidents:
        for t in i.attack_techniques or []:
            threat_dist[t.get("name") or "Unknown"] += 1

    highest_risk = max((i.risk_score for i in incidents), default=0.0)

    return {
        "live_mode_running": player.running,
        "total_events": events_count,
        "total_incidents": len(incidents),
        "active_incidents": len(active),
        "highest_risk_score": highest_risk,
        "severity_distribution": dict(severity_dist),
        "threat_distribution": dict(threat_dist),
    }
