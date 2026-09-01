"""
Groups new detections into incidents rather than treating every alert independently.

A detection is merged into an existing "fresh" incident if it shares an entity
(source IP, destination IP, username, or hostname) with that incident, and the
incident was last updated within CORRELATION_WINDOW_SECONDS. Otherwise a new
incident is created. This keeps a multi-stage attack (recon -> brute force ->
login -> privesc -> C2) as a single narrative on the dashboard.
"""
from datetime import timedelta

from sqlalchemy.orm import Session

from . import config, models


def _entity_overlap(incident: models.Incident, detection: models.Detection) -> bool:
    """An incident's source/destination IPs both count as "known entities" for matching:
    an attacker's C2 destination can become the source of a later pivot, and a victim
    host that was a destination in one stage is often the source in the next
    (e.g. outbound C2 traffic originates *from* the compromised host)."""
    entities = incident.entities or {}
    known_ips = set(entities.get("source_ips", [])) | set(entities.get("dest_ips", []))
    if detection.source_ip and detection.source_ip in known_ips:
        return True
    if detection.destination_ip and detection.destination_ip in known_ips:
        return True
    return False


def _find_candidate_incident(db: Session, detection: models.Detection) -> models.Incident | None:
    since = detection.timestamp - timedelta(seconds=config.CORRELATION_WINDOW_SECONDS)
    candidates = (
        db.query(models.Incident)
        .filter(models.Incident.updated_at >= since)
        .filter(models.Incident.investigation_status != "complete")
        .all()
    )
    for incident in candidates:
        if _entity_overlap(incident, detection):
            return incident
    return None


def _merge_entities(incident: models.Incident, detection: models.Detection, events: list[models.Event]):
    entities = dict(incident.entities or {"source_ips": [], "dest_ips": [], "users": [], "hosts": []})
    for key, value in (
        ("source_ips", detection.source_ip),
        ("dest_ips", detection.destination_ip),
    ):
        if value and value not in entities.setdefault(key, []):
            entities[key].append(value)
    for e in events:
        if e.username and e.username not in entities.setdefault("users", []):
            entities["users"].append(e.username)
        if e.hostname and e.hostname not in entities.setdefault("hosts", []):
            entities["hosts"].append(e.hostname)
    incident.entities = entities


def _append_timeline(incident: models.Incident, detection: models.Detection):
    timeline = list(incident.timeline or [])
    timeline.append({
        "timestamp": detection.timestamp.isoformat(),
        "description": f"{detection.threat_type}: {detection.evidence}",
        "detection_id": detection.detection_id,
        "severity": detection.severity,
    })
    timeline.sort(key=lambda t: t["timestamp"])
    incident.timeline = timeline


def _append_technique(incident: models.Incident, detection: models.Detection):
    if not detection.mitre_technique_id:
        return
    techniques = list(incident.attack_techniques or [])
    if not any(t["id"] == detection.mitre_technique_id for t in techniques):
        techniques.append({"id": detection.mitre_technique_id, "name": detection.mitre_technique_name})
    incident.attack_techniques = techniques


def _update_affected_assets(db: Session, incident: models.Incident):
    """Matches the incident's known source/destination IPs against the simulated
    asset inventory (topology.py) so the topology map knows which nodes to highlight
    — no separate lookup logic needed in the frontend.

    Order matters here: entities.source_ips/dest_ips accumulate in the order stages
    were observed (a later stage's source can be an earlier stage's destination — see
    _entity_overlap above), so walking them in that order and de-duping gives
    affected_assets a roughly chronological source -> pivot -> target sequence, which
    the topology map uses to draw the attack path."""
    entities = incident.entities or {}
    ordered_ips = list(entities.get("source_ips", [])) + list(entities.get("dest_ips", []))
    if not ordered_ips:
        return
    ip_to_asset_id = {
        row.ip_address: row.asset_id
        for row in db.query(models.Asset).filter(models.Asset.ip_address.in_(set(ordered_ips))).all()
    }
    asset_ids = []
    for ip in ordered_ips:
        asset_id = ip_to_asset_id.get(ip)
        if asset_id and asset_id not in asset_ids:
            asset_ids.append(asset_id)
    if asset_ids != (incident.affected_assets or []):
        incident.affected_assets = asset_ids


def _append_indicators(incident: models.Incident, detection: models.Detection):
    indicators = list(incident.indicators or [])
    for ind_type, value in (("source_ip", detection.source_ip), ("destination_ip", detection.destination_ip)):
        if value and not any(i["type"] == ind_type and i["value"] == value for i in indicators):
            indicators.append({"type": ind_type, "value": value})
    incident.indicators = indicators


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def correlate_detection(db: Session, detection: models.Detection) -> models.Incident:
    events = (
        db.query(models.Event)
        .filter(models.Event.event_id.in_(detection.event_ids or []))
        .all()
    )

    incident = _find_candidate_incident(db, detection)
    if incident is None:
        incident = models.Incident(
            title=detection.threat_type,
            severity=detection.severity,
            investigation_status="new",
        )
        db.add(incident)
        db.flush()

    _merge_entities(incident, detection, events)
    _update_affected_assets(db, incident)
    _append_timeline(incident, detection)
    _append_technique(incident, detection)
    _append_indicators(incident, detection)

    if SEVERITY_RANK.get(detection.severity, 0) > SEVERITY_RANK.get(incident.severity, 0):
        incident.severity = detection.severity
    if len(incident.attack_techniques or []) > 1:
        incident.title = f"Multi-Stage Attack ({', '.join(t['name'] for t in incident.attack_techniques if t['name'])})"

    detection.incident_id = incident.incident_id
    for e in events:
        e.incident_id = incident.incident_id

    db.flush()
    return incident
