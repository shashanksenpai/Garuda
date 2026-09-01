"""
The single pipeline both Live Mode (real Zeek/Suricata/auth logs) and Sample Mode
(replayed scenarios) feed into. Neither mode has special-case logic downstream of
`process_raw_event` — this is the architectural guarantee that a demo scenario and
a real sensor produce identical incidents, risk scores, and agent output.
"""
from sqlalchemy.orm import Session

from . import models, detection, correlation, schemas, assets, response_engine, packet_simulator, live_agents
from .agents.graph import run_investigation
from .normalization import NORMALIZERS


def process_raw_event(db: Session, source: str, raw: dict, log_type: str | None = None) -> list[dict]:
    """Runs one raw event through the full pipeline. Returns a list of broadcast messages
    (each a {"type": ..., "data": ...} dict) describing what happened, in order."""
    messages: list[dict] = []

    normalizer = NORMALIZERS.get(source)
    if normalizer is None:
        raise ValueError(f"Unknown event source: {source}")

    normalized = normalizer(raw, log_type) if source == "zeek" else normalizer(raw)

    event = models.Event(**normalized)
    db.add(event)
    db.flush()
    messages.append({"type": "event", "data": schemas.EventOut.model_validate(event).model_dump(mode="json")})

    for packet in packet_simulator.synth_packets_for_event(event):
        messages.append({"type": "packet", "data": packet})

    fired = detection.run_detections(db, event)
    for det in fired:
        messages.append({"type": "detection", "data": schemas.DetectionOut.model_validate(det).model_dump(mode="json")})

        attacker_asset = live_agents.mark_attacker(db, det)
        if attacker_asset is not None:
            messages.append({"type": "asset_update", "data": schemas.AssetOut.model_validate(attacker_asset).model_dump(mode="json")})

        incident = correlation.correlate_detection(db, det)
        run_investigation(db, incident)
        messages.extend(assets.sync_asset_statuses(db, incident))
        messages.extend(response_engine.process_incident(db, incident))
        db.commit()
        db.refresh(incident)

        messages.append({
            "type": "incident_update",
            "data": schemas.IncidentDetailOut.model_validate(incident).model_dump(mode="json"),
        })

    if not fired:
        db.commit()

    return messages
