from langgraph.graph import StateGraph, END
from sqlalchemy.orm import Session

from .. import models, risk
from . import log_analysis_agent, threat_investigation_agent, response_agent
from .state import InvestigationState


def _build_graph():
    graph = StateGraph(InvestigationState)
    graph.add_node("log_analysis", log_analysis_agent.run)
    graph.add_node("threat_investigation", threat_investigation_agent.run)
    graph.add_node("response", response_agent.run)

    graph.set_entry_point("log_analysis")
    graph.add_edge("log_analysis", "threat_investigation")
    graph.add_edge("threat_investigation", "response")
    graph.add_edge("response", END)
    return graph.compile()


_COMPILED_GRAPH = _build_graph()


def _serialize_detection(d: models.Detection) -> dict:
    return {
        "detection_id": d.detection_id,
        "threat_type": d.threat_type,
        "confidence": d.confidence,
        "severity": d.severity,
        "source_ip": d.source_ip,
        "destination_ip": d.destination_ip,
        "evidence": d.evidence,
        "mitre_technique_id": d.mitre_technique_id,
        "mitre_technique_name": d.mitre_technique_name,
    }


def run_investigation(db: Session, incident: models.Incident) -> models.Incident:
    """Runs the full agentic pipeline for an incident and persists the results."""
    risk.compute_risk(db, incident)

    detections = db.query(models.Detection).filter(models.Detection.incident_id == incident.incident_id).all()

    initial_state: InvestigationState = {
        "incident_id": incident.incident_id,
        "title": incident.title,
        "severity": incident.severity,
        "detections": [_serialize_detection(d) for d in detections],
        "timeline": incident.timeline or [],
        "entities": incident.entities or {},
        "attack_techniques": incident.attack_techniques or [],
        "indicators": incident.indicators or [],
    }

    result = _COMPILED_GRAPH.invoke(initial_state)

    incident.log_analysis_findings = result.get("log_analysis_findings", [])
    incident.investigation_summary = result.get("investigation_summary")
    incident.recommended_actions = result.get("recommended_actions", {})
    incident.structured_actions = result.get("structured_actions", [])
    incident.investigation_status = "investigating"

    db.flush()
    return incident
