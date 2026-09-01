"""
Log Analysis Agent.

Consumes the incident's detections (already produced by the rule engine) and turns
each one into a structured "finding": what the threat is, who's involved, why it's
suspicious (evidence pulled straight from the detection, never invented), and which
MITRE ATT&CK technique it maps to. This is the first LangGraph node in the
investigation graph.
"""
from .state import InvestigationState


def run(state: InvestigationState) -> InvestigationState:
    findings = []
    for d in state.get("detections", []):
        findings.append({
            "finding": d["threat_type"],
            "source_ip": d.get("source_ip"),
            "target": d.get("destination_ip"),
            "evidence": d.get("evidence"),
            "confidence": d.get("confidence"),
            "severity": d.get("severity"),
            "technique": {
                "id": d.get("mitre_technique_id"),
                "name": d.get("mitre_technique_name"),
            },
        })
    state["log_analysis_findings"] = findings
    return state
