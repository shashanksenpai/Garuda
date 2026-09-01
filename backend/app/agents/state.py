from typing import Any, TypedDict


class InvestigationState(TypedDict, total=False):
    incident_id: str
    title: str
    severity: str
    detections: list[dict[str, Any]]     # serialized Detection rows
    timeline: list[dict[str, Any]]
    entities: dict[str, Any]
    attack_techniques: list[dict[str, Any]]
    indicators: list[dict[str, Any]]

    # Populated by agents as the graph runs
    log_analysis_findings: list[dict[str, Any]]
    investigation_summary: str
    risk_score: float
    recommended_actions: dict[str, list[str]]
    structured_actions: list[dict[str, Any]]  # machine-actionable mirror of recommended_actions, for response_engine.py
