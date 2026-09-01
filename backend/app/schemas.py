from datetime import datetime, timezone
from typing import Annotated, Any, Optional

from pydantic import BaseModel, BeforeValidator, ConfigDict


def _stamp_utc(v: Any) -> Any:
    """SQLite drops tzinfo on round-trip, so a datetime read back from the DB — even
    though every _now() writes datetime.now(timezone.utc) — comes back naive. Left
    alone, that serializes without a 'Z'/offset suffix, and JS's `new Date(...)`
    then parses it as local time instead of UTC (silently off by the browser's UTC
    offset). Every datetime the API returns is UTC; make that explicit here once
    rather than special-casing every timestamp comparison client-side."""
    if isinstance(v, datetime) and v.tzinfo is None:
        return v.replace(tzinfo=timezone.utc)
    return v


UtcDatetime = Annotated[datetime, BeforeValidator(_stamp_utc)]


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: str
    timestamp: UtcDatetime
    source: str
    event_type: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    process: Optional[str] = None
    conn_status: Optional[str] = None
    severity: str
    message: Optional[str] = None
    incident_id: Optional[str] = None


class DetectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    detection_id: str
    timestamp: UtcDatetime
    threat_type: str
    confidence: float
    severity: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    evidence: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    incident_id: Optional[str] = None


class IncidentSummaryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    incident_id: str
    created_at: UtcDatetime
    updated_at: UtcDatetime
    title: str
    severity: str
    risk_score: float
    investigation_status: str


class IncidentDetailOut(IncidentSummaryOut):
    risk_factors: dict[str, Any] = {}
    entities: dict[str, Any] = {}
    attack_techniques: list[dict[str, Any]] = []
    indicators: list[dict[str, Any]] = []
    timeline: list[dict[str, Any]] = []
    log_analysis_findings: list[dict[str, Any]] = []
    investigation_summary: Optional[str] = None
    recommended_actions: dict[str, Any] = {}
    structured_actions: list[dict[str, Any]] = []
    affected_assets: list[str] = []


class RawLogIngest(BaseModel):
    source: str  # zeek | suricata | auth
    log_type: Optional[str] = None  # conn|dns|http|ssl|ssh (for zeek); auth for authlog
    events: list[dict[str, Any]]


class StartLiveRequest(BaseModel):
    scenario: Optional[str] = None  # if provided, replay a scenario instead of a real sensor
    speed: float = 1.0  # playback speed multiplier for scenario mode


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    asset_id: str
    name: str
    asset_type: str
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    criticality: str
    zone: str
    status: str
    position_x: float = 0.0
    position_y: float = 0.0
    extra: dict[str, Any] = {}
    is_dynamic: bool = False
    role: str = "unknown"
    os_info: Optional[str] = None
    current_user: Optional[str] = None
    last_seen: Optional[UtcDatetime] = None
    processes: list[dict[str, Any]] = []
    attack_reasons: list[dict[str, Any]] = []


class AssetUpdate(BaseModel):
    role: Optional[str] = None  # unknown | enterprise | attacker
    criticality: Optional[str] = None  # low | medium | high | critical


class AgentRegisterIn(BaseModel):
    name: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    os_info: Optional[str] = None
    role: Optional[str] = "enterprise"  # unknown | enterprise | attacker
    current_user: Optional[str] = None
    criticality: Optional[str] = "medium"


class AgentHeartbeatIn(BaseModel):
    current_user: Optional[str] = None
    processes: Optional[list[dict[str, Any]]] = None
    connections: list[dict[str, Any]] = []  # raw "agent"-source events, fed through process_raw_event as-is
    dns_cache: Optional[dict[str, str]] = None  # {ip: hostname} scraped from the agent's own DNS resolver cache


class ConnectInfoOut(BaseModel):
    lan_ip: Optional[str] = None
    port: int = 8123


class AssetEdgeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    edge_id: str
    source_asset_id: str
    target_asset_id: str
    label: Optional[str] = None


class TopologyOut(BaseModel):
    assets: list[AssetOut]
    edges: list[AssetEdgeOut]


class ActionLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    action_id: str
    incident_id: Optional[str] = None
    action: str
    params: dict[str, Any] = {}
    target_asset_ids: list[str] = []
    mode: Optional[str] = None
    status: str
    reason: Optional[str] = None
    rollback_available: bool = False
    created_at: UtcDatetime
    updated_at: UtcDatetime
    executed_at: Optional[UtcDatetime] = None


class ResponsePolicyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    default_mode: str
    criticality_overrides: dict[str, Any] = {}
    auto_severity_ceiling: str
    updated_at: UtcDatetime


class ResponsePolicyUpdate(BaseModel):
    default_mode: Optional[str] = None  # manual | hybrid | auto
    # {"low"|"medium"|"high"|"critical": mode}; a null value clears that criticality's override
    criticality_overrides: Optional[dict[str, Optional[str]]] = None
    auto_severity_ceiling: Optional[str] = None  # low | medium | high | critical


class IncidentSummaryMarkdownOut(BaseModel):
    markdown: str


class DestinationOut(BaseModel):
    destination_ip: str
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    hostname: Optional[str] = None  # a known Asset's name (internal) or best-effort reverse-DNS (external)
    known_asset_id: Optional[str] = None
    count: int
    last_seen: UtcDatetime
    severity: str
