import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, Float, DateTime, JSON, Integer, Text, Boolean
from sqlalchemy.orm import relationship

from .database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Event(Base):
    """A normalized security event (from Zeek, Suricata, auth logs, or a replayed scenario)."""

    __tablename__ = "events"

    event_id = Column(String, primary_key=True, default=_uuid)
    timestamp = Column(DateTime(timezone=True), default=_now, index=True)
    source = Column(String, index=True)          # zeek | suricata | auth | scenario
    event_type = Column(String, index=True)      # network_connection | auth_failure | ...
    source_ip = Column(String, index=True, nullable=True)
    destination_ip = Column(String, index=True, nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)
    username = Column(String, nullable=True)
    hostname = Column(String, nullable=True)
    process = Column(String, nullable=True)
    conn_status = Column(String, nullable=True)   # TCP handshake outcome (e.g. ESTABLISHED, SYN_SENT) where the source can report it — see detection.py's _looks_like_benign_browsing
    severity = Column(String, default="info")     # info | low | medium | high | critical
    message = Column(Text, nullable=True)
    raw_event_reference = Column(JSON, nullable=True)  # original raw payload, kept for evidence
    incident_id = Column(String, nullable=True, index=True)  # set once correlated


class Detection(Base):
    """A rule/anomaly detection fired on one or more events."""

    __tablename__ = "detections"

    detection_id = Column(String, primary_key=True, default=_uuid)
    timestamp = Column(DateTime(timezone=True), default=_now, index=True)
    threat_type = Column(String, index=True)      # e.g. SSH Brute Force
    confidence = Column(Float, default=0.0)
    severity = Column(String, default="medium")
    source_ip = Column(String, nullable=True)
    destination_ip = Column(String, nullable=True)
    evidence = Column(Text, nullable=True)
    mitre_technique_id = Column(String, nullable=True)
    mitre_technique_name = Column(String, nullable=True)
    event_ids = Column(JSON, default=list)         # events that support this detection
    incident_id = Column(String, nullable=True, index=True)


class Incident(Base):
    """A correlated set of events/detections representing one attack narrative."""

    __tablename__ = "incidents"

    incident_id = Column(String, primary_key=True, default=_uuid)
    created_at = Column(DateTime(timezone=True), default=_now)
    updated_at = Column(DateTime(timezone=True), default=_now, onupdate=_now)

    title = Column(String, default="Untitled Incident")
    severity = Column(String, default="medium")
    risk_score = Column(Float, default=0.0)
    risk_factors = Column(JSON, default=dict)
    investigation_status = Column(String, default="new")  # new|investigating|complete

    entities = Column(JSON, default=dict)           # {source_ips: [...], dest_ips: [...], users: [...], hosts: [...]}
    attack_techniques = Column(JSON, default=list)   # [{id, name}]
    indicators = Column(JSON, default=list)          # [{type, value}]
    timeline = Column(JSON, default=list)            # ordered [{timestamp, description, event_id}]

    log_analysis_findings = Column(JSON, default=list)
    investigation_summary = Column(Text, nullable=True)
    recommended_actions = Column(JSON, default=dict)  # {immediate: [], investigation: [], recovery: []}
    structured_actions = Column(JSON, default=list)   # [{action, params}] — machine-actionable mirror of recommended_actions, consumed by response_engine.py

    affected_assets = Column(JSON, default=list)      # asset_ids matched from entities.source_ips/dest_ips against Asset.ip_address

    report_markdown = Column(Text, nullable=True)


class Asset(Base):
    """A node in the simulated enterprise topology GARUDA owns for this demo.

    This inventory is entirely local to GARUDA's own database — it does not
    represent, and response actions against it never reach, any real
    infrastructure, cloud account, or production system.
    """

    __tablename__ = "assets"

    asset_id = Column(String, primary_key=True, default=_uuid)
    name = Column(String)
    asset_type = Column(String, index=True)   # workstation | server | database | firewall | router | cloud_service
    ip_address = Column(String, index=True, nullable=True)
    hostname = Column(String, index=True, nullable=True)
    criticality = Column(String, default="medium", index=True)  # low | medium | high | critical
    zone = Column(String, default="internal")   # dmz | internal | cloud
    status = Column(String, default="healthy", index=True)  # healthy | at_risk | compromised | isolated | blocked
    position_x = Column(Float, default=0.0)
    position_y = Column(Float, default=0.0)
    extra = Column(JSON, default=dict)  # role markers (e.g. domain_controller) + response-engine side effects (disabled_accounts, killed_sessions, rate_limited_ips)

    # Populated only for real machines running a GARUDA Agent (see agent/garuda_agent.py) —
    # False for the seeded demo topology (topology.py).
    is_dynamic = Column(Boolean, default=False, index=True)
    role = Column(String, default="unknown", index=True)  # unknown | enterprise | attacker — self-declared at registration, auto-escalated to "attacker" once implicated as a detection source (see live_agents.mark_attacker)
    os_info = Column(String, nullable=True)
    current_user = Column(String, nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    processes = Column(JSON, default=list)  # recent local process snapshot [{pid, name, username}], for the hover card only
    attack_reasons = Column(JSON, default=list)  # [{detection_id, threat_type, evidence, mitre_technique_id, mitre_technique_name, timestamp}] — why this asset was flagged an attacker, most recent last


class AssetEdge(Base):
    """A directed "can talk to" edge between two assets in the topology."""

    __tablename__ = "asset_edges"

    edge_id = Column(String, primary_key=True, default=_uuid)
    source_asset_id = Column(String, index=True)
    target_asset_id = Column(String, index=True)
    label = Column(String, nullable=True)


class BlockedIP(Base):
    """Simulated firewall blocklist — mutated by the block_ip response action."""

    __tablename__ = "blocked_ips"

    id = Column(String, primary_key=True, default=_uuid)
    ip_address = Column(String, index=True)
    firewall_asset_id = Column(String, nullable=True)
    incident_id = Column(String, nullable=True, index=True)
    blocked_at = Column(DateTime(timezone=True), default=_now)
    active = Column(Boolean, default=True)


class ResponsePolicy(Base):
    """Singleton settings row controlling how the response engine handles recommended actions."""

    __tablename__ = "response_policy"

    id = Column(String, primary_key=True, default=lambda: "global")
    default_mode = Column(String, default="manual")  # manual | hybrid | auto
    criticality_overrides = Column(JSON, default=dict)  # {"low": "auto", "high": "hybrid", ...} — falls back to default_mode when absent
    auto_severity_ceiling = Column(String, default="high")  # in auto mode, incidents above this severity always require approval
    updated_at = Column(DateTime(timezone=True), default=_now, onupdate=_now)


class ActionLog(Base):
    """Every response action the engine ever decided on — executed, queued, rejected, or rolled back.
    Doubles as the pending-approval queue (status == "pending") and the audit log (everything)."""

    __tablename__ = "action_log"

    action_id = Column(String, primary_key=True, default=_uuid)
    incident_id = Column(String, index=True, nullable=True)
    action = Column(String, index=True)  # block_ip | isolate_host | disable_account | kill_session | alert_soc | rate_limit
    params = Column(JSON, default=dict)
    target_asset_ids = Column(JSON, default=list)
    mode = Column(String)  # manual | hybrid | auto — the effective mode in force when this action was decided
    status = Column(String, default="pending", index=True)  # pending | executed | rejected | rolled_back
    reason = Column(Text, nullable=True)
    rollback_available = Column(Boolean, default=False)
    rollback_data = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=_now)
    updated_at = Column(DateTime(timezone=True), default=_now, onupdate=_now)
    executed_at = Column(DateTime(timezone=True), nullable=True)
