"""
Handles real GARUDA Agents — the lightweight collector script friends run on their
own laptops (see agent/garuda_agent.py) — registering as dynamic Asset rows and
reporting live telemetry. This module only owns dynamic-asset bookkeeping
(registration, heartbeat metadata, attacker-role escalation); the actual connection
telemetry an agent reports is fed through the exact same
normalize -> detect -> correlate -> agents -> risk -> SSE pipeline as every other
event source, via `process_raw_event(db, "agent", raw)` — nothing pipeline-specific
lives here.
"""
import socket
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from . import models

_DYNAMIC_COLUMNS_PER_ROW = 4
_DYNAMIC_ROW_SPACING = 160
_DYNAMIC_COL_SPACING = 110
_DYNAMIC_ORIGIN = (-240, 620)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def register(db: Session, payload: dict) -> models.Asset:
    """Idempotent by IP — re-running `join` on the same laptop updates its existing
    asset rather than spawning a duplicate node."""
    ip = payload.get("ip_address")
    existing = None
    if ip:
        existing = (
            db.query(models.Asset)
            .filter(models.Asset.ip_address == ip, models.Asset.is_dynamic == True)  # noqa: E712
            .first()
        )

    asset = existing or models.Asset(is_dynamic=True, status="healthy", zone="internal", asset_type="workstation")
    asset.name = payload.get("name") or payload.get("hostname") or ip or "Unknown Agent"
    asset.hostname = payload.get("hostname")
    asset.ip_address = ip
    asset.criticality = payload.get("criticality") or asset.criticality or "medium"
    asset.os_info = payload.get("os_info")
    asset.role = payload.get("role") or asset.role or "unknown"
    asset.current_user = payload.get("current_user")
    asset.last_seen = _now()

    if existing is None:
        count = db.query(models.Asset).filter(models.Asset.is_dynamic == True).count()  # noqa: E712
        ox, oy = _DYNAMIC_ORIGIN
        asset.position_x = ox + (count % _DYNAMIC_COLUMNS_PER_ROW) * _DYNAMIC_ROW_SPACING
        asset.position_y = oy + (count // _DYNAMIC_COLUMNS_PER_ROW) * _DYNAMIC_COL_SPACING
        db.add(asset)
        db.flush()

        # Wire every joining laptop into the visual topology like any other LAN
        # workstation, so it doesn't render as a disconnected island.
        core_router = db.query(models.Asset).filter(models.Asset.asset_type == "router").first()
        if core_router is not None:
            db.add(models.AssetEdge(source_asset_id=core_router.asset_id, target_asset_id=asset.asset_id, label="LAN"))

    db.flush()
    return asset


_MAX_DNS_CACHE_ENTRIES = 400


def heartbeat(db: Session, asset_id: str, payload: dict) -> models.Asset | None:
    asset = db.get(models.Asset, asset_id)
    if asset is None or not asset.is_dynamic:
        return None
    if payload.get("current_user") is not None:
        asset.current_user = payload["current_user"]
    if payload.get("processes") is not None:
        asset.processes = payload["processes"]
    if payload.get("dns_cache"):
        extra = dict(asset.extra or {})
        merged = {**extra.get("dns_cache", {}), **payload["dns_cache"]}
        if len(merged) > _MAX_DNS_CACHE_ENTRIES:
            # Keep the most recently-merged entries — dict preserves insertion order,
            # and the freshest scrape's keys were just re-inserted last above.
            merged = dict(list(merged.items())[-_MAX_DNS_CACHE_ENTRIES:])
        extra["dns_cache"] = merged
        asset.extra = extra
    asset.last_seen = _now()
    db.flush()
    return asset


def set_role(db: Session, asset_id: str, role: str) -> models.Asset | None:
    asset = db.get(models.Asset, asset_id)
    if asset is None:
        return None
    asset.role = role
    db.flush()
    return asset


def mark_attacker(db: Session, detection: models.Detection) -> models.Asset | None:
    """Escalates a dynamic asset's role to "attacker" once it's implicated as a
    detection's source, and records *why* (threat type, evidence, MITRE technique) so
    that's visible on the dashboard rather than an unexplained label. This is how
    GARUDA "identifies the attacker" among connected laptops — grounded in the same
    rule engine as everything else, not a guess. Keeps recording new reasons even
    after the role is already "attacker", so repeat offenses build a trail."""
    if not detection.source_ip:
        return None
    asset = (
        db.query(models.Asset)
        .filter(models.Asset.ip_address == detection.source_ip, models.Asset.is_dynamic == True)  # noqa: E712
        .first()
    )
    if asset is None:
        return None

    reasons = list(asset.attack_reasons or [])
    already_recorded = any(r.get("detection_id") == detection.detection_id for r in reasons)
    if not already_recorded:
        reasons.append({
            "detection_id": detection.detection_id,
            "threat_type": detection.threat_type,
            "evidence": detection.evidence,
            "mitre_technique_id": detection.mitre_technique_id,
            "mitre_technique_name": detection.mitre_technique_name,
            "timestamp": _now().isoformat(),
        })
        asset.attack_reasons = reasons[-10:]

    was_already_attacker = asset.role == "attacker"
    asset.role = "attacker"
    if already_recorded and was_already_attacker:
        return None  # nothing new to broadcast

    db.flush()
    return asset


def connect_info() -> dict:
    """Best-effort LAN-reachable address for the "connect a device" helper card.
    Opens no real connection — the UDP connect() here never sends a packet, it only
    asks the OS which local interface would be used to reach the internet."""
    ip = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        ip = None
    return {"lan_ip": ip, "port": 8123}
