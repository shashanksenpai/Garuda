"""
Response Engine — executes, queues, or (in manual mode) simply leaves alone the
structured actions response_agent.py recommends, according to the active
ResponsePolicy.

Scope boundary: every handler below mutates rows in GARUDA's own `assets`,
`blocked_ips`, and `action_log` tables — a simulated enterprise inventory
GARUDA owns for this demo. Nothing here calls out to a real firewall, IdP,
cloud account, or production system.

manual mode is the default and is a complete no-op for this module (identical
to the pre-existing "recommendations only" behavior) — process_incident()
returns an empty list and no ActionLog rows are created.
"""
import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from . import models, schemas

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
CRITICALITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# hybrid mode always executes these immediately — considered safe/reversible regardless of target.
LOW_RISK_ACTIONS = {"block_ip", "alert_soc", "rate_limit"}

TIMELINE_LABELS = {
    "block_ip": "Blocked source IP",
    "isolate_host": "Host isolated",
    "disable_account": "Account disabled",
    "kill_session": "Session terminated",
    "alert_soc": "SOC alerted",
    "rate_limit": "Source rate-limited",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

def get_policy(db: Session) -> models.ResponsePolicy:
    policy = db.get(models.ResponsePolicy, "global")
    if policy is None:
        policy = models.ResponsePolicy(id="global")
        db.add(policy)
        db.flush()
    return policy


def _target_criticality(db: Session, incident: models.Incident) -> str:
    if not incident.affected_assets:
        return "low"
    assets = db.query(models.Asset).filter(models.Asset.asset_id.in_(incident.affected_assets)).all()
    if not assets:
        return "low"
    return max(assets, key=lambda a: CRITICALITY_RANK.get(a.criticality, 1)).criticality


def _effective_mode(policy: models.ResponsePolicy, target_criticality: str) -> str:
    override = (policy.criticality_overrides or {}).get(target_criticality)
    return override or policy.default_mode


def _decide(policy: models.ResponsePolicy, incident: models.Incident, action_name: str, target_criticality: str) -> str | None:
    """Returns "executed", "pending", or None (manual mode — do nothing)."""
    mode = _effective_mode(policy, target_criticality)
    if mode == "manual":
        return None
    if mode == "auto":
        # Safety rail: never auto-act above the configured ceiling without approval, even in auto mode.
        if SEVERITY_RANK.get(incident.severity, 0) > SEVERITY_RANK.get(policy.auto_severity_ceiling, 3):
            return "pending"
        return "executed"
    if mode == "hybrid":
        if action_name in LOW_RISK_ACTIONS:
            return "executed"
        if target_criticality in ("high", "critical"):
            return "pending"
        return "executed"
    return None


# ---------------------------------------------------------------------------
# Action handlers — (execute_fn, rollback_fn_or_None). execute_fn returns the
# rollback_data dict to persist (or None if the action isn't reversible).
# ---------------------------------------------------------------------------

def _find_domain_controller(db: Session) -> models.Asset | None:
    for asset in db.query(models.Asset).filter(models.Asset.asset_type == "server").all():
        if (asset.extra or {}).get("role") == "domain_controller":
            return asset
    return None


def _exec_block_ip(db: Session, action: models.ActionLog, incident: models.Incident) -> dict:
    firewall = db.query(models.Asset).filter(models.Asset.asset_type == "firewall").first()
    row_ids = []
    for ip in action.params.get("ip_addresses", []):
        already = (
            db.query(models.BlockedIP)
            .filter(models.BlockedIP.ip_address == ip, models.BlockedIP.active == True)  # noqa: E712
            .first()
        )
        if already is not None:
            continue
        row = models.BlockedIP(ip_address=ip, firewall_asset_id=firewall.asset_id if firewall else None, incident_id=incident.incident_id)
        db.add(row)
        db.flush()
        row_ids.append(row.id)
    if firewall is not None:
        action.target_asset_ids = [firewall.asset_id]
    return {"blocked_ip_row_ids": row_ids}


def _rollback_block_ip(db: Session, action: models.ActionLog, incident: models.Incident):
    row_ids = (action.rollback_data or {}).get("blocked_ip_row_ids", [])
    if row_ids:
        db.query(models.BlockedIP).filter(models.BlockedIP.id.in_(row_ids)).update({"active": False}, synchronize_session=False)


def _exec_isolate_host(db: Session, action: models.ActionLog, incident: models.Incident) -> dict:
    previous_statuses = {}
    changed = []
    for asset_id in incident.affected_assets or []:
        asset = db.get(models.Asset, asset_id)
        if asset is None or asset.asset_type not in ("workstation", "server", "database") or asset.status == "isolated":
            continue
        previous_statuses[asset.asset_id] = asset.status
        asset.status = "isolated"
        changed.append(asset.asset_id)
    action.target_asset_ids = changed
    return {"previous_statuses": previous_statuses}


def _rollback_isolate_host(db: Session, action: models.ActionLog, incident: models.Incident):
    for asset_id, prev_status in (action.rollback_data or {}).get("previous_statuses", {}).items():
        asset = db.get(models.Asset, asset_id)
        if asset is not None:
            asset.status = prev_status


def _exec_disable_account(db: Session, action: models.ActionLog, incident: models.Incident) -> dict:
    dc = _find_domain_controller(db)
    if dc is None:
        return {"usernames": []}
    extra = dict(dc.extra or {})
    disabled = list(extra.get("disabled_accounts", []))
    added = [u for u in action.params.get("usernames", []) if u not in disabled]
    disabled.extend(added)
    extra["disabled_accounts"] = disabled
    dc.extra = extra
    action.target_asset_ids = [dc.asset_id]
    return {"usernames": added}


def _rollback_disable_account(db: Session, action: models.ActionLog, incident: models.Incident):
    dc = _find_domain_controller(db)
    if dc is None:
        return
    to_remove = set((action.rollback_data or {}).get("usernames", []))
    extra = dict(dc.extra or {})
    extra["disabled_accounts"] = [u for u in extra.get("disabled_accounts", []) if u not in to_remove]
    dc.extra = extra


def _exec_kill_session(db: Session, action: models.ActionLog, incident: models.Incident) -> None:
    touched = []
    for asset_id in incident.affected_assets or []:
        asset = db.get(models.Asset, asset_id)
        if asset is None:
            continue
        extra = dict(asset.extra or {})
        killed = list(extra.get("killed_sessions", []))
        killed.append({"at": _now().isoformat(), "targets": action.params.get("hostnames", [])})
        extra["killed_sessions"] = killed
        asset.extra = extra
        touched.append(asset_id)
    action.target_asset_ids = touched
    return None  # point-in-time action — not reversible


def _exec_alert_soc(db: Session, action: models.ActionLog, incident: models.Incident) -> None:
    return None  # notification only — nothing to mutate or roll back


def _exec_rate_limit(db: Session, action: models.ActionLog, incident: models.Incident) -> dict:
    edge_asset = db.query(models.Asset).filter(models.Asset.asset_type.in_(("firewall", "router"))).first()
    if edge_asset is None:
        return {"ip_addresses": []}
    extra = dict(edge_asset.extra or {})
    limited = list(extra.get("rate_limited_ips", []))
    added = [ip for ip in action.params.get("ip_addresses", []) if ip not in limited]
    limited.extend(added)
    extra["rate_limited_ips"] = limited
    edge_asset.extra = extra
    action.target_asset_ids = [edge_asset.asset_id]
    return {"ip_addresses": added, "asset_id": edge_asset.asset_id}


def _rollback_rate_limit(db: Session, action: models.ActionLog, incident: models.Incident):
    data = action.rollback_data or {}
    asset = db.get(models.Asset, data.get("asset_id")) if data.get("asset_id") else None
    if asset is None:
        return
    to_remove = set(data.get("ip_addresses", []))
    extra = dict(asset.extra or {})
    extra["rate_limited_ips"] = [ip for ip in extra.get("rate_limited_ips", []) if ip not in to_remove]
    asset.extra = extra


ACTION_REGISTRY = {
    "block_ip": (_exec_block_ip, _rollback_block_ip),
    "isolate_host": (_exec_isolate_host, _rollback_isolate_host),
    "disable_account": (_exec_disable_account, _rollback_disable_account),
    "kill_session": (_exec_kill_session, None),
    "alert_soc": (_exec_alert_soc, None),
    "rate_limit": (_exec_rate_limit, _rollback_rate_limit),
}


# ---------------------------------------------------------------------------
# Lifecycle: execute / reject / rollback a single ActionLog row
# ---------------------------------------------------------------------------

def execute_action(db: Session, action: models.ActionLog, incident: models.Incident):
    handler = ACTION_REGISTRY.get(action.action)
    rollback_data = handler[0](db, action, incident) if handler else None
    action.status = "executed"
    action.executed_at = _now()
    action.rollback_available = bool(handler and handler[1] is not None)
    action.rollback_data = rollback_data or {}
    db.flush()


def reject_action(db: Session, action: models.ActionLog):
    action.status = "rejected"
    db.flush()


def rollback_action(db: Session, action: models.ActionLog, incident: models.Incident):
    handler = ACTION_REGISTRY.get(action.action)
    if not action.rollback_available or handler is None or handler[1] is None:
        raise ValueError(f"Action '{action.action}' is not reversible")
    handler[1](db, action, incident)
    action.status = "rolled_back"
    db.flush()


# ---------------------------------------------------------------------------
# Entry point called from pipeline.py after each investigation run
# ---------------------------------------------------------------------------

def _already_logged(db: Session, incident_id: str, action_name: str, params: dict) -> bool:
    signature = json.dumps(params, sort_keys=True)
    existing = (
        db.query(models.ActionLog)
        .filter(models.ActionLog.incident_id == incident_id, models.ActionLog.action == action_name)
        .all()
    )
    return any(json.dumps(a.params or {}, sort_keys=True) == signature for a in existing)


def process_incident(db: Session, incident: models.Incident) -> list[dict]:
    """Runs the incident's current structured_actions (recomputed by response_agent.py on
    every pipeline cycle) through the active ResponsePolicy: skips anything already logged
    for this incident, decides execute/pending/skip, executes what qualifies, and appends a
    timeline entry + broadcast message for each new action. In manual mode this is a no-op."""
    messages: list[dict] = []
    policy = get_policy(db)
    target_criticality = _target_criticality(db, incident)

    for spec in incident.structured_actions or []:
        action_name = spec.get("action")
        params = spec.get("params", {})
        if action_name not in ACTION_REGISTRY or _already_logged(db, incident.incident_id, action_name, params):
            continue

        decision = _decide(policy, incident, action_name, target_criticality)
        if decision is None:
            continue  # manual mode: recommendation-only, unchanged from pre-existing behavior

        mode = _effective_mode(policy, target_criticality)
        reason = None
        if decision == "pending":
            reason = (
                f"Incident severity ({incident.severity}) exceeds the auto-mode approval ceiling "
                f"({policy.auto_severity_ceiling})."
                if mode == "auto"
                else f"Targets a {target_criticality}-criticality asset under hybrid mode — requires analyst approval."
            )

        action = models.ActionLog(
            incident_id=incident.incident_id,
            action=action_name,
            params=params,
            mode=mode,
            status="pending",
            reason=reason,
        )
        db.add(action)
        db.flush()

        if decision == "executed":
            execute_action(db, action, incident)

        label = TIMELINE_LABELS.get(action_name, action_name)
        icon = "\U0001F512" if decision == "executed" else "⏳"
        suffix = "auto-executed" if decision == "executed" else "pending analyst approval"
        timeline = list(incident.timeline or [])
        timeline.append({
            "timestamp": _now().isoformat(),
            "description": f"{icon} {label} — {suffix} ({mode} mode)",
            "action_id": action.action_id,
            "severity": incident.severity,
        })
        timeline.sort(key=lambda t: t["timestamp"])
        incident.timeline = timeline

        messages.append({
            "type": "action_executed" if decision == "executed" else "action_pending",
            "data": schemas.ActionLogOut.model_validate(action).model_dump(mode="json"),
        })
        for asset_id in action.target_asset_ids or []:
            asset = db.get(models.Asset, asset_id)
            if asset is not None:
                messages.append({
                    "type": "asset_update",
                    "data": schemas.AssetOut.model_validate(asset).model_dump(mode="json"),
                })

    return messages
