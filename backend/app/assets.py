"""
Keeps simulated Asset.status in sync with incident risk, serializes the topology
for the frontend, and answers "what has this asset actually talked to" from the
Event table (no separate destinations table — Event is already the source of truth
for every connection any source has made). This never reaches real infrastructure —
it only reads/mutates rows in GARUDA's own database.
"""
import socket
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy.orm import Session

from . import models, schemas

# healthy < at_risk < compromised — status only escalates automatically here.
# "isolated"/"blocked" are response-engine-owned states and are never
# downgraded back to at_risk/compromised by this automatic sync.
_AUTO_RANK = {"healthy": 0, "at_risk": 1, "compromised": 2}

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Best-effort reverse DNS for external destinations — a small dedicated pool with a
# hard per-call timeout so a slow/unresponsive PTR lookup can't stall a request
# (socket.setdefaulttimeout is process-global and would race across concurrent
# requests, so we bound it per-call via the executor instead).
_DNS_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="garuda-rdns")
_HOSTNAME_CACHE: dict[str, str | None] = {}


def _resolve_hostname(ip: str) -> str | None:
    if ip in _HOSTNAME_CACHE:
        return _HOSTNAME_CACHE[ip]
    try:
        hostname = _DNS_EXECUTOR.submit(lambda: socket.gethostbyaddr(ip)[0]).result(timeout=0.4)
    except Exception:
        hostname = None
    _HOSTNAME_CACHE[ip] = hostname
    return hostname


def sync_asset_statuses(db: Session, incident: models.Incident) -> list[dict]:
    """Escalates the status of an incident's affected assets based on its current
    risk. Returns a list of {"type": "asset_update", "data": AssetOut} broadcast messages
    for every asset whose status actually changed."""
    messages: list[dict] = []
    if not incident.affected_assets:
        return messages

    compromise_confirmed = bool((incident.risk_factors or {}).get("successful_compromise"))
    target_status = "compromised" if (compromise_confirmed or incident.severity == "critical") else "at_risk"

    for asset_id in incident.affected_assets:
        asset = db.get(models.Asset, asset_id)
        if asset is None or asset.status not in _AUTO_RANK:
            continue  # isolated/blocked assets are owned by the response engine now
        if _AUTO_RANK[target_status] > _AUTO_RANK[asset.status]:
            asset.status = target_status
            db.flush()
            messages.append({
                "type": "asset_update",
                "data": schemas.AssetOut.model_validate(asset).model_dump(mode="json"),
            })
    return messages


def get_destinations(db: Session, asset: models.Asset, event_limit: int = 500, top_n: int = 40) -> list[dict]:
    """What this asset has actually connected out to, grouped by destination, most
    recent first. Name resolution, in priority order: a known internal Asset's name;
    then this asset's own DNS resolver cache (agent/garuda_agent.py's dns_cache_snapshot
    — what THIS machine actually resolved when it connected, far more accurate than a
    server-side guess); then a best-effort server-side reverse-DNS lookup as a last resort."""
    if not asset.ip_address:
        return []
    own_dns_cache = (asset.extra or {}).get("dns_cache", {})

    events = (
        db.query(models.Event)
        .filter(models.Event.source_ip == asset.ip_address, models.Event.destination_ip.isnot(None))
        .order_by(models.Event.timestamp.desc())
        .limit(event_limit)
        .all()
    )
    if not events:
        return []

    grouped: dict[tuple, dict] = {}
    for e in events:
        key = (e.destination_ip, e.destination_port)
        g = grouped.get(key)
        if g is None:
            g = {
                "destination_ip": e.destination_ip, "destination_port": e.destination_port,
                "protocol": e.protocol, "count": 0, "last_seen": e.timestamp, "severity": "info",
            }
            grouped[key] = g
        g["count"] += 1
        if e.timestamp > g["last_seen"]:
            g["last_seen"] = e.timestamp
        if _SEVERITY_RANK.get(e.severity, 0) > _SEVERITY_RANK.get(g["severity"], 0):
            g["severity"] = e.severity

    results = sorted(grouped.values(), key=lambda g: g["last_seen"], reverse=True)[:top_n]

    known_by_ip = {
        row.ip_address: row
        for row in db.query(models.Asset).filter(models.Asset.ip_address.in_({r["destination_ip"] for r in results})).all()
    }
    for r in results:
        known = known_by_ip.get(r["destination_ip"])
        if known is not None:
            r["hostname"] = known.name
            r["known_asset_id"] = known.asset_id
        else:
            r["hostname"] = own_dns_cache.get(r["destination_ip"]) or _resolve_hostname(r["destination_ip"])
            r["known_asset_id"] = None

    return results


def get_topology(db: Session) -> dict:
    assets = db.query(models.Asset).order_by(models.Asset.name).all()
    edges = db.query(models.AssetEdge).all()
    return {
        "assets": [schemas.AssetOut.model_validate(a).model_dump(mode="json") for a in assets],
        "edges": [schemas.AssetEdgeOut.model_validate(e).model_dump(mode="json") for e in edges],
    }
