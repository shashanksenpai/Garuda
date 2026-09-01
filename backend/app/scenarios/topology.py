"""
Seed data for GARUDA's simulated enterprise asset inventory + network topology.

This is infrastructure GARUDA owns for the demo — a fixed set of assets and the
edges describing which ones can talk to which. It is seeded once (idempotent)
and then mutated in place by the pipeline (assets.py, response_engine.py) as
incidents happen and response actions execute. It never represents, and is
never wired to, real production systems.

`WEB01`'s ip_address intentionally matches `scenarios/definitions.py::VICTIM_IP`
so that every built-in attack scenario lands on a real node in this topology.
"""
from sqlalchemy.orm import Session

from .. import models

# Kept in sync with scenarios/definitions.py — the scenario "victim" is this asset.
WEB01_IP = "192.168.56.10"

ASSETS = [
    {"key": "fw-edge", "name": "FW-EDGE (Perimeter Firewall)", "asset_type": "firewall",
     "ip_address": "192.168.56.1", "criticality": "high", "zone": "dmz", "position": (0, 200)},
    {"key": "web01", "name": "WEB01 (DMZ Web Server)", "asset_type": "server",
     "ip_address": WEB01_IP, "hostname": "web01.internal", "criticality": "high", "zone": "dmz", "position": (220, 100)},
    {"key": "web02", "name": "WEB02 (DMZ Web Server)", "asset_type": "server",
     "ip_address": "192.168.56.11", "hostname": "web02.internal", "criticality": "medium", "zone": "dmz", "position": (220, 300)},
    {"key": "core-rtr", "name": "CORE-RTR (Core Router)", "asset_type": "router",
     "ip_address": "10.0.0.1", "criticality": "high", "zone": "internal", "position": (440, 200)},
    {"key": "app01", "name": "APP01 (Internal App Server)", "asset_type": "server",
     "ip_address": "10.0.10.20", "hostname": "app01.internal", "criticality": "high", "zone": "internal", "position": (660, 100)},
    {"key": "app02", "name": "APP02 (Internal App Server)", "asset_type": "server",
     "ip_address": "10.0.10.21", "hostname": "app02.internal", "criticality": "medium", "zone": "internal", "position": (660, 300)},
    {"key": "db01", "name": "DB01 (Primary Database)", "asset_type": "database",
     "ip_address": "10.0.20.10", "hostname": "db01.internal", "criticality": "critical", "zone": "internal", "position": (880, 200)},
    {"key": "dc01", "name": "DC01 (Domain Controller)", "asset_type": "server",
     "ip_address": "10.0.5.5", "hostname": "dc01.internal", "criticality": "critical", "zone": "internal",
     "position": (440, 420), "extra": {"role": "domain_controller"}},
    {"key": "ws-fin01", "name": "WS-FIN01 (Finance)", "asset_type": "workstation",
     "ip_address": "10.0.30.11", "hostname": "ws-fin01", "criticality": "medium", "zone": "internal", "position": (220, 500)},
    {"key": "ws-fin02", "name": "WS-FIN02 (Finance)", "asset_type": "workstation",
     "ip_address": "10.0.30.12", "hostname": "ws-fin02", "criticality": "low", "zone": "internal", "position": (340, 560)},
    {"key": "ws-eng01", "name": "WS-ENG01 (Engineering)", "asset_type": "workstation",
     "ip_address": "10.0.30.21", "hostname": "ws-eng01", "criticality": "medium", "zone": "internal", "position": (560, 560)},
    {"key": "ws-eng02", "name": "WS-ENG02 (Engineering)", "asset_type": "workstation",
     "ip_address": "10.0.30.22", "hostname": "ws-eng02", "criticality": "low", "zone": "internal", "position": (680, 500)},
    {"key": "ws-hr01", "name": "WS-HR01 (HR)", "asset_type": "workstation",
     "ip_address": "10.0.30.31", "hostname": "ws-hr01", "criticality": "medium", "zone": "internal", "position": (800, 460)},
    {"key": "cloud-s3", "name": "ACME-BACKUPS (Cloud Storage Bucket)", "asset_type": "cloud_service",
     "ip_address": "10.0.90.5", "criticality": "high", "zone": "cloud", "position": (880, 40)},
]

EDGES = [
    ("fw-edge", "web01", "inbound HTTPS"),
    ("fw-edge", "web02", "inbound HTTPS"),
    ("fw-edge", "core-rtr", "perimeter -> core"),
    ("web01", "core-rtr", "app tier"),
    ("web02", "core-rtr", "app tier"),
    ("core-rtr", "app01", "internal routing"),
    ("core-rtr", "app02", "internal routing"),
    ("core-rtr", "dc01", "auth traffic"),
    ("app01", "db01", "db queries"),
    ("app02", "db01", "db queries"),
    ("app01", "cloud-s3", "backup sync"),
    ("core-rtr", "ws-fin01", "LAN"),
    ("core-rtr", "ws-fin02", "LAN"),
    ("core-rtr", "ws-eng01", "LAN"),
    ("core-rtr", "ws-eng02", "LAN"),
    ("core-rtr", "ws-hr01", "LAN"),
    ("ws-fin01", "dc01", "domain auth"),
    ("ws-fin02", "dc01", "domain auth"),
    ("ws-eng01", "dc01", "domain auth"),
    ("ws-eng02", "dc01", "domain auth"),
    ("ws-hr01", "dc01", "domain auth"),
]


def seed_topology(db: Session) -> None:
    """Idempotently seeds the enterprise asset inventory + topology edges.
    No-ops if assets already exist (so re-running init_db on an existing garuda.db is safe)."""
    if db.query(models.Asset).first() is not None:
        return

    key_to_id: dict[str, str] = {}
    for spec in ASSETS:
        asset = models.Asset(
            name=spec["name"],
            asset_type=spec["asset_type"],
            ip_address=spec.get("ip_address"),
            hostname=spec.get("hostname"),
            criticality=spec.get("criticality", "medium"),
            zone=spec.get("zone", "internal"),
            status="healthy",
            position_x=spec["position"][0],
            position_y=spec["position"][1],
            extra=spec.get("extra", {}),
        )
        db.add(asset)
        db.flush()
        key_to_id[spec["key"]] = asset.asset_id

    for source_key, target_key, label in EDGES:
        db.add(models.AssetEdge(
            source_asset_id=key_to_id[source_key],
            target_asset_id=key_to_id[target_key],
            label=label,
        ))

    db.commit()
