from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import assets, live_agents, models, schemas
from ..database import get_db
from ..sse import broadcaster

router = APIRouter(prefix="/api/topology", tags=["topology"])

_VALID_ROLES = {"unknown", "enterprise", "attacker"}
_VALID_CRITICALITIES = {"low", "medium", "high", "critical"}


@router.get("", response_model=schemas.TopologyOut)
def get_topology(db: Session = Depends(get_db)):
    """All assets + edges + current status for the simulated enterprise topology map."""
    return assets.get_topology(db)


@router.get("/assets/{asset_id}/destinations", response_model=list[schemas.DestinationOut])
def get_asset_destinations(asset_id: str, db: Session = Depends(get_db)):
    """What this asset has actually connected out to — grouped, most recent first.
    Internal destinations resolve to the known asset's name; external ones get a
    best-effort reverse-DNS hostname where available."""
    asset = db.get(models.Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return assets.get_destinations(db, asset)


@router.patch("/assets/{asset_id}", response_model=schemas.AssetOut)
async def update_asset(asset_id: str, payload: schemas.AssetUpdate, db: Session = Depends(get_db)):
    """Manual override for an asset's role/criticality — e.g. self-declaring "attacker"
    from the Fleet panel, or correcting GARUDA's auto-detected role."""
    asset = db.get(models.Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    if payload.role is not None and payload.role in _VALID_ROLES:
        live_agents.set_role(db, asset_id, payload.role)
    if payload.criticality is not None and payload.criticality in _VALID_CRITICALITIES:
        asset.criticality = payload.criticality
    db.commit()
    db.refresh(asset)
    await broadcaster.publish("asset_update", schemas.AssetOut.model_validate(asset).model_dump(mode="json"))
    return asset
