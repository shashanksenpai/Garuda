from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import live_agents, schemas
from ..database import get_db
from ..pipeline import process_raw_event
from ..sse import broadcaster

router = APIRouter(prefix="/api/agents", tags=["agents"])


@router.get("/connect-info", response_model=schemas.ConnectInfoOut)
def connect_info():
    """LAN address + port for the "connect a device" helper card — what a friend's
    agent.py should point --server at."""
    return live_agents.connect_info()


@router.post("/register", response_model=schemas.AssetOut)
async def register_agent(payload: schemas.AgentRegisterIn, db: Session = Depends(get_db)):
    asset = live_agents.register(db, payload.model_dump())
    db.commit()
    db.refresh(asset)
    await broadcaster.publish("asset_update", schemas.AssetOut.model_validate(asset).model_dump(mode="json"))
    return asset


@router.post("/{asset_id}/heartbeat", response_model=schemas.AssetOut)
async def heartbeat(asset_id: str, payload: schemas.AgentHeartbeatIn, db: Session = Depends(get_db)):
    asset = live_agents.heartbeat(db, asset_id, payload.model_dump(exclude={"connections"}))
    if asset is None:
        raise HTTPException(status_code=404, detail="Unknown agent — register first")
    db.commit()

    all_messages: list[dict] = []
    for raw_conn in payload.connections:
        all_messages.extend(process_raw_event(db, "agent", raw_conn))
    db.refresh(asset)

    for m in all_messages:
        await broadcaster.publish(m["type"], m["data"])
    await broadcaster.publish("asset_update", schemas.AssetOut.model_validate(asset).model_dump(mode="json"))
    return asset
