from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, response_engine, schemas
from ..database import get_db
from ..sse import broadcaster

router = APIRouter(prefix="/api/actions", tags=["actions"])


@router.get("/pending", response_model=list[schemas.ActionLogOut])
def list_pending(db: Session = Depends(get_db)):
    return (
        db.query(models.ActionLog)
        .filter(models.ActionLog.status == "pending")
        .order_by(models.ActionLog.created_at.desc())
        .all()
    )


@router.get("/audit-log", response_model=list[schemas.ActionLogOut])
def audit_log(db: Session = Depends(get_db)):
    return db.query(models.ActionLog).order_by(models.ActionLog.created_at.desc()).limit(500).all()


def _get_pending_action(db: Session, action_id: str) -> models.ActionLog:
    action = db.get(models.ActionLog, action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="Action not found")
    if action.status != "pending":
        raise HTTPException(status_code=409, detail=f"Action is '{action.status}', not pending")
    return action


@router.post("/{action_id}/approve", response_model=schemas.ActionLogOut)
async def approve(action_id: str, db: Session = Depends(get_db)):
    action = _get_pending_action(db, action_id)
    incident = db.get(models.Incident, action.incident_id) if action.incident_id else None

    response_engine.execute_action(db, action, incident)

    label = response_engine.TIMELINE_LABELS.get(action.action, action.action)
    if incident is not None:
        timeline = list(incident.timeline or [])
        timeline.append({
            "timestamp": action.executed_at.isoformat(),
            "description": f"\U0001F512 {label} — approved and executed by analyst",
            "action_id": action.action_id,
            "severity": incident.severity,
        })
        timeline.sort(key=lambda t: t["timestamp"])
        incident.timeline = timeline

    db.commit()
    db.refresh(action)

    await broadcaster.publish("action_executed", schemas.ActionLogOut.model_validate(action).model_dump(mode="json"))
    if incident is not None:
        await broadcaster.publish("incident_update", schemas.IncidentDetailOut.model_validate(incident).model_dump(mode="json"))
        for asset_id in action.target_asset_ids or []:
            asset = db.get(models.Asset, asset_id)
            if asset is not None:
                await broadcaster.publish("asset_update", schemas.AssetOut.model_validate(asset).model_dump(mode="json"))

    return action


@router.post("/{action_id}/reject", response_model=schemas.ActionLogOut)
async def reject(action_id: str, db: Session = Depends(get_db)):
    action = _get_pending_action(db, action_id)
    response_engine.reject_action(db, action)
    db.commit()
    db.refresh(action)
    await broadcaster.publish("action_rejected", schemas.ActionLogOut.model_validate(action).model_dump(mode="json"))
    return action


@router.post("/{action_id}/rollback", response_model=schemas.ActionLogOut)
async def rollback(action_id: str, db: Session = Depends(get_db)):
    action = db.get(models.ActionLog, action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="Action not found")
    if action.status != "executed" or not action.rollback_available:
        raise HTTPException(status_code=409, detail="Action cannot be rolled back")

    incident = db.get(models.Incident, action.incident_id) if action.incident_id else None
    try:
        response_engine.rollback_action(db, action, incident)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    db.commit()
    db.refresh(action)

    await broadcaster.publish("action_rolled_back", schemas.ActionLogOut.model_validate(action).model_dump(mode="json"))
    for asset_id in action.target_asset_ids or []:
        asset = db.get(models.Asset, asset_id)
        if asset is not None:
            await broadcaster.publish("asset_update", schemas.AssetOut.model_validate(asset).model_dump(mode="json"))

    return action
