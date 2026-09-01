from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("", response_model=list[schemas.EventOut])
def list_events(limit: int = Query(100, le=1000), db: Session = Depends(get_db)):
    events = (
        db.query(models.Event)
        .order_by(models.Event.timestamp.desc())
        .limit(limit)
        .all()
    )
    return list(reversed(events))
