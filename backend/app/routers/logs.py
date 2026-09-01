from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import schemas
from ..database import get_db
from ..pipeline import process_raw_event
from ..sse import broadcaster

router = APIRouter(prefix="/api/logs", tags=["logs"])


@router.post("/upload")
async def upload_logs(payload: schemas.RawLogIngest, db: Session = Depends(get_db)):
    """Ingests a batch of raw events from a file (Zeek log lines as JSON, Suricata EVE
    JSON, or auth log entries already parsed to JSON). Runs each through the same
    pipeline used by Live Mode and Sample Mode."""
    processed = 0
    incidents_touched = set()
    for raw in payload.events:
        messages = process_raw_event(db, payload.source, raw, payload.log_type)
        processed += 1
        for m in messages:
            await broadcaster.publish(m["type"], m["data"])
            if m["type"] == "incident_update":
                incidents_touched.add(m["data"]["incident_id"])
    return {"processed": processed, "incidents_touched": list(incidents_touched)}
