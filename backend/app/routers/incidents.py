from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db
from ..report import build_incident_markdown, build_incident_report_pdf

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


@router.get("", response_model=list[schemas.IncidentSummaryOut])
def list_incidents(db: Session = Depends(get_db)):
    return (
        db.query(models.Incident)
        .order_by(models.Incident.updated_at.desc())
        .all()
    )


@router.get("/{incident_id}", response_model=schemas.IncidentDetailOut)
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    incident = db.get(models.Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.get("/{incident_id}/report")
def download_report(incident_id: str, db: Session = Depends(get_db)):
    incident = db.get(models.Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    pdf_bytes = build_incident_report_pdf(incident)
    headers = {"Content-Disposition": f'attachment; filename="garuda-incident-{incident_id[:8]}.pdf"'}
    return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)


@router.get("/{incident_id}/summary", response_model=schemas.IncidentSummaryMarkdownOut)
def get_summary_markdown(incident_id: str, db: Session = Depends(get_db)):
    """Shareable markdown summary for Present mode's "Copy shareable summary" button."""
    incident = db.get(models.Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"markdown": build_incident_markdown(incident)}
