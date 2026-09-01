from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import response_engine, schemas
from ..database import get_db

router = APIRouter(prefix="/api/policy", tags=["policy"])

_VALID_MODES = {"manual", "hybrid", "auto"}
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}


@router.get("", response_model=schemas.ResponsePolicyOut)
def get_policy(db: Session = Depends(get_db)):
    return response_engine.get_policy(db)


@router.put("", response_model=schemas.ResponsePolicyOut)
def update_policy(payload: schemas.ResponsePolicyUpdate, db: Session = Depends(get_db)):
    policy = response_engine.get_policy(db)
    if payload.default_mode is not None and payload.default_mode in _VALID_MODES:
        policy.default_mode = payload.default_mode
    if payload.auto_severity_ceiling is not None and payload.auto_severity_ceiling in _VALID_SEVERITIES:
        policy.auto_severity_ceiling = payload.auto_severity_ceiling
    if payload.criticality_overrides is not None:
        overrides = dict(policy.criticality_overrides or {})
        for criticality, mode in payload.criticality_overrides.items():
            if criticality in _VALID_SEVERITIES and mode in _VALID_MODES:
                overrides[criticality] = mode
            elif criticality in _VALID_SEVERITIES and mode is None:
                overrides.pop(criticality, None)
        policy.criticality_overrides = overrides
    db.commit()
    db.refresh(policy)
    return policy
