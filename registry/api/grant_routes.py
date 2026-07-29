# Grant CRUD endpoints. PRD.md §4.2, §6 Grant.
# Storage only — enforcement of revocation-at-load-time is
# agent/resolver/'s job (see registry/ARCHITECTURE.md).

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from registry.db import get_session
from registry.models.schemas import CreateGrantRequest, RevokeGrantRequest
from registry.services import grant_service

router = APIRouter(prefix="/grants", tags=["grants"])


@router.post("", status_code=201)
def create_grant(body: CreateGrantRequest, session: Session = Depends(get_session)):
    grant_id = grant_service.create_grant(
        session,
        grantor=body.grantor,
        grantee=body.grantee,
        grant_type=body.grant_type,
        scope_capsule_ids=body.scope_capsule_ids,
        expires_at=body.expires_at,
    )
    session.commit()
    return {"id": grant_id}


@router.post("/revoke", status_code=200)
def revoke_grant(body: RevokeGrantRequest, session: Session = Depends(get_session)):
    grant_service.revoke_grant(session, body.grant_id)
    session.commit()
    return {"revoked": True}


@router.get("/{grant_id}")
def get_grant(grant_id: str, session: Session = Depends(get_session)):
    row = grant_service.get_grant(session, grant_id)
    if row is None:
        raise HTTPException(status_code=404, detail="grant not found")
    return dict(row)


@router.get("")
def list_grants(grantee: str, session: Session = Depends(get_session)):
    return [dict(row) for row in grant_service.list_grants_for_grantee(session, grantee)]
