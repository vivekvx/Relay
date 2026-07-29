# Grant CRUD endpoints. PRD.md §4.2, §6 Grant.
# Storage only — enforcement of revocation-at-load-time is
# agent/resolver/'s job (see registry/ARCHITECTURE.md). Creation/
# revocation themselves DO require signature verification here (PRD.md
# §5 R2) — see grant_service.create_grant_signed/revoke_grant_signed.

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from registry.db import get_session
from registry.models.schemas import CreateGrantRequest, RevokeGrantRequest
from registry.services import grant_service

router = APIRouter(prefix="/grants", tags=["grants"])

_OUTCOME_STATUS = {
    "malformed_payload": 400,
    "unknown_sender": 404,
    "invalid_signature": 401,
    "expired_timestamp": 401,
    "replayed_nonce": 409,
    "not_found": 404,
}


@router.post("", status_code=201)
def create_grant(body: CreateGrantRequest, session: Session = Depends(get_session)):
    now = datetime.now(timezone.utc)
    try:
        grant_id = grant_service.create_grant_signed(
            session,
            grantor=body.grantor,
            grantee=body.grantee,
            grant_type=body.grant_type,
            scope_capsule_ids=body.scope_capsule_ids,
            expires_at=body.expires_at,
            timestamp=body.timestamp,
            nonce=body.nonce,
            signature_hex=body.signature_hex,
            now=now,
        )
    except grant_service.GrantRejection as rejection:
        status_code = _OUTCOME_STATUS.get(rejection.outcome, 400)
        raise HTTPException(
            status_code=status_code,
            detail={"outcome": rejection.outcome, "message": rejection.detail},
        )
    session.commit()
    return {"id": grant_id}


@router.post("/revoke", status_code=200)
def revoke_grant(body: RevokeGrantRequest, session: Session = Depends(get_session)):
    now = datetime.now(timezone.utc)
    try:
        grant_service.revoke_grant_signed(
            session,
            grant_id=body.grant_id,
            timestamp=body.timestamp,
            nonce=body.nonce,
            signature_hex=body.signature_hex,
            now=now,
        )
    except grant_service.GrantRejection as rejection:
        status_code = _OUTCOME_STATUS.get(rejection.outcome, 400)
        raise HTTPException(
            status_code=status_code,
            detail={"outcome": rejection.outcome, "message": rejection.detail},
        )
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
