# Approval request lifecycle endpoints. PRD.md §3.2, §6 Approval
# Request. Expiry is checked on read (see services/approval_service.py
# for the justification of that choice).

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from registry.db import get_session
from registry.models.schemas import CreateApprovalRequestRequest, ResolveApprovalRequestRequest
from registry.services import approval_service

router = APIRouter(prefix="/approval-requests", tags=["approval-requests"])


@router.post("", status_code=201)
def create_approval_request(
    body: CreateApprovalRequestRequest, session: Session = Depends(get_session)
):
    now = datetime.now(timezone.utc)
    request_id = approval_service.create_approval_request(
        session,
        sender=body.sender,
        recipient=body.recipient,
        candidate_capsule_ids=body.candidate_capsule_ids,
        now=now,
        expiry_secs_override=body.expiry_secs_override,
    )
    session.commit()
    return {"id": request_id}


@router.get("/{request_id}")
def get_approval_request(request_id: str, session: Session = Depends(get_session)):
    now = datetime.now(timezone.utc)
    row = approval_service.get_approval_request(session, request_id, now)
    if row is None:
        raise HTTPException(status_code=404, detail="approval request not found")
    session.commit()  # persists any lazy expiry->denied transition
    return dict(row)


@router.post("/resolve")
def resolve_approval_request(
    body: ResolveApprovalRequestRequest, session: Session = Depends(get_session)
):
    now = datetime.now(timezone.utc)
    resolved = approval_service.resolve_approval_request(
        session, body.approval_request_id, body.decision, now
    )
    if not resolved:
        session.commit()
        raise HTTPException(
            status_code=409, detail="request is no longer pending (already resolved or expired)"
        )
    session.commit()
    return {"resolved": True}
