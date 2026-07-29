# Audit log read endpoint. Metadata only, per the hard boundary — read
# access, never write (writes only ever happen from services/, and the
# DB trigger structurally blocks UPDATE/DELETE regardless).

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from registry.db import get_session
from registry.models.tables import audit_log

router = APIRouter(prefix="/audit-log", tags=["audit-log"])


@router.get("")
def list_audit_log(
    sender: str | None = None,
    recipient: str | None = None,
    limit: int = 100,
    session: Session = Depends(get_session),
):
    query = select(audit_log).order_by(audit_log.c.id.desc()).limit(limit)
    if sender is not None:
        query = query.where(audit_log.c.sender == sender)
    if recipient is not None:
        query = query.where(audit_log.c.recipient == recipient)
    return [dict(row) for row in session.execute(query).mappings().all()]
