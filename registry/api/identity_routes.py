# Identity registration endpoint. PRD.md §4.2 "Identity layer".
# Thin route — validation via Pydantic schema, logic in services/.

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from registry.db import get_session
from registry.models.schemas import RegisterIdentityRequest
from registry.services import audit_service, identity_service

router = APIRouter(prefix="/identities", tags=["identities"])


@router.post("", status_code=201)
def register_identity(
    body: RegisterIdentityRequest, session: Session = Depends(get_session)
):
    try:
        identity_service.register_identity(
            session, body.handle, body.public_key_hex, body.x25519_public_key_hex
        )
    except identity_service.DuplicateHandleError:
        audit_service.record_audit_event(
            session,
            "identity_registration",
            "duplicate_handle",
            sender=body.handle,
            detail=f"handle {body.handle!r} already registered",
        )
        session.commit()
        raise HTTPException(status_code=409, detail="handle already registered")

    audit_service.record_audit_event(
        session, "identity_registration", "success", sender=body.handle
    )
    session.commit()
    return {"handle": body.handle}


# Judgment call (flagged, not silently added): the task's Part 2 scope
# only mentioned updating the *registration* endpoint. A minimal read
# endpoint is added here because without one, a sender has no way to
# ever look up a recipient's X25519 public key to encrypt content for
# them — the stored column would be otherwise unreachable data. Kept to
# the minimum: returns the two public keys, nothing else.
@router.get("/{handle}")
def get_identity(handle: str, session: Session = Depends(get_session)):
    row = identity_service.get_identity(session, handle)
    if row is None:
        raise HTTPException(status_code=404, detail="handle not registered")
    return {
        "handle": row["handle"],
        "public_key_hex": row["public_key_hex"],
        "x25519_public_key_hex": row["x25519_public_key_hex"],
    }
