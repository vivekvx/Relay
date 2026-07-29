# Request relay/queueing endpoints. PRD.md §3 (Core User Flows), §5.
# Rejections map to distinct HTTP statuses/bodies so calling agents can
# handle each case deliberately, not a generic 500.

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from registry.db import get_session
from registry.models.schemas import PendingRelayItem, RelaySubmitRequest
from registry.services import relay_service

router = APIRouter(prefix="/relay", tags=["relay"])

_OUTCOME_STATUS = {
    "malformed_payload": 400,
    "suspicious_payload_content": 400,
    "unknown_sender": 404,
    "invalid_signature": 401,
    "unknown_recipient": 404,
    "expired_timestamp": 401,
    "replayed_nonce": 409,
    "rate_limited": 429,
    "ciphertext_too_large": 413,
}


@router.post("", status_code=202)
def submit_relay_request(
    body: RelaySubmitRequest, session: Session = Depends(get_session)
):
    now = datetime.now(timezone.utc)
    try:
        item_id = relay_service.submit_relay_request(
            session,
            body.payload_hex,
            body.signature_hex,
            now,
            content_ciphertext_hex=body.content_ciphertext_hex,
        )
    except relay_service.RelayRejection as rejection:
        status_code = _OUTCOME_STATUS.get(rejection.outcome, 400)
        raise HTTPException(
            status_code=status_code,
            detail={"outcome": rejection.outcome, "message": rejection.detail},
        )
    return {"id": item_id}


@router.get("/pending/{recipient}", response_model=list[PendingRelayItem])
def get_pending_requests(recipient: str, session: Session = Depends(get_session)):
    return relay_service.fetch_pending(session, recipient)
